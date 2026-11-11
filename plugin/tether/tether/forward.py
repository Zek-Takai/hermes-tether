"""Device mode (design D22): while a device is the session's target, the session works ON that device.

Host side, all through public plugin surfaces:
- ``tool_execution`` middleware hands the file tools (read_file, write_file, patch, search_files) whole to the
  device, whose own Hermes runs them (``ctx.dispatch_tool`` there) with its own paths, file rules, write fence and
  credential protections. Terminal and computer use already run on the device through the tether backend and
  the tether_screen provider, with the session's approvals.
- ``pre_llm_call`` tells the model once per turn which machine it is working on and whose rules apply, so the
  plugin does not have to coach it tool by tool.
"""
from __future__ import annotations

import io
import json
import logging
import os
import posixpath
import re
import tarfile
import threading
import time
from pathlib import Path
from typing import Any, Optional

from .machine import describe
from .runtime import explain, get_runtime

logger = logging.getLogger(__name__)

FORWARDED_TOOLS = frozenset({"read_file", "write_file", "patch", "search_files"})
TOOL_TIMEOUT_S = 300
_facts: dict[str, tuple[float, dict[str, Any]]] = {}     # device -> (fetched_at, announce)


SKILL_COPY_MAX_BYTES = 20 * 1024 * 1024
_SKIP_DIRS = frozenset({"__pycache__", ".git", "node_modules", ".venv", "venv", ".mypy_cache"})
REVIEW_PROMPT = "Review the conversation above"       # all of Hermes's background review prompts start so


def target_for(session_id: Optional[str]) -> Optional[str]:
    """The device this session's work runs on right now, or None when it runs on this host (D23 route)."""
    rt = get_runtime(create=False)
    if rt is None or rt.host is None:
        return None
    target = rt.route(session_id or None)
    return None if target == "local" else target


def _host_owned(path: Any) -> bool:
    """Paths inside this host's own Hermes home (her skills, memories, sessions) stay on the host."""
    if not isinstance(path, str) or not path.startswith(("/", "~")):
        return False
    try:
        from hermes_constants import get_hermes_home
        home = str(get_hermes_home())       # the active profile's home
    except Exception:  # noqa: BLE001 - tests / outside Hermes
        home = os.environ.get("HERMES_HOME") or os.path.expanduser("~/.hermes")
    try:
        root = os.path.realpath(home)
        full = os.path.realpath(os.path.expanduser(path)) if path.startswith("~") else os.path.realpath(path)
    except (OSError, ValueError):
        return False
    return full == root or full.startswith(root.rstrip("/") + "/")


def _is_review(user_message: Any) -> bool:
    return threading.current_thread().name.startswith("bg-review") or _text(user_message).startswith(REVIEW_PROMPT)


def _text(message: Any) -> str:
    if isinstance(message, str):
        return message.strip()
    if isinstance(message, list):
        return " ".join(str(p.get("text", "")) for p in message if isinstance(p, dict)).strip()
    return ""


def _absolute(args: dict[str, Any], task_id: Optional[str]) -> dict[str, Any]:
    """A relative path means relative to where this session's terminal is on the device."""
    path = args.get("path")
    if isinstance(path, str) and path and not path.startswith(("/", "~")):
        from .provider import cwd_for
        cwd = cwd_for(task_id)
        if cwd and cwd.startswith("/"):
            return {**args, "path": posixpath.normpath(posixpath.join(cwd, path))}
    return args


def tool_execution(**kwargs: Any) -> Any:
    """Middleware: run a file tool on the session's device instead of this host. Anything else passes through."""
    name, args, next_call = kwargs.get("tool_name"), kwargs.get("args") or {}, kwargs["next_call"]
    if name not in FORWARDED_TOOLS:
        return next_call(args)
    target = target_for(kwargs.get("session_id"))
    if target is None or _host_owned(args.get("path")):
        return next_call(args)
    try:
        meta, body = get_runtime().call_target(
            "tool", {"name": name, "args": _absolute(dict(args), kwargs.get("task_id"))},
            timeout=TOOL_TIMEOUT_S, target=target)
    except Exception as e:  # noqa: BLE001 - offline, not allowed, link down: one plain sentence for the model
        return json.dumps({"error": explain(e, target)})
    text = body.decode(errors="replace")
    return json.loads(text) if meta.get("json_dict") else text


_HOME_RE = re.compile(r"[A-Za-z0-9 ._~:/\\-]{1,200}")


def _safe_home(value: Any) -> str:
    """The device announces its home folder; only a plain path goes into the model's note (no newlines, no
    instructions), else nothing."""
    return value if isinstance(value, str) and _HOME_RE.fullmatch(value) else ""


def _device_facts(target: str) -> dict[str, Any]:
    cached = _facts.get(target)
    if cached and time.monotonic() - cached[0] < 120:
        return cached[1]
    try:
        rt = get_runtime()
        rows = rt.run(rt.host.list_devices(), 10)
        facts = next((r.get("capabilities") or {} for r in rows if r.get("name") == target), {})
    except Exception:  # noqa: BLE001 - context is best effort; the tools themselves report problems
        facts = {}
    _facts[target] = (time.monotonic(), facts)
    get_runtime().learn_rules(target, facts)
    return facts


def turn_context(session_id: str = "", user_message: Any = "", **kwargs: Any) -> Optional[str]:
    """pre_llm_call: a user turn starts. Record the user's own words (only they may open or close a device
    connection, D23) and, while a device is open, tell the model where it works. Background reviews never open
    a turn, so their work stays on this host."""
    rt = get_runtime(create=False)
    if rt is None or rt.host is None or not session_id or _is_review(user_message):
        return None
    rt.turn_open[session_id] = True
    rt.turn_text[session_id] = _text(user_message)
    note = rt.closed_note.pop(session_id, None)
    target = target_for(session_id)
    f = _device_facts(target) if target else {}
    if target and target_for(session_id) is None:            # the facts may carry the idle limit: re-check
        target = None
    if target is None:
        note = rt.closed_note.pop(session_id, note)          # route() may have just timed it out
        return f"[tether] {note}" if note else None
    home = _safe_home(f.get("home"))
    where = f" (home {home})" if home else ""
    about = describe(f)
    return (f"[tether] You are working ON the paired machine '{target}'{where}, as if it were your own. "
            f"{about + ' ' if about else ''}Terminal, read_file, write_file, patch, search_files and computer_use act on "
            f"{target} natively, under {target}'s own Hermes rules and permissions. Your terminal starts in your "
            f"workspace there; save results where the user asks. Stay on {target} for the whole task and do not "
            f"carry files or data between {target} and your host. A refusal from {target} is final: report it. "
            f"To show the user a file from {target}, put MEDIA:<absolute path on {target}> in your reply. Your "
            "memory, skills and this conversation stay on your host; change skills only with skill_manage. Only "
            "the user can close this connection, by sending 'untether' as a message on its own; inside a longer "
            "message it does nothing, so if they ask to close it any other way, tell them that.")


def turn_closed(session_id: str = "", user_message: Any = "", **kwargs: Any) -> None:
    """post_llm_call: the user turn ended; anything after it (a background review) runs on this host."""
    rt = get_runtime(create=False)
    if rt is None or not session_id or _is_review(user_message):
        return None
    rt.turn_open[session_id] = False
    return None


def _pack(skill_dir: Path) -> Optional[bytes]:
    buf, total = io.BytesIO(), 0
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for root, dirs, files in os.walk(skill_dir):
            dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS and not os.path.islink(os.path.join(root, d)))
            for name in sorted(files):
                full = os.path.join(root, name)
                if os.path.islink(full) or not os.path.isfile(full):
                    continue
                total += os.path.getsize(full)
                if total > SKILL_COPY_MAX_BYTES:
                    return None
                tar.add(full, arcname=os.path.relpath(full, skill_dir), recursive=False)
    return buf.getvalue()


def skill_files(tool_name: str = "", result: Any = "", session_id: str = "", **kwargs: Any) -> Optional[str]:
    """transform_tool_result: when a skill is opened while a device is open, give the device a read-only copy of
    the skill's folder in the session's workspace so its scripts and files can run there (D24)."""
    if tool_name != "skill_view" or not isinstance(result, str):
        return None
    target = target_for(session_id)
    if target is None:
        return None
    try:
        data = json.loads(result)
    except ValueError:
        return None
    skill_dir = data.get("skill_dir") if isinstance(data, dict) and data.get("success") else None
    if not skill_dir or not os.path.isdir(skill_dir):
        return None
    rt = get_runtime()
    copies = rt.skill_copies.setdefault(session_id, {})
    path = copies.get(skill_dir)
    if path is None:
        packed = _pack(Path(skill_dir))
        if packed is None:
            data["on_device"] = {"device": target, "note": f"this skill is too large to copy to {target}"}
            return json.dumps(data)
        name = re.sub(r"[^A-Za-z0-9._-]", "_", os.path.basename(os.path.normpath(skill_dir)))[:80] or "skill"
        try:
            meta, _ = rt.call_target("skill_put", {"name": name}, packed, timeout=60, target=target)
        except Exception as e:  # noqa: BLE001 - the skill text still helps; say plainly the files are not there
            data["on_device"] = {"device": target, "note": explain(e, target)}
            return json.dumps(data)
        path = copies[skill_dir] = meta.get("path")
    data["on_device"] = {
        "device": target, "path": path,
        "note": (f"read-only copy of this skill's files on {target}, for running its scripts there; removed when "
                 f"the {target} connection closes. Change the skill itself only with skill_manage, which saves it "
                 "on your host.")}
    return json.dumps(data)
