"""Device mode (design D22): while a device is the session's target, the session works ON that device.

Host side, all through public plugin surfaces:
- ``tool_execution`` middleware hands the file tools (read_file, write_file, patch, search_files) whole to the
  device, whose own Hermes runs them (``ctx.run_tool_call`` there: its hooks, its middleware) with its own paths,
  file rules, write fence and credential protections. Hermes's own checks of the call (its pre_tool_call hooks,
  compression-marker guard, loop guardrails and ACP edit approval) run here first, through Hermes's public
  ``authorize_tool_call``: in its agent loop they sit inside next_call, which a forwarded call never reaches (D59).
  Terminal and computer use
  already run on the device through the tether backend and the tether_screen provider, with the session's
  approvals.
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

from .identity import shield_children
from .machine import describe, is_path, model_view, shown_home
from .provider import _host_only_active, host_home, host_only, within
from .runtime import explain, get_runtime, shared
from .tools import hermes_wrote, user_words
from .workspace import safe_name

logger = logging.getLogger(__name__)

FORWARDED_TOOLS = frozenset({"read_file", "write_file", "patch", "search_files"})
TOOL_TIMEOUT_S = 300
FACTS_TTL_S = 120
# D71: said in the per-turn note when the open device runs the session's commands inside its session lock.
_LOCKED_NOTE = ("While you are connected, {target}'s own Tether and Hermes files (its Hermes home, install and "
                "plugins) are locked: you cannot read or change them there, and commands get 'Operation not "
                "permitted' if they try. To improve Tether, change a copy of its project; the person at {target} "
                "installs it. ")
# device -> (fetched_at, the key pinned for that name when fetched, announce). Used only while the same key is
# still pinned under that name: a re-paired name never gets the previous machine's facts (F61).
_facts: dict[str, tuple[float, str, dict[str, Any]]] = {}


SKILL_COPY_MAX_BYTES = 20 * 1024 * 1024
_SKIP_DIRS = frozenset({"__pycache__", ".git", "node_modules", ".venv", "venv", ".mypy_cache"})


def target_for(session_id: Optional[str]) -> Optional[str]:
    """The device this session's work runs on right now, or None when it runs on this host (D23 route)."""
    rt = get_runtime(create=False)
    if rt is None or rt.host is None:
        return None
    target = rt.route(session_id or None)
    return None if target == "local" else target


def _host_owned(path: Any) -> bool:
    """Paths inside this host's own Hermes home (her skills, memories, sessions) stay on the host. Judged on the
    path as written and on where it resolves (a skill folder symlinked out of the home is still the host's).
    By a fixed rule here, never by what a device announces, two kinds of path are not the host's:
    - a device's session workspace, even when the device has the same home path: <home>/tether/sessions/..., or
      <home>/profiles/<name>/tether/sessions/... for a device that runs Hermes under a named profile (F34);
    - a '~' path whose '~' alone already lands in the home. Where this host's HOME is its Hermes home or lies
      inside it (Hermes's Docker image: HOME=HERMES_HOME=/opt/data), every '~' path would, so there '~' can only
      mean the device's home, which the device expands itself (F6). A '~' path is the host's only when it walks
      into the Hermes home from above it (~/.hermes/skills/...)."""
    if not isinstance(path, str) or not path.startswith(("/", "~")):
        return False
    home = host_home()
    try:
        homes = _spellings(home)
        if path.startswith("~"):
            base = os.path.expanduser(path.split("/", 1)[0])     # '~' or '~user', as this host would expand it
            if base.startswith("~") or any(within(b, h) for b in _spellings(base) for h in homes):
                return False
        spots = _spellings(os.path.expanduser(path))
    except (OSError, ValueError):
        return False
    if any(_device_workspace(p, h) for p in spots for h in homes):
        return False
    return any(within(p, h) for p in spots for h in homes)


def _spellings(path: str) -> set[str]:
    """A path as written (absolute, normalised) and where it resolves."""
    return {os.path.normpath(os.path.abspath(path)), os.path.realpath(path)}


def _device_workspace(path: str, home: str) -> bool:
    """True when path is in a device-role session workspace under this home: <home>/tether/sessions/..., or
    <home>/profiles/<name>/tether/sessions/... (where Hermes keeps a named profile's home). Only the device role
    keeps anything in those folders; the host's memories, skills and settings are never there."""
    if within(path, os.path.join(home, "tether", "sessions")):
        return True
    profiles = os.path.join(home, "profiles")
    if not within(path, profiles):
        return False
    name = path[len(profiles.rstrip("/")) + 1:].split("/", 1)[0]      # cut by length: within() may fold case
    return bool(name) and within(path, os.path.join(profiles, name, "tether", "sessions"))


def _v4a_names(patch: Any) -> Optional[list[str]]:
    """Every file a V4A patch names, read by Hermes's own reader (tools.patch_parser.patch_file_paths), or None
    when they cannot be read (no file named, or a header Hermes refuses): a refusal, never "no files"."""
    if not isinstance(patch, str) or not patch:
        return None
    from tools.patch_parser import patch_file_paths
    return patch_file_paths(patch)


def _is_review() -> bool:
    """Hermes's background review runs (their own thread, their own flag). The user's words never count: a
    message that merely starts like a review prompt is the user's turn, and it opens its device connection."""
    if threading.current_thread().name.startswith("bg-review"):
        return True
    try:
        from tools.skill_provenance import is_background_review
        return bool(is_background_review())
    except Exception:  # noqa: BLE001 - outside Hermes: the thread name decides
        return False


# Runs whose prompt no person typed: scheduled jobs, sub-agents, webhook and other event deliveries (their text is
# a template filled from an outside payload), Hermes's internal kanban, tool, codex and gateway runs, agent-to-agent
# (a2a) peers and hosted bot rooms. Matched against the run's platform AND its session source: Hermes labels a
# third-party integration (`hermes chat --source tool`) and a managed worker only by source, never by platform.
UNATTENDED_PLATFORMS = frozenset({"cron", "subagent", "webhook", "msgraph_webhook", "kanban", "tool", "codex",
                                  "gateway", "a2a", "bot_room"})
_AGENT_SHELL_MARKS = ("HERMES_SESSION_KEY", "HERMES_SESSION_PLATFORM", "HERMES_DELEGATED_CHILD_CONTEXT")


def _launched_from_agent_shell() -> bool:
    """Hermes puts its session variables and the delegated-child marker into every tool shell a gateway or TUI turn
    starts; its own processes never set HERMES_SESSION_KEY or HERMES_SESSION_PLATFORM in os.environ
    (gateway/run_turn_runner.py). One exception: Hermes's TUI slash-command worker sets HERMES_SESSION_KEY itself when
    it starts (tui_gateway/slash_worker.py), so in that process the key is not a sign of an agent's shell.
    Not detected (D35, a stated limit): the classic CLI binds no session variables, so its tool shells carry none of
    these marks, and a Hermes started from such a shell looks like the user's own. It holds no grant token (D33), so
    the device asks its person again before anything runs there."""
    import sys
    main = getattr(getattr(sys.modules.get("__main__"), "__spec__", None), "name", "") or ""
    marks = [m for m in _AGENT_SHELL_MARKS if not (m == "HERMES_SESSION_KEY" and main == "tui_gateway.slash_worker")]
    return any(os.environ.get(name) for name in marks)


def record_process_origin() -> None:
    """Called when the plugin loads: note whether this process was started from an agent's shell. The first answer
    is kept on the shared handle, so a reload of the plugin cannot change it."""
    shared("started_from_agent_shell", _launched_from_agent_shell)


def _unattended(kwargs: dict[str, Any]) -> bool:
    """A run no person typed: a scheduled job, sub-agent, webhook or other event run, or a Hermes process that was
    itself started from an agent's shell. Its prompt is not the user's words, even when it names a device. Each
    Hermes check is separate, so one missing helper only drops that check. parent_session_id alone is not a test:
    Hermes also sets it when a user's conversation is compressed, and that turn is the user's own."""
    if {str(kwargs.get("platform") or ""), _sender(kwargs)["platform"]} & UNATTENDED_PLATFORMS:
        return True
    if _session_sources() & UNATTENDED_PLATFORMS:
        return True
    try:
        from gateway.session_context import get_session_env
        if get_session_env("HERMES_CRON_SESSION") == "1":
            return True
    except Exception:  # noqa: BLE001
        pass
    try:
        from hermes_cli.plugin_session import in_delegated_child
        if in_delegated_child(include_subprocesses=True):
            return True
    except Exception:  # noqa: BLE001
        pass
    return bool(shared("started_from_agent_shell", lambda: False))


def _session_sources() -> set[str]:
    """The run's session source as Hermes records it, from all three places it can be: the process environment
    (`hermes chat --source tool` sets it there, hermes_cli/main.py), the gateway's bound session context, and a
    managed worker's launch policy (hermes_cli.plugin_session.session_source; its worker binds an empty source).
    The gateway daemon strips HERMES_SESSION_SOURCE from its own environment, so the user's chats are not affected."""
    sources = {os.environ.get("HERMES_SESSION_SOURCE", "")}
    try:
        from gateway.session_context import get_session_env
        sources.add(str(get_session_env("HERMES_SESSION_SOURCE") or ""))
    except Exception:  # noqa: BLE001 - outside Hermes
        pass
    try:
        from hermes_cli.plugin_session import session_source
        sources.add(str(session_source() or ""))
    except Exception:  # noqa: BLE001
        pass
    return {s.strip() for s in sources} - {""}


def _turn_event() -> Any:
    """Hermes's frozen view of the running gateway turn's event (hermes_cli.plugin_session.turn_event). None outside
    a gateway turn (classic CLI, TUI) or when it cannot be read: every check that uses it is an extra refusal, never
    a permission."""
    try:
        from hermes_cli.plugin_session import turn_event
        return turn_event()
    except Exception:  # noqa: BLE001
        return None


def _self_injected(kwargs: dict[str, Any], raw: str) -> bool:
    """A turn Hermes started itself or another agent wrote, never the user's own, whatever its platform: a Bot Mode
    message from another bot, a /loop wakeup, a /goal continuation, a heartbeat, a background-job, sub-agent or
    kanban wake, a Bot Chat delivery, a plugin's injected message, or a message whose author is a bot. Hermes's own
    marks, in order: the display kind it stamps on the turn's user row before pre_llm_call (agent/turn_context.py
    _stage_turn_user_message; gateway/response_filters.py display_kind_for_event, the TUI and the classic CLI type
    their own notification turns the same way; a user's own message has none), the gateway turn's event, and the
    exact text Hermes writes for the turns it queues as plain input (tools.hermes_wrote). A turn run by a separate
    managed-worker process carries none of these marks, but that process holds no device connection or grant (D33,
    D34), so nothing it runs reaches a device without the person's Allow."""
    history = kwargs.get("conversation_history")
    row = history[-1] if isinstance(history, list) and history else None
    if isinstance(row, dict) and row.get("role") == "user" and row.get("display_kind"):
        return True
    event = _turn_event()
    if event is not None:
        # internal: a synthetic event; inherit_channel_pin: a goal continuation, heartbeat or /goal resume; is_bot: a
        # bot or webhook author.
        if getattr(event, "internal", False) or getattr(event, "inherit_channel_pin", False) \
                or getattr(event, "is_bot", False):
            return True
    return hermes_wrote(raw, **_sender(kwargs))


def _sender(kwargs: dict[str, Any]) -> dict[str, str]:
    """Who sent this turn and where, as Hermes bound it for this run (gateway/session_context.py). With no
    session context, the process environment; with neither, empty values: no tag or label is peeled.
    In a shared chat Hermes leaves the session's USER empty (Telegram observe mode: session_detached.py
    session_env_source) and binds the turn's trusted sender as the ACTOR; the actor is "" once another sender's
    input joined the turn, so nothing is peeled then."""
    def value(name: str) -> str:
        try:
            from gateway.session_context import get_session_env
            return str(get_session_env(name) or "")
        except Exception:  # noqa: BLE001 - outside Hermes
            return os.environ.get(name, "")
    user_name, user_id = value("HERMES_SESSION_USER_NAME"), value("HERMES_SESSION_USER_ID")
    if not (user_name or user_id):
        user_name, user_id = value("HERMES_SESSION_ACTOR_NAME"), value("HERMES_SESSION_ACTOR_ID")
    return {"platform": value("HERMES_SESSION_PLATFORM") or str(kwargs.get("platform") or ""),
            "user_name": user_name, "user_id": user_id, "chat_type": value("HERMES_SESSION_CHAT_TYPE")}


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
    """Middleware for every tool call: binds the call's turn id on this thread (D23: a call from another run than the
    user's open turn stays on this host), then runs a file tool on the device instead of this host.

    Hermes runs the real tool on this host when a middleware raises before it has called next_call. So nothing
    raised before that point may escape: it becomes an error the model reads, and the tool does not run here. An
    exception from inside next_call is the host's own tool failing, and passes through unchanged."""
    # Every tool call, in every Hermes process the plugin is loaded in: Hermes may have loaded .env into os.environ
    # again (a cron job's start, a reload), and its own terminal builds a foreground child from os.environ.
    shield_children()
    rt = get_runtime(create=False)
    entered: list[bool] = []
    inner = kwargs["next_call"]

    def next_call(args: Any) -> Any:
        entered.append(True)
        return inner(args)

    previous = (rt.begin_call(kwargs.get("turn_id") or "", kwargs.get("conversation_id") or "")
                if rt is not None else None)
    try:
        return _tool_execution(**{**kwargs, "next_call": next_call})
    except Exception as e:  # noqa: BLE001 - see above: a failure before the host run must not run the tool here
        if entered:
            raise
        logger.warning("tether: a file call could not be routed: %s", type(e).__name__)
        return json.dumps({"error": f"tether: this file call could not be checked ({type(e).__name__}), so it did "
                                    "not run anywhere. Tell the user; do not retry it here."})
    finally:
        if rt is not None:
            rt.end_call(previous)


def _tool_execution(**kwargs: Any) -> Any:
    name, args, next_call = kwargs.get("tool_name"), kwargs.get("args") or {}, kwargs["next_call"]
    from .filebox import lent_call
    boxed = lent_call(kwargs)                            # device side: a host's lent file tool, in its session lock
    if boxed is not None:
        return boxed
    if _host_only_active():
        # This thread's work is already this machine's own: a host-owned call's inner work, or a file tool this
        # machine runs for its host as a device (device_exec.ToolRunner). It runs here, as is.
        return next_call(args)
    rt = get_runtime(create=False)
    if rt is not None and rt.host is not None:
        # D34: a session id Hermes rotated between turns is matched to the connection it had (every tool call
        # carries the conversation id; pre_llm_call does not), before this call is routed. For every tool: the
        # terminal reaches the tether backend through the return just below.
        rt.adopt_conversation(kwargs.get("session_id") or "")
    if name not in FORWARDED_TOOLS:
        return next_call(args)
    target = target_for(kwargs.get("session_id"))
    host, refusal = _judge(name, args, target or "")     # a V4A patch: all of its files are the host's, or none
    if host:
        # The host's own Hermes home: never work meant for a device, so it runs here whatever the route, and a lost
        # connection holds it back no more than an open one (D34 holds back device-meant work only, F36). Hermes
        # runs the tool on this thread and its shell calls go through the tether terminal: mark them host-only, or
        # they would run on the device (same path, wrong machine).
        with host_only():
            return next_call(args)
    if target is None:
        lost = rt.lost_device(session=kwargs.get("session_id") or None) if rt is not None else None
        if lost:        # D34: this session's model works on a device whose connection is gone: say so
            return json.dumps({"error": lost})
        return next_call(args)
    if refusal:
        return json.dumps({"error": refusal})
    # D59: Hermes's own checks of this call (in its agent loop they run inside next_call, never reached below),
    # through its public authorize_tool_call: hooks (block, approve, modify), compression-marker guard, loop
    # guardrails and ACP edit approval. A refusal is already reported; it is returned unchanged.
    from hermes_cli.middleware import authorize_tool_call
    decision = authorize_tool_call(args)
    if not decision.allowed:
        return decision.result
    args = decision.args
    host, refusal = _judge(name, args, target)           # a pre_tool_call 'modify' may have changed the paths
    if refusal or host:
        return json.dumps({"error": refusal or (
            "tether: a plugin on this host changed this call so that it names a file in this host's own Hermes "
            "home, so it did not run anywhere. Tell the user; do not retry it.")})
    get_runtime().note_device_use(None, target, kwargs.get("session_id") or None)   # by session, never by key
    try:
        meta, body = get_runtime().call_target(
            "tool", {"name": name, "args": _absolute(dict(args), kwargs.get("task_id"))},
            timeout=TOOL_TIMEOUT_S, target=target, session=kwargs.get("session_id") or None)
    except Exception as e:  # noqa: BLE001 - offline, not allowed, link down: one plain sentence for the model
        return json.dumps({"error": explain(e, target)})
    # The device controls the reply: a reply of the wrong shape is an error, never an exception (see above).
    if not isinstance(meta, dict):
        return json.dumps({"error": _bad_reply(target)})
    text = body.decode(errors="replace")
    if not meta.get("json_dict"):
        result: Any = text
    else:
        try:
            data = json.loads(text)
        except ValueError:
            data = None
        if not isinstance(data, dict):
            return json.dumps({"error": _bad_reply(target)})
        result = data
    return result                                        # Hermes applies post_tool_call and transform_tool_result


def _judge(name: Any, args: dict[str, Any], target: str) -> tuple[bool, Optional[str]]:
    """Whose call this is: (True, None) when every file it names is in this host's own Hermes home, (False, None)
    when it is the device's, (False, refusal) when a V4A patch's files cannot be read or lie on both machines."""
    if name == "patch" and args.get("mode") == "patch":
        # A V4A patch names its files in the patch text, not in 'path': judge those, all of them, or none.
        names = _v4a_names(args.get("patch"))
        if not names:
            return False, ("tether: the files this patch names could not be read, so it did not run anywhere. Send "
                           "one patch per machine.")
        owners = {_host_owned(n) for n in names}
        if len(owners) > 1:
            return False, (f"tether: this patch names files on this host and on {target}, so it did not run "
                           "anywhere. Send one patch per machine.")
        return owners.pop(), None
    return _host_owned(args.get("path")), None


def _bad_reply(target: str) -> str:
    return (f"tether ({target}): {target} sent a reply this host could not read. The call may have run on "
            f"{target}, but its result is lost. Tell the user; do not retry it here or on this host.")


def pinned_fp(device: str) -> str:
    """The key pinned under this name right now (the pins file every Hermes process on the host reads), or "" (an
    unreadable pins file included: nothing cached is trusted). The same read as Runtime.pinned_fp (D43)."""
    return get_runtime().pinned_fp(device)


def _device_facts(target: str) -> dict[str, Any]:
    """The host's view of a device's announce (machine.clean_announce): what the backend uses, never the model.
    Kept for FACTS_TTL_S, and only while the same key is pinned under that name."""
    fp = pinned_fp(target)
    cached = _facts.get(target)
    if cached and cached[1] == fp and time.monotonic() - cached[0] < FACTS_TTL_S:
        return cached[2]
    try:
        rt = get_runtime()
        rows = rt.run(rt.host.list_devices(), 10)
        row = next((r for r in rows if r.get("name") == target), None)
        # the row names the key it describes (its first 16 characters): facts of another key are not this device's
        facts = (row.get("capabilities") or {}) if row and fp and fp.startswith(str(row.get("fp") or "-")) else {}
    except Exception:  # noqa: BLE001 - context is best effort; the tools themselves report problems
        facts = {}
    _facts[target] = (time.monotonic(), fp, facts)
    get_runtime().learn_rules(target, facts)
    return facts


def turn_context(session_id: str = "", user_message: Any = "", **kwargs: Any) -> Optional[str]:
    """pre_llm_call: a user turn starts. Record the user's own words (only they may open or close a device
    connection, D23) and, while a device is open, tell the model where it works. Background reviews never open
    a turn, so their work stays on this host."""
    rt = get_runtime(create=False)
    if rt is None or rt.host is None or not session_id or _is_review():
        return None
    raw = _text(user_message)
    if _unattended(kwargs) or _self_injected(kwargs, raw):
        # Not the user's turn: it opens nothing and records no turn id, so the user's own open turn keeps its
        # device. Empty words mean the devices tool cannot open or close anything in this run (fail closed).
        rt.turn_text[session_id] = ""
        rt.turn_wrapped[session_id] = False
        return _unattended_note(rt, session_id, kwargs.get("parent_session_id") or "")
    rt.turn_open[session_id] = True
    words, added = user_words(raw, **_sender(kwargs))
    event = _turn_event()
    # A forward Hermes passes on as plain text (a Discord, Telegram or Feishu forward), as Hermes reads the message.
    if words and event is not None and getattr(event, "forwarded", False):
        words, added = "", True                          # a forward is someone else's text, even when it says tether
    rt.turn_text[session_id] = words                     # only what the user typed may open or close (D23, D31)
    rt.turn_wrapped[session_id] = added                  # Hermes added text that was refused or dropped
    rt.turn_id[session_id] = str(kwargs.get("turn_id") or "")
    rt.turn_started(session_id, rt.turn_id[session_id])  # D34: this turn id is this session's; earlier holds end
    note = rt.closed_note.pop(session_id, None)
    target = target_for(session_id)
    facts = _device_facts(target) if target else {}
    f = model_view(facts)                                    # the model is shown only the model's view
    if target and target_for(session_id) is None:            # the facts may carry the idle limit: re-check
        target = None
    if target is None:
        note = rt.closed_note.pop(session_id, note)          # route() may have just timed it out
        if note is None:
            note = rt.lost_elsewhere(session_id)             # D34: open in another process, or lost in a restart
        if note:
            rt.forget_tasks(session_id)                      # the model is told here; its tasks start clean
        return f"[tether] {note}" if note else None
    home = shown_home(facts.get("home"))      # the open device's home, in the narrow shape (machine.shown_home)
    where = f" (home {home})" if home else ""
    about = describe(f)
    return (f"[tether] You are working ON the paired machine '{target}'{where}, as if it were your own. "
            f"{about + ' ' if about else ''}Terminal, read_file, write_file, patch, search_files and computer_use act on "
            f"{target} natively, under {target}'s own Hermes rules and permissions. Your terminal starts in your "
            f"workspace there; save results where the user asks. Stay on {target} for the whole task and do not "
            f"carry files or data between {target} and your host. Sub-agents you start, scheduled jobs and Hermes's "
            f"own follow-up turns (/goal and /loop steps, heartbeats, background-job wakes, messages from other "
            f"agents) work on your host, not on {target}. A refusal from {target} is final: report it. "
            f"{_LOCKED_NOTE.format(target=target) if f.get('files_locked') else ''}"
            f"To show the user a file from {target}, put MEDIA:<absolute path on {target}> in your reply. Your "
            "memory, skills and this conversation stay on your host; change skills only with skill_manage. Only "
            "the user can close this connection, by sending 'untether' as a message on its own; inside a longer "
            "message it does nothing, so if they ask to close it any other way, tell them that.")


def _unattended_note(rt: Any, session_id: str, parent: str) -> Optional[str]:
    """What a run the user did not start (a scheduled job, a sub-agent, one of Hermes's own follow-up turns, another
    agent's message) is told when its conversation has a device open; None otherwise."""
    device = rt.active_target(session_id)
    if device == "local" and parent:
        device = rt.active_target(parent)
    if device == "local":
        return None
    return (f"[tether] This run was not started by the user in this conversation (a scheduled job, a sub-agent, a "
            f"/goal or /loop step, a heartbeat, a background-job wake or another agent's message), so it works on "
            f"your host, not on {device}. Do not do work meant for {device} here; say so in your result if the task "
            f"needs {device}. Only the user's own next message reaches {device} again.")


def turn_closed(session_id: str = "", user_message: Any = "", **kwargs: Any) -> None:
    """post_llm_call: the user turn ended; anything after it (a background review) runs on this host. A scheduled
    job or sub-agent never closes the user's turn. The user's words are spent with their turn."""
    rt = get_runtime(create=False)
    if rt is None or not session_id or _is_review() or _unattended(kwargs):
        return None
    ending = str(kwargs.get("turn_id") or "")
    # The turn belongs to the session that opened it. Hermes reports the end under the session id it has now, which
    # differs when it rotated the id during the turn (compression with in_place false).
    owner = rt.turn_owner.get(ending, session_id) if ending else session_id
    open_turn = rt.turn_id.get(owner, "")
    if ending and open_turn and ending != open_turn:
        return None     # the end of an older turn, arriving late: the turn that is open now stays open
    rt.turn_open[owner] = False
    rt.end_lost(owner)                                   # a connection lost in this turn holds nothing back after it
    rt.turn_id.pop(owner, None)
    rt.turn_text[owner] = ""
    rt.turn_wrapped[owner] = False
    if owner != session_id:
        rt.session_moved(owner, session_id)              # D34: the old id's connection closes; the new id is told
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
    # Hermes runs this hook on its own thread, where the tool call's turn is not bound: judge the route by the
    # turn the hook was given, so a background review's skill_view never copies the skill to the device.
    rt, turn = get_runtime(create=False), str(kwargs.get("turn_id") or "")
    previous = rt.begin_call(turn) if rt is not None and turn else None
    try:
        target = target_for(session_id)
    finally:
        if previous is not None:
            rt.end_call(previous)
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
    name = re.sub(r"[^A-Za-z0-9._-]", "_", os.path.basename(os.path.normpath(skill_dir)))[:80] or "skill"
    path = copies.get(skill_dir)
    if path is None:
        packed = _pack(Path(skill_dir))
        if packed is None:
            data["on_device"] = {"device": target, "note": f"this skill is too large to copy to {target}"}
            return json.dumps(data)
        sid = session_id or rt.current_session()
        try:
            meta, _ = rt.call_target("skill_put", {"name": name}, packed, timeout=60, target=target,
                                     session=sid)
        except Exception as e:  # noqa: BLE001 - the skill text still helps; say plainly the files are not there
            data["on_device"] = {"device": target, "note": explain(e, target)}
            return json.dumps(data)
        path = copies[skill_dir] = _skill_copy_path(target, sid, name, meta)
    where = "" if path else f", in skills/{safe_name(name)} inside your workspace there (where your terminal starts)"
    data["on_device"] = {
        "device": target, **({"path": path} if path else {}),
        "note": (f"read-only copy of this skill's files on {target}{where}, for running its scripts there; removed "
                 f"when the {target} connection closes. Change the skill itself only with skill_manage, which saves "
                 "it on your host.")}
    return json.dumps(data)


def _skill_copy_path(target: str, session: str, name: str, meta: Any) -> str:
    """The folder the device says it unpacked the skill into, shown to the model only when it is exactly the one
    the device's workspace makes for it (workspace.Workspaces.put_skill): <workspace_root>/<session>/skills/<name>,
    built here from the workspace root the device announced and the same folder names. Anything else from the
    device is not shown (F58): the model is told where the copy is in its own words instead. "" then."""
    reply = meta.get("path") if isinstance(meta, dict) else None
    root = (_device_facts(target).get("rules") or {}).get("workspace_root")
    if not is_path(root) or not is_path(reply):
        return ""
    sep = "\\" if re.match(r"[A-Za-z]:\\", root) else "/"
    expected = sep.join((root.rstrip(sep), safe_name(session), "skills", safe_name(name)))
    return reply if reply == expected else ""
