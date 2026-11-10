"""Device-side handlers: each host call runs inside this machine's own Hermes (design §3, Device role).

Terminal and file tools arrive as ``exec`` and run in a Hermes ``LocalEnvironment`` kept per host session,
so the session snapshot (exported vars, functions) behaves exactly as it does for local use. Every command
is judged by this device's own Hermes rules (``device_rules``, D25): its floors always; its full approval
rules when the command did not pass Hermes's command gate in the host session, sending flagged ones back
for the human there.
Command output travels in the frame body (it can be far larger than a header).
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

ENV_IDLE_S = 30 * 60


class LocalExec:
    def __init__(self, workspaces: Any = None) -> None:
        self._envs: dict[str, tuple[Any, float]] = {}
        self._lock = threading.Lock()
        self.workspaces = workspaces            # D24: each host session's terminal starts in its workspace

    def cwd_for(self, session: str) -> str | None:
        """Where this session's terminal is now (the base for relative paths in its file tools)."""
        with self._lock:
            env = self._envs.get(session, (None, 0))[0]
        return getattr(env, "cwd", None) if env is not None else None

    def drop(self, session: str) -> None:
        with self._lock:
            env = self._envs.pop(session, (None, 0))[0]
        if env is not None:
            _cleanup(env)

    def _env(self, session: str, timeout: int):
        from tools.environments.local import LocalEnvironment
        now = time.monotonic()
        with self._lock:
            for key, (env, used) in list(self._envs.items()):
                if now - used > ENV_IDLE_S and key != session:
                    self._envs.pop(key, None)
                    _cleanup(env)
            env = self._envs.get(session, (None, 0))[0]
            if env is None:
                start = self.workspaces.ensure(session) if self.workspaces is not None else Path.home()
                env = LocalEnvironment(cwd=str(start), timeout=timeout)
            self._envs[session] = (env, now)
            return env

    def close_all(self) -> None:
        with self._lock:
            envs, self._envs = [e for e, _ in self._envs.values()], {}
        for env in envs:
            _cleanup(env)

    async def exec(self, args: dict[str, Any], body: bytes) -> tuple[dict[str, Any], bytes]:
        command = str(args.get("command") or "")
        if not command:
            raise ValueError("exec needs a command")
        from .device_rules import judge
        verdict, info = judge(command, args.get("approved_keys") or (), bool(args.get("host_gate")))
        if verdict == "block":
            raise PermissionError(info["reason"])
        if verdict == "ask":                  # D25: this device's rules flag it; the host asks the human
            logger.info("tether: command needs approval under this device's rules (%s)", info["description"])
            return {"needs_approval": True, **info}, b""
        return await asyncio.to_thread(self._run, args, body)

    def _run(self, args: dict[str, Any], body: bytes) -> tuple[dict[str, Any], bytes]:
        timeout = max(1, int(args.get("timeout") or 60))
        env = self._env(str(args.get("session") or "default"), timeout)
        cwd = str(args.get("cwd") or "")
        session = str(args.get("session") or "default")
        if cwd in ("", "~") and self.workspaces is not None:
            cwd = str(self.workspaces.ensure(session))        # the host's default start: the session workspace
        elif cwd.startswith("~"):
            cwd = os.path.expanduser(cwd)
        if cwd and not os.path.isdir(cwd):
            cwd = ""          # a host-side path (or a folder gone since): stay where this session was
        result = env.execute(command := str(args["command"]), cwd, timeout=timeout,
                             stdin_data=body.decode(errors="replace") if body else None)
        logger.debug("tether exec (%s): rc=%s", command[:60], result.get("returncode"))
        meta = {"returncode": result.get("returncode", result.get("exit_code", -1)),
                "cwd": result.get("cwd") or env.cwd, "cwd_observed": bool(result.get("cwd_observed")),
                "home": str(Path.home())}
        return meta, str(result.get("output") or "").encode()


def _cleanup(env: Any) -> None:
    try:
        env.cleanup()
    except Exception:  # noqa: BLE001
        logger.debug("tether: env cleanup failed", exc_info=True)


DEVICE_TOOLS = frozenset({"read_file", "write_file", "patch", "search_files"})


class ToolRunner:
    """Runs a host's file tool here, through this machine's own Hermes (``ctx.dispatch_tool``): its paths, its
    file rules, its write fence, its credential protections, exactly as for local use (design D22). Only the
    tools in DEVICE_TOOLS are lent; anything else is refused."""

    def __init__(self, ctx: Any, local_exec: Any = None, workspaces: Any = None) -> None:
        self.ctx, self.local_exec, self.workspaces = ctx, local_exec, workspaces

    async def run(self, args: dict[str, Any], body: bytes) -> tuple[dict[str, Any], bytes]:
        name = str(args.get("name") or "")
        if name not in DEVICE_TOOLS:
            raise PermissionError(f"this device does not lend {name!r} over tether")
        tool_args = dict(args.get("args") or {})
        session = str(args.get("session") or "default")
        return await asyncio.to_thread(self._run, name, tool_args, session)

    def _base(self, session: str) -> str | None:
        cwd = self.local_exec.cwd_for(session) if self.local_exec is not None else None
        if cwd and os.path.isabs(cwd):
            return cwd
        return str(self.workspaces.ensure(session)) if self.workspaces is not None else None

    def _run(self, name: str, tool_args: dict[str, Any], session: str) -> tuple[dict[str, Any], bytes]:
        path = tool_args.get("path")
        if isinstance(path, str) and path and not path.startswith(("/", "~")):
            base = self._base(session)           # relative = from where this session's terminal is, here
            if base:
                tool_args = {**tool_args, "path": os.path.normpath(os.path.join(base, path))}
        result = self.ctx.dispatch_tool(name, tool_args, task_id=f"tether-{session}")
        if isinstance(result, dict):
            return {"json_dict": True}, json.dumps(result).encode()
        return {}, str(result).encode()


class SessionControl:
    """Device-side handlers for the connection itself (D23/D24): closing a session and receiving skill copies."""

    def __init__(self, consent: Any, workspaces: Any, local_exec: LocalExec, host_fp: Any) -> None:
        self.consent, self.workspaces, self.local_exec, self.host_fp = consent, workspaces, local_exec, host_fp

    async def close_session(self, args: dict[str, Any], body: bytes) -> tuple[dict[str, Any], bytes]:
        session = str(args.get("session") or "default")
        self.consent.revoke(self.host_fp(), session)
        self.local_exec.drop(session)
        wiped = await asyncio.to_thread(self.workspaces.wipe, session)
        logger.info("tether: session %s closed by the host (workspace %s)", session, "removed" if wiped else "none")
        from .store import log_event
        log_event(getattr(self.consent, "events_dir", None), "session_closed", session=session,
                  reason="workspace emptied" if wiped else "")
        return {"closed": True, "workspace_removed": wiped}, b""

    async def skill_put(self, args: dict[str, Any], body: bytes) -> tuple[dict[str, Any], bytes]:
        if not body:
            raise ValueError("skill_put needs the skill's files")
        session = str(args.get("session") or "default")
        dest = await asyncio.to_thread(self.workspaces.put_skill, session, str(args.get("name") or "skill"), body)
        return {"path": str(dest)}, b""


def rules() -> dict[str, Any]:
    """Whose rules apply on this device, announced to the host and shown in `devices list`."""
    try:
        from hermes_constants import get_hermes_home
        hermes_home = str(get_hermes_home())
    except Exception:  # noqa: BLE001
        hermes_home = ""
    return {"home": str(Path.home()), "hermes_home": hermes_home,
            "write_safe_root": os.getenv("HERMES_WRITE_SAFE_ROOT") or None,
            "judged_by": "this device's own Hermes (its config, approvals and file rules)"}


def capabilities() -> dict[str, Any]:
    return {"terminal": True, "home": str(Path.home()), "rules": rules()}
