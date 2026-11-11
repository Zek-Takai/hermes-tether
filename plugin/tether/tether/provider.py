"""Host side: the ``tether`` terminal backend (design §3, Host role).

Selected with ``terminal.backend: tether``. Each command goes to the session's active target: a paired
device (``devices`` tool, ``use``), or ``local``, which is always a target so the host keeps its own machine.
Approvals (D25): Hermes's own gates run in this session exactly as Hermes runs them, whatever the target:
the dangerous-command card (with its session/always answers, smart mode and yolo) for terminal commands,
the execute_code gate for scripts, the per-action cards for computer use. This backend is not a container,
so none of them is skipped. The device then adds its own floors (hardline, its ``approvals.deny`` rules,
...). A command that reaches the device without having passed the command gate here is judged by the
device's full Hermes rules, and when they flag it the human here is asked through Hermes's command gate.
A command meant for a device never runs on this host: if the connection closes between the gate and the
run, it runs nowhere.
"""
from __future__ import annotations

import logging
import os
import threading
import time
import weakref
from typing import Any, Optional

from .runtime import explain, get_runtime

logger = logging.getLogger(__name__)

CONSENT_SLACK_S = 90       # a first call may wait on the person at the device (consent_timeout_seconds)
GUARD_HANDOFF_S = 600      # gate -> run on one thread, including the time a human takes on the card

_guard = threading.local()   # (command, time) noted when Hermes's command gate checks a command for a device


_ENVS: "weakref.WeakValueDictionary[str, TetherEnvironment]" = weakref.WeakValueDictionary()


def cwd_for(task_id: Optional[str]) -> Optional[str]:
    """Where this task's terminal currently is on the device (file tools resolve relative paths there)."""
    env = _ENVS.get(task_id or "")
    return getattr(env, "cwd", None) if env is not None else None


def current_session() -> str:
    return get_runtime().current_session()


def active_target(session: Optional[str] = None) -> str:
    return get_runtime().active_target(session)


class TetherEnvironment:
    """BaseEnvironment duck type. File tools reach the device through ``execute()``."""

    uses_host_filesystem = False

    def __init__(self, cwd: str, timeout: int, task_id: str) -> None:
        self.cwd, self.timeout, self.task_id = cwd or "~", timeout, task_id
        self._local = None
        self._homes: dict[str, str] = {}
        self._forced = threading.local()          # attachment fallback: run on this device for one call
        self._fetched_from: dict[str, str] = {}   # resolved attachment path -> device it was found on

    def _target(self) -> str:
        return getattr(self._forced, "target", None) or get_runtime().route()

    @property
    def _remote_home(self) -> Optional[str]:
        """Home folder of the active device: Hermes resolves ``~/`` in MEDIA paths with it."""
        target = self._target()
        return os.path.expanduser("~") if target == "local" else self._device_home(target)

    def _device_home(self, device: str) -> Optional[str]:
        if device in self._homes:
            return self._homes[device]
        from .forward import _device_facts
        home = _device_facts(device).get("home")
        if home:
            self._homes[device] = home
        return home

    # Hermes delivers files an agent attaches (MEDIA:<path>) from a remote backend with these two; the
    # BaseEnvironment versions run over execute(), so they reach the active device unchanged. A file that is
    # not on this host (the session switched back to local before replying) is looked up on the device the
    # session last worked on, and re-checked against Hermes's attachment denylist (conservative form).
    def fetch_realpath(self, remote_path: str) -> Optional[str]:
        from tools.environments.base import BaseEnvironment
        resolved = BaseEnvironment.fetch_realpath(self, remote_path)
        if resolved is not None or self._target() != "local":
            return resolved
        device = get_runtime().last_device.get(current_session())
        if not device:
            return None
        self._forced.target = device
        try:
            resolved = BaseEnvironment.fetch_realpath(self, remote_path)
        finally:
            self._forced.target = None
        if resolved is None:
            return None
        try:
            from gateway.media_fetch import remote_path_is_denied
            # No home: Hermes then matches its home-relative entries (.ssh, .aws, Hermes secrets, ...) at ANY path
            # component, the conservative superset, so a symlinked or unexpected device home cannot slip past.
            denied = remote_path_is_denied(resolved, None)
        except Exception:  # noqa: BLE001 - cannot vet it: do not deliver it
            denied = True
        if denied:
            logger.info("tether: attachment %s on %s is on the denylist; not delivered", resolved, device)
            return None
        self._fetched_from[resolved] = device
        return resolved

    def fetch_file(self, remote_path: str, local_dest, *, max_bytes: int) -> None:
        from tools.environments.base import BaseEnvironment
        device = self._fetched_from.pop(remote_path, None)
        if device is None or self._target() != "local":
            return BaseEnvironment.fetch_file(self, remote_path, local_dest, max_bytes=max_bytes)
        self._forced.target = device
        try:
            return BaseEnvironment.fetch_file(self, remote_path, local_dest, max_bytes=max_bytes)
        finally:
            self._forced.target = None

    def execute(self, command: str, cwd: str = "", *, timeout: Optional[int] = None,
                stdin_data: Optional[str] = None, **kwargs: Any) -> dict[str, Any]:
        target = self._target()
        gated = _take_guard_handoff(command)
        if target == "local":
            if gated:
                # Hermes's gate checked this command for a device, and the connection closed before it ran:
                # a command meant for the device never runs on this host.
                return {"output": "tether: the device connection closed before this command ran, so it did not "
                                  "run anywhere. Run it again if it is still wanted.", "returncode": 1}
            return self._run_local(command, cwd, timeout, stdin_data, **kwargs)
        t = int(timeout or self.timeout or 60)
        args: dict[str, Any] = {"command": command, "cwd": cwd or self.cwd, "timeout": t, "host_gate": gated}
        try:
            meta, out = get_runtime().call_target("exec", args, (stdin_data or "").encode(),
                                                  timeout=t + CONSENT_SLACK_S, target=target)
            if meta.get("needs_approval"):
                refused = _ask_human(target, command, meta)
                if refused:
                    return {"output": refused, "returncode": 1}
                args["approved_keys"] = list(meta.get("pattern_keys") or [])
                meta, out = get_runtime().call_target("exec", args, (stdin_data or "").encode(),
                                                      timeout=t + CONSENT_SLACK_S, target=target)
                if meta.get("needs_approval"):
                    return {"output": f"tether ({target}): {target} still flags this command "
                                      f"({meta.get('description')}); it did not run.", "returncode": 1}
        except InterruptedError:
            return {"output": "[interrupted]", "returncode": 130}
        except Exception as e:  # noqa: BLE001 - offline device, denied consent, link loss: tell the model
            return {"output": explain(e, target), "returncode": 1}
        if meta.get("home"):
            self._homes[target] = meta["home"]
        if meta.get("cwd_observed"):
            self.cwd = meta["cwd"]
        return {"output": out.decode(errors="replace"), "returncode": meta.get("returncode", -1),
                "cwd": meta.get("cwd"), "cwd_observed": bool(meta.get("cwd_observed"))}

    def _run_local(self, command, cwd, timeout, stdin_data, **kwargs):
        if self._local is None:
            from tools.environments.local import LocalEnvironment
            self._local = LocalEnvironment(cwd=os.path.expanduser("~"), timeout=self.timeout)
        if cwd and not os.path.isdir(os.path.expanduser(cwd)):
            cwd = ""        # a device path recorded before switching back to local
        return self._local.execute(command, cwd, timeout=timeout, stdin_data=stdin_data, **kwargs)

    def cleanup(self) -> None:
        if self._local is not None:
            self._local.cleanup()
            self._local = None


def _gate_command() -> Optional[str]:
    """The command Hermes's dangerous-command gate is checking, when that gate is the reader (not the
    execute_code gate, which approves a script as a whole: its commands are still judged in full by the
    device). None otherwise."""
    import sys
    f = sys._getframe(1)
    for _ in range(8):
        if f is None:
            return None
        if f.f_code.co_name in ("check_all_command_guards", "check_dangerous_command"):
            command = f.f_locals.get("command")
            return command if isinstance(command, str) else None
        f = f.f_back
    return None


def _take_guard_handoff(command: str) -> bool:
    """True once if Hermes's command gate checked exactly this command for a device on this thread (D25).
    The note is made when the gate starts, before it decides; a different command (one the gate never saw,
    e.g. from an execute_code script) never inherits it, and it is dropped when the tool call ends."""
    note = getattr(_guard, "note", None)
    _guard.note = None
    if note is None:
        return False
    checked, at = note
    return checked == command and time.monotonic() - at < GUARD_HANDOFF_S


def clear_guard_handoff(**_: Any) -> None:
    """post_tool_call hook: whatever the gate decided, its note ends with the tool call that made it."""
    _guard.note = None


def _ask_human(device: str, command: str, meta: dict[str, Any]) -> Optional[str]:
    """The device's rules flagged a command that did not pass Hermes's command gate here: put it through that
    gate now (Hermes's public ``check_dangerous_command``: its card showing the command, its session/always
    answers, its unattended rules). None = approved; otherwise the message for the model."""
    description = str(meta.get("description") or "flagged as dangerous")
    try:
        from tools.approval import check_dangerous_command
        result = check_dangerous_command(command, "local")
    except Exception as e:  # noqa: BLE001 - cannot ask: do not run it
        logger.warning("tether: could not ask for approval: %s", e)
        return f"tether ({device}): {device}'s rules need approval for this command ({description}) and none " \
               "could be asked; it did not run."
    if result.get("approved"):
        return None
    return str(result.get("message") or f"tether ({device}): the command was not approved; it did not run.")


def make_provider():
    from agent.terminal_env_provider import TerminalEnvironmentProvider

    class TetherTerminalProvider(TerminalEnvironmentProvider):
        name = "tether"
        display_name = "tether (paired devices)"
        is_remote = True
        is_container = False
        supports_streams = False      # Bot Desktop is never placed on a device

        @property
        def skip_container_guards(self) -> bool:
            """Never skipped: Hermes's gates always run (D25). Hermes reads this at the start of its command
            gate, on the thread that then runs the command; while a device is the target, note that the
            command went through the gate so the device does not ask the human a second time."""
            rt = get_runtime(create=False)
            if rt is not None and rt.host is not None and rt.route() != "local":
                command = _gate_command()
                if command is not None:
                    _guard.note = (command, time.monotonic())
            return False

        @property
        def description(self) -> str:
            return "Run commands on a paired desktop machine over tether, or on this machine (target local)."

        @property
        def default_cwd(self) -> Optional[str]:
            return "~"

        @property
        def env_description(self) -> str:
            return ("a paired desktop machine reached over tether (see the devices tool), under that machine's own "
                    "Hermes rules and permissions, or this host")

        def is_available(self) -> bool:
            # Every Hermes process with the host role has the link (owner or relay); role off = unavailable.
            rt = get_runtime(create=False)
            return bool(rt is not None and rt.host is not None)

        def create_environment(self, *, cwd: str, timeout: int, task_id: str = "default", image=None,
                               container_config=None, **kwargs: Any) -> TetherEnvironment:
            env = TetherEnvironment(cwd, timeout, task_id)
            _ENVS[task_id] = env
            return env

    return TetherTerminalProvider()
