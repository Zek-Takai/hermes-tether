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
import re
import shlex
import sys
import threading
import time
import weakref
from contextlib import contextmanager
from typing import Any, Iterator, Optional

from .device_exec import first_pid, job_group_of, stop_job_tree
from .runtime import BgJob, explain, get_runtime, shared

logger = logging.getLogger(__name__)

CONSENT_SLACK_S = 90       # a first call may wait on the person at the device (consent_timeout_seconds)
GUARD_HANDOFF_S = 600      # gate -> run on one thread, including the time a human takes on the card

# Kept on the shared runtime handle, not in this module: Hermes may load this file again (a forced plugin
# re-discovery) while terminals made by the earlier copy are alive, and every copy must see the same state.
_guard = shared("guard_state", threading.local)   # (command, time) noted when Hermes's gate checks a command
_host = shared("host_state", threading.local)     # depth of host_only() blocks on this thread (host's work)
_ENVS: "weakref.WeakValueDictionary[str, TetherEnvironment]" = shared("envs", weakref.WeakValueDictionary)


def host_home() -> str:
    """This host's Hermes home (the active profile's): the folder that host-owned paths are judged against."""
    try:
        from hermes_constants import get_hermes_home
        return str(get_hermes_home())
    except Exception:  # noqa: BLE001 - tests / outside Hermes
        return os.path.expanduser(os.environ.get("HERMES_HOME") or "~/.hermes")


def within(path: str, root: str) -> bool:
    """True when path is root or lies under it (both normalised). Case-folded on macOS and Windows, whose
    volumes are case-insensitive by default."""
    if sys.platform in ("darwin", "win32"):
        path, root = path.lower(), root.lower()
    root = root.rstrip("/\\")
    return path == root or path.startswith((root + "/", root + os.sep))


@contextmanager
def host_only() -> Iterator[None]:
    """This thread's work is the host's own (its Hermes home): it runs here even while a device is tethered.
    A depth counter, not a flag, so nested blocks and exceptions restore the outer state."""
    depth = getattr(_host, "depth", 0)
    _host.depth = depth + 1
    try:
        yield
    finally:
        _host.depth = depth


def _host_only_active() -> bool:
    return getattr(_host, "depth", 0) > 0


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
    # Hermes's plugin contract (tools/environments/base.py): background jobs outlive cleanup() and stay reachable
    # through this object (a device job by its record, a host job on this host), so Hermes's teardown must not
    # mark them lost; their pollers keep collecting the real result.
    cleanup_stops_processes = False

    def __init__(self, cwd: str, timeout: int, task_id: str) -> None:
        self.cwd, self.timeout, self.task_id = cwd or "~", timeout, task_id
        self._local = None
        self._homes: dict[str, tuple[str, str]] = {}   # device -> (key pinned for it then, its home)
        self._forced = threading.local()          # attachment fallback: run on this device for one call
        self._fetched_from: dict[str, str] = {}   # resolved attachment path -> device it was found on

    def _target(self) -> str:
        if _host_only_active():     # Hermes's own files: the host's, whatever device is tethered
            return "local"
        return getattr(self._forced, "target", None) or get_runtime().route()

    @property
    def _remote_home(self) -> Optional[str]:
        """Home folder of the active device, as its shell names it: Hermes resolves ``~/`` in MEDIA paths with it
        and checks its attachment denylist under it. None when the device's home has no usual shape: Hermes then
        uses its conservative denylist (home-relative entries at any path component)."""
        target = self._target()
        return os.path.expanduser("~") if target == "local" else self._device_home(target)

    def _device_home(self, device: str) -> Optional[str]:
        """Kept per name and key: after a re-pair under the same name, the previous machine's home is not used (F61).
        Only a home of the usual shape, in the form the device's shell prints it, is kept (_shell_home)."""
        from .forward import _device_facts, pinned_fp
        fp = pinned_fp(device)
        kept = self._homes.get(device)
        if kept is not None and kept[0] == fp:
            return kept[1]
        home = _shell_home(_device_facts(device).get("home"))
        if home:
            self._homes[device] = (fp, home)
        else:
            self._homes.pop(device, None)
        return home

    def agent_visible_cache_base(self) -> str:
        """Where the agent sees Hermes's media cache (generated images): at this host's own Hermes home, its real
        place. Nothing copies the cache to a device, and paths in the home are the host's (forward._host_owned).
        Hermes's image tool then keeps the host path, instead of naming a device path built from the device's
        home (tools/image_generation_tool._agent_cache_base_for_env reads this before _remote_home)."""
        return host_home()

    # Hermes delivers files an agent attaches (MEDIA:<path>) from a remote backend with these two; the
    # BaseEnvironment versions run over execute(), so they reach the active device unchanged. A file that is
    # not on this host (the session switched back to local before replying) is looked up on the device the
    # session last worked on. Every file found on a device is checked here too (_attachment_denied), whatever
    # home Hermes was given.
    def fetch_realpath(self, remote_path: str) -> Optional[str]:
        from tools.environments.base import BaseEnvironment
        target = self._target()
        resolved = BaseEnvironment.fetch_realpath(self, remote_path)
        if target != "local":
            return None if resolved is None or self._attachment_denied(resolved, target) else resolved
        if resolved is not None:
            return resolved                 # on this host: Hermes's own checks, with this host's home
        device = get_runtime().last_device.get(current_session())
        if not device:
            return None
        self._forced.target = device
        try:
            resolved = BaseEnvironment.fetch_realpath(self, remote_path)
        finally:
            self._forced.target = None
        if resolved is None or self._attachment_denied(resolved, device):
            return None
        self._fetched_from[resolved] = device
        return resolved

    def _attachment_denied(self, resolved: str, device: str) -> bool:
        """True when a file found on a device must not be delivered as an attachment: Hermes's attachment denylist
        with no home (its home-relative entries, .ssh, .aws, Hermes's secrets, ..., then match at ANY path
        component, so an unexpected device home cannot slip past), or the device's own Hermes home outside the
        session workspaces (_in_device_hermes_home). A file that cannot be checked is not delivered."""
        try:
            from gateway.media_fetch import remote_path_is_denied
            denied = remote_path_is_denied(resolved, None)
            if not denied:
                from .forward import _device_facts
                hermes_home = _shell_path((_device_facts(device).get("rules") or {}).get("hermes_home"))
                denied = _in_device_hermes_home(resolved, hermes_home)
        except Exception:  # noqa: BLE001 - cannot vet it: do not deliver it
            denied = True
        if denied:
            logger.info("tether: an attachment on %s is on the denylist; not delivered", device)
        return denied

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

    def get_temp_dir(self) -> str:
        """Hermes keeps a background job's files here, on the machine that runs it: /tmp exists on the host,
        on macOS and Linux devices, and in Git Bash on Windows devices."""
        return BG_TEMP

    def execute(self, command: str, cwd: str = "", *, timeout: Optional[int] = None,
                stdin_data: Optional[str] = None, **kwargs: Any) -> dict[str, Any]:
        site = _hermes_site()                           # which of Hermes's own code sent this, if any
        gated = _take_guard_handoff(command, site)      # always consumed, even for host-only work
        gated = gated or _per_call_cleanup(site, command)
        if _spill_probe(command):
            # Hermes asks whether its spill file for a large result is readable before it copies the whole result
            # into the sandbox. That file is on this host, so the answer comes from this host: the result never
            # reaches a device.
            return self._run_local(command, cwd, timeout, stdin_data, **kwargs)
        media = _host_media_read(command)
        if media is not None:
            # Hermes's vision/video read of a file "inside the sandbox", for a file in this host's own Hermes home
            # (a skill's image): that file is the host's, so it is read here, never on the device (same path,
            # wrong machine). Hermes's credential-read guard applies, as it does to its own host reads.
            try:
                from agent.file_safety import get_read_block_error
                blocked = get_read_block_error(media)
            except Exception:  # noqa: BLE001 - cannot check it: do not read it
                blocked = "tether: this file could not be checked, so it was not read"
            if blocked:
                return {"output": blocked, "returncode": 1}
            return self._run_local(command, cwd, timeout, stdin_data, **kwargs)
        kind, hermes_job = site if site is not None else ("", None)
        if kind == "kernel":
            # Hermes's persistent remote session kernel is not used over tether: it would leave a runner behind on
            # the machine and later probe and stop it by pid through whatever the route is then. Nothing runs;
            # Hermes falls back to its per-call path (one foreground command per script, on the routed machine).
            return {"output": KERNEL_OFF, "returncode": 1}
        if kind in ("poll", "kill"):
            # Hermes's own poll, status read or stop of one of its background jobs: to the machine the job started
            # on, under the job's own session, whoever asks (the poller, the parent, a sub-agent, /stop) and
            # whatever the route is now (D38).
            return self._run_job(kind, hermes_job, command, cwd, timeout, stdin_data, **kwargs)
        if kind == "other":
            raise RuntimeError(f"tether does not recognise this command from Hermes's background-job code, so it "
                               f"was not run. {UNTRACKED}")
        if kind == "spawn" and spawned_job_id(command) != getattr(hermes_job, "id", None):
            raise RuntimeError(f"tether cannot recognise this background job's start command, so it could not be "
                               f"checked or stopped later; it was not started. {UNTRACKED}")
        target = self._target()
        if target != "local" and stdin_data and _sandbox_spill(command):
            # Hermes copies an oversized result into the sandbox when its own spill file on this host could not be
            # written. A host result never goes to a device: refused, Hermes shows the result shortened instead.
            return {"output": "tether: a large result is not copied to a device", "returncode": 1}
        result = self._routed(target, gated, command, cwd, timeout, stdin_data, **kwargs)
        if kind == "spawn":
            _record_job(hermes_job, target, result.get("output", ""))
        return result

    def _run_job(self, kind: str, hermes_job: Any, command: str, cwd: str, timeout: Optional[int],
                 stdin_data: Optional[str], **kwargs: Any) -> dict[str, Any]:
        """One of Hermes's own commands for a job it started through this backend. Anything that cannot be matched
        to the job's record and its exact text runs nowhere and raises: Hermes then marks a poll's job lost and
        reports a stop as an error, never as done."""
        rt = get_runtime()
        job = rt.bg_job(getattr(hermes_job, "id", None))
        if job is None:
            raise RuntimeError(f"tether has no record of where this background job runs, so nothing was sent. "
                               f"{UNTRACKED}")
        if kind == "kill":
            if job.pid is None or getattr(hermes_job, "pid", None) != job.pid or \
                    command != f"kill {job.pid} 2>/dev/null":
                raise RuntimeError(f"tether does not recognise this stop of a background job, so nothing was "
                                   f"stopped. {UNTRACKED}")
            if job.machine == "local":
                why = stop_job_tree(job.pid, job.pgid, job.exit_path)
                if why:
                    raise RuntimeError(f"the job on this host was not stopped: {why}")
                return {"output": "", "returncode": 0}
            return rt.bg_call(job, command, max(int(timeout or 0), STOP_TIMEOUT_S), stop=True)
        if not _status_text(job, command):
            raise RuntimeError(f"tether does not recognise this status read of a background job, so it was not "
                               f"run. {UNTRACKED}")
        if job.machine == "local":
            return self._run_local(command, cwd, timeout, stdin_data, **kwargs)
        return rt.bg_call(job, command, int(timeout or self.timeout or 60))

    def _routed(self, target: str, gated: bool, command: str, cwd: str, timeout: Optional[int],
                stdin_data: Optional[str], **kwargs: Any) -> dict[str, Any]:
        if _host_only_active():
            # Host-owned file work (forward.host_only): not a command meant for a device, so no lost-link or
            # gate refusal applies here; it runs on this host.
            return self._run_local(command, cwd, timeout, stdin_data, **kwargs)
        if target == "local":
            # D34, judged by the calling session and its turn, never by self.task_id: Hermes gives this environment
            # its container key, which a parent, its sub-agents, its /bg runs and the next conversation of the same
            # chat share, and which differs from the key its file tools carry.
            lost = get_runtime().lost_device()
            if lost:
                # This session's model works on a device whose connection is gone. A command written for that
                # machine does not quietly run here instead; the model is told, with the reason.
                return {"output": lost, "returncode": 1}
            if gated:
                # Hermes's gate checked this command for a device, and the connection closed before it ran:
                # a command meant for the device never runs on this host.
                return {"output": "tether: the device connection closed before this command ran, so it did not "
                                  "run anywhere. Run it again if it is still wanted.", "returncode": 1}
            return self._run_local(command, cwd, timeout, stdin_data, **kwargs)
        get_runtime().note_device_use(None, target)     # by the calling session (D34), not by this key
        t = int(timeout or self.timeout or 60)
        args: dict[str, Any] = {"command": command, "cwd": cwd or self.cwd, "timeout": t, "host_gate": gated}
        # The target must be the session's open connection (the attachment fallback included: it reads from the
        # device the session is still connected to); call_target refuses anything else before a prompt can show.
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
        home = _shell_home(meta.get("home"))       # the device's reply: the same check as its announce
        if home:
            from .forward import pinned_fp
            self._homes[target] = (pinned_fp(target), home)
        if meta.get("cwd_observed"):
            self.cwd = meta["cwd"]
        return {"output": out.decode(errors="replace"), "returncode": meta.get("returncode", -1),
                "cwd": meta.get("cwd"), "cwd_observed": bool(meta.get("cwd_observed"))}

    def _run_local(self, command, cwd, timeout, stdin_data, **kwargs):
        from .identity import blank_env, shield_children
        # Hermes may have loaded .env into the environment again since start-up: out of os.environ again (other
        # spawn paths read it), and the mask refreshed. The terminal's own env blanks the names in every child it
        # starts, whatever os.environ or a multiplexed profile's secret scope holds at that moment.
        shield_children()
        if self._local is None:
            from tools.environments.local import LocalEnvironment
            self._local = LocalEnvironment(cwd=os.path.expanduser("~"), timeout=self.timeout, env=blank_env())
        if cwd and not os.path.isdir(os.path.expanduser(cwd)):
            cwd = ""        # a device path recorded before switching back to local
        return self._local.execute(command, cwd, timeout=timeout, stdin_data=stdin_data, **kwargs)

    def cleanup(self) -> None:
        if self._local is not None:
            self._local.cleanup()
            self._local = None


# ---------- background jobs: Hermes's terminal tool with background=true (process_registry.spawn_via_env) ----------
# Hermes wraps the command once (a job id, three files in its temp folder, the pid), then a poller thread runs a
# poll command every 2 s (and two status reads when a reply is unreadable), and a stop runs "kill <pid>". The text
# alone cannot tell Hermes's command from the same text typed by the model, and the caller's session or turn says
# nothing either (a sub-agent's teardown stops its jobs on the parent's thread). So a command is a job's own only
# when Hermes's registry sent it (its spawn, poller or stop, read from the call stack as _gate_command does) AND
# its whole text equals what Hermes builds for that very job (by Hermes's job id, never by pid). Everything else,
# whatever it mentions, is an ordinary command for the current route.
BG_TEMP = "/tmp"                 # the temp folder Hermes uses for a job's files (TetherEnvironment.get_temp_dir)
_OFFSET = re.compile(r"O=([0-9]{1,20}); ")
_SPAWN_TAIL = re.compile(r"echo \$! > /tmp/hermes_bg_(proc_[0-9a-f]{12})\.pid && cat /tmp/hermes_bg_\1\.pid\Z")
_REGISTRY = "tools.process_registry"          # Hermes's background-job registry (spawn, poller, stop)
_JOB_SITES = {"spawn_via_env": "spawn", "_env_poller_loop": "poll", "_signal_kill": "kill"}
_KERNEL = "tools.code_kernel_remote"          # Hermes's persistent remote session kernel (execute_code)
_PER_CALL = ("tools.code_execution_tool", "_run_remote_per_call")   # execute_code's per-call path
_PER_CALL_DIR = re.compile(r"/tmp/hermes_exec_[0-9a-f]{12}")       # the folder it makes, and removes, per script
STOP_TIMEOUT_S = 20              # a stop waits for the job's processes to end (device_exec.STOP_GRACE_S, then SIGKILL)
KERNEL_OFF = ("tether: Hermes's persistent remote kernel is not used over tether; execute_code runs each script "
              "as one command instead")
UNTRACKED = "Tell the user; the job may need to be checked at the machine it runs on."


def _hermes_site(depth: int = 2) -> Optional[tuple[str, Any]]:
    """Which of Hermes's own call sites sent the command now in TetherEnvironment.execute: ("spawn" | "poll" |
    "kill", Hermes's ProcessSession for the job) from its background-job registry, ("other", None) from any other
    function of that registry, ("kernel", None) from its remote session kernel, ("percall", the script folder) from
    execute_code's per-call path; None for anything else (a command the model wrote, a file tool). Read from the
    call stack, like _gate_command: Hermes passes nothing else that says who is asking."""
    f = sys._getframe(depth)
    for _ in range(6):
        if f is None:
            return None
        module = f.f_globals.get("__name__", "")
        if module == _KERNEL:
            return ("kernel", None)
        if module == _REGISTRY:
            kind = _JOB_SITES.get(f.f_code.co_name)
            return (kind, f.f_locals.get("session")) if kind else ("other", None)
        if (module, f.f_code.co_name) == _PER_CALL:
            return ("percall", f.f_locals.get("quoted_sandbox_dir"))
        f = f.f_back
    return None


def _per_call_cleanup(site: Optional[tuple[str, Any]], command: str) -> bool:
    """True when command is exactly execute_code's own removal of the script folder it made for this call (Hermes's
    text, never the model's): the device's floors still apply, but nobody is asked about it (F47, D54)."""
    if site is None or site[0] != "percall" or not isinstance(site[1], str):
        return False
    return bool(_PER_CALL_DIR.fullmatch(site[1])) and command == f"rm -rf {site[1]}"


def _spill_probe(command: str) -> bool:
    """True when command is exactly Hermes's readability probe ('test -r <path>') for a spill file in this host's
    own cache/spillover folder (tools.tool_result_storage writes those on the host). Matched on the exact text."""
    prefix = "test -r "
    if not command.startswith(prefix):
        return False
    try:
        words = shlex.split(command[len(prefix):])
    except ValueError:
        return False
    if len(words) != 1 or command != prefix + shlex.quote(words[0]):
        return False
    literal = os.path.normpath(os.path.abspath(os.path.expanduser(words[0])))
    spill = os.path.join(host_home(), "cache", "spillover")
    roots = {os.path.normpath(os.path.abspath(spill)), os.path.realpath(spill)}
    return any(within(p, r) for p in {literal, os.path.realpath(literal)} for r in roots)


def _sandbox_spill(command: str) -> bool:
    """True when command is exactly Hermes's copy of an oversized tool result into the sandbox temp folder
    (tools.tool_result_storage._write_to_sandbox into <get_temp_dir()>/hermes-results/<name>), which Hermes sends
    when its spill file on this host could not be written. Matched on the exact text Hermes builds; if Hermes's
    helper cannot be read, any command that starts the same way and names that folder counts (refused)."""
    folder = f"{BG_TEMP}/hermes-results"
    try:
        from tools.code_execution_rpc import _private_dirs_cmd
        head = f"{_private_dirs_cmd(folder)} && cat > "
    except Exception:  # noqa: BLE001 - fail closed: such a command is refused, never sent to a device
        return command.startswith("umask 077 && ") and f"{folder}/" in command
    if not command.startswith(head):
        return False
    try:
        words = shlex.split(command[len(head):])
    except ValueError:
        return False
    if len(words) != 1 or command != head + shlex.quote(words[0]) or not words[0].startswith(folder + "/"):
        return False
    name = words[0][len(folder) + 1:]
    return bool(name) and "/" not in name


def _host_media_read(command: str) -> Optional[str]:
    """The file, when command is exactly Hermes's in-sandbox read of a media file for vision_analyze or
    video_analyze (tools.image_source._resolve_container_fallback: head -c <cap> < <path> | base64 | tr -d '\\n')
    and that file is in this host's own Hermes home (forward._host_owned). None for anything else, which stays an
    ordinary command."""
    try:
        from tools.image_source import _MAX_INGEST_BYTES
    except Exception:  # noqa: BLE001 - Hermes's reader is not here: nothing is recognised
        return None
    head, tail = f"head -c {_MAX_INGEST_BYTES + 1} < ", " | base64 | tr -d '\\n'"
    if len(command) <= len(head) + len(tail) or not (command.startswith(head) and command.endswith(tail)):
        return None
    try:
        words = shlex.split(command[len(head):len(command) - len(tail)])
    except ValueError:
        return None
    if len(words) != 1 or command != head + shlex.quote(words[0]) + tail:
        return None
    from .forward import _host_owned
    return words[0] if _host_owned(words[0]) else None


_DRIVE_PATH = re.compile(r"([A-Za-z]):[\\/](.*)", re.S)


def _shell_path(value: Any) -> Optional[str]:
    """An absolute path a device announced, in the form its shell prints it: a Windows path (C:\\Users\\Ada) in Git
    Bash's form (/c/Users/Ada), a POSIX path as it is. None for anything that is not a plain absolute path."""
    from .machine import is_path
    if not is_path(value):
        return None
    m = _DRIVE_PATH.fullmatch(value)
    if m is None:
        return value
    return ("/" + m.group(1).lower() + "/" + m.group(2).replace("\\", "/")).rstrip("/")


# Hermes's own home on a Windows device (%LOCALAPPDATA%\hermes, in Git Bash form) and the session workspaces tether
# keeps inside a Hermes home (a named profile's too), matched on a lower-cased path that ends with "/".
_WINDOWS_HERMES_HOME = "/appdata/local/hermes/"
_WORKSPACES_IN_HOME = re.compile(r"(?:profiles/[^/]+/)?tether/sessions/[^/]")


def _in_device_hermes_home(path: str, hermes_home: Optional[str]) -> bool:
    """True when a device path lies in that device's own Hermes home (its secrets, memories, chats), as the device
    announced it or, on Windows, at Hermes's default place, but not in a session workspace tether keeps there
    (<home>/tether/sessions/<session>/..., where the agent's own files are). Case-insensitive, as device volumes
    may be; a fixed rule, so a device cannot announce a home that hides another one."""
    folded = path.lower().rstrip("/") + "/"
    roots = [_WINDOWS_HERMES_HOME] + ([hermes_home.lower().rstrip("/") + "/"] if hermes_home else [])
    for root in roots:
        at = folded.find(root) if root == _WINDOWS_HERMES_HOME else (0 if folded.startswith(root) else -1)
        if at >= 0 and not _WORKSPACES_IN_HOME.match(folded, at + len(root)):
            return True
    return False


def _shell_home(value: Any) -> Optional[str]:
    """A device's home folder in its shell's form, or None unless it has the usual home-folder shape
    (machine.is_home_folder: the one shape the model may be shown, D37)."""
    from .machine import is_home_folder
    return _shell_path(value) if is_home_folder(value) else None


def _job_paths(job_id: str) -> tuple[str, str, str]:
    log, pid, done = (f"{BG_TEMP}/hermes_bg_{job_id}.{ext}" for ext in ("log", "pid", "exit"))
    return log, pid, done


def _spawn_text(job_id: str, command: str) -> str:
    """The wrapper Hermes's spawn_via_env builds for one job: same words, same quoting."""
    q = shlex.quote
    log, pid, done = _job_paths(job_id)
    return (f"mkdir -p {q(BG_TEMP)} && ( nohup bash -lc {q(command)} > {q(log)} 2>&1; "
            f"rc=$?; printf '%s\\n' \"$rc\" > {q(done)} ) & echo $! > {q(pid)} && cat {q(pid)}")


def _poll_text(job: BgJob, offset: int) -> str:
    from tools.process_registry_env_log import log_delta_command
    q = shlex.quote
    return log_delta_command(q(job.log), offset, q(job.pid_path), q(job.exit_path))


def _probe_texts(job: BgJob) -> list[str]:
    """The two fallback status reads Hermes sends when a poll reply is unreadable (its own function, recorded)."""
    from tools.process_registry_env_log import fallback_exit_code
    sent: list[str] = []

    class _Recorder:
        def execute(self, command: str, *args: Any, **kwargs: Any) -> dict[str, Any]:
            sent.append(command)      # only the text matters; Hermes 0.23.3 also passes cwd="/" and a timeout
            return {"output": "1" if len(sent) == 1 else "0"}   # 1: not running, so the exit file is read too

    fallback_exit_code(_Recorder(), shlex.quote(job.pid_path), shlex.quote(job.exit_path))
    return sent


def _status_text(job: BgJob, command: str) -> bool:
    """True when command is exactly Hermes's poll of this job (at some offset) or one of its two status reads."""
    try:
        om = _OFFSET.search(command)
        return bool(om and command == _poll_text(job, int(om.group(1)))) or command in _probe_texts(job)
    except Exception:  # noqa: BLE001 - Hermes's helper is missing or changed: fail closed (not recognised)
        logger.warning("tether: cannot read Hermes's background-job commands; refusing to run them", exc_info=True)
        return False


def spawned_job_id(command: str) -> Optional[str]:
    """The job id when command is exactly Hermes's background wrapper for one job (the device uses this too, to
    know which job files a session left behind). Nothing else: a command that only mentions job files is None."""
    m = _SPAWN_TAIL.search(command)
    if m is None or not command.startswith("mkdir -p /tmp && ( nohup bash -lc "):
        return None
    job_id = m.group(1)
    pre, post = _spawn_text(job_id, "\x00").split(shlex.quote("\x00"))
    if len(command) < len(pre) + len(post) or not (command.startswith(pre) and command.endswith(post)):
        return None
    try:
        words = shlex.split(command[len(pre):len(command) - len(post)])
    except ValueError:
        return None
    return job_id if len(words) == 1 and _spawn_text(job_id, words[0]) == command else None


def _record_job(hermes_job: Any, machine: str, output: str) -> None:
    """Remember a job Hermes's spawn_via_env started: where, under which session, its pid (the first all-digit
    line, as Hermes reads it) and, on this host, its process group. Kept while Hermes tracks the job (a weak
    reference to Hermes's own record). A wrapper that printed no pid started nothing and is not recorded."""
    rt = get_runtime(create=False)
    pid = first_pid(output)
    if rt is None or pid is None:
        return
    job_id = hermes_job.id
    log, pid_path, exit_path = _job_paths(job_id)
    try:
        ref = weakref.ref(hermes_job)
    except TypeError:
        ref = None
    rt.bg_start(BgJob(id=job_id, machine=machine, session=current_session(), log=log, pid_path=pid_path,
                      exit_path=exit_path, pid=pid, pgid=job_group_of(pid) if machine == "local" else None,
                      hermes=ref))


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


def _take_guard_handoff(command: str, site: Optional[tuple[str, Any]] = None) -> bool:
    """True once if Hermes's command gate checked exactly this command for a device on this thread (D25), or this
    command is Hermes's own background wrapper (spawn_via_env) of exactly the command the gate checked: Hermes
    gates the model's command, then sends its wrapper, which the person must not be asked about again (F47).
    The note is made when the gate starts, before it decides; a different command (one the gate never saw,
    e.g. from an execute_code script) never inherits it, and it is dropped when the tool call ends."""
    note = getattr(_guard, "note", None)
    _guard.note = None
    if note is None:
        return False
    checked, at = note
    if time.monotonic() - at >= GUARD_HANDOFF_S:
        return False
    if checked == command:
        return True
    if site is None or site[0] != "spawn":
        return False
    hermes_job = site[1]
    job_id = spawned_job_id(command)
    return (job_id is not None and job_id == getattr(hermes_job, "id", None)
            and getattr(hermes_job, "command", None) == checked and _spawn_text(job_id, checked) == command)


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
        def strip_env_keys(self) -> frozenset:
            """Hermes strips these from every child it builds with its own sanitizers (background and PTY
            terminal children, execute_code, helpers it starts), in every process the plugin loads in. Not
            from foreground terminal children (Hermes passes no strip set there): the plugin's own terminals blank
            the names themselves (identity.blank_env). Listing them also makes Hermes drop the plugin's
            session-env None for the same names (DESIGN 5.1); keep them listed anyway."""
            from .identity import LEGACY_PASSPHRASE_SECRETS, PASSPHRASE_SECRET
            return frozenset({PASSPHRASE_SECRET, *LEGACY_PASSPHRASE_SECRETS})

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
