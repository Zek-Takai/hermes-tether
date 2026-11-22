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
import re
import signal
import threading
import time
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

BG_TEMP = "/tmp"                       # the folder Hermes's background wrapper writes a job's three files to
BG_RECORD = "bg_jobs.json"             # device side: ids of background jobs still running when their session closed
JOB_MAX_AGE_S = 24 * 3600.0            # Windows: a job's files are dropped after this, since no pid is probed there
_JOB_ID = re.compile(r"proc_[0-9a-f]{12}")
_JOB_STOP = re.compile(r"kill ([0-9]{1,10}) 2>/dev/null")    # Hermes's stop of a background job (fullmatch)
STOP_GRACE_S = 2.0                     # a stopped job's processes get this long to end before SIGKILL
NO_TREE_STOP = ("tether cannot stop a background job's whole process tree on Windows, so nothing was stopped; "
                "stop it at the machine, or with a command of your own")


def _set_stop(tid: int | None, active: bool) -> None:
    """Sets or clears Hermes's interrupt bit for one worker thread (its terminal wait kills the command when set).
    Without Hermes importable there is nothing to stop, so this does nothing; it never raises."""
    try:
        from tools.interrupt import set_interrupt
        set_interrupt(active, tid)
    except Exception:  # noqa: BLE001 - the stop signal must never fail a command
        pass


def _stop_pending() -> bool:
    """Whether a stop has reached the current worker thread (see _run_stoppable). Without Hermes: never."""
    try:
        from tools.interrupt import is_interrupted
        return bool(is_interrupted())
    except Exception:  # noqa: BLE001
        return False


class _Stop:
    """One stoppable worker: its thread (once it has started) and whether a stop has been asked for."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.cancelled = False
        self.tid: int | None = None
        self.done = False

    def request(self) -> None:
        with self.lock:
            self.cancelled = True
            if self.tid is not None and not self.done:
                _set_stop(self.tid, True)


class _Stops:
    """The stop handles of the calls in flight for one host session (a command from before its terminal is made, a
    file tool, a screen action from before it reaches the driver): closing the session stops every one."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._items: set[_Stop] = set()

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)

    def add(self, stop: _Stop) -> None:
        with self._lock:
            self._items.add(stop)

    def discard(self, stop: _Stop) -> None:
        with self._lock:
            self._items.discard(stop)

    def stop_all(self) -> None:
        with self._lock:
            items = list(self._items)
        for stop in items:
            stop.request()


def _stoppable_worker(stop: _Stop, fn: Any, args: tuple) -> Any:
    tid = threading.get_ident()
    with stop.lock:
        if stop.cancelled:                    # stopped before this thread got to it: do not run at all
            raise InterruptedError("stopped before it started")
        stop.tid = tid
    try:
        return fn(*args)
    finally:
        with stop.lock:
            stop.done = True
            _set_stop(tid, False)             # executor threads are reused: the bit must not outlive this call


async def _run_stoppable(fn: Any, *args: Any, stops: _Stops | None = None, stop: _Stop | None = None,
                         executor: Any = None) -> Any:
    """Runs ``fn(*args)`` in a worker thread. If the awaiting task is cancelled, the worker's command is stopped too.
    A cancel comes from the host stopping the turn, a timed-out host call, or a dropped link (Peer.close cancels the
    handler tasks; Pause drops the link): a command whose result can no longer reach the host is not left running on
    the person's machine. Once a stop has reached the worker, ``fn`` sees it through ``_stop_pending()`` and must not
    start what it was about to start. A session's ``stops`` see the call too, so closing the session stops it.
    ``stop``: a handle the caller made and already registered (LocalExec.stops_for), so a stop that lands before this
    runs is kept: the worker then refuses to start. ``executor``: where the worker runs (default: the loop's)."""
    stop = stop if stop is not None else _Stop()
    if stops is not None:
        stops.add(stop)                       # a set: no change when the caller registered it already
    try:
        if executor is None:
            return await asyncio.to_thread(_stoppable_worker, stop, fn, args)
        return await asyncio.get_running_loop().run_in_executor(executor, _stoppable_worker, stop, fn, args)
    except asyncio.CancelledError:
        stop.request()
        raise
    finally:
        if stops is not None:
            stops.discard(stop)


def _bg_dir() -> str:
    """Where the wrapper's files really are on this machine. The wrapper names /tmp; in Git Bash on Windows
    that is the user's temp folder (MSYS mounts /tmp there), which Python has to be told."""
    if os.name == "nt":
        import tempfile
        return tempfile.gettempdir()
    return BG_TEMP


def job_paths(job_id: str) -> tuple[str, str, str]:
    """(log, pid, exit) of one background job: the only three names this module ever deletes."""
    folder = _bg_dir()
    return tuple(os.path.join(folder, f"hermes_bg_{job_id}.{ext}") for ext in ("log", "pid", "exit"))


def _job_ended(job_id: str, pgid: Optional[int] = None) -> bool:
    """Ended when its .exit file exists and, on POSIX with the job's own process group known, that group has no live
    process (the file is in the shared temp folder, where a session's command can write it: R4-2). Without one, POSIX
    asks the pid from its .pid file (a dead pid has ended, unless the job's own process group, when known, still has a
    process: the wrapper was killed and the command it started runs on). Windows never probes a pid (os.kill(pid, 0)
    would end the process there): it waits for .exit or the age limit."""
    _, pid_path, exit_path = job_paths(job_id)
    exited = os.path.exists(exit_path)
    if exited and (os.name == "nt" or not pgid):
        return True
    try:
        started = os.path.getmtime(pid_path)
    except OSError:
        return True                      # no pid file: the job was never started, or its files are already gone
    if os.name == "nt":
        return time.time() - started > JOB_MAX_AGE_S
    if exited:
        return not (pgid > 1 and pgid != os.getpgrp() and _group_running(pgid))
    try:
        pid = int(Path(pid_path).read_text().strip())
        os.kill(pid, 0)
    except ProcessLookupError:
        group = _job_group(pid, pgid)
        return not (group is not None and _group_running(group))
    except (OSError, ValueError):
        return False                     # cannot tell (permissions, unreadable): keep it for the next pass
    return False


# ---------- stopping a background job: Hermes's own stop ("kill <wrapper pid>") ends only Hermes's wrapper, and the
# command it started would run on. Used on a device (LocalExec) and on the host (provider, a job on "local"). POSIX.
def _running(pid: int) -> bool:
    """True while pid is a live process (a zombie, already dead and waiting to be reaped, is not)."""
    try:
        import psutil
    except ImportError:
        psutil = None
    if psutil is not None:
        try:
            return psutil.Process(pid).status() != psutil.STATUS_ZOMBIE
        except psutil.NoSuchProcess:
            return False
        except (psutil.AccessDenied, OSError):
            return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True
    return True


def _group_running(pgid: int) -> bool:
    """True while the process group pgid has a live (non-zombie) member."""
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True
    try:
        import psutil
    except ImportError:
        return True
    for proc in psutil.process_iter():
        try:
            if os.getpgid(proc.pid) == pgid and proc.status() != psutil.STATUS_ZOMBIE:
                return True
        except (OSError, psutil.Error):
            continue
    return False


def _job_group(pid: int, pgid: Optional[int]) -> Optional[int]:
    """The job's own process group, only when it can be told apart from anything else: never this process's own
    group; while the wrapper lives, only if the wrapper is still in it; once the wrapper is gone, only while no live
    process holds the group's number (POSIX gives no new process that number while the group exists, so a live
    holder means the number was reused). None otherwise."""
    if not pgid or pgid <= 1 or pgid == os.getpgrp():
        return None
    if _running(pid):
        try:
            return pgid if os.getpgid(pid) == pgid else None
        except OSError:
            return None
    return None if _running(pgid) else pgid


def _descendants(pid: int) -> list:
    try:
        import psutil
        return psutil.Process(pid).children(recursive=True)
    except Exception:  # noqa: BLE001 - no psutil, or the wrapper just ended: the group still covers the job
        return []


def stop_job_tree(pid: int, pgid: Optional[int], exit_path: str) -> Optional[str]:
    """Stops one background job Hermes started: its wrapper, every process in the job's own process group, and the
    wrapper's descendants that left that group; SIGTERM, then SIGKILL after STOP_GRACE_S. Returns None when nothing
    of the job runs any more, otherwise one sentence saying why the stop did not happen (the caller reports it).
    The job's .exit file is never taken as proof on its own: it is in the shared temp folder, where the session's own
    commands can write it (R4-2). What still runs of the job decides; the file only explains a reused number."""
    wrapper = _running(pid)
    if wrapper and pgid:
        try:
            if os.getpgid(pid) != pgid:
                if os.path.exists(exit_path) and not _group_running(pgid):
                    return None          # the wrapper wrote its exit code and its number went to another program
                return ("the job's process number now belongs to another program (the job had already ended or was "
                        "stopped another way), so nothing was stopped")
        except OSError:
            wrapper = _running(pid)
    group = _job_group(pid, pgid)
    procs = _descendants(pid) if wrapper else []

    def send(sig: int) -> None:
        if group is not None:
            try:
                os.killpg(group, sig)
            except OSError:
                pass
        if wrapper:
            try:
                os.kill(pid, sig)
            except OSError:
                pass
        for proc in procs:
            try:
                proc.send_signal(sig)     # psutil checks the process is still the one it saw (no reused pid)
            except Exception:  # noqa: BLE001
                pass

    def gone(seconds: float) -> bool:
        end = time.monotonic() + seconds
        while True:
            left = ((wrapper and _running(pid)) or (group is not None and _group_running(group))
                    or any(_proc_running(p) for p in procs))
            if not left:
                return True
            if time.monotonic() >= end:
                return False
            time.sleep(0.05)

    send(signal.SIGTERM)
    if gone(STOP_GRACE_S):
        return None
    send(signal.SIGKILL)
    if gone(2.0):
        return None
    return "some of the job's processes are still running after SIGKILL, so the stop did not finish"


def _proc_running(proc: Any) -> bool:
    try:
        import psutil
        return proc.is_running() and proc.status() != psutil.STATUS_ZOMBIE
    except Exception:  # noqa: BLE001 - gone, or cannot tell: psutil raises NoSuchProcess for a finished one
        return False


def first_pid(output: str) -> Optional[int]:
    """The pid Hermes's background wrapper printed: its first all-digit line, as Hermes reads it."""
    return next((int(ln) for ln in map(str.strip, output.splitlines()) if ln.isdigit()), None)


def job_group_of(pid: Optional[int]) -> Optional[int]:
    """The process group of a job's wrapper right after it started (POSIX), or None."""
    if pid is None or os.name == "nt":
        return None
    try:
        return os.getpgid(pid)
    except OSError:
        return None


def spawned_job_id(command: str) -> Optional[str]:
    from .provider import spawned_job_id as exact
    return exact(command)


class LocalExec:
    def __init__(self, workspaces: Any = None, record_dir: Optional[Path] = None) -> None:
        self._envs: dict[str, tuple[Any, float]] = {}
        self._lock = threading.Lock()
        self.workspaces = workspaces            # D24: each host session's terminal starts in its workspace
        self._jobs: dict[str, set[str]] = {}    # session -> background jobs whose spawn wrapper this process ran
        # session -> job id -> (wrapper pid, the job's process group), read when its wrapper returned. Lives as long
        # as the session's entry in _jobs (dropped with it); only Hermes's stop for one of these is a tree stop.
        self._job_procs: dict[str, dict[str, tuple[int, Optional[int]]]] = {}
        self._record = record_dir / BG_RECORD if record_dir is not None else None
        self._rec_lock = threading.Lock()
        self._stops: dict[str, _Stops] = {}     # session -> stop handles of its running commands
        self._stops_lock = threading.Lock()     # apart from _lock, which is held while a terminal is being made
        self._boxes: dict[str, Any] = {}        # session -> its file-tool helper inside the lock (filebox, D79)

    def cwd_for(self, session: str) -> str | None:
        """Where this session's terminal is now (the base for relative paths in its file tools)."""
        with self._lock:
            env = self._envs.get(session, (None, 0))[0]
        return getattr(env, "cwd", None) if env is not None else None

    def stops_for(self, session: str, stop: Optional[_Stop] = None) -> _Stops:
        """The session's stop handles. With ``stop``, it joins them in the same locked step that finds the set, so a
        close that takes the set away at that moment (drop, under the same lock) still stops it."""
        with self._stops_lock:
            stops = self._stops.setdefault(session, _Stops())
            if stop is not None:
                stops.add(stop)
            return stops

    def busy_sessions(self) -> set[str]:
        """Sessions with a call in flight here (registered from admission to its end). The sweeper keeps them."""
        with self._stops_lock:
            return {s for s, stops in self._stops.items() if len(stops)}

    def drop(self, session: str) -> int:
        """The session is closed: stop its calls in flight (a running command, one still waiting for its terminal, a
        file tool, a screen action still waiting for the driver), end its terminal and remove the files of its background
        jobs that have ended. A job still running is left running (the user asked for it) and recorded for the sweeper.
        Returns how many of this session's jobs are still running."""
        with self._stops_lock:
            stops = self._stops.pop(session, None)
        if stops is not None:
            stops.stop_all()                    # a closed session's command must not run on to its end here
        with self._lock:
            env = self._envs.pop(session, (None, 0))[0]
            jobs = self._jobs.pop(session, set())
            procs = self._job_procs.pop(session, {})
            box = self._boxes.pop(session, None)
        if box is not None:
            _cleanup_box(box)
        if env is not None:
            _cleanup(env)
        return len(self._reap(jobs, {j: g for j, (_, g) in procs.items()}) & jobs)

    def sweep_jobs(self, live: set[str]) -> int:
        """Device sweeper (once a minute; the name is kept from when it only reaped jobs). Every session that has no
        live grant here and no call in flight ended without a close_session (its idle limit, Pause, a re-pair) and is
        ended now the way a close ends it (D39): its terminal goes, and with it Hermes's snapshot of the session's
        shell; its stop handles go; Hermes's per-task state for its file tools is released; the files of its ended
        background jobs are removed (running ones are recorded with their process group). A new Allow for the same
        session id then starts clean. A session with a call in flight is left for a later pass. Returns how many jobs
        are still running."""
        with self._lock:                        # a terminal being made waits for this pass, and the reverse
            with self._stops_lock:              # nested in this order only here; nothing nests them the other way
                busy = {s for s, stops in self._stops.items() if len(stops)}
                ended = (set(self._stops) | set(self._envs) | set(self._jobs) | set(self._boxes)) - set(live) - busy
                for session in ended:
                    self._stops.pop(session, None)
            envs = [self._envs.pop(s)[0] for s in ended if s in self._envs]
            boxes = [self._boxes.pop(s) for s in ended if s in self._boxes]
            lapsed: set[str] = set()
            groups: dict[str, Optional[int]] = {}
            for session in [s for s in ended if s in self._jobs]:
                lapsed |= self._jobs.pop(session)
                groups.update({j: g for j, (_, g) in self._job_procs.pop(session, {}).items()})
        for box in boxes:
            _cleanup_box(box)
        for env in envs:
            _cleanup(env)
        for session in ended:
            _release_file_tasks(session)
        return len(self._reap(lapsed, groups))

    def reap_recorded(self) -> int:
        """Device start: the record from an earlier run. Returns how many are still running."""
        return len(self._reap(set()))

    def _note_job(self, session: str, job_id: str) -> None:
        with self._lock:
            self._jobs.setdefault(session, set()).add(job_id)

    def _note_job_proc(self, session: str, job_id: str, output: str) -> None:
        """The wrapper of job_id returned: keep its pid and its process group for Hermes's later stop."""
        pid = first_pid(output)
        if pid is None:
            return
        with self._lock:
            if job_id in self._jobs.get(session, set()):      # the session was not closed meanwhile
                self._job_procs.setdefault(session, {})[job_id] = (pid, job_group_of(pid))

    def _job_stop_target(self, session: str, command: str) -> Optional[tuple[str, int, Optional[int]]]:
        """(job id, pid, group) when command is exactly Hermes's stop of a job this session started here."""
        m = _JOB_STOP.fullmatch(command)
        if m is None:
            return None
        pid = int(m.group(1))
        with self._lock:
            for job_id, (job_pid, group) in self._job_procs.get(session, {}).items():
                if job_pid == pid:
                    return job_id, pid, group
        return "", pid, None

    def _stop_job(self, job_id: str, pid: int, group: Optional[int]) -> tuple[dict[str, Any], bytes]:
        """The host's stop of one of this session's background jobs (passive, from Hermes's own kill): the job's
        whole process tree, never just Hermes's wrapper. A stop that did not happen says so (returncode 1)."""
        if not job_id:
            why = "this device has no record of that background job in this session, so nothing was stopped"
        elif os.name == "nt":
            why = NO_TREE_STOP
        else:
            why = stop_job_tree(pid, group, job_paths(job_id)[2])
        if why:
            return {"returncode": 1}, why.encode()
        return {"returncode": 0}, b""

    def _reap(self, job_ids: set[str], groups: Optional[dict[str, Optional[int]]] = None) -> set[str]:
        """Delete the files of every job (given, or recorded) that has ended; record the rest. Returns the running.
        groups: the process group of each given job, when this process still knows it."""
        if self._record is None and not job_ids:
            return set()
        with self._rec_lock:
            keep: set[str] = set()
            for job in self._load_record() | job_ids:
                if _job_ended(job, (groups or {}).get(job)):
                    for path in job_paths(job):           # exact names of a job id this module noted or recorded
                        try:
                            os.unlink(path)
                        except OSError:
                            pass
                else:
                    keep.add(job)
            self._save_record(keep)
            return keep

    def _load_record(self) -> set[str]:
        if self._record is None:
            return set()
        try:
            data = json.loads(self._record.read_text())
        except (OSError, ValueError):
            return set()
        return {j for j in data if isinstance(j, str) and _JOB_ID.fullmatch(j)} if isinstance(data, list) else set()

    def _save_record(self, job_ids: set[str]) -> None:
        if self._record is None:
            return
        if job_ids:
            from .store import _write        # the same private (0600) write every state file uses
            _write(self._record, sorted(job_ids))
        else:
            self._record.unlink(missing_ok=True)

    def _env(self, session: str, timeout: int):
        """The session's terminal, made on first use. It lives as long as the session's grant: a close (drop) or the
        sweeper (sweep_jobs, once the grant has ended) removes it; another session's use never does."""
        from .identity import blank_env
        from .lock import locked_environment, unlocked
        now = time.monotonic()
        mode, stale = unlocked(), None
        with self._lock:
            env = self._envs.get(session, (None, 0))[0]
            if env is not None and getattr(env, "_tether_unlocked", mode) != mode:
                # allow_unlocked_commands changed since this terminal was made (only possible between sessions,
                # device.apply_panel_settings): a terminal of the other kind is never reused, nor its file helper.
                stale, env = env, None
                self._envs.pop(session, None)
                old_box = self._boxes.pop(session, None)
                if old_box is not None:
                    _cleanup_box(old_box)
            if env is None:
                start = self.workspaces.ensure(session) if self.workspaces is not None else Path.home()
                # blank_env: no child of this terminal has the passphrase, whatever os.environ holds when it starts.
                # locked_environment (D71): every process this terminal starts runs inside the session lock; where
                # the lock cannot be applied it raises LockError and no terminal is made (D73).
                # REMOTE_MARK: `hermes tether authenticator ...` and `join` refuse to run in it (D67; a mark, not a wall).
                from .enroll import REMOTE_MARK
                env = locked_environment(cwd=str(start), timeout=timeout, env={**blank_env(), REMOTE_MARK: "1"},
                                         workspace=str(start))
                try:
                    env._tether_unlocked = mode
                except AttributeError:
                    pass
            self._envs[session] = (env, now)
        if stale is not None:
            _cleanup(stale)
        return env

    def close_all(self) -> None:
        with self._lock:
            envs, self._envs = [e for e, _ in self._envs.values()], {}
            boxes, self._boxes = list(self._boxes.values()), {}
        for box in boxes:
            _cleanup_box(box)
        for env in envs:
            _cleanup(env)

    def file_box(self, session: str, cwd: str) -> Any:
        """The session's file-tool helper inside its lock (filebox, D79), made with the session's own terminal (the
        same checks as a command first: no lock, no helper). ``cwd``: where the session's terminal is now (relative
        paths in the call resolve there). Raises LockError when the lock cannot hold it."""
        from .filebox import FileBox, NO_BOX
        from .lock import LockError
        with self._lock:
            box = self._boxes.get(session)
        if box is None or box.closed:
            env = self._prepare({"session": session})
            spec = getattr(env, "tether_box_spec", None)
            if spec is None:
                raise LockError(NO_BOX.format(why="this session's terminal is not locked"))
            prefix, run_env, temp = spec()
            fresh = FileBox(prefix, run_env, temp, cwd)
            with self._lock:
                box = self._boxes.get(session)
                if box is None or box.closed:
                    box, fresh = fresh, None
                    self._boxes[session] = box
            if fresh is not None:
                _cleanup_box(fresh)
        box.cwd = cwd
        return box

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
        session = str(args.get("session") or "default")
        # The call joins its session's stop handles before anything else is awaited, and before its terminal is
        # made, so a close (or the sweeper) that lands while the terminal is being made, its own or another
        # session's, still stops it: the worker then refuses to start the command. The terminal itself is made
        # outside the stoppable part: a stop that reached Hermes's login-shell start would kill the snapshot and
        # leave the session's terminal without it.
        stop = _Stop()
        stops = self.stops_for(session, stop)
        try:
            if args.get("passive"):
                # The host's own stop of a background job (Hermes's "kill <pid>", sent by bg_call): the whole job
                # stops, not only Hermes's wrapper. Any other passive command (a poll, a status read) runs as given.
                job_stop = self._job_stop_target(session, command)
                if job_stop is not None:
                    return await asyncio.to_thread(self._stop_job, *job_stop)
            env = await asyncio.to_thread(self._prepare, args)
            return await _run_stoppable(self._run, args, body, env, stops=stops, stop=stop)
        finally:
            stops.discard(stop)

    def _prepare(self, args: dict[str, Any]) -> Any:
        """The session's terminal, made before its command runs (never stoppable, see exec)."""
        from .identity import shield_children
        from .lock import check_commands
        # D73/D74: before every command, whether its terminal exists yet or not: no lock, no command.
        check_commands()
        # Before the terminal exists (Hermes snapshots the environment when it makes one): the remote host must never
        # read this machine's key passphrase from the environment.
        shield_children()
        return self._env(str(args.get("session") or "default"), max(1, int(args.get("timeout") or 60)))

    def _run(self, args: dict[str, Any], body: bytes, env: Any = None) -> tuple[dict[str, Any], bytes]:
        from .identity import mask_secrets, shield_children
        session = str(args.get("session") or "default")
        timeout = max(1, int(args.get("timeout") or 60))
        if env is None:                       # a direct call: make the terminal here
            env = self._prepare(args)
        cwd = str(args.get("cwd") or "")
        if cwd in ("", "~") and self.workspaces is not None:
            cwd = str(self.workspaces.ensure(session))        # the host's default start: the session workspace
        elif cwd.startswith("~"):
            cwd = os.path.expanduser(cwd)
        if cwd and not os.path.isdir(cwd):
            cwd = ""          # a host-side path (or a folder gone since): stay where this session was
        command = str(args["command"])
        if _stop_pending():                   # stopped before the command is spawned: it does not start
            return ({"returncode": 130, "cwd": env.cwd, "cwd_observed": False, "home": str(Path.home())},
                    b"[interrupted]")
        job = spawned_job_id(command)
        if job is not None:
            self._note_job(session, job)          # noted before it runs: its files are checked when the session ends
        shield_children()                     # before every command: Hermes may have reloaded the environment
        result = env.execute(command, cwd, timeout=timeout,
                             stdin_data=body.decode(errors="replace") if body else None)
        if job is not None:
            self._note_job_proc(session, job, str(result.get("output") or ""))
        logger.debug("tether exec (%s): rc=%s", command[:60], result.get("returncode"))
        meta = {"returncode": result.get("returncode", result.get("exit_code", -1)),
                "cwd": result.get("cwd") or env.cwd, "cwd_observed": bool(result.get("cwd_observed")),
                "home": str(Path.home())}
        # This machine's own passphrase never leaves it in plain output (the host does not hold it to mask it)
        return meta, mask_secrets(str(result.get("output") or "")).encode()


def _release_file_tasks(session: str) -> None:
    """Hermes keeps per-task file state for the file tools it runs for this session, under the task id
    "tether-<session>" (what it read, its patch failures, its file-state record). Release exactly that, with
    Hermes's own cleanup_vm; best effort. The terminal environment those tools ran in is not released here: Hermes
    keys it by its container key ("default" on a device with the local backend), which this machine's own
    sessionless runs share, so it is not Tether's to tear down (F80, D39)."""
    try:
        from tools.terminal_tool_lifecycle import cleanup_vm
        cleanup_vm(f"tether-{session}")
    except Exception:  # noqa: BLE001 - Hermes not importable, or a teardown error: nothing to do here
        logger.debug("tether: file-tool task not released", exc_info=True)


def _cleanup_box(box: Any) -> None:
    try:
        box.close()
    except Exception:  # noqa: BLE001
        logger.debug("tether: file helper cleanup failed", exc_info=True)


def _cleanup(env: Any) -> None:
    try:
        env.cleanup()
    except Exception:  # noqa: BLE001
        logger.debug("tether: env cleanup failed", exc_info=True)


DEVICE_TOOLS = frozenset({"read_file", "write_file", "patch", "search_files"})


def _hermes_dispatch(name: str, args: dict[str, Any], task_id: str) -> Any:
    """One lent file tool, run the way this machine's Hermes runs a tool outside its agent loop
    (model_tools.handle_function_call): its tool_request middleware, its pre_tool_call hooks (block, approve,
    modify), its edit approval, its tool_execution middleware, the tool, then its post_tool_call and
    transform_tool_result hooks (D59). ctx.dispatch_tool is plain registry.dispatch and ran none of them."""
    import model_tools
    return model_tools.handle_function_call(name, args, task_id=task_id, session_id=task_id)


class ToolRunner:
    """Runs a host's file tool here, through this machine's own Hermes (_hermes_dispatch): its hooks, its paths,
    its file rules, its write fence, its credential protections, exactly as for local use (design D22). Only the
    tools in DEVICE_TOOLS are lent; anything else is refused. ``dispatch`` replaces _hermes_dispatch (tests)."""

    def __init__(self, ctx: Any, local_exec: Any = None, workspaces: Any = None, dispatch: Any = None) -> None:
        self.ctx, self.local_exec, self.workspaces = ctx, local_exec, workspaces
        self.dispatch = dispatch

    async def run(self, args: dict[str, Any], body: bytes) -> tuple[dict[str, Any], bytes]:
        name = str(args.get("name") or "")
        if name not in DEVICE_TOOLS:
            raise PermissionError(f"this device does not lend {name!r} over tether")
        tool_args = dict(args.get("args") or {})
        session = str(args.get("session") or "default")
        stop = _Stop()
        stops = self.local_exec.stops_for(session, stop) if self.local_exec is not None else None
        return await _run_stoppable(self._run, name, tool_args, session, stops=stops, stop=stop)

    def _base(self, session: str) -> str | None:
        cwd = self.local_exec.cwd_for(session) if self.local_exec is not None else None
        if cwd and os.path.isabs(cwd):
            return cwd
        return str(self.workspaces.ensure(session)) if self.workspaces is not None else None

    def _run(self, name: str, tool_args: dict[str, Any], session: str) -> tuple[dict[str, Any], bytes]:
        from .filebox import NO_BOX, install, serving
        from .identity import mask_secrets, shield_children
        from .lock import LockError, files_boxed, tool_refusal
        path = tool_args.get("path")
        base = self._base(session)
        if name == "search_files" and not path and base:
            tool_args = {**tool_args, "path": base}      # Hermes's default "." is its own cwd: name the session's
        elif isinstance(path, str) and path and not path.startswith(("/", "~")):
            if base:                             # relative = from where this session's terminal is, here
                tool_args = {**tool_args, "path": os.path.normpath(os.path.join(base, path))}
        # D76: protected paths are refused before Hermes runs the tool, with a sentence the agent can act on. Since
        # D79 this is only the early answer: on a locked Mac the tool body runs inside the session's lock (below).
        where = getattr(self.workspaces, "path", None)
        why = tool_refusal(name, tool_args, base=base, workspace=str(where(session)) if where else None)
        if why:
            raise PermissionError(why)
        box = None
        if files_boxed() and self.dispatch is None:
            # D79: Hermes's registry hands this call's tool body to the session's helper inside its lock; with no
            # helper the call is refused, never run in this process.
            if self.local_exec is None:
                raise LockError(NO_BOX.format(why="no session terminal on this device"))
            install()
            box = self.local_exec.file_box(session, base or str(Path.home()))
        try:
            if _stop_pending():               # a stop reached this call before the tool ran: it does not run
                raise InterruptedError("stopped before it started")
            from .provider import host_only
            # Hermes's file tools start shells of their own here (not through the middleware): out of os.environ
            # first, in case Hermes loaded .env into it again.
            shield_children()
            # This machine's own work: a tether terminal or middleware in this process (a machine that is also a
            # host) never sends it on to another machine.
            with host_only(), serving(f"tether-{session}", box):
                result = (self.dispatch or _hermes_dispatch)(name, tool_args, task_id=f"tether-{session}")
        finally:
            if _stop_pending():
                # A stop may have cut the tool short: drop this task's file state (what it read, its patch count),
                # so the next call starts from what is on disk. Hermes's shared terminal environment is kept.
                _release_file_tasks(session)
        if isinstance(result, dict):
            return {"json_dict": True}, mask_secrets(json.dumps(result)).encode()
        return {}, mask_secrets(str(result)).encode()


class SessionControl:
    """Device-side handlers for the connection itself (D23/D24): closing a session and receiving skill copies."""

    def __init__(self, consent: Any, workspaces: Any, local_exec: LocalExec, host_fp: Any) -> None:
        self.consent, self.workspaces, self.local_exec, self.host_fp = consent, workspaces, local_exec, host_fp

    async def close_session(self, args: dict[str, Any], body: bytes) -> tuple[dict[str, Any], bytes]:
        from .workspace import check_session
        session = check_session(args.get("session"))
        # D33: only the caller that holds the session's grant can end it. With no live grant there is nothing
        # to protect, and what is left of the session (its workspace) is removed as before.
        if not self.consent.release(self.host_fp(), session, str(args.get("grant") or "")):
            raise PermissionError("this session is open from another program on the host; it was not closed")
        # D46: a folder another live session works in (a letter-case twin of this id, or an id spelled like its
        # folder name) is never emptied by this close.
        shared = self.consent.folder_shared(session)
        running = await asyncio.to_thread(self.local_exec.drop, session)
        wiped = False if shared else await asyncio.to_thread(self.workspaces.wipe, session)
        await asyncio.to_thread(_release_file_tasks, session)     # Hermes's teardown may block: not on the loop
        logger.info("tether: session %s closed by the host (workspace %s)", session, "removed" if wiped else "none")
        from .store import log_event
        log_event(getattr(self.consent, "events_dir", None), "session_closed", session=session,
                  reason="workspace emptied" if wiped else "", jobs=running or None)
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
    from .lock import locked
    # files_locked (D71): this device runs a session's commands inside the session lock, so the host tells the agent
    # its Tether and Hermes files are out of reach there.
    return {"terminal": True, "files_locked": locked(), "home": str(Path.home()), "rules": rules()}
