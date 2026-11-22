"""The file tools a remote session uses run inside its session lock (D79).

On a Mac whose session lock is on, the four file tools Tether lends (read_file, write_file, patch, search_files) no
longer run in this Hermes process. Each session gets one helper: this device's own Python, started through
``/usr/bin/sandbox-exec`` with the very profile the session's commands run under (lock.session_profile, taken from
its LockedEnvironment), in the session's current folder. The helper imports Hermes's own file tools and runs each
call there, so macOS refuses a protected path however it is named: a link, '..' after a link, the
/System/Volumes/Data prefix, /.vol/<fs>/<inode>, a link swapped between a check and the use, several paths in one
search string, a relative path inside a patch. Tether's path checks (lock.tool_refusal) still run first, as an early
and friendlier refusal; they are no longer what protects the files.

Everything else about a call stays in this process, as before: Hermes's request middleware, its pre_tool_call hooks
(block, approve, modify), its edit approval, its execution middleware, its post-call hooks. Only the tool body moves:
Hermes's registry.dispatch is wrapped once (install) and, for a call whose task id is one of Tether's remote sessions
("tether-<session>"), hands the call to that session's helper. Where no helper serves the call, it is refused; it
never falls back to this process (fail closed). The device's own agent never uses a "tether-" task id and is not
affected. Windows and allow_unlocked_commands keep the earlier behaviour: the tools run in this process, behind the
path checks only (no lock there; see lock.files_boxed).

The helper holds Hermes's per-task file state (what was read, patch failures) for the life of the session, as this
process did before. Its Hermes home is a new empty folder in the terminal's temp folder (never the device's own
home, which the lock keeps unreadable), so the helper sees Hermes's default file-tool settings. It gets the same
environment the session's commands get (no secrets), runs Python with -I (no current-folder imports, no PYTHON*
variables) and -B (no .pyc writes), and is stopped with the session (LocalExec.drop, the sweeper, close_all).
"""
from __future__ import annotations

import contextlib
import json
import logging
import os
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable, Iterator, Optional

logger = logging.getLogger(__name__)

LENT = frozenset({"read_file", "write_file", "patch", "search_files"})
TASK_PREFIX = "tether-"                 # ToolRunner's task id for a remote session's file tool: "tether-<session>"
START_TIMEOUT_S = 60.0                  # the helper's start (Python and Hermes's file tools imported)
# Hermes names the helper uses (inside its source string) and the dispatch install() wraps, with its one caller:
# listed for the maintainers' watcher (scripts/hermes_watch.py).
_HERMES_NAMES = (("tools.registry", "registry"), ("tools.file_tools", "read_file_tool"),
                 ("tools.file_tools", "write_file_tool"), ("tools.file_tools", "patch_tool"),
                 ("tools.file_tools", "search_tool"), ("tools.terminal_tool", "_active_environments"),
                 ("model_tools", "_execute_tool"))

NO_BOX = ("tether: this file tool was not run: this device's session lock could not start for file tools ({why}). "
          "A remote session's file tools run only inside it; the person at the machine can see the reason in "
          "Hermes's log")

# The helper. argv[1]: the folder holding Hermes's ``tools`` package. One JSON request per line on stdin; one JSON
# reply per line on the descriptor that was stdout (stdout itself is pointed at stderr, so nothing Hermes prints can
# reach the replies).
_HELPER = r"""
import json, os, sys
out = os.fdopen(os.dup(1), "w", encoding="utf-8")
os.dup2(2, 1)
sys.stdout = sys.stderr
sys.path[:0] = [p for p in [sys.argv[1], *(json.loads(sys.argv[2]) if len(sys.argv) > 2 else [])] if p not in sys.path]
try:
    import tools.file_tools
    import tools.terminal_tool as T
    from tools.registry import registry
except BaseException as e:
    out.write(json.dumps({"ready": False, "error": type(e).__name__ + ": " + str(e)[:200]}) + "\n")
    out.flush()
    sys.exit(3)
out.write(json.dumps({"ready": True}) + "\n")
out.flush()
for line in sys.stdin:
    try:
        req = json.loads(line)
        cwd = req.get("cwd") or ""
        if cwd and os.path.isdir(cwd):
            os.chdir(cwd)
            os.environ["TERMINAL_CWD"] = cwd
            for env in list(getattr(T, "_active_environments", {}).values()):
                try:
                    env.cwd = cwd
                except Exception:
                    pass
        res = registry.dispatch(req["name"], req["args"], task_id=req["task_id"],
                                session_id=req.get("session_id") or req["task_id"])
        reply = {"ok": True, "result": res}
    except BaseException as e:
        reply = {"ok": False, "error": type(e).__name__ + ": " + str(e)[:300]}
    out.write(json.dumps(reply, default=str) + "\n")
    out.flush()
"""


def _lock_error(why: str) -> Exception:
    from .lock import LockError
    return LockError(NO_BOX.format(why=why))


def _import_dirs() -> list[str]:
    """The folders this process imports from (its sys.path, folders only), in order: the helper gets the same, so it
    finds Hermes's libraries on any Python Hermes runs on (3.11 to 3.14: a venv, or Hermes 0.23.3's own runtime with
    its libraries in <home>/installs, which -I alone would not find)."""
    return [p for p in dict.fromkeys(sys.path) if p and os.path.isdir(p)]


def code_root() -> str:
    """The folder holding Hermes's ``tools`` package as this process imported it (the helper imports the same)."""
    import tools
    return str(Path(tools.__file__).resolve().parent.parent)


class FileBox:
    """One session's helper. ``prefix``: sandbox-exec and the session's profile; ``env``: the environment the
    session's commands get; ``temp_root``: the terminal's temp folder (the profile lets the session use it).
    Calls are served one at a time; the helper is started on the first call and again after a stop."""

    def __init__(self, prefix: list[str], env: dict, temp_root: str, cwd: str) -> None:
        self._prefix, self._env, self._temp_root = list(prefix), dict(env), temp_root
        self.cwd = cwd
        self._lock = threading.Lock()
        self._proc: Optional[subprocess.Popen] = None
        self._home: Optional[str] = None
        self._buf = bytearray()
        self.closed = False
        self.started = 0                  # how many helpers this box started (tests, the timing note)

    # ----- the helper process -----
    def _start(self) -> subprocess.Popen:
        if not self._prefix or not os.access(self._prefix[0], os.X_OK):
            raise _lock_error("the sandbox is missing")
        home = tempfile.mkdtemp(prefix="tether-files-", dir=self._temp_root or None)
        env = {k: v for k, v in self._env.items() if isinstance(k, str) and isinstance(v, str)}
        # The local backend always (a terminal backend named in this process's environment, "tether" on a machine that
        # is also a host, is not what a lent tool means), lazy installs off (no network, nothing written to Hermes).
        env.update(HERMES_HOME=home, TERMINAL_CWD=self.cwd, TERMINAL_ENV="local", HERMES_DISABLE_LAZY_INSTALLS="1")
        argv = [*self._prefix, sys.executable, "-I", "-B", "-c", _HELPER, code_root(), json.dumps(_import_dirs())]
        cwd = self.cwd if os.path.isdir(self.cwd) else home
        try:
            proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                    cwd=cwd, env=env, start_new_session=True, close_fds=True)
        except OSError as e:
            shutil.rmtree(home, ignore_errors=True)
            raise _lock_error(type(e).__name__) from None
        self._proc, self._home, self._buf = proc, home, bytearray()
        self.started += 1
        try:
            ready = self._reply(time.monotonic() + START_TIMEOUT_S, lambda: False)
        except BaseException:
            self._kill()
            raise
        if not ready.get("ready"):
            self._kill()
            logger.warning("tether: the file-tool helper did not start: %s", str(ready.get("error"))[:200])
            raise _lock_error("the helper did not start")
        return proc

    def _kill(self) -> None:
        proc, home, self._proc, self._home = self._proc, self._home, None, None
        if proc is not None:
            # Hermes starts each shell in a group of its own: its descendants first, then the helper's own group.
            try:
                import psutil
                kids = psutil.Process(proc.pid).children(recursive=True)
            except Exception:  # noqa: BLE001 - no psutil, or the helper already ended
                kids = []
            for kid in kids:
                with contextlib.suppress(Exception):
                    kid.kill()
            with contextlib.suppress(OSError):
                os.killpg(proc.pid, signal.SIGKILL)
            with contextlib.suppress(Exception):
                proc.kill()
            with contextlib.suppress(Exception):
                proc.wait(timeout=5)
            for f in (proc.stdin, proc.stdout):
                with contextlib.suppress(Exception):
                    f.close()
        if home:
            shutil.rmtree(home, ignore_errors=True)

    def _reply(self, deadline: Optional[float], stopped: Callable[[], bool]) -> dict:
        proc = self._proc
        if proc is None or proc.stdout is None:
            raise _lock_error("the helper ended")
        fd = proc.stdout.fileno()
        with selectors.DefaultSelector() as sel:      # kqueue on macOS: no FD_SETSIZE limit in a busy gateway
            sel.register(fd, selectors.EVENT_READ)
            return self._read_line(proc, fd, sel, deadline, stopped)

    def _read_line(self, proc: subprocess.Popen, fd: int, sel: Any, deadline: Optional[float],
                   stopped: Callable[[], bool]) -> dict:
        while b"\n" not in self._buf:
            if self.closed:
                raise InterruptedError("the session was closed")
            if stopped():
                self._kill()
                raise InterruptedError("stopped")
            if deadline is not None and time.monotonic() > deadline:
                self._kill()
                raise _lock_error("the helper did not answer in time")
            if sel.select(0.05):
                chunk = os.read(fd, 1 << 20)
                if not chunk:
                    self._kill()
                    raise _lock_error("the helper ended")
                self._buf += chunk
        line, _, rest = bytes(self._buf).partition(b"\n")
        self._buf = bytearray(rest)
        try:
            data = json.loads(line.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            self._kill()
            raise _lock_error("the helper's answer could not be read") from None
        return data if isinstance(data, dict) else {}

    # ----- calls -----
    def call(self, name: str, args: dict, *, task_id: str, session_id: Optional[str] = None,
             stopped: Callable[[], bool] = lambda: False) -> Any:
        """Hermes's own tool ``name`` with ``args``, run in the helper; returns what Hermes's registry.dispatch
        returned there (a JSON string or a dict). Raises LockError when the helper cannot run it, InterruptedError
        when the call was stopped (the helper is then ended: a stopped tool must not run on)."""
        if name not in LENT:
            raise _lock_error(f"{name!r} is not a lent file tool")
        while not self._lock.acquire(timeout=0.05):
            if stopped() or self.closed:
                raise InterruptedError("stopped")
        try:
            if self.closed:
                raise InterruptedError("the session was closed")
            if self._proc is None or self._proc.poll() is not None:
                self._kill()
                self._start()
            request = json.dumps({"name": name, "args": args, "task_id": task_id,
                                  "session_id": session_id or task_id, "cwd": self.cwd}, default=str)
            proc = self._proc
            try:
                proc.stdin.write(request.encode("utf-8") + b"\n")
                proc.stdin.flush()
            except (OSError, ValueError):
                self._kill()
                raise _lock_error("the helper ended") from None
            reply = self._reply(None, stopped)
        finally:
            self._lock.release()
        if not reply.get("ok"):
            raise _lock_error(str(reply.get("error") or "the helper failed")[:200])
        return reply.get("result")

    def close(self) -> None:
        self.closed = True
        with self._lock:
            self._kill()


# ---------- Hermes's registry: the one place a lent tool's body runs ----------
_serving: dict[str, list] = {}          # task id -> [box, number of calls in flight]
_serving_lock = threading.Lock()
_install_lock = threading.Lock()


@contextlib.contextmanager
def serving(task_id: str, box: Optional[FileBox]) -> Iterator[None]:
    """While a call of ``task_id`` is in flight, its registry dispatch is run by ``box`` (None: nothing to serve)."""
    if box is None:
        yield
        return
    with _serving_lock:
        entry = _serving.setdefault(task_id, [box, 0])
        entry[0] = box
        entry[1] += 1
    try:
        yield
    finally:
        with _serving_lock:
            entry = _serving.get(task_id)
            if entry is not None:
                entry[1] -= 1
                if entry[1] <= 0:
                    _serving.pop(task_id, None)


def _error(text: str) -> str:
    return json.dumps({"error": text})


def _route(original: Callable[..., Any], name: Any, args: Any, a: tuple, kw: dict) -> Any:
    task = str(kw.get("task_id") or "")
    if name not in LENT or not task.startswith(TASK_PREFIX):
        return original(name, args, *a, **kw)
    from .lock import files_boxed
    if not files_boxed():
        return original(name, args, *a, **kw)        # Windows, allow_unlocked_commands: this process, as before
    with _serving_lock:
        entry = _serving.get(task)
    if entry is None:
        logger.warning("tether: a remote session's file tool reached Hermes with no locked helper; refused")
        return _error(NO_BOX.format(why="no locked helper serves this call"))
    from .device_exec import _stop_pending
    from .lock import LockError
    try:
        return entry[0].call(str(name), dict(args or {}), task_id=task, session_id=kw.get("session_id"),
                             stopped=_stop_pending)
    except LockError as e:
        return _error(str(e))


def install() -> None:
    """Wraps Hermes's registry.dispatch once (idempotent). Raises LockError when it cannot be wrapped."""
    with _install_lock:
        try:
            from tools.registry import ToolRegistry, registry
        except Exception as e:  # noqa: BLE001
            raise _lock_error(f"Hermes's tool registry is not importable ({type(e).__name__})") from None
        current = registry.dispatch
        if getattr(current, "_tether_files_boxed", False):
            return
        if getattr(current, "__func__", None) is not ToolRegistry.dispatch:
            logger.warning("tether: Hermes's tool dispatch was already replaced by something else; it is wrapped as is")

        def dispatch(name: Any, args: Any, *a: Any, **kw: Any) -> Any:
            return _route(current, name, args, a, kw)

        dispatch._tether_files_boxed = True           # type: ignore[attr-defined]
        dispatch.__wrapped__ = current                # type: ignore[attr-defined]
        registry.dispatch = dispatch
        if not getattr(registry.dispatch, "_tether_files_boxed", False):
            raise _lock_error("Hermes's tool registry could not be wrapped")


def installed() -> bool:
    try:
        from tools.registry import registry
    except Exception:  # noqa: BLE001
        return False
    return bool(getattr(registry.dispatch, "_tether_files_boxed", False))
