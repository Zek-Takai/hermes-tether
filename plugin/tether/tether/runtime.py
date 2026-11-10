"""Process-wide runtime: one asyncio loop on its own daemon thread (design §3, listener note).

Hermes tool handlers are synchronous and run in Hermes's worker threads; they reach the link through
``Runtime.run(coro, timeout)``, which schedules onto this loop with ``run_coroutine_threadsafe``. The gateway's
own loop is never touched. ``tether_screen`` (a separate plugin, same process) finds the same runtime
through ``get_runtime()``.
"""
from __future__ import annotations

import asyncio
import concurrent.futures
import sys
import time
import threading
import types
from typing import Any, Awaitable, Optional

_HANDLE = "tether_runtime_handle"     # a tiny module in sys.modules, shared by both plugins


class Runtime:
    def __init__(self) -> None:
        self.loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run, name="tether-link", daemon=True)
        self._thread.start()
        self.host = None      # host.HostService when the host role runs here
        self.device = None    # device.DeviceService when the device role runs here
        self.targets: dict[str, str] = {}   # host: session id -> device name or "local" (devices tool, use)
        self.last_device: dict[str, str] = {}   # host: session id -> the device it last worked on
        # D23: a session reaches its device only inside a turn the user started, and within the idle limit.
        self.turn_open: dict[str, bool] = {}
        self.turn_text: dict[str, str] = {}     # session -> the user's own words this turn (who may switch)
        self.last_activity: dict[str, float] = {}
        self.idle_limit_s: dict[str, float] = {}  # device -> its announced grant_idle_minutes, in seconds
        self.closed_note: dict[str, str] = {}   # session -> why its device connection closed (said next turn)
        self.skill_copies: dict[str, dict[str, str]] = {}   # session -> host skill dir -> path on the device
        self.default_target = "local"
        self.consent = None   # device: consent.ConsentGate (tether_screen honours its screen freeze)

    def _run(self) -> None:
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    def submit(self, coro: Awaitable[Any]) -> concurrent.futures.Future:
        return asyncio.run_coroutine_threadsafe(coro, self.loop)

    def run(self, coro: Awaitable[Any], timeout: Optional[float] = None) -> Any:
        fut = self.submit(coro)
        try:
            return fut.result(timeout)
        except concurrent.futures.TimeoutError:
            fut.cancel()
            raise TimeoutError("tether call timed out") from None


    # ---------- host helpers, also used by tether_screen through this shared object ----------
    @staticmethod
    def current_session() -> str:
        try:
            from gateway.session_context import get_session_env
            sid = get_session_env("HERMES_SESSION_ID") or get_session_env("HERMES_SESSION_KEY")
        except Exception:  # noqa: BLE001
            import os
            sid = os.getenv("HERMES_SESSION_ID", "")
        return sid or "default"

    def active_target(self, session: Optional[str] = None) -> str:
        """The device this session is connected to (its intent), whether or not a turn is running."""
        return self.targets.get(session or self.current_session(), self.default_target)

    def route(self, session: Optional[str] = None) -> str:
        """Where this session's work runs right now: its device only inside a turn the user started (never a
        background review after it) and within the device's idle limit; otherwise this host."""
        sid = session or self.current_session()
        target = self.active_target(sid)
        if target == "local" or not self.turn_open.get(sid, False):
            return "local"
        limit, last = self.idle_limit(target), self.last_activity.get(sid)
        if limit and last and time.monotonic() - last > limit:
            self.close_device(sid, f"timed out after {limit / 60:.0f} idle minutes")
            return "local"
        return target

    def idle_limit(self, device: str) -> Optional[float]:
        """Seconds a tethered session may sit idle: the shorter of the device's own limit and the limit this
        host set for it in the Tether panel (either may be unset)."""
        limits = [x for x in (self.idle_limit_s.get(device), self._host_idle_s(device)) if x]
        return min(limits) if limits else None

    def _host_idle_s(self, device: str) -> Optional[float]:
        pins = getattr(self.host, "pins", None)
        try:
            minutes = pins.idle_minutes(device) if pins is not None else None
        except Exception:  # noqa: BLE001
            minutes = None
        return minutes * 60 if minutes else None

    def learn_rules(self, device: str, capabilities: Any) -> None:
        """The device decides its own idle timer: keep its announced grant_idle_minutes."""
        minutes = ((capabilities or {}).get("rules") or {}).get("grant_idle_minutes")
        if isinstance(minutes, (int, float)) and minutes > 0:
            self.idle_limit_s[device] = float(minutes) * 60

    def events_dir(self):
        """The host's tether data folder (connection log), or None."""
        host = self.host
        d = getattr(host, "dir", None)
        if d is None and getattr(host, "pins", None) is not None:
            d = host.pins.path.parent
        return d

    def open_device(self, session: str, device: str) -> None:
        from .store import log_event
        if self.targets.get(session) != device:
            log_event(self.events_dir(), "tethered", device=device, session=session)
        self.targets[session] = device
        self.last_device[session] = device
        self.last_activity[session] = time.monotonic()
        self.closed_note.pop(session, None)

    def close_device(self, session: str, reason: str) -> None:
        """Back to this host; the device empties the session's workspace and ends its grant (D23/D24)."""
        target = self.targets.get(session, "local")
        self.targets[session] = "local"
        self.last_device.pop(session, None)
        self.last_activity.pop(session, None)
        self.skill_copies.pop(session, None)
        if target == "local":
            return
        from .store import log_event
        log_event(self.events_dir(), "untethered", device=target, session=session, reason=reason)
        self.closed_note[session] = (f"The {target} connection is closed ({reason}); you are on your host again. "
                                     "Only the user can reopen it.")
        if self.host is not None:
            try:
                self.submit(self.host.call(target, "close_session", {"session": session}, b"", 30))
            except Exception:  # noqa: BLE001 - the device also wipes on its own when the grant lapses
                pass

    def call_target(self, kind: str, args: dict, body: bytes = b"", timeout: float = 120.0,
                    target: Optional[str] = None) -> tuple[dict, bytes]:
        """Blocking call from a Hermes worker thread to the session's active device. Raises
        ConnectionError / PermissionError / RemoteError / TimeoutError, or InterruptedError when the user
        stops the turn (the call is cancelled on the device too)."""
        if self.host is None:
            raise ConnectionError("the tether plugin is not set up as a host on this machine")
        sid = self.current_session()
        target = target or self.route(sid)
        if target == "local":
            raise ConnectionError("no device connection is open for this session; only the user can open one, "
                                  "by naming the device in their message")
        fut = self.submit(self.host.call(target, kind, {**args, "session": sid}, body, timeout=timeout))
        while True:
            try:
                result = fut.result(0.25)
                self.last_activity[sid] = time.monotonic()
                return result
            except concurrent.futures.TimeoutError:
                if _interrupted():
                    fut.cancel()
                    raise InterruptedError("interrupted") from None
            except Exception as e:  # noqa: BLE001 - a denial ends the connection; everything is re-raised
                if DENIED in str(e) and self.targets.get(sid) == target:
                    self.close_device(sid, f"the person at {target} did not allow it")
                raise


def _interrupted() -> bool:
    try:
        from tools.interrupt import is_interrupted
        return is_interrupted()
    except Exception:  # noqa: BLE001
        return False


def _handle() -> types.ModuleType:
    handle = sys.modules.get(_HANDLE)
    if handle is None:
        handle = types.ModuleType(_HANDLE)
        handle.lock = threading.Lock()
        handle.runtime = None
        handle.host_factory = None
        handle = sys.modules.setdefault(_HANDLE, handle)
    return handle


def get_runtime(create: bool = True) -> Optional[Runtime]:
    if not create and _HANDLE not in sys.modules:
        return None
    handle = _handle()
    with handle.lock:
        if handle.runtime is None and create:
            handle.runtime = Runtime()
            if handle.host_factory is not None:
                handle.runtime.host = handle.host_factory()
        return handle.runtime


def set_host_factory(factory) -> None:
    """Host role: every process gets a ``HostLink`` (owner or relay) when it first needs the link."""
    handle = _handle()
    with handle.lock:
        handle.host_factory = factory
        if handle.runtime is not None and handle.runtime.host is None:
            handle.runtime.host = factory()


STOP = "Tell the user what happened; do not retry, work around it or investigate further."
DENIED = "did not allow remote use"       # consent.py's refusal; the host closes the connection on it


def explain(e: BaseException, target: str = "") -> str:
    """One plain sentence for the model about a tether failure, ending in what to do (nothing)."""
    where = f" ({target})" if target and target != "local" else ""
    msg = str(e) or type(e).__name__
    if msg.startswith("no device connection is open"):
        return f"tether: {msg}. Ask the user if you need it."
    if DENIED in msg:
        return (f"tether{where}: {msg}. The connection is closed and you are on your host again; nothing ran on "
                f"that machine. Only the user can reopen it. {STOP}")
    if isinstance(e, PermissionError) or "did not allow" in msg:
        return f"tether{where}: {msg}. Someone must be at that machine to allow it. {STOP}"
    return f"tether{where}: {msg}. {STOP}"


Runtime.explain = staticmethod(explain)     # tether_screen reaches it through the handle
