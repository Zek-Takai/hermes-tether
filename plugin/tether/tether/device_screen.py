"""Device side of remote computer use: each call runs on this machine's own computer-use backend (its
driver, its macOS permissions) in ``standard`` mode (design §3, D14). Approvals for the actions happen on
the host session, exactly as Hermes asks for local use; this side adds the consent grant (D10) and the
screen freeze: while the approval box is open, no action from any session reaches the screen, screenshots
included, and an action already running is waited for before the box opens (D10.7, D65).
Screenshots travel in the frame body (base64 text, as the backend produced it).
"""
from __future__ import annotations

import asyncio
import concurrent.futures
import dataclasses
import logging
import threading
from typing import Any, Optional

from .consent import FROZEN_TEXT
from .device_exec import _run_stoppable, _Stop, _stop_pending

logger = logging.getLogger(__name__)

INPUT_METHODS = frozenset({"click", "drag", "scroll", "type_text", "key", "focus_app", "set_value"})
READ_METHODS = frozenset({"capture", "list_apps", "list_windows", "wait"})
SELF_NAME = "tether_screen"


class ScreenExec:
    def __init__(self, consent, local_exec=None) -> None:
        self.consent = consent
        self.local_exec = local_exec           # its per-session stop handles: a close stops a session's waiting actions
        self._backend = None
        self._lock = threading.Lock()          # the backend is made and stopped under it
        # One driver, one action at a time, on a thread of its own. An action waiting its turn holds no thread, so a
        # driver call that never returns cannot use up the threads terminal, file and close calls need; a waiting
        # action that is stopped leaves the queue without running (F63).
        self._pool: Optional[concurrent.futures.ThreadPoolExecutor] = None

    def _executor(self) -> concurrent.futures.ThreadPoolExecutor:
        if self._pool is None:
            self._pool = concurrent.futures.ThreadPoolExecutor(max_workers=1, thread_name_prefix="tether-screen")
        return self._pool

    def _get_backend(self):
        if self._backend is None:
            from plugins.computer_use import configured_backend_name, get_active_provider
            if configured_backend_name() == SELF_NAME:
                raise RuntimeError("this device's own computer_use.backend is tether_screen; set it to its "
                                   "local driver (cua) so remote use has a real screen to drive")
            backend = get_active_provider().create_backend(permission_mode="standard")
            backend.start()
            self._backend = backend
        return self._backend

    def _idle(self, timeout: float) -> bool:
        if self._lock.acquire(timeout=timeout):        # taken and given back in this same thread: never left held
            self._lock.release()
            return True
        return False

    async def drain(self, timeout: float) -> bool:
        """The approval box is about to open and screen_frozen is already set: wait until no action is inside the
        driver (one that started before the freeze finishes; every later one sees the freeze and is refused).
        False when one is still running after ``timeout`` seconds: the box is then not shown (D65)."""
        return await asyncio.to_thread(self._idle, timeout)

    def available(self) -> bool:
        try:
            from plugins.computer_use import configured_backend_name, get_active_provider
            return configured_backend_name() != SELF_NAME and get_active_provider().is_available()
        except Exception:  # noqa: BLE001
            return False

    def stop(self) -> None:
        with self._lock:
            if self._backend is not None:
                try:
                    self._backend.stop()
                finally:
                    self._backend = None

    async def call(self, args: dict[str, Any], body: bytes) -> tuple[dict[str, Any], bytes]:
        method = str(args.get("method") or "")
        if method not in INPUT_METHODS | READ_METHODS:
            raise ValueError(f"unknown computer-use method {method!r}")
        if self.consent.screen_frozen:              # every action, screenshots included, while the box is open (D65)
            raise PermissionError(FROZEN_TEXT)
        kwargs = dict(args.get("kwargs") or {})
        for k in ("from_xy", "to_xy"):
            if isinstance(kwargs.get(k), list):
                kwargs[k] = tuple(kwargs[k])
        # The action joins its session's stop handles before it waits for the driver: closing the session (or the
        # device's Pause, which drops the link) keeps it off the screen.
        stop = _Stop()
        stops = None
        if self.local_exec is not None:
            stops = self.local_exec.stops_for(str(args.get("session") or "default"), stop)
        return await _run_stoppable(self._run, method, kwargs, stops=stops, stop=stop, executor=self._executor())

    def _run(self, method: str, kwargs: dict[str, Any]) -> tuple[dict[str, Any], bytes]:
        with self._lock:
            if self.consent.screen_frozen:                                   # re-check under the lock
                raise PermissionError(FROZEN_TEXT)
            # A stop that landed while this action waited for the driver keeps it off the screen. An action already
            # inside the driver is not interrupted: the driver has no way to cancel one, so it finishes.
            if _stop_pending():
                raise InterruptedError("stopped before it started")
            result = getattr(self._get_backend(), method)(**kwargs)
        return pack(result)


def pack(result: Any) -> tuple[dict[str, Any], bytes]:
    """Result → (header-safe dict, body). The one screenshot (capture's or an action's trailing capture)
    rides in the body."""
    if isinstance(result, list):
        return {"items": result}, b""
    data = dataclasses.asdict(result)
    png: Optional[str] = None
    if "png_b64" in data:
        png, data["png_b64"] = data["png_b64"], None
    elif isinstance(data.get("capture"), dict):
        png, data["capture"]["png_b64"] = data["capture"]["png_b64"], None
    return {"result": data}, (png or "").encode()
