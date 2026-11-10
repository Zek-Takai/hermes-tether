"""Device side of remote computer use: each call runs on this machine's own computer-use backend (its
driver, its macOS permissions) in ``standard`` mode (design §3, D14). Approvals for the actions happen on
the host session, exactly as Hermes asks for local use; this side adds the consent grant (D10) and the
screen freeze: while a consent prompt is open, no input from any session reaches the screen (D10.7).
Screenshots travel in the frame body (base64 text, as the backend produced it).
"""
from __future__ import annotations

import asyncio
import dataclasses
import logging
import threading
from typing import Any, Optional

logger = logging.getLogger(__name__)

INPUT_METHODS = frozenset({"click", "drag", "scroll", "type_text", "key", "focus_app", "set_value"})
READ_METHODS = frozenset({"capture", "list_apps", "list_windows", "wait"})
SELF_NAME = "tether_screen"


class ScreenExec:
    def __init__(self, consent) -> None:
        self.consent = consent
        self._backend = None
        self._lock = threading.Lock()          # one driver, one action at a time

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
        if method in INPUT_METHODS and self.consent.screen_frozen:
            raise PermissionError("screen input is frozen on this device while a consent prompt is open")
        kwargs = dict(args.get("kwargs") or {})
        for k in ("from_xy", "to_xy"):
            if isinstance(kwargs.get(k), list):
                kwargs[k] = tuple(kwargs[k])
        return await asyncio.to_thread(self._run, method, kwargs)

    def _run(self, method: str, kwargs: dict[str, Any]) -> tuple[dict[str, Any], bytes]:
        with self._lock:
            if method in INPUT_METHODS and self.consent.screen_frozen:      # re-check under the lock
                raise PermissionError("screen input is frozen on this device while a consent prompt is open")
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
