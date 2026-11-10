"""tether_screen: computer use on a paired tether device.

Select with ``computer_use.backend: tether_screen`` on the host. Every call goes to the session's active
device (the ``devices`` tool, ``use``), whose own Hermes runs it on its own driver with its own macOS
permissions. Hermes's computer-use tool on this host keeps doing what it always does (schema, approvals,
safety rules); this backend only carries the calls. Needs the ``tether`` plugin (host role) in the same
process: they meet through the shared runtime handle.
"""
from __future__ import annotations

import sys
from typing import Any, Optional

from tools.computer_use.backend import ActionResult, CaptureResult, ComputerUseBackend, ComputerUseProvider, UIElement

HANDLE = "tether_runtime_handle"
CALL_TIMEOUT_S = 180        # a first call may wait on the person at the device to allow the session


def _runtime():
    rt = _runtime_or_none()
    if rt is None or rt.host is None:
        raise RuntimeError("tether is not running as a host in this Hermes (enable the tether plugin with "
                           "role: host)")
    return rt


def _runtime_or_none():
    handle = sys.modules.get(HANDLE)
    return getattr(handle, "runtime", None) if handle else None


def _capture(d: Optional[dict], png: bytes) -> Optional[CaptureResult]:
    if d is None:
        return None
    d = dict(d)
    d["elements"] = [UIElement(**{**e, "bounds": tuple(e.get("bounds") or (0, 0, 0, 0))})
                     for e in d.get("elements") or []]
    d["png_b64"] = png.decode() if png else d.get("png_b64")
    return CaptureResult(**{k: v for k, v in d.items() if k in CaptureResult.__dataclass_fields__})


def _action(d: dict, png: bytes) -> ActionResult:
    d = dict(d)
    d["capture"] = _capture(d.get("capture"), png)
    return ActionResult(**{k: v for k, v in d.items() if k in ActionResult.__dataclass_fields__})


class TetherScreenBackend(ComputerUseBackend):
    def __init__(self, permission_mode: str) -> None:
        self.permission_mode = permission_mode

    def start(self) -> None:
        pass

    def stop(self) -> None:
        pass

    def is_available(self) -> bool:
        return True     # selected explicitly; calls report offline devices or a missing host clearly

    def _call(self, method: str, **kwargs: Any):
        rt = _runtime()
        return rt.call_target("cu", {"method": method, "kwargs": kwargs}, timeout=CALL_TIMEOUT_S)

    def _act(self, method: str, **kwargs: Any) -> ActionResult:
        try:
            meta, png = self._call(method, **kwargs)
        except Exception as e:  # noqa: BLE001 - device offline, consent denied, frozen, interrupted
            explain = getattr(_runtime_or_none(), "explain", None)
            msg = explain(e) if explain else f"tether: {e}"
            return ActionResult(ok=False, action=method, message=msg, code="tether_unavailable")
        return _action(meta["result"], png)

    def capture(self, mode: str = "som", app: Optional[str] = None, pid: Optional[int] = None,
                window_id: Optional[int] = None) -> CaptureResult:
        meta, png = self._call("capture", mode=mode, app=app, pid=pid, window_id=window_id)
        return _capture(meta["result"], png)

    def click(self, **kw: Any) -> ActionResult:
        return self._act("click", **kw)

    def drag(self, **kw: Any) -> ActionResult:
        return self._act("drag", **kw)

    def scroll(self, **kw: Any) -> ActionResult:
        return self._act("scroll", **kw)

    def type_text(self, text: str, **kw: Any) -> ActionResult:
        return self._act("type_text", text=text, **kw)

    def key(self, keys: str, **kw: Any) -> ActionResult:
        return self._act("key", keys=keys, **kw)

    def focus_app(self, app: str, raise_window: bool = False) -> ActionResult:
        return self._act("focus_app", app=app, raise_window=raise_window)

    def set_value(self, value: str, element: Optional[int] = None) -> ActionResult:
        return self._act("set_value", value=value, element=element)

    def wait(self, seconds: float) -> ActionResult:
        return self._act("wait", seconds=seconds)

    def list_apps(self) -> list[dict[str, Any]]:
        return self._call("list_apps")[0]["items"]

    def list_windows(self) -> list[dict[str, Any]]:
        return self._call("list_windows")[0]["items"]


class TetherScreenProvider(ComputerUseProvider):
    name = "tether_screen"
    display_name = "tether (a paired device's screen)"

    def create_backend(self, *, permission_mode: str) -> ComputerUseBackend:
        return TetherScreenBackend(permission_mode)

    def is_available(self) -> bool:
        return True     # cheap, no network: a process without the tether host gets a clear error per call


def register(ctx) -> None:
    ctx.register_computer_use_provider(TetherScreenProvider())
