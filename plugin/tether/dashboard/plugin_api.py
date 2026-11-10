"""tether backend for the Desktop Tether panel: what this Hermes is (host, device), its paired machines and their
idle limits, the device's own settings, and the connection log. Nothing private: no commands, paths, keys,
fingerprints in full or addresses.

The panel talks to whichever Hermes the Desktop app is connected to. On a host it shows the paired devices
(asked through the running gateway's link, never by taking the link itself). On a device it also offers the
settings this machine owns: the idle limit, the consent wait and pause.
"""
from __future__ import annotations

import importlib
import importlib.util
import sys
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException

_CORE = Path(__file__).resolve().parent.parent / "tether"
_NAME = "tether_panel_core"


def _core():
    if _NAME not in sys.modules:
        spec = importlib.util.spec_from_file_location(_NAME, _CORE / "__init__.py",
                                                      submodule_search_locations=[str(_CORE)])
        mod = importlib.util.module_from_spec(spec)
        sys.modules[_NAME] = mod
        spec.loader.exec_module(mod)
    return importlib.import_module(f"{_NAME}.store"), importlib.import_module(f"{_NAME}.hostlink")


router = APIRouter()


def _settings() -> dict[str, Any]:
    try:
        from hermes_cli.config import load_config_readonly
        cfg = load_config_readonly() or {}
    except Exception:  # noqa: BLE001
        cfg = {}
    entry = (((cfg.get("plugins") or {}).get("entries") or {}).get("tether") or {}).get("settings") or {}
    roles = sorted({r.strip() for r in str(entry.get("role") or "off").lower().split(",")} & {"host", "device"})
    return {"roles": roles, "name": str(entry.get("name") or ""),
            "grant_idle_minutes": float(entry.get("grant_idle_minutes") or 15),
            "consent_timeout_seconds": float(entry.get("consent_timeout_seconds") or 15)}


async def _devices(store, hostlink) -> tuple[list[dict[str, Any]], str]:
    link = hostlink.HostLink(store.data_dir(), lambda: None)
    try:
        rows = await link.list_devices(may_own=False)          # through the gateway's link; never owns it
        note = ""
    except Exception as e:  # noqa: BLE001 - gateway down or starting: show the pairings without live status
        rows = [{"name": n, "online": None} for n in sorted(store.DevicePins(store.data_dir()).all())]
        note = str(e) or "the link is not running"
    finally:
        try:
            await link.close()
        except Exception:  # noqa: BLE001
            pass
    out = []
    for r in rows:
        caps = r.get("capabilities") or {}
        rules = caps.get("rules") or {}
        pins = store.DevicePins(store.data_dir())
        name = r.get("name")
        out.append({
            "name": name, "online": r.get("online"), "phrase": "tether " + str(name).replace("-", " "),
            "os": " ".join(x for x in (caps.get("os"), caps.get("os_version")) if x) or None,
            "hermes": caps.get("hermes"),
            "device_idle_minutes": rules.get("grant_idle_minutes"),
            "host_idle_minutes": pins.idle_minutes(name),
            "last_seen": r.get("last_seen"),
            "link": (r.get("link") or {}).get("suite"), "computer_use": caps.get("computer_use"),
        })
    return out, note


@router.get("/status")
async def status(limit: int = 100):
    store, hostlink = _core()
    s = _settings()
    d = store.data_dir()
    body: dict[str, Any] = {"roles": s["roles"], "name": s["name"], "events": store.read_events(d, min(limit, 300))}
    if "host" in s["roles"]:
        devices, note = await _devices(store, hostlink)
        body["host"] = {"devices": devices, "note": note}
    if "device" in s["roles"]:
        pin = store.HostPin(d).get() or {}
        panel = store.read_panel_settings(d)
        body["device"] = {
            "paired_host": pin.get("name") or pin.get("label") or ("paired" if pin else None),
            "paused": (d / "paused").exists(),
            "grant_idle_minutes": panel.get("grant_idle_minutes", s["grant_idle_minutes"]),
            "consent_timeout_seconds": panel.get("consent_timeout_seconds", s["consent_timeout_seconds"]),
            "limits": {k: {"min": lo, "max": hi} for k, (lo, hi) in store.SETTINGS_LIMITS.items()},
        }
    return body


@router.put("/devices/{name}")
async def update_device(name: str, body: dict):
    """Host: rename a paired device (its label is the word that opens it) and set this host's idle limit for it.
    A renamed device reconnects under its new label within seconds."""
    store, _ = _core()
    if "host" not in _settings()["roles"]:
        raise HTTPException(status_code=403, detail="device labels and host idle limits are set on the host")
    body = body or {}
    try:
        new = store.DevicePins(store.data_dir()).update(
            name, label=body.get("label"),
            idle_minutes=body["idle_minutes"] if "idle_minutes" in body else "keep")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    if new != name:
        store.log_event(store.data_dir(), "device_renamed", device=new, reason=f"was {name}")
    if "idle_minutes" in body:
        store.log_event(store.data_dir(), "settings_changed", device=new,
                        reason=f"host idle limit {body['idle_minutes'] or 'cleared'} min")
    return {"name": new, "phrase": "tether " + new.replace("-", " ")}


@router.put("/settings")
async def save_settings(body: dict):
    store, _ = _core()
    if "device" not in _settings()["roles"]:
        raise HTTPException(status_code=403, detail="settings belong to each device; open this panel on that device")
    try:
        saved = store.write_panel_settings(store.data_dir(), {k: v for k, v in (body or {}).items()
                                                              if k in store.SETTINGS_LIMITS})
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return {"saved": saved, "note": "applies within a few seconds"}


@router.post("/pause")
async def pause(body: dict):
    store, _ = _core()
    if "device" not in _settings()["roles"]:
        raise HTTPException(status_code=403, detail="pause belongs to each device; open this panel on that device")
    flag = store.data_dir() / "paused"
    if bool((body or {}).get("paused")):
        flag.touch(mode=0o600, exist_ok=True)
        store.log_event(store.data_dir(), "paused", reason="from the Tether panel")
    elif flag.exists():
        flag.unlink()
        store.log_event(store.data_dir(), "resumed", reason="from the Tether panel")
    return {"paused": flag.exists()}
