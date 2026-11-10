"""Non-secret state in the plugin's data folder: pins and addresses (secrets live in Hermes's store, D13)."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Optional

DEVICES_FILE = "paired_devices.json"   # host side: name -> {fp, cert_pem, paired_at}
HOST_FILE = "paired_host.json"         # device side: {host, port, fp, cert_pem, name, paired_at}
EVENTS_FILE = "events.jsonl"           # both sides: connection log for the Tether panel (no commands, no content)
EVENTS_MAX_BYTES = 128 * 1024
EVENTS_KEEP = 300


def data_dir() -> Path:
    try:
        from hermes_constants import get_hermes_home
        base = Path(get_hermes_home())
    except Exception:  # noqa: BLE001 - tests / outside Hermes
        base = Path(os.environ.get("HERMES_HOME", Path.home() / ".hermes"))
    d = base / "tether"
    legacy = base / "homeport"            # the plugin's working name before 2026-11-06: keep its keys and pins
    if not d.exists() and legacy.is_dir():
        try:
            legacy.rename(d)
        except OSError:                   # another Hermes process moved it first
            pass
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    return d


def _read(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return default


def _write(path: Path, data: Any) -> None:
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2))
    os.chmod(tmp, 0o600)
    tmp.replace(path)


def log_event(d: Optional[Path], kind: str, **fields: Any) -> None:
    """Append one line to the connection log: when, what (connected, tethered, allowed, ...), which device or
    host, a short session id, a reason. Never a command, a path or any content. Best effort: never raises."""
    if d is None:
        return
    try:
        rec = {"ts": round(time.time(), 3), "kind": kind}
        for key, value in fields.items():
            if value is None or value == "":
                continue
            rec[key] = short_session(value) if key == "session" else str(value)[:120]
        path = d / EVENTS_FILE
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a") as fh:
            fh.write(json.dumps(rec) + "\n")
        if path.stat().st_size > EVENTS_MAX_BYTES:
            lines = path.read_text().splitlines()[-EVENTS_KEEP:]
            tmp = path.with_suffix(".tmp")
            tmp.write_text("\n".join(lines) + "\n")
            os.chmod(tmp, 0o600)
            tmp.replace(path)
    except Exception:  # noqa: BLE001 - the log must never break a connection
        pass


def read_events(d: Path, limit: int = 100) -> list[dict[str, Any]]:
    """Newest first."""
    try:
        lines = (d / EVENTS_FILE).read_text().splitlines()[-max(1, limit):]
    except OSError:
        return []
    out = []
    for line in reversed(lines):
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


SETTINGS_FILE = "settings.json"         # device side: the Tether panel's choices; overrides config.yaml live
SETTINGS_LIMITS = {"grant_idle_minutes": (1.0, 24 * 60.0), "consent_timeout_seconds": (5.0, 600.0)}


def read_panel_settings(d: Path) -> dict[str, float]:
    raw = _read(d / SETTINGS_FILE, {})
    out: dict[str, float] = {}
    for key, (lo, hi) in SETTINGS_LIMITS.items():
        value = raw.get(key) if isinstance(raw, dict) else None
        if isinstance(value, (int, float)) and lo <= float(value) <= hi:
            out[key] = float(value)
    return out


def write_panel_settings(d: Path, changes: dict[str, Any]) -> dict[str, float]:
    """Validate and save; raises ValueError naming the setting and its range."""
    current = read_panel_settings(d)
    for key, value in changes.items():
        if key not in SETTINGS_LIMITS:
            raise ValueError(f"unknown setting {key!r}")
        lo, hi = SETTINGS_LIMITS[key]
        try:
            number = float(value)
        except (TypeError, ValueError):
            raise ValueError(f"{key} must be a number") from None
        if not lo <= number <= hi:
            raise ValueError(f"{key} must be between {lo:g} and {hi:g}")
        current[key] = number
    _write(d / SETTINGS_FILE, current)
    return current


HOST_IDLE_LIMITS = (1.0, 24 * 60.0)
RESERVED_LABELS = frozenset({"local", "host", "all"})


def normalize_label(label: Any) -> str:
    """A device label as the user says it: 'Studio PC' -> 'studio-pc' (opened by 'tether studio pc')."""
    import re
    text = re.sub(r"[\s_-]+", "-", str(label or "").strip().lower()).strip("-")
    if not re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", text) or len(text) > 32:
        raise ValueError("a label is 1-32 letters, numbers, spaces or hyphens")
    if text in RESERVED_LABELS:
        raise ValueError(f"{text!r} is reserved")
    return text


def short_session(session: Any) -> str:
    s = str(session or "")
    return s[-6:] if len(s) > 6 else s


class DevicePins:
    def __init__(self, d: Path) -> None:
        self.path = d / DEVICES_FILE

    def all(self) -> dict[str, dict[str, Any]]:
        return _read(self.path, {})

    def add(self, name: str, fp: str, cert_pem: str) -> None:
        data = self.all()
        data[name] = {"fp": fp, "cert_pem": cert_pem, "paired_at": time.time()}
        _write(self.path, data)

    def remove(self, name: str) -> bool:
        data = self.all()
        if data.pop(name, None) is None:
            return False
        _write(self.path, data)
        return True

    def update(self, name: str, *, label: Any = None, idle_minutes: Any = "keep") -> str:
        """Rename a paired device (its label is the word that opens it: 'tether <label>') and/or set the host's
        own idle limit for it (None clears it). Returns the device's name after the change."""
        data = self.all()
        if name not in data:
            raise ValueError(f"no paired device named {name!r}")
        rec = data[name]
        if idle_minutes != "keep":
            if idle_minutes in (None, ""):
                rec.pop("idle_minutes", None)
            else:
                lo, hi = HOST_IDLE_LIMITS
                try:
                    minutes = float(idle_minutes)
                except (TypeError, ValueError):
                    raise ValueError("idle_minutes must be a number") from None
                if not lo <= minutes <= hi:
                    raise ValueError(f"idle_minutes must be between {lo:g} and {hi:g}")
                rec["idle_minutes"] = minutes
        new = name
        if label not in (None, ""):
            new = normalize_label(label)
            if new != name and new in data:
                raise ValueError(f"another device is already called {new!r}")
        data.pop(name)
        data[new] = rec
        _write(self.path, data)
        return new

    def idle_minutes(self, name: str) -> Optional[float]:
        value = (self.all().get(name) or {}).get("idle_minutes")
        return float(value) if isinstance(value, (int, float)) else None

    def by_fp(self) -> dict[str, str]:
        return {v["fp"]: k for k, v in self.all().items()}

    def mtime(self) -> float:
        try:
            return self.path.stat().st_mtime
        except OSError:
            return 0.0


class HostPin:
    def __init__(self, d: Path) -> None:
        self.path = d / HOST_FILE

    def get(self) -> Optional[dict[str, Any]]:
        return _read(self.path, None)

    def set(self, **record: Any) -> None:
        _write(self.path, {**record, "paired_at": time.time()})

    def clear(self) -> bool:
        if self.path.exists():
            self.path.unlink()
            return True
        return False
