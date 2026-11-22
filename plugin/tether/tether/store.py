"""Non-secret state in the plugin's data folder: pins and addresses (secrets live in Hermes's store, D13)."""
from __future__ import annotations

import json
import math
import os
import tempfile
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
    _owner_only(d)
    return d


def _owner_only(d: Path) -> None:
    """chmod 0700 on the data folder itself, never on what a link in its place points to (the device's session
    workspaces refuse a linked data folder, workspace.py)."""
    if os.name == "nt":
        os.chmod(d, 0o700)
        return
    try:
        os.chmod(d, 0o700, follow_symlinks=False)       # macOS, Linux with glibc 2.32+: a link itself is never followed
        return
    except NotImplementedError:
        pass
    try:                                                # older Linux: change the folder held open, never a link
        fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        return
    try:
        os.fchmod(fd, 0o700)
    finally:
        os.close(fd)


def _read(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return default


def _write(path: Path, data: Any) -> None:
    _replace(path, json.dumps(data, indent=2))


def _replace(path: Path, text: str) -> None:
    """Replace a state file through a new private (0600) temporary file next to it: made fresh with a random name
    (mkstemp: O_EXCL, never through a link someone put there), then renamed into place. A failed write leaves no
    temporary file behind."""
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(text)
        os.replace(tmp, path)
    except BaseException:             # a failed write leaves no temporary file behind
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


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
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "a") as fh:
            fh.write(json.dumps(rec) + "\n")
            size = os.fstat(fh.fileno()).st_size
        if size > EVENTS_MAX_BYTES:
            lines = path.read_text().splitlines()[-EVENTS_KEEP:]
            _replace(path, "\n".join(lines) + "\n")
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
DEFAULT_GRANT_IDLE_MINUTES = 60.0      # D77: an hour without remote use before a session's Allow lapses
SETTINGS_LIMITS = {"grant_idle_minutes": (1.0, 24 * 60.0), "consent_timeout_seconds": (20.0, 600.0)}
# Yes/no settings of the panel. allow_unlocked_commands (D73): run a remote session's commands without the session
# lock. Unset: on for Windows (it has no lock), off for macOS. The device applies a change only while no remote
# session is connected (device.apply_panel_settings), so a session cannot unlock its own commands.
SETTINGS_FLAGS = ("allow_unlocked_commands",)


def default_unlocked() -> bool:
    """allow_unlocked_commands when nobody set it: on for Windows, off for macOS (and anything else)."""
    return os.name == "nt"


def flag(value: Any, default: bool) -> bool:
    """A yes/no setting as config.yaml or the panel may write it; anything unclear is the default."""
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower() if value is not None else ""
    if text in ("true", "1", "yes", "on"):
        return True
    if text in ("false", "0", "no", "off"):
        return False
    return default


def read_panel_settings(d: Path) -> dict[str, Any]:
    raw = _read(d / SETTINGS_FILE, {})
    out: dict[str, Any] = {}
    for key, (lo, hi) in SETTINGS_LIMITS.items():
        value = raw.get(key) if isinstance(raw, dict) else None
        if isinstance(value, (int, float)) and not isinstance(value, bool) and lo <= float(value) <= hi:
            out[key] = float(value)
    for key in SETTINGS_FLAGS:
        value = raw.get(key) if isinstance(raw, dict) else None
        if isinstance(value, bool):
            out[key] = value
    return out


def write_panel_settings(d: Path, changes: dict[str, Any]) -> dict[str, Any]:
    """Validate and save; raises ValueError naming the setting and its range."""
    current = read_panel_settings(d)
    for key, value in changes.items():
        if key in SETTINGS_FLAGS:
            if not isinstance(value, bool):
                raise ValueError(f"{key} must be true or false")
            current[key] = value
            continue
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


OPEN_FILE = "open_sessions.json"     # host side: session -> {device, pid, run, at}; who holds which connection
OPEN_LOCK_OLD = "open_sessions.lock"  # the lock file of the earlier version; removed when seen
# A record whose process is alive is kept whatever its age. One whose process has ended is kept this long after its
# holder last re-dated it, so a conversation resumed days after a crash or a clean exit is still told (F7, F31).
OPEN_MAX_AGE_S = 7 * 24 * 3600.0
OPEN_REFRESH_S = 600.0               # how often a live holder re-dates its records (Runtime.date_records)
OPEN_LOCK_WAIT_S = 2.0               # how long a record change waits for the folder lock before it gives up


def process_alive(pid: Any) -> bool:
    try:
        os.kill(int(pid), 0)
    except (ProcessLookupError, ValueError, TypeError, OverflowError):
        return False
    except PermissionError:           # it exists, under another user
        return True
    return True


class OpenSessions:
    """Which Hermes process on this host holds which device connection. The connection itself (targets, the
    grant token) lives only in that process's memory; this small file exists so that the same conversation,
    when it turns up in another process or after a restart, can be TOLD its device connection is not there
    instead of silently working on the host. Session ids and device names only: nothing secret."""

    def __init__(self, d: Path) -> None:
        self.path = d / OPEN_FILE

    def all(self) -> dict[str, dict[str, Any]]:
        data = _read(self.path, {})
        if not isinstance(data, dict):
            return {}
        now = time.time()

        def keep(v: Any) -> bool:
            if not isinstance(v, dict):
                return False
            try:                              # a damaged entry (an 'at' that is no number, or not finite) is old (F64)
                at = float(v.get("at") or 0)
                fresh = math.isfinite(at) and now - at < OPEN_MAX_AGE_S
            except (TypeError, ValueError):
                fresh = False
            return fresh or process_alive(v.get("pid"))     # a live holder's record never ages out (F31)
        return {k: v for k, v in data.items() if keep(v)}

    def _change(self, fn) -> None:
        import fcntl
        folder = self.path.parent
        try:
            # The data folder itself is the lock, so no lock file is left behind; the file of the earlier version
            # is removed when seen. An empty record is removed, not kept as "{}".
            fd = os.open(folder, os.O_RDONLY)
            try:
                # A note for later, never a reason to block: another program may hold the folder, and the sweeper
                # that calls this must not hang on it (F98).
                deadline = time.monotonic() + OPEN_LOCK_WAIT_S
                while True:
                    try:
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except BlockingIOError:
                        if time.monotonic() >= deadline:
                            return
                        time.sleep(0.05)
                (folder / OPEN_LOCK_OLD).unlink(missing_ok=True)
                data = self.all()
                fn(data)
                if data:
                    _write(self.path, data)
                else:
                    self.path.unlink(missing_ok=True)
            finally:
                os.close(fd)
        except OSError:               # a note for later, never a reason to fail the connection
            pass

    def put(self, session: str, device: str, run: str = "") -> None:
        """run: the writing process's own mark (Runtime.run_id), so a later process that gets the same pid is not
        taken for it."""
        self._change(lambda data: data.__setitem__(session, {"device": device, "pid": os.getpid(), "run": run,
                                                             "at": time.time()}))

    def touch(self, sessions: list[str], pid: int, run: str) -> None:
        """Re-dates the records of these sessions that this process (pid and run) wrote: it still holds them. A
        record another process wrote is left as it is."""
        def redate(data: dict[str, Any]) -> None:
            now = time.time()
            for session in sessions:
                rec = data.get(session)
                if isinstance(rec, dict) and rec.get("pid") == pid and rec.get("run") == run:
                    rec["at"] = now
        self._change(redate)

    def drop(self, session: str, pid: Optional[int] = None) -> None:
        """Removes the session's record. With pid, only a record that process wrote: another process's record stays
        (its connection is its own, F91)."""
        def remove(data: dict[str, Any]) -> None:
            rec = data.get(session)
            if rec is not None and (pid is None or rec.get("pid") == pid):
                data.pop(session, None)
        rec = self.all().get(session)
        if rec is not None and (pid is None or rec.get("pid") == pid):
            self._change(remove)


class DevicePins:
    def __init__(self, d: Path) -> None:
        self.path = d / DEVICES_FILE

    def all(self) -> dict[str, dict[str, Any]]:
        return _read(self.path, {})

    def add(self, name: str, fp: str, cert_pem: str) -> None:
        """Pin a device's key under this name. A limit the host owner set for the name stays (F66): pairing again
        never quietly lifts it."""
        data = self.all()
        rec = {"fp": fp, "cert_pem": cert_pem, "paired_at": time.time()}
        old = data.get(name) if isinstance(data.get(name), dict) else {}
        if isinstance(old.get("idle_minutes"), (int, float)):
            rec["idle_minutes"] = old["idle_minutes"]
        data[name] = rec
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
