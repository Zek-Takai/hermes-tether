"""Long-term identity for one machine: an Ed25519 key and a self-signed certificate made from it.

Storage follows Hermes's normal secret path (design D13):
- the private key lives on disk only ENCRYPTED (PEM, BestAvailableEncryption) in the plugin's data folder;
- the passphrase that unlocks it is a Hermes secret (``TETHER_KEY_PASSPHRASE``), stored and read through
  Hermes's own env-secret functions, so it sits in ``.env`` or whatever secret source the user configured;
- the certificate and the pins are not secret.
Python's ``ssl`` can only load a key from a file, so the encrypted file plus passphrase means the plain key
never touches disk.
"""
from __future__ import annotations

import base64
import contextvars
import ctypes
import datetime as _dt
import hashlib
import logging
import os
import secrets
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional, Protocol

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

logger = logging.getLogger(__name__)

PASSPHRASE_SECRET = "TETHER_KEY_PASSPHRASE"
LEGACY_PASSPHRASE_SECRETS = ("HOMEPORT_KEY_PASSPHRASE",)   # the working name before 2026-11-06
_NAMES = (PASSPHRASE_SECRET, *LEGACY_PASSPHRASE_SECRETS)
MASK = "\u00abredacted-vault-secret\u00bb"   # the mark Hermes's own exact-value masking uses
KEY_FILE = "identity.key.enc"
CERT_FILE = "identity.crt"
# Passphrases read at start-up and then taken out of os.environ: kept in memory only, so the store can still
# return them later in this process. Keyed by (Hermes home, name): one process can serve several profiles,
# each with its own key. Never logged, printed or persisted.
_HELD: dict[tuple[str, str], str] = {}
_HELD_LOCK = threading.Lock()


def _home_key() -> str:
    """The Hermes home (profile) the caller is working for, as one key whatever its spelling: Hermes's plugin loader
    names the home resolved (symlinks followed) while plugins register, and as written at run time (F48)."""
    try:
        from hermes_constants import get_hermes_home, hermes_home_key
        return hermes_home_key(get_hermes_home())
    except Exception:  # noqa: BLE001 - tests / outside Hermes
        return os.environ.get("HERMES_HOME") or os.path.expanduser("~/.hermes")


def blank_env() -> dict:
    """The env a terminal this plugin creates is given (LocalEnvironment(env=...)): Hermes lays it over everything
    else it builds a child's environment from (the process environment as it is at that moment, a reloaded .env, a
    multiplexed profile's secret scope), and drops a name whose value is None. So no child of such a terminal ever
    has the passphrase, whatever happened to os.environ since (F19, F73)."""
    return {name: None for name in _NAMES}


class SecretStore(Protocol):
    """Where the passphrase lives. Production: Hermes's env secrets. Tests: memory."""

    def get(self, name: str) -> Optional[str]: ...

    def put(self, name: str, value: str) -> None: ...


class HermesSecretStore:
    """Hermes's normal path: the same functions `hermes config set` uses for secrets."""

    def get(self, name: str) -> Optional[str]:
        """Hermes's public secret API first (catalog rule 11: honours the active profile's scope under
        multiplexing), then Hermes's own config reader (the environment, then this home's .env). Under
        multiplexing with no profile scope bound both refuse (UnscopedSecretError); then this home's own .env and
        secret sources are read, the home the plugin's data folder is in, never another profile's."""
        with _HELD_LOCK:
            held = _HELD.get((_home_key(), name))
        if held:
            return held                     # already read and taken out of the environment (protect_passphrase)
        try:
            from agent.secret_scope import get_secret
            value = get_secret(name)
            if value:
                return value
        except Exception:  # noqa: BLE001 - UnscopedSecretError: no profile scope bound yet
            pass
        from agent.secret_scope import UnscopedSecretError
        from hermes_cli.config import get_env_value
        try:
            return get_env_value(name) or None
        except UnscopedSecretError:
            from agent.secret_scope import build_profile_secret_scope
            from hermes_constants import get_hermes_home
            return build_profile_secret_scope(Path(get_hermes_home())).get(name) or None

    def put(self, name: str, value: str) -> None:
        from hermes_cli.config import save_env_value_secure
        save_env_value_secure(name, value)
        with _HELD_LOCK:
            _HELD[(_home_key(), name)] = value


_WARNED: set = set()


def _warn_once(what: str, text: str) -> None:
    if what not in _WARNED:
        _WARNED.add(what)
        logger.warning(text)


def _register_mask_as(home: str, value: str, register: Callable[[str], None]) -> None:
    """Run in a copied context: names the home as `home` for this one registration, then the copy is dropped. `home`
    is the same folder as the bound one, so Hermes only changes how the home is spelled (no scope is switched)."""
    from hermes_constants import set_hermes_home_override
    set_hermes_home_override(home)
    register(value)


def _mask_in_output(value: str) -> None:
    """Hermes masks this exact value in the output its tools hand the model (in memory, per process and per home
    spelling). Registered for the home as the caller names it, and also as the process names its own home when that
    is the same folder spelled another way (a home reached through a symlink: resolved while plugins load, as
    written at run time, F48). shield_children refreshes it under each tool call's own home."""
    try:
        from agent.redact_vault_values import register_vault_redaction_value
    except Exception:  # noqa: BLE001 - this Hermes lacks it: say so once, the plugin's own masking still applies
        _warn_once("mask", "tether: this Hermes cannot mask the key passphrase in its own tool output "
                           "(agent.redact_vault_values is missing)")
        return
    register_vault_redaction_value(value)
    try:
        from hermes_constants import get_hermes_home, get_process_hermes_home, hermes_home_key
        here, process = str(get_hermes_home()), str(get_process_hermes_home())
        if process != here and hermes_home_key(process) == hermes_home_key(here):
            contextvars.copy_context().run(_register_mask_as, process, value, register_vault_redaction_value)
    except Exception:  # noqa: BLE001 - the mask for the caller's own spelling is in place
        pass


def mask_secrets(text: str) -> str:
    """Every key passphrase this process holds, replaced by MASK, exactly. A device runs its command and tool output
    through this before it leaves the machine: the host never holds the device's value, so Hermes's masking there
    cannot catch it. Exact bytes only: an encoded or transformed copy passes (README: what it does not protect
    against)."""
    if not text:
        return text
    with _HELD_LOCK:
        held = {v for v in _HELD.values() if v}
    try:
        from .seedstore import masked_values      # the authenticator seed's forms this process holds (D66)
        held |= masked_values()
    except Exception:  # noqa: BLE001 - masking must never fail a command's output
        pass
    values = sorted(held, key=len, reverse=True)
    for value in values:
        if value in text:
            text = text.replace(value, MASK)
    return text


# ---------- the start-up copy of the environment (F2) ----------
# os.environ.pop unsets a name for this process and its future children, but the kernel keeps the environment the
# process was started with, and shows it to any program of the same user: `ps -E` / psutil on macOS (sysctl
# KERN_PROCARGS2 reads the strings above the main thread's stack), /proc/<pid>/environ on Linux. A gateway that
# Hermes starts itself (gateway ensure, a detached restart) gets every .env secret there. So the value bytes of
# each passphrase name are overwritten in place with '*'. The name and the string's length stay, so every other
# variable still reads as before (Hermes's own updater reads a gateway's start-up environment). Nothing is written
# unless the bytes at the address are first read back, safely, and match the kernel's copy exactly.

def _value_spots(area: bytes, first: int, names=_NAMES) -> list:
    """(offset of the string, length of NAME=, length of the value) for each NUL-separated string from `first` on
    that starts with NAME= and whose value is not already all '*'."""
    keys = [name.encode() + b"=" for name in names]
    spots, i = [], first
    while i < len(area):
        j = area.find(b"\0", i)
        j = len(area) if j == -1 else j
        for key in keys:
            if area.startswith(key, i) and area[i + len(key):j].strip(b"*"):
                spots.append((i, len(key), j - i - len(key)))
        i = j + 1
    return spots


def _procargs(libc) -> Optional[bytes]:
    mib = (ctypes.c_int * 3)(1, 49, os.getpid())          # CTL_KERN, KERN_PROCARGS2, this process
    size = ctypes.c_size_t(0)
    if libc.sysctl(mib, 3, None, ctypes.byref(size), None, ctypes.c_size_t(0)) != 0 or not size.value:
        return None
    buf = ctypes.create_string_buffer(size.value)
    if libc.sysctl(mib, 3, buf, ctypes.byref(size), None, ctypes.c_size_t(0)) != 0:
        return None
    return buf.raw[:size.value]


def _clear_startup_darwin() -> Optional[bool]:
    libc = ctypes.CDLL(None, use_errno=True)
    raw = _procargs(libc)
    if raw is None or len(raw) < 8:
        return None
    first = raw.find(b"\0", 4)                           # argc (4 bytes), the executable path, NUL padding, argv[0]
    if first == -1:
        return None
    while first < len(raw) and raw[first] == 0:
        first += 1
    spots = _value_spots(raw, first)
    if not spots:
        return None
    task = ctypes.c_uint.in_dll(libc, "mach_task_self_").value
    libc.vm_read_overwrite.argtypes = [ctypes.c_uint, ctypes.c_size_t, ctypes.c_size_t, ctypes.c_void_p,
                                       ctypes.POINTER(ctypes.c_size_t)]
    libc.vm_read_overwrite.restype = ctypes.c_int
    libc.vm_write.argtypes = [ctypes.c_uint, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_uint]
    libc.vm_write.restype = ctypes.c_int
    libc._NSGetArgv.restype = ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))

    def peek(addr: int, n: int) -> Optional[bytes]:       # an unmapped address is an error code, never a crash
        buf, got = ctypes.create_string_buffer(n), ctypes.c_size_t(0)
        if libc.vm_read_overwrite(task, addr, n, ctypes.addressof(buf), ctypes.byref(got)) != 0:
            return None
        return buf.raw[:got.value]

    argv0 = libc._NSGetArgv().contents[0]               # the original argv[0] string, in the same area
    end0 = raw.find(b"\0", first)
    if not argv0 or end0 == -1 or peek(argv0, end0 - first + 1) != raw[first:end0 + 1]:
        return False                                    # argv was moved (a process-title library): leave it alone
    for at, key_len, value_len in spots:
        addr = argv0 + (at - first)
        if peek(addr, key_len + value_len + 1) != raw[at:at + key_len + value_len + 1]:
            return False
        stars = ctypes.create_string_buffer(b"*" * value_len, value_len)
        if libc.vm_write(task, addr + key_len, ctypes.addressof(stars), value_len) != 0:
            return False
    after = _procargs(libc)
    return after is not None and not _value_spots(after, first)


def _writable_mapping(start: int, end: int) -> bool:
    """True when [start, end) lies in one writable mapping of this process (/proc/self/maps)."""
    with open("/proc/self/maps", "rb") as fh:
        for line in fh:
            span, perms = line.split()[:2]
            low, high = (int(x, 16) for x in span.split(b"-"))
            if low <= start and end <= high:
                return perms[1:2] == b"w"
    return False


def _clear_startup_linux() -> Optional[bool]:
    with open("/proc/self/stat", "rb") as fh:
        fields = fh.read().rsplit(b")", 1)[1].split()
    start, end = int(fields[47]), int(fields[48])       # env_start, env_end: fields 50 and 51 of proc(5)
    if not 0 < start < end:
        return None
    fd = os.open("/proc/self/mem", os.O_RDWR)           # an unmapped address is an error here, never a crash
    try:
        spots = _value_spots(os.pread(fd, end - start, start), 0)
        if not spots:
            return None
        for at, key_len, value_len in spots:
            addr, stars = start + at + key_len, b"*" * value_len
            try:
                os.pwrite(fd, stars, addr)
            except OSError:                             # a kernel that refuses writes through /proc/self/mem
                if not _writable_mapping(addr, addr + value_len):
                    return False
                ctypes.memmove(addr, stars, value_len)  # read just above, and writable: mapped, never a crash
        return not _value_spots(os.pread(fd, end - start, start), 0)
    finally:
        os.close(fd)


def clear_startup_copy() -> Optional[bool]:
    """Overwrite the passphrase values in this process's start-up environment (see above). True: cleared; None:
    there was nothing to clear (or no such copy: Windows keeps one live environment, which os.environ.pop updates);
    False: found but not cleared. Never raises; never logs a value."""
    try:
        if sys.platform == "darwin":
            return _clear_startup_darwin()
        if sys.platform.startswith("linux"):
            return _clear_startup_linux()
    except Exception:  # noqa: BLE001
        return False
    return None


def protect_passphrase(store: "SecretStore") -> None:
    """Take the key passphrase out of this process's environment, so no shell the agent starts inherits it and
    no listing of this process's environment shows it (README/DESIGN 5.1). Hermes loads .env into the
    environment; this reads the values first, masks them in output, pops the names and clears the start-up copy.
    Run in every process the plugin loads in. Never logs, prints or returns a value."""
    try:
        held: dict[str, str] = {}
        for name in _NAMES:
            try:
                value = store.get(name)
            except Exception:  # noqa: BLE001 - one unreadable name must not hide the others
                value = None
            if value:
                held[name] = value
        home = _home_key()
        with _HELD_LOCK:
            _HELD.update({(home, name): value for name, value in held.items()})
        for name in _NAMES:
            os.environ.pop(name, None)
        if clear_startup_copy() is False:
            logger.warning("tether: the key passphrase could not be cleared from this process's start-up "
                           "environment")
        for value in held.values():
            _mask_in_output(value)
    except Exception:  # noqa: BLE001 - never let the passphrase or its error reach the log
        logger.warning("tether: could not take the key passphrase out of the process environment")


def shield_children() -> None:
    """Call at the start of every tool call (forward.tool_execution) and right before this plugin starts a child.
    Hermes can load its .env into the process environment again at any time (a cron job's start, a "reload env"
    command, a secret-source refresh): take the names out again, and refresh the mask of this home's value under
    the home as this call names it (Hermes keeps a bounded number of masks per home). A value found here is not
    kept (it belongs to the launch profile, which may not be the one being served); the store reads it from
    Hermes again when it is needed. Cheap; never raises; never logs a value."""
    try:
        found = [os.environ.pop(name, None) for name in _NAMES]
        home = _home_key()
        with _HELD_LOCK:
            held = [value for (h, _), value in _HELD.items() if h == home]
        for value in {v for v in (*found, *held) if v}:
            _mask_in_output(value)
    except Exception:  # noqa: BLE001
        pass


class MemorySecretStore:
    def __init__(self) -> None:
        self._values: dict[str, str] = {}

    def get(self, name: str) -> Optional[str]:
        return self._values.get(name)

    def put(self, name: str, value: str) -> None:
        self._values[name] = value


def fingerprint(cert_der: bytes) -> str:
    """SHA-256 of the DER certificate, lowercase hex: what both sides pin."""
    return hashlib.sha256(cert_der).hexdigest()


@dataclass(frozen=True)
class Identity:
    cert_pem: bytes
    key_path: Path          # encrypted PEM on disk
    passphrase: bytes       # unlocks key_path; never logged, never returned to the agent

    @property
    def cert_der(self) -> bytes:
        return x509.load_pem_x509_certificate(self.cert_pem).public_bytes(serialization.Encoding.DER)

    @property
    def fp(self) -> str:
        return fingerprint(self.cert_der)

    def password_callback(self) -> Callable[[], bytes]:
        return lambda: self.passphrase


def _make_cert(key: Ed25519PrivateKey, common_name: str) -> bytes:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = _dt.datetime.now(_dt.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - _dt.timedelta(days=1))
            # Trust is the pinned fingerprint, not the date; a long life avoids silent expiry breaks.
            .not_valid_after(now + _dt.timedelta(days=365 * 20))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, algorithm=None))
    return cert.public_bytes(serialization.Encoding.PEM)


def load_or_create(data_dir: Path, store: SecretStore, common_name: str) -> Identity:
    """Load this machine's identity, creating it on first use."""
    data_dir.mkdir(parents=True, exist_ok=True)
    from .store import _owner_only
    _owner_only(data_dir)                 # the folder itself, never what a link in its place names (D39, D55)
    key_path, cert_path = data_dir / KEY_FILE, data_dir / CERT_FILE
    raw = store.get(PASSPHRASE_SECRET)
    if not raw:
        for legacy in LEGACY_PASSPHRASE_SECRETS:   # carried over through Hermes's own secret store, never logged
            raw = store.get(legacy)
            if raw:
                store.put(PASSPHRASE_SECRET, raw)
                break
    if key_path.exists() and cert_path.exists() and raw:
        passphrase = base64.urlsafe_b64decode(raw.encode())
        serialization.load_pem_private_key(key_path.read_bytes(), password=passphrase)  # fails loudly if wrong
        return Identity(cert_path.read_bytes(), key_path, passphrase)
    if key_path.exists() or cert_path.exists():
        raise RuntimeError(
            f"tether identity in {data_dir} is incomplete (key, certificate or the {PASSPHRASE_SECRET} "
            "secret is missing); remove the folder to create a new identity, then pair again")
    passphrase = secrets.token_bytes(32)
    key = Ed25519PrivateKey.generate()
    enc = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.BestAvailableEncryption(passphrase))
    cert_pem = _make_cert(key, common_name)
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(enc)
    cert_path.write_bytes(cert_pem)
    store.put(PASSPHRASE_SECRET, base64.urlsafe_b64encode(passphrase).decode())
    return Identity(cert_pem, key_path, passphrase)
