"""The device's authenticator secret (its TOTP seed) and its recovery codes (design D66).

The seed has two exits and no others:
- once, at setup, on this machine's own screen: ``PendingSetup.key_text()``, shown by the setup command's box at the
  device (never through the link, never in a log, never on stdout);
- ``SeedStore.get_seed()`` / ``seal_key()``, from this process's memory, to the code check (authcode.CodeChecker),
  which answers only accepted / wrong / used / held. The host learns only the gate's approve or deny.
Nothing in this module logs, prints or raises a seed or a code, and it starts no process: every error text is fixed
and raised ``from None``.

Where the seed lives: one sealed file in Tether's own data folder, next to ``identity.key.enc``:
``authenticator.json`` (0600, written through a fresh private temporary file that is flushed and renamed into place,
read without ever following a link). Its ``sealed`` field holds the record (the seed and salted fingerprints of the
recovery codes), encrypted:
- macOS (and the tests): AES-256-GCM under a key derived (HKDF-SHA256) from Tether's key passphrase, the Hermes
  secret ``TETHER_KEY_PASSPHRASE`` that also unlocks ``identity.key.enc``, with the authenticator's id as associated
  data. The file alone (a copied data folder, a backup without Hermes's secrets) opens nothing.
- macOS while Hermes keeps its own vault key in the OS keychain (``vault.key_storage: keychain``): the same
  AES-256-GCM under a 32-byte random key that lives in the OS keychain, written and read exactly the way Hermes
  writes and reads its vault key there (Hermes's own ``os_keyring()``, its own service name, its own read-back
  check; the record names the entry, never the key). The owner's rule (D78): Tether keeps its 2FA secret the way
  Hermes keeps its own. The record says which seal wrote it and is always opened with that seal; a setting that
  changed later re-seals it. A re-seal that fails for any reason leaves the old record whole and the open unharmed
  (one fixed warning line, never the error's own text), and a keychain entry that re-seal wrote but that no record
  names goes with it, so no key is left behind that nothing can open.
- Windows: DPAPI, this user's scope, never with a prompt (CRYPTPROTECT_UI_FORBIDDEN).
- Anything else: no store; the device refuses remote use (it has no box either).
There is no password box and no administrator dialog (the owner's ruling, 2026-11-21: Tether cannot require a step
that Hermes itself does not have). The keychain is used only when Hermes uses it for its own vault key, and it asks
for nothing: the same keychain, the same call and the same read-back check Hermes makes. What keeps a remote
session away from these files on macOS is the
session lock (lock.py, D70-D76): a session's commands can neither read nor write Tether's data folder or Hermes's
``.env``, and the file tools run inside the same lock (filebox, D79). Outside a session, any program running as the person can read them (the
normal risk of a program on one's own computer; README limits). The sealed code state ``authenticator_state.json``
lives beside it (authcode.py).
"""
from __future__ import annotations

import base64
import contextlib
import ctypes
import hashlib
import hmac
import json
import logging
import os
import secrets
import stat
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Optional

from . import authcode
from .authcode import NO_AUTHENTICATOR_TEXT, NO_SAFE_STORE_TEXT, SET_UP_AGAIN_TEXT, SeedUnavailable, hkdf

logger = logging.getLogger(__name__)

NAME = "Hermes Tether authenticator"         # the record's name (DPAPI description; never a secret)
REF_FILE = "authenticator.json"              # the sealed record and which authenticator it is (0600)
STATUS_FILE = "authenticator_status.json"    # non-secret: what the running Hermes last saw (for the CLI and panel)
OWN_FILES = (REF_FILE, authcode.STATE_FILE, authcode.LOCK_FILE, STATUS_FILE)

SEED_BYTES = 20                # 160 bits, RFC 4226's recommended HMAC-SHA1 key length
_RECOVERY_LABEL = b"tether-recovery-v1\0"
_SEED_SEAL_INFO = b"tether-authenticator-seed-v1"
_FORMAT = 2                    # 1 was the keychain pointer of the G2 prototype (never released)
KEYCHAIN_SERVICE = "Hermes Tether 2FA key"     # the OS keychain entry's service (never a secret)
_SEAL_NAMES = ("passphrase", "hermes-keychain", "dpapi")     # the seals a record may name
_KEYCHAIN_ACCOUNT_RE = __import__("re").compile(r"tether-2fa-[0-9a-f]{32}")   # a random entry name, never a path

# ---------- Hermes's own key storage (where its vault key lives) ----------
# Hermes keeps its vault key either in a 0600 file (the default) or, when the user sets `vault.key_storage:
# keychain`, in the OS keychain through the `keyring` library (Hermes's own agent/vault_keychain.py). Tether's
# 2FA secret follows the same rule (D78): the same helpers, the same keychain, the same read-back check, and no
# step of its own. A Hermes that cannot say (no such setting, or a config it cannot read) means the file.

try:                                    # Hermes's own keychain helpers (its vault's), used as they are
    from agent.vault_keychain import os_keyring
except Exception:                       # noqa: BLE001 - this Hermes has no keychain support: the file seal stays
    os_keyring = None                   # type: ignore[assignment]

try:                                    # Hermes's own setting: where it keeps its vault key
    from agent.vault_store import configured_key_storage
except Exception:                       # noqa: BLE001 - this Hermes cannot say: the file seal stays
    configured_key_storage = None       # type: ignore[assignment]

_WARNED: set[str] = set()


def _warn_once(what: str, text: str) -> None:
    """One warning line per process (never a value, never a stack trace)."""
    if what in _WARNED:
        return
    _WARNED.add(what)
    logger.warning(text)


def _hermes_key_storage() -> str:
    """Hermes's own setting (``vault.key_storage``): "file" (its default) or "keychain". "file" when this Hermes
    cannot say (no such setting, or a config that cannot be read)."""
    if configured_key_storage is None:
        return "file"
    try:
        return str(configured_key_storage() or "file").strip().lower()
    except Exception:  # noqa: BLE001 - an unreadable config: the default (a file) is the safe answer
        return "file"


def _keychain_backend():
    """The OS credential store Hermes's own vault would use, or raise StoreUnavailable."""
    if os_keyring is None:
        raise StoreUnavailable("no OS keychain is reachable on this machine")
    try:
        return os_keyring()
    except Exception:  # noqa: BLE001 - a locked or absent keychain (Hermes's own words are not ours to show)
        raise StoreUnavailable("no OS keychain is reachable on this machine") from None


def _keychain_answers() -> bool:
    """True when the OS keychain answers (Hermes's own check, through its own os_keyring())."""
    try:
        _keychain_backend()
        return True
    except StoreUnavailable:
        return False


# Store states (status()).
NONE = "none"                  # no authenticator set up in this profile
READY = "ready"                # held in this process's memory; codes can be checked
MISSING = "missing"            # the record is damaged, sealed for another key, or not a plain file
UNAVAILABLE = "unavailable"    # no supported way to seal the record on this machine
PRESENT = "present"            # pointer_state() only: a record is there (not opened)

REFUSALS = {NONE: NO_AUTHENTICATOR_TEXT, MISSING: SET_UP_AGAIN_TEXT, UNAVAILABLE: NO_SAFE_STORE_TEXT}

# What the person sees for each state (`hermes tether status`, the panel). Fixed sentences, no values.
STATUS_TEXT = {
    NONE: f"authenticator: OFF, so remote use is refused; to turn it on, run `{authcode.SETUP_COMMAND}` here, with "
          "your phone at hand",
    READY: "authenticator: on",
    MISSING: f"authenticator: DAMAGED, so remote use is refused; set it up again here: `{authcode.SETUP_COMMAND}`",
    UNAVAILABLE: "authenticator: this machine has no safe place for one (macOS and Windows only); remote use is "
                 "refused",
}


class SeedStoreError(Exception):
    """A fixed sentence; never a value."""


class StoreUnavailable(SeedStoreError):
    pass


def _b32(seed: bytes | bytearray) -> str:
    return base64.b32encode(bytes(seed)).decode().rstrip("=")


def _unb32(text: str) -> bytearray:
    return bytearray(base64.b32decode(text + "=" * (-len(text) % 8)))


# ---------- what the device masks in its output (identity.mask_secrets) ----------

_MASKS: set[str] = set()
_MASKS_LOCK = threading.Lock()


def _add_masks(seed: bytes | bytearray) -> None:
    text = _b32(seed)
    grouped = " ".join(text[i:i + 4] for i in range(0, len(text), 4))
    with _MASKS_LOCK:
        _MASKS.update({text, text.lower(), grouped, grouped.lower(), bytes(seed).hex()})


def masked_values() -> set[str]:
    """The seed forms this process holds (setup, unlock): a device replaces them with the mask in what it sends."""
    with _MASKS_LOCK:
        return set(_MASKS)


# ---------- recovery codes (stored only as salted fingerprints inside the sealed record) ----------
# A recovery code is 80 random bits (enroll.new_recovery_codes), so an offline search of a fingerprint is out of
# reach without a slow hash; the fingerprints also live only inside the sealed record.

def hash_recovery_codes(codes: list[str]) -> dict:
    """{"salt": hex, "hashes": [hex, ...]} for codes already cleaned (enroll.clean_recovery)."""
    salt = secrets.token_bytes(16)
    return {"salt": salt.hex(), "hashes": [_recovery_hash(salt, c) for c in codes]}


def _recovery_hash(salt: bytes, code: str) -> str:
    return hmac.new(salt, _RECOVERY_LABEL + str(code).encode(), hashlib.sha256).hexdigest()


def _valid_recovery(rec: Any) -> bool:
    if not isinstance(rec, dict) or not isinstance(rec.get("salt"), str) or not isinstance(rec.get("hashes"), list):
        return False
    try:
        bytes.fromhex(rec["salt"])
    except ValueError:
        return False
    return all(isinstance(h, str) and len(h) == 64 for h in rec["hashes"])


# ---------- small private-file helpers (never through a link) ----------

def _read_own(path: Path) -> Optional[bytes]:
    """The bytes of a regular file of ours, or None when it is missing. A link (or reparse point) in its place, or
    anything that is not a plain file, raises: it is never followed."""
    if os.name == "nt":
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            return None
        if stat.S_ISLNK(st.st_mode) or getattr(st, "st_file_attributes", 0) & 0x400 or not stat.S_ISREG(st.st_mode):
            raise SeedStoreError("an authenticator file in the data folder is not a plain file; it was not read")
        return path.read_bytes()
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
    except FileNotFoundError:
        return None
    except OSError:
        raise SeedStoreError("an authenticator file in the data folder is not a plain file; it was not read") from None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise SeedStoreError("an authenticator file in the data folder is not a plain file; it was not read")
        chunks = []
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def _write_own(path: Path, data: bytes) -> None:
    """Replace one of our files through a fresh private (0600) temporary file next to it, flushed to disk and renamed
    into place: a link put at the name is replaced, never written through, and a crash leaves the old file or the new
    one, never half of either. A failed write leaves no temporary file."""
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def _remove_own(path: Path) -> None:
    """Remove the name itself (a link is removed, never followed); a folder in its place is left alone."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return
    if stat.S_ISDIR(st.st_mode):
        return
    with contextlib.suppress(OSError):
        os.unlink(path)


# ---------- sealing the record ----------

def _hermes_passphrase() -> bytes:
    """Tether's key passphrase as Hermes's secret store holds it (never created here)."""
    from .identity import PASSPHRASE_SECRET, HermesSecretStore
    raw = HermesSecretStore().get(PASSPHRASE_SECRET)
    if not raw:
        raise StoreUnavailable("Tether's key passphrase is not set on this machine yet (pair it first: hermes tether "
                               "join)")
    return base64.urlsafe_b64decode(raw.encode())


def _seal_bytes(key: bytes, record: bytes, account: str) -> bytes:
    """AES-256-GCM under key (a fresh nonce each time), with the authenticator's id as associated data."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = secrets.token_bytes(12)
    return b"\x01" + nonce + AESGCM(key).encrypt(nonce, bytes(record), account.encode())


def _open_bytes(key: bytes, blob: bytes, account: str) -> bytes:
    """The record inside a sealed blob (the same text as before, whichever seal wrote it)."""
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if len(blob) < 1 + 12 + 16 or blob[:1] != b"\x01":
        raise SeedStoreError("the authenticator record is damaged")
    try:
        return AESGCM(key).decrypt(blob[1:13], blob[13:], account.encode())
    except InvalidTag:
        raise SeedStoreError("the authenticator record is damaged or sealed with another key") from None


class PassphraseSeal:
    """AES-256-GCM under HKDF-SHA256(Tether's key passphrase): the same secret that unlocks identity.key.enc. The
    associated data is the authenticator's id, so a record cannot be moved under another one's name."""

    name = "sealed file"
    kind = "sealed-file"
    seal_name = "passphrase"

    def __init__(self, secret: Optional[Callable[[], bytes]] = None) -> None:
        self.secret = secret or _hermes_passphrase

    def available(self) -> bool:
        return True

    def _key(self) -> bytes:
        try:
            passphrase = self.secret()
        except SeedStoreError:
            raise
        except Exception:  # noqa: BLE001 - never the secret store's own text
            raise StoreUnavailable("Tether's key passphrase could not be read") from None
        if not passphrase:
            raise StoreUnavailable("Tether's key passphrase could not be read")
        return hkdf(bytes(passphrase), _SEED_SEAL_INFO)

    def seal(self, record: bytes, account: str) -> bytes:
        return _seal_bytes(self._key(), record, account)

    def open(self, blob: bytes, account: str) -> bytes:
        return _open_bytes(self._key(), blob, account)


class HermesKeychainSeal:
    """AES-256-GCM under a 32-byte random key that lives in the OS keychain: the way Hermes keeps its own vault key
    when ``vault.key_storage: keychain`` is set (Hermes's own ``os_keyring()``, its own read-back check, a random
    account name in Tether's own non-secret record). The owner's rule (D78): Tether keeps its 2FA secret the way
    Hermes keeps its own; it adds no step and asks for nothing.

    ``created_entry``: True when this seal wrote a keychain entry of its own that no record names yet. Only such an
    entry may be taken away again (a failure that left no record to open it); an entry that was there before is the
    record's own key and stays."""

    name = "OS keychain"
    kind = "hermes-keychain"
    seal_name = "hermes-keychain"
    SERVICE = KEYCHAIN_SERVICE

    def __init__(self, account: str = "") -> None:
        self.account = str(account or "")
        self._key: Optional[bytes] = None
        self.created_entry = False       # True only when this seal wrote an entry of its own

    def available(self) -> bool:
        return _keychain_answers()

    def entry(self) -> str:
        """The keychain account this seal uses: a random name, never derived from a path or a profile."""
        if not self.account:
            self.account = f"tether-2fa-{uuid.uuid4().hex}"
        return self.account

    def keychain_ref(self) -> dict:
        """The non-secret pointer to the entry (Hermes's own shape): what the record keeps."""
        return {"storage": "keychain", "service": self.SERVICE, "account": self.entry()}

    def _write_key(self, key: bytes) -> None:
        """The key into the OS keychain, the way Hermes writes its vault key: set it, then read it back (a store
        that cannot return what it was given is unusable)."""
        backend = _keychain_backend()
        value = key.hex()
        try:
            backend.set_password(self.SERVICE, self.entry(), value)
            readback = backend.get_password(self.SERVICE, self.account)
        except Exception:  # noqa: BLE001 - every keyring backend raises its own types
            raise StoreUnavailable("the OS keychain refused the authenticator's key") from None
        if readback != value:
            raise StoreUnavailable("the OS keychain did not return the authenticator's key")

    def _stored_key(self) -> Optional[bytes]:
        """The key this entry holds now, or None when it holds none (or cannot be read)."""
        if not self.account:
            return None
        try:
            backend = _keychain_backend()
        except StoreUnavailable:
            return None
        try:
            value = backend.get_password(self.SERVICE, self.account)
        except Exception:  # noqa: BLE001 - a locked keychain answers with its own error
            return None
        if not value:
            return None
        try:
            key = bytes.fromhex(value)
        except ValueError:
            return None
        return key if len(key) == 32 else None

    def _read_key(self) -> bytes:
        key = self._stored_key()
        if key is None:
            raise SeedStoreError("the authenticator record is damaged or sealed with another key")
        return key

    def seal(self, record: bytes, account: str) -> bytes:
        key = self._key
        if key is None:
            key = self._stored_key()          # the entry's own key: a record sealed again keeps its key
            if key is None:
                key = secrets.token_bytes(32)
                self._write_key(key)
                self.created_entry = True     # an entry of our own: it goes if no record is written for it
            self._key = key
        return _seal_bytes(hkdf(key, _SEED_SEAL_INFO), record, account)

    def open(self, blob: bytes, account: str) -> bytes:
        return _open_bytes(hkdf(self._read_key(), _SEED_SEAL_INFO), blob, account)


class _Blob(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_uint32), ("pbData", ctypes.POINTER(ctypes.c_char))]


class WindowsDpapi:
    """DPAPI, this user's scope (CryptProtectData without CRYPTPROTECT_LOCAL_MACHINE), never a prompt. Any program
    running as this user can unprotect it: Windows binds it to the user, not to a program. Untested (no Windows
    machine in this design round)."""

    name = "Windows DPAPI"
    kind = "windows-dpapi"
    seal_name = "dpapi"
    UI_FORBIDDEN = 0x1
    ENTROPY = b"hermes-tether-authenticator-v1\0"   # not a secret: with the id it binds the blob to its record

    def available(self) -> bool:
        if os.name != "nt":
            return False
        try:
            ctypes.WinDLL("crypt32")
            return True
        except OSError:
            return False

    def _call(self, name: str, data: bytes, account: str) -> bytes:
        crypt32, kernel32 = ctypes.WinDLL("crypt32"), ctypes.WinDLL("kernel32")
        f = getattr(crypt32, name)
        f.restype = ctypes.c_int
        # CryptProtectData(in, description, entropy, reserved, prompt, flags, out); CryptUnprotectData has the same
        # shape with an out-pointer for the description, passed as NULL here.
        f.argtypes = [ctypes.POINTER(_Blob), ctypes.c_wchar_p, ctypes.POINTER(_Blob), ctypes.c_void_p,
                      ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(_Blob)]
        kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        kernel32.LocalFree.restype = ctypes.c_void_p
        entropy = self.ENTROPY + account.encode()
        buf = ctypes.create_string_buffer(bytes(data), len(data))
        ent = ctypes.create_string_buffer(entropy, len(entropy))
        inb = _Blob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
        entb = _Blob(len(entropy), ctypes.cast(ent, ctypes.POINTER(ctypes.c_char)))
        out = _Blob()
        desc = NAME if name == "CryptProtectData" else None
        try:
            if not f(ctypes.byref(inb), desc, ctypes.byref(entb), None, None, self.UI_FORBIDDEN, ctypes.byref(out)):
                raise SeedStoreError("Windows did not seal or open the authenticator record (DPAPI)")
            try:
                return ctypes.string_at(out.pbData, out.cbData)
            finally:
                if name == "CryptUnprotectData":
                    ctypes.memset(out.pbData, 0, out.cbData)
                kernel32.LocalFree(out.pbData)
        finally:
            ctypes.memset(buf, 0, len(data))

    def seal(self, record: bytes, account: str) -> bytes:
        return self._call("CryptProtectData", record, account)

    def open(self, blob: bytes, account: str) -> bytes:
        return self._call("CryptUnprotectData", blob, account)


class NoStore:
    name = "none"
    kind = "none"
    seal_name = "none"

    def available(self) -> bool:
        return False

    def seal(self, record: bytes, account: str) -> bytes:
        raise StoreUnavailable(STATUS_TEXT[UNAVAILABLE])

    def open(self, blob: bytes, account: str) -> bytes:
        raise StoreUnavailable(STATUS_TEXT[UNAVAILABLE])


def default_backend(folder: Path, secret: Optional[Callable[[], bytes]] = None):
    """The seal this machine uses now (D78): Windows keeps DPAPI; elsewhere the OS keychain when Hermes keeps its
    own vault key there and the keychain answers, else Tether's key passphrase (the default). A keychain that was
    configured but does not answer falls back to the passphrase seal and says so, once."""
    if os.name == "nt":
        return WindowsDpapi()
    if _hermes_key_storage() == "keychain":
        if _keychain_answers():
            return HermesKeychainSeal()
        _warn_once("keychain", "tether: Hermes keeps its vault key in the OS keychain, but no keychain answers here; "
                               "the authenticator's key stays sealed with Tether's key passphrase instead")
    if sys.platform == "darwin":
        return PassphraseSeal(secret)
    return NoStore()


# ---------- the seal a record names ----------

def _seal_name(ref: dict) -> str:
    """The seal a record names: "passphrase", "hermes-keychain" or "dpapi" ("" when it names none of them). A record
    from before the field existed says it through its "backend": a Windows record stays a DPAPI one, every other a
    passphrase one."""
    name = ref.get("seal")
    if isinstance(name, str) and name:
        return name if name in _SEAL_NAMES else ""
    backend = ref.get("backend")
    if backend == WindowsDpapi.kind:
        return "dpapi"
    return "passphrase"


def _keychain_account(ref: dict) -> str:
    """The keychain entry a record names (its own; never another record's)."""
    entry = ref.get("keychain")
    if isinstance(entry, dict):
        account = entry.get("account")
        if isinstance(account, str) and _KEYCHAIN_ACCOUNT_RE.fullmatch(account):
            return account
    raise SeedStoreError("the authenticator record is damaged")


def _delete_keychain_entry(entry: Any) -> None:
    """Tether's own keychain entry, removed the way Hermes removes its vault's: delete it, then read it back."""
    if not isinstance(entry, dict):
        return
    account = entry.get("account")
    service = entry.get("service") or KEYCHAIN_SERVICE
    if not isinstance(account, str) or not account:
        return
    try:
        backend = _keychain_backend()
    except StoreUnavailable:
        _warn_once("keychain-entry", "tether: the OS keychain did not answer; Tether's authenticator key may still be "
                                     "in it")
        return
    try:
        with contextlib.suppress(Exception):     # a missing entry raises PasswordDeleteError
            backend.delete_password(str(service), account)
        left = backend.get_password(str(service), account)
    except Exception:  # noqa: BLE001 - an unreachable keychain: the entry stays and is named once
        _warn_once("keychain-entry", "tether: the OS keychain did not answer; Tether's authenticator key may still be "
                                     "in it")
        return
    if left is not None:
        _warn_once("keychain-entry", "tether: the OS keychain did not answer; Tether's authenticator key may still be "
                                     "in it")


def _record_names_entry(folder: Path, account: str) -> bool:
    """True when the record file in this folder names this keychain entry: that entry is the record's own key and
    stays, whatever a failure does."""
    try:
        raw = _read_own(Path(folder) / REF_FILE)
        ref = json.loads(raw.decode()) if raw else None
    except (SeedStoreError, ValueError, UnicodeDecodeError):
        return False
    entry = (ref or {}).get("keychain")
    return isinstance(entry, dict) and entry.get("account") == account


def _drop_created_entry(seal: Any, folder: Path) -> None:
    """A keychain entry this call wrote and that no record names: it goes with the failure, so no key is left
    behind that nothing can open. An entry that was there before (the record's own key) stays: only the seal's own
    flag says what this call wrote."""
    if not getattr(seal, "created_entry", False):
        return
    seal.created_entry = False
    account = getattr(seal, "account", "")
    if not isinstance(account, str) or not account:
        return
    if _record_names_entry(folder, account):
        return
    _delete_keychain_entry({"service": getattr(seal, "SERVICE", KEYCHAIN_SERVICE), "account": account})


# ---------- setup (the one-time display) ----------

class PendingSetup:
    """A new seed between its one display at the device and commit. key_text() and check() work only until then."""

    def __init__(self, seed: bytes) -> None:
        self._seed = bytearray(seed)
        self._done = False
        _add_masks(self._seed)

    def _live(self) -> bytearray:
        if self._done:
            raise SeedStoreError("this setup is finished; its key is not shown again")
        return self._seed

    def key_text(self) -> str:
        """The setup key in groups of four (what a person types into an authenticator app)."""
        text = _b32(self._live())
        return " ".join(text[i:i + 4] for i in range(0, len(text), 4))

    def check(self, code: Any, now: float, window: int = authcode.WINDOW_STEPS) -> Optional[int]:
        """The time step (nearest to now) whose code from the new seed equals code, within window steps; None if the
        code matches none (or is not 6 digits). Used to confirm the person's app made the same codes, and at setup
        only with a wide window to name a wrong clock."""
        typed = authcode.normalize(code)
        if typed is None:
            return None
        found = authcode.matches(bytes(self._live()), typed, now, window)
        centre = authcode.step_at(now)
        return min(found, key=lambda s: abs(s - centre)) if found else None

    def discard(self) -> None:
        for i in range(len(self._seed)):
            self._seed[i] = 0
        self._done = True

    def __repr__(self) -> str:
        return "PendingSetup(<hidden>)"

    __str__ = __repr__

    def __reduce__(self):
        raise TypeError("an authenticator setup cannot be copied")


# ---------- the store ----------

_UNSEEN = object()
_ENTRY_RE = __import__("re").compile(r"[A-Za-z0-9 ()._:@'-]{1,64}")
_ACCOUNT_RE = __import__("re").compile(r"tether-[0-9a-f]{32}")


class SeedStore:
    """One profile's authenticator (its data folder). The running Hermes opens the sealed record (at start and after
    every change of the file) and hands the seed to the code check from memory; a CLI command at the device sets up,
    replaces or removes it. ``publish``: write what this process sees to STATUS_FILE (the gateway). ``secret``: how
    to get Tether's key passphrase (macOS seal); the device role and the CLI pass the identity's."""

    def __init__(self, folder: Path, backend: Any = None, *, clock: Callable[[], float] = time.time,
                 publish: bool = False, secret: Optional[Callable[[], bytes]] = None) -> None:
        self.dir = Path(folder)
        self._own_backend = backend is not None
        self.backend = backend if backend is not None else default_backend(self.dir, secret)
        self._secret = secret if secret is not None else getattr(self.backend, "secret", None)
        self._clock = clock
        self._publish_status = publish
        self._lock = threading.RLock()
        self._key: Optional[bytearray] = None
        self._recovery: dict = {"salt": "", "hashes": []}
        self._ref: Optional[dict] = None
        self._seen: Any = _UNSEEN         # the record's signature at the last read
        self._status = NONE
        self.unlock()

    def __repr__(self) -> str:
        return f"SeedStore({self.backend.name}, {self._status})"

    def __reduce__(self):
        raise TypeError("the authenticator store cannot be copied")

    # -- the record file --
    def _resolved_dir(self) -> str:
        return str(self.dir.resolve())

    def _read_ref(self) -> Optional[dict]:
        raw = _read_own(self.dir / REF_FILE)
        if raw is None:
            return None
        try:
            ref = json.loads(raw.decode())
        except (ValueError, UnicodeDecodeError):
            raise SeedStoreError("the authenticator record is damaged") from None
        if not isinstance(ref, dict) or ref.get("v") != _FORMAT:
            raise SeedStoreError("the authenticator record is damaged or belongs to another kind of store")
        if ref.get("dir") != self._resolved_dir():
            # Copied from another profile (a profile clone): never used or replaced from here.
            raise SeedStoreError("the authenticator record was copied from another Hermes profile")
        if not isinstance(ref.get("account"), str) or not _ACCOUNT_RE.fullmatch(ref["account"]) \
                or not isinstance(ref.get("sealed"), str):
            raise SeedStoreError("the authenticator record is damaged")
        if not _seal_name(ref):
            raise SeedStoreError("the authenticator record is damaged")
        return ref

    def _new_ref(self, entry: str) -> dict:
        return {"v": _FORMAT, "account": f"tether-{uuid.uuid4().hex}",
                "dir": self._resolved_dir(), "made": round(self._clock(), 3),
                "entry": entry if _ENTRY_RE.fullmatch(entry or "") else ""}

    def _seal_for(self, ref: dict) -> Any:
        """The seal a record names: the record decides how it is opened, never the current setting (D78)."""
        name = _seal_name(ref)
        if name == "passphrase":
            if getattr(self.backend, "seal_name", None) == "passphrase":
                return self.backend
            return PassphraseSeal(self._secret)
        if name == "hermes-keychain":
            return HermesKeychainSeal(_keychain_account(ref))
        if name == "dpapi":
            return WindowsDpapi()
        raise SeedStoreError("the authenticator record is damaged")

    def _configured_seal(self) -> Any:
        """The seal Hermes's setting asks for now (the store's own backend when it was given one)."""
        if self._own_backend:
            return self.backend
        try:
            return default_backend(self.dir, self._secret)
        except Exception:  # noqa: BLE001 - the choice must never break an open
            return None

    def _signature(self) -> Any:
        """What identifies the record's content (not its mtime): a new setup, new recovery codes or a used one."""
        try:
            ref = self._read_ref()
        except SeedStoreError:
            return "damaged"
        if ref is None:
            return None
        return ref.get("account"), ref.get("made"), hashlib.sha256(str(ref.get("sealed")).encode()).hexdigest()

    # -- status --
    def status(self) -> str:
        return self._status

    def status_text(self) -> str:
        return STATUS_TEXT[self._status]

    def refusal(self) -> Optional[str]:
        """None when codes can be checked; otherwise the fixed sentence the device answers the host with (no box)."""
        return None if self._status == READY else REFUSALS.get(self._status, SET_UP_AGAIN_TEXT)

    def _set(self, status: str, event: str = "") -> None:
        changed = status != self._status
        self._status = status
        if not self._publish_status:
            return
        with contextlib.suppress(Exception):
            _write_own(self.dir / STATUS_FILE, json.dumps({
                "status": status, "at": round(self._clock(), 3), "store": self.backend.name,
                "recovery_left": len(self._recovery.get("hashes") or []) if self._key is not None else None,
                "entry": self.entry_name()}).encode())
        if changed or event:
            from .store import log_event
            log_event(self.dir, "authenticator", reason=event or status)

    # -- what the code check uses (authcode.SeedStore) --
    def holds_key(self) -> bool:
        with self._lock:
            return self._key is not None

    def get_seed(self) -> bytes:
        """The seed from this process's memory. Raises SeedUnavailable when none is held."""
        with self._lock:
            if self._key is None:
                raise SeedUnavailable("no authenticator is held in this process")
            return bytes(self._key)

    def seal_key(self) -> bytes:
        with self._lock:
            if self._key is None:
                raise SeedUnavailable("no authenticator is held in this process")
            return hkdf(bytes(self._key), authcode._SEAL_INFO)

    def account(self) -> str:
        with self._lock:
            return str((self._ref or {}).get("account") or "") if self._key is not None else ""

    def entry_name(self) -> str:
        with self._lock:
            ref = self._ref
        if ref is None:
            try:
                ref = self._read_ref()
            except SeedStoreError:
                ref = None
        entry = str((ref or {}).get("entry") or "")
        return entry if _ENTRY_RE.fullmatch(entry) else ""

    # -- reading the record (the running Hermes at start and on every change; the CLI before a change) --
    def unlock(self) -> str:
        """Open the sealed record into memory (no prompt of any kind). Returns the new status."""
        with self._lock:
            self._seen = self._signature()
            if not self.backend.available():
                self._forget()
                self._set(UNAVAILABLE)
                return self._status
            try:
                ref = self._read_ref()
                if ref is None:
                    self._forget()
                    self._set(NONE)
                    return self._status
                key, recovery = self._parse(self._seal_for(ref).open(base64.b64decode(ref["sealed"]), ref["account"]))
            except (SeedStoreError, ValueError, base64.binascii.Error):
                self._forget()
                self._set(MISSING)
                logger.warning("tether: the authenticator record could not be opened; remote use is refused until it "
                               "is set up again")
                return self._status
            self._forget()
            self._key, self._recovery, self._ref = key, recovery, ref
            _add_masks(key)
            self._set(READY, "opened")
            self._follow_setting(ref)
            return self._status

    def _follow_setting(self, ref: dict) -> None:
        """Hermes's key storage setting changed: the record is re-sealed under the seal the setting names now (D78).
        The old record stays whole unless the new one is written, so the seed is never lost; a failure of any kind
        (not only the store's own errors) says so once and never breaks the open. Nothing of the failure itself is
        logged: an error's own text can hold a value."""
        target = self._configured_seal()
        if target is None:
            return
        name = _seal_name(ref)
        if getattr(target, "seal_name", None) == name:
            return
        old = ref.get("keychain") if name == "hermes-keychain" else None
        try:
            new_ref = self._write(ref, self._key, self._recovery, seal=target)
        except Exception:  # noqa: BLE001 - a re-seal that fails must never break an open
            _drop_created_entry(target, self.dir)      # a keychain entry this call wrote, with no record for it
            _warn_once("reseal", "tether: the authenticator record could not follow Hermes's key storage setting; it "
                                 "stays as it is")
            return
        self._ref = new_ref
        self._seen = self._signature()
        if old:
            _delete_keychain_entry(old)

    def refresh(self) -> None:
        """The device's settings watcher, every few seconds: a record written by another process (a setup, replace,
        new recovery codes, removal) is read again. Never raises."""
        try:
            if self._signature() != self._seen:
                self.unlock()
        except Exception:  # noqa: BLE001
            logger.warning("tether: checking the authenticator failed")

    def lock(self) -> None:
        with self._lock:
            self._forget()

    def _forget(self) -> None:
        if self._key is not None:
            for i in range(len(self._key)):
                self._key[i] = 0
        self._key, self._recovery, self._ref = None, {"salt": "", "hashes": []}, None

    @staticmethod
    def _parse(raw: bytes) -> tuple[bytearray, dict]:
        try:
            rec = json.loads(raw.decode())
            if not isinstance(rec, dict) or rec.get("v") != 1:
                raise ValueError
            key = _unb32(str(rec["seed"]))
            recovery = rec.get("recovery") or {"salt": "", "hashes": []}
            if not _valid_recovery(recovery):
                raise ValueError
        except (ValueError, KeyError, TypeError, UnicodeDecodeError, base64.binascii.Error):
            raise SeedStoreError("the authenticator record is damaged") from None
        if len(key) < authcode.MIN_SEED_BYTES:
            raise SeedStoreError("the authenticator record is damaged")
        return key, {"salt": recovery["salt"], "hashes": list(recovery["hashes"])}

    @staticmethod
    def _record(seed: bytes | bytearray, recovery: dict) -> bytes:
        return json.dumps({"v": 1, "seed": _b32(seed), "recovery": recovery}).encode()

    def _write(self, ref: dict, seed: bytes | bytearray, recovery: dict, seal: Any = None) -> dict:
        """The record file with the record sealed afresh (a new nonce each time); returns what was written. The seal
        is the record's own (a used recovery code must not change how the record is sealed), or the one asked for."""
        if seal is None:
            seal = self._seal_for(ref)
        blob = seal.seal(self._record(seed, recovery), ref["account"])
        out = {k: v for k, v in ref.items() if k not in ("sealed", "keychain", "backend")}
        out["seal"] = getattr(seal, "seal_name", "passphrase")
        if out["seal"] == "hermes-keychain":
            out["keychain"] = seal.keychain_ref()
        out["sealed"] = base64.b64encode(blob).decode()
        _write_own(self.dir / REF_FILE, json.dumps(out).encode())
        if getattr(seal, "created_entry", False):
            seal.created_entry = False     # the record names the entry now: it is no entry of our own to drop
        return out

    # -- setup, replace, remove, recovery codes (the CLI at the device) --
    def begin_setup(self) -> PendingSetup:
        if not self.backend.available():
            raise StoreUnavailable(STATUS_TEXT[UNAVAILABLE])
        return PendingSetup(secrets.token_bytes(SEED_BYTES))

    def commit(self, pending: PendingSetup, recovery: dict, used_step: int, entry: str = "") -> None:
        """Save pending's seed as this profile's authenticator: first the sealed code state for the new id with the
        confirming code's step already used, then the record file, renamed into place in one step (the old key stops
        working at that moment). Raises SeedStoreError when the record could not be sealed (nothing is then saved)."""
        if not _valid_recovery(recovery):
            raise SeedStoreError("the recovery codes were not made right; nothing was saved")
        seed = pending._live()
        with self._lock:
            ref = self._new_ref(entry)
            try:
                self.backend.seal(b"check", ref["account"])    # the seal works before anything is written
            except Exception:  # noqa: BLE001 - a keychain entry this call wrote goes with the failure
                _drop_created_entry(self.backend, self.dir)
                raise
            key = bytearray(seed)
            self._forget()
            self._key, self._ref = key, ref
            self._recovery = {"salt": recovery["salt"], "hashes": list(recovery["hashes"])}
            _add_masks(key)
            try:
                # One state lock over both writes; a failed record write puts the old code state back (R2-2).
                self._ref = authcode.CodeChecker(self, self.dir, clock=self._clock).start(
                    int(used_step), then=lambda: self._write(ref, key, self._recovery, seal=self.backend))
            except Exception:  # noqa: BLE001 - nothing is saved when the record cannot be written
                self.unlock()                                 # back to whatever the record file holds now
                _drop_created_entry(self.backend, self.dir)   # an entry this setup wrote, with nothing to open
                raise SeedStoreError("the new authenticator could not be saved") from None
            self._seen = self._signature()
            self._set(READY, "set up")
        pending.discard()

    def set_recovery(self, recovery: dict) -> None:
        """Replace the recovery codes' fingerprints (new codes; the old ones stop working)."""
        if not _valid_recovery(recovery):
            raise SeedStoreError("the recovery codes were not made right; nothing was saved")
        with self._lock:
            if self._key is None or self._ref is None:
                raise SeedStoreError("no authenticator is held in this process")
            fresh = {"salt": recovery["salt"], "hashes": list(recovery["hashes"])}
            self._ref = self._write(self._ref, self._key, fresh)
            self._recovery = fresh
            self._seen = self._signature()

    def use_recovery_code(self, code: str) -> bool:
        """True (and that code is gone from the sealed record) when code (already cleaned) is one of the recovery
        codes. A code that could not be struck from the record is not accepted, so none ever works twice."""
        with self._lock:
            if self._key is None or self._ref is None or not code:
                return False
            try:
                salt = bytes.fromhex(self._recovery.get("salt") or "")
            except ValueError:
                return False
            mine = _recovery_hash(salt, code)
            hashes = list(self._recovery.get("hashes") or [])
            hits = [h for h in hashes if hmac.compare_digest(h, mine)]
            if not hits:
                return False
            left = {"salt": self._recovery["salt"], "hashes": [h for h in hashes if h != hits[0]]}
            try:
                self._ref = self._write(self._ref, self._key, left)
            except (SeedStoreError, OSError):
                logger.warning("tether: a recovery code could not be marked as used; it was not accepted")
                return False
            self._recovery = left
            self._seen = self._signature()
            return True

    def recovery_fingerprints(self) -> dict:
        """The salted fingerprints of the recovery codes still unused, for the transfer file (D85). A copy: the
        record's own dict is never handed out."""
        with self._lock:
            if self._key is None or self._ref is None:
                raise SeedStoreError("no authenticator is held in this process")
            return {"salt": self._recovery.get("salt", ""), "hashes": list(self._recovery.get("hashes") or [])}

    def recovery_left(self) -> int:
        with self._lock:
            return len(self._recovery.get("hashes") or [])

    def remove(self) -> bool:
        """Remove this profile's authenticator: Tether's own files, each by its exact name (D39). True when none of
        them is left. A keychain entry of Tether's own goes with the record it belonged to."""
        with self._lock:
            entry = None
            try:
                ref = self._read_ref()
            except SeedStoreError:
                ref = None
            if ref and _seal_name(ref) == "hermes-keychain":
                entry = ref.get("keychain")
            for name in (authcode.STATE_FILE, authcode.LOCK_FILE, REF_FILE):
                _remove_own(self.dir / name)
            self._forget()
            self._seen = None
            self._set(NONE, "removed")
            if entry and not os.path.lexists(self.dir / REF_FILE):
                _delete_keychain_entry(entry)
            return not any(os.path.lexists(self.dir / n) for n in (REF_FILE, authcode.STATE_FILE))


def read_published(folder: Path) -> Optional[dict]:
    """What the running Hermes last saw (STATUS_FILE), for `hermes tether status` and the panel; None if unknown."""
    try:
        raw = _read_own(Path(folder) / STATUS_FILE)
        data = json.loads(raw.decode()) if raw else None
    except (SeedStoreError, ValueError, UnicodeDecodeError, AttributeError):
        return None
    if not isinstance(data, dict) or data.get("status") not in STATUS_TEXT:
        return None
    return data


def pointer_state(folder: Path) -> str:
    """NONE, MISSING (a damaged or copied record file) or PRESENT (one is there) from the file's outside alone: it is
    never opened, so this needs no secret."""
    raw = None
    try:
        raw = _read_own(Path(folder) / REF_FILE)
        ref = json.loads(raw.decode()) if raw else None
    except (SeedStoreError, ValueError, UnicodeDecodeError):
        return MISSING
    if raw is None:
        return NONE
    ok = isinstance(ref, dict) and ref.get("v") == _FORMAT and isinstance(ref.get("account"), str) \
        and isinstance(ref.get("sealed"), str) and ref.get("dir") == str(Path(folder).resolve())
    return PRESENT if ok else MISSING
