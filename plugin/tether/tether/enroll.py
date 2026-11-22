"""Setting up, replacing, unlocking and removing a device's authenticator, and its recovery codes (design D67).

The person does all of it AT the device: `hermes tether authenticator setup|remove|recovery-codes|unlock` in a terminal
there, then boxes on that screen (macOS: AppleScript dialogs; Windows: a Windows Forms window). Every answer goes
into a box, never onto the command line, stdin, the link or a file; the setup key and the recovery codes are shown
only in a box, never printed, logged or sent anywhere.

- Turning it on when none is set up (or the one there cannot be opened) needs no further proof, and no system
  dialog (no administrator or UAC check, the owner's ruling of 2026-11-21): remote use is refused until the first
  setup, so no remote session can exist to run it; on macOS the session lock also keeps every session command from
  writing Tether's data folder, so a session cannot delete the authenticator to start over either.
- Replacing it, removing it or making new recovery codes needs the current code from the app or a recovery code,
  typed into a box here. Unlocking code entry after too many wrong codes takes a recovery code, never an app code.
  Wrong app codes here count toward the same pause and lock as the approval box (authcode.CodeChecker). A person who
  lost both phone and recovery codes ("Lost both") is told how to start over by hand: delete the authenticator's
  record file in Tether's data folder at this machine, then set up again. Tether itself never does that without a
  code.
- A new key is 160 random bits made here (RFC 4226 R6), shown once as a setup key: as a code to scan, made by
  this machine itself (Core Image on a Mac, the qrcode package on a PC), with the key as text under it for an app
  that cannot scan, and never as a picture on the terminal, in a log or in a file. Nothing is saved until the
  person typed a code their app made from it and was shown the recovery codes; that first code's step is then used up.
- Ten recovery codes of 80 bits, shown once. Only salted fingerprints are kept, inside the protected record with the
  key (seedstore.py). A recovery code opens these settings; it never allows remote use.
- While a run lasts the device counts as paused (D48): every grant ends, the link drops, nothing remote reaches
  this screen. None of these starts from a remote session's or an agent's shell (a mark, not a wall).
"""
from __future__ import annotations

import asyncio
import base64
import contextlib
import errno
import hashlib
import io
import json
import logging
import math
import os
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional, Protocol
from urllib.parse import quote

from . import authcode
from .seedstore import (MISSING, NONE, REF_FILE, PendingSetup, SeedStore, SeedStoreError, hash_recovery_codes)
from .store import _read, _write, log_event

logger = logging.getLogger(__name__)

BUSY_FILE = "authenticator.busy"          # a setup is running: the device counts as paused while it is fresh
REMOTE_MARK = "TETHER_REMOTE_SESSION"     # set in every terminal a remote session gets on this device

ON, OFF, DAMAGED = "on", "off", "damaged"

RECOVERY_COUNT = 10
RECOVERY_CHARS = 16             # 80 bits each, shown as XXXX-XXXX-XXXX-XXXX
CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"     # no I, L, O, U: read back without mix-ups
TRIES_PER_BOX = 3               # wrong entries in one box before that run ends
TRANSFER_TRIES = 5              # wrong transfer phrases in one join before that run ends
TRANSFER_FILE = "tether-authenticator.transfer"
TRANSFER_KIND = "tether-authenticator-transfer"
TRANSFER_V = 1
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 15, 8, 1     # the file names these; nothing else is accepted
SCRYPT_MAXMEM = 256 * 1024 * 1024                  # well above 128 * n * r for the parameters above
ENTRY_NAME = "Hermes Tether"   # one entry for every machine (D85), never "Hermes Tether (<machine>)"
_ENTRY_RE = re.compile(r"[A-Za-z0-9 ()._:@'-]{1,64}")
SKEW_SEARCH_STEPS = 20          # setup only: a first code that matches within +/- 10 minutes names the clock
BOX_INFO_S = 300                # how long each box waits before it gives up (= cancel)
BOX_KEY_S = 600
BOX_CODE_S = 120
BUSY_BEAT_S = 5.0               # a running setup re-dates its marker this often ...
BUSY_STALE_S = 20.0             # ... and a marker this old (or this far in the future) counts for nothing
BUSY_SETTLE_S = 2.5             # the device's pause check runs every second (D48): let it end grants first


class EnrollError(Exception):
    """A refusal with a sentence for the person; nothing changed."""


# ---------- the state, as these settings see it ----------

def state(store: SeedStore) -> str:
    """ON when this process holds the key (opened from its sealed file, no prompt); OFF when none is set up; DAMAGED
    for anything else (a damaged file, one sealed with another key, a link in its place)."""
    st = store.status()
    if st == NONE:
        return OFF
    if st == MISSING:
        return DAMAGED
    if not store.holds_key():
        try:
            store.unlock()
        except Exception:  # noqa: BLE001 - never the store's error text
            logger.warning("tether: the authenticator record could not be opened")
    return ON if store.holds_key() else DAMAGED


def new_recovery_codes() -> list[str]:
    return ["".join(secrets.choice(CROCKFORD) for _ in range(RECOVERY_CHARS)) for _ in range(RECOVERY_COUNT)]


def show_code(code: str) -> str:
    return "-".join(code[i:i + 4] for i in range(0, len(code), 4))


def clean_recovery(text: Any) -> str:
    """A recovery code as typed: case, spaces and dashes free; O read as 0 and I or L as 1. '' if not one."""
    raw = str(text or "").upper().replace(" ", "").replace("-", "")
    raw = raw.translate(str.maketrans({"O": "0", "I": "1", "L": "1"}))
    return raw if len(raw) == RECOVERY_CHARS and all(c in CROCKFORD for c in raw) else ""


# ---------- one authenticator for all machines: the transfer file (D85) ----------
# The file holds the seed, the recovery codes' fingerprints and the entry name, sealed with AES-256-GCM under a key
# made from a one-time phrase (scrypt). The phrase is shown in one box at the exporting machine and typed into one
# box at the joining machine; it never reaches the terminal, a log, an argument or the file.

def new_transfer_phrase() -> str:
    """One transfer phrase: the same 80-bit Crockford format and generator as one recovery code."""
    return "".join(secrets.choice(CROCKFORD) for _ in range(RECOVERY_CHARS))


def clean_transfer(text: Any) -> str:
    """A transfer phrase as typed: the recovery-code rules (case, spaces and dashes free; O as 0, I/L as 1)."""
    return clean_recovery(text)


def _transfer_header(phrase: str, salt: bytes, nonce: bytes) -> dict:
    return {"v": TRANSFER_V, "kind": TRANSFER_KIND, "kdf": "scrypt", "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P,
            "salt": base64.b64encode(salt).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode("ascii")}


def _transfer_ad(header: dict) -> bytes:
    """The JSON header fields (everything but ``sealed``), in one canonical text, as associated data."""
    return json.dumps(header, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _transfer_key(phrase: str, salt: bytes) -> bytes:
    return hashlib.scrypt(phrase.encode("ascii"), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=32,
                          maxmem=SCRYPT_MAXMEM)


def _transfer_plaintext(seed: bytes, recovery: dict, entry: str) -> bytes:
    return json.dumps({"seed": base64.b64encode(bytes(seed)).decode("ascii"),
                       "recovery": {"salt": recovery["salt"], "hashes": list(recovery["hashes"])},
                       "entry": entry}, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def make_transfer_record(phrase: str, seed: bytes, recovery: dict, entry: str) -> dict:
    """The JSON object the transfer file holds. ``phrase`` must already be cleaned."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    header = _transfer_header(phrase, salt, nonce)
    sealed = AESGCM(_transfer_key(phrase, salt)).encrypt(nonce, _transfer_plaintext(seed, recovery, entry),
                                                         _transfer_ad(header))
    return {**header, "sealed": base64.b64encode(sealed).decode("ascii")}


class TransferError(Exception):
    """A transfer file that is missing, not a plain file or not right; its text is fixed and carries no value."""


def _b64(text: Any) -> bytes:
    if not isinstance(text, str):
        raise TransferError("damaged")
    try:
        return base64.b64decode(text, validate=True)
    except (ValueError, base64.binascii.Error):
        raise TransferError("damaged") from None


def read_transfer_file(path: Path) -> tuple[dict, bytes, bytes, bytes]:
    """(header, sealed, salt, nonce) from a plain file, never through a link; raises TransferError for anything
    else. It only checks the shape: whether the bytes are the ones sealed can be known with the phrase alone."""
    try:
        raw = _read_transfer_bytes(Path(path))
    except OSError:
        raise TransferError("not a plain file") from None
    if raw is None:
        raise TransferError("missing")
    try:
        data = json.loads(raw.decode())
    except (ValueError, UnicodeDecodeError):
        raise TransferError("damaged") from None
    if not isinstance(data, dict) or data.get("v") != TRANSFER_V or data.get("kind") != TRANSFER_KIND \
            or data.get("kdf") != "scrypt":
        raise TransferError("damaged")
    for key in ("n", "r", "p"):
        value = data.get(key)
        if isinstance(value, bool) or not isinstance(value, int):
            raise TransferError("damaged")
    if (data["n"], data["r"], data["p"]) != (SCRYPT_N, SCRYPT_R, SCRYPT_P):
        raise TransferError("damaged")
    header = {k: v for k, v in data.items() if k != "sealed"}      # every header field is authenticated
    sealed = _b64(data.get("sealed"))
    salt, nonce = _b64(header.get("salt")), _b64(header.get("nonce"))
    if len(salt) != 16 or len(nonce) != 12 or len(sealed) < 16:
        raise TransferError("damaged")
    return header, sealed, salt, nonce


def open_transfer_record(header: dict, sealed: bytes, salt: bytes, nonce: bytes, phrase: str) -> dict:
    """The sealed payload, or TransferError when the phrase is wrong or any header or sealed byte changed."""
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    try:
        payload = AESGCM(_transfer_key(phrase, salt)).decrypt(nonce, sealed, _transfer_ad(header))
        data = json.loads(payload.decode())
        if not isinstance(data, dict):
            raise ValueError
        seed = _b64(data.get("seed"))
        recovery = data.get("recovery")
        if len(seed) < authcode.MIN_SEED_BYTES or not isinstance(recovery, dict):
            raise ValueError
        salt_hex, hashes = recovery.get("salt"), recovery.get("hashes")
        if not isinstance(salt_hex, str) or not isinstance(hashes, list) or len(bytes.fromhex(salt_hex)) < 1:
            raise ValueError
        if not all(isinstance(h, str) and len(h) == 64 for h in hashes):
            raise ValueError
        entry = data.get("entry")
        if not isinstance(entry, str) or not _ENTRY_RE.fullmatch(entry):
            entry = ENTRY_NAME
    except (InvalidTag, ValueError, TypeError, KeyError, UnicodeDecodeError, base64.binascii.Error):
        raise TransferError("the phrase did not open it") from None
    return {"seed": seed, "recovery": {"salt": salt_hex, "hashes": list(hashes)}, "entry": entry}


def _read_transfer_bytes(path: Path) -> Optional[bytes]:
    """A plain file's bytes, or None when missing; a link, a reparse point or anything not a plain file raises."""
    if os.name == "nt":
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            return None
        if stat.S_ISLNK(st.st_mode) or getattr(st, "st_file_attributes", 0) & 0x400 or not stat.S_ISREG(st.st_mode):
            raise OSError(errno.ELOOP, "not a plain file")
        return path.read_bytes()
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
    except FileNotFoundError:
        return None
    except OSError:
        raise
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(errno.EINVAL, "not a plain file")
        chunks = []
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def _write_transfer_new(path: Path, data: bytes) -> bool:
    """Write a new private (0600) file, atomically, refusing to replace anything; False when the name is taken.
    The final name is made with a hard link from a fresh temporary file, so a link or file put there is never
    followed and this never overwrites what it finds."""
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with contextlib.suppress(OSError, AttributeError):
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        try:
            os.link(tmp, path)
            return True
        except FileExistsError:
            return False
        except OSError:
            # A folder or filesystem without hard links: create the name exclusively, never following a link.
            try:
                out = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
                              | getattr(os, "O_BINARY", 0), 0o600)
            except FileExistsError:
                return False
            try:
                with contextlib.suppress(OSError, AttributeError):
                    os.fchmod(out, 0o600)
                with os.fdopen(out, "wb") as fh:
                    fh.write(data)
                    fh.flush()
                    os.fsync(fh.fileno())
            except BaseException:
                with contextlib.suppress(OSError):
                    os.unlink(path)
                raise
            return True
    finally:
        with contextlib.suppress(OSError):
            os.unlink(tmp)


def write_transfer_file(path: Path, record: dict) -> bool:
    """The transfer JSON into a new file at path; False when path already exists (never overwritten)."""
    return _write_transfer_new(Path(path), json.dumps(record, indent=1, sort_keys=True).encode() + b"\n")


def delete_transfer_file(path: Path) -> bool:
    """Delete a plain transfer file by its name (never following a link); False for a link, a folder or a file this
    account may not remove."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    if stat.S_ISLNK(st.st_mode) or getattr(st, "st_file_attributes", 0) & 0x400 or not stat.S_ISREG(st.st_mode):
        return False
    try:
        os.unlink(path)
    except OSError:
        return False
    return True


def export_folder(folder: str = "") -> Path:
    """The folder the export writes in: the argument, else the person's Downloads folder when it exists, else the
    current directory."""
    if folder:
        path = Path(folder).expanduser()
    else:
        downloads = Path.home() / "Downloads"
        path = downloads if downloads.is_dir() else Path.cwd()
    if not path.is_dir():
        raise EnrollError(f"{path} is not a folder; nothing was written")
    return path


# ---------- the busy marker (the device counts as paused while a setup runs) ----------

def busy(d: Path, clock: Callable[[], float] = time.time) -> bool:
    data = _read(d / BUSY_FILE, None)
    at = data.get("at") if isinstance(data, dict) else None
    if isinstance(at, bool) or not isinstance(at, (int, float)) or not math.isfinite(at):
        return False
    return abs(clock() - at) < BUSY_STALE_S


class Busy:
    """Held for the whole of a setup, replace, remove or new-codes run. Re-dated every few seconds from a thread, so
    a run that dies stops pausing the device within BUSY_STALE_S. Only this run's own marker is removed."""

    def __init__(self, d: Path, clock: Callable[[], float] = time.time) -> None:
        self.path, self._clock = d / BUSY_FILE, clock
        self._mark = secrets.token_hex(8)
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def _write(self) -> None:
        _write(self.path, {"pid": os.getpid(), "mark": self._mark, "at": round(self._clock(), 3)})

    def _mine(self) -> bool:
        data = _read(self.path, None)
        return isinstance(data, dict) and data.get("mark") == self._mark

    def __enter__(self) -> "Busy":
        if busy(self.path.parent, self._clock):
            raise EnrollError("another authenticator setup is running on this machine")
        # R2-1: an empty folder in the way is removed; the marker is then a new private file renamed into place, so a
        # stale marker or a link put there at any moment is replaced itself, never followed, and there is no gap
        # between a removal and a create for anything to slip into. What still cannot be replaced (a folder with
        # something in it) is a plain refusal, never a raw OSError.
        if self.path.is_dir() and not self.path.is_symlink():
            try:
                self.path.rmdir()
            except OSError:
                pass
        try:
            self._write()
        except OSError:
            raise EnrollError(f"{self.path} is in the way (a folder or something this setup cannot replace); remove "
                              "it at this computer and run the setup again") from None
        self._thread = threading.Thread(target=self._beat, name="tether-setup-busy", daemon=True)
        self._thread.start()
        return self

    def _beat(self) -> None:
        while not self._stop.wait(BUSY_BEAT_S):
            try:
                if self._mine():
                    self._write()
            except OSError:
                pass

    def __exit__(self, *exc) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2)
        try:
            if self._mine():
                self.path.unlink()
        except OSError:
            pass


# ---------- the key as a code to scan ----------

ISSUER = "Hermes Tether"          # the name the app shows beside the entry


def otpauth_uri(key_text: str, name: str = "", issuer: str = ISSUER) -> str:
    """The key URI an authenticator app scans (the otpauth form they all read): the issuer as the label, so every
    machine's entry is the same "Hermes Tether" (D85), the key in base32 without padding, time-based, 6 digits, 30
    seconds. Every part is percent-encoded. ``name`` is accepted for older callers and is not part of the label."""
    del name                                  # one entry for all machines: the label is the issuer itself
    secret = "".join(key_text.split()).replace("-", "").upper().rstrip("=")
    return (f"otpauth://totp/{quote(issuer, safe='')}"
            f"?secret={quote(secret, safe='')}"
            f"&issuer={quote(issuer, safe='')}"
            "&algorithm=SHA1&digits=6&period=30")


# ---------- the boxes ----------

@dataclass
class Answer:
    button: Optional[str]       # the button pressed; None: cancelled, closed, gave up or failed
    text: str = ""              # what was typed (a field box only); never logged


@dataclass
class QrCode:
    """The new key as a code to scan. ``uri`` is what the app reads, ``key_text`` the key as text and ``fallback``
    the line under the code for an app that cannot scan; ``text`` is the wording of the box and ``plain_text``
    today's key box wording, used when the code cannot be drawn at all."""
    uri: str
    key_text: str
    fallback: str
    text: str
    plain_text: str


class SetupUI(Protocol):
    machine: str                # "Mac" or "PC"

    async def ask(self, text: str, buttons: tuple[str, ...], *, field: bool = False,
                  timeout_s: float = BOX_INFO_S) -> Answer: ...

    async def ask_qr(self, qr: QrCode, buttons: tuple[str, ...], *,
                     timeout_s: float = BOX_KEY_S) -> Answer: ...


@dataclass
class Result:
    ok: bool
    message: str


TITLE = {"Mac": "Hermes Tether — authenticator", "PC": "Hermes Tether - authenticator"}
CLOCK_WHERE = {"Mac": "System Settings > General > Date & Time > Set time and date automatically",
               "PC": "Settings > Time & language > Date & time > Set time automatically"}
CANCELLED = "Cancelled; nothing changed."
LOST = "Lost both"


def _tries(n: int) -> str:
    return f"{n} try left" if n == 1 else f"{n} tries left"


class Texts:
    """Every word the boxes show (spec section 6)."""

    def __init__(self, machine: str, name: str, folder: str = "") -> None:
        self.m, self.name, self.entry = machine, name, ENTRY_NAME
        self.folder = folder or "Tether's data folder"

    def _watch(self, what: str) -> str:
        return (f"Continue only if you started this yourself, at this {self.m}, just now. Make sure this screen is not "
                f"being shared, recorded or watched by another program: a later box shows {what}.")

    def intro_setup(self, damaged: bool) -> str:
        head = (f"The current authenticator on this {self.m} cannot be opened (its file is damaged, or was sealed "
                "with another key), so remote use is off. Setting up a new one replaces it.\n\n" if damaged else "")
        return (f"{head}Set up the authenticator for remote use of this {self.m} ({self.name}).\n\n"
                f"From now on, before a Hermes agent may use this {self.m} from another computer, a box like this one "
                "will ask for a 6-digit code from an authenticator app on your phone (for example 1Password, Proton "
                f"Pass or Google Authenticator).\n\n{self._watch('a secret key')}\n\n"
                f"Remote use of this {self.m} is paused until this ends.")

    def intro_replace(self) -> str:
        return (f"Replace the authenticator for remote use of this {self.m} ({self.name}).\n\n"
                f"You will add a new key to your authenticator app; the old entry \"{self.entry}\" stops working, "
                f"and so do your old recovery codes.\n\n{self._watch('a secret key')}\n\n"
                f"Remote use of this {self.m} is paused until this ends.")

    def intro_remove(self) -> str:
        return (f"Remove the authenticator from this {self.m} ({self.name})?\n\n"
                f"Remote use of this {self.m} is then off until you set up an authenticator again. Your recovery "
                f"codes stop working.\n\nContinue only if you started this yourself, at this {self.m}, just now.")

    def intro_codes(self) -> str:
        return (f"Make new recovery codes for this {self.m} ({self.name})?\n\nYour old recovery codes stop working."
                f"\n\n{self._watch('the new codes')}")

    def prove(self, action: str, wrong_left: Optional[int], used: bool = False) -> str:
        head = ""
        if wrong_left is not None:
            head = ("That code was already used: wait for the next code in your app. " if used else
                    "That code did not match (each code works only once). Check the entry name and that this "
                    f"{self.m}'s clock is right. ") + f"{_tries(wrong_left)}.\n\n"
        return (f"{head}To {action}, enter the current 6-digit code from your authenticator app (entry "
                f"\"{self.entry}\"), or one of your recovery codes.\n\n"
                f"Lost your phone and your recovery codes? Choose \"{LOST}\" to see how to start over.")

    def prove_held(self, action: str, held: tuple[str, float], wrong_left: Optional[int]) -> str:
        head = f"That is not one of your unused recovery codes. {_tries(wrong_left)}.\n\n" if wrong_left is not None \
            else ""
        if held[0] == authcode.PAUSED:
            until = _hhmm(time.time() + held[1])
            why = f"Codes from your app are not taken here until {until} (too many wrong codes)."
        elif held[0] == authcode.LOCKED:
            why = "Codes from your app are not taken: code entry is locked after too many wrong codes."
        else:
            why = "Codes from your app cannot be checked right now."
        return (f"{head}{why}\n\nTo {action} now, enter one of your recovery codes, or choose \"{LOST}\" to see how "
                "to start over.")

    def lost_both(self) -> str:
        return ("Without a code from your app or one of your recovery codes, Tether does not change the authenticator: "
                "that is what keeps anyone else from replacing it.\n\n"
                f"To start over, remove it yourself, here at this {self.m} and never from a remote session: delete the "
                f"file {REF_FILE} in {self.folder}, then run `{authcode.SETUP_COMMAND}` again and add the new key to "
                f"your app. Remote use of this {self.m} stays off until then.\n\nNothing was changed.")

    def key(self, key_text: str, replacing: bool) -> str:
        old = (f"Your app already has an entry \"{self.entry}\" for the old key: rename it (for example to "
               f"\"{self.entry} old\") so you can tell them apart, and delete it once this setup is done.\n\n"
               if replacing else "")
        return (f"{old}Add this key to your authenticator app on your phone:\n\n"
                "1. In the app, add a new entry and choose to enter a setup key (not to scan a QR code).\n"
                f"2. Name: {self.entry}\n"
                f"3. Key: {key_text}\n"
                "4. Type: time-based, 6 digits, every 30 seconds (the app's usual default).\n\n"
                f"Type the key on your phone; spaces do not matter. Do not copy it on this {self.m}. It is shown only "
                f"now and never leaves this {self.m}. Keep it on your phone only, not in a password manager that this "
                f"{self.m} or your Hermes host can open.")

    KEY_HEAD = "Add this key to your authenticator app on your phone"

    def key_qr(self, replacing: bool) -> str:
        """The wording of the box that shows the key as a code to scan (the key as text is under the code)."""
        old = (f"Your app already has an entry \"{self.entry}\" for the old key: rename it (for example to "
               f"\"{self.entry} old\") so you can tell them apart, and delete it once this setup is done.\n\n"
               if replacing else "")
        return (f"{old}1. In the app, add a new entry and choose to scan a QR code.\n"
                f"2. Scan the code below with the app; it adds the entry \"{self.entry}\".\n"
                "3. Type: time-based, 6 digits, every 30 seconds (the app's usual default).\n\n"
                f"Scan the code with your phone; do not copy it on this {self.m}. It is shown only now and never "
                f"leaves this {self.m}. Keep it on your phone only, not in a password manager that this {self.m} or "
                "your Hermes host can open.\n\n"
                "If your app cannot scan a code, type the key shown under it.")

    def key_fallback(self, key_text: str) -> str:
        """The line under the code: the key as text, for an app that cannot scan it."""
        return f"Can't scan? Type this key: {key_text}"

    def confirm(self, wrong_left: Optional[int]) -> str:
        head = ""
        if wrong_left is not None:
            head = (f"That code did not match. Check that the key was typed exactly as shown (\"Show key again\"). "
                    f"{_tries(wrong_left)}.\n\n")
        return f"{head}Enter the 6-digit code your app now shows for \"{self.entry}\"."

    def confirm_failed(self) -> str:
        return (f"The codes did not match, so nothing was saved. Delete the entry \"{self.entry}\" in your app and run "
                "setup again.")

    def clock(self, steps: int) -> str:
        minutes = max(1, round(abs(steps) * authcode.STEP_S / 60))
        side = "behind" if steps > 0 else "ahead"
        unit = "minute" if minutes == 1 else "minutes"
        return (f"This {self.m}'s clock seems to be about {minutes} {unit} {side} (compared with your phone). Codes "
                "depend on the clock, so nothing was saved.\n\n"
                f"Set this {self.m}'s time automatically ({CLOCK_WHERE[self.m]}), then run setup again, and delete the "
                f"entry \"{self.entry}\" you just added.")

    def recovery(self, codes: list[str], renewing: bool) -> str:
        shown = [show_code(c) for c in codes]
        rows = "\n".join(f"{shown[i]}      {shown[i + 1]}" if i + 1 < len(shown) else shown[i]
                         for i in range(0, len(shown), 2))
        head = "These replace your earlier recovery codes, which no longer work.\n\n" if renewing else ""
        return (f"{head}Recovery codes for \"{self.entry}\":\n\n{rows}\n\n"
                f"If you lose your phone, each code works once, here at this {self.m}, in place of a code from the app, "
                "to replace or remove the authenticator. A recovery code cannot allow remote use.\n\n"
                f"Save them now, away from this {self.m}: write them down or keep them in your password manager. They "
                "are shown only now; Tether keeps only a fingerprint of each.")

    def done_setup(self, replaced: bool) -> str:
        if replaced:
            return (f"The new authenticator is set up for this {self.m} ({self.name}). The old key and the old "
                    f"recovery codes no longer work.\n\nEach new remote session asks for a code from your app in a box "
                    f"on this screen. Enter a code only when you yourself just asked Hermes to use this {self.m}.")
        return (f"The authenticator is set up for this {self.m} ({self.name}).\n\nEach new remote session now asks for "
                "a code from your app in a box on this screen. Enter a code only when you yourself just asked Hermes "
                f"to use this {self.m}.")

    def replace_warning(self) -> str:
        """The owner's add-on: a replacement (setup or join) says the other machines still hold the old one."""
        return ("This creates a new authenticator. Your other machines still use the old one: run "
                "`hermes tether authenticator export` here and `join` on each of them again.")

    def join_replace_warning(self) -> str:
        """Joining a machine that already has its own authenticator: that one is replaced by the shared one."""
        return ("This replaces this machine's own authenticator with the one in the transfer file. Codes from this "
                "machine's old entry in your authenticator app stop working here; use the shared entry.")

    def transfer_phrase(self, phrase: str) -> str:
        """The one-time transfer phrase, shown in this box only (never in the terminal or a log)."""
        return ("One-time transfer phrase for your other machine:\n\n"
                f"{phrase}\n\n"
                "Write this down: the other machine asks for it; it is not shown again.\n\n"
                f"Keep it with the {TRANSFER_FILE} file and delete both after the other machine has joined.")

    def join_phrase(self, wrong_left: Optional[int]) -> str:
        head = f"That phrase did not match. {_tries(wrong_left)}.\n\n" if wrong_left is not None else ""
        return (f"{head}Enter the one-time transfer phrase from the other machine (letters and digits; case, spaces "
                "and dashes do not matter).")

    def join_confirm(self, wrong_left: Optional[int]) -> str:
        head = f"That code did not match. {_tries(wrong_left)}.\n\n" if wrong_left is not None else ""
        return f"{head}Enter the 6-digit code your authenticator app shows for {self.entry}."

    def join_failed(self) -> str:
        return ("The codes did not match, so nothing was saved; this machine's authenticator is unchanged. Run join "
                "again when your app shows a new code.")

    def done_join(self, replaced: bool) -> str:
        what = ("The authenticator on this machine now matches the other machine's."
                if replaced else "The authenticator is set up on this machine, the same as on the other machine.")
        return (f"{what}\n\nEach new remote session asks for a code from your app in a box on this screen. Enter a "
                "code only when you yourself just asked Hermes to use this machine.")

    def delete_transfer(self, path: str) -> str:
        return (f"Delete the transfer file now?\n\n{path}\n\nIt holds your authenticator sealed with the one-time "
                "transfer phrase. Delete it after joining so it cannot be used again; the phrase is not shown again "
                "either.")

    def transfer_deleted(self, path: str) -> str:
        return f"The transfer file is deleted: {path}"

    def transfer_not_deleted(self, path: str) -> str:
        return (f"The transfer file could not be deleted: {path}\n\nIt is not a plain file (a link or a folder), or "
                "this account may not remove it. Delete it yourself, at this machine, and never through a link.")

    def done_remove(self) -> str:
        return (f"The authenticator is removed from this {self.m}. Remote use of it is off until you set one up again "
                f"(hermes tether authenticator setup). You can delete the entry \"{self.entry}\" from your app.")

    def done_codes(self) -> str:
        return "Your new recovery codes are saved. The old ones no longer work."

    def intro_unlock(self) -> str:
        return (f"Unlock code entry on this {self.m} ({self.name})?\n\n"
                f"After too many wrong codes, or after its record of used codes was changed or deleted, this {self.m} "
                "stopped taking codes from your authenticator app. Unlock it only if those wrong codes were yours and "
                "you know why the record changed. If not, someone tried to guess your code or tampered with Tether's "
                f"files: check what runs on this {self.m} and on your Hermes host first.\n\n"
                f"Continue only if you started this yourself, at this {self.m}, just now.")

    def prove_unlock(self, wrong_left: Optional[int]) -> str:
        head = ""
        if wrong_left is not None:
            head = f"That is not one of your unused recovery codes. {_tries(wrong_left)}.\n\n"
        return (f"{head}To unlock code entry, enter one of your recovery codes (a code from the app is not taken "
                f"here).\n\nNo recovery codes left? Choose \"{LOST}\" to see how to start over.")

    def done_unlock(self) -> str:
        return "Code entry is unlocked. The next remote session asks for a code from your app again."


# ---------- the flows ----------

def _hhmm(t: float) -> str:
    return time.strftime("%H:%M", time.localtime(t))


NOT_READ = ("The authenticator on this machine could not be opened (its file is damaged, or was sealed with another "
            f"key), so nothing changed; run `{authcode.SETUP_COMMAND}` here to replace it.")
NOT_ON = f"No working authenticator is set up on this machine; run `{authcode.SETUP_COMMAND}` here first."


class Enrollment:
    """One run of setup, remove, recovery-codes or unlock on this device. ``ui`` shows the boxes, ``store`` keeps the
    key, ``codes`` checks app codes against the same sealed state and limits as the approval box."""

    LOST = LOST

    def __init__(self, d: Path, name: str, store: SeedStore, ui: "SetupUI", *, codes=None,
                 clock: Callable[[], float] = time.time, settle_s: float = BUSY_SETTLE_S) -> None:
        self.d, self.name, self.store, self.ui, self._clock, self._settle = d, name, store, ui, clock, settle_s
        self.t = Texts(ui.machine, name, str(d))
        self.codes = codes if codes is not None else authcode.CodeChecker(store, d, clock=clock, wall=clock)
        self.st = OFF

    def _log(self, kind: str, reason: str = "") -> None:
        log_event(self.d, kind, reason=reason)

    async def _settle_pause(self) -> None:
        if self._settle > 0:
            await asyncio.sleep(self._settle)

    async def _info(self, text: str, go: str = "Continue", timeout_s: float = BOX_INFO_S) -> bool:
        return (await self.ui.ask(text, ("Cancel", go), timeout_s=timeout_s)).button == go

    async def _note(self, text: str) -> None:
        await self.ui.ask(text, ("OK",), timeout_s=60)

    # --- proofs ---
    async def _lost_both(self) -> bool:
        """No code and no recovery code: say how to start over by hand, change nothing (D67)."""
        self._log("settings_lost_both")
        await self._note(self.t.lost_both())
        return False

    def _recovery_code(self, typed: str) -> bool:
        code = clean_recovery(typed)
        if not code or not self.store.use_recovery_code(code):
            return False
        self._log("recovery_code_used", f"{self.store.recovery_left()} left")
        return True

    async def _prove(self, action: str, purpose: str, *, app_code: bool = True) -> bool:
        """The current code (unless app_code is False: unlocking takes recovery codes only) or a recovery code; "Lost
        both" only says how to start over by hand. App codes go through the same check as the approval box (each step once;
        wrong ones count toward its pause and lock); recovery codes are tried even while code entry is held: they
        are 80 bits, not guessable, and the lock exists to stop guessing 6 digits."""
        if self.st != ON:
            return False
        wrong_left: Optional[int] = None
        used = False
        for attempt in range(TRIES_PER_BOX):
            held = await asyncio.to_thread(self.codes.blocked) if app_code else None
            if held is not None:
                text = self.t.prove_held(action, held, wrong_left)
            elif app_code:
                text = self.t.prove(action, wrong_left, used)
            else:
                text = self.t.prove_unlock(wrong_left)
            ans = await self.ui.ask(text, ("Cancel", self.LOST, "OK"), field=True, timeout_s=BOX_CODE_S)
            if ans.button == self.LOST:
                return await self._lost_both()
            if ans.button != "OK":
                return False
            typed, ans.text = ans.text, ""
            six = authcode.normalize(typed)
            used = False
            if six is not None and app_code and held is None:
                verdict = await asyncio.to_thread(self.codes.check, six)
                if verdict == authcode.ACCEPTED:
                    return True
                used = verdict in (authcode.USED, authcode.JUST_STARTED)
            elif self._recovery_code(typed):
                return True
            typed = six = None
            self._log("settings_code_wrong", action)
            wrong_left = TRIES_PER_BOX - 1 - attempt
            if wrong_left <= 0:
                return False
        return False

    async def _show_key(self, pending: PendingSetup, replacing: bool) -> bool:
        """Show the new key as a code to scan (the key as text under it) and wait for the person to say it is in
        their app. The code is made by the machine itself and never leaves it; the key as text is the fallback for
        an app that cannot scan."""
        key_text = pending.key_text()
        qr = QrCode(uri=otpauth_uri(key_text), key_text=key_text,
                    fallback=self.t.key_fallback(key_text), text=self.t.key_qr(replacing),
                    plain_text=self.t.key(key_text, replacing))
        ask_qr = getattr(self.ui, "ask_qr", None)
        if ask_qr is None:                     # a box program without the code box: the key as text, as before
            return await self._info(qr.plain_text, "I added it", BOX_KEY_S)
        return (await ask_qr(qr, ("Cancel", "I added it"), timeout_s=BOX_KEY_S)).button == "I added it"

    async def _new_key(self, replacing: bool) -> Optional[tuple[PendingSetup, int, list[str]]]:
        """Show a new key, take a first code made from it, show the recovery codes. Nothing is saved here."""
        pending = self.store.begin_setup()
        if not await self._show_key(pending, replacing):
            pending.discard()
            return None
        wrong_left: Optional[int] = None
        while True:
            ans = await self.ui.ask(self.t.confirm(wrong_left), ("Cancel", "Show key again", "OK"), field=True,
                                    timeout_s=BOX_CODE_S)
            if ans.button == "Show key again":
                if not await self._show_key(pending, replacing):
                    pending.discard()
                    return None
                continue
            if ans.button != "OK":
                pending.discard()
                return None
            now = self._clock()
            step = pending.check(ans.text, now)
            if step is not None:
                break
            far = pending.check(ans.text, now, window=SKEW_SEARCH_STEPS)
            if far is not None:
                pending.discard()
                await self._note(self.t.clock(far - authcode.step_at(now)))
                self._log("authenticator_setup_stopped", "clock")
                return None
            wrong_left = TRIES_PER_BOX - 1 if wrong_left is None else wrong_left - 1
            if wrong_left <= 0:
                pending.discard()
                await self._note(self.t.confirm_failed())
                self._log("authenticator_setup_stopped", "first code did not match")
                return None
        codes = new_recovery_codes()
        if not await self._info(self.t.recovery(codes, False), "I saved them", BOX_KEY_S):
            pending.discard()
            return None
        return pending, step, codes

    # --- the four commands ---
    async def setup(self) -> Result:
        if not self.store.backend.available():
            raise EnrollError("this machine has no usable secret store for the authenticator key")
        with Busy(self.d, self._clock):
            await self._settle_pause()
            self.st = state(self.store)
            replacing = self.st == ON
            intro = self.t.intro_replace() if replacing else self.t.intro_setup(self.st == DAMAGED)
            if not await self._info(intro):
                return Result(False, CANCELLED)
            # D67: replacing needs the current code or a recovery code. Turning it on (none set up, or one that
            # cannot be opened) needs none: no remote session can exist while it is off, and on macOS no session
            # command can write Tether's data folder (the session lock).
            if replacing and not await self._prove("replace the authenticator", "replace its authenticator"):
                return Result(False, CANCELLED)
            if replacing:
                await self._note(self.t.replace_warning())
            made = await self._new_key(replacing)
            if made is None:
                return Result(False, CANCELLED)
            pending, step, codes = made
            try:
                self.store.commit(pending, hash_recovery_codes(codes), step, entry=self.t.entry)
            except SeedStoreError as e:
                pending.discard()
                raise EnrollError(str(e)) from None
            del codes
            self._log("authenticator_replaced" if replacing else "authenticator_set_up")
            await self._note(self.t.done_setup(replacing))
            return Result(True, "The new authenticator is set up; the old one no longer works." if replacing else
                          "The authenticator is set up. Each new remote session now asks for a code from your app on "
                          "this screen.")

    async def export(self, folder: str = "") -> Result:
        """Make the one-time transfer file for another machine (D85). A current code or a recovery code comes first;
        the one-time phrase is shown only in a box, and the terminal is told only the path and the next steps."""
        if self.store.status() == NONE:
            return Result(False, NOT_ON)
        with Busy(self.d, self._clock):
            await self._settle_pause()
            refused = await self._need_on()
            if refused is not None:
                return refused
            target = export_folder(folder) / TRANSFER_FILE
            if os.path.lexists(target):
                raise EnrollError(f"{target} already exists; move or delete it first (this never overwrites a file)")
            if not await self._prove("export the authenticator", "export its authenticator"):
                return Result(False, CANCELLED)
            phrase = new_transfer_phrase()
            seed = self.store.get_seed()
            try:
                record = make_transfer_record(phrase, seed, self.store.recovery_fingerprints(),
                                              self.store.entry_name() or ENTRY_NAME)
            finally:
                del seed
            shown = await self.ui.ask(self.t.transfer_phrase(show_code(phrase)), ("OK",), timeout_s=BOX_KEY_S)
            if shown.button != "OK":
                return Result(False, CANCELLED)
            try:
                written = write_transfer_file(target, record)
            except OSError:
                raise EnrollError(f"{target} could not be written; nothing was saved") from None
            if not written:
                raise EnrollError(f"{target} already exists; move or delete it first (this never overwrites a file)")
            self._log("authenticator_exported")
            return Result(True, f"Transfer file: {target}\nOn the other machine run `hermes tether authenticator "
                                f"join {target}`, then delete this file.")

    async def join(self, file_arg: str = "") -> Result:
        """Join this machine with the transfer file from another machine (D85): the phrase (five tries), then the
        first code from the app for the imported seed, then commit through the local seal. Nothing is saved unless
        every step succeeds; the file may be deleted afterwards, only when it is a plain file."""
        if not file_arg:
            raise EnrollError("say which transfer file to join with: hermes tether authenticator join <file>")
        path = Path(file_arg).expanduser()
        with Busy(self.d, self._clock):
            await self._settle_pause()
            self.st = state(self.store)
            replacing = self.st == ON
            if replacing:
                # The replace path setup uses: the machine's own current code, or one of its recovery codes.
                if not await self._prove("replace the authenticator", "replace its authenticator"):
                    return Result(False, CANCELLED)
                await self._note(self.t.join_replace_warning())
            try:
                header, sealed, salt, nonce = read_transfer_file(path)
            except TransferError as why:
                return Result(False, f"{path} cannot be used ({why}); nothing was saved.")
            opened: Optional[dict] = None
            wrong_left: Optional[int] = None
            for attempt in range(TRANSFER_TRIES):
                ans = await self.ui.ask(self.t.join_phrase(wrong_left), ("Cancel", "OK"), field=True,
                                        timeout_s=BOX_CODE_S)
                if ans.button != "OK":
                    return Result(False, CANCELLED)
                typed, ans.text = ans.text, ""
                phrase = clean_transfer(typed)
                typed = None
                if phrase:
                    try:
                        opened = open_transfer_record(header, sealed, salt, nonce, phrase)
                    except TransferError:
                        opened = None
                if opened is not None:
                    break
                self._log("authenticator_join_phrase_wrong")
                wrong_left = TRANSFER_TRIES - 1 - attempt
            if opened is None:
                return Result(False, "The transfer phrase did not match, so nothing was saved.")
            recovery, entry = opened["recovery"], opened["entry"]
            seed = opened["seed"]
            opened = None
            pending = PendingSetup(seed)
            del seed
            step: Optional[int] = None
            wrong_left = None
            while step is None:
                ans = await self.ui.ask(self.t.join_confirm(wrong_left), ("Cancel", "OK"), field=True,
                                        timeout_s=BOX_CODE_S)
                if ans.button != "OK":
                    pending.discard()
                    return Result(False, CANCELLED)
                typed, ans.text = ans.text, ""
                now = self._clock()
                step = pending.check(typed, now)
                if step is not None:
                    typed = None
                    break
                far = pending.check(typed, now, window=SKEW_SEARCH_STEPS)
                typed = None
                if far is not None:
                    pending.discard()
                    await self._note(self.t.clock(far - authcode.step_at(now)))
                    return Result(False, "This machine's clock seems wrong; nothing was saved.")
                wrong_left = TRIES_PER_BOX - 1 if wrong_left is None else wrong_left - 1
                if wrong_left <= 0:
                    pending.discard()
                    await self._note(self.t.join_failed())
                    return Result(False, "The codes did not match; nothing was saved.")
            try:
                self.store.commit(pending, recovery, step, entry=entry)
            except SeedStoreError as e:
                pending.discard()
                raise EnrollError(str(e)) from None
            self._log("authenticator_joined" if not replacing else "authenticator_joined_replaced")
            ans = await self.ui.ask(f"{self.t.done_join(replacing)}\n\n{self.t.delete_transfer(str(path))}",
                                    ("Keep", "Delete"), timeout_s=BOX_KEY_S)
            if ans.button == "Delete":
                if delete_transfer_file(path):
                    await self._note(self.t.transfer_deleted(str(path)))
                else:
                    await self._note(self.t.transfer_not_deleted(str(path)))
            return Result(True, "The authenticator is set up on this machine from the transfer file.")

    async def remove(self) -> Result:
        if self.store.status() == NONE:
            return Result(False, "No authenticator is set up on this machine; remote use is already off.")
        with Busy(self.d, self._clock):
            await self._settle_pause()
            self.st = state(self.store)
            if not await self._info(self.t.intro_remove()):
                return Result(False, CANCELLED)
            # One that cannot be opened is removed without a code (there is none to check, and it already refuses
            # remote use); a working one needs the current code or a recovery code.
            if self.st == ON and not await self._prove("remove the authenticator", "remove its authenticator"):
                return Result(False, CANCELLED)
            self.store.remove()
            self._log("authenticator_removed")
            await self._note(self.t.done_remove())
            return Result(True, "The authenticator is removed; remote use of this machine is off.")

    async def _need_on(self) -> Optional[Result]:
        self.st = state(self.store)
        if self.st == ON:
            return None
        return Result(False, NOT_READ if self.st == DAMAGED else NOT_ON)

    async def recovery_codes(self) -> Result:
        if self.store.status() == NONE:
            return Result(False, NOT_ON)
        with Busy(self.d, self._clock):
            await self._settle_pause()
            refused = await self._need_on()
            if refused is not None:
                return refused
            if not await self._info(self.t.intro_codes()):
                return Result(False, CANCELLED)
            if not await self._prove("make new recovery codes", "make new recovery codes"):
                return Result(False, CANCELLED)
            codes = new_recovery_codes()
            if not await self._info(self.t.recovery(codes, True), "I saved them", BOX_KEY_S):
                return Result(False, CANCELLED)
            try:
                self.store.set_recovery(hash_recovery_codes(codes))
            except SeedStoreError:
                return Result(False, "The new recovery codes could not be saved; the old ones still work.")
            del codes
            self._log("recovery_codes_renewed")
            await self._note(self.t.done_codes())
            return Result(True, "New recovery codes are saved; the old ones no longer work.")

    async def unlock(self) -> Result:
        """Code entry paused or locked after too many wrong codes (here or in the approval box), or locked because its
        state file was changed: a recovery code opens it again. A code from the app is not taken
        here, so the lock cannot be guessed open."""
        if self.store.status() == NONE:
            return Result(False, NOT_ON)
        with Busy(self.d, self._clock):
            await self._settle_pause()
            refused = await self._need_on()
            if refused is not None:
                return refused
            if not await self._info(self.t.intro_unlock()):
                return Result(False, CANCELLED)
            if not await self._prove("unlock code entry", "unlock code entry", app_code=False):
                return Result(False, CANCELLED)
            await asyncio.to_thread(self.codes.clear_lock)
            self._log("code_entry_unlocked")
            await self._note(self.t.done_unlock())
            return Result(True, "Code entry is unlocked.")


# ---------- who may start these ----------

REMOTE_TEXT = ("The authenticator is set up, changed and removed by a person at this machine, never from a remote "
               "session's or an agent's shell. Run this yourself in a terminal here.")


JOIN_REMOTE_TEXT = ("Pairing is done by a person at this machine, never from a remote session's or an agent's shell. "
                    "Run `hermes tether join` yourself in a terminal here.")


def in_remote_shell() -> bool:
    """True in a terminal a remote session got on this device (REMOTE_MARK) or in an agent's shell (Hermes's session
    marks). Not a wall against a program that already runs as this user (it can unset them); it keeps the plain
    paths (`hermes tether authenticator ...` or `hermes tether join` sent through device exec) out and says so."""
    if os.environ.get(REMOTE_MARK):
        return True
    try:
        from .forward import _launched_from_agent_shell
        return bool(_launched_from_agent_shell())
    except Exception:  # noqa: BLE001 - outside Hermes: the mark above still counts
        return False


def refuse_reason() -> str:
    """Why this process must not run a setup, or ''."""
    if in_remote_shell():
        return REMOTE_TEXT
    if sys.platform not in ("darwin", "win32"):
        return "The authenticator needs macOS or Windows; other devices refuse remote use."
    if sys.platform == "darwin" and os.geteuid() == 0:
        return "Run this as your own user, not as root: the files it saves must belong to the user Hermes runs as."
    return ""


# ---------- the real boxes ----------

def _minimal_env(keys: tuple[str, ...]) -> dict[str, str]:
    from .consent import _minimal_env as env
    return env(keys)


async def _run_dialog(argv: list[str], stdin: bytes, env: dict[str, str], timeout_s: float) -> Optional[str]:
    """Run a box program: everything secret goes in on stdin and comes back on stdout, never in argv or env. A box
    that outlives its time is killed (it takes its window with it)."""
    from .consent import _close_dialog
    try:
        proc = await asyncio.create_subprocess_exec(*argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                                    stderr=subprocess.DEVNULL, env=env)
    except OSError:
        return None
    try:
        out, _ = await asyncio.wait_for(proc.communicate(stdin), timeout_s + 15)
    except asyncio.TimeoutError:
        return None
    finally:
        await _close_dialog(proc)
    return out.decode("utf-8", errors="replace")


def _aq(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


JXA_QR_SCRIPT = """\
ObjC.import('AppKit'); ObjC.import('CoreImage'); ObjC.import('CoreGraphics');
// The new key as a code to scan, drawn by the system itself (Core Image's own QR generator) and shown in a box.
// The script, the URI and the key are inside it: it goes in on stdin, never in the arguments, the environment or
// a file. The button the person pressed comes back on stdout, as the AppleScript box does.
function run() {
  var uri = @@URI@@;
  var fallback = @@FALLBACK@@;
  var head = @@HEAD@@;
  var message = @@MESSAGE@@;
  var title = @@TITLE@@;
  var buttons = @@BUTTONS@@;          // the order they are shown in: the way on first, cancel last

  // --- the code to scan ---
  var data = $.NSString.stringWithString(uri).dataUsingEncoding($.NSUTF8StringEncoding);
  var filter = $.CIFilter.filterWithName("CIQRCodeGenerator");
  filter.setValueForKey(data, "inputMessage");
  filter.setValueForKey("M", "inputCorrectionLevel");
  var code = filter.outputImage;
  if (!code) { return ""; }                        // no code: the caller shows the key box instead
  var w = Math.round(code.extent.size.width);     // the modules, one pixel each
  var quiet = 4;                                   // the white margin a scanner needs
  var scale = Math.max(1, Math.floor(300 / (w + 2 * quiet)));
  var side = (w + 2 * quiet) * scale;             // about 300 by 300 points

  var context = $.CIContext.context;              // no options argument: JXA passes a null as NSNull, which crashes
  var picture = context.createCGImageFromRect(code, code.extent);
  var space = $.CGColorSpaceCreateDeviceRGB();
  var bits = $.CGBitmapContextCreate(null, side, side, 8, side * 4, space, 1);
  try { $.CGContextSetInterpolation(bits, 1); } catch (e) { }   // nearest neighbour: sharp squares
  try { bits.interpolation = 1; } catch (e) { }
  $.CGContextSetRGBFillColor(bits, 1, 1, 1, 1);
  $.CGContextFillRect(bits, $.CGRectMake(0, 0, side, side));
  $.CGContextTranslateCTM(bits, 0, side);
  $.CGContextScaleCTM(bits, 1, -1);                // the bitmap counts its rows from the top: the code stays upright
  $.CGContextDrawImage(bits, $.CGRectMake(quiet * scale, quiet * scale, w * scale, w * scale), picture);
  var image = $.NSImage.alloc.initWithCGImageSize($.CGBitmapContextCreateImage(bits), $.NSMakeSize(side, side));

  // --- the box ---
  var app = $.NSApplication.sharedApplication;
  app.setActivationPolicy(1);                     // an accessory app: no Dock icon, but our box may come forward
  app.activateIgnoringOtherApps(true);
  var alert = $.NSAlert.alloc.init;
  alert.setMessageText(head);
  alert.setInformativeText(message);
  alert.window.setTitle(title);
  for (var i = 0; i < buttons.length; i++) { alert.addButtonWithTitle(buttons[i]); }
  var shown = alert.buttons;
  try {
    shown.objectAtIndex(0).setKeyEquivalent("\\r");                          // Return: the way on
    shown.objectAtIndex(shown.count - 1).setKeyEquivalent("\\u001b");       // Esc: cancel
  } catch (e) { }

  var width = Math.max(side, 430);
  var box = $.NSView.alloc.initWithFrame($.NSMakeRect(0, 0, width, side + 48));
  var shot = $.NSImageView.alloc.initWithFrame($.NSMakeRect((width - side) / 2, 36, side, side));
  shot.setImage(image);
  shot.setImageScaling(3);                       // NSImageScaleNone: the code at its own size
  var at = fallback.indexOf(": ");
  var says = at > 0 ? fallback.substring(0, at) : fallback;
  var key = at > 0 ? fallback.substring(at + 2) : "";
  var note = $.NSTextField.alloc.initWithFrame($.NSMakeRect(0, 18, width, 16));
  note.setStringValue(says);
  note.setEditable(false);
  note.setSelectable(false);
  note.setBordered(false);
  note.setDrawsBackground(false);
  note.setAlignment(2);                           // centred
  var line = $.NSTextField.alloc.initWithFrame($.NSMakeRect(0, 0, width, 18));
  line.setStringValue(key);
  try { line.setFont($.NSFont.userFixedPitchFontOfSize(12)); } catch (e) { }
  line.setEditable(false);
  line.setSelectable(false);
  line.setBordered(false);
  line.setDrawsBackground(false);
  line.setAlignment(2);
  box.addSubview(shot);
  box.addSubview(note);
  box.addSubview(line);
  alert.setAccessoryView(box);
  try { alert.window.makeKeyAndOrderFront(null); } catch (e) { }
  var answer = Number(alert.runModal);           // JXA runs a no-argument method on access; "()" after it throws
  if (answer >= 1000 && answer < 1000 + buttons.length) { return buttons[answer - 1000]; }
  return "";                                     // closed without a button: nothing chosen, so cancel
}
"""


def _js(value: str) -> str:
    """A string as a JavaScript literal (JSON's strings are JavaScript's)."""
    return json.dumps(value)


def _fill(text: str, values: dict[str, str]) -> str:
    """Put the values into the placeholders of a script, in one pass (a value is never read as a placeholder)."""
    return re.sub(r"@@([A-Z]+)@@", lambda m: values[m.group(1)], text)


class MacUI:
    machine = "Mac"
    ENV = ("PATH", "HOME", "LANG")

    def __init__(self, name: str) -> None:
        self.name = name

    @staticmethod
    def dialog_script(text: str, buttons: tuple[str, ...], field: bool, timeout_s: float) -> str:
        btns = "{" + ", ".join(_aq(b) for b in buttons) + "}"
        answer = ' default answer "" with hidden answer' if field else ""
        cancel = f" cancel button {_aq(buttons[0])}" if len(buttons) > 1 else ""
        back = ("  return (button returned of r) & linefeed & (text returned of r)\n" if field
                else "  return button returned of r\n")
        return ("try\n"
                f"  set r to display dialog {_aq(text)}{answer} buttons {btns} default button {_aq(buttons[-1])}"
                f"{cancel} with title {_aq(TITLE['Mac'])} with icon caution giving up after {int(timeout_s)}\n"
                "  if gave up of r then return \"\"\n"
                f"{back}"
                "on error number -128\n  return \"\"\nend try")

    async def ask(self, text: str, buttons: tuple[str, ...], *, field: bool = False,
                  timeout_s: float = BOX_INFO_S) -> Answer:
        out = await _run_dialog(["/usr/bin/osascript", "-"], self.dialog_script(text, buttons, field, timeout_s).encode(),
                                _minimal_env(self.ENV), timeout_s)
        if not out:
            return Answer(None)
        button, _, typed = out.rstrip("\n").partition("\n")
        return Answer(button if button in buttons and (len(buttons) == 1 or button != buttons[0]) else None, typed)

    @staticmethod
    def qr_script(qr: QrCode, buttons: tuple[str, ...]) -> str:
        """The JXA that draws the key as a code to scan and shows it in a box. The URI, the key and the whole
        script travel on stdin; nothing of it is ever in the arguments or the environment."""
        values = {
            "URI": _js(qr.uri),
            "FALLBACK": _js(qr.fallback),
            "HEAD": _js(Texts.KEY_HEAD),
            "MESSAGE": _js(qr.text),
            "TITLE": _js(TITLE["Mac"]),
            "BUTTONS": json.dumps(list(reversed(buttons))),
        }
        return _fill(JXA_QR_SCRIPT, values)

    async def ask_qr(self, qr: QrCode, buttons: tuple[str, ...], *,
                     timeout_s: float = BOX_KEY_S) -> Answer:
        """The box with the key as a code to scan (the key as text under it). A code that cannot be drawn (no
        Core Image, no window) is no reason to stop the setup: the key box of today is shown instead."""
        script = self.qr_script(qr, buttons)
        out = await _run_dialog(["/usr/bin/osascript", "-l", "JavaScript", "-"], script.encode("utf-8"),
                                _minimal_env(self.ENV), timeout_s)
        answer = (out or "").strip()
        if answer not in buttons:
            logger.warning("tether: the authenticator's code box did not answer; the key box is shown instead")
            return await self.ask(qr.plain_text, buttons, timeout_s=timeout_s)
        if len(buttons) > 1 and answer == buttons[0]:
            return Answer(None)
        return Answer(answer)


WINDOWS_BOX_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
[Console]::InputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$in = [Console]::In.ReadToEnd() | ConvertFrom-Json
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()
$script:choice = ''
$f = New-Object System.Windows.Forms.Form
$f.Text = $in.title; $f.TopMost = $true; $f.FormBorderStyle = 'FixedDialog'; $f.MaximizeBox = $false
$f.MinimizeBox = $false; $f.ShowInTaskbar = $true; $f.StartPosition = 'CenterScreen'
$f.AutoSize = $true; $f.AutoSizeMode = 'GrowAndShrink'; $f.Padding = New-Object System.Windows.Forms.Padding(14)
$p = New-Object System.Windows.Forms.FlowLayoutPanel
$p.FlowDirection = 'TopDown'; $p.WrapContents = $false; $p.AutoSize = $true
$l = New-Object System.Windows.Forms.Label
$l.Text = $in.text; $l.AutoSize = $true; $l.MaximumSize = New-Object System.Drawing.Size(600, 0)
$l.Font = New-Object System.Drawing.Font('Segoe UI', 10)
$p.Controls.Add($l)
if ($in.PSObject.Properties.Name -contains 'image' -and $in.image) {
  try {
    $bytes = [Convert]::FromBase64String([string]$in.image)
    $stream = New-Object System.IO.MemoryStream(,$bytes)
    $shot = New-Object System.Windows.Forms.PictureBox
    $shot.Image = [System.Drawing.Image]::FromStream($stream)
    $shot.SizeMode = [System.Windows.Forms.PictureBoxSizeMode]::AutoSize
    $shot.Anchor = 'Top'
    $p.Controls.Add($shot)
  } catch { }
}
$t = $null
if ($in.field) {
  $t = New-Object System.Windows.Forms.TextBox
  $t.UseSystemPasswordChar = $true; $t.Width = 280; $t.Font = New-Object System.Drawing.Font('Consolas', 12)
  $p.Controls.Add($t)
}
$row = New-Object System.Windows.Forms.FlowLayoutPanel
$row.FlowDirection = 'RightToLeft'; $row.AutoSize = $true; $row.Anchor = 'Right'
$names = @($in.buttons)
for ($i = $names.Count - 1; $i -ge 0; $i--) {
  $b = New-Object System.Windows.Forms.Button
  $b.Text = $names[$i]; $b.Tag = $names[$i]; $b.AutoSize = $true
  $b.Add_Click({ $script:choice = [string]$this.Tag; $f.Close() })
  $row.Controls.Add($b)
  if ($i -eq $names.Count - 1) { $f.AcceptButton = $b }
  if ($i -eq 0 -and $names.Count -gt 1) { $f.CancelButton = $b }
}
$p.Controls.Add($row)
$f.Controls.Add($p)
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = [int]$in.timeout * 1000
$timer.Add_Tick({ $script:choice = ''; $timer.Stop(); $f.Close() })
$f.Add_Shown({ $f.Activate(); if ($t -ne $null) { [void]$t.Focus() }; $timer.Start() })
[void]$f.ShowDialog()
$typed = ''
if ($t -ne $null) { $typed = $t.Text }
[Console]::Out.Write((@{ button = $script:choice; text = $typed } | ConvertTo-Json -Compress))
"""



def _qr_png(uri: str) -> Optional[bytes]:
    """The key as a code to scan, as PNG bytes in memory (never a file), or None when the qrcode package (or the
    Pillow that draws it) is not there: the key box of today is shown then."""
    try:
        import qrcode
    except Exception:  # noqa: BLE001 - the package is optional; the key box is the fallback
        return None
    try:
        image = qrcode.make(uri, box_size=6, border=4)      # about 300 pixels, with the quiet zone a scanner needs
        buf = io.BytesIO()
        image.save(buf, format="PNG")
        data = buf.getvalue()
    except Exception:  # noqa: BLE001 - a package that cannot draw it is no reason to stop the setup
        return None
    return data if data[:8] == b"\x89PNG\r\n\x1a\n" else None


class WindowsUI:
    machine = "PC"
    ENV = ("PATH", "SystemRoot", "TEMP", "TMP", "USERPROFILE", "LANG", "LC_ALL")

    def __init__(self, name: str) -> None:
        self.name = name

    @staticmethod
    def _ps(script: str) -> list[str]:
        from .consent import _powershell
        return [_powershell(), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script]

    async def ask(self, text: str, buttons: tuple[str, ...], *, field: bool = False,
                  timeout_s: float = BOX_INFO_S) -> Answer:
        data = json.dumps({"title": TITLE["PC"], "text": text, "buttons": list(buttons), "field": bool(field),
                           "timeout": int(timeout_s)})
        out = await _run_dialog(self._ps(WINDOWS_BOX_SCRIPT), data.encode("utf-8"), _minimal_env(self.ENV), timeout_s)
        try:
            got = json.loads(out or "")
        except ValueError:
            return Answer(None)
        button = got.get("button") if isinstance(got, dict) else None
        typed = got.get("text") if isinstance(got, dict) and isinstance(got.get("text"), str) else ""
        ok = isinstance(button, str) and button in buttons and (len(buttons) == 1 or button != buttons[0])
        return Answer(button if ok else None, typed)

    async def ask_qr(self, qr: QrCode, buttons: tuple[str, ...], *,
                     timeout_s: float = BOX_KEY_S) -> Answer:
        """The box with the key as a code to scan (the key as text under it). The code is drawn by the qrcode
        package when it is installed; without it the key box of today is shown instead. The picture goes into the
        box as bytes on stdin: never as a file."""
        image = _qr_png(qr.uri)
        if image is None:
            return await self.ask(qr.plain_text, buttons, timeout_s=timeout_s)
        data = json.dumps({"title": TITLE["PC"], "text": f"{qr.text}\n\n{qr.fallback}", "buttons": list(buttons),
                           "field": False, "timeout": int(timeout_s),
                           "image": base64.b64encode(image).decode("ascii")})
        out = await _run_dialog(self._ps(WINDOWS_BOX_SCRIPT), data.encode("utf-8"), _minimal_env(self.ENV), timeout_s)
        try:
            got = json.loads(out or "")
        except ValueError:
            return Answer(None)
        button = got.get("button") if isinstance(got, dict) else None
        ok = isinstance(button, str) and button in buttons and (len(buttons) == 1 or button != buttons[0])
        return Answer(button if ok else None, "")


def default_ui(name: str) -> SetupUI:
    return WindowsUI(name) if sys.platform == "win32" else MacUI(name)


async def run(command: str, d: Path, name: str, store: SeedStore, ui: SetupUI, arg: str = "") -> Result:
    e = Enrollment(d, name, store, ui)
    if command == "setup":
        return await e.setup()
    if command == "export":
        return await e.export(arg)
    if command == "join":
        return await e.join(arg)
    if command == "remove":
        return await e.remove()
    if command == "recovery-codes":
        return await e.recovery_codes()
    if command == "unlock":
        return await e.unlock()
    raise EnrollError(f"unknown command {command!r}")
