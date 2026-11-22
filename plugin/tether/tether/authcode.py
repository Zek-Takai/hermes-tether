"""The device's approval check: a code from the person's authenticator app (RFC 6238 TOTP), typed into the
approval box on this device's screen (design D63, D68).

- The authenticator's secret (the seed) lives in a ``SeedStore`` (seedstore.py: a sealed file in Tether's data
  folder, opened by the running Hermes and then held in memory). This module asks it for the seed only after a well-formed code was typed,
  for one comparison, and never keeps it: it is never stored on an object, logged, written, put in an error text,
  an argument or an environment.
- A code is 6 digits for one 30-second step; the steps just before and after the device's own are accepted too
  (a clock up to 30 s off). Each step is accepted once: the newest accepted step is recorded in
  ``authenticator_state.json`` (written and flushed to disk before anything is granted), so a code cannot be used
  again, also after a restart.
- Wrong codes are counted for the whole device: after every 5 in a row code entry pauses (5, 10, 20 minutes);
  after 20 in a row it is locked until the owner unlocks it at the computer (``clear_lock``, called only by the
  owner's unlock, enroll.py). A correct code resets the count. Nobody on the host can type into the box, so nobody
  there can cause a lock or guess a code: only the device's own keyboard can.
- The state file is sealed with a key derived from the seed, so a program without the seed can neither forge it nor
  reset it. A missing, changed or older copy (a lower generation than this process saw) is treated as tampering:
  code entry is locked until the owner unlocks it, and nothing is ever accepted on its word.
"""
from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import logging
import math
import os
import re
import stat
import struct
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable, Iterator, Optional, Protocol

logger = logging.getLogger(__name__)

DIGITS = 6
STEP_S = 30                 # RFC 6238 time step
WINDOW_STEPS = 1            # accept the step before and after the device's own (a clock up to 30 s off)
MIN_SEED_BYTES = 16         # RFC 4226 asks for at least 128 bits (setup makes 160)
MAX_TRIES_PER_BOX = 3       # submits per approval request (a retyped box counts)
PAUSE_EVERY = 5             # wrong codes in a row before code entry pauses
PAUSE_BASE_S = 300.0        # first pause 5 min, then 10, then 20
LOCK_AFTER = 20             # wrong codes in a row before code entry is locked until the owner unlocks it
STATE_FILE = "authenticator_state.json"   # sealed: newest used step, wrong-code count, pause, lock (no secret)
LOCK_FILE = "authenticator_state.lock"    # Windows only: the file the state lock is taken on
LOCK_WAIT_S = 5.0                         # a check that cannot take the state lock in this time is refused
SETUP_COMMAND = "hermes tether authenticator setup"
UNLOCK_COMMAND = "hermes tether authenticator unlock"
_SEAL_INFO = b"tether-authenticator-state-v1"

# Verdicts of CodeChecker.check
ACCEPTED, WRONG, USED, PAUSED, LOCKED, UNAVAILABLE = "accepted", "wrong", "used", "paused", "locked", "unavailable"
JUST_STARTED = "just started"   # a right code, but from the minute this Hermes started in (D68): refused, not counted

# The device's refusals when no code can be checked at all (seedstore.SeedStore.refusal): no box is shown. Each
# contains runtime.DENIED ("did not allow remote use"), so the host closes the connection on it.
_REFUSED = "this device did not allow remote use: "
NO_AUTHENTICATOR_TEXT = _REFUSED + "no authenticator is set up on it"
SET_UP_AGAIN_TEXT = _REFUSED + "its authenticator must be set up again there"
NO_SAFE_STORE_TEXT = _REFUSED + "it has no safe place to keep an authenticator"
STORE_REFUSALS = (NO_AUTHENTICATOR_TEXT, SET_UP_AGAIN_TEXT, NO_SAFE_STORE_TEXT)

_TYPED = re.compile(r"[0-9]{%d}" % DIGITS)
_ENTRY = re.compile(r"[A-Za-z0-9 ()._:@'-]{1,64}")


class SeedUnavailable(Exception):
    """The seed could not be had (none set up, its record could not be opened). Its text is fixed and never
    carries the seed."""


class SeedStore(Protocol):
    """What the checker needs from where the seed lives (seedstore.SeedStore on a device; MemorySeedStore in tests).

    refusal(): None when codes can be checked now (an authenticator is set up and this process holds it); else the
        device's fixed refusal text (STORE_REFUSALS). Reads no secret, shows no prompt, never raises.
    get_seed(): the raw seed (at least 16 bytes), from this process's memory; raises SeedUnavailable. The caller
        holds it for one comparison and drops it.
    seal_key(): a key derived from the seed (HKDF-SHA256, info _SEAL_INFO) that seals the state file; raises
        SeedUnavailable. Not the seed.
    account(): the name of the stored seed (it changes with every setup), so a state file of an earlier seed is
        never taken for this one; "" when none is held.
    entry_name(): the entry name the person's authenticator app shows ("Hermes Tether" on every machine), or "".

    Optional: matching_steps(code, steps) -> list[int]: the steps among ``steps`` whose code equals ``code``,
        computed where the seed lives (a helper process, a hardware-held key). When a store has it, the checker
        calls it instead of get_seed, and the seed never enters Hermes's memory.
    """

    def refusal(self) -> Optional[str]: ...

    def get_seed(self) -> bytes: ...

    def seal_key(self) -> bytes: ...

    def account(self) -> str: ...

    def entry_name(self) -> str: ...


def hkdf(key: bytes, info: bytes) -> bytes:
    """HKDF-SHA256 (RFC 5869) with an all-zero salt, one 32-byte block."""
    prk = hmac.new(b"\0" * 32, bytes(key), hashlib.sha256).digest()
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()


class NoSeedStore:
    """No authenticator: remote use is refused (a gate built without a store)."""

    def refusal(self) -> Optional[str]:
        return NO_AUTHENTICATOR_TEXT

    def get_seed(self) -> bytes:
        raise SeedUnavailable("no authenticator is set up on this device")

    def seal_key(self) -> bytes:
        raise SeedUnavailable("no authenticator is set up on this device")

    def account(self) -> str:
        return ""

    def entry_name(self) -> str:
        return ""


class MemorySeedStore:
    """Tests and stand-ins: a seed held in memory. Never used by the device role."""

    def __init__(self, seed: Optional[bytes], entry: str = "Hermes Tether", account: str = "memory") -> None:
        self._seed, self._entry, self._account = seed, entry, account
        self.reads = 0                   # how many times the seed was read (tests assert when it must not be)

    def refusal(self) -> Optional[str]:
        return None if self._seed else NO_AUTHENTICATOR_TEXT

    def get_seed(self) -> bytes:
        self.reads += 1
        if not self._seed:
            raise SeedUnavailable("no authenticator is set up on this device")
        return bytes(self._seed)

    def seal_key(self) -> bytes:
        if not self._seed:
            raise SeedUnavailable("no authenticator is set up on this device")
        return hkdf(self._seed, _SEAL_INFO)

    def account(self) -> str:
        return self._account if self._seed else ""

    def entry_name(self) -> str:
        return self._entry


# ---------- RFC 4226 / RFC 6238 ----------
def hotp(key: bytes, counter: int, digits: int = DIGITS) -> str:
    """RFC 4226 HOTP with HMAC-SHA1 (what every authenticator app uses for TOTP by default)."""
    mac = hmac.new(bytes(key), struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    value = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % (10 ** digits)).zfill(digits)


def step_at(t: float) -> int:
    """RFC 6238 time step of the Unix time t (T0 = 0, X = 30 s)."""
    return int(t // STEP_S)


def normalize(typed: object) -> Optional[str]:
    """What the person typed, as 6 ASCII digits (spaces and one hyphen in the middle allowed, as apps show
    "123 456"), or None when it is not a code. Never logs or returns anything else."""
    if not isinstance(typed, str) or len(typed) > 32:
        return None
    text = typed.strip().replace(" ", "").replace(" ", "")
    if len(text) == DIGITS + 1 and text[DIGITS // 2] == "-":
        text = text[:DIGITS // 2] + text[DIGITS // 2 + 1:]
    return text if _TYPED.fullmatch(text) else None


def _candidates(now: float, window: int = WINDOW_STEPS) -> list[int]:
    centre = step_at(now)
    return list(range(centre - window, centre + window + 1))


def matches(seed: bytes, code: str, now: float, window: int = WINDOW_STEPS) -> list[int]:
    """The steps around now whose code equals code. Every candidate is compared, in constant time, and no
    comparison stops early."""
    found = []
    for step in _candidates(now, window):
        if hmac.compare_digest(hotp(seed, step).encode(), code.encode()):
            found.append(step)
    return found


# ---------- the private state file (never through a link) ----------
def _read_own(path: Path) -> Optional[bytes]:
    """The bytes of a regular file of ours, or None when it is missing. A link (or reparse point) in its place, or
    anything that is not a plain file, raises OSError: it is never followed."""
    if os.name == "nt":
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            return None
        if stat.S_ISLNK(st.st_mode) or getattr(st, "st_file_attributes", 0) & 0x400 or not stat.S_ISREG(st.st_mode):
            raise OSError("not a plain file")
        return path.read_bytes()
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
    except FileNotFoundError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError("not a plain file")
        chunks = []
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def _canonical(state: dict) -> bytes:
    return json.dumps(state, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _fresh(last_step: int = 0) -> dict:
    return {"last_step": int(last_step), "wrong": 0, "paused_until": 0.0, "locked": False}


def _shape(data: Any) -> Optional[dict]:
    if not isinstance(data, dict) or data.get("v") != 1 or not isinstance(data.get("account"), str):
        return None
    try:
        gen, last, wrong = data["gen"], data["last_step"], data["wrong"]
        paused, locked = data["paused_until"], data["locked"]
        if any(isinstance(v, bool) or not isinstance(v, int) for v in (gen, last, wrong)):
            return None
        if isinstance(paused, bool) or not isinstance(paused, (int, float)) or not math.isfinite(paused):
            return None
        if not isinstance(locked, bool) or gen < 0 or last < 0 or wrong < 0:
            return None
    except KeyError:
        return None
    return {"account": data["account"], "gen": gen, "last_step": last, "wrong": wrong,
            "paused_until": float(paused), "locked": locked}


def peek_state(folder: Path) -> Optional[dict]:
    """The state file's counters for display only (`hermes tether status`, the panel): NOT verified (that needs the
    seed), so nothing may be decided on them. None when there is none or it cannot be read."""
    try:
        raw = _read_own(Path(folder) / STATE_FILE)
        data = _shape(json.loads(raw.decode())) if raw else None
    except (OSError, ValueError, UnicodeDecodeError):
        return None
    return data


class CodeChecker:
    """Checks a typed code against the seed and the persisted state, under one exclusive lock, so two boxes (or
    two processes: the gateway and the CLI's settings boxes) can never both accept one step.

    ``folder`` is the device's tether data folder (state in STATE_FILE there), or None for memory only (tests).
    ``clock``: the time codes are judged by (Unix time; time.time on a device). ``wall``: the time pauses are
    measured in (time.time). ``narrow``: the running gateway passes True, so the codes of the minute it started in
    are refused: a code typed before a restart can never be used again after it, whatever copy of the state file
    a program puts back (D68)."""

    def __init__(self, store: SeedStore, folder: Optional[Path], *, clock: Callable[[], float] = time.time,
                 wall: Callable[[], float] = time.time, narrow: bool = False) -> None:
        self.store, self.folder = store, Path(folder) if folder is not None else None
        self._clock, self._wall = clock, wall
        self._mem = _fresh()
        self._mem_lock = threading.Lock()
        # Newest step this process may never accept again: what it accepted itself, and with ``narrow`` the
        # minute it started in. A state file that is deleted or rolled back cannot bring one back.
        self._floor = step_at(clock()) + WINDOW_STEPS if narrow else -1
        self._start_floor = self._floor      # the restart floor alone (later acceptances raise _floor, not this)
        self._accepted_max = -1              # the newest step this process itself accepted
        self._gens: dict[str, int] = {}      # account -> newest generation of its state file this process saw
        self._warned = False

    # ----- reading and writing the state -----
    @property
    def path(self) -> Optional[Path]:
        return self.folder / STATE_FILE if self.folder is not None else None

    def _tampered(self, account: str, why: str) -> dict:
        """The state file is missing, changed outside Tether, sealed for another seed or older than one this process
        saw: lock code entry until the owner unlocks it, and never accept a step it might have used."""
        if not self._warned:
            self._warned = True
            logger.warning("tether: the authenticator's state file was %s; code entry is locked until its owner "
                           "unlocks it at this computer (%s)", why, UNLOCK_COMMAND)
        state = _fresh(max(self._floor, step_at(self._clock()) + WINDOW_STEPS))
        state.update(locked=True, account=account, gen=self._gens.get(account, 0), tampered=True)
        return state

    def _load(self) -> dict:
        """The verified state (memory mode: the in-memory one). Raises SeedUnavailable when the store holds no
        seed; returns a locked state (to be saved) when the file cannot be trusted."""
        if self.path is None:
            return dict(self._mem)
        account = str(self.store.account() or "")
        key = self.store.seal_key()
        if not account:
            raise SeedUnavailable("no authenticator is held")
        try:
            raw = _read_own(self.path)
        except OSError:
            return self._tampered(account, "not a plain file")
        if raw is None:
            return self._tampered(account, "missing")
        try:
            data = json.loads(raw.decode())
            mac = str(data.pop("mac", "")) if isinstance(data, dict) else ""
        except (ValueError, UnicodeDecodeError):
            return self._tampered(account, "damaged")
        state = _shape(data)
        if state is None or not hmac.compare_digest(mac, hmac.new(key, _canonical(data), hashlib.sha256).hexdigest()):
            return self._tampered(account, "changed outside Tether")
        if state["account"] != account:
            return self._tampered(account, "sealed for another authenticator")
        if state["gen"] < self._gens.get(account, -1):
            return self._tampered(account, "replaced by an older copy")
        self._gens[account] = state["gen"]
        state["last_step"] = max(state["last_step"], self._floor)
        return state

    def _save(self, state: dict) -> None:
        clean = {k: state[k] for k in ("last_step", "wrong", "paused_until", "locked")}
        if self.path is None:
            self._mem = dict(clean)
            return
        account = str(self.store.account() or "")
        gen = max(self._gens.get(account, -1), int(state.get("gen", 0))) + 1
        payload = {"v": 1, "account": account, "gen": gen, **clean}
        payload["mac"] = hmac.new(self.store.seal_key(), _canonical(payload), hashlib.sha256).hexdigest()
        # A new private file next to it (mkstemp: 0600, O_EXCL), flushed to disk, then renamed into place: a crash
        # can never bring back an older last_step than one a grant was given on, and a link at the name is
        # replaced, never written through.
        fd, tmp = tempfile.mkstemp(dir=self.folder, prefix=f".{STATE_FILE}.", suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as fh:
                fh.write(json.dumps(payload))
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise
        self._gens[account] = gen

    @contextlib.contextmanager
    def _exclusive(self) -> Iterator[None]:
        """The state lock: across threads (memory state) or across processes (the data folder itself on macOS and
        Linux, as OpenSessions does; a lock file on Windows). Raises TimeoutError when it cannot be had."""
        if self.folder is None:
            if not self._mem_lock.acquire(timeout=LOCK_WAIT_S):
                raise TimeoutError("the code state is busy")
            try:
                yield
            finally:
                self._mem_lock.release()
            return
        deadline = time.monotonic() + LOCK_WAIT_S
        if os.name == "nt":                                      # untested on Windows (no machine): see spec
            import msvcrt
            fd = os.open(self.folder / LOCK_FILE, os.O_RDWR | os.O_CREAT, 0o600)
            try:
                while True:
                    try:
                        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                        break
                    except OSError:
                        if time.monotonic() >= deadline:
                            raise TimeoutError("the code state is busy") from None
                        time.sleep(0.05)
                try:
                    yield
                finally:
                    os.lseek(fd, 0, 0)
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            finally:
                os.close(fd)
            return
        import fcntl
        fd = os.open(self.folder, os.O_RDONLY)
        try:
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise TimeoutError("the code state is busy") from None
                    time.sleep(0.05)
            yield
        finally:
            os.close(fd)

    def _locked_state(self) -> dict:
        """Under the lock: the state, with a tampered one saved as locked right away."""
        state = self._load()
        if state.pop("tampered", False):
            self._save(state)            # the lock is on disk too, so a restart keeps it
        return state

    # ----- what the gate asks -----
    def refusal(self) -> Optional[str]:
        """None when codes can be checked; else the device's refusal text (no box is shown). Never raises."""
        try:
            why = self.store.refusal()
        except Exception:  # noqa: BLE001 - a store that cannot answer counts as not set up
            return NO_AUTHENTICATOR_TEXT
        return why if why is None or why in STORE_REFUSALS else NO_AUTHENTICATOR_TEXT

    def configured(self) -> bool:
        return self.refusal() is None

    def entry_name(self) -> str:
        try:
            name = str(self.store.entry_name() or "")
        except Exception:  # noqa: BLE001
            return ""
        return name if _ENTRY.fullmatch(name) else ""

    def blocked(self) -> Optional[tuple[str, float]]:
        """(PAUSED, seconds left), (LOCKED, 0) or (UNAVAILABLE, 0) when code entry is held now, else None. Reads no
        seed (only the key that seals the state)."""
        try:
            with self._exclusive():
                state = self._locked_state()
        except Exception:  # noqa: BLE001 - the lock, the file, a store without its seed: refused
            return (UNAVAILABLE, 0.0)
        if state["locked"]:
            return (LOCKED, 0.0)
        left = state["paused_until"] - self._wall()
        return (PAUSED, left) if left > 0 else None

    def check(self, code: str) -> str:
        """One submitted code (already normalized to 6 digits). Returns ACCEPTED (the step is recorded as used
        before this returns), USED (a right code for a step already used: not a guess), WRONG (counted), PAUSED or
        LOCKED (code entry is held, possibly by this very failure), or UNAVAILABLE (the seed or the state could not
        be read or written: refused, not counted). Never raises; never logs the code or the seed."""
        if normalize(code) != code:
            return WRONG
        try:
            with self._exclusive():
                state = self._locked_state()
                if state["locked"]:
                    return LOCKED
                if state["paused_until"] > self._wall():
                    return PAUSED
                found = self._found(code)
                if found is None:
                    return UNAVAILABLE
                last = max(state["last_step"], self._floor)
                fresh = [step for step in found if step > last]
                if fresh:
                    state.update(last_step=max(fresh), wrong=0, paused_until=0.0)
                    self._save(state)                       # recorded before anything is granted
                    self._floor = max(self._floor, state["last_step"])
                    self._accepted_max = max(self._accepted_max, max(fresh))
                    return ACCEPTED
                if found:
                    # A right code for a step never used, refused only because this Hermes started in that minute
                    # (the restart floor, D68): the person is told to wait for the next code, not that it was used.
                    if (self._start_floor >= 0 and all(step <= self._start_floor for step in found)
                            and max(found) > self._accepted_max):
                        return JUST_STARTED
                    return USED
                state["wrong"] += 1
                verdict = WRONG
                if state["wrong"] >= LOCK_AFTER:
                    state["locked"], verdict = True, LOCKED
                elif state["wrong"] % PAUSE_EVERY == 0:
                    rounds = state["wrong"] // PAUSE_EVERY
                    state["paused_until"] = self._wall() + PAUSE_BASE_S * 2 ** (rounds - 1)
                    verdict = PAUSED
                self._save(state)
                return verdict
        except Exception:  # noqa: BLE001 - the lock, the file, the seed: refused, and nothing about the code is said
            logger.warning("tether: the approval code could not be checked (code state unavailable)")
            return UNAVAILABLE

    def _found(self, code: str) -> Optional[list[int]]:
        """The candidate steps the code matches, or None when the seed (or the store's own check) is unavailable."""
        now = self._clock()
        match = getattr(self.store, "matching_steps", None)
        try:
            if callable(match):                         # the comparison happens where the seed lives
                candidates = _candidates(now)
                return sorted({int(s) for s in match(code, list(candidates)) if s in candidates})
            seed = self.store.get_seed()
        except Exception:  # noqa: BLE001 - SeedUnavailable or the store's own error: refused
            return None
        if not isinstance(seed, (bytes, bytearray)) or len(seed) < MIN_SEED_BYTES:
            return None
        try:
            return matches(seed, code, now)
        finally:
            del seed

    def clear_lock(self) -> None:
        """End a pause or lock (a tampered state file's too) and reset the wrong-code count. ONLY for the owner's
        unlock at the computer, after it has authenticated the owner itself (enroll.py: one of the recovery codes);
        nothing reachable from the link calls it. The newest used step is kept (for a
        tampered file: the current minute is used up)."""
        with self._exclusive():
            state = self._load()
            state.update(wrong=0, paused_until=0.0, locked=False)
            self._save(state)

    def start(self, used_step: int, then: Optional[Callable[[], Any]] = None) -> Any:
        """A new seed was just set up (seedstore.SeedStore.commit): its state starts with the step of the code that
        confirmed it already used, so that code can never open a session. ``then`` (the record file's write) runs
        inside the same state lock, and when it fails the state file is put back as it was, so no running Hermes
        ever reads a state for a seed the record does not hold (R2-2: that read locked code entry). Returns what
        ``then`` returned."""
        with self._exclusive():
            before: Optional[bytes] = None
            if self.path is not None:
                try:
                    before = _read_own(self.path)
                except OSError:
                    before = None                  # not a plain file: nothing worth putting back
            self._save({**_fresh(used_step), "gen": 0})
            self._floor = max(self._floor, int(used_step))
            if then is None:
                return None
            try:
                return then()
            except BaseException:
                self._restore(before)
                raise

    def _restore(self, before: Optional[bytes]) -> None:
        """The state file as it was before start() (None: it did not exist). Best effort; a failure here is logged and
        leaves the locked state the running Hermes would then report."""
        if self.path is None:
            return
        try:
            if before is None:
                self.path.unlink(missing_ok=True)
                return
            fd, tmp = tempfile.mkstemp(dir=self.folder, prefix=f".{STATE_FILE}.", suffix=".tmp")
            try:
                with os.fdopen(fd, "wb") as fh:
                    fh.write(before)
                    fh.flush()
                    os.fsync(fh.fileno())
                os.replace(tmp, self.path)
            except BaseException:
                with contextlib.suppress(OSError):
                    os.unlink(tmp)
                raise
        except OSError:
            logger.warning("tether: the authenticator's earlier code state could not be put back", exc_info=True)
