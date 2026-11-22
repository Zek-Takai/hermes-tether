"""The device's authenticator seed (D66): a sealed file in Tether's data folder, opened by the running Hermes without
any prompt and held in memory; codes are checked from memory against the sealed state (D68).

Threat numbers refer to the 2FA design brief: 1 outsiders, 2 input on the device, 3 the seed, 4 setup/recovery,
5 replay and guessing, 7 leaks, 8 people. No test prints a seed, a passphrase or a code: every check is
assertTrue/assertFalse/assertNotIn with a fixed message. The seal's passphrase is a random test value.
"""
from __future__ import annotations

import base64
import io
import json
import logging
import os
import pickle
import secrets
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "plugin" / "tether"))

from tether import authcode, frames, identity, seedstore as ss  # noqa: E402
from tether.authcode import CodeChecker  # noqa: E402
from tether.consent import ConsentGate  # noqa: E402
from tether.link import RemoteError  # noqa: E402

T0 = 1_800_000_000.0          # a fixed wall time for the unit tests (step boundaries are known)
CODES = ["ABCDEFGHJKMNPQRS", "0123456789ABCDEF"]     # recovery codes for the tests (cleaned form)
PASS = secrets.token_bytes(32)                       # the test's stand-in for Tether's key passphrase


def remove_tree(path: Path) -> None:
    import shutil
    shutil.rmtree(path, ignore_errors=True)


def seal(passphrase: bytes = PASS) -> ss.PassphraseSeal:
    return ss.PassphraseSeal(lambda: passphrase)


def record(folder: Path) -> dict:
    return json.loads((folder / ss.REF_FILE).read_text())


def seed_of(folder: Path, passphrase: bytes = PASS) -> bytes:
    """The seed a record file holds (tests only; never printed)."""
    ref = record(folder)
    raw = seal(passphrase).open(base64.b64decode(ref["sealed"]), ref["account"])
    return bytes(ss._unb32(json.loads(raw.decode())["seed"]))


def code_at(seed: bytes, at: float) -> str:
    return authcode.hotp(seed, authcode.step_at(at))


def forms(seed: bytes) -> list[bytes]:
    text = ss._b32(seed)
    grouped = " ".join(text[i:i + 4] for i in range(0, len(text), 4))
    return [s.encode() for s in (text, text.lower(), grouped, seed.hex())] + [seed]


def not_code(right: str) -> str:
    return "000000" if right != "000000" else "111111"


class Made:
    """A data folder with an authenticator set up, as `hermes tether authenticator setup` leaves it (the confirming
    code's step, T0's, already used)."""

    def __init__(self, test: unittest.TestCase, at: float = T0, codes: list[str] = ()) -> None:
        self.dir = Path(tempfile.mkdtemp(prefix="tt-seed-"))
        test.addCleanup(remove_tree, self.dir)
        setup = ss.SeedStore(self.dir, seal(), clock=lambda: at)
        pending = setup.begin_setup()
        step = pending.check(authcode.hotp(bytes(pending._live()), authcode.step_at(at)), at)
        test.assertTrue(step == authcode.step_at(at), "the new seed's own code must match")
        setup.commit(pending, ss.hash_recovery_codes(list(codes)), step, entry="Hermes Tether")
        self.seed = seed_of(self.dir)

    def store(self, now: list[float] | None = None, passphrase: bytes = PASS) -> ss.SeedStore:
        clock = (lambda: now[0]) if now is not None else (lambda: T0)
        return ss.SeedStore(self.dir, seal(passphrase), clock=clock)

    def checker(self, store: ss.SeedStore, now: list[float]) -> CodeChecker:
        return CodeChecker(store, self.dir, clock=lambda: now[0], wall=lambda: now[0])


class StorageTests(unittest.TestCase):
    def test_the_record_is_a_private_sealed_file_in_the_data_folder(self):
        """Threat 3 (owner's ruling G1): the seed and the recovery fingerprints are one 0600 file next to
        identity.key.enc, sealed (AES-256-GCM) with Tether's key passphrase; the state file is 0600 too."""
        made = Made(self, codes=CODES)
        for name in (ss.REF_FILE, authcode.STATE_FILE):
            mode = stat.S_IMODE(os.lstat(made.dir / name).st_mode)
            self.assertTrue(mode == 0o600, f"{name} must be private (0600)")
        raw = (made.dir / ss.REF_FILE).read_bytes()
        self.assertFalse(any(f in raw for f in forms(made.seed)), "the record file holds the seed readably")
        self.assertFalse(any(c.encode() in raw.upper() for c in CODES), "a recovery code is readable in the file")
        self.assertTrue(set(record(made.dir)) == {"v", "seal", "account", "dir", "made", "entry", "sealed"},
                        "the record file has exactly its fields")
        self.assertFalse([p.name for p in made.dir.iterdir() if p.name.endswith(".tmp")], "a temporary file was left")

    def test_a_failed_replacement_keeps_code_entry_working(self):
        """R2-2: when the new record cannot be written, the code state is put back as it was; the old
        authenticator's codes still work and code entry is not locked."""
        made = Made(self)
        state = made.dir / authcode.STATE_FILE
        before = state.read_bytes()
        store = made.store()
        pending = store.begin_setup()
        step = pending.check(authcode.hotp(bytes(pending._live()), authcode.step_at(T0 + 60)), T0 + 60)
        with mock.patch.object(ss, "_write_own", side_effect=OSError("disk full")):
            with self.assertRaises(ss.SeedStoreError):
                store.commit(pending, ss.hash_recovery_codes([]), step)
        self.assertEqual(state.read_bytes(), before, "the code state was left for the seed that was not saved")
        now = [T0 + 120]
        fresh = made.store(now)
        verdict = made.checker(fresh, now).check(authcode.hotp(made.seed, authcode.step_at(now[0])))
        self.assertEqual(verdict, authcode.ACCEPTED)

    def test_the_running_hermes_opens_it_without_any_prompt_and_holds_it(self):
        """Threats 3 and 8: a new store opens the record at once (no keychain, no password box, no process) and checks
        every code from memory, never reading the file again for a code."""
        made = Made(self)
        reads = []
        real = ss._read_own

        def counting(path):
            reads.append(Path(path).name)
            return real(path)

        def boom(*a, **k):
            raise AssertionError("the seed store started a process or showed a box")
        with mock.patch.object(ss, "_read_own", counting), mock.patch("subprocess.Popen", boom), \
                mock.patch("asyncio.create_subprocess_exec", boom):
            store = made.store()
            self.assertTrue(store.status() == ss.READY and store.refusal() is None, "opened at once, no prompt")
            opened = reads.count(ss.REF_FILE)
            now = [T0 + 60]
            codes = made.checker(store, now)
            self.assertTrue(codes.check(code_at(made.seed, now[0])) == authcode.ACCEPTED, "a right code is accepted")
            now[0] += 30
            codes.check(not_code(code_at(made.seed, now[0])))
        self.assertTrue(reads.count(ss.REF_FILE) == opened, "checking codes must not read the record again")

    def test_no_keychain_password_box_or_admin_dialog_in_the_store(self):
        """Owner's rulings G1, G2: nothing in the store or the setup asks for a system password or uses the keychain."""
        root = Path(ss.__file__).parent
        for name in ("seedstore.py", "enroll.py", "authcode.py"):
            src = (root / name).read_text()
            for word in ("/usr/bin/security", "Security.framework", "SecItem", "SecKeychain", "with administrator",
                         "-Verb RunAs", "Always Allow"):
                self.assertNotIn(word, src, f"{name} still uses {word}")

    def test_another_passphrase_or_another_name_opens_nothing(self):
        """Threat 3: the record opens only with this machine's key passphrase and only under its own id; a copied
        file (a backup without Hermes's secrets) or a record moved under another id reads as damaged."""
        made = Made(self)
        store = made.store(passphrase=secrets.token_bytes(32))
        self.assertTrue(store.status() == ss.MISSING and not store.holds_key(), "a wrong passphrase opened the record")
        self.assertTrue(store.refusal() == authcode.SET_UP_AGAIN_TEXT, "the device refuses with the reset text")
        ref = record(made.dir)
        ref["account"] = "tether-" + "0" * 32
        (made.dir / ss.REF_FILE).write_text(json.dumps(ref))
        self.assertTrue(made.store().status() == ss.MISSING, "a record under another id was opened")

    def test_no_seal_means_no_setup_and_no_file(self):
        """Threat 3: where there is no supported seal (Linux) setup refuses; nothing is written in clear."""
        d = Path(tempfile.mkdtemp(prefix="tt-seed-"))
        self.addCleanup(remove_tree, d)
        store = ss.SeedStore(d, ss.NoStore())
        self.assertTrue(store.status() == ss.UNAVAILABLE, "no seal must read as unavailable")
        with self.assertRaises(ss.StoreUnavailable):
            store.begin_setup()
        self.assertTrue(store.refusal() == authcode.NO_SAFE_STORE_TEXT, "the device must refuse")
        self.assertFalse(list(d.iterdir()), "nothing may be written without a seal")

    def test_a_passphrase_that_cannot_be_read_saves_nothing(self):
        """Threat 3: a setup whose seal cannot get Tether's key passphrase saves no record and no state."""
        d = Path(tempfile.mkdtemp(prefix="tt-seed-"))
        self.addCleanup(remove_tree, d)

        def missing() -> bytes:
            raise ss.StoreUnavailable("Tether's key passphrase could not be read")
        store = ss.SeedStore(d, ss.PassphraseSeal(missing), clock=lambda: T0)
        pending = store.begin_setup()
        with self.assertRaises(ss.SeedStoreError):
            store.commit(pending, ss.hash_recovery_codes([]), authcode.step_at(T0))
        self.assertFalse([p.name for p in d.iterdir()], "no record and no state for a seal that failed")

    def test_the_confirming_code_is_used_up_by_the_setup(self):
        """Threats 4, 5: the code that confirmed the new key at setup can never open a session afterwards."""
        made = Made(self)
        store = made.store()
        self.assertTrue(made.checker(store, [T0 + 5]).check(code_at(made.seed, T0)) == authcode.USED,
                        "the setup's confirming code worked again")

    def test_seed_never_in_any_file(self):
        """Threats 3 and 7: after setup, opening, right, wrong and reused codes, a recovery code and a removal, no
        file in the data folder or the temp folder holds the seed in any form."""
        made = Made(self, codes=CODES)
        store = made.store()
        now = [T0 + 60]
        codes = made.checker(store, now)
        good = code_at(made.seed, now[0])
        codes.check(good)
        codes.check(good)
        codes.check(not_code(good))
        store.use_recovery_code(CODES[0])
        seen = []
        for root in (made.dir, Path(tempfile.gettempdir())):
            for path in root.rglob("*"):
                if path.is_file() and not path.is_symlink():
                    try:
                        data = path.read_bytes()
                    except OSError:
                        continue
                    seen.append(any(f in data for f in forms(made.seed)))
        self.assertFalse(any(seen), "the seed must not be in any file")
        store.remove()
        self.assertFalse([p for p in made.dir.iterdir() if p.name in (ss.REF_FILE, authcode.STATE_FILE)],
                         "remove must take Tether's own authenticator files")

    def test_seed_and_codes_never_logged(self):
        """Threat 7: every path, the failing ones included, logs no seed and no code (root logger at DEBUG)."""
        buf = io.StringIO()
        handler = logging.StreamHandler(buf)
        root = logging.getLogger()
        old = root.level
        root.addHandler(handler)
        root.setLevel(logging.DEBUG)
        self.addCleanup(root.removeHandler, handler)
        self.addCleanup(root.setLevel, old)
        made = Made(self)
        store = made.store()
        now = [T0 + 60]
        codes = made.checker(store, now)
        good = code_at(made.seed, now[0])
        codes.check(good)
        codes.check(good)
        (made.dir / authcode.STATE_FILE).write_text("{}")      # forged state: logged as changed, no value
        codes.check("123456")
        made.store(passphrase=secrets.token_bytes(32))         # a record that does not open: logged, no value
        events = (made.dir / "events.jsonl").read_text() if (made.dir / "events.jsonl").exists() else ""
        text = buf.getvalue() + events
        self.assertFalse(any(f.decode(errors="replace") in text for f in forms(made.seed)[:4]), "seed in a log")
        self.assertNotIn(good, text, "a code was logged")
        self.assertNotIn(base64.urlsafe_b64encode(PASS).decode(), text, "the passphrase was logged")

    def test_errors_carry_no_secret(self):
        """Threat 7: damaged records raise fixed sentences with no chained exception (which could carry the document
        it failed on)."""
        made = Made(self)
        with self.assertRaises(ss.SeedStoreError) as caught:
            ss.SeedStore._parse(b'{"v": 1, "seed": "' + forms(made.seed)[0] + b'!", "recovery": {}}')
        err = caught.exception
        self.assertFalse(any(f.decode(errors="replace") in str(err) + repr(err) for f in forms(made.seed)[:4]),
                         "an error text holds the seed")
        self.assertTrue(err.__cause__ is None and err.__suppress_context__, "an error chains its cause")
        ref = record(made.dir)
        with self.assertRaises(ss.SeedStoreError) as caught:
            seal(secrets.token_bytes(32)).open(base64.b64decode(ref["sealed"]), ref["account"])
        self.assertTrue(caught.exception.__cause__ is None, "a seal error chains its cause")
        (made.dir / ss.REF_FILE).write_text("{not json")
        with self.assertRaises(ss.SeedStoreError) as caught:
            made.store()._read_ref()
        self.assertTrue(caught.exception.__cause__ is None, "a record error chains its cause")

    def test_store_and_setup_objects_show_nothing(self):
        """Threats 4 and 7: repr, str and pickling show no seed; the setup key is shown only until setup finishes."""
        made = Made(self)
        store = made.store()
        text = repr(store) + str(store)
        self.assertFalse(any(f.decode(errors="replace") in text for f in forms(made.seed)[:4]), "repr shows the seed")
        with self.assertRaises(TypeError):
            pickle.dumps(store)
        pending = store.begin_setup()
        self.assertNotIn(ss._b32(pending._live()), repr(pending) + str(pending), "repr shows the new seed")
        with self.assertRaises(TypeError):
            pickle.dumps(pending)
        pending.key_text()
        store.commit(pending, ss.hash_recovery_codes([]), authcode.step_at(T0) + 1)
        with self.assertRaises(ss.SeedStoreError):
            pending.key_text()

    def test_store_never_starts_a_process(self):
        """Threat 7: no seed or code can reach a child's argv, environment or pipe: the store starts none."""
        def boom(*a, **k):
            raise AssertionError("the seed store started a process")
        with mock.patch("subprocess.Popen", boom), mock.patch("os.system", boom), \
                mock.patch("asyncio.create_subprocess_exec", boom), mock.patch("os.posix_spawn", boom, create=True):
            made = Made(self, codes=CODES)
            store = made.store()
            made.checker(store, [T0 + 60]).check(code_at(made.seed, T0 + 60))
            store.use_recovery_code(CODES[1])
            store.remove()

    def test_device_output_masks_the_seed(self):
        """Threat 7: a seed this device holds is replaced by the mask in command and tool output it sends back."""
        made = Made(self)
        made.store()
        text = ss._b32(made.seed)
        out = identity.mask_secrets(f"key={text} lower={text.lower()}")
        self.assertNotIn(text, out, "the seed was sent back unmasked")
        self.assertNotIn(text.lower(), out, "the seed was sent back unmasked")

    def test_record_copied_from_another_profile_is_neither_used_nor_replaced(self):
        """Threat 3 and D39: a profile clone carries the record file; it is never opened from the clone."""
        made = Made(self)
        other = Path(tempfile.mkdtemp(prefix="tt-seed-"))
        self.addCleanup(remove_tree, other)
        (other / ss.REF_FILE).write_bytes((made.dir / ss.REF_FILE).read_bytes())
        clone = ss.SeedStore(other, seal(), clock=lambda: T0)
        self.assertTrue(clone.status() == ss.MISSING, "a copied record must not open in another profile")
        clone.remove()
        self.assertTrue(made.store().status() == ss.READY, "the original profile's authenticator is untouched")

    def test_record_or_state_link_is_never_followed(self):
        """Threat 3: a link put in place of the record or the state file is not read through, and a write replaces
        the link itself, never its target."""
        made = Made(self)
        target = made.dir / "elsewhere.json"
        target.write_bytes((made.dir / ss.REF_FILE).read_bytes())
        (made.dir / ss.REF_FILE).unlink()
        os.symlink(target, made.dir / ss.REF_FILE)
        self.assertTrue(made.store().status() == ss.MISSING, "a linked record must not be followed")
        os.unlink(made.dir / ss.REF_FILE)
        os.rename(target, made.dir / ss.REF_FILE)
        victim = made.dir / "victim.txt"
        victim.write_text("person's file")
        (made.dir / authcode.STATE_FILE).unlink()
        os.symlink(victim, made.dir / authcode.STATE_FILE)
        store = made.store()
        verdict = made.checker(store, [T0 + 90]).check(code_at(made.seed, T0 + 90))
        self.assertTrue(verdict == authcode.LOCKED, "a linked state file is not believed: code entry locks")
        self.assertTrue(victim.read_text() == "person's file", "a state write must not go through a link")
        self.assertFalse((made.dir / authcode.STATE_FILE).is_symlink(), "the link itself is replaced")
        os.symlink(victim, made.dir / "link-target-check")
        store.use_recovery_code("NOTACODE00000000")
        self.assertTrue(victim.read_text() == "person's file", "a record write must not go through a link")

    def test_recovery_codes_are_single_use_and_stored_hashed(self):
        """Threat 4: a recovery code works once, also for another process; only salted fingerprints are kept."""
        made = Made(self, codes=CODES)
        store = made.store()
        ref = record(made.dir)
        inner = seal().open(base64.b64decode(ref["sealed"]), ref["account"])
        self.assertNotIn(CODES[0].encode(), inner.upper(), "a recovery code is stored in clear inside the seal")
        self.assertTrue(store.use_recovery_code(CODES[0]), "a stored recovery code must work")
        self.assertFalse(store.use_recovery_code(CODES[0]), "a recovery code must work only once")
        self.assertTrue(store.recovery_left() == 1, "one recovery code left")
        self.assertFalse(made.store().use_recovery_code(CODES[0]), "a used recovery code stays used after a restart")

    def test_a_recovery_code_that_cannot_be_struck_out_is_not_accepted(self):
        """Threat 4: when the record cannot be rewritten, the code is not accepted (it could work again)."""
        made = Made(self, codes=CODES)
        store = made.store()

        def refuse(path, data):
            raise OSError("read-only")
        with mock.patch.object(ss, "_write_own", refuse):
            self.assertFalse(store.use_recovery_code(CODES[0]), "a recovery code worked without being used up")
        self.assertTrue(store.recovery_left() == 2, "nothing was used up")

    def test_a_crash_while_writing_leaves_the_old_record_whole(self):
        """Threat 3: the record is replaced by a flushed temporary file renamed into place; a failure at the rename
        leaves the old record working and no temporary file."""
        made = Made(self, codes=CODES)
        store = made.store()
        before = (made.dir / ss.REF_FILE).read_bytes()
        with mock.patch.object(ss.os, "replace", side_effect=OSError("disk full")):
            self.assertFalse(store.use_recovery_code(CODES[0]), "a code was accepted though nothing was written")
        self.assertTrue((made.dir / ss.REF_FILE).read_bytes() == before, "the old record must stay whole")
        self.assertFalse([p.name for p in made.dir.iterdir() if p.name.endswith(".tmp")], "a temporary file was left")
        self.assertTrue(made.store().status() == ss.READY, "the old record still opens")

    def test_refresh_reads_again_only_on_a_change(self):
        """Threats 3 and 8: the running Hermes opens the record at start and again after another process changed it
        (new recovery codes, a new setup, a removal); not on every poll and not when the file is only touched."""
        made = Made(self, codes=CODES)
        gateway = made.store()
        reads = []
        real = ss._read_own

        def counting(path):
            if Path(path).name == ss.REF_FILE:
                reads.append(1)
            return real(path)
        with mock.patch.object(ss, "_read_own", counting):
            gateway.refresh()
            polls = len(reads)
            os.utime(made.dir / ss.REF_FILE, (time.time() + 5, time.time() + 5))     # touched, not changed
            gateway.refresh()
            self.assertTrue(gateway.status() == ss.READY, "a touched record stays open")
            cli = made.store()
            cli.use_recovery_code(CODES[0])                                 # another process changed the record
            gateway.refresh()
        self.assertTrue(len(reads) > polls * 2, "a changed record must be read again")
        self.assertTrue(gateway.recovery_left() == 1, "the running Hermes sees the code used elsewhere")
        made.store().remove()
        gateway.refresh()
        self.assertTrue(gateway.status() == ss.NONE and not gateway.holds_key(), "a removal elsewhere is followed")

    def test_the_seed_comes_from_memory_and_only_once_set_up(self):
        """Threats 3 and 8: the code check gets the seed from this process's memory; nothing before a setup."""
        d = Path(tempfile.mkdtemp(prefix="tt-seed-"))
        self.addCleanup(remove_tree, d)
        empty = ss.SeedStore(d, seal())
        with self.assertRaises(authcode.SeedUnavailable):
            empty.get_seed()
        with self.assertRaises(authcode.SeedUnavailable):
            empty.seal_key()
        made = Made(self)
        store = made.store()
        for _ in range(3):
            self.assertTrue(len(store.get_seed()) == ss.SEED_BYTES, "the held seed")
        self.assertTrue(store.entry_name() == "Hermes Tether", "the entry name the box shows")

    def test_default_seal_per_system(self):
        """G1: macOS seals with Tether's key passphrase; Windows keeps DPAPI (user scope, no prompt); else none."""
        with mock.patch.object(ss.sys, "platform", "darwin"):
            self.assertTrue(isinstance(ss.default_backend(Path("."), lambda: PASS), ss.PassphraseSeal), "macOS seal")
        with mock.patch.object(ss.sys, "platform", "linux"), mock.patch.object(ss.os, "name", "posix"):
            self.assertTrue(isinstance(ss.default_backend(Path(".")), ss.NoStore), "Linux has no seal")
        self.assertTrue(ss.WindowsDpapi.UI_FORBIDDEN == 0x1, "DPAPI must never prompt")


class GateTests(unittest.IsolatedAsyncioTestCase):
    async def test_a_store_that_cannot_check_codes_refuses_before_any_box(self):
        """Threat 8: no authenticator, a damaged one or no seal refuses with its own text, shows no box and costs no
        cool-down or box budget."""
        cases = {}
        d = Path(tempfile.mkdtemp(prefix="tt-seed-"))
        self.addCleanup(remove_tree, d)
        cases[authcode.NO_AUTHENTICATOR_TEXT] = ss.SeedStore(d, seal())
        made = Made(self)
        cases[authcode.SET_UP_AGAIN_TEXT] = made.store(passphrase=secrets.token_bytes(32))
        cases[authcode.NO_SAFE_STORE_TEXT] = ss.SeedStore(d, ss.NoStore())
        for text, store in cases.items():
            asked = []

            async def box(t, timeout_s):
                asked.append(t)
                return "123456"
            gate = ConsentGate(idle_minutes=15, timeout_s=60, prompt=box, codes=CodeChecker(store, store.dir))
            for _ in range(12):                                     # more than the box budget
                with self.assertRaises(PermissionError) as caught:
                    await gate.require("fp", "Test host", "s1")
                self.assertTrue(str(caught.exception) == text, "the store's own refusal text")
            self.assertFalse(asked, "no box may be shown when no code can be checked")
            self.assertFalse(gate._denied_until, "no cool-down for a refusal before any box")


class LoopbackCodeTests(unittest.IsolatedAsyncioTestCase):
    def _rig(self, store: ss.SeedStore, box, clock=time.time):
        from test_link_loopback import Rig
        rig = Rig()
        self.addCleanup(rig.close)
        gate = ConsentGate(idle_minutes=15, timeout_s=60, prompt=box,
                           codes=CodeChecker(store, store.dir, clock=clock, wall=clock))
        rig.consent = rig.device.consent = gate
        return rig

    async def test_code_and_seed_never_reach_the_host(self):
        """Threats 1 and 7: a right code opens the session, and neither the code nor the seed is in any frame either
        side sent or read; the host gets only the grant."""
        made = Made(self, at=time.time() - 120)
        store = made.store()
        typed = []

        async def box(text, timeout_s):
            code = code_at(made.seed, time.time())
            typed.append(code)
            return code
        rig = self._rig(store, box)
        seen = []
        real_read, real_write = frames.read_frame, frames.write_frame

        async def read(reader):
            header, body = await real_read(reader)
            seen.append((json.dumps(header), body))
            return header, body

        async def write(writer, header, body=b"", *rest):
            seen.append((json.dumps(header), body))
            return await real_write(writer, header, body, *rest)
        with mock.patch.object(frames, "read_frame", read), mock.patch.object(frames, "write_frame", write):
            await rig.pair()
            await rig.connect()
            data, _ = await rig.host.call("mac", "exec", {"command": "echo hi", "session": "s1"})
        rig.device._task.cancel()
        self.assertTrue(data.get("grant"), "a right code must open the session")
        leaked = any(any(c in header for c in typed) or any(f in body or f in header.encode()
                                                             for f in forms(made.seed)[:4]) for header, body in seen)
        self.assertFalse(leaked, "a code or the seed travelled over the link")

    async def test_wrong_code_gives_no_grant(self):
        """Threats 1 and 5: a wrong code is a deny; the host gets no grant and the wrong code is counted (sealed)."""
        made = Made(self, at=time.time() - 120)
        store = made.store()

        async def box(text, timeout_s):
            return not_code(code_at(made.seed, time.time()))
        rig = self._rig(store, box)
        await rig.pair()
        await rig.connect()
        with self.assertRaises(RemoteError) as caught:
            await rig.host.call("mac", "exec", {"command": "echo hi", "session": "s1"})
        rig.device._task.cancel()
        self.assertIn("did not allow remote use", str(caught.exception), "a wrong code must be a deny")
        self.assertTrue((authcode.peek_state(made.dir) or {}).get("wrong") == authcode.MAX_TRIES_PER_BOX,
                        "each wrong code in the box is counted")

    async def test_a_damaged_record_refuses_without_a_box(self):
        """Threat 8: a record that does not open (damaged, sealed with another key) refuses every opening with a fixed
        text and shows no box."""
        made = Made(self)
        store = made.store(passphrase=secrets.token_bytes(32))
        asked = []

        async def box(text, timeout_s):
            asked.append(text)
            return "123456"
        rig = self._rig(store, box)
        await rig.pair()
        await rig.connect()
        with self.assertRaises(RemoteError) as caught:
            await rig.host.call("mac", "exec", {"command": "echo hi", "session": "s1"})
        rig.device._task.cancel()
        self.assertTrue(str(caught.exception) == authcode.SET_UP_AGAIN_TEXT, "the set-up-again text")
        self.assertFalse(asked, "no box for a record that does not open")


if __name__ == "__main__":
    unittest.main()
