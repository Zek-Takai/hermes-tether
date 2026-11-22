"""Tether's 2FA secret follows Hermes's own key storage (D78): the OS keychain when Hermes keeps its vault key
there, Tether's key passphrase otherwise.

The real keychain is never touched: Hermes's own ``os_keyring()`` and ``configured_key_storage()`` are replaced
with fakes (a dict-backed keyring backend with get_password/set_password/delete_password). No test prints a seed,
a key or a code: every check is assertTrue/assertFalse with a fixed message, and the flow is checked to print
nothing at all.
"""
from __future__ import annotations

import base64
import contextlib
import io
import json
import logging
import secrets
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "plugin" / "tether"))

from tether import authcode, seedstore as ss  # noqa: E402

T0 = 1_800_000_000.0          # a fixed wall time for the unit tests (step boundaries are known)
PASS = secrets.token_bytes(32)                       # the test's stand-in for Tether's key passphrase


class FakeKeyring:
    """A dict-backed keyring backend, like the one Hermes's own vault uses (get, set, delete)."""

    def __init__(self, refuse: bool = False) -> None:
        self.items: dict[tuple[str, str], str] = {}
        self.name = "Fake OS keychain"
        self.refuse = refuse              # a keychain that answers but takes nothing (a write that fails)

    def get_password(self, service, account):
        return self.items.get((service, account))

    def set_password(self, service, account, password):
        if self.refuse:
            raise RuntimeError("the keychain refused the write")
        self.items[(service, account)] = password

    def delete_password(self, service, account):
        if (service, account) not in self.items:
            raise KeyError("no such entry")         # the real backend raises PasswordDeleteError
        del self.items[(service, account)]

    def accounts(self) -> list[str]:
        return sorted(account for (service, account) in self.items if service == ss.KEYCHAIN_SERVICE)


class NoKeyring:
    """A keychain that is not there at all (Hermes's own os_keyring() raises)."""

    @staticmethod
    def os_keyring():
        raise RuntimeError("no OS keychain is reachable from this session")


def keychain_mode(storage: str = "keychain", refuse: bool = False):
    """Hermes's own setting and keychain, as fakes: nothing outside this test is touched."""
    fake = FakeKeyring(refuse=refuse)
    patches = mock.patch.multiple(ss, os_keyring=lambda: fake,
                                   configured_key_storage=lambda: storage)
    return patches, fake


def record(folder: Path) -> dict:
    return json.loads((folder / ss.REF_FILE).read_text())


def forms(seed: bytes) -> list[bytes]:
    text = ss._b32(seed)
    grouped = " ".join(text[i:i + 4] for i in range(0, len(text), 4))
    return [s.encode() for s in (text, text.lower(), grouped, seed.hex())] + [seed]


class KeychainModeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp(prefix="tt-keychain-"))
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.addCleanup(ss._WARNED.clear)

    # -- helpers --
    def set_up(self, seal, codes=()) -> ss.SeedStore:
        """An authenticator set up in this folder, as `hermes tether authenticator setup` leaves it."""
        store = ss.SeedStore(self.dir, seal, clock=lambda: T0)
        pending = store.begin_setup()
        step = pending.check(authcode.hotp(bytes(pending._live()), authcode.step_at(T0)), T0)
        store.commit(pending, ss.hash_recovery_codes(list(codes)), step, entry="Hermes Tether")
        return store

    def test_the_file_mode_seals_with_tethers_key_passphrase(self):
        """Hermes keeps its vault key in a file (its default): Tether's 2FA secret is sealed the same way, and
        nothing is put in a keychain."""
        patches, fake = keychain_mode(storage="file")
        with patches, mock.patch.object(ss.sys, "platform", "darwin"):
            backend = ss.default_backend(Path("."))
            self.assertTrue(isinstance(backend, ss.PassphraseSeal), "the file mode uses the passphrase seal")
            store = ss.SeedStore(self.dir, secret=lambda: PASS, clock=lambda: T0)
            self.assertTrue(isinstance(store.backend, ss.PassphraseSeal), "the store's seal is the passphrase one")
            pending = store.begin_setup()
            step = pending.check(authcode.hotp(bytes(pending._live()), authcode.step_at(T0)), T0)
            store.commit(pending, ss.hash_recovery_codes([]), step, entry="Hermes Tether")
        ref = record(self.dir)
        self.assertTrue(ref["seal"] == "passphrase", "the record says which seal wrote it")
        self.assertTrue(fake.accounts() == [], "the file mode writes nothing to a keychain")
        self.assertTrue("keychain" not in ref, "the record names no keychain entry")

    def test_the_keychain_mode_seals_with_the_keychains_own_key(self):
        """Hermes keeps its vault key in the OS keychain: Tether's 2FA secret goes there the same way (the same
        helpers, the same read-back check, a random account name in Tether's own record), and the passphrase alone
        opens nothing."""
        patches, fake = keychain_mode(storage="keychain")
        with patches, mock.patch.object(ss.sys, "platform", "darwin"):
            backend = ss.default_backend(Path("."))
            self.assertTrue(isinstance(backend, ss.HermesKeychainSeal), "the keychain mode uses the keychain seal")
            store = ss.SeedStore(self.dir, secret=lambda: PASS, clock=lambda: T0)
            self.assertTrue(isinstance(store.backend, ss.HermesKeychainSeal), "the store's seal is the keychain one")
            pending = store.begin_setup()
            step = pending.check(authcode.hotp(bytes(pending._live()), authcode.step_at(T0)), T0)
            store.commit(pending, ss.hash_recovery_codes([]), step, entry="Hermes Tether")
        seed = bytes(store.get_seed())
        ref = record(self.dir)
        self.assertTrue(ref["seal"] == "hermes-keychain", "the record says which seal wrote it")
        self.assertTrue(len(fake.accounts()) == 1, "the keychain holds Tether's own key")
        self.assertTrue(ref["keychain"]["account"] == fake.accounts()[0], "the record names the entry")
        self.assertTrue(ref["keychain"]["service"] == ss.KEYCHAIN_SERVICE, "the entry is in Tether's own service")
        blob = base64.b64decode(ref["sealed"])
        with self.assertRaises(ss.SeedStoreError):
            ss.PassphraseSeal(lambda: PASS).open(blob, ref["account"])
        with patches:
            opened = ss.HermesKeychainSeal(ref["keychain"]["account"]).open(blob, ref["account"])
        inner = json.loads(opened.decode())
        self.assertTrue(bytes(ss._unb32(inner["seed"])) == seed, "the keychain seal opens the record")

    def test_the_recorded_seal_wins_over_a_changed_setting(self):
        """The record says which seal wrote it, and it is opened with that seal whatever the setting says later. A
        re-seal that fails leaves the old record whole."""
        patches, fake = keychain_mode(storage="keychain", refuse=True)
        with patches:
            store = self.set_up(ss.PassphraseSeal(lambda: PASS))
            seed = bytes(store.get_seed())
            before = (self.dir / ss.REF_FILE).read_bytes()
            moved = ss.SeedStore(self.dir, ss.HermesKeychainSeal(), secret=lambda: PASS, clock=lambda: T0)
        self.assertTrue(moved.status() == ss.READY, "the record opened with the seal it names")
        self.assertTrue(bytes(moved.get_seed()) == seed, "the seed is the one the record holds")
        self.assertTrue(fake.accounts() == [], "the keychain seal could not have opened it")
        self.assertTrue((self.dir / ss.REF_FILE).read_bytes() == before, "a failed re-seal leaves the record whole")

    def test_a_changed_setting_re_seals_the_record_under_the_keychain(self):
        """Hermes's setting changed to the keychain: the record, opened with the seal it names, is re-sealed under
        the keychain key, and the passphrase alone opens nothing any more. The seed does not change."""
        patches, fake = keychain_mode(storage="keychain")
        with patches:
            store = self.set_up(ss.PassphraseSeal(lambda: PASS))
            seed = bytes(store.get_seed())
            moved = ss.SeedStore(self.dir, ss.HermesKeychainSeal(), secret=lambda: PASS, clock=lambda: T0)
        self.assertTrue(moved.status() == ss.READY, "the record opened with the seal it names")
        self.assertTrue(bytes(moved.get_seed()) == seed, "the seed is the same after the re-seal")
        ref = record(self.dir)
        self.assertTrue(ref["seal"] == "hermes-keychain", "the record is sealed with the keychain now")
        self.assertTrue(len(fake.accounts()) == 1, "the keychain holds Tether's own key")
        self.assertTrue(ref["keychain"]["account"] == fake.accounts()[0], "the record names the entry")
        with self.assertRaises(ss.SeedStoreError):
            ss.PassphraseSeal(lambda: PASS).open(base64.b64decode(ref["sealed"]), ref["account"])
        with patches:
            opened = ss.HermesKeychainSeal(ref["keychain"]["account"]).open(base64.b64decode(ref["sealed"]),
                                                                            ref["account"])
        inner = json.loads(opened.decode())
        self.assertTrue(bytes(ss._unb32(inner["seed"])) == seed, "the keychain seal opens the record")

    def test_a_changed_setting_re_seals_the_record_under_the_passphrase(self):
        """Hermes's setting changed back to the file: the record, opened with the keychain seal it names, is
        re-sealed under Tether's key passphrase and Tether's keychain entry goes with it."""
        patches, fake = keychain_mode(storage="keychain")
        with patches:
            store = self.set_up(ss.HermesKeychainSeal())
            seed = bytes(store.get_seed())
            self.assertTrue(len(fake.accounts()) == 1, "the keychain holds Tether's own key")
            moved = ss.SeedStore(self.dir, ss.PassphraseSeal(lambda: PASS), secret=lambda: PASS, clock=lambda: T0)
        self.assertTrue(moved.status() == ss.READY, "the record opened with the seal it names")
        self.assertTrue(bytes(moved.get_seed()) == seed, "the seed is the same after the re-seal")
        ref = record(self.dir)
        self.assertTrue(ref["seal"] == "passphrase", "the record is sealed with the passphrase now")
        self.assertTrue("keychain" not in ref, "the record names no keychain entry")
        self.assertTrue(fake.accounts() == [], "Tether's keychain entry is gone")
        opened = ss.PassphraseSeal(lambda: PASS).open(base64.b64decode(ref["sealed"]), ref["account"])
        inner = json.loads(opened.decode())
        self.assertTrue(bytes(ss._unb32(inner["seed"])) == seed, "the passphrase seal opens the record")

    def test_a_keychain_that_does_not_answer_falls_back_with_one_warning(self):
        """Hermes's setting says the keychain, but no keychain answers: the passphrase seal is used instead and one
        warning line says so. Nothing is asked of the person."""
        buf = io.StringIO()
        handler = logging.StreamHandler(buf)
        root = logging.getLogger()
        old = root.level
        root.addHandler(handler)
        root.setLevel(logging.DEBUG)
        self.addCleanup(root.removeHandler, handler)
        self.addCleanup(root.setLevel, old)
        ss._WARNED.discard("keychain")
        with mock.patch.object(ss, "configured_key_storage", lambda: "keychain"), \
                mock.patch.object(ss, "os_keyring", NoKeyring.os_keyring), \
                mock.patch.object(ss.sys, "platform", "darwin"):
            backend = ss.default_backend(Path("."))
            store = ss.SeedStore(self.dir, secret=lambda: PASS, clock=lambda: T0)
        self.assertTrue(isinstance(backend, ss.PassphraseSeal), "the passphrase seal is the fallback")
        self.assertTrue(isinstance(store.backend, ss.PassphraseSeal), "the store falls back too")
        lines = [line for line in buf.getvalue().splitlines() if line.strip()]
        self.assertTrue(len(lines) == 1, "one warning line, no more")
        self.assertTrue("keychain" in lines[0], "the warning says why")

    def test_a_record_without_the_new_field_opens_as_a_passphrase_record(self):
        """A record from before the field existed says through its old "backend" that it is a passphrase record (and
        a record without either field is one too)."""
        patches, fake = keychain_mode(storage="file")
        with patches:
            self.set_up(ss.PassphraseSeal(lambda: PASS))
            ref = record(self.dir)
            ref.pop("seal")
            ref["backend"] = "sealed-file"                 # the field the record had before
            (self.dir / ss.REF_FILE).write_text(json.dumps(ref))
            again = ss.SeedStore(self.dir, ss.PassphraseSeal(lambda: PASS), clock=lambda: T0)
            self.assertTrue(again.status() == ss.READY, "an old record opens as a passphrase record")
            ref.pop("backend")
            (self.dir / ss.REF_FILE).write_text(json.dumps(ref))
            plain = ss.SeedStore(self.dir, ss.PassphraseSeal(lambda: PASS), clock=lambda: T0)
            self.assertTrue(plain.status() == ss.READY, "a record without either field opens as a passphrase one")

    def test_a_used_recovery_code_keeps_the_keychain_key(self):
        """Striking a recovery code out of a keychain-sealed record seals it again with the same key: the entry is
        never replaced, so a write that fails leaves the record openable and the seed safe."""
        code = "ABCDEFGHJKMNPQRS"
        patches, fake = keychain_mode(storage="keychain")
        with patches:
            store = self.set_up(ss.HermesKeychainSeal(), codes=[code])
            seed = bytes(store.get_seed())
            before = dict(fake.items)
            self.assertTrue(store.use_recovery_code(code), "the recovery code works")
            self.assertTrue(fake.items == before, "the keychain entry is the same one")
            again = ss.SeedStore(self.dir, ss.HermesKeychainSeal(), secret=lambda: PASS, clock=lambda: T0)
            self.assertTrue(again.status() == ss.READY, "the record still opens")
            self.assertTrue(bytes(again.get_seed()) == seed, "the seed is the same")
            with mock.patch.object(ss.os, "replace", side_effect=OSError("disk full")):
                self.assertFalse(store.use_recovery_code(code), "a code that cannot be struck out is not accepted")
            self.assertTrue(fake.items == before, "the keychain entry is still the same one")
            kept = ss.SeedStore(self.dir, ss.HermesKeychainSeal(), secret=lambda: PASS, clock=lambda: T0)
            self.assertTrue(kept.status() == ss.READY, "the record still opens after a failed write")
            self.assertTrue(bytes(kept.get_seed()) == seed, "the seed is the same after a failed write")

    def test_nothing_is_printed(self):
        """The whole flow prints nothing and logs no seed, no key and no code."""
        out, err = io.StringIO(), io.StringIO()
        log = io.StringIO()
        handler = logging.StreamHandler(log)
        root = logging.getLogger()
        old = root.level
        root.addHandler(handler)
        root.setLevel(logging.DEBUG)
        self.addCleanup(root.removeHandler, handler)
        self.addCleanup(root.setLevel, old)
        patches, fake = keychain_mode(storage="keychain")
        with patches:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                store = self.set_up(ss.HermesKeychainSeal())
                seed = bytes(store.get_seed())
                moved = ss.SeedStore(self.dir, ss.PassphraseSeal(lambda: PASS), secret=lambda: PASS,
                                     clock=lambda: T0)
                moved.get_seed()
        self.assertTrue(out.getvalue() == "", "something was printed")
        self.assertTrue(err.getvalue() == "", "something was printed")
        text = out.getvalue() + err.getvalue() + log.getvalue()
        self.assertFalse(any(f.decode(errors="replace") in text for f in forms(seed)[:4]), "the seed was printed")
        for value in fake.items.values():
            self.assertFalse(value in text, "the keychain's key was printed")

    # -- a re-seal that fails (never breaks an open, leaves no key behind) --
    def test_a_re_seal_that_fails_with_any_error_never_breaks_the_open(self):
        """A re-seal that fails with an error that is not one of the store's own (here a ValueError) never breaks
        the open: the seed is still there, the old record file is byte for byte the same, and one warning line says
        so. The error's own text is never logged (it could hold a value)."""
        patches, fake = keychain_mode(storage="keychain")
        ss._WARNED.discard("reseal")
        with patches:
            store = self.set_up(ss.PassphraseSeal(lambda: PASS))
            seed = bytes(store.get_seed())
            before = (self.dir / ss.REF_FILE).read_bytes()
            target = ss.HermesKeychainSeal()

            def boom(record, account):
                raise ValueError("a-failing-value-marker")

            target.seal = boom
            with self.assertLogs(ss.logger, level="WARNING") as caught:
                moved = ss.SeedStore(self.dir, target, secret=lambda: PASS, clock=lambda: T0)
        self.assertTrue(moved.status() == ss.READY, "the record opened with the seal it names")
        self.assertTrue(bytes(moved.get_seed()) == seed, "the seed is the one the record holds")
        self.assertTrue((self.dir / ss.REF_FILE).read_bytes() == before, "the old record file is byte for byte whole")
        self.assertTrue(len(caught.records) == 1, "one warning line, no more")
        self.assertTrue("a-failing-value-marker" not in caught.output[0], "the error's own text is never logged")

    def test_a_re_seal_that_cannot_be_written_leaves_no_keychain_entry_behind(self):
        """The re-seal writes a fresh key into the OS keychain and then the record file cannot be written: the
        entry goes with the failure, so no key is left in the keychain that no record can open. The old record file
        stays whole and the open still works."""
        patches, fake = keychain_mode(storage="keychain")
        with patches:
            store = self.set_up(ss.PassphraseSeal(lambda: PASS))
            seed = bytes(store.get_seed())
            before = (self.dir / ss.REF_FILE).read_bytes()
            with mock.patch.object(ss.os, "replace", side_effect=OSError("disk full")):
                moved = ss.SeedStore(self.dir, ss.HermesKeychainSeal(), secret=lambda: PASS, clock=lambda: T0)
        self.assertTrue(moved.status() == ss.READY, "the record opened with the seal it names")
        self.assertTrue(bytes(moved.get_seed()) == seed, "the seed is the one the record holds")
        self.assertTrue((self.dir / ss.REF_FILE).read_bytes() == before, "the old record file is byte for byte whole")
        self.assertTrue(fake.accounts() == [], "the keychain holds no entry of our own")

    def test_a_setup_that_cannot_be_written_leaves_no_keychain_entry_behind(self):
        """A setup in the keychain mode writes a fresh key into the OS keychain and then the record file cannot be
        written: the entry goes with the failure, so no key is left in the keychain that no record can open, and no
        record is saved."""
        patches, fake = keychain_mode(storage="keychain")
        real_write = ss._write_own

        def fail(path, data):
            if Path(path).name == ss.REF_FILE:
                raise ValueError("a-failing-value-marker")
            return real_write(path, data)

        with patches:
            store = ss.SeedStore(self.dir, ss.HermesKeychainSeal(), clock=lambda: T0)
            pending = store.begin_setup()
            step = pending.check(authcode.hotp(bytes(pending._live()), authcode.step_at(T0)), T0)
            with mock.patch.object(ss, "_write_own", side_effect=fail):
                with self.assertRaises(ss.SeedStoreError):
                    store.commit(pending, ss.hash_recovery_codes([]), step, entry="Hermes Tether")
        self.assertTrue(fake.accounts() == [], "the keychain holds no entry of our own")
        self.assertTrue(not (self.dir / ss.REF_FILE).exists(), "no record file was written")

    def test_a_failed_re_seal_keeps_the_keychain_entry_the_record_names(self):
        """The record names a keychain entry that is already there, and the re-seal (the setting changed back to
        the file) fails with an error that is not one of the store's own: the open still works, the record file is
        whole, and the entry the record names is still there."""
        patches, fake = keychain_mode(storage="keychain")
        ss._WARNED.discard("reseal")
        with patches:
            store = self.set_up(ss.HermesKeychainSeal())
            seed = bytes(store.get_seed())
            entry = record(self.dir)["keychain"]["account"]
            before = (self.dir / ss.REF_FILE).read_bytes()
            target = ss.PassphraseSeal(lambda: PASS)

            def boom(record, account):
                raise ValueError("a-failing-value-marker")

            target.seal = boom
            with self.assertLogs(ss.logger, level="WARNING") as caught:
                moved = ss.SeedStore(self.dir, target, secret=lambda: PASS, clock=lambda: T0)
        self.assertTrue(moved.status() == ss.READY, "the record opened with the seal it names")
        self.assertTrue(bytes(moved.get_seed()) == seed, "the seed is the one the record holds")
        self.assertTrue((self.dir / ss.REF_FILE).read_bytes() == before, "the old record file is byte for byte whole")
        self.assertTrue(fake.accounts() == [entry], "the entry the record names is still there")
        self.assertTrue(len(caught.records) == 1, "one warning line, no more")

    def test_a_failed_re_seal_keeps_an_entry_that_was_there_before(self):
        """The re-seal is aimed at a keychain entry that was already there (the record's own key) and the record
        cannot be written: that entry is never taken away, because only an entry this call wrote may go."""
        patches, fake = keychain_mode(storage="keychain")
        ss._WARNED.discard("reseal")
        account = "tether-2fa-" + "a" * 32
        with patches:
            store = self.set_up(ss.PassphraseSeal(lambda: PASS))
            seed = bytes(store.get_seed())
            made = ss.HermesKeychainSeal(account)
            made.seal(b"check", store.account())        # the entry is in the keychain before the re-seal
            self.assertTrue(fake.accounts() == [account], "the keychain holds an entry of our own")
            before = (self.dir / ss.REF_FILE).read_bytes()
            target = ss.HermesKeychainSeal(account)    # the re-seal finds that entry and keeps its key
            with mock.patch.object(ss.os, "replace", side_effect=ValueError("a-failing-value-marker")):
                with self.assertLogs(ss.logger, level="WARNING") as caught:
                    moved = ss.SeedStore(self.dir, target, secret=lambda: PASS, clock=lambda: T0)
        self.assertTrue(moved.status() == ss.READY, "the record opened with the seal it names")
        self.assertTrue(bytes(moved.get_seed()) == seed, "the seed is the one the record holds")
        self.assertTrue((self.dir / ss.REF_FILE).read_bytes() == before, "the old record file is byte for byte whole")
        self.assertTrue(fake.accounts() == [account], "the entry that was there before is still there")
        self.assertTrue(len(caught.records) == 1, "one warning line, no more")
        self.assertTrue("a-failing-value-marker" not in caught.output[0], "the error's own text is never logged")


if __name__ == "__main__":
    unittest.main()
