"""One authenticator for all machines: `authenticator export` makes a locked transfer file, `join` moves it to
another machine (design D85).

Fake boxes only: nothing is shown on screen and no command is run. A test never prints a seed, a code, a phrase or a
key; the transfer phrase is read out of the fake box to play the person's part, and never with print().
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import io
import json
import os
import re
import secrets
import stat
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "plugin" / "tether"))
sys.path.insert(1, str(Path.home() / ".hermes" / "hermes-agent"))

from test_enroll import Clock, Person, recovery_in, run, seal, seed_in  # noqa: E402
from test_link_loopback import isolate_session, temp_dir  # noqa: E402
from tether import authcode, enroll, seedstore as ss  # noqa: E402


class TransferPerson:
    """The person at the boxes: an app with a phone seed, a transfer phrase they read in one box and type in another.
    Never prints or keeps a value anywhere but the test's own assertions."""

    machine = "Mac"

    def __init__(self, clock: Clock, *, phone: bytes = b"", prove_phone: bytes = b"", phrase: str = "",
                 prove: str = "code", saved=None, wrong_phrases: int = 0, wrong_codes: int = 0,
                 delete: str = "Delete", swap_before_delete=None) -> None:
        self.clock, self.phone, self.phrase, self.prove = clock, phone, phrase, prove
        self.prove_phone = prove_phone or phone
        self.saved = list(saved or [])
        self.wrong_phrases, self.wrong_codes, self.delete = wrong_phrases, wrong_codes, delete
        self.swap_before_delete = swap_before_delete
        self.shown: list[str] = []
        self.prove_boxes = self.phrase_boxes = self.code_boxes = self.delete_boxes = 0
        self.displayed_phrase = ""
        self.delete_buttons: tuple[str, ...] = ()

    def code(self, phone: bytes = b"") -> str:
        return authcode.hotp(phone or self.phone, authcode.step_at(self.clock() + 0))

    def _wrong_code(self, phone: bytes = b"") -> str:
        return "000000" if self.code(phone) != "000000" else "111111"

    async def ask(self, text, buttons, *, field=False, timeout_s=0):
        self.shown.append(text)
        if "enter the current 6-digit code" in text:
            self.prove_boxes += 1
            if self.prove == "recovery" and self.saved:
                return enroll.Answer("OK", self.saved[0].lower().replace("-", " "))
            if self.prove == "wrong":
                return enroll.Answer("OK", self._wrong_code(self.prove_phone))
            return enroll.Answer("OK", self.code(self.prove_phone))
        if "One-time transfer phrase for your other machine" in text:
            found = re.search(r"\b[0-9A-Z]{4}(?:-[0-9A-Z]{4}){3}\b", text)
            if found:
                self.displayed_phrase = found.group(0).replace("-", "")
            return enroll.Answer("OK")                       # the box only shows it: OK
        if "Enter the one-time transfer phrase" in text:
            self.phrase_boxes += 1
            if self.phrase_boxes <= self.wrong_phrases:
                return enroll.Answer("OK", "AAAA-BBBB-CCCC-DDDD")
            return enroll.Answer("OK", self.phrase.lower().replace("-", " "))
        if "Enter the 6-digit code your authenticator app shows for" in text:
            self.code_boxes += 1
            if self.code_boxes <= self.wrong_codes:
                return enroll.Answer("OK", self._wrong_code())
            if self.swap_before_delete is not None and self.code_boxes == 1:
                self.swap_before_delete()
            return enroll.Answer("OK", self.code())
        if "Delete the transfer file now?" in text:
            self.delete_boxes += 1
            self.delete_buttons = buttons
            return enroll.Answer(self.delete)
        return enroll.Answer(buttons[-1])                     # a note or the replace warning


def flow(folder: Path, clock: Clock, person: TransferPerson) -> enroll.Enrollment:
    return enroll.Enrollment(folder, "mac", ss.SeedStore(folder, seal(), clock=clock), person,
                             clock=clock, settle_s=0)


def set_up(test: unittest.TestCase, folder: Path, clock: Clock) -> Person:
    """A machine with an authenticator, as `setup` leaves it; returns the person's phone and recovery codes."""
    person = Person(clock)
    res = run(enroll.Enrollment(folder, "mac", ss.SeedStore(folder, seal(), clock=clock), person,
                                clock=clock, settle_s=0).setup())
    test.assertTrue(res.ok, "the exporting machine's setup did not finish")
    clock.t += 60
    return person


def transfer_path(folder: Path) -> Path:
    return folder / enroll.TRANSFER_FILE


class TransferBase(unittest.TestCase):
    def setUp(self):
        self.d = temp_dir(self, "hp-transfer-a-")
        self.out = temp_dir(self, "hp-transfer-out-")
        self.clock = Clock()

    def exporting_machine(self) -> Person:
        return set_up(self, self.d, self.clock)

    def export(self, phone: bytes, *, prove: str = "code", saved=None, folder: Path = None) -> tuple:
        person = TransferPerson(self.clock, phone=phone, prove=prove, saved=saved)
        res = run(flow(self.d, self.clock, person).export(str(folder or self.out)))
        return person, res


class ExportTests(TransferBase):
    def test_export_needs_a_valid_code(self):
        """A wrong code makes no file at all (the existing _prove path, three tries)."""
        first = self.exporting_machine()
        person, res = self.export(first.phone, prove="wrong")
        self.assertFalse(res.ok, "export finished without a valid code")
        self.assertEqual(person.prove_boxes, enroll.TRIES_PER_BOX)
        self.assertFalse(transfer_path(self.out).exists(), "a transfer file was written after wrong codes")

    def test_export_refuses_to_overwrite_and_never_follows_a_link(self):
        """An existing file is left whole; a link at the name is refused and its target is never written through."""
        first = self.exporting_machine()
        destination = transfer_path(self.out)
        destination.write_text("keep me")
        with self.assertRaises(enroll.EnrollError):
            self.export(first.phone)
        self.assertEqual(destination.read_text(), "keep me", "an existing file was overwritten")

        victim = self.out / "victim"
        victim.write_text("safe")
        destination.unlink()
        os.symlink(victim, destination)
        with self.assertRaises(enroll.EnrollError):
            self.export(first.phone)
        self.assertTrue(destination.is_symlink(), "the link at the transfer name was replaced or followed")
        self.assertEqual(victim.read_text(), "safe", "the export wrote through a link")

    def test_the_file_holds_no_readable_seed_fingerprint_or_phrase(self):
        """The seed, the recovery fingerprints and the phrase are not readable in the file; only the header is."""
        first = self.exporting_machine()
        person, res = self.export(first.phone)
        self.assertTrue(res.ok, "the export did not finish")
        self.assertEqual(stat.S_IMODE(transfer_path(self.out).stat().st_mode), 0o600, "not a private file")
        raw = transfer_path(self.out).read_bytes()
        data = json.loads(raw.decode())
        self.assertEqual(data["v"], 1)
        self.assertEqual(data["kind"], "tether-authenticator-transfer")
        self.assertEqual(data["kdf"], "scrypt")
        self.assertEqual((data["n"], data["r"], data["p"]), (2 ** 15, 8, 1))
        for name in ("salt", "nonce", "sealed"):
            self.assertIsInstance(data[name], str)
        seed = seed_in(self.d)
        b32 = base64.b32encode(seed).decode().rstrip("=").encode()
        b64 = base64.b64encode(seed)
        self.assertNotIn(b32, raw, "the seed is readable in the transfer file")
        self.assertNotIn(b64, raw, "the seed is readable in the transfer file")
        for fingerprint in recovery_in(self.d):
            self.assertNotIn(fingerprint.encode(), raw, "a recovery fingerprint is readable in the transfer file")
        phrase = person.displayed_phrase
        self.assertEqual(len(phrase), enroll.RECOVERY_CHARS, "the phrase box did not show a full phrase")
        self.assertNotIn(phrase.encode(), raw, "the transfer phrase is readable in the file")
        self.assertNotIn(enroll.show_code(phrase).encode(), raw, "the transfer phrase is readable in the file")

    def test_export_is_refused_in_a_remote_or_agent_shell(self):
        """The same check as setup: no box and no file from a remote session's or an agent's shell."""
        from tether import cli
        isolate_session(self)
        data = temp_dir(self, "hp-transfer-cli-")
        made: list = []
        patches = [mock.patch.object(cli, "data_dir", lambda: data),
                   mock.patch.object(enroll, "default_ui", lambda name: made.append(name) or TransferPerson(self.clock))]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        os.environ[enroll.REMOTE_MARK] = "1"
        with contextlib.redirect_stdout(io.StringIO()) as out:
            rc = cli.run(argparse.Namespace(tether_cmd="authenticator", auth_cmd="export", folder=str(self.out)),
                         SimpleNamespace(roles={"device"}, name="mac"))
        self.assertEqual(rc, 2)
        self.assertIn("never from a remote session's or an agent's shell", out.getvalue())
        self.assertEqual(made, [], "a box was prepared in a remote session's shell")
        self.assertFalse(transfer_path(self.out).exists())

        del os.environ[enroll.REMOTE_MARK]
        os.environ["HERMES_SESSION_KEY"] = "agent:main:telegram:dm:1"
        with contextlib.redirect_stdout(io.StringIO()) as out:
            rc = cli.run(argparse.Namespace(tether_cmd="authenticator", auth_cmd="export", folder=str(self.out)),
                         SimpleNamespace(roles={"device"}, name="mac"))
        self.assertEqual(rc, 2)
        self.assertEqual(made, [], "a box was prepared in an agent's shell")
        self.assertFalse(transfer_path(self.out).exists())


class JoinTests(TransferBase):
    def setUp(self):
        super().setUp()
        self.other = temp_dir(self, "hp-transfer-b-")

    def exported(self, first: Person) -> tuple[str, Path]:
        person, res = self.export(first.phone)
        self.assertTrue(res.ok, "the export did not finish")
        self.assertTrue(transfer_path(self.out).exists())
        return person.displayed_phrase, transfer_path(self.out)

    def test_join_with_the_phrase_and_code_moves_the_same_seed(self):
        """The joined machine holds the exporting seed; codes the exporting phone makes are accepted there."""
        first = self.exporting_machine()
        phrase, path = self.exported(first)
        joiner = TransferPerson(self.clock, phone=first.phone, phrase=phrase)
        res = run(flow(self.other, self.clock, joiner).join(str(path)))
        self.assertTrue(res.ok, "join did not finish")
        self.assertEqual(seed_in(self.other), seed_in(self.d), "the joined machine holds another seed")
        self.assertEqual(recovery_in(self.other), recovery_in(self.d), "the recovery fingerprints did not move")
        self.assertEqual(enroll.state(ss.SeedStore(self.other, seal(), clock=self.clock)), enroll.ON)

        self.clock.t += 60
        store = ss.SeedStore(self.other, seal(), clock=self.clock)
        checker = authcode.CodeChecker(store, self.other, clock=self.clock, wall=self.clock)
        code = authcode.hotp(first.phone, authcode.step_at(self.clock()))
        self.assertEqual(checker.check(code), authcode.ACCEPTED,
                         "a code from the exporting machine's seed was not accepted after join")
        self.assertTrue(store.use_recovery_code(enroll.clean_recovery(first.saved[0])),
                        "a recovery code from the exporting machine does not work after join")

    def test_wrong_phrase_five_times_stops_with_nothing_saved(self):
        first = self.exporting_machine()
        phrase, path = self.exported(first)
        joiner = TransferPerson(self.clock, phone=first.phone, phrase=phrase, wrong_phrases=enroll.TRANSFER_TRIES)
        res = run(flow(self.other, self.clock, joiner).join(str(path)))
        self.assertFalse(res.ok, "join finished with a wrong phrase")
        self.assertEqual(joiner.phrase_boxes, enroll.TRANSFER_TRIES, "more or fewer than five phrase tries")
        self.assertEqual(joiner.code_boxes, 0, "a phone code was asked for after the phrase failed")
        self.assertIsNone(seed_in(self.other), "a seed was saved after wrong phrases")

    def test_a_correct_phrase_but_a_wrong_phone_code_saves_nothing(self):
        first = self.exporting_machine()
        phrase, path = self.exported(first)
        joiner = TransferPerson(self.clock, phone=secrets.token_bytes(20), phrase=phrase,
                                wrong_codes=enroll.TRIES_PER_BOX)
        res = run(flow(self.other, self.clock, joiner).join(str(path)))
        self.assertFalse(res.ok, "join finished with wrong phone codes")
        self.assertEqual(joiner.code_boxes, enroll.TRIES_PER_BOX)
        self.assertIsNone(seed_in(self.other), "a seed was saved although the phone code did not match")

    def test_a_tampered_file_is_refused(self):
        """Any changed header field or sealed byte leaves nothing saved (the header is authenticated too)."""
        first = self.exporting_machine()
        phrase, path = self.exported(first)
        original = path.read_bytes()

        def flip(text: str) -> str:
            return ("A" if text[0] != "A" else "B") + text[1:]

        def changed(mutator) -> bytes:
            data = json.loads(original.decode())
            mutator(data)
            return json.dumps(data).encode()

        cases = {
            "v": changed(lambda d: d.update(v=2)),
            "kind": changed(lambda d: d.update(kind="something-else")),
            "kdf": changed(lambda d: d.update(kdf="pbkdf2")),
            "n": changed(lambda d: d.update(n=2 ** 14)),
            "r": changed(lambda d: d.update(r=4)),
            "p": changed(lambda d: d.update(p=2)),
            "salt": changed(lambda d: d.update(salt=flip(d["salt"]))),
            "nonce": changed(lambda d: d.update(nonce=flip(d["nonce"]))),
            "sealed": changed(lambda d: d.update(sealed=flip(d["sealed"]))),
        }
        for name, data in cases.items():
            with self.subTest(name=name):
                path.write_bytes(data)
                joiner = TransferPerson(self.clock, phone=first.phone, phrase=phrase)
                res = run(flow(self.other, self.clock, joiner).join(str(path)))
                self.assertFalse(res.ok, f"a tampered {name} was accepted")
                self.assertIsNone(seed_in(self.other), f"a seed was saved from a tampered {name}")
        path.write_bytes(original)

    def test_join_on_a_machine_with_an_authenticator_needs_its_current_code_first(self):
        """The replace path setup uses: without this machine's current code nothing is read; with it the seed moves."""
        first = self.exporting_machine()
        phrase, path = self.exported(first)
        old = set_up(self, self.other, self.clock)
        before = seed_in(self.other)
        refused = TransferPerson(self.clock, phone=first.phone, prove_phone=old.phone, phrase=phrase, prove="wrong")
        res = run(flow(self.other, self.clock, refused).join(str(path)))
        self.assertFalse(res.ok, "join replaced an authenticator without its current code")
        self.assertEqual(refused.phrase_boxes, 0, "the transfer phrase was asked for before the current code")
        self.assertEqual(seed_in(self.other), before, "the existing authenticator changed without a code")

        allowed = TransferPerson(self.clock, phone=first.phone, prove_phone=old.phone, phrase=phrase, prove="code")
        res = run(flow(self.other, self.clock, allowed).join(str(path)))
        self.assertTrue(res.ok, "join did not finish with this machine's current code")
        self.assertEqual(seed_in(self.other), seed_in(self.d), "the joined seed is not the exporting seed")
        self.assertTrue(any(enroll.Texts("Mac", "mac").join_replace_warning() in text for text in allowed.shown),
                        "the join did not say this machine's own authenticator is replaced by the shared one")
        self.assertFalse(any(enroll.Texts("Mac", "mac").replace_warning() in text for text in allowed.shown),
                         "the join told the person to export and re-join the other machines")

    def test_the_delete_offer_removes_a_plain_file_and_refuses_a_link(self):
        first = self.exporting_machine()
        phrase, path = self.exported(first)
        joiner = TransferPerson(self.clock, phone=first.phone, phrase=phrase, delete="Delete")
        res = run(flow(self.other, self.clock, joiner).join(str(path)))
        self.assertTrue(res.ok, "join did not finish")
        self.assertEqual(joiner.delete_boxes, 1, "no delete offer was shown")
        self.assertEqual(joiner.delete_buttons[-1], "Delete", "Delete is not the default button")
        self.assertFalse(path.exists(), "the transfer file was not deleted")

        other = temp_dir(self, "hp-transfer-c-")
        self.clock.t += 60                     # a later code step for the second export
        phrase, path = self.exported(first)
        victim = self.out / "keep-me"
        victim.write_text("safe")

        def swap():
            path.unlink()
            os.symlink(victim, path)

        joiner = TransferPerson(self.clock, phone=first.phone, phrase=phrase, delete="Delete",
                                swap_before_delete=swap)
        res = run(flow(other, self.clock, joiner).join(str(path)))
        self.assertTrue(res.ok, "join did not finish before the delete offer")
        self.assertTrue(path.is_symlink(), "the link at the transfer name was deleted")
        self.assertEqual(victim.read_text(), "safe", "the delete offer followed the link")
        self.assertTrue(any("could not be deleted" in text for text in joiner.shown),
                        "the box did not say the transfer file could not be deleted")


class ReplaceWarningTests(TransferBase):
    def test_a_replace_with_a_code_and_with_a_recovery_code_says_the_other_machines_use_the_old_one(self):
        wanted = enroll.Texts("Mac", "mac").replace_warning()
        for prove in ("code", "recovery"):
            with self.subTest(prove=prove):
                folder = temp_dir(self, "hp-transfer-warn-")
                first = set_up(self, folder, self.clock)
                replacer = Person(self.clock, phone=first.phone, saved=first.saved, prove=prove)
                res = run(enroll.Enrollment(folder, "mac", ss.SeedStore(folder, seal(), clock=self.clock), replacer,
                                            clock=self.clock, settle_s=0).setup())
                self.assertTrue(res.ok, f"the {prove} replacement did not finish")
                self.assertTrue(any(wanted in text for text in replacer.shown),
                                f"the {prove} replace did not show the other-machines box")


class EntryNameTests(unittest.TestCase):
    def test_the_entry_name_is_hermes_tether_for_every_machine(self):
        self.assertEqual(enroll.Texts("Mac", "studio-mac").entry, "Hermes Tether")
        uri = enroll.otpauth_uri("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
        self.assertTrue(uri.startswith("otpauth://totp/Hermes%20Tether?secret="), uri)
        self.assertNotIn("studio", uri)
        self.assertIn("&issuer=Hermes%20Tether&", uri)

    def test_the_joined_machine_records_the_generic_entry(self):
        d, out, other = (temp_dir(self, "hp-transfer-entry-a-"), temp_dir(self, "hp-transfer-entry-o-"),
                         temp_dir(self, "hp-transfer-entry-b-"))
        clock = Clock()
        first = set_up(self, d, clock)
        person = TransferPerson(clock, phone=first.phone)
        self.assertTrue(run(enroll.Enrollment(d, "mac", ss.SeedStore(d, seal(), clock=clock), person,
                                              clock=clock, settle_s=0).export(str(out))).ok)
        phrase = person.displayed_phrase
        joiner = TransferPerson(clock, phone=first.phone, phrase=phrase)
        self.assertTrue(run(enroll.Enrollment(other, "mac", ss.SeedStore(other, seal(), clock=clock), joiner,
                                              clock=clock, settle_s=0).join(str(transfer_path(out)))).ok)
        self.assertEqual(ss.SeedStore(other, seal(), clock=clock).entry_name(), "Hermes Tether")


class CliTests(unittest.TestCase):
    def setUp(self):
        isolate_session(self)
        from tether import cli
        self.cli = cli
        self.data = temp_dir(self, "hp-transfer-cli-")
        self.out = temp_dir(self, "hp-transfer-cli-out-")
        patcher = mock.patch.object(cli, "data_dir", lambda: self.data)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.uis: list = []
        patcher = mock.patch.object(enroll, "default_ui", lambda name: self.uis.append(name) or TransferPerson(Clock()))
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = mock.patch.object(ss, "default_backend", lambda folder, secret=None: seal())
        patcher.start()
        self.addCleanup(patcher.stop)
        from tether.identity import MemorySecretStore, load_or_create
        ident = load_or_create(temp_dir(self, "hp-transfer-id-"), MemorySecretStore(), "tether-dev")
        patcher = mock.patch.object(cli, "identity", lambda s: ident)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _run(self, *words):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            rc = self.cli.run(argparse.Namespace(tether_cmd="authenticator", auth_cmd=words[0],
                                                 folder=words[1] if len(words) > 1 else "",
                                                 file=words[1] if len(words) > 1 else ""),
                              SimpleNamespace(roles={"device"}, name="mac"))
        return rc, out.getvalue()

    def test_join_is_refused_in_a_remote_session_shell(self):
        os.environ[enroll.REMOTE_MARK] = "1"
        rc, out = self._run("join", str(self.out / enroll.TRANSFER_FILE))
        self.assertEqual(rc, 2)
        self.assertIn("never from a remote session's or an agent's shell", out)
        self.assertEqual(self.uis, [], "a box was prepared in a remote session's shell")

    def test_export_and_join_take_a_folder_or_a_file_not_a_secret(self):
        parser = argparse.ArgumentParser()
        self.cli.setup(parser)
        self.assertEqual(parser.parse_args(["authenticator", "export"]).folder, "")
        self.assertEqual(parser.parse_args(["authenticator", "export", "/tmp/x"]).folder, "/tmp/x")
        self.assertEqual(parser.parse_args(["authenticator", "join", "/tmp/f"]).file, "/tmp/f")
        for words in (["authenticator", "export", "--code", "123456"],
                      ["authenticator", "join", "--phrase", "ABCD-EFGH-JKMN-PQRS"]):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                parser.parse_args(words)


if __name__ == "__main__":
    unittest.main()
