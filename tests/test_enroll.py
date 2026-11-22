"""Setting up, replacing and removing the device's authenticator; recovery codes; unlocking code entry; the upgrade
of 0.2 devices (design D67). Fake boxes and the sealed-file store with a random test passphrase: nothing is shown on
screen, and no system dialog (administrator, UAC) exists any more.
A test never prints a key or a code: every check is an assertTrue/assertFalse with a fixed message.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import contextlib
import io
import json
import logging
import os
import re
import secrets
import sys
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "plugin" / "tether"))
sys.path.insert(1, str(Path.home() / ".hermes" / "hermes-agent"))

from test_link_loopback import FakePrompt, Rig, isolate_session, temp_dir  # noqa: E402
from tether import authcode, enroll, seedstore as ss  # noqa: E402
from tether.consent import NO_AUTHENTICATOR_TEXT, ConsentGate  # noqa: E402
from tether.link import RemoteError  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
T0 = 1_800_000_000.0          # a fixed wall clock for the flows (2027-01-15)
PASS = secrets.token_bytes(32)                       # the test's stand-in for Tether's key passphrase


def seal() -> ss.PassphraseSeal:
    return ss.PassphraseSeal(lambda: PASS)


class Clock:
    def __init__(self, t: float = T0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


class Person:
    """Answers the setup boxes the way a person with a phone would. ``phone`` is the key the person typed into the
    app; ``saved`` the recovery codes they wrote down. Choices are set per test."""

    machine = "Mac"

    def __init__(self, clock: Clock, *, prove: str = "code", cancel_at: str = "",
                 phone_skew_s: float = 0.0, confirm: str = "right", phone: bytes = b"", saved=None) -> None:
        self.clock, self.prove, self.cancel_at = clock, prove, cancel_at
        self.phone_skew_s, self.confirm = phone_skew_s, confirm
        self.phone, self.saved = phone, list(saved or [])
        self.shown: list[str] = []
        self.qrs: list = []               # the code boxes (the key as a code to scan)
        self.prove_boxes = 0
        self.held_boxes = 0
        self.typed_recovery = ""

    def code(self) -> str:
        return authcode.hotp(self.phone, authcode.step_at(self.clock() + self.phone_skew_s))

    def _scanned(self, key_text: str):
        """The person scanned the code (or typed the key under it): their app has the key now."""
        key = key_text.replace(" ", "")
        self.phone = base64.b32decode(key + "=" * (-len(key) % 8))
        return enroll.Answer("I added it")

    async def ask_qr(self, qr, buttons, *, timeout_s=0):
        """The box with the key as a code to scan (the key as text under it)."""
        self.shown.append(qr.text)
        self.qrs.append(qr)
        if self.cancel_at == "key":
            return enroll.Answer(None)
        return self._scanned(qr.key_text)

    async def ask(self, text, buttons, *, field=False, timeout_s=0):
        self.shown.append(text)
        if text.startswith(("Set up the authenticator", "Replace the authenticator", "Remove the authenticator",
                            "Make new recovery codes", "The current authenticator on this", "Unlock code entry")):
            return enroll.Answer(None if self.cancel_at == "intro" else buttons[-1])
        if "Add this key to your authenticator app" in text:
            if self.cancel_at == "key":
                return enroll.Answer(None)
            return self._scanned(re.search(r"3\. Key: ([A-Z2-7 ]+)\n", text).group(1))
        if "Enter the 6-digit code your app now shows" in text:
            if self.confirm == "wrong":
                return enroll.Answer("OK", "000000" if self.code() != "000000" else "111111")
            return enroll.Answer("OK", self.code())
        if "Recovery codes for" in text:
            if self.cancel_at == "recovery":
                return enroll.Answer(None)
            self.saved = re.findall(r"\b[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}\b", text)
            return enroll.Answer("I saved them")
        if "Codes from your app are not taken" in text:
            self.held_boxes += 1
            if self.prove == "lost":
                return enroll.Answer(enroll.Enrollment.LOST)
            if self.prove == "recovery":
                return enroll.Answer("OK", self.saved[0])
            return enroll.Answer(None)
        if "enter the current 6-digit code" in text or "To unlock code entry, enter one of your recovery" in text:
            self.prove_boxes += 1
            if self.prove == "lost":
                return enroll.Answer(enroll.Enrollment.LOST)
            if self.prove == "code":
                return enroll.Answer("OK", self.code())
            if self.prove == "recovery":
                self.typed_recovery = self.saved[0]
                return enroll.Answer("OK", self.saved[0].lower().replace("-", " "))
            if self.prove == "planted":
                return enroll.Answer("OK", self.typed_recovery)
            return enroll.Answer("OK", "000000" if self.code() != "000000" else "111111")    # "wrong"
        return enroll.Answer(buttons[-1])          # notes: OK


def run(coro):
    return asyncio.run(coro)


def _inner(folder: Path):
    path = Path(folder) / ss.REF_FILE
    if not path.exists():
        return None
    ref = json.loads(path.read_text())
    try:
        return json.loads(seal().open(base64.b64decode(ref["sealed"]), ref["account"]).decode())
    except ss.SeedStoreError:
        return None


def seed_in(folder: Path):
    """The seed the record file holds now (tests only; never printed), or None."""
    inner = _inner(folder)
    return None if inner is None else bytes(ss._unb32(inner["seed"]))


def recovery_in(folder: Path) -> list:
    return _inner(folder)["recovery"]["hashes"]


class Base(unittest.TestCase):
    def setUp(self):
        self.d = temp_dir(self, "hp-enroll-")
        self.clock = Clock()

    def new_store(self) -> ss.SeedStore:
        return ss.SeedStore(self.d, seal(), clock=self.clock)

    def flow(self, person: Person) -> enroll.Enrollment:
        return enroll.Enrollment(self.d, "mac", self.new_store(), person, clock=self.clock, settle_s=0)

    @property
    def seed(self):
        return seed_in(self.d)

    def set_up(self) -> Person:
        p = Person(self.clock)
        res = run(self.flow(p).setup())
        self.assertTrue(res.ok, "the setup a person completed did not finish")
        self.clock.t += 60                  # later codes come from later steps
        return p

    def state(self) -> str:
        return enroll.state(self.new_store())

    def lock_code_entry(self) -> None:
        """Code entry locked, as after 20 wrong codes or a changed state file (here: the state file deleted)."""
        (self.d / authcode.STATE_FILE).unlink()
        store = self.new_store()
        codes = authcode.CodeChecker(store, self.d, clock=self.clock, wall=self.clock)
        self.assertEqual(codes.blocked(), (authcode.LOCKED, 0.0))


class SetupTests(Base):
    def test_first_setup_shows_no_system_dialog(self):
        """G2: turning the authenticator on asks for no administrator or UAC check (the fake UI has none: a call would
        fail) and no password; remote use is refused until it is done, so no session can run it."""
        self.assertFalse(hasattr(enroll.MacUI, "owner_check") or hasattr(enroll.WindowsUI, "owner_check"),
                         "an administrator check is still wired")
        p = Person(self.clock)
        self.assertTrue(run(self.flow(p).setup()).ok, "a first setup at the device did not finish")
        self.assertFalse(any(w in t.lower() for t in p.shown for w in ("administrator", "login password", "keychain",
                                                                      "user account control")),
                         "a box still speaks of an administrator check, a login password or the keychain")
        self.assertEqual(self.state(), enroll.ON)

    def test_nothing_is_saved_until_the_recovery_codes_were_shown(self):
        """T4/T8: cancelling at the last box leaves nothing behind; a full run turns the authenticator on."""
        for where in ("key", "recovery"):
            p = Person(self.clock, cancel_at=where)
            self.assertFalse(run(self.flow(p).setup()).ok)
            self.assertIsNone(self.seed, f"a key was stored after a cancel at the {where} box")
            self.assertEqual(self.state(), enroll.OFF)
        self.set_up()
        self.assertEqual(self.state(), enroll.ON)

    def test_the_first_code_is_used_up(self):
        """T5: the code that confirmed the new key cannot be used again (it would approve a session next)."""
        p = Person(self.clock)
        self.assertTrue(run(self.flow(p).setup()).ok)
        self.assertEqual((authcode.peek_state(self.d) or {}).get("last_step"), authcode.step_at(self.clock()))
        store = self.new_store()
        store.unlock()
        verdict = authcode.CodeChecker(store, self.d, clock=self.clock).check(p.code())
        self.assertEqual(verdict, authcode.USED, "the confirming code still opens something")

    def test_a_wrong_clock_is_named_and_nothing_is_saved(self):
        """T5/T8: a first code that matches minutes away says the clock is off, and saves nothing."""
        p = Person(self.clock, phone_skew_s=300)
        self.assertFalse(run(self.flow(p).setup()).ok)
        self.assertTrue(any("clock seems to be about 5 minutes behind" in t for t in p.shown),
                        "the clock box did not name the difference")
        self.assertIsNone(self.seed, "a key was stored although the clock was off")

    def test_three_wrong_first_codes_save_nothing(self):
        p = Person(self.clock, confirm="wrong")
        self.assertFalse(run(self.flow(p).setup()).ok)
        self.assertIsNone(self.seed, "a key was stored after wrong first codes")
        self.assertTrue(any("The codes did not match, so nothing was saved" in t for t in p.shown))

    def test_a_store_that_cannot_keep_keys_refuses_setup(self):
        """Fail closed: no seal (Linux), no setup and remote use stays off."""
        store = ss.SeedStore(self.d, ss.NoStore())
        flow = enroll.Enrollment(self.d, "mac", store, Person(self.clock), settle_s=0)
        with self.assertRaises(enroll.EnrollError):
            run(flow.setup())
        self.assertFalse(list(self.d.iterdir()), "something was written without a secret store")

    def test_a_record_that_cannot_be_opened_is_replaced_by_a_new_setup(self):
        """G2: a damaged record (or one sealed with another key) already refuses remote use; a setup at the device
        replaces it without a code (there is none to check) and says why."""
        self.set_up()
        before = self.seed
        (self.d / ss.REF_FILE).write_text("{damaged")
        self.assertEqual(self.state(), enroll.DAMAGED)
        p = Person(self.clock)
        self.assertTrue(run(self.flow(p).setup()).ok)
        self.assertTrue(any(t.startswith("The current authenticator on this Mac cannot be opened") for t in p.shown))
        self.assertEqual(p.prove_boxes, 0, "a code was asked for a record that cannot be opened")
        self.assertFalse(self.seed == before, "the key did not change")


class ChangeTests(Base):
    def test_replace_needs_the_current_code(self):
        """T4: an authenticator is replaced only with a current code (or a recovery code)."""
        self.set_up()
        before = self.seed
        p = Person(self.clock, prove="wrong")
        self.assertFalse(run(self.flow(p).setup()).ok)
        self.assertTrue(self.seed == before, "the key changed without a current code")
        self.assertEqual(p.prove_boxes, enroll.TRIES_PER_BOX)

    def test_replace_with_the_current_code_makes_a_new_key_and_new_codes(self):
        first = self.set_up()
        before = self.seed
        p = Person(self.clock, phone=first.phone, saved=first.saved)
        self.assertTrue(run(self.flow(p).setup()).ok)
        self.assertFalse(self.seed == before, "the key did not change")
        self.assertEqual(self.state(), enroll.ON)
        self.clock.t += 60
        old = Person(self.clock, prove="recovery", phone=first.phone, saved=first.saved)
        self.assertFalse(run(self.flow(old).remove()).ok, "an old recovery code still worked after a replace")

    def test_lost_both_changes_nothing_and_says_how_to_start_over(self):
        """G2: without a code or a recovery code nothing is changed by Tether; the box says to delete the record file
        here by hand and set up again (outside any session; the session lock blocks that file on macOS)."""
        self.set_up()
        before = self.seed
        for action in ("setup", "remove", "unlock"):
            p = Person(self.clock, prove="lost")
            self.assertFalse(run(getattr(self.flow(p), action)()).ok, f"Lost both changed something ({action})")
            self.assertTrue(self.seed == before, f"Lost both replaced or removed the key ({action})")
            self.assertTrue(any(f"delete the file {ss.REF_FILE}" in t for t in p.shown), "no way back was named")
        (self.d / ss.REF_FILE).unlink()                    # what the person does by hand, at the machine
        self.assertTrue(run(self.flow(Person(self.clock)).setup()).ok)
        self.assertFalse(self.seed == before)

    def test_remove_needs_proof(self):
        first = self.set_up()
        self.assertFalse(run(self.flow(Person(self.clock, prove="wrong")).remove()).ok)
        self.assertEqual(self.state(), enroll.ON, "removed without proof")
        self.assertTrue(run(self.flow(Person(self.clock, prove="recovery", saved=first.saved)).remove()).ok)
        self.assertEqual(self.state(), enroll.OFF)
        self.assertIsNone(self.seed)
        for name in (ss.REF_FILE, authcode.STATE_FILE):
            self.assertFalse((self.d / name).exists(), f"{name} was left behind")

    def test_recovery_codes_need_proof(self):
        self.set_up()
        hashes = recovery_in(self.d)
        self.assertFalse(run(self.flow(Person(self.clock, prove="wrong")).recovery_codes()).ok)
        self.assertEqual(recovery_in(self.d), hashes, "new codes without proof")

    def test_a_recovery_code_works_once(self):
        """T4/T5: a recovery code is used up when it is accepted, even if the run goes no further."""
        first = self.set_up()
        p = Person(self.clock, prove="recovery", saved=first.saved, cancel_at="recovery")
        self.assertFalse(run(self.flow(p).recovery_codes()).ok)     # accepted, then cancelled at the new codes
        self.assertEqual(len(recovery_in(self.d)), enroll.RECOVERY_COUNT - 1)
        again = Person(self.clock, prove="recovery", saved=first.saved)
        self.assertFalse(run(self.flow(again).remove()).ok, "a used recovery code worked a second time")
        self.assertEqual(self.state(), enroll.ON)

    def test_a_used_step_cannot_be_used_again(self):
        """T5: the current code opens the settings once; the same code in the same step is refused."""
        first = self.set_up()
        p = Person(self.clock, prove="code", phone=first.phone, cancel_at="recovery")
        self.assertFalse(run(self.flow(p).recovery_codes()).ok)
        self.assertEqual(p.prove_boxes, 1)
        again = Person(self.clock, prove="code", phone=first.phone)
        self.assertFalse(run(self.flow(again).remove()).ok, "the same code worked twice in one step")
        self.assertEqual(self.state(), enroll.ON)

    def test_a_deleted_changed_or_planted_record_turns_remote_use_off(self):
        """T4: deleting or rewriting the record file (only possible outside a session on macOS: the session lock)
        turns remote use off; a planted record not sealed with this machine's key passphrase is never opened, so it
        cannot bring its own key or recovery codes."""
        for attack in ("delete", "rewrite", "plant"):
            first = self.set_up()
            pointer = self.d / ss.REF_FILE
            if attack == "delete":
                pointer.unlink()
            elif attack == "rewrite":
                data = json.loads(pointer.read_text())
                data["account"] = "tether-" + "0" * 32
                pointer.write_text(json.dumps(data))
            else:
                other = ss.SeedStore(self.d, ss.PassphraseSeal(lambda: secrets.token_bytes(32)), clock=self.clock)
                pending = other.begin_setup()
                other.commit(pending, ss.hash_recovery_codes(["ABCDEFGHJKMNPQRS"]), authcode.step_at(T0))
            store = self.new_store()
            gate = ConsentGate(prompt=FakePrompt(True), codes=authcode.CodeChecker(store, self.d))
            with self.assertRaises(PermissionError):
                run(gate.require("fp", "host", "s1"))
            self.assertFalse(store.holds_key(), f"{attack}: a record not sealed here was opened")
            planted = Person(self.clock, prove="recovery", saved=["ABCD-EFGH-JKMN-PQRS"])
            self.assertFalse(run(self.flow(planted).recovery_codes()).ok, f"{attack}: a planted recovery code worked")
            del first
            self.d = temp_dir(self, "hp-enroll-")

    def test_wrong_codes_pause_code_entry_but_not_recovery_codes(self):
        """T5: wrong app codes here count toward the same pause and lock as the approval box (5 in a row pause code
        entry); a right code is then not taken, but a recovery code still is."""
        first = self.set_up()
        for _ in range(2):
            run(self.flow(Person(self.clock, prove="wrong")).remove())
        self.assertEqual((authcode.peek_state(self.d) or {}).get("wrong"), authcode.PAUSE_EVERY)
        right = Person(self.clock, prove="code", phone=first.phone)
        self.assertFalse(run(self.flow(right).remove()).ok, "a code was taken while code entry was paused")
        self.assertEqual(right.prove_boxes, 0)
        self.assertTrue(right.held_boxes >= 1)
        rec = Person(self.clock, prove="recovery", saved=first.saved)
        self.assertTrue(run(self.flow(rec).remove()).ok, "a recovery code was paused too")


class UnlockTests(Base):
    def test_unlock_takes_a_recovery_code_never_an_app_code(self):
        """T4/T5: a lock after wrong codes (or a changed state file) is opened only with a recovery code, so it cannot
        be guessed open with 6 digits; Lost both changes nothing."""
        first = self.set_up()
        self.lock_code_entry()
        app = Person(self.clock, prove="code", phone=first.phone)
        self.assertFalse(run(self.flow(app).unlock()).ok, "an app code unlocked code entry")
        self.assertEqual((authcode.peek_state(self.d) or {}).get("locked"), True)
        rec = Person(self.clock, prove="recovery", saved=first.saved)
        self.assertTrue(run(self.flow(rec).unlock()).ok)
        self.assertEqual((authcode.peek_state(self.d) or {}).get("locked"), False, "still locked after unlock")
        self.assertEqual(len(recovery_in(self.d)), enroll.RECOVERY_COUNT - 1)
        self.lock_code_entry()
        self.assertFalse(run(self.flow(Person(self.clock, prove="lost")).unlock()).ok)
        self.assertEqual((authcode.peek_state(self.d) or {}).get("locked"), True, "Lost both unlocked code entry")


class LeakTests(Base):
    def test_no_key_or_code_reaches_stdout_logs_events_or_files(self):
        """T7: the key and the recovery codes are shown in boxes only: never on stdout or stderr, in a log record,
        in the connection log or in any file of the data folder."""
        records: list[str] = []

        class Grab(logging.Handler):
            def emit(self, record):
                records.append(record.getMessage())

        root = logging.getLogger()
        handler, level = Grab(level=logging.DEBUG), root.level
        root.addHandler(handler)
        root.setLevel(logging.DEBUG)
        self.addCleanup(root.removeHandler, handler)
        self.addCleanup(root.setLevel, level)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            p = self.set_up()
            run(self.flow(Person(self.clock, prove="code", phone=p.phone)).recovery_codes())
        key = base64.b32encode(self.seed).decode().rstrip("=")
        grouped = " ".join(key[i:i + 4] for i in range(0, len(key), 4))
        secrets_ = [key, grouped, self.seed.hex()]
        for c in p.saved:
            secrets_ += [c, c.replace("-", "")]
        files = "".join(f.read_text(errors="replace") for f in self.d.iterdir() if f.is_file())
        for where, blob in (("stdout", out.getvalue()), ("stderr", err.getvalue()), ("logs", "\n".join(records)),
                            ("data folder", files)):
            self.assertFalse(any(s in blob for s in secrets_), f"a key or recovery code reached the {where}")
        self.assertTrue((self.d / "events.jsonl").exists(), "the connection log was not written at all")

    def test_box_programs_get_secrets_on_stdin_only(self):
        """T7: the text of a box (which can hold the key) goes to osascript or PowerShell on stdin, never in their
        arguments or environment."""
        secret = "QWERTYUIOPASDFGH"
        seen = []

        class Proc:
            returncode = 0

            async def communicate(self, data=None):
                seen.append(("stdin", data or b""))
                return b"", b""

            def kill(self):
                pass

        async def fake_exec(*argv, **kw):
            seen.append(("argv", " ".join(argv).encode()))
            seen.append(("env", json.dumps(kw.get("env") or {}).encode()))
            return Proc()

        with mock.patch("asyncio.create_subprocess_exec", fake_exec):
            run(enroll.MacUI("mac").ask(f"Key: {secret}", ("Cancel", "OK"), field=True))
            run(enroll.WindowsUI("pc").ask(f"Key: {secret}", ("Cancel", "OK"), field=True))
        for kind, data in seen:
            if kind in ("argv", "env"):
                self.assertFalse(secret.encode() in data, f"box text reached the box program's {kind}")
        self.assertEqual(sum(1 for k, d in seen if k == "stdin" and secret.encode() in d), 2,
                         "the box text did not go on stdin")


class CliTests(unittest.TestCase):
    def setUp(self):
        isolate_session(self)
        from tether import cli
        self.cli = cli
        self.data = temp_dir(self, "hp-enroll-cli-")
        patcher = mock.patch.object(cli, "data_dir", lambda: self.data)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.uis = []
        patcher = mock.patch.object(enroll, "default_ui", lambda name: self.uis.append(name) or Person(Clock()))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.backend = seal()                         # a random test passphrase, never the machine's own
        patcher = mock.patch.object(ss, "default_backend", lambda folder, secret=None: self.backend)
        patcher.start()
        self.addCleanup(patcher.stop)
        from tether.identity import MemorySecretStore, load_or_create
        ident = load_or_create(temp_dir(self, "hp-enroll-id-"), MemorySecretStore(), "tether-dev")
        patcher = mock.patch.object(cli, "identity", lambda s: ident)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _run(self, *words):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = self.cli.run(argparse.Namespace(tether_cmd="authenticator", auth_cmd=words[0] if words else None),
                              SimpleNamespace(roles={"device"}, name="mac"))
        return rc, out.getvalue()

    def test_refused_in_a_remote_session_shell(self):
        """T4: `hermes tether authenticator setup` run through device exec (its terminal carries the mark) shows no
        box and changes nothing."""
        os.environ[enroll.REMOTE_MARK] = "1"
        rc, out = self._run("setup")
        self.assertEqual(rc, 2)
        self.assertIn("never from a remote session's or an agent's shell", out)
        self.assertEqual(self.uis, [], "a box was prepared in a remote session's shell")

    def test_refused_in_an_agent_shell(self):
        os.environ["HERMES_SESSION_KEY"] = "agent:main:telegram:dm:1"
        rc, out = self._run("remove")
        self.assertEqual(rc, 2)
        self.assertEqual(self.uis, [], "a box was prepared in an agent's shell")

    def test_join_is_refused_in_a_remote_session_shell(self):
        """T4: a remote session cannot re-pair this device to a host of its choice with `hermes tether join`."""
        joined = []
        from tether import device as device_mod

        async def fake_join(svc, link_text):
            joined.append(link_text)
            return {"host": "10.0.0.5", "port": 4455, "host_label": "Studio"}

        os.environ[enroll.REMOTE_MARK] = "1"
        with mock.patch.object(device_mod.DeviceService, "join", fake_join), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            rc = self.cli._join(argparse.Namespace(link="tether://10.0.0.5:4455/#" + "ab" * 32 + "." + "S" * 22),
                                SimpleNamespace(roles={"device"}, name="mac"))
        self.assertEqual(rc, 2)
        self.assertEqual(joined, [], "joined from a remote session's shell")
        self.assertIn("never from a remote session's or an agent's shell", out.getvalue())

    def test_takes_no_code_or_key_on_the_command_line(self):
        """T4/T7: there is no argument to hand a code, a recovery code or a key to these commands."""
        parser = argparse.ArgumentParser()
        self.cli.setup(parser)
        self.assertEqual(parser.parse_args(["authenticator", "setup"]).auth_cmd, "setup")
        for words in (["authenticator", "setup", "123456"], ["authenticator", "setup", "--code", "123456"],
                      ["authenticator", "remove", "ABCD-EFGH-JKMN-PQRS"], ["authenticator", "setup", "--key", "X"]):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                parser.parse_args(words)

    def test_status_says_on_or_off_never_the_key(self):
        """T8: the status line says whether remote use is possible and how to turn it on; never the key."""
        off = self.cli.authenticator_line(self.data)
        self.assertIn("OFF", off)
        self.assertIn("hermes tether authenticator setup", off)
        clock = Clock(time.time())
        store = ss.SeedStore(self.data, self.backend, clock=clock)
        res = run(enroll.Enrollment(self.data, "mac", store, Person(clock), clock=clock, settle_s=0).setup())
        self.assertTrue(res.ok)
        gateway = ss.SeedStore(self.data, self.backend, publish=True)     # what the running Hermes publishes
        on = self.cli.authenticator_line(self.data)
        self.assertIn("authenticator: on (recovery codes left: 10)", on)
        self.assertFalse(base64.b32encode(seed_in(self.data)).decode()[:8] in on, "the status line shows the key")
        (self.data / authcode.STATE_FILE).unlink()
        authcode.CodeChecker(gateway, self.data).blocked()                # the gateway notices: locked
        self.assertIn("code entry is LOCKED", self.cli.authenticator_line(self.data))
        self.assertIn("hermes tether authenticator unlock", self.cli.authenticator_line(self.data))

    def test_setup_through_the_cli_needs_nothing_but_the_boxes(self):
        """G1/G2: the command seals the record with this machine's identity passphrase and finishes with the boxes
        alone; there is no `load` command (nothing to reload: no keychain)."""
        with mock.patch.object(enroll, "default_ui", lambda name: Person(Clock(time.time()))):
            rc, out = self._run("setup")
        self.assertEqual(rc, 0, out)
        self.assertEqual(ss.pointer_state(self.data), ss.PRESENT)
        parser = argparse.ArgumentParser()
        self.cli.setup(parser)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            parser.parse_args(["authenticator", "load"])

    def test_join_says_how_to_turn_the_authenticator_on(self):
        """T8: a device paired (or re-paired) without an authenticator is told remote use stays off and how."""
        from tether import device as device_mod
        from tether.identity import MemorySecretStore, load_or_create
        ident = load_or_create(temp_dir(self, "hp-enroll-id-"), MemorySecretStore(), "tether-dev")

        async def fake_join(svc, link_text):
            return {"host": "10.0.0.5", "port": 4455, "host_label": "Studio"}

        with mock.patch.object(self.cli, "identity", lambda s: ident), \
                mock.patch.object(device_mod.DeviceService, "join", fake_join), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            rc = self.cli._join(argparse.Namespace(link="tether://10.0.0.5:4455/#" + "ab" * 32 + "." + "S" * 22),
                                SimpleNamespace(roles={"device"}, name="mac"))
        self.assertEqual(rc, 0)
        self.assertIn("Remote use stays off until you set up the authenticator", out.getvalue())
        self.assertIn("hermes tether authenticator setup", out.getvalue())


class DeviceTests(unittest.IsolatedAsyncioTestCase):
    def test_device_terminals_carry_the_remote_mark(self):
        """T4: every terminal a remote session gets on the device carries the mark the CLI refuses on."""
        made = []

        class FakeEnv:
            def __init__(self, **kw):
                made.append(kw)

        import tools.environments.local as local_env
        from tether import lock
        from tether.device_exec import LocalExec
        with mock.patch.object(local_env, "LocalEnvironment", FakeEnv), mock.patch.object(lock, "_LOCKED_CLASS", None):
            LocalExec()._env("s1", 30)
        self.assertEqual(made[0]["env"].get(enroll.REMOTE_MARK), "1")
        self.assertIsNone(made[0]["env"].get("TETHER_KEY_PASSPHRASE", "missing"), "the passphrase blank was lost")

    async def test_a_running_setup_pauses_the_device(self):
        """T2/T4: while a setup runs, every grant ends and every call is refused (D48); a stale marker counts for
        nothing; the marker goes when the setup ends."""
        rig = Rig()
        self.addCleanup(rig.close)
        d = rig.host_pin.path.parent
        token = await rig.consent.require("fp", "host", "s1")
        self.assertTrue(token)
        with enroll.Busy(d):
            self.assertTrue(rig.device.paused, "a running setup did not pause the device")
            self.assertEqual(rig.consent.active(), [], "a grant outlived the start of a setup")
        self.assertFalse(rig.device.paused, "the device stayed paused after the setup")
        self.assertFalse((d / enroll.BUSY_FILE).exists(), "the marker was left behind")
        (d / enroll.BUSY_FILE).write_text(json.dumps({"at": time.time() - 3600}))
        self.assertFalse(rig.device.paused, "a stale marker paused the device")

    async def test_a_device_without_authenticator_refuses_before_any_box(self):
        """T1/T8 (upgrade from 0.2): with no authenticator the device refuses every opening call without a box, and
        nothing runs; the host tells the model a fixed sentence and closes the connection."""
        ran = []

        async def exec_(args, body):
            ran.append(args)
            return {"output": "", "returncode": 0}, b""

        rig = Rig(handlers={"exec": exec_})
        self.addCleanup(rig.close)
        d = rig.host_pin.path.parent
        rig.consent.codes = authcode.CodeChecker(ss.SeedStore(d, seal()), d)    # a 0.2 device: none
        _, task = await rig.pair()
        await task
        await rig.connect()
        self.addCleanup(rig.device._task.cancel)
        with self.assertRaises(RemoteError) as caught:
            await rig.host.call("mac", "exec", {"command": "true", "session": "s1"})
        self.assertEqual(str(caught.exception), NO_AUTHENTICATOR_TEXT)
        self.assertEqual(rig.prompt.asked, [], "a box was shown without an authenticator")
        self.assertEqual(ran, [], "work ran on a device without an authenticator")
        from tether import tools
        said = tools._opening_error(caught.exception, "mac")
        self.assertIn("no authenticator is set up there yet", said)
        self.assertIn("The connection is closed", said)
        self.assertNotIn("hermes tether authenticator", said)     # the agent is given no command to run


class BusyMarkerTests(unittest.TestCase):
    """R2-1: whatever is at authenticator.busy, a setup gets its marker or a clear refusal, never a crash."""

    def test_a_folder_or_a_raced_link_at_the_marker(self):
        d = temp_dir(self, "hp-busy-")
        marker = d / enroll.BUSY_FILE
        marker.mkdir()                                   # an empty folder: removed, the setup goes on
        with enroll.Busy(d):
            self.assertTrue(marker.is_file())
        marker.mkdir()
        (marker / "x").write_text("x")                   # a folder with something in it: refused, said plainly
        with self.assertRaises(enroll.EnrollError):
            enroll.Busy(d).__enter__()
        (marker / "x").unlink()
        marker.rmdir()
        os.symlink(d / "stale", marker)                  # a link left at the name
        real_write, raced = enroll._write, []

        def racing_write(path, data):
            if path == marker and not raced:             # and one put there at the last moment before the write
                raced.append(True)
                marker.unlink()
                os.symlink(d / "elsewhere", marker)
            return real_write(path, data)

        with mock.patch.object(enroll, "_write", racing_write):
            with enroll.Busy(d):
                self.assertTrue(marker.is_file() and not marker.is_symlink())
        self.assertTrue(raced)
        self.assertFalse((d / "elsewhere").exists() or (d / "stale").exists(), "the marker went through a link")


if __name__ == "__main__":
    unittest.main()
