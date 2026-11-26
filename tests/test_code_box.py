"""The approval code box (D63-D65): a session is approved only by a valid code from the person's authenticator app,
typed into the box on the device. Clicking never approves, codes are single-use and rate-limited, the box names the
pinned host and the session, the screen is frozen while it is open, and neither the code nor the seed ever leaves
the device. No real dialog is shown: boxes are fakes or stand-in processes; seeds are random test values and are
never printed (assertions use fixed messages)."""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import stat
import sys
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "plugin" / "tether"))
sys.path.insert(1, str(Path(os.environ.get("HERMES_AGENT_SRC") or Path.home() / ".hermes" / "hermes-agent")))

from tether import authcode, consent, frames  # noqa: E402
from tether.authcode import CodeChecker, MemorySeedStore  # noqa: E402
from tether.consent import ConsentGate  # noqa: E402
from tether.link import RemoteError  # noqa: E402

from test_link_loopback import FakePhone, Rig, consent_gate, isolate_session, temp_dir  # noqa: E402


class Clock:
    def __init__(self, t: float = 1_900_000_000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


def started(c: CodeChecker) -> CodeChecker:
    """As a setup leaves it: a sealed state whose newest used step is well before now (setup.commit -> start)."""
    c.start(authcode.step_at(c._clock()) - 5)
    return c


def checker(test, seed: bytes, folder=None, clock=None, wall=None, start=True) -> CodeChecker:
    folder = folder if folder is not None else temp_dir(test, "hp-codes-")
    c = CodeChecker(MemorySeedStore(seed), folder, clock=clock or Clock(), wall=wall or Clock())
    return started(c) if start else c


def code_at(seed: bytes, t: float, steps: int = 0) -> str:
    return authcode.hotp(seed, authcode.step_at(t) + steps)


async def _up(rig: Rig) -> None:
    _, task = await rig.pair()
    await task
    await rig.connect()


class Answers:
    """A box that answers from a list (None = Cancel); records each text it showed."""

    def __init__(self, *answers) -> None:
        self.answers, self.asked = list(answers), []

    async def __call__(self, text, timeout_s):
        self.asked.append(text)
        answer = self.answers.pop(0) if self.answers else None
        return answer() if callable(answer) else answer


# ---------- RFC 6238 / RFC 4226 ----------
class TotpTests(unittest.TestCase):
    def test_rfc6238_and_rfc4226_vectors(self):
        """Threat 5: the standard algorithm, so every authenticator app agrees with the box."""
        seed = b"12345678901234567890"
        rfc4226 = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"]
        self.assertEqual([authcode.hotp(seed, c) for c in range(10)], rfc4226)
        rfc6238 = {59: "94287082", 1111111109: "07081804", 1111111111: "14050471", 1234567890: "89005924",
                   2000000000: "69279037", 20000000000: "65353130"}
        for t, code in rfc6238.items():
            self.assertEqual(authcode.hotp(seed, authcode.step_at(t), 8), code, t)
            self.assertEqual(code_at(seed, t), code[-6:], t)

    def test_only_six_ascii_digits_count_as_a_code(self):
        """Threats 2, 5: a click, a word or a near-number is never a code."""
        for typed, expected in (("123456", "123456"), (" 123 456 ", "123456"), ("123-456", "123456")):
            self.assertEqual(authcode.normalize(typed), expected)
        for typed in ("", "12345", "1234567", "abcdef", "12345a", "１２３４５６",
                      "1-23456", True, None, 123456, "1" * 40):
            self.assertIsNone(authcode.normalize(typed), repr(typed)[:12])


# ---------- the check and its persisted state ----------
class CodeCheckerTests(unittest.TestCase):
    def setUp(self):
        self.seed = os.urandom(20)

    def test_each_step_is_accepted_once_also_after_a_restart(self):
        """Threat 5: a code used once is refused, by this process and by the next one (state on disk)."""
        folder, clock = temp_dir(self, "hp-codes-"), Clock()
        first = checker(self, self.seed, folder, clock)
        code = code_at(self.seed, clock.t)
        self.assertEqual(first.check(code), authcode.ACCEPTED)
        self.assertEqual(first.check(code), authcode.USED)
        restarted = checker(self, self.seed, folder, clock, start=False)
        self.assertEqual(restarted.check(code), authcode.USED, "a used code worked again after a restart")
        self.assertEqual(restarted.check(code_at(self.seed, clock.t, -1)), authcode.USED)   # older steps too
        self.assertEqual(restarted.check(code_at(self.seed, clock.t, 1)), authcode.ACCEPTED)

    def test_one_step_of_clock_skew_each_way_and_no_more(self):
        """Threat 5: the step before and after the device's own; two steps away is a wrong code."""
        clock = Clock()
        for steps, verdict in ((-1, authcode.ACCEPTED), (1, authcode.ACCEPTED), (-2, authcode.WRONG),
                               (2, authcode.WRONG)):
            self.assertEqual(checker(self, self.seed, clock=clock).check(code_at(self.seed, clock.t, steps)),
                             verdict, steps)

    def test_wrong_codes_pause_then_lock_and_the_lock_survives_a_restart(self):
        """Threat 5: 5 wrong in a row pause code entry (5, 10, 20 min); 20 lock it until the owner unlocks."""
        folder, clock, wall = temp_dir(self, "hp-codes-"), Clock(), Clock(5_000.0)
        store = MemorySeedStore(self.seed)
        c = started(CodeChecker(store, folder, clock=clock, wall=wall))
        wrong = "000000" if code_at(self.seed, clock.t) != "000000" else "111111"
        pauses = []
        for n in range(1, authcode.LOCK_AFTER + 1):
            verdict = c.check(wrong)
            if n % authcode.PAUSE_EVERY == 0 and n < authcode.LOCK_AFTER:
                self.assertEqual(verdict, authcode.PAUSED, n)
                held = c.blocked()
                pauses.append(round(held[1]))
                reads = store.reads
                self.assertEqual(c.check(code_at(self.seed, clock.t)), authcode.PAUSED)   # not even checked
                self.assertEqual(store.reads, reads, "the seed was read during a pause")
                wall.t += held[1] + 1
            elif n < authcode.LOCK_AFTER:
                self.assertEqual(verdict, authcode.WRONG, n)
        self.assertEqual(verdict, authcode.LOCKED)
        self.assertEqual(pauses, [300, 600, 1200])
        restarted = CodeChecker(store, folder, clock=clock, wall=wall)
        self.assertEqual(restarted.blocked(), (authcode.LOCKED, 0.0))
        wall.t += 7 * 24 * 3600
        self.assertEqual(restarted.check(code_at(self.seed, clock.t)), authcode.LOCKED, "a lock ended by itself")
        restarted.clear_lock()                                   # only the owner's recovery path calls this
        self.assertEqual(restarted.check(code_at(self.seed, clock.t)), authcode.ACCEPTED)

    def test_a_correct_code_resets_the_wrong_code_count(self):
        clock = Clock()
        c = checker(self, self.seed, clock=clock)
        wrong = "000000" if code_at(self.seed, clock.t) != "000000" else "111111"
        for _ in range(4):
            self.assertEqual(c.check(wrong), authcode.WRONG)
        self.assertEqual(c.check(code_at(self.seed, clock.t)), authcode.ACCEPTED)
        for _ in range(4):
            self.assertEqual(c.check(wrong), authcode.WRONG)        # a fresh run of 4: no pause yet

    def test_two_checkers_on_one_state_cannot_both_accept_one_code(self):
        """Threat 5: two boxes (or the gateway and the CLI) racing with the same code: exactly one wins."""
        folder, clock = temp_dir(self, "hp-codes-"), Clock()
        code = code_at(self.seed, clock.t)
        for _ in range(5):
            folder = temp_dir(self, "hp-codes-")
            checker(self, self.seed, folder, clock)
            checkers = [checker(self, self.seed, folder, clock, start=False) for _ in range(4)]
            verdicts, go = [], threading.Event()

            def run(c):
                go.wait(5)
                verdicts.append(c.check(code))
            threads = [threading.Thread(target=run, args=(c,)) for c in checkers]
            for t in threads:
                t.start()
            go.set()
            for t in threads:
                t.join(10)
            self.assertEqual(sorted(verdicts), [authcode.ACCEPTED] + [authcode.USED] * 3)

    def test_a_damaged_or_unreadable_state_fails_closed(self):
        folder, clock = temp_dir(self, "hp-codes-"), Clock()
        store = MemorySeedStore(self.seed)
        (folder / authcode.STATE_FILE).write_text("{not json")
        c = CodeChecker(store, folder, clock=clock)
        self.assertEqual(c.blocked(), (authcode.LOCKED, 0.0))
        self.assertEqual(c.check(code_at(self.seed, clock.t)), authcode.LOCKED)
        self.assertEqual(store.reads, 0)

    def test_a_missing_forged_or_older_state_file_locks_code_entry(self):
        """Threats 3, 5 (D68): the state is sealed with a key from the seed. Deleting it, writing one without the
        seed, or putting back an older genuine copy (to reset the wrong-code count or a used step) locks code entry
        until the owner unlocks it; the lock is written back, so a restart keeps it."""
        clock = Clock()
        wrong = "000000" if code_at(self.seed, clock.t) != "000000" else "111111"
        for attack in ("delete", "forge", "older copy", "other seed"):
            folder = temp_dir(self, "hp-codes-")
            c = checker(self, self.seed, folder, clock)
            path = folder / authcode.STATE_FILE
            old = path.read_bytes()
            for _ in range(4):
                self.assertEqual(c.check(wrong), authcode.WRONG)
            if attack == "delete":
                path.unlink()
            elif attack == "forge":
                data = json.loads(path.read_text())
                data.update(wrong=0, mac="0" * 64)
                path.write_text(json.dumps(data))
            elif attack == "older copy":
                path.write_bytes(old)
            else:
                started(CodeChecker(MemorySeedStore(os.urandom(20)), folder, clock=clock))
            self.assertEqual(c.check(code_at(self.seed, clock.t)), authcode.LOCKED, attack)
            self.assertEqual(checker(self, self.seed, folder, clock, start=False).blocked(),
                             (authcode.LOCKED, 0.0), f"{attack}: the lock did not survive a restart")
            c.clear_lock()                                   # the owner's unlock (enroll.py)
            self.assertEqual(c.check(code_at(self.seed, clock.t, 1)), authcode.USED,
                             f"{attack}: a step of the minute the file was changed in was accepted")
            clock.t += 3 * authcode.STEP_S
            self.assertEqual(c.check(code_at(self.seed, clock.t)), authcode.ACCEPTED, attack)

    def test_a_restarted_gateway_refuses_every_code_typed_before_it_started(self):
        """Threat 5 (D68): the running Hermes refuses the codes of the minute it started in, so a code typed before
        a restart is never accepted after it, whatever older copy of the state file a program put back."""
        folder, clock = temp_dir(self, "hp-codes-"), Clock()
        c = checker(self, self.seed, folder, clock)
        old = (folder / authcode.STATE_FILE).read_bytes()
        code = code_at(self.seed, clock.t)
        self.assertEqual(c.check(code), authcode.ACCEPTED)
        (folder / authcode.STATE_FILE).write_bytes(old)       # a genuine older copy, then a restart
        clock.t += 20
        restarted = CodeChecker(MemorySeedStore(self.seed), folder, clock=clock, narrow=True)
        self.assertEqual(restarted.check(code), authcode.JUST_STARTED, "a code typed before the restart worked after it")

    def test_an_unreadable_seed_refuses_and_counts_nothing(self):
        class Broken(MemorySeedStore):
            def get_seed(self):
                raise authcode.SeedUnavailable("the keychain said no")
        folder, clock = temp_dir(self, "hp-codes-"), Clock()
        c = started(CodeChecker(Broken(self.seed), folder, clock=clock))
        for _ in range(authcode.LOCK_AFTER + 1):
            self.assertEqual(c.check("123456"), authcode.UNAVAILABLE)
        self.assertIsNone(c.blocked())

    def test_a_store_that_checks_codes_itself_never_hands_over_the_seed(self):
        """Threat 3: a store with matching_steps (a helper process, a hardware-held key) is asked which steps match;
        get_seed is never called, and the answer is held to the candidate steps."""
        seed, clock = self.seed, Clock()

        class Helper(MemorySeedStore):
            def matching_steps(self, code, steps):
                return [s for s in steps if authcode.hotp(seed, s) == code] + [10 ** 9]   # an extra step ignored

            def get_seed(self):
                raise AssertionError("get_seed was called")
        c = started(CodeChecker(Helper(seed), temp_dir(self, "hp-codes-"), clock=clock))
        self.assertEqual(c.check(code_at(seed, clock.t)), authcode.ACCEPTED)
        self.assertEqual(c.check(code_at(seed, clock.t)), authcode.USED)

    def test_the_state_file_is_private_and_holds_no_secret(self):
        """Threats 3, 7: the state file is 0600 and holds only counters, never a code or the seed."""
        folder, clock = temp_dir(self, "hp-codes-"), Clock()
        c = checker(self, self.seed, folder, clock)
        code = code_at(self.seed, clock.t)
        self.assertEqual(c.check(code), authcode.ACCEPTED)
        path = folder / authcode.STATE_FILE
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        text = path.read_text()
        self.assertEqual(set(json.loads(text)), {"v", "account", "gen", "last_step", "wrong", "paused_until", "locked",
                                                 "mac"})
        for secret in secret_forms(self.seed, [code]):
            self.assertFalse(secret.found_in(text), "a code or the seed is in the state file")
        kept = {authcode.STATE_FILE} | ({authcode.LOCK_FILE} if os.name == "nt" else set())   # Windows locks a file
        self.assertEqual({p.name for p in folder.iterdir()}, kept, "a temporary file was left")


def secret_forms(seed: bytes, codes) -> list["Secret"]:
    return [Secret(seed.hex()), Secret(base64.b32encode(seed).decode().rstrip("=")),
            Secret(base64.b64encode(seed).decode()), Secret(seed.decode("latin-1")), *(Secret(c) for c in codes)]


class Secret(str):
    """A seed form, or a code that counts only as a number of its own (never inside a longer run of digits such as
    a timestamp)."""

    def found_in(self, text: str) -> bool:
        import re
        if self.isdigit() and len(self) == 6:
            return re.search(r"(?<![0-9])" + str(self) + r"(?![0-9])", text) is not None
        return str(self) in text


# ---------- the box flow at the gate ----------
class BoxFlowTests(unittest.IsolatedAsyncioTestCase):
    def gate(self, box, phone=None, **kw):
        phone = phone or FakePhone()
        self.phone = phone
        return consent_gate(prompt=box, phone=phone, idle_minutes=15, timeout_s=60, **kw)

    async def test_clicking_approve_never_approves(self):
        """Threat 2: the old Yes (True), Approve with nothing typed, a word, a wrong code, Cancel: none approves."""
        for answer in (True, "", "Approve", "yes", "000000", None, 1):
            box = Answers(answer, answer, answer)
            gate = self.gate(box)
            with self.assertRaises(PermissionError):
                await gate.require("fp", "Hermes on nas", "s1")
            self.assertEqual(gate.live_sessions(), set(), f"{answer!r} approved a session")

    async def test_three_tries_per_box_then_deny(self):
        """Threat 5: three submits per request; the fourth is never shown and the session cools down."""
        phone = FakePhone()
        wrong = lambda: "000000" if phone.code() != "000000" else "111111"   # noqa: E731
        box = Answers(wrong, wrong, wrong, wrong)
        gate = self.gate(box, phone)
        with self.assertRaisesRegex(PermissionError, "did not allow remote use"):
            await gate.require("fp", "Hermes on nas", "s1")
        self.assertEqual(len(box.asked), 3)
        self.assertIn("That code was not accepted. 1 try left.", box.asked[-1])
        with self.assertRaisesRegex(PermissionError, "refused moments ago"):
            await gate.require("fp", "Hermes on nas", "s1")
        self.assertEqual(len(box.asked), 3)

    async def test_a_mistyped_box_is_shown_again_and_then_a_valid_code_approves(self):
        phone = FakePhone()
        box = Answers("12345", phone.code)
        gate = self.gate(box, phone)
        self.assertTrue(await gate.require("fp", "Hermes on nas", "s1"))
        self.assertTrue(box.asked[1].startswith("Type the 6 digits from your authenticator app. 2 tries left."))

    async def test_a_code_typed_for_one_request_cannot_open_another(self):
        """Threat 5: the person's code for s1, typed again into a box for s2 within the same 30 s, is refused."""
        phone = FakePhone()
        code = phone.code()
        box = Answers(code, code, None)
        gate = self.gate(box, phone)
        self.assertTrue(await gate.require("fp", "Hermes on nas", "s1"))
        with self.assertRaises(PermissionError):
            await gate.require("fp", "Hermes on nas", "s2")
        self.assertIn("That code was already used", box.asked[2])
        self.assertEqual(gate.live_sessions(), {"s1"})

    async def test_no_authenticator_means_no_box_and_a_clear_refusal(self):
        """Threat 8 / fail closed: a device with no authenticator never shows a box and never falls back to Yes/No."""
        box = Answers(True)
        events = temp_dir(self, "hp-ev-")
        gate = ConsentGate(prompt=box, idle_minutes=15, timeout_s=60)      # the default store: nothing set up
        gate.events_dir = events
        with self.assertRaises(PermissionError) as cm:
            await gate.require("fp", "Hermes on nas", "s1")
        self.assertEqual(str(cm.exception), consent.NO_AUTHENTICATOR_TEXT)
        self.assertIn("did not allow remote use", str(cm.exception))      # the host closes the connection on it
        self.assertEqual(box.asked, [])
        from tether.store import read_events
        self.assertEqual(read_events(events)[0]["reason"], "no authenticator set up")

    async def test_a_locked_device_shows_no_box(self):
        phone = FakePhone()
        box = Answers(phone.code)
        gate = self.gate(box, phone)
        gate.codes._mem["locked"] = True
        with self.assertRaisesRegex(PermissionError, "locked after too many wrong codes"):
            await gate.require("fp", "Hermes on nas", "s1")
        self.assertEqual(box.asked, [])

    async def test_the_seed_is_read_only_after_a_code_was_typed(self):
        """Threat 3: no refusal path, no Cancel and no non-code reads the seed; the gate never keeps it."""
        phone = FakePhone()
        for answer in (None, "", "abc", True):
            gate = self.gate(Answers(answer, answer, answer), phone)
            with self.assertRaises(PermissionError):
                await gate.require("fp", "Hermes on nas", "s1")
        gate = self.gate(Answers(phone.code), phone)
        gate.codes._mem["locked"] = True
        with self.assertRaises(PermissionError):
            await gate.require("fp", "Hermes on nas", "s2")
        self.assertEqual(phone.store.reads, 0, "the seed was read without a typed code")
        gate = self.gate(Answers(phone.code), phone)
        self.assertTrue(await gate.require("fp", "Hermes on nas", "s3"))
        self.assertEqual(phone.store.reads, 1)
        held = repr(vars(gate)) + repr(vars(gate.codes))
        self.assertFalse(phone.seed.hex() in held or repr(phone.seed) in held, "the gate kept the seed")

    async def test_the_box_names_the_pinned_host_the_session_and_when_it_closes(self):
        """Threat 6: who asks (as recorded at pairing), which session, only if you just asked, when it gives up."""
        phone = FakePhone()
        box = Answers(phone.code, None)
        gate = self.gate(box, phone)
        paired = time.mktime((2026, 11, 2, 12, 0, 0, 0, 0, -1))
        before = time.time()
        await gate.require("fp", "Hermes on nas", "20261121_101500_ab12cd", paired_at=paired)
        text = box.asked[0]
        self.assertTrue(text.startswith("Hermes on nas wants to use this computer.\nSession: 20261121_101500_ab12cd"))
        self.assertIn("Host paired here on 2 Nov 2026.", text)
        self.assertIn("Only approve if you just asked Hermes for this yourself. If you did not, press Cancel.", text)
        self.assertIn('type the 6-digit code from your authenticator app (entry "Hermes Tether")', text)
        closes = time.strftime("%H:%M:%S", time.localtime(before + 60))
        later = time.strftime("%H:%M:%S", time.localtime(before + 61))
        self.assertTrue(f"This box closes at {closes}" in text or f"This box closes at {later}" in text)
        with self.assertRaises(PermissionError):
            await gate.require("fp", "Hermes on nas", "20261121_101500_ab12cd")    # another caller, no token
        self.assertIn("asks AGAIN to use this computer for session 20261121_101500_ab12cd", box.asked[1])


# ---------- through the link ----------
class DeviceBoxTests(unittest.IsolatedAsyncioTestCase):
    async def test_forged_calls_only_ever_open_the_box(self):
        """Threat 1: a host program with the host's key can make the box appear, never get a grant without a code:
        no token, a forged token, forged session ids, a parallel batch, passive calls, screen and skill calls,
        closes. Here the person (or a clicker) only ever clicks."""
        ran = []

        async def handler(args, body):
            ran.append(args.get("session"))
            return {"output": "ran"}, b""
        clicks = [True, "", "Approve"]

        async def close(args, body):                 # as SessionControl.close_session decides it (D33)
            if not rig.consent.release(rig.host_ident.fp, args["session"], str(args.get("grant") or "")):
                raise PermissionError("this session is open from another program on the host; it was not closed")
            return {"closed": True}, b""
        rig = Rig(handlers={"exec": handler, "cu": handler, "skill_put": handler, "close_session": close})
        self.addCleanup(rig.close)
        box = Answers(*(clicks * 40))
        rig.consent._prompt = box
        await _up(rig)
        self.addCleanup(rig.device._task.cancel)
        attempts = [("exec", {"session": "s1"}), ("exec", {"session": "s1", "grant": "forged"}),
                    ("cu", {"session": "s2", "method": "capture"}), ("skill_put", {"session": "s3"}),
                    ("exec", {"session": "s4", "passive": True}), ("exec", {"session": "s5", "passive": True,
                                                                            "grant": "forged"})]
        for kind, args in attempts:
            with self.assertRaises(RemoteError):
                await rig.host.call("mac", kind, {"command": "true", **args}, b"x" if kind == "skill_put" else b"")
        batch = await asyncio.gather(*(rig.host.call("mac", "exec", {"command": "true", "session": f"p{n}"})
                                       for n in range(3)), return_exceptions=True)
        self.assertTrue(all(isinstance(r, RemoteError) for r in batch))
        await rig.host.call("mac", "close_session", {"session": "s1", "grant": "forged"})
        self.assertEqual(ran, [], "work ran without a valid code")
        self.assertEqual(rig.consent.live_sessions(), set(), "a grant was issued without a valid code")
        requests = [t for t in box.asked if not t.startswith(("Type the 6 digits", "That code"))]   # retypes aside
        # s1, s2, s3 and the batch of 3; s1's forged retry met the cool-down; passive calls and closes never ask
        self.assertEqual(len(requests), 3 + 3)

    async def test_the_box_shows_the_label_recorded_at_pairing_not_the_hosts_current_one(self):
        """Threat 6: after pairing, the host (or a stolen host key) names itself differently: the box keeps the
        label recorded on the device when it was paired, and says when that was."""
        rig = Rig()
        self.addCleanup(rig.close)
        await _up(rig)
        self.addCleanup(rig.device._task.cancel)
        rig.host.label = "Hermes on your-bank"                 # what the host says in its next hello
        rig.device._redial.set()
        await rig.device.peer.close()                          # reconnect: the new hello carries the new label
        for _ in range(100):
            if rig.device.host_label == "Hermes on your-bank":
                break
            await asyncio.sleep(0.05)
        self.assertEqual(rig.device.host_label, "Hermes on your-bank")
        await rig.host.call("mac", "exec", {"command": "true", "session": "s1"})
        text = rig.prompt.asked[-1]
        self.assertTrue(text.startswith("Test host wants to use this computer."), "the box took the host's word")
        self.assertNotIn("your-bank", text)
        self.assertIn("Host paired here on ", text)

    async def test_codes_and_seeds_never_leave_the_device(self):
        """Threat 7: approve with a real code over the link; neither the code nor the seed is in any frame either
        way, the connection log, the log records or the errors."""
        rig = Rig()
        self.addCleanup(rig.close)
        rig.consent.events_dir = rig.host_pin.path.parent
        typed: list[str] = []
        phone = rig.phone

        async def person(text, timeout_s):
            code = phone.code()
            typed.append(code)
            return code if len(typed) != 2 else "000000" if code != "000000" else "111111"
        rig.consent._prompt = person
        sent: list[str] = []
        real = frames.write_frame

        async def spy(writer, header, body=b"", lock=None):
            sent.append(json.dumps(header) + body.decode("latin-1"))
            return await real(writer, header, body, lock)
        errors = []
        with mock.patch.object(frames, "write_frame", spy), \
                self.assertLogs("tether", level=logging.DEBUG) as logs:
            await _up(rig)
            data, _ = await rig.host.call("mac", "exec", {"command": "echo ok", "session": "s1"})
            self.assertTrue(data.get("grant"))
            try:
                await rig.host.call("mac", "exec", {"command": "echo no", "session": "s2"})
            except RemoteError as e:
                errors.append(str(e))
            logging.getLogger("tether").debug("end")
            rig.device._task.cancel()
        events = (rig.host_pin.path.parent / "events.jsonl").read_text()
        blob = "\n".join(sent + logs.output + errors + [events])
        self.assertTrue(sent and typed)
        for secret in secret_forms(phone.seed, typed):
            self.assertFalse(secret.found_in(blob), "a code or the seed left the box")


# ---------- the screen while the box is open ----------
class ScreenFreezeTests(unittest.IsolatedAsyncioTestCase):
    def screen(self, gate, driver):
        from tether.device_screen import ScreenExec
        screen = ScreenExec(gate)
        screen._backend = driver
        return screen

    async def test_every_screen_action_is_refused_while_the_box_is_open(self):
        """Threat 2: input and screenshots alike (base: a screenshot went through while the prompt was open)."""
        calls = []

        class Driver:
            def __getattr__(self, name):
                return lambda **kw: calls.append(name) or []
        gate = consent_gate()
        screen = self.screen(gate, Driver())
        gate.screen_frozen = True
        for method in ("capture", "list_apps", "list_windows", "wait", "click", "type_text", "key"):
            with self.assertRaisesRegex(PermissionError, "approval box is open"):
                await screen.call({"method": method, "kwargs": {}}, b"")
        self.assertEqual(calls, [], "a screen action reached the driver while the box was open")

    async def test_the_box_waits_for_a_running_screen_action_and_is_not_shown_over_a_stuck_one(self):
        """Threat 2: an action already inside the driver when a request comes (a long type_text) finishes before the
        box appears; one that never finishes keeps the box from appearing at all."""
        release, inside = threading.Event(), threading.Event()
        order = []

        class Driver:
            def type_text(self, **kw):
                inside.set()
                release.wait(10)
                order.append("action done")
                return []
        phone = FakePhone()

        async def box(text, timeout_s):
            order.append("box shown")
            return phone.code()
        gate = consent_gate(prompt=box, phone=phone, timeout_s=60)
        screen = self.screen(gate, Driver())
        gate.screen_drain = screen.drain
        action = asyncio.create_task(screen.call({"method": "type_text", "kwargs": {"text": "x"}}, b""))
        self.assertTrue(await asyncio.to_thread(inside.wait, 5))
        asking = asyncio.create_task(gate.require("fp", "Hermes on nas", "s1"))
        await asyncio.sleep(0.3)
        self.assertEqual(order, [], "the box opened over a running screen action")
        release.set()
        await action
        self.assertTrue(await asking)
        self.assertEqual(order, ["action done", "box shown"])

        stuck, entered = threading.Event(), threading.Event()

        class Stuck:
            def wait(self, **kw):
                entered.set()
                stuck.wait(10)
                return []
        gate2 = consent_gate(prompt=box, phone=phone, timeout_s=60)
        screen2 = self.screen(gate2, Stuck())
        gate2.screen_drain = screen2.drain
        hung = asyncio.create_task(screen2.call({"method": "wait", "kwargs": {}}, b""))
        self.assertTrue(await asyncio.to_thread(entered.wait, 5))
        order.clear()
        with mock.patch.object(consent, "SCREEN_DRAIN_S", 0.3):
            with self.assertRaisesRegex(PermissionError, "screen was busy"):
                await gate2.require("fp", "Hermes on nas", "s1")
        self.assertEqual(order, [])
        self.assertFalse(gate2.screen_frozen)
        stuck.set()
        await hung


# ---------- the box processes ----------
@unittest.skipIf(sys.platform == "win32", "uses a POSIX shell stand-in for the dialog program")
class BoxProcessTests(unittest.IsolatedAsyncioTestCase):
    def stand_in(self, answer_file: Path) -> Path:
        """A stand-in for osascript / powershell.exe: records its arguments, environment and stdin; prints the
        answer it finds in answer_file (the test writes the code there, so it is never in an argument)."""
        d = temp_dir(self, "hp-box-")
        exe = d / "dialog"
        exe.write_text("#!/bin/sh\n"
                       f'printf "%s\\n" "$@" > "{d}/args"\n'
                       f'env > "{d}/env"\n'
                       f'cat > "{d}/stdin"\n'
                       f'cat "{answer_file}"\n')
        exe.chmod(0o755)
        return exe

    async def test_the_box_processes_never_see_the_code_or_the_seed(self):
        """Threats 7, 2: the text reaches osascript on stdin (PowerShell: in the environment), the code comes back
        on stdout, and neither the code nor the seed is in either program's arguments or environment."""
        for system in ("Darwin", "Windows"):
            phone = FakePhone()
            answer = temp_dir(self, "hp-ans-") / "answer"
            exe = self.stand_in(answer)
            typed = []

            async def box(text, timeout_s, system=system):
                code = phone.code()
                typed.append(code)
                answer.write_text("CODE:" + code)
                fn = consent.macos_code_box if system == "Darwin" else consent.windows_code_box
                return await fn(text, timeout_s)
            gate = consent_gate(prompt=box, phone=phone, timeout_s=60)
            with mock.patch.object(consent, "OSASCRIPT", str(exe)), \
                    mock.patch.object(consent, "_powershell", lambda: str(exe)):
                self.assertTrue(await gate.require("fp", "Hermes on nas", "20261121_101500_ab12cd"), system)
            d = exe.parent
            args, env, stdin = ((d / name).read_text() for name in ("args", "env", "stdin"))
            for secret in secret_forms(phone.seed, typed):
                self.assertFalse(secret.found_in(args + env + stdin),
                                 f"{system}: a code or the seed reached the dialog program")
            if system == "Darwin":
                self.assertEqual(args, "-\n")                                  # the script comes on stdin
                self.assertIn("with hidden answer", stdin)
                self.assertIn("20261121_101500_ab12cd", stdin)
                self.assertNotIn("TETHER_BOX_TEXT", env)
            else:
                self.assertNotIn("20261121_101500_ab12cd", args)               # the text only in the environment
                self.assertIn("20261121_101500_ab12cd", env)
                self.assertIn("UseSystemPasswordChar = $true", args)


# ---------- what the agent is told ----------
class AgentTextTests(unittest.TestCase):
    def test_refusals_become_fixed_sentences_that_never_ask_for_a_code(self):
        """Threat 8: each refusal of the new box reaches the model as a fixed sentence that says what happened,
        closes the connection, and tells the agent never to ask the user for a code."""
        from tether import tools
        cases = {
            consent.DENIED_TEXT: "no valid code was entered in the approval box there",
            consent.NO_AUTHENTICATOR_TEXT: "no authenticator is set up there yet",
            authcode.SET_UP_AGAIN_TEXT: "must be set up again at that machine",
            authcode.NO_SAFE_STORE_TEXT: "no safe place to keep an authenticator",
            consent.LOCKED_TEXT: "locked after too many wrong codes until its owner unlocks it",
            consent.PAUSED_CODES_TEXT.format(minutes=7): "paused after several wrong codes (about 7 min left)",
            consent.UNAVAILABLE_TEXT: "could not check the approval code there",
            consent.SCREEN_BUSY_TEXT: "its screen was busy",
            consent.LATE_TEXT: "did not show its approval box",
        }
        for reply, expected in cases.items():
            text = tools._opening_error(RemoteError(reply), "mac")
            self.assertIn(expected, text)
            self.assertIn("Never ask the user for an approval code", text)
            self.assertNotIn("its reply is not shown", text)
            self.assertNotIn("hermes tether", text, "the model was handed a command")
        for reply in list(cases)[:7]:
            self.assertIn("did not allow remote use", reply)      # runtime.DENIED: the host closes the connection


# ---------- the device role's wiring ----------
class DeviceWiringTests(unittest.TestCase):
    def test_the_device_role_checks_codes_on_its_data_folder_and_drains_the_screen(self):
        """Threats 1, 3, 8: the device role checks codes against the sealed record in its own data folder (sealed with
        the identity's passphrase), refuses the codes of its first minute, and waits for the screen before a box."""
        try:
            import agent.terminal_env_provider  # noqa: F401
        except Exception:  # noqa: BLE001
            self.skipTest("Hermes source not importable")
        import importlib
        from test_plugin_register import Ctx, load_plugin
        from tether.runtime import get_runtime
        isolate_session(self)
        home = temp_dir(self, "hp-home-")
        rt = get_runtime()
        if rt.device is not None:
            self.skipTest("a device role is already running in this process")
        plugin = load_plugin()
        seeds_mod = importlib.import_module(plugin.__name__ + ".tether.seedstore")
        made = []

        def backend_for(folder, secret=None):
            made.append(seeds_mod.PassphraseSeal(secret))
            return made[-1]
        with mock.patch.dict(os.environ, {"HERMES_HOME": str(home)}), \
                mock.patch.object(plugin, "_in_gateway", lambda: True), \
                mock.patch.object(seeds_mod, "default_backend", backend_for):
            plugin.register(Ctx({"role": "device", "name": "mac"}))
        device = rt.device
        try:
            gate = rt.consent
            self.assertIsInstance(gate.codes.store, seeds_mod.SeedStore)
            self.assertIs(gate.codes.store.backend, made[0])
            self.assertTrue(len(made[0]._key()) == 32, "the seal key comes from the identity's passphrase")
            self.assertIs(device.seeds, gate.codes.store)
            self.assertEqual(Path(gate.codes.folder).resolve(), (home / "tether").resolve())
            self.assertEqual(gate.screen_drain, device._handlers["cu"].__self__.drain)
            self.assertGreater(gate.codes._floor, 0, "the gateway does not refuse the codes of its first minute")
            self.assertEqual(gate.codes.refusal(), consent.NO_AUTHENTICATOR_TEXT)   # nothing set up: refused
        finally:
            def stop():
                for name in ("_task", "_settings_task", "_sweeper"):
                    task = getattr(device, name, None) if device is not None else None
                    if task is not None:
                        task.cancel()
            done = threading.Event()
            rt.loop.call_soon_threadsafe(lambda: (stop(), done.set()))
            done.wait(5)
            rt.device = None
            rt.consent = None


if __name__ == "__main__":
    unittest.main()


class JustStartedTests(unittest.TestCase):
    def setUp(self):
        self.seed = bytes(range(20))

    def test_a_right_code_right_after_a_restart_says_wait_and_the_next_code_works(self):
        """First live test, 2026-11-22: right after the Mac's Hermes restarted, the box kept refusing right codes and
        the person could not tell why. They are refused on purpose (D68); the box now says to wait for the next code."""
        folder, clock = temp_dir(self, "hp-codes-"), Clock()
        c = started(CodeChecker(MemorySeedStore(self.seed), folder, clock=clock, narrow=True))   # a set-up machine
        verdict = c.check(code_at(self.seed, clock.t))
        self.assertEqual(verdict, authcode.JUST_STARTED, "a right code right after a start is not told apart")
        note = consent._note(verdict, 2)
        self.assertIn("started moments ago", note, "the box does not say why the code was refused")
        self.assertNotIn("already used", note, "the box blames the person for a code they never used")
        clock.t += 61
        self.assertEqual(c.check(code_at(self.seed, clock.t)), authcode.ACCEPTED, "the next code after the wait failed")

    def test_a_code_this_process_just_accepted_is_still_already_used(self):
        folder, clock = temp_dir(self, "hp-codes-"), Clock()
        c = started(CodeChecker(MemorySeedStore(self.seed), folder, clock=clock, narrow=True))
        clock.t += 61
        code = code_at(self.seed, clock.t)
        self.assertEqual(c.check(code), authcode.ACCEPTED)
        self.assertEqual(c.check(code), authcode.USED, "a code just accepted here is called a restart refusal")
