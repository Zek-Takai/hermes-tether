"""D43: a grant token goes only to the key that issued it, on every close path.

Another program running as the host's user can rewrite paired_devices.json: it pins its own key B under the name the
session's device had (and may keep the real key A under another name). Every way a session can close (the idle
sweeper, an expired route, a background poll, untether, a switch) and every way it can be (re)opened (a re-pin while
the Allow prompt is up, a second 'tether mac' in the same turn) must keep A's token away from B. These tests use a
real second identity that dials the host, so a token sent "to mac" really reaches B when the code is wrong.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "plugin" / "tether"))
sys.path.insert(1, str(Path.home() / ".hermes" / "hermes-agent"))

from tether import forward, tools  # noqa: E402
from tether.device import DeviceService  # noqa: E402
from tether.identity import MemorySecretStore, load_or_create  # noqa: E402
from tether.runtime import BgJob, get_runtime  # noqa: E402
from tether.store import HostPin  # noqa: E402

from test_link_loopback import FakePrompt, consent_gate, Rig, isolate_session, temp_dir  # noqa: E402

S = "default"


class OtherKey:
    """Device identity B of another program on the host. It records every grant token it is shown."""

    def __init__(self, testcase, rig: Rig) -> None:
        d = temp_dir(testcase, "hp-b-")
        self.ident = load_or_create(d, MemorySecretStore(), "tether-other")
        real = rig.host_pin.get()
        pin = HostPin(d)
        pin.set(host="127.0.0.1", port=rig.host.listen_port, fp=real["fp"], cert_pem=real["cert_pem"], name="mac")
        self.prompt = FakePrompt(True)
        self.tokens: list[str] = []

        async def seen(args, body):
            self.tokens.append(str(args.get("grant") or ""))
            return {"returncode": 0, "output": "ran on B", "closed": True}, b""

        gate = consent_gate(idle_minutes=15, timeout_s=5, prompt=self.prompt)
        real_require = gate.require

        async def require(host_fp, label, session, *rest, **kw):
            self.tokens.append(str(kw.get("token") or ""))       # what reached B's consent gate
            return await real_require(host_fp, label, session, *rest, **kw)
        gate.require = require
        self.device = DeviceService(self.ident, pin, gate, "mac", {"exec": seen, "close_session": seen},
                                    lambda: {"rules": {"grant_idle_minutes": 15}})

    def record(self) -> dict:
        return {"fp": self.ident.fp, "cert_pem": self.ident.cert_pem.decode(), "paired_at": 0}


class GrantKeyTests(unittest.TestCase):
    def setUp(self):
        isolate_session(self)
        self.rt = get_runtime()
        self.a_closed: list[tuple[str, str]] = []

        async def a_close(args, body):
            self.a_closed.append((args.get("session"), str(args.get("grant") or "")))
            return {"closed": True}, b""

        async def a_exec(args, body):
            return {"returncode": 0, "cwd": "/w", "cwd_observed": True}, b"ran on A"

        self.rig = Rig(handlers={"exec": a_exec, "close_session": a_close},
                       capabilities={"rules": {"grant_idle_minutes": 15}})
        self.addCleanup(self.rig.close)

        async def up():
            _, task = await self.rig.pair()
            await task
            await self.rig.connect()
        self.rt.run(up(), 30)
        self.other = OtherKey(self, self.rig)
        self.addCleanup(self._stop_devices)
        self._reset()
        self.rt.host = self.rig.host
        self.addCleanup(self._reset)

    def _reset(self):
        self.rt.host = None
        for table in (self.rt.targets, self.rt.turn_open, self.rt.turn_text, self.rt.turn_wrapped,
                      self.rt.last_device, self.rt.last_activity, self.rt.idle_limit_s, self.rt.closed_note,
                      self.rt.skill_copies, self.rt.grants, self.rt.grant_fp, self.rt.working_on, self.rt.held,
                      self.rt.turn_owner, self.rt.conversation_of, self.rt.last_wall, self.rt.turn_id,
                      self.rt.open_fp, self.rt.bg_jobs, self.rt.bg_closed):
            table.clear()
        self.rt._told_elsewhere.clear()

    def _stop_devices(self):
        for dev in (self.rig.device, self.other.device):
            if dev._task is not None:
                self.rt.loop.call_soon_threadsafe(dev._task.cancel)

    # ---------- helpers ----------
    def turn(self, words, turn_id="T1"):
        forward.turn_context(session_id=S, user_message=words, turn_id=turn_id)

    def devices(self, turn_id="T1", **args):
        previous = self.rt.begin_call(turn_id)
        try:
            return json.loads(tools.handler(args))
        finally:
            self.rt.end_call(previous)

    def open(self) -> str:
        self.turn("tether mac")
        self.assertEqual(self.devices(action="use", device="mac").get("active"), "mac")
        self.assertEqual(self.rt.open_fp[S][1], self.rig.dev_ident.fp)
        return self.rt.grants[(S, "mac")]

    def write_pins(self, *, a_as=None):
        """The other program's edit: B under 'mac'; A kept under ``a_as`` (a rename swap) or dropped."""
        pins = json.loads(self.rig.pins.path.read_text())
        new = {"mac": self.other.record()}
        if a_as:
            new[a_as] = pins["mac"]
        self.rig.pins.path.write_text(json.dumps(new))

    def repin(self, *, a_as=None):
        self.write_pins(a_as=a_as)
        self.go_online(a_as)

    def go_online(self, a_as=None):
        async def wait():
            await self.rig.host._reload()
            self.other.device.start()
            for _ in range(300):
                b = self.rig.host.devices.get("mac")
                if b is not None and b.fp == self.other.ident.fp and b.announce and \
                        (a_as is None or a_as in self.rig.host.devices):
                    return
                await asyncio.sleep(0.05)
            raise AssertionError("the re-pinned keys never came online")
        self.rt.run(wait(), 40)

    def expire(self):
        self.rt.idle_limit_s["mac"] = 0.05
        self.rt.last_activity[S] = time.monotonic() - 5

    def settle(self, until=None, seconds=0.6):
        deadline = time.monotonic() + 10
        while until is not None and not until() and time.monotonic() < deadline:
            time.sleep(0.05)
        time.sleep(seconds)                    # long enough for a misdirected close to arrive

    def assert_b_never_saw(self, token):
        self.assertTrue(token)
        self.assertFalse(token in self.other.tokens, "a grant token reached a key it did not come from")

    def assert_a_closed_with(self, token):
        self.assertTrue((S, token) in self.a_closed, "the key the session was opened with was not told to close")

    # ---------- the close paths ----------
    def test_the_idle_sweeper_sends_the_close_only_to_the_key_it_came_from(self):
        token = self.open()
        forward.turn_closed(session_id=S, user_message="", turn_id="T1")
        self.repin(a_as="old-mac")                       # a rename swap: A is 'old-mac' now, B is 'mac'
        self.expire()
        self.assertEqual(self.rt.sweep_idle(), 1)
        self.settle(until=lambda: self.a_closed)
        self.assert_b_never_saw(token)
        self.assert_a_closed_with(token)                 # A, under its new name, ended the grant and the workspace

    def test_an_expired_route_after_a_repin_sends_the_old_token_nowhere(self):
        token = self.open()
        self.repin()                                     # A is no longer paired at all
        self.expire()
        self.assertEqual(self.rt.route(S), "local")
        self.settle()
        self.assert_b_never_saw(token)
        self.assertEqual(self.a_closed, [])
        self.assertIn("paired again with a different key", self.rt.closed_note[S])

    def test_a_background_poll_after_a_repin_sends_the_old_token_nowhere(self):
        token = self.open()
        job = BgJob(id="proc_0123456789ab", machine="mac", session=S, log="/tmp/hermes_bg_proc_0123456789ab.log",
                    pid_path="/tmp/hermes_bg_proc_0123456789ab.pid", exit_path="/tmp/hermes_bg_proc_0123456789ab.exit")
        self.rt.bg_start(job)
        forward.turn_closed(session_id=S, user_message="", turn_id="T1")
        self.repin()
        self.expire()
        with self.assertRaises(ConnectionError):
            self.rt.bg_call(job, "kill -0 4242", 10)     # Hermes's own poller thread, outside any turn
        self.settle()
        self.assert_b_never_saw(token)

    def test_untether_after_a_repin_inside_the_turn_sends_the_old_token_nowhere(self):
        token = self.open()
        self.turn("untether", turn_id="T2")              # the turn's own check runs first, with A still pinned
        self.repin(a_as="old-mac")                       # then the pins change inside the turn
        self.assertEqual(self.devices(turn_id="T2", action="close").get("active"), "local")
        self.settle(until=lambda: self.a_closed)
        self.assert_b_never_saw(token)
        self.assert_a_closed_with(token)

    def test_switching_after_a_repin_sends_the_old_token_nowhere(self):
        token = self.open()
        self.turn("tether pc", turn_id="T2")
        self.repin()
        pc_row = {"name": "pc", "online": True, "fp": "f" * 16, "link": {}, "capabilities": {},
                  "last_seen": None, "host_idle_minutes": None}

        async def rows(may_own=True):
            return [*self.rig.host.status(), pc_row]

        async def pc_allows(target, kind, args, body=b"", timeout=120.0, opening=False):
            self.assertEqual(target, "pc")
            return {}, b""

        with mock.patch.object(self.rig.host, "list_devices", new=rows), \
                mock.patch.object(self.rt, "device_call", new=pc_allows):
            self.assertEqual(self.devices(turn_id="T2", action="use", device="pc").get("active"), "pc")
        self.settle()
        self.assert_b_never_saw(token)

    # ---------- the open paths ----------
    def test_a_repin_while_the_allow_prompt_is_up_never_records_the_new_key(self):
        test = self

        class RepinWhileAsking(FakePrompt):
            async def __call__(self, text, timeout_s):
                self.asked.append(text)
                test.write_pins()                        # the file changes while the person reads the prompt
                return self.phone.code()
        self.rig.consent._prompt = RepinWhileAsking(True, self.rig.phone)
        self.turn("tether mac")
        self.assertEqual(self.devices(action="use", device="mac").get("active"), "mac")
        token = self.rt.grants[(S, "mac")]
        self.assertEqual(self.rt.open_fp[S][1], self.rig.dev_ident.fp, "the key read after the prompt was recorded")
        self.go_online()
        self.assertEqual(self.rt.route(S), "local")
        self.assertIn("paired again with a different key", self.rt.closed_note[S])
        with self.assertRaises(ConnectionError):
            self.rt.call_target("exec", {"command": "echo next"})
        self.settle()
        self.assert_b_never_saw(token)

    def test_a_second_tether_in_the_same_turn_after_a_repin_asks_the_new_key_afresh(self):
        token = self.open()
        self.repin()                                     # inside the user's 'tether mac' turn
        out = self.devices(action="use", device="mac")   # the model calls use again in the same turn
        self.assertEqual(out.get("active"), "mac")
        self.assertEqual(len(self.other.prompt.asked), 1, "the new key was not asked for its own Allow")
        self.assertEqual(self.rt.open_fp[S][1], self.other.ident.fp)
        self.rt.call_target("exec", {"command": "echo next"})
        self.settle()
        self.assert_b_never_saw(token)

    def test_a_renamed_device_is_told_to_close_and_the_note_says_renamed(self):
        """F65: a rename in the Tether panel keeps the key; the close (with its token) reaches it under the new name."""
        token = self.open()
        self.assertEqual(self.rig.pins.update("mac", label="studio"), "studio")

        async def studio_online():
            await self.rig.host._reload()
            for _ in range(300):
                if "studio" in self.rig.host.devices and self.rig.host.devices["studio"].announce:
                    return
                await asyncio.sleep(0.05)
            raise AssertionError("the renamed device never came back")
        self.rt.run(studio_online(), 40)
        self.assertEqual(self.rt.route(S), "local")
        self.assertIn("mac was renamed to studio", self.rt.closed_note[S])
        self.settle(until=lambda: self.a_closed, seconds=0.1)
        self.assert_a_closed_with(token)

    def test_a_grant_that_arrives_after_the_close_is_not_kept_and_is_handed_back(self):
        """F83/F12: the connection closes while a call that got a new Allow is still out. Its token is not kept (a
        later 'tether mac' must ask afresh), and it goes back to the key that issued it, which ends that grant."""
        self.open()
        self.rt.forget_grant(S, "mac")                   # the host lost its token: the next call gets a new Allow
        test = self
        real = self.rig.device.peer.handlers["exec"]

        async def close_meanwhile(args, body):
            test.rt.close_device(S, "closed meanwhile")
            return {"returncode": 0}, b"ok"
        self.rig.device.peer.handlers["exec"] = self.rig.device._guard("exec", close_meanwhile)
        try:
            self.rt.call_target("exec", {"command": "echo late"}, session=S)
        finally:
            self.rig.device.peer.handlers["exec"] = real
        self.assertFalse((S, "mac") in self.rt.grants, "a grant for a closed connection was kept")
        self.settle(until=lambda: [g for s, g in self.a_closed if g], seconds=0.1)
        self.assertEqual(len([g for s, g in self.a_closed if g]), 1, "the late grant was not handed back")


if __name__ == "__main__":
    unittest.main()
