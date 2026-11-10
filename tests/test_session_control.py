"""D23/D24: only the user's words open or close a device connection; the idle timer closes it; background reviews
stay on the host; the device keeps a per-session workspace that is wiped on close; skills arrive read-only."""
from __future__ import annotations

import io
import json
import os
import stat
import sys
import tarfile
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "plugin" / "tether"))
sys.path.insert(1, str(Path.home() / ".hermes" / "hermes-agent"))

from tether import forward, tools  # noqa: E402
from tether.consent import ConsentGate  # noqa: E402
from tether.device_exec import LocalExec, SessionControl  # noqa: E402
from tether.runtime import get_runtime  # noqa: E402
from tether.workspace import Workspaces  # noqa: E402

from test_link_loopback import FakePrompt, Rig  # noqa: E402


class WorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.ws = Workspaces(Path(tempfile.mkdtemp(prefix="hp-ws-")) / "sessions")

    def test_ensure_wipe_sweep(self):
        a = self.ws.ensure("s/1:a")                          # unsafe characters are neutralised
        self.assertEqual(oct(a.stat().st_mode & 0o777), "0o700")
        (a / "scratch.txt").write_text("x")
        b = self.ws.ensure("s2")
        self.assertEqual(self.ws.sweep({"s2"}), 1)           # no grant for s/1:a any more
        self.assertFalse(a.exists())
        self.assertTrue(self.ws.wipe("s2"))
        self.assertFalse(b.exists())

    def _tar(self, entries):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            for name, data in entries:
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        return buf.getvalue()

    def test_skill_copy_is_read_only_and_wipeable(self):
        dest = self.ws.put_skill("s1", "cad", self._tar([("SKILL.md", b"# cad"), ("scripts/run.py", b"print(1)")]))
        self.assertEqual(oct(dest.parent.stat().st_mode & 0o777), "0o700")      # skills/ is owner-only
        self.assertEqual((dest / "scripts" / "run.py").read_text(), "print(1)")
        self.assertFalse(os.stat(dest / "SKILL.md").st_mode & stat.S_IWUSR)
        with self.assertRaises(PermissionError):
            (dest / "SKILL.md").write_text("changed")
        self.assertTrue(self.ws.wipe("s1"))                  # read-only does not stop the close from removing it

    def test_skill_copy_rejects_path_escape(self):
        with self.assertRaises(Exception):
            self.ws.put_skill("s1", "evil", self._tar([("../../outside.txt", b"x")]))
        self.assertFalse((self.ws.root.parent / "outside.txt").exists())


class UserWordsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rt = get_runtime()
        cls.closed = []
        cls.prompt_count = 0

        async def close_session(args, body):
            cls.closed.append(args["session"])
            return {"closed": True}, b""

        async def exec_ok(args, body):
            return {"returncode": 0, "cwd": "/w", "cwd_observed": True}, b"ok"

        cls.puts = []

        async def skill_put(args, body):
            cls.puts.append((args["name"], len(body)))
            return {"path": f"/Users/z/.hermes/tether/sessions/{args['session']}/skills/{args['name']}"}, b""

        cls.rig = Rig(handlers={"close_session": close_session, "exec": exec_ok, "skill_put": skill_put},
                      capabilities={"rules": {"grant_idle_minutes": 1}})
        cls.rig.device.UNGUARDED = frozenset({"close_session"})

        async def up():
            _, task = await cls.rig.pair()
            await task
            await cls.rig.connect()
        cls.rt.run(up(), 30)

    @classmethod
    def tearDownClass(cls):
        cls.rt.loop.call_soon_threadsafe(cls.rig.device._task.cancel)

    def setUp(self):
        self.rt.host = self.rig.host
        for d in (self.rt.targets, self.rt.turn_open, self.rt.turn_text, self.rt.last_device, self.rt.last_activity,
                  self.rt.idle_limit_s, self.rt.closed_note, self.rt.skill_copies):
            d.clear()
        os.environ.pop("HERMES_SESSION_ID", None)
        forward._facts.clear()

    def tearDown(self):
        self.rt.host = None
        self.rt.targets.clear()
        self.rt.turn_open.clear()

    def turn(self, words):
        forward.turn_context(session_id="default", user_message=words)

    def devices(self, **args):
        return json.loads(tools.handler(args))

    def test_open_needs_the_users_words(self):
        for words in ("can you check something for me", "open bambu studio on the mac",
                      "we are running on mac", "use the mac", "untether mac"):
            self.turn(words)
            err = self.devices(action="use", device="mac")["error"]
            self.assertIn("says 'tether mac'", err, words)
            self.assertEqual(self.rt.route("default"), "local", words)
        self.turn("tether mac")
        out = self.devices(action="use", device="mac")
        self.assertEqual(out["active"], "mac")
        self.assertIn("It runs ", out["machine"])          # the device announced itself on connect
        self.assertEqual(self.rt.route("default"), "mac")

    def test_tether_and_untether_words(self):
        self.assertTrue(tools.names_device("tether studio pc", "studio-pc"))
        self.assertTrue(tools.names_device("Tether Mac please", "mac"))
        self.assertFalse(tools.names_device("open the macro editor", "mac"))
        self.assertTrue(tools.asked_to_open("tether studio pc", "studio-pc"))
        self.assertTrue(tools.asked_to_open("ok, Tether-Mac please", "mac"))
        self.assertFalse(tools.asked_to_open("open bambu studio on the mac", "mac"))
        self.assertFalse(tools.asked_to_open("tether the mac", "mac"))
        self.assertFalse(tools.asked_to_open("untether mac", "mac"))
        self.assertFalse(tools.asked_to_open("tether macro", "mac"))
        for solo in ("untether", "Untether", "  untether.  ", "UNTETHER!"):
            self.assertTrue(tools.asked_to_close(solo, "mac"), solo)
        for not_solo in ("untether mac", "ok untether", "good it worked thank you. untether", "untethered",
                         "please untether now", "close mac connection", "go home", "tether mac and keep going"):
            self.assertFalse(tools.asked_to_close(not_solo, "mac"), not_solo)
        self.turn("tether mac")
        self.assertEqual(self.devices(action="use", device="mac")["active"], "mac")
        self.turn("untether")
        self.assertEqual(self.devices(action="close")["active"], "local")
        from tether.store import read_events
        kinds = [(e["kind"], e.get("device")) for e in read_events(self.rig.host.pins.path.parent, 5)]
        self.assertEqual(kinds[:2], [("untethered", "mac"), ("tethered", "mac")])   # the panel's log

    def test_close_needs_the_users_words_and_reaches_the_device(self):
        self.turn("tether mac")
        self.devices(action="use", device="mac")
        self.turn("now make a file")
        self.assertIn("only the user can close", self.devices(action="close")["error"])
        self.assertEqual(self.rt.route("default"), "mac")
        for words in ("ok close mac connection", "thanks, untether", "untether mac"):
            self.turn(words)
            err = self.devices(action="close")["error"]
            self.assertIn("'untether' as a message on its own", err, words)
            self.assertEqual(self.rt.route("default"), "mac", words)
        self.turn("untether")
        self.assertEqual(self.devices(action="close")["active"], "local")
        self.assertEqual(self.rt.route("default"), "local")
        self.assertNotIn("default", self.rt.last_device)      # no attachment fallback after a close
        for _ in range(50):
            if "default" in self.closed:
                break
            time.sleep(0.05)
        self.assertIn("default", self.closed)                 # the device was told to wipe the workspace

    def test_use_waits_for_consent_before_reporting_active(self):
        self.rig.consent.revoke_all()
        self.rig.prompt.asked.clear()
        self.turn("tether mac")
        out = self.devices(action="use", device="mac")
        self.assertEqual(out["active"], "mac")
        self.assertEqual(len(self.rig.prompt.asked), 1)      # the device asked during use, not on a later call
        self.assertEqual(self.rt.route("default"), "mac")

    def test_use_denied_is_not_connected(self):
        self.rig.consent.revoke_all()
        self.rig.prompt.answer = False
        try:
            self.turn("tether mac")
            out = self.devices(action="use", device="mac")
        finally:
            self.rig.prompt.answer = True
        self.assertNotIn("active", out)
        self.assertIn("Not connected", out["error"])
        self.assertIn("did not allow remote use", out["error"])
        self.assertEqual(self.rt.active_target("default"), "local")
        self.assertEqual(self.rt.route("default"), "local")

    def test_denial_drops_back_to_the_host(self):
        from tether.provider import make_provider
        self.turn("tether mac")
        self.devices(action="use", device="mac")
        self.rig.consent.revoke_all()
        self.rig.prompt.answer = False
        try:
            env = make_provider().create_environment(cwd="/w", timeout=10, task_id="deny")
            out = env.execute("echo hi")
        finally:
            self.rig.prompt.answer = True
        self.assertEqual(out["returncode"], 1)
        self.assertIn("did not allow remote use", out["output"])
        self.assertIn("you are on your host again", out["output"])
        self.assertEqual(self.rt.active_target("default"), "local")   # not left pointing at the mac
        self.assertEqual(self.rt.route("default"), "local")
        text = forward.turn_context(session_id="default", user_message="try again")
        self.assertIn("The mac connection is closed (the person at mac did not allow it)", text)
        self.assertNotIn("working ON", text)

    def test_idle_timer_closes(self):
        self.turn("tether mac")
        self.devices(action="use", device="mac")
        self.rt.idle_limit_s["mac"] = 0.05
        self.rt.last_activity["default"] = time.monotonic() - 1
        text = forward.turn_context(session_id="default", user_message="still there?")
        self.assertIn("timed out", text)
        self.assertEqual(self.rt.route("default"), "local")

    def test_timer_known_from_the_open_and_reported_next_turn(self):
        self.turn("tether mac")
        self.devices(action="use", device="mac")
        self.assertEqual(self.rt.idle_limit_s.get("mac"), 60.0)      # learned when the connection opened
        forward.turn_closed(session_id="default", user_message="tether mac")
        self.rt.last_activity["default"] = time.monotonic() - 120
        text = forward.turn_context(session_id="default", user_message="are you still on the mac?")
        self.assertIn("The mac connection is closed (timed out after 1 idle minutes)", text)
        self.assertNotIn("working ON", text)
        self.assertEqual(self.rt.route("default"), "local")

    def test_timer_learned_from_the_facts_is_honoured_the_same_turn(self):
        self.rt.targets["default"] = "mac"                           # open, but its timer not yet known
        self.rt.last_activity["default"] = time.monotonic() - 120
        text = forward.turn_context(session_id="default", user_message="still there?")
        self.assertIn("timed out after 1 idle minutes", text)
        self.assertNotIn("working ON", text)

    def test_review_never_routes_to_the_device(self):
        self.turn("tether mac")
        self.devices(action="use", device="mac")
        forward.turn_closed(session_id="default", user_message="tether mac")
        self.assertEqual(self.rt.route("default"), "local")          # after the user's turn: host only
        forward.turn_context(session_id="default", user_message="Review the conversation above and update ...")
        self.assertEqual(self.rt.route("default"), "local")          # a review never opens a turn
        out = forward.tool_execution(tool_name="write_file", args={"path": "/x", "content": "y"},
                                     next_call=lambda a: "HOST", session_id="default", task_id="t")
        self.assertEqual(out, "HOST")

    def test_host_owned_paths_stay_on_the_host(self):
        self.turn("tether mac")
        self.devices(action="use", device="mac")
        home = os.environ.get("HERMES_HOME") or os.path.expanduser("~/.hermes")
        out = forward.tool_execution(tool_name="patch", args={"path": f"{home}/skills/cad/SKILL.md"},
                                     next_call=lambda a: "HOST", session_id="default", task_id="t")
        self.assertEqual(out, "HOST")


class SkillCopyTests(UserWordsTests):
    """Reuses the rig above; only the skill-copy hook is exercised here."""

    def test_skill_view_while_on_a_device_copies_once(self):
        skill = Path(tempfile.mkdtemp(prefix="hp-skill-")) / "cad"
        (skill / "scripts").mkdir(parents=True)
        (skill / "SKILL.md").write_text("# cad")
        (skill / "scripts" / "run.py").write_text("print(1)")
        result = json.dumps({"success": True, "name": "cad", "skill_dir": str(skill), "content": "# cad"})
        self.assertIsNone(forward.skill_files(tool_name="skill_view", result=result, session_id="default"))  # local
        self.turn("tether mac")
        self.devices(action="use", device="mac")
        before = len(self.puts)
        out = json.loads(forward.skill_files(tool_name="skill_view", result=result, session_id="default"))
        self.assertTrue(out["on_device"]["path"].endswith("/skills/cad"))
        self.assertIn("skill_manage", out["on_device"]["note"])
        forward.skill_files(tool_name="skill_view", result=result, session_id="default")
        self.assertEqual(len(self.puts), before + 1)           # second view reuses the copy

    test_open_needs_the_users_words = test_close_needs_the_users_words_and_reaches_the_device = None
    test_idle_timer_closes = test_review_never_routes_to_the_device = test_host_owned_paths_stay_on_the_host = None
    test_tether_and_untether_words = None


class CloseNeedsNoConsentTests(unittest.IsolatedAsyncioTestCase):
    async def test_close_session_wipes_and_revokes_without_prompting(self):
        prompt = FakePrompt(True)
        gate = ConsentGate(idle_minutes=15, timeout_s=5, prompt=prompt)
        ws = Workspaces(Path(tempfile.mkdtemp(prefix="hp-ws-")) / "sessions")
        await gate.require("fp", "host", "s1")
        ws.ensure("s1")
        control = SessionControl(gate, ws, LocalExec(ws), lambda: "fp")
        out, _ = await control.close_session({"session": "s1"}, b"")
        self.assertTrue(out["workspace_removed"])
        self.assertEqual(gate.live_sessions(), set())
        self.assertEqual(len(prompt.asked), 1)                # only the original allow; closing asked nothing


if __name__ == "__main__":
    unittest.main()
