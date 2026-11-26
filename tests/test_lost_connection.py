"""D34 with the call shapes Hermes 0.23.3 really uses, and the host's idle timer (D23/D29).

Hermes keys the terminal environment by its container key (tools/terminal_tool.py _resolve_container_task_id): 'default'
in the CLI, 'session:<chat key>' in the gateway, and the parent, its delegate_task children and its /bg runs all get the
same one. The file tools' task id is the session id (gateway/run_turn_runner.py, hermes_cli/cli_chat_turn_mixin.py).
Every tool call carries its own run's turn id and Hermes's conversation id, the compression-lineage root that a
delegated child shares with its parent (agent/inline_tool_executors.py tool_hook_ids, agent/prompt_cache_scope.py).
A rotating compression changes the session id and keeps the turn id (agent/conversation_compression.py)."""
from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "plugin" / "tether"))
sys.path.insert(1, str(Path(os.environ.get("HERMES_AGENT_SRC") or Path.home() / ".hermes" / "hermes-agent")))

from tether import forward, runtime, tools  # noqa: E402
from tether.provider import TetherEnvironment  # noqa: E402
from tether.runtime import BgJob, get_runtime  # noqa: E402
from tether.store import OpenSessions  # noqa: E402

from test_link_loopback import isolate_session, through_hermes, Rig  # noqa: E402

try:
    from agent.delegation_context import delegated_child_context
    from gateway.session_context import scoped_current_session_id
    HAVE_HERMES = True
except Exception:  # noqa: BLE001
    HAVE_HERMES = False

CLI_KEY = "default"                               # the terminal environment key in the CLI
GW_KEY = "session:agent:main:telegram:dm:42"     # the same key in a gateway chat


@unittest.skipUnless(HAVE_HERMES, "Hermes source not importable")
class LostConnectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rt = get_runtime()
        cls.device = []          # what reached the device, in order
        cls.closed = []

        async def exec_on_device(args, body):
            cls.device.append(("exec", args.get("command")))
            return {"returncode": 0, "cwd": "/w", "cwd_observed": True}, b"ON-MAC"

        async def tool_on_device(args, body):
            cls.device.append(("tool", args.get("name")))
            return {"json_dict": True}, json.dumps({"ran_on": "device"}).encode()

        async def close_session(args, body):
            cls.closed.append(args["session"])
            return {"closed": True}, b""

        async def slow(args, body):
            cls.device.append(("slow", "started"))
            try:
                await asyncio.sleep(10)
            except asyncio.CancelledError:
                cls.device.append(("slow", "cancelled"))
                raise
            return {}, b""

        cls.rig = Rig(handlers={"exec": exec_on_device, "tool": tool_on_device, "close_session": close_session,
                                "slow": slow}, capabilities={"rules": {"grant_idle_minutes": 15}})
        cls.rig.device.UNGUARDED = frozenset({"close_session"})
        cls.addClassCleanup(cls.rig.close)

        async def up():
            _, task = await cls.rig.pair()
            await task
            await cls.rig.connect()
        cls.rt.run(up(), 30)

    @classmethod
    def tearDownClass(cls):
        cls.rt.loop.call_soon_threadsafe(cls.rig.device._task.cancel)

    def setUp(self):
        isolate_session(self)
        spy = mock.patch.object(TetherEnvironment, "_run_local", autospec=True, side_effect=self._host_run)
        spy.start()
        self.addCleanup(spy.stop)
        self.reset()

    def reset(self):
        """A clean host: no connection, no turn, no D34 state, no open-session records."""
        self.rt.host = self.rig.host
        for name in ("targets", "turn_open", "turn_text", "turn_wrapped", "turn_id", "last_device", "last_activity",
                     "last_wall", "idle_limit_s", "closed_note", "skill_copies", "grants", "working_on", "held",
                     "turn_owner", "conversation_of", "_told_elsewhere", "open_fp", "_busy"):
            getattr(self.rt, name, set()).clear()
        self.rig.consent._asked.clear()
        self.rig.consent._denied_until.clear()
        self.book = OpenSessions(self.rig.host.pins.path.parent)
        for session in list(self.book.all()):
            self.book.drop(session)
        self.device.clear()
        self.closed.clear()
        forward._facts.clear()
        self.host_ran = []

    def tearDown(self):
        self.rt.host = None
        self.rt.targets.clear()
        self.rt.turn_open.clear()

    # ---- Hermes-shaped calls -----------------------------------------------------------------------------------
    def _host_run(self, env, command, cwd, timeout, stdin_data, **kwargs):
        self.host_ran.append(command)
        return {"output": "ON-HOST", "returncode": 0}

    def turn(self, session, turn, words="go on", **kwargs):
        return forward.turn_context(session_id=session, user_message=words, turn_id=turn, **kwargs)

    def open_mac(self, session, turn, conversation=""):
        self.turn(session, turn, "tether mac")
        with scoped_current_session_id(session):
            out = json.loads(forward.tool_execution(tool_name="devices", args={"action": "use", "device": "mac"},
                                                    session_id=session, task_id=session, turn_id=turn,
                                                    conversation_id=conversation,
                                                    next_call=lambda a: tools.handler(a)))
        self.assertEqual(out.get("active"), "mac")

    def terminal(self, env, command, *, session, turn, conversation=""):
        """Hermes's terminal tool: the middleware binds the call's ids, then the backend runs on the same thread."""
        with scoped_current_session_id(session):
            return forward.tool_execution(tool_name="terminal", args={"command": command}, session_id=session,
                                          task_id=session, turn_id=turn, conversation_id=conversation,
                                          next_call=lambda a: env.execute(command))

    def read_file(self, path, *, session, turn, conversation=""):
        """Hermes's read_file: the middleware forwards it to the device, or lets it run here."""
        with scoped_current_session_id(session):
            out = through_hermes("read_file", {"path": path},
                                 lambda a: (self.host_ran.append(f"read_file {path}"), "HOST")[1], session_id=session,
                                 task_id=session, turn_id=turn, conversation_id=conversation)
        return out if isinstance(out, dict) else (json.loads(out) if out.startswith("{") else out)

    def idle_out(self, session):
        self.rt.idle_limit_s["mac"] = 0.05
        self.rt.last_activity[session] = time.monotonic() - 5
        self.assertEqual(self.rt.sweep_idle(), 1)

    # ---- F3 / F15: other runs on the shared terminal environment -----------------------------------------------
    def test_a_sub_agent_on_the_shared_terminal_works_on_the_host_and_leaves_the_parents_device_alone(self):
        """F15: the parent works on the mac; its delegate_task child shares the terminal environment key. The child's
        terminal and file work runs on the host (as its turn note says), and the parent stays on the mac."""
        for key in (CLI_KEY, GW_KEY):
            with self.subTest(key=key):
                self.reset()
                env = TetherEnvironment("~", 30, key)
                self.open_mac("S1", "T1")
                self.assertEqual(self.terminal(env, "make", session="S1", turn="T1")["output"], "ON-MAC")
                with delegated_child_context("C1"):
                    note = self.turn("C1", "C1:C1:1", "TASK: summarize the notes", platform="subagent",
                                     parent_session_id="S1")
                    self.assertIn("works on your host", note)
                    child = self.terminal(env, "wc -l notes.txt", session="C1", turn="C1:C1:1")
                    child_read = self.read_file("/Users/z/notes.txt", session="C1", turn="C1:C1:1")
                self.assertEqual((child["output"], child_read), ("ON-HOST", "HOST"))
                self.assertEqual(self.rt.route("S1"), "mac")
                self.assertEqual(self.terminal(env, "make test", session="S1", turn="T1")["output"], "ON-MAC")

    def test_a_sub_agent_call_after_a_mid_turn_close_neither_takes_nor_releases_the_parents_refusal(self):
        """F3: the idle limit closes the parent's connection while its sub-agent runs. The child's call runs on the
        host and changes nothing; the parent's next commands of that turn, written for the mac, run nowhere."""
        env = TetherEnvironment("~", 30, GW_KEY)
        self.open_mac("S1", "T1")
        self.terminal(env, "git pull", session="S1", turn="T1")
        self.idle_out("S1")
        with delegated_child_context("C1"):
            self.turn("C1", "C1:C1:1", "TASK: research", platform="subagent", parent_session_id="S1")
            self.assertEqual(self.terminal(env, "curl notes", session="C1", turn="C1:C1:1")["output"], "ON-HOST")
        self.host_ran.clear()
        first = self.terminal(env, "./deploy.sh --prod", session="S1", turn="T1")
        self.assertIn("did not run anywhere", first["output"])
        with delegated_child_context("C1"):                      # [terminal, delegate_task, terminal]
            self.terminal(env, "echo child", session="C1", turn="C1:C1:2")
        second = self.terminal(env, "rm -rf build", session="S1", turn="T1")
        self.assertIn("did not run anywhere", second["output"])
        self.assertEqual(self.host_ran, ["echo child"], "a command meant for the mac ran on this host")

    def test_a_close_between_turns_is_still_said_after_a_background_childs_call(self):
        """F3: a background delegate_task child calls after the parent's turn ended and its connection closed; the
        parent's next turn is still told."""
        env = TetherEnvironment("~", 30, GW_KEY)
        self.open_mac("S1", "T1")
        self.terminal(env, "npm test", session="S1", turn="T1")
        forward.turn_closed(session_id="S1", user_message="", turn_id="T1")
        self.idle_out("S1")
        with delegated_child_context("C1"):
            self.assertEqual(self.terminal(env, "python3 summarize.py", session="C1", turn="C1:C1:1")["output"],
                             "ON-HOST")
        note = self.turn("S1", "T2")
        self.assertIn("The mac connection is closed (timed out", note or "")

    # ---- F4: one hold per session and turn, for the terminal and the file tools alike ---------------------------
    def test_a_lost_connection_holds_back_the_terminal_and_the_file_tools_of_that_turn(self):
        """F4: the file tools carry the session id, the terminal its environment key. After a loss inside the turn,
        a batch [read_file, terminal] runs nowhere, whichever key each call carries; the next turn works here."""
        for loss in ("idle", "deny"):
            with self.subTest(loss=loss):
                self.reset()
                env = TetherEnvironment("~", 30, GW_KEY)
                self.open_mac("S1", "T1")
                self.assertEqual(self.read_file("/Users/z/a.md", session="S1", turn="T1"), {"ran_on": "device"})
                if loss == "idle":
                    self.rt.idle_limit_s["mac"] = 0.05
                    self.rt.last_activity["S1"] = time.monotonic() - 5
                else:
                    self.rig.consent.revoke_all()
                    self.rig.prompt.answer = False
                    self.addCleanup(setattr, self.rig.prompt, "answer", True)
                first = self.read_file("/Users/z/b.md", session="S1", turn="T1")
                second = self.terminal(env, "make clean", session="S1", turn="T1")
                with scoped_current_session_id("S1"):            # a Hermes thread of that turn: no turn id bound
                    third = env.execute("rm -rf dist")
                self.rig.prompt.answer = True
                self.assertIn("error", first)
                self.assertIn("did not run anywhere", second["output"])
                self.assertIn("did not run anywhere", third["output"])
                self.assertEqual(self.host_ran, [], "work meant for the mac ran on this host")
                forward.turn_closed(session_id="S1", user_message="", turn_id="T1")
                self.turn("S1", "T2")
                self.assertEqual(self.terminal(env, "ls", session="S1", turn="T2")["output"], "ON-HOST")

    def test_a_loss_seen_by_the_terminal_holds_back_the_file_tools_too(self):
        """F4, the other order: the terminal ran on the mac, the file tools never did. After a loss inside the turn,
        a batch [terminal, write_file] runs nothing on this host."""
        env = TetherEnvironment("~", 30, GW_KEY)
        self.open_mac("S1", "T1")
        self.assertEqual(self.terminal(env, "make", session="S1", turn="T1")["output"], "ON-MAC")
        self.rt.idle_limit_s["mac"] = 0.05
        self.rt.last_activity["S1"] = time.monotonic() - 5
        first = self.terminal(env, "make deploy", session="S1", turn="T1")
        with scoped_current_session_id("S1"):
            second = through_hermes("write_file", {"path": "/Users/z/out.txt", "content": "x"},
                                    lambda a: (self.host_ran.append("write_file"), "HOST")[1], session_id="S1",
                                    task_id="S1", turn_id="T1")
        self.assertIn("did not run anywhere", first["output"])
        self.assertIn("did not run anywhere", second)
        self.assertEqual(self.host_ran, [], "work meant for the mac ran on this host")

    def test_parallel_file_calls_after_a_loss_are_all_held(self):
        """F4: Hermes runs read_file and search_files side by side. After a loss, the first of two parallel calls is
        told and the other is held; neither runs here, even when the first is paused in the middle of its decision
        (the decision is one step under the state lock)."""
        self.open_mac("S1", "T1")
        self.assertEqual(self.read_file("/Users/z/a.md", session="S1", turn="T1"), {"ran_on": "device"})
        self.idle_out("S1")

        class Slow(dict):                                   # the first call is preempted right after its first pop
            def pop(self, *args):
                value = dict.pop(self, *args)
                time.sleep(0.3)
                return value
        real = self.rt.working_on
        self.rt.working_on = Slow(real)
        self.addCleanup(setattr, self.rt, "working_on", real)
        results = {}

        def call(name, delay):
            time.sleep(delay)
            results[name] = self.read_file(f"/Users/z/{name}.md", session="S1", turn="T1")
        workers = [threading.Thread(target=call, args=("b", 0)), threading.Thread(target=call, args=("c", 0.1))]
        for w in workers:
            w.start()
        for w in workers:
            w.join(10)
        self.assertEqual(sorted(results), ["b", "c"])
        for name, out in results.items():
            self.assertIn("did not run anywhere", str(out), f"parallel call {name} was not held")
        self.assertEqual(self.host_ran, [], "work meant for the mac ran on this host")

    # ---- F16 / F32: Hermes gives the conversation a new session id ----------------------------------------------
    def test_a_session_id_changed_mid_turn_closes_the_old_connection_and_runs_nothing_here(self):
        """F16: only file tools were used on the mac; compression (in_place false) moves the id A -> B inside the turn,
        and the terminal's key ('default') never held anything. The command runs nowhere, the model is told, and the
        connection opened for A is closed on the device."""
        env = TetherEnvironment("~", 30, CLI_KEY)
        self.open_mac("A", "T1")
        self.assertEqual(self.read_file("/Users/z/notes/a.md", session="A", turn="T1"), {"ran_on": "device"})
        out = self.terminal(env, "cd ~/notes && rm -f *.bak", session="B", turn="T1")
        self.assertIn("did not run anywhere", out["output"])
        self.assertIn("new session id", out["output"])
        self.assertEqual(self.host_ran, [], "a command meant for the mac ran on this host")
        self.assertIn("error", self.read_file("/Users/z/notes/b.md", session="B", turn="T1"))
        self.assertNotIn("A", self.rt.targets)
        for _ in range(50):
            if "A" in self.closed:
                break
            time.sleep(0.05)
        self.assertIn("A", self.closed)

    def test_a_long_turn_keeps_its_owner_however_many_turns_start_meanwhile(self):
        """F16: the turn-id map is capped, but a turn that is still open is never dropped from it, so a session id
        Hermes changes late in a long turn (while many other chats' turns started) is still recognised."""
        env = TetherEnvironment("~", 30, CLI_KEY)
        self.open_mac("A", "T1")
        self.assertEqual(self.read_file("/Users/z/notes/a.md", session="A", turn="T1"), {"ran_on": "device"})
        with mock.patch.object(type(self.rt), "TURNS_KEPT", 3):
            for n in range(8):                                  # other chats' turns start and end meanwhile
                self.turn(f"other-{n}", f"O{n}")
                forward.turn_closed(session_id=f"other-{n}", user_message="", turn_id=f"O{n}")
        out = self.terminal(env, "rm -f *.bak", session="B", turn="T1")
        self.assertIn("new session id", out["output"])
        self.assertEqual(self.host_ran, [], "a command meant for the mac ran on this host")

    def test_a_session_id_changed_during_a_turn_is_said_at_the_next_turn(self):
        """F32: the id moves A -> B after the turn's last device call. Hermes reports the turn's end under B; the next
        turn (session B) is told the mac connection is closed."""
        env = TetherEnvironment("~", 30, GW_KEY)
        self.open_mac("A", "T1")
        self.read_file("/Users/z/a.md", session="A", turn="T1")
        forward.turn_closed(session_id="B", user_message="", turn_id="T1")
        self.assertNotIn("A", self.rt.targets)                  # the old id's connection is closed at once
        with scoped_current_session_id("B"):                    # Hermes delivers the reply's MEDIA (no turn bound)
            self.assertIsNone(env.fetch_realpath("/Users/z/Desktop/shot.png"))
        self.assertEqual(self.host_ran, [], "the attachment meant for the mac was looked up on this host")
        note = self.turn("B", "T2")
        self.assertIn("The mac connection is closed", note or "")
        self.assertFalse(self.rt.turn_open.get("A"))

    def test_a_session_id_changed_between_turns_is_found_by_hermes_conversation_id(self):
        """F32: the gateway compresses before turn 2 and moves the id A -> B. The first tool call of turn 2 carries
        the conversation id A had: the old connection closes and nothing meant for the mac runs here."""
        for first_call in ("read_file", "terminal backend"):
            with self.subTest(first_call=first_call):
                self.reset()
                env = TetherEnvironment("~", 30, GW_KEY)
                self.open_mac("A", "T1", conversation="A")
                self.read_file("/Users/z/a.md", session="A", turn="T1", conversation="A")
                forward.turn_closed(session_id="A", user_message="", turn_id="T1")
                self.assertIsNone(self.turn("B", "T2"))
                if first_call == "read_file":
                    first = self.read_file("/Users/z/b.md", session="B", turn="T2", conversation="A")
                else:       # the backend's own check, with only the ids bound (as if no middleware matched it first)
                    previous = self.rt.begin_call("T2", "A")
                    try:
                        with scoped_current_session_id("B"):
                            first = env.execute("make deploy")["output"]
                    finally:
                        self.rt.end_call(previous)
                second = self.terminal(env, "pytest", session="B", turn="T2", conversation="A")
                self.assertIn("new session id", str(first))
                self.assertIn("did not run anywhere", second["output"])
                self.assertEqual(self.host_ran, [], "work meant for the mac ran on this host")
                self.assertNotIn("A", self.rt.targets)

    # ---- F30: a new conversation on the same environment key ----------------------------------------------------
    def test_a_new_conversation_on_the_shared_terminal_works_on_the_host(self):
        """F30: /new (CLI) or a gateway reset starts session C with a new conversation id on the same terminal key
        while A is still on the mac. C never tethered anything: its work runs here and A keeps its device."""
        for key in (CLI_KEY, GW_KEY):
            with self.subTest(key=key):
                self.reset()
                env = TetherEnvironment("~", 30, key)
                self.open_mac("A", "T1", conversation="A")
                self.terminal(env, "ls", session="A", turn="T1", conversation="A")
                forward.turn_closed(session_id="A", user_message="", turn_id="T1")
                self.assertIsNone(self.turn("C", "TC1", is_first_turn=True))
                self.assertEqual(self.terminal(env, "ls ~/Downloads", session="C", turn="TC1",
                                               conversation="C")["output"], "ON-HOST")
                self.assertEqual(self.read_file("/Users/z/x.md", session="C", turn="TC1", conversation="C"), "HOST")
                self.assertEqual(self.rt.active_target("A"), "mac")

    # ---- F33: Hermes's own work after the turn ------------------------------------------------------------------
    def test_a_media_delivery_after_the_turn_spends_nothing(self):
        """F33: the connection closes after the turn's last device call; Hermes then delivers the reply's MEDIA
        (fetch_realpath, no tool call bound). It finds nothing, and the next turn is told and works here."""
        env = TetherEnvironment("~", 30, GW_KEY)
        self.open_mac("S1", "T1")
        self.terminal(env, "screencapture shot.png", session="S1", turn="T1")
        self.rt.close_device("S1", "the person at mac ended it")
        forward.turn_closed(session_id="S1", user_message="", turn_id="T1")
        with scoped_current_session_id("S1"):
            self.assertIsNone(env.fetch_realpath("/Users/x/Desktop/shot.png"))
        self.assertEqual(self.host_ran, [], "the attachment was looked up on this host")
        note = self.turn("S1", "T2")
        self.assertIn("The mac connection is closed (the person at mac ended it)", note or "")
        self.assertEqual(self.terminal(env, "ls", session="S1", turn="T2")["output"], "ON-HOST")
        self.assertEqual(self.terminal(env, "ls -la", session="S1", turn="T2")["output"], "ON-HOST")

    # ---- F7 / F31: the open-session record ----------------------------------------------------------------------
    def test_a_clean_exit_of_the_holding_process_is_said_to_the_next_one(self):
        """F7: the Hermes process that held the connection exits normally (atexit runs). The next process is told."""
        folder = str(self.rig.host.pins.path.parent)
        plugin = str(Path(__file__).resolve().parents[1] / "plugin" / "tether")
        code = ("import sys, types; sys.path.insert(0, sys.argv[1]); from pathlib import Path\n"
                "from tether.runtime import get_runtime\n"
                "rt = get_runtime(); rt.host = types.SimpleNamespace(dir=Path(sys.argv[2]))\n"
                "rt.open_device('held-elsewhere', 'mac')\n"
                "sys.exit(0)\n")
        done = subprocess.run([sys.executable, "-c", code, plugin, folder], capture_output=True, timeout=60)
        self.assertEqual(done.returncode, 0, "the holder process failed")
        note = self.turn("held-elsewhere", "N1")
        self.assertIn("The mac connection is closed (Hermes restarted on this host)", note or "")

    def test_a_live_holders_record_never_ages_out_and_survives_another_write(self):
        """F31: a connection held for more than the record window (seven days) by another live Hermes process: its
        record is still read, another process's write keeps it, and this conversation here is told where it is."""
        self.book._change(lambda data: data.__setitem__("conv-A", {"device": "mac", "pid": os.getppid(),
                                                                   "run": "other", "at": time.time() - 8 * 24 * 3600}))
        self.assertIn("conv-A", self.book.all())
        self.book.put("conv-B", "pc")
        self.assertIn("conv-A", json.loads(self.book.path.read_text()))
        self.assertIn("open in another Hermes program", self.turn("conv-A", "N1") or "")

    def test_a_held_connection_is_re_dated_so_a_restart_much_later_is_still_told(self):
        """F31: while this process holds the connection, the idle sweeper re-dates its record (date_records), so the
        record's age counts from the last time its holder held it, not from the open. Opened eight days ago, then
        this process ends: the next process is still told."""
        self.open_mac("S1", "T1")
        self.book._change(lambda data: data["S1"].__setitem__("at", time.time() - 8 * 24 * 3600))
        self.rt._records_dated = float("-inf")
        self.rt.date_records()
        ended = subprocess.Popen([sys.executable, "-c", "pass"])
        ended.wait()
        self.book._change(lambda data: data["S1"].__setitem__("pid", ended.pid))     # the holder has ended
        self.rt.targets.clear()                                                     # a new process knows nothing
        self.assertIn("The mac connection is closed (Hermes restarted on this host)", self.turn("S1", "T9") or "")

    def test_a_record_left_by_an_earlier_process_with_this_pid_is_an_ended_connection(self):
        """F7: records outlive their process, and a later process can get the same pid (after a reboot). Such a
        record is not taken for this process's own: the model is told the connection ended."""
        self.book._change(lambda data: data.__setitem__("S7", {"device": "mac", "pid": os.getpid(),
                                                               "run": "an-earlier-process", "at": time.time()}))
        self.assertIn("The mac connection is closed (Hermes restarted on this host)", self.turn("S7", "T1") or "")

    def test_closing_a_session_leaves_a_record_another_process_wrote(self):
        """F91 (B1 F83 item 3, coverage): a record is removed only by the process that wrote it, also when the close
        comes from this process and when the record changes between drop's first read and its locked write."""
        self.open_mac("S1", "T1")
        self.book._change(lambda data: data["S1"].__setitem__("pid", os.getppid()))  # another live process now
        self.rt.close_device("S1", "untether")
        self.assertEqual(self.book.all().get("S1", {}).get("pid"), os.getppid(), "another process's record was removed")
        self.book.put("S2", "mac")
        mine = self.book.all()
        self.book._change(lambda data: data["S2"].__setitem__("pid", os.getppid()))  # changed after the first read
        with mock.patch.object(OpenSessions, "all", side_effect=[mine, self.book.all()]):
            self.book.drop("S2", pid=os.getpid())
        self.assertIn("S2", self.book.all(), "another process's record was removed")

    # ---- F8: a call that runs past its time limit ----------------------------------------------------------------
    def test_a_call_past_its_time_limit_returns_promptly_and_frees_the_session(self):
        """F8: Peer.call raises the builtin TimeoutError when the call runs past its limit (on Python 3.11 that is
        concurrent.futures.TimeoutError too). call_target must raise it at once, not spin, and leave nothing busy."""
        self.open_mac("S1", "T1")
        outcome: dict = {}

        def call():
            start = time.monotonic()
            try:
                self.rt.call_target("slow", {}, timeout=1.0, target="mac", session="S1")
            except BaseException as e:  # noqa: BLE001
                outcome["error"] = type(e).__name__
            outcome["took"] = time.monotonic() - start

        worker = threading.Thread(target=call, daemon=True)
        worker.start()
        worker.join(5)
        if worker.is_alive():                                    # end the spin, as the user's Stop would
            from tools.interrupt import set_interrupt
            set_interrupt(True, worker.ident)
            worker.join(5)
            set_interrupt(False, worker.ident)
        self.assertEqual(outcome.get("error"), "TimeoutError")
        self.assertLess(outcome.get("took", 99), 4)
        self.assertNotIn("S1", self.rt._busy)
        for _ in range(40):
            if ("slow", "cancelled") in self.device:
                break
            time.sleep(0.05)
        self.assertIn(("slow", "cancelled"), self.device)

    # ---- F25 / F39: the host's idle decision ---------------------------------------------------------------------
    def test_a_session_with_a_call_in_flight_is_not_closed_by_route_or_a_job_poll(self):
        """F25: a long command is running on the mac past the idle limit. route() from another call and Hermes's
        background-job poll must not close the session under it; once nothing is in flight, the limit applies."""
        self.open_mac("S1", "T1")
        self.rt.call_target("exec", {"command": "true"}, target="mac", session="S1")
        self.rt.idle_limit_s["mac"] = 0.05
        self.rt.last_activity["S1"] = time.monotonic() - 5
        self.rt._busy["S1"] = 1                                  # the long command's call is in flight
        job = BgJob(id="proc_0123456789ab", machine="mac", session="S1", log="/tmp/hermes_bg_proc_0123456789ab.log",
                    pid_path="/tmp/hermes_bg_proc_0123456789ab.pid",
                    exit_path="/tmp/hermes_bg_proc_0123456789ab.exit", pid=4242)
        self.assertEqual(self.rt.route("S1"), "mac")
        self.assertEqual(self.rt.bg_call(job, "true", 5)["returncode"], 0)
        self.assertEqual(self.rt.active_target("S1"), "mac")
        self.assertNotIn("S1", self.closed)
        self.rt._busy.pop("S1")
        self.assertEqual(self.rt.route("S1"), "local")          # nothing in flight now: the limit applies

    def test_time_asleep_counts_toward_the_host_idle_limit(self):
        """F39: the host's monotonic clock stops while the machine sleeps (macOS mach_absolute_time, Linux
        CLOCK_MONOTONIC). An hour asleep is an hour idle: a host limit of a minute closes the session."""
        self.open_mac("S1", "T1")
        self.rt.turn_open["S1"] = False
        self.rt.idle_limit_s["mac"] = 60.0

        class Asleep:                                            # the wall clock moved an hour, monotonic did not
            def __getattr__(self, name):
                return getattr(time, name)

            @staticmethod
            def time():
                return time.time() + 3600

        with mock.patch.object(runtime, "time", Asleep()):
            self.assertEqual(self.rt.sweep_idle(), 1)
        self.assertIn("timed out", self.rt.closed_note.get("S1", ""))


if __name__ == "__main__":
    unittest.main()
