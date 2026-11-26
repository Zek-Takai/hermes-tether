"""Stop, Pause and close reach work in flight on the device, nothing is left stuck, and the consent wait agrees
between host and device (F26-F29, F59, F63, F77, F82). Loopback where a link matters, real Hermes terminals where a
command matters; the dialogs are stand-in processes (no real dialog is shown)."""
from __future__ import annotations

import asyncio
import concurrent.futures
import json
import os
import subprocess
import sys
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "plugin" / "tether"))
sys.path.insert(1, str(Path(os.environ.get("HERMES_AGENT_SRC") or Path.home() / ".hermes" / "hermes-agent")))

try:
    import tools.environments.local  # noqa: F401
    from tools.computer_use.backend import ActionResult
    HAVE_HERMES = True
except Exception:  # noqa: BLE001
    HAVE_HERMES = False

from tether import consent  # noqa: E402
from tether.link import RemoteError  # noqa: E402

from test_link_loopback import FakePrompt, consent_gate, Rig, _until, isolate_session, temp_dir  # noqa: E402


async def _up(rig: Rig) -> None:
    _, task = await rig.pair()
    await task
    await rig.connect()


class SlowDriver:
    """A stand-in screen driver: `wait` holds the driver until the test lets go; every action is recorded."""

    def __init__(self) -> None:
        self.calls: list[str] = []
        self.busy, self.go = threading.Event(), threading.Event()

    def wait(self, **kw):
        self.calls.append("wait")
        self.busy.set()
        self.go.wait(20)
        return ActionResult(ok=True, action="wait")

    def click(self, **kw):
        self.calls.append("click")
        return ActionResult(ok=True, action="click")


def screen_for(gate, local_exec=None):
    """A ScreenExec wired to the session stop handles the way the device role wires it (plugin __init__.py)."""
    from tether.device_screen import ScreenExec
    screen = ScreenExec(gate)
    screen.local_exec = local_exec
    return screen


# ---------- F26: a cancelled prompt takes its dialog with it; the prompt never outlasts the host's wait ----------
@unittest.skipIf(sys.platform == "win32", "uses a POSIX stand-in for the dialog program")
class PromptDialogTests(unittest.TestCase):
    def test_a_cancelled_prompt_takes_its_dialog_with_it(self):
        real = asyncio.create_subprocess_exec
        for name, prompt in (("macos", consent.macos_code_box), ("windows", consent.windows_code_box)):
            procs = []

            async def fake(program, *args, **kwargs):     # the dialog program, stood in by a process that waits
                proc = await real("/bin/sleep", "30", **kwargs)
                procs.append(proc)
                return proc

            async def scenario():
                task = asyncio.create_task(prompt("Hermes on studio wants to use this machine", 30))
                try:
                    for _ in range(200):
                        if procs:
                            break
                        await asyncio.sleep(0.01)
                    await asyncio.sleep(0.1)                # the dialog is up
                    task.cancel()                           # the host's Stop, its time-out, a dropped link, Pause
                    with self.assertRaises(asyncio.CancelledError):
                        await task
                    return procs[0].returncode if procs else "never started"
                finally:
                    for p in procs:                         # never leave the stand-in running
                        if p.returncode is None:
                            p.kill()
                            await p.wait()

            with self.subTest(name), mock.patch.object(consent.asyncio, "create_subprocess_exec", fake), \
                    mock.patch.object(consent, "_powershell", lambda: "/bin/sleep"):
                code = asyncio.run(scenario())
                self.assertNotEqual(code, "never started")
                self.assertIsNotNone(code, f"{name}: the dialog was left on screen after its prompt was cancelled")


class ConsentWaitTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.rig = Rig()
        self.addCleanup(self.rig.close)
        self.waits: list[float] = []

        async def prompt(text, timeout_s):
            self.waits.append(timeout_s)
            return self.rig.phone.code()
        self.rig.consent._prompt = prompt
        self.rig.consent.timeout_s = 120.0             # the person set a long wait in the panel
        await _up(self.rig)

    async def asyncTearDown(self):
        self.rig.device._task.cancel()

    async def test_the_prompt_never_outlasts_the_hosts_wait_for_the_call(self):
        await self.rig.host.call("mac", "exec", {"command": "true", "session": "s1"}, b"", 30)
        self.assertEqual(len(self.waits), 1)
        self.assertLessEqual(self.waits[0], 27.0, "the prompt would stay up after the host stopped waiting")
        self.assertGreater(self.waits[0], 22.0)

    async def test_with_too_little_time_left_no_prompt_is_shown_and_nothing_counts_against_the_session(self):
        with self.assertRaisesRegex(RemoteError, "did not show its approval box"):
            await self.rig.host.call("mac", "exec", {"command": "true", "session": "s1"}, b"", 22)
        self.assertEqual(self.waits, [])
        await self.rig.host.call("mac", "exec", {"command": "true", "session": "s1"}, b"", 30)   # no cool-down
        self.assertEqual(len(self.waits), 1)

    async def test_the_consent_wait_from_config_is_held_to_the_panels_range(self):
        self.assertEqual(consent_gate(timeout_s=10_000, prompt=FakePrompt(True)).timeout_s, 600.0)
        self.assertEqual(consent_gate(timeout_s=1, prompt=FakePrompt(True)).timeout_s, 20.0)


@unittest.skipUnless(HAVE_HERMES, "Hermes source not importable")
class OpeningWaitTests(unittest.TestCase):
    """The host's `devices use` waits as long as the device's own consent wait (announced), not a fixed 90 s."""

    @classmethod
    def setUpClass(cls):
        from tether.runtime import get_runtime
        cls.rt = get_runtime()

        async def exec_ok(args, body):
            return {"returncode": 0, "cwd": "/w", "cwd_observed": True}, b"ok"
        cls.rig = Rig(handlers={"exec": exec_ok},
                      capabilities={"rules": {"grant_idle_minutes": 15, "consent_wait_seconds": 300}})
        cls.addClassCleanup(cls.rig.close)
        cls.rt.run(_up(cls.rig), 30)

    @classmethod
    def tearDownClass(cls):
        cls.rt.loop.call_soon_threadsafe(cls.rig.device._task.cancel)

    def setUp(self):
        from tether import forward
        isolate_session(self)
        os.environ.pop("HERMES_SESSION_ID", None)
        os.environ.pop("HERMES_SESSION_KEY", None)
        self.rt.host = self.rig.host
        self.addCleanup(self._reset)
        self._reset()
        forward._facts.clear()

    def _reset(self):
        for d in (self.rt.targets, self.rt.turn_open, self.rt.turn_text, self.rt.turn_wrapped, self.rt.turn_id,
                  self.rt.grants, self.rt.grant_fp, self.rt.open_fp, self.rt.idle_limit_s, self.rt.last_activity,
                  self.rt.last_wall, self.rt.closed_note, self.rt.working_on, self.rt.held, self.rt.turn_owner,
                  self.rt.conversation_of):
            d.clear()
        from tether.store import OpenSessions
        book = OpenSessions(self.rig.host.pins.path.parent)
        for session in list(book.all()):
            book.drop(session)

    def test_use_waits_as_long_as_the_devices_own_consent_wait(self):
        from tether import forward, tools
        forward.turn_context(session_id="default", user_message="tether mac")
        waits, real = [], self.rt.device_call

        def spy(target, kind, args, body=b"", timeout=120.0, opening=False):
            waits.append(timeout)
            return real(target, kind, args, body, timeout, opening)
        with mock.patch.object(self.rt, "device_call", spy):
            out = json.loads(tools.handler({"action": "use", "device": "mac"}))
        self.rt.host = None
        self.assertEqual(out.get("active"), "mac")
        self.assertGreaterEqual(waits[0], 330.0, "the host gives up before the person's own consent wait is over")


# ---------- F27: Pause stops work already in flight ----------
class PauseGuardTests(unittest.IsolatedAsyncioTestCase):
    """Within the second before the watcher sees Pause, the guard itself holds back what Pause should stop."""

    async def test_an_allow_or_a_result_that_comes_after_pause_gives_nothing(self):
        from tether.device import DeviceService
        from tether.store import HostPin
        d = temp_dir(self, "hp-pg-")
        pin = HostPin(d)
        pin.set(host="192.0.2.10", port=9130, fp="aa" * 32, cert_pem="A", host_label="Hermes on nas")
        flag = d / "paused"

        phone = FakePrompt(True).phone

        async def pause_while_asking(text, timeout_s):
            flag.write_text("")                      # the person presses Pause while the box is up...
            return phone.code()                      # ...and a valid code is typed anyway

        gate = consent_gate(prompt=pause_while_asking, phone=phone)
        ran = []

        async def handler(args, body):
            ran.append(args["session"])
            return {"output": "SECRET-OUTPUT"}, b""
        svc = DeviceService(None, pin, gate, "mac", {"exec": handler}, lambda: {})
        guarded = svc._guard("exec", handler)
        with self.assertRaisesRegex(PermissionError, "paused"):
            await guarded({"session": "s1"}, b"")
        self.assertEqual(ran, [], "work ran on an Allow given after Pause")
        self.assertEqual(gate.live_sessions(), set())

        flag.unlink()
        gate._prompt = FakePrompt(True, phone)

        async def pause_while_running(args, body):
            flag.write_text("")                      # Pause lands while the call runs
            return {"output": "SECRET-OUTPUT"}, b""
        guarded = svc._guard("exec", pause_while_running)
        with self.assertRaisesRegex(PermissionError, "paused"):
            await guarded({"session": "s2"}, b"")
        self.assertEqual(gate.live_sessions(), set())


@unittest.skipUnless(HAVE_HERMES, "Hermes source not importable")
class PauseTests(unittest.IsolatedAsyncioTestCase):
    def paused_flag(self, rig: Rig) -> Path:
        flag = rig.host_pin.path.parent / "paused"
        self.addCleanup(lambda: flag.unlink(missing_ok=True))
        return flag

    async def test_pause_stops_the_running_command_and_nothing_of_it_reaches_the_host(self):
        from tether.device_exec import LocalExec
        from tether.workspace import Workspaces
        ws = Workspaces(temp_dir(self, "hp-ws-") / "sessions")
        loc = LocalExec(ws)
        self.addCleanup(loc.close_all)
        rig = Rig(handlers={"exec": loc.exec})
        self.addCleanup(rig.close)
        # wired as the device role wires them (plugin __init__.py)
        rig.device.workspaces, rig.device.job_sweep = ws, loc.sweep_jobs
        rig.device.busy_sessions = getattr(loc, "busy_sessions", None)
        await _up(rig)
        flag = self.paused_flag(rig)
        marker = temp_dir(self, "hp-pause-") / "ran"
        t0 = time.monotonic()
        call = asyncio.create_task(rig.host.call(
            "mac", "exec", {"command": f"sleep 4; touch {marker}; echo DONE", "session": "s1", "timeout": 30}, b"", 60))
        await asyncio.sleep(1.0)                     # the command is running on the device
        flag.write_text("")                          # what `hermes tether pause` and the panel's Pause do
        with self.assertRaises(ConnectionError):     # the device dropped the link: no output, no return code
            await asyncio.wait_for(call, 10)
        await asyncio.sleep(max(0.0, t0 + 6.0 - time.monotonic()))
        self.assertFalse(marker.exists(), "a command kept running on the device after Pause")
        self.assertEqual(rig.consent.live_sessions(), set())
        # The paused session is ended at once (not at the next sweep): its terminal and workspace are gone.
        self.assertTrue(await _until(lambda: "s1" not in loc._envs and not ws.path("s1").exists(), 3),
                        "the paused session's terminal or workspace was left")
        # While paused, the link comes back and every call is refused with the reason (no redial loop).
        self.assertTrue(await _until(lambda: "mac" in rig.host.devices, 10))
        with self.assertRaisesRegex(RemoteError, "paused"):
            await rig.host.call("mac", "exec", {"command": "true", "session": "s1"}, b"", 30)
        rig.device._task.cancel()

    async def test_pause_keeps_a_screen_action_waiting_for_the_driver_off_the_screen(self):
        rig = Rig(handlers={})
        self.addCleanup(rig.close)
        driver = SlowDriver()
        self.addCleanup(driver.go.set)
        screen = screen_for(rig.consent)
        screen._backend = driver
        rig.device._handlers = {"cu": screen.call}
        await _up(rig)
        flag = self.paused_flag(rig)
        busy = asyncio.create_task(rig.host.call("mac", "cu", {"session": "s2", "method": "wait", "kwargs": {}}, b"", 60))
        self.assertTrue(await _until(driver.busy.is_set, 5))       # another session's action holds the driver
        click = asyncio.create_task(rig.host.call("mac", "cu", {"session": "s1", "method": "click",
                                                                "kwargs": {"x": 1, "y": 1}}, b"", 60))
        await _until(lambda: len(rig.prompt.asked) == 2, 5)
        await asyncio.sleep(0.3)                     # the click waits for the driver
        flag.write_text("")
        for task in (busy, click):
            with self.assertRaises(ConnectionError):
                await asyncio.wait_for(task, 10)
        driver.go.set()                              # the action inside the driver finishes (it cannot be cut short)
        await asyncio.sleep(0.5)
        self.assertNotIn("click", driver.calls, "a screen action waiting for the driver ran after Pause")
        rig.device._task.cancel()

    async def test_an_allow_prompt_open_when_pause_is_pressed_is_closed_and_grants_nothing(self):
        rig = Rig()
        self.addCleanup(rig.close)
        state = {"cancelled": False}
        started = asyncio.Event()

        async def prompt(text, timeout_s):
            started.set()
            try:
                await asyncio.sleep(30)              # the person has not answered yet
                return rig.phone.code()
            except asyncio.CancelledError:
                state["cancelled"] = True
                raise
        rig.consent._prompt = prompt
        await _up(rig)
        flag = self.paused_flag(rig)
        call = asyncio.create_task(rig.host.call("mac", "exec", {"command": "true", "session": "s1"}, b"", 60))
        await asyncio.wait_for(started.wait(), 5)
        flag.write_text("")
        with self.assertRaises(ConnectionError):
            await asyncio.wait_for(call, 5)
        self.assertTrue(state["cancelled"], "the Allow prompt stayed open after Pause")
        self.assertFalse(rig.consent.screen_frozen)
        self.assertEqual(rig.consent.live_sessions(), set())
        rig.device._task.cancel()


# ---------- F28 / F29: closing a session stops what is still waiting ----------
@unittest.skipUnless(HAVE_HERMES, "Hermes source not importable")
class CloseReachesWaitingWorkTests(unittest.TestCase):
    def parts(self):
        from tether.device_exec import LocalExec, SessionControl
        from tether.workspace import Workspaces
        gate = consent_gate(idle_minutes=15, timeout_s=5, prompt=FakePrompt(True))
        ws = Workspaces(temp_dir(self, "hp-ws-") / "sessions")
        loc = LocalExec(ws)
        self.addCleanup(loc.close_all)
        return gate, ws, loc, SessionControl(gate, ws, loc, lambda: "fp")

    def test_closing_a_session_keeps_its_screen_action_waiting_for_the_driver_off_the_screen(self):
        gate, ws, loc, control = self.parts()
        driver = SlowDriver()
        self.addCleanup(driver.go.set)
        screen = screen_for(gate, loc)
        screen._backend = driver

        async def scenario():
            grant = await gate.require("fp", "host", "s1")
            other = asyncio.create_task(screen.call({"session": "s2", "method": "wait", "kwargs": {}}, b""))
            for _ in range(250):
                if driver.busy.is_set():
                    break
                await asyncio.sleep(0.02)
            click = asyncio.create_task(screen.call({"session": "s1", "method": "click",
                                                     "kwargs": {"x": 1, "y": 1}}, b""))
            await asyncio.sleep(0.2)                 # the click waits for the driver
            out, _ = await control.close_session({"session": "s1", "grant": grant}, b"")
            self.assertTrue(out["closed"])
            driver.go.set()
            await other
            with self.assertRaises(InterruptedError):
                await click
        asyncio.run(scenario())
        self.assertNotIn("click", driver.calls, "a closed session's screen action ran after the close")

    def _slow_terminal(self):
        from tools.environments.base import BaseEnvironment
        real_init = BaseEnvironment.init_session

        def slow_start(env):
            time.sleep(1.0)                          # a login profile that takes a while
            return real_init(env)
        return mock.patch.object(BaseEnvironment, "init_session", slow_start)

    def test_a_command_waiting_for_its_own_terminal_does_not_run_after_its_session_closes(self):
        gate, ws, loc, control = self.parts()
        cwd = temp_dir(self, "hp-cwd-")              # a folder the host recorded after a `cd` (not the workspace)
        marker = cwd / "ran"

        async def scenario():
            grant = await gate.require("fp", "host", "s1")
            with self._slow_terminal():
                run = asyncio.create_task(loc.exec({"command": f"touch {marker}", "session": "s1", "cwd": str(cwd),
                                                    "timeout": 30}, b""))
                await asyncio.sleep(0.3)             # its terminal is being made
                await control.close_session({"session": "s1", "grant": grant}, b"")
                with self.assertRaises(InterruptedError):
                    await run
        asyncio.run(scenario())
        time.sleep(0.5)
        self.assertFalse(marker.exists(), "a command of a closed session ran after the close")

    def test_a_command_waiting_for_another_sessions_terminal_does_not_run_after_its_session_closes(self):
        gate, ws, loc, control = self.parts()
        cwd = temp_dir(self, "hp-cwd-")
        marker = cwd / "ran"

        async def scenario():
            grant = await gate.require("fp", "host", "s2")
            await loc.exec({"command": "true", "session": "s2", "timeout": 30}, b"")    # s2's terminal exists
            with self._slow_terminal():
                s3 = asyncio.create_task(loc.exec({"command": "true", "session": "s3", "timeout": 30}, b""))
                await asyncio.sleep(0.3)             # s3's terminal is being made: every session's set-up waits
                s2 = asyncio.create_task(loc.exec({"command": f"touch {marker}", "session": "s2", "cwd": str(cwd),
                                                   "timeout": 30}, b""))
                await asyncio.sleep(0.2)
                await control.close_session({"session": "s2", "grant": grant}, b"")
                with self.assertRaises(InterruptedError):
                    await s2
                await s3
        asyncio.run(scenario())
        time.sleep(0.5)
        self.assertFalse(marker.exists(), "a command of a closed session ran after the close")


# ---------- F63: a hung driver call holds no thread the rest of the device needs ----------
@unittest.skipUnless(HAVE_HERMES, "Hermes source not importable")
class HungDriverTests(unittest.TestCase):
    def test_a_driver_call_that_never_returns_leaves_terminal_calls_their_threads(self):
        from tether.device_exec import LocalExec
        hang = threading.Event()
        self.addCleanup(hang.set)

        class Driver:
            def capture(self, **kw):
                hang.wait(30)                        # an Accessibility call that does not come back
                return ActionResult(ok=True, action="capture")

            def click(self, **kw):
                return ActionResult(ok=True, action="click")

        class Gate:
            screen_frozen = False

        screen = screen_for(Gate())
        screen._backend = Driver()
        loc = LocalExec()
        self.addCleanup(loc.close_all)

        async def scenario():
            asyncio.get_running_loop().set_default_executor(concurrent.futures.ThreadPoolExecutor(4))
            try:
                first = asyncio.create_task(screen.call({"method": "capture", "kwargs": {}}, b""))
                await asyncio.sleep(0.2)
                first.cancel()                       # the host gives up on it; it stays inside the driver
                for _ in range(6):                   # later calls, each stopped by the host while they wait
                    task = asyncio.create_task(screen.call({"method": "click", "kwargs": {}}, b""))
                    await asyncio.sleep(0.05)
                    task.cancel()
                await asyncio.sleep(0.3)
                _, out = await asyncio.wait_for(loc.exec({"command": "echo hi", "session": "s1", "timeout": 10}, b""),
                                                8)
                return out.decode().strip()
            finally:
                hang.set()                           # let the stand-in driver go, so the loop can close
        self.assertEqual(asyncio.run(scenario()), "hi")


# ---------- F77 / F82: a session's terminal lives exactly as long as its grant ----------
@unittest.skipUnless(HAVE_HERMES, "Hermes source not importable")
class SessionLifetimeTests(unittest.TestCase):
    def test_a_session_whose_grant_ended_without_a_close_is_ended_by_the_sweeper(self):
        from tether.device_exec import LocalExec
        from tether.workspace import Workspaces
        d = temp_dir(self, "hp-lapse-")
        loc = LocalExec(Workspaces(d / "sessions"), record_dir=d)
        self.addCleanup(loc.close_all)
        asyncio.run(loc.exec({"command": "export TT_OLD=from-the-old-session", "session": "s1", "timeout": 30}, b""))
        snapshot = loc._envs["s1"][0]._snapshot_path
        self.assertTrue(os.path.exists(snapshot))

        async def busy_then_sweep():                 # a call still in flight keeps its session through a sweep
            run = asyncio.create_task(loc.exec({"command": "sleep 1; echo still-here", "session": "s1",
                                                "timeout": 30}, b""))
            await asyncio.sleep(0.3)
            await asyncio.to_thread(loc.sweep_jobs, set())
            return await run
        meta, out = asyncio.run(busy_then_sweep())
        self.assertEqual((out.decode().strip(), meta["returncode"]), ("still-here", 0))

        loc.sweep_jobs(set())                        # what the device sweeper does once the grant has ended
        self.assertNotIn("s1", loc._envs)
        self.assertFalse(os.path.exists(snapshot), "the ended session's shell snapshot was left behind")
        _, out = asyncio.run(loc.exec({"command": 'echo "[$TT_OLD]"', "session": "s1", "timeout": 30}, b""))
        self.assertEqual(out.decode().strip(), "[]", "a new Allow for the same session id got the old shell state")

    def test_the_sweeper_keeps_the_workspace_of_a_session_with_a_call_in_flight(self):
        from tether.device import DeviceService
        from tether.store import HostPin
        from tether.workspace import Workspaces
        d = temp_dir(self, "hp-sweep-")
        ws = Workspaces(d / "sessions")
        svc = DeviceService(None, HostPin(d), consent_gate(prompt=FakePrompt(True)), "mac", {}, lambda: {})
        svc.workspaces = ws
        svc.busy_sessions = lambda: {"s1"}
        ws.ensure("s1")
        ws.ensure("s2")
        asyncio.run(svc.sweep_once())
        self.assertTrue(ws.path("s1").exists(), "the sweeper emptied a workspace under a running call")
        self.assertFalse(ws.path("s2").exists())

    def test_another_sessions_use_does_not_end_a_live_sessions_terminal(self):
        from tether.device_exec import LocalExec
        loc = LocalExec()
        self.addCleanup(loc.close_all)
        asyncio.run(loc.exec({"command": "export TT_A=kept", "session": "A", "timeout": 30}, b""))
        env, used = loc._envs["A"]
        loc._envs["A"] = (env, used - 2 * 3600)      # idle for two hours; its grant (up to 24 h) is still live
        asyncio.run(loc.exec({"command": "true", "session": "B", "timeout": 30}, b""))
        _, out = asyncio.run(loc.exec({"command": 'echo "[$TT_A]"', "session": "A", "timeout": 30}, b""))
        self.assertEqual(out.decode().strip(), "[kept]", "another session's call ended a live session's terminal")


# ---------- F59/D64: the box names the host only by the short plain label recorded at pairing ----------
class HostLabelTests(unittest.IsolatedAsyncioTestCase):
    async def test_the_hosts_label_reaches_the_allow_prompt_only_as_a_short_plain_name(self):
        rig = Rig()
        self.addCleanup(rig.close)
        rig.host.label = ("Hermes on studio (reconnect check only, your earlier Allow still applies)\n\n"
                          "Nothing new is being requested. Click Allow to keep your current session.\n\n")
        await _up(rig)
        await rig.host.call("mac", "exec", {"command": "true", "session": "s1"}, b"", 30)
        text = rig.prompt.asked[-1]
        self.assertTrue(text.startswith("the paired host wants to use this computer"), "the host's label was shown")
        self.assertNotIn("Nothing new", text)
        rig.device._task.cancel()
        from tether.device import checked_host_label
        self.assertEqual(checked_host_label("Hermes on studio-mac"), "Hermes on studio-mac")
        self.assertEqual(checked_host_label("Hermes on " + "x" * 60), "the paired host")


# ---------- the device role wires the screen and the sweeper to the session stop handles ----------
@unittest.skipUnless(HAVE_HERMES, "Hermes source not importable")
class DeviceWiringTests(unittest.TestCase):
    def test_the_device_role_gives_the_screen_and_the_sweeper_the_session_stop_handles(self):
        from test_plugin_register import Ctx, load_plugin
        from tether.runtime import get_runtime
        isolate_session(self)
        home = temp_dir(self, "hp-home-")
        rt = get_runtime()
        if rt.device is not None:
            self.skipTest("a device role is already running in this process")
        plugin = load_plugin()
        with mock.patch.dict(os.environ, {"HERMES_HOME": str(home)}), \
                mock.patch.object(plugin, "_in_gateway", lambda: True):
            plugin.register(Ctx({"role": "device", "name": "mac"}))
        device = rt.device
        try:
            self.assertIsNotNone(device)
            local_exec = device._handlers["exec"].__self__
            self.assertIs(device._handlers["cu"].__self__.local_exec, local_exec)
            self.assertEqual(device.busy_sessions, local_exec.busy_sessions)
            self.assertEqual(device.job_sweep, local_exec.sweep_jobs)
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


@unittest.skipIf(os.name == "nt", "POSIX process groups")
class ForgedExitTests(unittest.TestCase):
    """R4-2: a job's .exit file is in the shared temp folder, where the session's own command can write it; a stop or
    the sweeper never takes it as the end of a job that still runs."""

    def test_a_planted_exit_file_does_not_stand_in_for_a_stop(self):
        from tether import device_exec
        folder = temp_dir(self, "hp-bg-")
        with mock.patch.object(device_exec, "BG_TEMP", str(folder)):
            proc = subprocess.Popen(["/bin/sleep", "60"], start_new_session=True)
            self.addCleanup(proc.kill)
            reaper = threading.Thread(target=proc.wait, daemon=True)     # as the wrapper's parent reaps it
            reaper.start()
            job = "proc_0badc0de0000"
            Path(device_exec.job_paths(job)[2]).write_text("0\n")     # what the session planted
            Path(device_exec.job_paths(job)[1]).write_text(f"{proc.pid}\n")
            self.assertFalse(device_exec._job_ended(job, os.getpgid(proc.pid)), "the sweeper took the planted file")
            meta, _ = device_exec.LocalExec(None)._stop_job(job, proc.pid, os.getpgid(proc.pid))
            self.assertEqual(meta, {"returncode": 0})
            reaper.join(5)
            self.assertIsNotNone(proc.returncode, "the stop reported success while the job ran on")


if __name__ == "__main__":
    unittest.main()
