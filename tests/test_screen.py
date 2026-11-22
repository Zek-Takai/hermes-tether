"""tether_screen ↔ device ScreenExec over the loopback link, with a stand-in driver (no real screen)."""
from __future__ import annotations

import importlib.util
import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "plugin" / "tether"))
sys.path.insert(1, str(Path.home() / ".hermes" / "hermes-agent"))

try:
    from tools.computer_use.backend import ActionResult, CaptureResult, UIElement
    HAVE_HERMES = True
except Exception:  # noqa: BLE001
    HAVE_HERMES = False

from tether.runtime import get_runtime  # noqa: E402

from test_link_loopback import Rig  # noqa: E402

BIG_PNG = "iVBOR" + "A" * 400_000          # > one frame body: exercises chunking


class FakeBackend:
    def __init__(self):
        self.calls = []

    def capture(self, mode="som", app=None, pid=None, window_id=None):
        self.calls.append(("capture", mode, app))
        return CaptureResult(mode=mode, width=1512, height=982, png_b64=BIG_PNG, app=app or "Finder",
                             elements=[UIElement(index=1, role="AXButton", label="OK", bounds=(10, 20, 30, 40))])

    def click(self, **kw):
        self.calls.append(("click", kw))
        cap = CaptureResult(mode="vision", width=1, height=1, png_b64="iVBORsmall")
        return ActionResult(ok=True, action="click", message="clicked", capture=cap, effect="confirmed")

    def drag(self, **kw):
        self.calls.append(("drag", kw))
        assert isinstance(kw["from_xy"], tuple)
        return ActionResult(ok=True, action="drag")

    def list_apps(self):
        return [{"name": "Finder", "pid": 1}]


def load_screen_plugin():
    spec = importlib.util.spec_from_file_location("hp_screen_under_test", ROOT / "plugin/tether_screen/__init__.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@unittest.skipUnless(HAVE_HERMES, "Hermes source not importable")
class ScreenTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tether.device_screen import ScreenExec
        cls.rt = get_runtime()
        cls.fake = FakeBackend()
        cls.rig = Rig(handlers={})
        cls.screen = ScreenExec(cls.rig.consent)
        cls.screen._backend = cls.fake
        cls.rig.device._handlers = {"cu": cls.screen.call}

        cls.addClassCleanup(cls.rig.close)

        async def up():
            _, task = await cls.rig.pair()
            await task
            await cls.rig.connect()
        cls.rt.run(up(), 30)
        cls.rt.host = cls.rig.host
        for table in (cls.rt.grants, cls.rt.grant_fp, cls.rt.open_fp):   # another module's rig, another key (D43)
            table.clear()
        cls.rt.targets["default"] = "mac"
        cls.rt.turn_open["default"] = True
        os.environ.pop("HERMES_SESSION_ID", None)
        os.environ.pop("HERMES_SESSION_KEY", None)
        cls.backend = load_screen_plugin().TetherScreenProvider().create_backend(permission_mode="standard")

    @classmethod
    def tearDownClass(cls):
        cls.rt.loop.call_soon_threadsafe(cls.rig.device._task.cancel)
        cls.rt.host = None
        cls.rt.targets.clear()
        cls.rt.turn_open.clear()

    def test_capture_round_trip(self):
        cap = self.backend.capture(app="Finder")
        self.assertEqual((cap.width, cap.height, cap.app), (1512, 982, "Finder"))
        self.assertEqual(cap.png_b64, BIG_PNG)
        self.assertEqual(cap.elements[0].bounds, (10, 20, 30, 40))
        self.assertEqual(cap.elements[0].label, "OK")

    def test_action_with_trailing_capture_and_tuple_args(self):
        r = self.backend.click(element=1, button="left")
        self.assertTrue(r.ok)
        self.assertEqual(r.effect, "confirmed")
        self.assertEqual(r.capture.png_b64, "iVBORsmall")
        self.assertTrue(self.backend.drag(from_xy=(1, 2), to_xy=(3, 4)).ok)
        self.assertEqual(self.backend.list_apps(), [{"name": "Finder", "pid": 1}])

    def test_frozen_screen_refuses_every_action_screenshots_included(self):
        """D65 (threat 2): while the approval box is open no session's action reaches the screen, and no screenshot
        is taken either (base: a capture went through)."""
        self.rig.consent.screen_frozen = True
        before = len(self.fake.calls)
        try:
            r = self.backend.click(x=5, y=5)
            self.assertFalse(r.ok)
            self.assertIn("approval box is open", r.message)
            with self.assertRaisesRegex(Exception, "approval box is open"):
                self.backend.capture()
            with self.assertRaisesRegex(Exception, "approval box is open"):
                self.backend.list_apps()
        finally:
            self.rig.consent.screen_frozen = False
        self.assertEqual(len(self.fake.calls), before, "a screen action reached the driver while the box was open")

    def test_a_stopped_action_that_has_not_started_is_not_carried_out(self):
        # The action waits for the driver (one action at a time). A stop that lands while it waits keeps it off screen.
        import asyncio
        from tether.device_screen import ScreenExec
        fake = FakeBackend()
        screen = ScreenExec(self.rig.consent)
        screen._backend = fake

        async def scenario():
            screen._lock.acquire()                    # another action holds the driver
            task = asyncio.create_task(screen.call({"method": "click", "kwargs": {"x": 1, "y": 1}}, b""))
            await asyncio.sleep(0.2)                  # the click is waiting for the driver
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            screen._lock.release()                    # the worker gets the driver only now
            await asyncio.sleep(0.5)

        asyncio.run(scenario())
        self.assertFalse(any(c[0] == "click" for c in fake.calls), "a stopped screen action was carried out")

    def test_no_device_selected(self):
        self.rt.targets["default"] = "local"
        self.rt.turn_open["default"] = True
        try:
            r = self.backend.click(x=1, y=1)
            self.assertFalse(r.ok)
            self.assertIn("only the user can open", r.message)
        finally:
            self.rt.targets["default"] = "mac"
            self.rt.turn_open["default"] = True


if __name__ == "__main__":
    unittest.main()
