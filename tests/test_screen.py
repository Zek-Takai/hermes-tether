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

        async def up():
            _, task = await cls.rig.pair()
            await task
            await cls.rig.connect()
        cls.rt.run(up(), 30)
        cls.rt.host = cls.rig.host
        cls.rt.targets["default"] = "mac"
        cls.rt.turn_open["default"] = True
        os.environ.pop("HERMES_SESSION_ID", None)
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

    def test_frozen_screen_refuses_input_but_not_reads(self):
        self.rig.consent.screen_frozen = True
        try:
            r = self.backend.click(x=5, y=5)
            self.assertFalse(r.ok)
            self.assertIn("frozen", r.message)
            self.assertEqual(self.backend.capture().width, 1512)
        finally:
            self.rig.consent.screen_frozen = False

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
