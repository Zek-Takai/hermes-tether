"""Tether panel: the connection log, the device's own settings (applied live), and the panel's backend API."""
from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "plugin" / "tether"))
sys.path.insert(1, str(Path.home() / ".hermes" / "hermes-agent"))

from tether import store  # noqa: E402
from tether.consent import ConsentGate  # noqa: E402
from tether.device import DeviceService  # noqa: E402

from test_link_loopback import FakePrompt  # noqa: E402


def tmpdir() -> Path:
    return Path(tempfile.mkdtemp(prefix="hp-panel-"))


class EventLogTests(unittest.TestCase):
    def test_log_is_newest_first_short_and_bounded(self):
        d = tmpdir()
        store.log_event(d, "tethered", device="mac", session="20261107_223218_53ebf4")
        store.log_event(d, "untethered", device="mac", session="20261107_223218_53ebf4", reason="closed by the user",
                        empty="")
        events = store.read_events(d)
        self.assertEqual([e["kind"] for e in events], ["untethered", "tethered"])
        self.assertEqual(events[0]["session"], "53ebf4")              # never the full session id
        self.assertNotIn("empty", events[0])
        self.assertEqual(oct((d / store.EVENTS_FILE).stat().st_mode & 0o777), "0o600")
        with mock.patch.object(store, "EVENTS_MAX_BYTES", 2000), mock.patch.object(store, "EVENTS_KEEP", 5):
            for i in range(100):
                store.log_event(d, "allowed", session=f"s{i}")
        self.assertLessEqual(len(store.read_events(d, 1000)), 40)

    def test_log_never_raises(self):
        store.log_event(None, "tethered")
        store.log_event(Path("/nonexistent/forbidden"), "tethered")
        self.assertEqual(store.read_events(Path("/nonexistent/forbidden")), [])


class PanelSettingsTests(unittest.TestCase):
    def test_validated_and_bounded(self):
        d = tmpdir()
        self.assertEqual(store.write_panel_settings(d, {"grant_idle_minutes": 30}), {"grant_idle_minutes": 30.0})
        with self.assertRaisesRegex(ValueError, "between 1 and 1440"):
            store.write_panel_settings(d, {"grant_idle_minutes": 0})
        with self.assertRaisesRegex(ValueError, "unknown setting"):
            store.write_panel_settings(d, {"role": "host"})                  # the panel can never change a role
        (d / store.SETTINGS_FILE).write_text(json.dumps({"grant_idle_minutes": 99999, "consent_timeout_seconds": 30}))
        self.assertEqual(store.read_panel_settings(d), {"consent_timeout_seconds": 30.0})   # out of range ignored
        self.assertEqual(store.write_panel_settings(d, {"consent_timeout_seconds": 5}), {"consent_timeout_seconds": 5.0})
        with self.assertRaisesRegex(ValueError, "between 5 and 600"):
            store.write_panel_settings(d, {"consent_timeout_seconds": 4})

    def test_device_applies_panel_settings_live_and_logs_it(self):
        d = tmpdir()
        gate = ConsentGate(idle_minutes=60, timeout_s=60, prompt=FakePrompt(True))
        svc = DeviceService(None, store.HostPin(d), gate, "mac", {}, lambda: {})
        self.assertFalse(asyncio.run(svc.apply_panel_settings()))
        store.write_panel_settings(d, {"grant_idle_minutes": 5, "consent_timeout_seconds": 20})
        self.assertTrue(asyncio.run(svc.apply_panel_settings()))
        self.assertEqual((gate.idle_s, gate.timeout_s), (300.0, 20.0))
        self.assertFalse(asyncio.run(svc.apply_panel_settings()))            # no change, no log line
        self.assertEqual([e["kind"] for e in store.read_events(d)], ["settings_changed"])


class ConsentLogTests(unittest.IsolatedAsyncioTestCase):
    async def test_allowed_and_denied_are_logged(self):
        d = tmpdir()
        prompt = FakePrompt(False)
        gate = ConsentGate(idle_minutes=15, timeout_s=5, prompt=prompt)
        gate.events_dir = d
        with self.assertRaises(PermissionError):
            await gate.require("fp", "Hermes on nas", "20261107_223218_53ebf4")
        prompt.answer = True
        await gate.require("fp", "Hermes on nas", "20261107_223218_53ebf4")
        kinds = [(e["kind"], e["session"]) for e in store.read_events(d)]
        self.assertEqual(kinds, [("allowed", "53ebf4"), ("denied", "53ebf4")])


class DeviceLabelTests(unittest.TestCase):
    def test_labels_are_spoken_words(self):
        self.assertEqual(store.normalize_label("Studio PC"), "studio-pc")
        self.assertEqual(store.normalize_label("  studio_pc "), "studio-pc")
        for bad in ("", "local", "a/b", "x" * 40, "../etc"):
            with self.assertRaises(ValueError):
                store.normalize_label(bad)

    def test_rename_and_host_idle_limit(self):
        d = tmpdir()
        pins = store.DevicePins(d)
        pins.add("mac", "ab" * 32, "CERT")
        pins.add("pc", "cd" * 32, "CERT2")
        self.assertEqual(pins.update("mac", label="Studio Mac", idle_minutes=20), "studio-mac")
        self.assertEqual(sorted(pins.all()), ["pc", "studio-mac"])
        self.assertEqual(pins.all()["studio-mac"]["fp"], "ab" * 32)          # same pinned machine, new word
        self.assertEqual(pins.idle_minutes("studio-mac"), 20.0)
        with self.assertRaisesRegex(ValueError, "already called"):
            pins.update("pc", label="studio mac")
        with self.assertRaisesRegex(ValueError, "between 1 and 1440"):
            pins.update("pc", idle_minutes=0)
        pins.update("studio-mac", idle_minutes=None)
        self.assertIsNone(pins.idle_minutes("studio-mac"))

    def test_shorter_idle_limit_wins(self):
        from tether.runtime import Runtime
        d = tmpdir()
        pins = store.DevicePins(d)
        pins.add("mac", "ab" * 32, "CERT")
        rt = Runtime.__new__(Runtime)
        rt.idle_limit_s = {"mac": 3600.0}
        rt.host = type("H", (), {"pins": pins})()
        self.assertEqual(rt.idle_limit("mac"), 3600.0)
        pins.update("mac", idle_minutes=10)
        self.assertEqual(rt.idle_limit("mac"), 600.0)
        pins.update("mac", idle_minutes=120)
        self.assertEqual(rt.idle_limit("mac"), 3600.0)                       # the machine's own limit still holds
        rt.idle_limit_s = {}
        self.assertEqual(rt.idle_limit("mac"), 7200.0)

    def test_computer_name_never_leaves_the_device(self):
        from tether import device
        self.assertNotIn("hostname", device._local_facts())
        from tether.host import HostService
        pins = store.DevicePins(tmpdir())
        pins.add("mac", "ab" * 32, "CERT")
        svc = HostService.__new__(HostService)
        svc.pins, svc.last_seen = pins, {}
        conn = type("C", (), {"announce": {"os": "Darwin", "hostname": "Someones-MacBook"}, "link": {}})()
        svc.devices = {"mac": conn}
        row = svc.status()[0]
        self.assertNotIn("hostname", row["capabilities"])
        self.assertEqual(row["capabilities"]["os"], "Darwin")


class FollowHostPinTests(unittest.IsolatedAsyncioTestCase):
    async def test_device_follows_a_new_pairing_without_restart(self):
        d = tmpdir()
        pin = store.HostPin(d)
        pin.set(host="192.0.2.10", port=9130, fp="aa" * 32, cert_pem="A", host_label="Hermes on nas")
        gate = ConsentGate(idle_minutes=15, timeout_s=5, prompt=FakePrompt(True))
        await gate.require("aa" * 32, "Hermes on nas", "s1")
        svc = DeviceService(None, pin, gate, "mac", {}, lambda: {})

        class FakePeer:
            def __init__(self):
                self.closed = asyncio.Event()

            async def close(self):
                self.closed.set()

        svc.peer = FakePeer()
        svc._connected_key = svc._pin_key(pin.get())
        self.assertFalse(await svc.follow_host_pin())                 # same pairing: stay connected
        self.assertFalse(svc.peer.closed.is_set())

        pin.set(host="192.0.2.20", port=9130, fp="bb" * 32, cert_pem="B", host_label="Hermes on server")
        self.assertTrue(await svc.follow_host_pin())                  # re-paired: drop the old host now
        self.assertTrue(svc.peer.closed.is_set())
        self.assertTrue(svc._redial.is_set())                         # the loop dials the new host at once
        self.assertEqual(gate.live_sessions(), set())                 # the old host's grants are gone
        self.assertEqual(store.read_events(d)[0]["kind"], "host_changed")

        svc.peer, svc._redial = FakePeer(), asyncio.Event()
        svc._connected_key = svc._pin_key(pin.get())
        pin.clear()
        self.assertTrue(await svc.follow_host_pin())                  # unpaired: leave too


try:
    import fastapi  # noqa: F401
    HAVE_FASTAPI = True
except Exception:  # noqa: BLE001
    HAVE_FASTAPI = False


@unittest.skipUnless(HAVE_FASTAPI, "fastapi not importable")
class PanelApiTests(unittest.TestCase):
    def setUp(self):
        import importlib.util
        self.home = tmpdir()
        os.environ["HERMES_HOME"] = str(self.home)
        spec = importlib.util.spec_from_file_location(
            "tether_panel_api_test", Path(__file__).resolve().parents[1] / "plugin" / "tether" / "dashboard" / "plugin_api.py")
        self.api = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.api)
        self.d = self.home / "tether"

    def tearDown(self):
        os.environ.pop("HERMES_HOME", None)

    def roles(self, role):
        return mock.patch.object(self.api, "_settings", lambda: {"roles": role, "name": "nas", "grant_idle_minutes": 60.0,
                                                                  "consent_timeout_seconds": 60.0})

    def test_host_status_lists_pairings_without_taking_the_link(self):
        self.d.mkdir(parents=True, exist_ok=True)
        store.DevicePins(self.d).add("mac", "ab" * 32, "CERT")
        store.log_event(self.d, "tethered", device="mac", session="x_53ebf4")
        with self.roles(["host"]):
            body = asyncio.run(self.api.status())
        self.assertEqual(body["host"]["devices"][0]["name"], "mac")
        self.assertEqual(body["host"]["devices"][0]["phrase"], "tether mac")
        self.assertIsNone(body["host"]["devices"][0]["online"])          # no gateway link here: unknown, not owned
        self.assertTrue(body["host"]["note"])
        self.assertFalse((self.d / "link.sock").exists())                 # the panel never became the link owner
        self.assertEqual(body["events"][0]["kind"], "tethered")
        self.assertNotIn("CERT", json.dumps(body))
        self.assertNotIn("ab" * 16, json.dumps(body))

    def test_host_renames_a_device_and_sets_its_idle_limit(self):
        from fastapi import HTTPException
        self.d.mkdir(parents=True, exist_ok=True)
        store.DevicePins(self.d).add("mac", "ab" * 32, "CERT")
        with self.roles(["device"]):
            with self.assertRaises(HTTPException):
                asyncio.run(self.api.update_device("mac", {"label": "x"}))     # a device cannot rename the host's pins
        with self.roles(["host"]):
            res = asyncio.run(self.api.update_device("mac", {"label": "Studio PC", "idle_minutes": 15}))
            self.assertEqual(res, {"name": "studio-pc", "phrase": "tether studio pc"})
            dev = asyncio.run(self.api.status())["host"]["devices"][0]
            self.assertEqual((dev["name"], dev["phrase"], dev["host_idle_minutes"]), ("studio-pc", "tether studio pc", 15.0))
            self.assertNotIn("hostname", dev)
            with self.assertRaises(HTTPException) as e:
                asyncio.run(self.api.update_device("studio-pc", {"label": "local"}))
            self.assertEqual(e.exception.status_code, 400)
        kinds = [e["kind"] for e in store.read_events(self.d)]
        self.assertEqual(kinds[:2], ["settings_changed", "device_renamed"])

    def test_device_status_never_loads_the_host_link(self):
        """The host link is POSIX-only (fcntl, a Unix socket): a device's panel, e.g. on Windows, must not load it."""
        sys.modules.pop("tether_panel_core.hostlink", None)
        with self.roles(["device"]):
            asyncio.run(self.api.status())
        self.assertNotIn("tether_panel_core.hostlink", sys.modules)
        with self.roles(["host"]), mock.patch.object(sys, "platform", "win32"):
            body = asyncio.run(self.api.status())
        self.assertEqual(body["host"]["devices"], [])
        self.assertIn("macOS or Linux", body["host"]["note"])
        self.assertNotIn("tether_panel_core.hostlink", sys.modules)

    def test_settings_and_pause_only_on_a_device(self):
        from fastapi import HTTPException
        with self.roles(["host"]):
            with self.assertRaises(HTTPException) as e:
                asyncio.run(self.api.save_settings({"grant_idle_minutes": 5}))
            self.assertEqual(e.exception.status_code, 403)
        with self.roles(["device"]):
            asyncio.run(self.api.save_settings({"grant_idle_minutes": 5, "role": "host"}))
            body = asyncio.run(self.api.status())
            self.assertEqual(body["device"]["grant_idle_minutes"], 5.0)
            with self.assertRaises(HTTPException):
                asyncio.run(self.api.save_settings({"grant_idle_minutes": -1}))
            self.assertEqual(asyncio.run(self.api.pause({"paused": True})), {"paused": True})
            self.assertTrue(asyncio.run(self.api.status())["device"]["paused"])
            self.assertEqual(asyncio.run(self.api.pause({"paused": False})), {"paused": False})
        kinds = [e["kind"] for e in store.read_events(self.d)]
        self.assertEqual(kinds[:2], ["resumed", "paused"])


class DefaultTimeoutTests(unittest.TestCase):
    def test_consent_wait_defaults_to_15_seconds(self):
        from tether.config import read_settings
        from tether.consent import ConsentGate
        self.assertEqual(read_settings(lambda key, default=None: "device" if key == "role" else default)
                         .consent_timeout_seconds, 15.0)
        self.assertEqual(ConsentGate(prompt=FakePrompt(True)).timeout_s, 15.0)


if __name__ == "__main__":
    unittest.main()
