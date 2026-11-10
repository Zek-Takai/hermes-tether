"""The host's ``tether`` terminal backend driving a device's real Hermes LocalEnvironment (loopback).

Needs Hermes itself importable (run with Hermes's Python; the test adds its source folder to the path).
"""
from __future__ import annotations

import os
import tempfile
import sys
import unittest
from pathlib import Path
from unittest import mock

HERMES_SRC = Path.home() / ".hermes" / "hermes-agent"
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "plugin" / "tether"))
sys.path.insert(1, str(HERMES_SRC))

try:
    import tools.approval_detection  # noqa: F401
    import tools.environments.local  # noqa: F401
    HAVE_HERMES = True
except Exception:  # noqa: BLE001
    HAVE_HERMES = False

from tether.runtime import get_runtime  # noqa: E402

from test_link_loopback import Rig  # noqa: E402


@unittest.skipUnless(HAVE_HERMES, "Hermes source not importable")
class TerminalBackendTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tether.device_exec import LocalExec
        cls.rt = get_runtime()
        cls.local_exec = LocalExec()
        cls.rig = Rig(handlers={"exec": cls.local_exec.exec})

        async def up():
            _, task = await cls.rig.pair()
            await task
            await cls.rig.connect()
        cls.rt.run(up(), 30)
        cls.rt.host = cls.rig.host
        os.environ.pop("HERMES_SESSION_ID", None)

    @classmethod
    def tearDownClass(cls):
        cls.rt.loop.call_soon_threadsafe(cls.rig.device._task.cancel)
        cls.local_exec.close_all()
        cls.rt.host = None
        cls.rt.targets.clear()
        cls.rt.turn_open.clear()
        cls.rt.last_device.clear()

    def env(self):
        from tether.provider import TetherEnvironment
        return TetherEnvironment("~", 30, "t1")

    def test_commands_and_cwd_go_to_the_device(self):
        self.rt.targets["default"] = "mac"
        self.rt.turn_open["default"] = True
        env = self.env()
        r = env.execute("cd /tmp && echo hi")
        self.assertEqual((r["output"].strip(), r["returncode"]), ("hi", 0))
        self.assertTrue(r["cwd_observed"])
        self.assertTrue(r["cwd"].endswith("/tmp"))
        r = env.execute("pwd", r["cwd"])
        self.assertTrue(r["output"].strip().endswith("/tmp"))
        r = env.execute("cat", stdin_data="from stdin")
        self.assertEqual(r["output"], "from stdin")
        r = env.execute("exit 3")
        self.assertEqual(r["returncode"], 3)

    def test_attached_files_come_back_from_the_device(self):
        # Hermes's MEDIA delivery from a remote backend: fetch_realpath, then fetch_file (gateway/media_fetch.py).
        import tempfile
        self.rt.targets["default"] = "mac"
        self.rt.turn_open["default"] = True
        env = self.env()
        payload = bytes(range(256)) * 300                      # binary, ~77 KB
        src = Path(tempfile.mkdtemp(prefix="hp-dev-")) / "shot.jpg"
        src.write_bytes(payload)
        real = env.fetch_realpath(str(src))
        self.assertTrue(real and real.endswith("/shot.jpg"))
        dest = Path(tempfile.mkdtemp(prefix="hp-host-")) / "copy.jpg"
        env.fetch_file(real, dest, max_bytes=10 * 1024 * 1024)
        self.assertEqual(dest.read_bytes(), payload)
        self.assertEqual(env._remote_home, str(Path.home()))

    def _local_misses(self, env):
        # The file is not on this host: every host-side lookup fails (as on the NAS for a Mac path).
        return mock.patch.object(env, "_run_local", return_value={"output": "", "returncode": 1})

    def test_attachment_found_on_last_device_after_switching_back(self):
        import tempfile
        env = self.env()
        payload = b"render-bytes" * 1000
        src = Path(tempfile.mkdtemp(prefix="hp-dev-")) / "torus.png"
        src.write_bytes(payload)
        self.rt.targets["default"] = "local"
        self.rt.turn_open["default"] = True
        self.rt.last_device["default"] = "mac"
        env._homes["mac"] = str(Path.home())
        with self._local_misses(env):
            real = env.fetch_realpath(str(src))
            self.assertTrue(real and real.endswith("/torus.png"))
            dest = Path(tempfile.mkdtemp(prefix="hp-host-")) / "copy.png"
            env.fetch_file(real, dest, max_bytes=10 * 1024 * 1024)
        self.assertEqual(dest.read_bytes(), payload)

    def test_device_attachment_denylist_uses_the_device_home(self):
        import tempfile
        env = self.env()
        fake_home = Path(tempfile.mkdtemp(prefix="hp-fakehome-"))
        (fake_home / ".ssh").mkdir()
        key = fake_home / ".ssh" / "id_ed25519"
        key.write_text("dummy, not a key")
        self.rt.targets["default"] = "local"
        self.rt.turn_open["default"] = True
        self.rt.last_device["default"] = "mac"
        env._homes["mac"] = str(fake_home)
        with self._local_misses(env):
            self.assertIsNone(env.fetch_realpath(str(key)))

    def test_no_last_device_no_fallback(self):
        env = self.env()
        self.rt.targets["default"] = "local"
        self.rt.turn_open["default"] = True
        self.rt.last_device.clear()
        with self._local_misses(env):
            self.assertIsNone(env.fetch_realpath("/tmp/whatever.png"))

    def test_device_hardline_check(self):
        self.rt.targets["default"] = "mac"
        self.rt.turn_open["default"] = True
        fake = lambda c: (c == "echo HARDLINE-TEST", "test pattern")  # noqa: E731 - never runs anything real
        with mock.patch("tools.approval_detection.detect_hardline_command", fake), \
                mock.patch("tools.approval.detect_hardline_command", fake):
            r = self.env().execute("echo HARDLINE-TEST")
        self.assertEqual(r["returncode"], 1)
        self.assertIn("hardline", r["output"])
        self.assertNotIn("HARDLINE-TEST\n", r["output"])

    # D25: Hermes's own gates run on the host; the device adds its floors, and judges in full only what did not
    # pass the host's command gate. Detection is faked so nothing dangerous runs; "echo FLAGGED" stands in for
    # a command the rules flag.
    def _flagging(self, mode="manual"):
        findings = lambda c: [("tether_test", "test flag")] if "FLAGGED" in c else []  # noqa: E731
        return (mock.patch("tools.approval._command_findings", findings),
                mock.patch("tools.approval_context._get_approval_mode", lambda: mode),
                mock.patch("tools.approval._command_matches_permanent_allowlist", lambda c: False),
                mock.patch("tools.approval._is_permanently_approved", lambda k: False))

    def _on_device(self):
        self.rt.targets["default"] = "mac"
        self.rt.turn_open["default"] = True

    @staticmethod
    def _hermes_command_gate_reads(provider):
        def check_all_command_guards():          # named like Hermes's gate: the provider looks for its reader
            return provider.skip_container_guards
        return check_all_command_guards()

    def test_hermes_gates_are_never_skipped(self):
        from tether.provider import make_provider, _take_guard_handoff
        p = make_provider()
        self._on_device()
        self.assertFalse(self._hermes_command_gate_reads(p))

        def check_execute_code_guard():
            return p.skip_container_guards
        _take_guard_handoff()
        self.assertFalse(check_execute_code_guard())
        self.assertFalse(_take_guard_handoff())          # the code gate does not stand in for the command gate
        self.rt.targets["default"] = "local"
        self.assertFalse(p.skip_container_guards)

    def test_command_that_passed_the_hermes_gate_is_not_asked_again(self):
        from tether.provider import make_provider
        p = make_provider()
        self._on_device()
        never = mock.Mock(side_effect=AssertionError("asked twice"))
        a, b, c, d = self._flagging()
        with a, b, c, d, mock.patch("tools.approval.check_dangerous_command", never):
            self._hermes_command_gate_reads(p)
            r = self.env().execute("echo FLAGGED")
        self.assertEqual((r["output"].strip(), r["returncode"]), ("FLAGGED", 0))

    def test_device_floors_hold_even_after_the_hermes_gate(self):
        from tether.provider import make_provider
        p = make_provider()
        self._on_device()
        fake = lambda c: (c == "echo HARDLINE-TEST", "test pattern")  # noqa: E731
        with mock.patch("tools.approval.detect_hardline_command", fake):
            self._hermes_command_gate_reads(p)
            r = self.env().execute("echo HARDLINE-TEST")
        self.assertEqual(r["returncode"], 1)
        self.assertNotIn("HARDLINE-TEST\n", r["output"])

    def test_ungated_flagged_command_goes_through_hermes_command_gate(self):
        self._on_device()
        asked = []

        def gate(command, env_type, **kw):
            asked.append((command, env_type))
            return {"approved": True}
        a, b, c, d = self._flagging()
        with a, b, c, d, mock.patch("tools.approval.check_dangerous_command", gate):
            r = self.env().execute("echo FLAGGED")
        self.assertEqual((r["output"].strip(), r["returncode"]), ("FLAGGED", 0))
        self.assertEqual(asked, [("echo FLAGGED", "local")])

    def test_ungated_flagged_command_does_not_run_when_refused(self):
        self._on_device()
        marker = Path(tempfile.mkdtemp(prefix="hp-d25-")) / "ran"
        a, b, c, d = self._flagging()
        with a, b, c, d, mock.patch("tools.approval.check_dangerous_command",
                                    lambda *x, **k: {"approved": False, "message": "BLOCKED: denied"}):
            r = self.env().execute(f"echo FLAGGED && touch {marker}")
        self.assertEqual((r["output"], r["returncode"]), ("BLOCKED: denied", 1))
        self.assertFalse(marker.exists())

    def test_clean_command_and_device_approvals_off_never_ask(self):
        self._on_device()
        never = mock.Mock(side_effect=AssertionError("asked"))
        a, b, c, d = self._flagging(mode="off")
        with a, b, c, d, mock.patch("tools.approval.check_dangerous_command", never):
            self.assertEqual(self.env().execute("echo FLAGGED")["returncode"], 0)
        a, b, c, d = self._flagging()
        with a, b, c, d, mock.patch("tools.approval.check_dangerous_command", never):
            self.assertEqual(self.env().execute("echo clean")["output"].strip(), "clean")

    def test_command_meant_for_the_device_never_runs_on_the_host(self):
        from tether.provider import make_provider
        p = make_provider()
        self._on_device()
        self._hermes_command_gate_reads(p)               # gated while the mac was the target
        self.rt.targets["default"] = "local"            # ...then the connection closed before it ran
        marker = Path(tempfile.mkdtemp(prefix="hp-d25-")) / "ran"
        r = self.env().execute(f"touch {marker}")
        self.assertEqual(r["returncode"], 1)
        self.assertIn("did not run anywhere", r["output"])
        self.assertFalse(marker.exists())
        self.assertEqual(self.env().execute("echo here")["output"].strip(), "here")   # next local call is normal

    def test_local_target_and_unknown_device(self):
        self.rt.targets["default"] = "local"
        self.rt.turn_open["default"] = True
        r = self.env().execute("echo here")
        self.assertEqual(r["output"].strip(), "here")
        self.rt.targets["default"] = "ghost"
        self.rt.turn_open["default"] = True
        r = self.env().execute("echo nope")
        self.assertEqual(r["returncode"], 1)
        self.assertIn("no paired device", r["output"])


if __name__ == "__main__":
    unittest.main()
