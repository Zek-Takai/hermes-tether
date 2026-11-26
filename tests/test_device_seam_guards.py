"""Gauntlet 3.1, device side: each protection that now rests on a Hermes seam refuses when the seam is not applied."""
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "plugin" / "tether"))
sys.path.insert(1, str(Path(os.environ.get("HERMES_AGENT_SRC") or Path.home() / ".hermes" / "hermes-agent")))

from tether import device_exec, lock  # noqa: E402
from test_link_loopback import remove_tree  # noqa: E402


class FakeTerminal:
    def __init__(self, profile, readable):
        self._tether_profile, self.readable, self.ran = profile, readable, []

    def execute(self, command, timeout=None):
        self.ran.append(command)
        return {"returncode": 0 if self.readable else 1, "output": ""}


class LockAppliedTests(unittest.TestCase):
    def setUp(self):
        folder = Path(tempfile.mkdtemp(prefix="hp-guard-"))
        self.addCleanup(remove_tree, folder)
        self.secret = folder / ".env"
        self.secret.write_text("X=1\n")
        self.addCleanup(lambda: self.secret.unlink(missing_ok=True))
        prot = mock.Mock(scan_files=(str(self.secret),))
        patch = mock.patch.object(lock, "protected_set", return_value=prot)
        patch.start()
        self.addCleanup(patch.stop)

    def test_a_shell_that_never_went_through_the_hook_is_refused(self):
        with self.assertRaises(lock.LockError) as e:
            lock._check_applied(FakeTerminal(None, readable=False))
        self.assertIn("did not go through the lock", str(e.exception))

    def test_a_protected_file_readable_from_the_terminal_is_refused(self):
        with self.assertRaises(lock.LockError) as e:
            lock._check_applied(FakeTerminal("(version 1)", readable=True))
        self.assertIn("protected file was readable", str(e.exception))

    def test_a_locked_terminal_passes_after_one_probe(self):
        term = FakeTerminal("(version 1)", readable=False)
        lock._check_applied(term)
        self.assertEqual(len(term.ran), 1)
        self.assertIn(str(self.secret), term.ran[0])


class ToolRefusalShapeTests(unittest.TestCase):
    def test_a_path_that_is_not_text_is_refused(self):
        for name in ("read_file", "write_file", "search_files", "patch"):
            with self.subTest(name):
                why = lock.tool_refusal(name, {"path": ["/etc/hosts"]}, base=None, workspace=None)
                self.assertEqual(why, lock.UNCHECKABLE)
        why = lock.tool_refusal("patch", {"mode": "patch", "patch": ["*** Begin Patch"]}, base=None, workspace=None)
        self.assertEqual(why, lock.UNCHECKABLE)


class StopSeamTests(unittest.TestCase):
    def test_without_the_stop_handle_remote_work_is_refused(self):
        ran = []
        with mock.patch.dict(sys.modules, {"tools.interrupt": mock.Mock(spec=[])}):
            with self.assertRaises(PermissionError):
                device_exec._stoppable_worker(device_exec._Stop(), ran.append, ("x",))
        self.assertEqual(ran, [])


if __name__ == "__main__":
    unittest.main()
