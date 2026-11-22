"""Closing a session removes everything Tether created for it, and nothing the user made (the owner's rule).

Loopback rig with the real device pieces (LocalExec, Workspaces, SessionControl), as test_session_control builds them.
Hermes's own terminal is needed for the commands, so these tests are skipped when it is not importable.
"""
from __future__ import annotations

import glob
import io
import json
import os
import secrets
import sys
import tarfile
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "plugin" / "tether"))
sys.path.insert(1, str(Path.home() / ".hermes" / "hermes-agent"))

from tether.device_exec import LocalExec, SessionControl, job_paths  # noqa: E402
from tether.provider import _spawn_text  # noqa: E402
from tether.runtime import get_runtime  # noqa: E402
from tether.store import OpenSessions  # noqa: E402
from tether.workspace import Workspaces  # noqa: E402

from test_link_loopback import FakePrompt, Rig, temp_dir  # noqa: E402,F401

try:
    import tools.environments.local  # noqa: F401
    HAVE_HERMES = True
except Exception:  # noqa: BLE001
    HAVE_HERMES = False


def _skill_tar() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        data = b"# cad"
        info = tarfile.TarInfo("SKILL.md")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _job_files(job_id: str) -> list[str]:
    return list(job_paths(job_id))


@unittest.skipUnless(HAVE_HERMES, "Hermes source not importable")
class CloseLeavesNothingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rt = get_runtime()
        cls.rig = Rig(capabilities={"rules": {"grant_idle_minutes": 1}})
        cls.addClassCleanup(cls.rig.close)
        dd = cls.rig.host_pin.path.parent                 # the device's tether data folder
        cls.ws = Workspaces(dd / "sessions")
        cls.local = LocalExec(cls.ws, record_dir=dd)
        cls.addClassCleanup(cls.local.close_all)          # any terminal the device still holds is ended
        pin = cls.rig.host_pin
        control = SessionControl(cls.rig.consent, cls.ws, cls.local, lambda: (pin.get() or {}).get("fp", ""))
        cls.rig.device._handlers = {"exec": cls.local.exec, "skill_put": control.skill_put,
                                    "close_session": control.close_session}

        async def up():
            _, task = await cls.rig.pair()
            await task
            await cls.rig.connect()
        cls.rt.run(up(), 30)
        cls.addClassCleanup(cls.rt.loop.call_soon_threadsafe, cls.rig.device._task.cancel)

    def setUp(self):
        self.rt.host = self.rig.host
        for d in (self.rt.targets, self.rt.grants, self.rt.grant_fp, self.rt.open_fp, self.rt.last_device,
                  self.rt.last_activity, self.rt.closed_note, self.rt.skill_copies, self.rt.working_on, self.rt.held,
                  self.rt.last_wall):
            d.clear()
        self.addCleanup(setattr, self.rt, "host", None)

    def call(self, kind: str, args: dict, body: bytes = b""):
        return self.rt.run(self.rig.host.call("mac", kind, args, body, 30), 40)

    def open_session(self, session: str) -> str:
        """Run a first command (the person's Allow, so a grant token comes back) and record the open connection
        the way the host does. Returns the grant."""
        data, _ = self.call("exec", {"command": "echo open", "session": session, "host_gate": True})
        self.rt.open_device(session, "mac")
        self.rt.grants[(session, "mac")] = data["grant"]
        return data["grant"]

    def close(self, session: str) -> None:
        self.rt.close_device(session, "closed by the test")
        deadline = time.monotonic() + 20
        while self.ws.path(session).exists() and time.monotonic() < deadline:
            time.sleep(0.05)

    def test_close_leaves_nothing_of_tethers_behind(self):
        session = f"cleanup-{secrets.token_hex(3)}"
        grant = self.open_session(session)
        scratch = self.ws.ensure(session) / "scratch.txt"
        scratch.write_text("made in the session")
        self.call("skill_put", {"session": session, "name": "cad", "grant": grant}, _skill_tar())
        job = f"proc_{secrets.token_hex(6)}"
        self.call("exec", {"command": _spawn_text(job, "sleep 0.2; echo done"), "session": session,
                           "grant": grant, "host_gate": True})
        deadline = time.monotonic() + 20
        while not os.path.exists(job_paths(job)[2]) and time.monotonic() < deadline:
            time.sleep(0.1)                                  # the short job has ended: its .exit file is there
        user_dir = temp_dir(self, "hp-user-")
        user_file = user_dir / "notes.txt"
        self.call("exec", {"command": f"echo keep > '{user_file}'", "session": session, "grant": grant,
                           "host_gate": True})
        self.assertEqual(user_file.read_text(), "keep\n")

        self.close(session)

        self.assertFalse(self.ws.path(session).exists())
        self.assertEqual(list(self.ws.root.iterdir()), [])
        for path in _job_files(job):
            self.assertFalse(os.path.exists(path), path)
        self.assertEqual(glob.glob(os.path.join(tempfile.gettempdir(), "tether-*.crt")), [])
        host_dir = self.rig.pins.path.parent
        self.assertFalse((host_dir / "open_sessions.json").exists())
        self.assertFalse((host_dir / "open_sessions.lock").exists())
        self.assertEqual(user_file.read_text(), "keep\n")     # the user's file is untouched

    def test_a_running_job_is_left_running_then_its_files_go_after_it_ends(self):
        session = f"running-{secrets.token_hex(3)}"
        grant = self.open_session(session)
        job = f"proc_{secrets.token_hex(6)}"
        self.call("exec", {"command": _spawn_text(job, "sleep 8; echo late"), "session": session,
                           "grant": grant, "host_gate": True})
        log, pid_path, exit_path = job_paths(job)
        deadline = time.monotonic() + 10
        while not os.path.exists(pid_path) and time.monotonic() < deadline:
            time.sleep(0.05)
        pid = int(Path(pid_path).read_text().strip())

        self.close(session)

        os.kill(pid, 0)                                        # still alive: the user asked for this job
        self.assertTrue(os.path.exists(log) and os.path.exists(pid_path))
        self.assertFalse(os.path.exists(exit_path))
        record = Path(self.rig.host_pin.path.parent) / "bg_jobs.json"
        self.assertEqual(json.loads(record.read_text()), [job])

        deadline = time.monotonic() + 60
        while not os.path.exists(exit_path) and time.monotonic() < deadline:
            time.sleep(0.2)                                    # the job ends on its own
        self.assertEqual(self.local.sweep_jobs(set()), 0)      # the next sweep
        for path in _job_files(job):
            self.assertFalse(os.path.exists(path), path)
        self.assertFalse(record.exists())


if __name__ == "__main__":
    unittest.main()
