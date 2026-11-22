"""The session lock (D70-D77): a remote session's commands and lent file tools cannot change Tether's live files or
this device's Hermes, or read their secrets; the person's own tools are untouched; where the lock cannot be applied,
nothing runs; and the idle limit defaults to an hour. Every path here is inside this run's temp folder."""
from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

HERMES_SRC = Path.home() / ".hermes" / "hermes-agent"
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "plugin" / "tether"))
sys.path.insert(1, str(HERMES_SRC))

try:
    import tools.environments.local  # noqa: F401
    HAVE_HERMES = True
except Exception:  # noqa: BLE001
    HAVE_HERMES = False

from test_link_loopback import temp_dir  # noqa: E402

SECRET = "dummy-test-secret-41"
ON_MAC = sys.platform == "darwin" and os.access("/usr/bin/sandbox-exec", os.X_OK)


class FakeDevice:
    """A fake HOME: a Hermes home with Tether's data folder, a plugin linked to a project, a fake install and Python."""

    def __init__(self, owner) -> None:
        base = temp_dir(owner, "hp-lock-").resolve()
        self.home, self.R = base / "home", base / "home" / ".hermes"
        self.data, self.proj = self.R / "tether", base / "home" / "proj" / "tether"
        self.install, self.py = self.R / "hermes-agent", base / "home" / "py"
        for d in (self.data / "sessions", self.proj, self.install / "venv", self.py / "lib", self.R / "plugins",
                  self.home / "work"):
            d.mkdir(parents=True, exist_ok=True)
        for p, text in {self.R / ".env": f"X={SECRET}\n", self.R / "config.yaml": "a: 1\n",
                        self.data / "identity.key.enc": SECRET, self.proj / "__init__.py": "# live\n",
                        self.py / "lib" / "os.py": "# os\n"}.items():
            p.write_text(text)
        os.symlink(self.proj, self.R / "plugins" / "tether")
        from tether import lock
        self.lock = lock
        patches = [mock.patch.dict(os.environ, {"HOME": str(self.home), "HERMES_HOME": str(self.R)}),
                   mock.patch.object(lock, "_interpreter",
                                     lambda: (str(self.install), [str(self.py), str(self.install / "venv")],
                                              [str(self.py / "lib")]))]
        for p in patches:
            p.start()
            owner.addCleanup(p.stop)
        lock.reset_scan_cache()
        owner.addCleanup(lock.reset_scan_cache)
        lock.set_unlocked(None)                     # this system's default (macOS: locked)
        owner.addCleanup(lock.set_unlocked, None)


class IdleDefaultTests(unittest.TestCase):
    def test_idle_limit_defaults_to_an_hour(self):
        from tether.config import read_settings
        from tether.consent import ConsentGate
        from tether import store
        self.assertEqual(read_settings(lambda key, default: default).grant_idle_minutes, 60.0)
        self.assertEqual(ConsentGate(prompt=lambda *a: None).idle_s, 3600.0)
        self.assertEqual(store.DEFAULT_GRANT_IDLE_MINUTES, 60.0)
        self.assertEqual(store.SETTINGS_LIMITS["grant_idle_minutes"], (1.0, 1440.0))
        manifest = (Path(__file__).resolve().parents[1] / "plugin" / "tether" / "plugin.yaml").read_text()
        self.assertIn("grant_idle_minutes: {type: float, default: 60,", manifest)
        self.assertEqual(read_settings(lambda key, default: 5 if key == "grant_idle_minutes" else default)
                         .grant_idle_minutes, 5.0)          # a machine's own setting still wins


@unittest.skipUnless(HAVE_HERMES, "Hermes source not importable")
class FailClosedTests(unittest.TestCase):
    """Threat 5: no lock, no command (and the agent is told why)."""

    def setUp(self):
        self.dev = FakeDevice(self)
        from tether.device_exec import LocalExec
        from tether.workspace import Workspaces
        ws = Workspaces(self.dev.data / "sessions")
        self.addCleanup(ws.close)
        self.loc = LocalExec(ws)
        self.addCleanup(self.loc.close_all)
        self.marker = self.dev.home / "work" / "ran"

    def _refused(self, needle: str) -> None:
        with self.assertRaises(PermissionError) as cm:
            asyncio.run(self.loc.exec({"command": f"touch {self.marker}", "session": "s1", "host_gate": True}, b""))
        self.assertIn(needle, str(cm.exception))
        self.assertFalse(self.marker.exists(), "a command ran without the lock")

    def test_unknown_platform_refuses(self):
        with mock.patch.object(self.dev.lock, "_system", lambda: "linux"):
            self._refused("cannot keep a remote session's commands away from Tether's and Hermes's own files")

    def test_windows_runs_unlocked_by_default_and_refuses_when_turned_off(self):
        """H1: Windows has no lock: allow_unlocked_commands is on by default there; off refuses every command."""
        lock = self.dev.lock
        with mock.patch.object(lock, "_system", lambda: "windows"):
            lock.check_commands()                       # the default on Windows: unlocked, no refusal
            self.assertFalse(lock.locked(), "Windows never announces files_locked")
            lock.set_unlocked(False)
            self._refused("on Windows this device cannot keep")

    @unittest.skipUnless(ON_MAC, "macOS sandbox only")
    def test_missing_sandbox_exec_refuses(self):
        with mock.patch.object(self.dev.lock, "SANDBOX_EXEC", str(self.dev.home / "no-sandbox-exec")):
            self._refused("session lock could not start")

    @unittest.skipUnless(ON_MAC, "macOS sandbox only")
    def test_a_profile_the_system_refuses_is_never_run_unlocked(self):
        with mock.patch.object(self.dev.lock, "session_profile", lambda **kw: "(version 1)(deny no-such-op)\n"):
            self._refused("session lock could not start")

    @unittest.skipUnless(ON_MAC, "macOS sandbox only")
    def test_macos_locks_by_default_and_unlocked_runs_without_the_lock(self):
        """H1: on macOS allow_unlocked_commands is off by default (the lock holds); turned on, a session's commands
        run without the sandbox (the panel says so), and a terminal of the other kind is never reused."""
        lock, d = self.dev.lock, self.dev
        self.assertTrue(lock.locked() and not lock.unlocked(), "macOS must lock by default")
        asyncio.run(self.loc.exec({"command": f"echo x >> {d.proj}/__init__.py", "session": "s1", "host_gate": True},
                                  b""))
        self.assertEqual((d.proj / "__init__.py").read_text(), "# live\n", "the default lock let a write through")
        lock.set_unlocked(True)
        self.assertFalse(lock.locked(), "unlocked: files_locked must not be announced")
        asyncio.run(self.loc.exec({"command": f"echo x >> {d.proj}/__init__.py", "session": "s1", "host_gate": True},
                                  b""))
        self.assertEqual((d.proj / "__init__.py").read_text(), "# live\nx\n", "unlocked means no sandbox")

    @unittest.skipUnless(ON_MAC, "macOS sandbox only")
    def test_a_protected_file_with_an_outside_name_refuses(self):
        link = self.dev.home / "work" / "os-link.py"
        os.link(self.dev.py / "lib" / "os.py", link)     # as a package cache's hard link would be
        self._refused("has another name outside the protected folders")

    def test_no_hermes_source_is_compared_on_the_device(self):
        """H2: the device never hashes or compares Hermes's own source or version (the maintainers' watcher does,
        scripts/hermes_watch.py); LockedEnvironment itself stays."""
        lock = self.dev.lock
        self.assertFalse(hasattr(lock, "HERMES_SPAWN_SOURCES") or hasattr(lock, "check_hermes_spawn"),
                         "a Hermes source pin is still on the device")
        src = Path(lock.__file__).read_text()
        self.assertNotIn("getsource", src)
        self.assertNotIn("sha256", src)
        self.assertIn("class LockedEnvironment(LocalEnvironment)", src)


@unittest.skipUnless(HAVE_HERMES and ON_MAC, "macOS sandbox and Hermes source needed")
class CommandLockTests(unittest.TestCase):
    """Threats 1, 2 and 4 through the device's real spawn path: LocalExec -> Hermes LocalEnvironment -> the lock."""

    def setUp(self):
        self.dev = FakeDevice(self)
        from tether.device_exec import LocalExec
        from tether.workspace import Workspaces
        self.ws = Workspaces(self.dev.data / "sessions")
        self.addCleanup(self.ws.close)
        self.loc = LocalExec(self.ws)
        self.addCleanup(self.loc.close_all)

    def run_cmd(self, command: str) -> tuple[int, str]:
        meta, body = asyncio.run(self.loc.exec({"command": command, "session": "s1", "host_gate": True,
                                                "timeout": 30}, b""))
        return int(meta.get("returncode", -1)), body.decode(errors="replace")

    def test_live_plugin_hermes_settings_and_python_cannot_change(self):
        d = self.dev
        mode = (d.data / "identity.key.enc").stat().st_mode
        for cmd in (f"echo x >> {d.R}/plugins/tether/__init__.py", f"echo x >> {d.proj}/__init__.py",
                    f"mv {d.proj.parent} {d.home}/moved", f"echo x >> {d.R}/config.yaml", f"rm -f {d.R}/.env",
                    f"chmod 777 {d.data}/identity.key.enc", f"echo 'import os' > {d.install}/venv/evil.pth",
                    f"echo x > {d.py}/lib/sitecustomize.py", f"mv {d.R} {d.home}/h2",
                    f"echo x >> {d.home}/.HERMES/config.yaml",
                    f"ln {d.R}/config.yaml {d.home}/work/c && echo x >> {d.home}/work/c"):
            self.run_cmd(cmd)
        self.assertEqual((d.proj / "__init__.py").read_text(), "# live\n")
        self.assertEqual((d.R / "config.yaml").read_text(), "a: 1\n")
        self.assertTrue((d.R / ".env").exists())
        self.assertEqual((d.data / "identity.key.enc").stat().st_mode, mode)
        self.assertFalse((d.install / "venv" / "evil.pth").exists())
        self.assertFalse((d.py / "lib" / "sitecustomize.py").exists())
        self.assertTrue(d.R.is_dir() and d.proj.is_dir())
        self.assertFalse((d.home / "work" / "c").exists())

    def test_secrets_cannot_be_read(self):
        d = self.dev
        _, out = self.run_cmd(f"cat {d.data}/identity.key.enc {d.R}/.env; grep -r -a {SECRET[:10]} {d.home}")
        self.assertNotIn(SECRET, out)

    def test_the_authenticator_files_cannot_be_read_or_rewritten(self):
        """G1 with H: the 2FA record and code state in Tether's data folder are read- and write-locked for a
        session's commands (stand-in files with a dummy value)."""
        d = self.dev
        for name in ("authenticator.json", "authenticator_state.json"):
            (d.data / name).write_text(f'{{"sealed": "{SECRET}"}}')
        _, out = self.run_cmd(f"cat {d.data}/authenticator.json {d.data}/authenticator_state.json; "
                              f"cp {d.data}/authenticator.json {d.home}/work/copy")
        self.assertNotIn(SECRET, out)
        self.assertFalse((d.home / "work" / "copy").exists(), "the record was copied out")
        self.run_cmd(f"echo '{{}}' > {d.data}/authenticator_state.json; rm -f {d.data}/authenticator.json; "
                     f"mv {d.data}/authenticator.json {d.home}/work/m; touch {d.data}/authenticator.busy")
        for name in ("authenticator.json", "authenticator_state.json"):
            self.assertEqual((d.data / name).read_text(), f'{{"sealed": "{SECRET}"}}', f"{name} was changed")
        self.assertFalse((d.data / "authenticator.busy").exists(), "a session command wrote the data folder")

    def test_a_background_job_stays_locked_after_its_command_returns(self):
        d = self.dev
        self.run_cmd(f"(sleep 0.5; echo x >> {d.proj}/__init__.py) >/dev/null 2>&1 &")
        import time
        time.sleep(1.5)
        self.assertEqual((d.proj / "__init__.py").read_text(), "# live\n")

    def test_the_workspace_and_the_persons_files_stay_usable(self):
        d = self.dev
        rc, out = self.run_cmd(f"git init -q r && cd r && echo a > a && git add a && echo ok; "
                               f"echo mine > {d.home}/work/n && cat {d.home}/work/n")
        self.assertEqual(rc, 0, out)
        self.assertIn("ok", out)
        self.assertIn("mine", out)
        self.assertNotIn("Operation not permitted", out)

    def test_the_lock_does_not_leak_to_this_devices_own_hermes_or_the_person(self):
        d = self.dev
        self.run_cmd(f"echo locked >> {d.proj}/__init__.py")
        from tools.environments.local import LocalEnvironment
        env = LocalEnvironment(cwd=str(d.home), timeout=30)
        try:
            env.execute(f"echo '# own agent' >> {d.proj}/__init__.py", timeout=30)
        finally:
            env.cleanup()
        subprocess.run(["/bin/sh", "-c", f"echo '# person' >> {d.proj}/__init__.py"], check=True)
        self.assertEqual((d.proj / "__init__.py").read_text(), "# live\n# own agent\n# person\n")

    def test_the_launcher_and_launch_agents_cannot_be_edited_in_a_renamed_folder(self):
        """S1-5: renaming ~/.local/bin (or ~/.local, or ~/Library/LaunchAgents) away, editing the hermes launcher or
        the ai.hermes launch agent there and renaming the folder back is refused."""
        d, h = self.dev, self.dev.home
        (h / ".local" / "bin").mkdir(parents=True)
        (h / ".local" / "bin" / "hermes").write_text("#!/bin/sh\n")
        (h / "Library" / "LaunchAgents").mkdir(parents=True)
        (h / "Library" / "LaunchAgents" / "ai.hermes.gateway.plist").write_text("<plist/>\n")
        self.run_cmd(f"mv {h}/.local/bin {h}/work/b && echo evil >> {h}/work/b/hermes; mv {h}/work/b {h}/.local/bin")
        self.run_cmd(f"mv {h}/.local {h}/work/l && echo evil >> {h}/work/l/bin/hermes; mv {h}/work/l {h}/.local")
        self.run_cmd(f"mv {h}/Library/LaunchAgents {h}/work/a && echo evil > {h}/work/a/ai.hermes.gateway.plist; "
                     f"mv {h}/work/a {h}/Library/LaunchAgents")
        self.run_cmd(f"mv {h}/Library {h}/work/L && echo evil > {h}/work/L/LaunchAgents/ai.hermes.gateway.plist; "
                     f"mv {h}/work/L {h}/Library")
        self.assertEqual((h / ".local" / "bin" / "hermes").read_text(), "#!/bin/sh\n")
        self.assertEqual((h / "Library" / "LaunchAgents" / "ai.hermes.gateway.plist").read_text(), "<plist/>\n")
        rc, out = self.run_cmd(f"mkdir -p {h}/Library/Caches/demo && echo x > {h}/.local/bin/other && echo ok")
        self.assertIn("ok", out)                 # the folders themselves stay usable
        self.assertTrue(d.R.is_dir())

    def test_profile_is_built_in_memory_and_names_exact_operations(self):
        prof = self.dev.lock.session_profile(workspace=str(self.ws.ensure("s1")), temp_dir=str(self.dev.home),
                                             own_id="abc")
        self.assertIn("(allow file-read-data file-write* (subpath", prof)     # never file-read* (see D71)
        self.assertNotIn("(allow file-read* ", prof)
        self.assertIn(f'(subpath "{self.dev.R}")', prof)
        self.assertIn(f'(literal "{self.dev.proj.parent}")', prof)            # the plugin's ancestors: no rename


@unittest.skipUnless(HAVE_HERMES, "Hermes source not importable")
class FileToolLockTests(unittest.TestCase):
    """Threat 3: the lent file tools run in this process; the check refuses protected paths before Hermes runs."""

    def setUp(self):
        self.dev = FakeDevice(self)
        from tether.device_exec import ToolRunner
        from tether.workspace import Workspaces
        self.ws = Workspaces(self.dev.data / "sessions")
        self.addCleanup(self.ws.close)
        self.calls = []
        self.runner = ToolRunner(None, workspaces=self.ws,
                                 dispatch=lambda name, args, task_id: self.calls.append((name, args)) or {"ok": True})

    def refused(self, name, args):
        with self.assertRaises(PermissionError):
            self.runner._run(name, args, "s1")

    def test_protected_paths_are_refused_however_they_are_named(self):
        d = self.dev
        os.symlink(d.data / "identity.key.enc", d.home / "work" / "k")
        self.refused("read_file", {"path": str(d.data / "identity.key.enc")})
        self.refused("read_file", {"path": "~/.hermes/.env"})
        self.refused("read_file", {"path": str(d.home / "work" / "k")})
        if sys.platform == "darwin":
            self.refused("read_file", {"path": str(d.home / ".HERMES" / "TETHER" / "identity.key.enc")})
        self.refused("write_file", {"path": str(d.proj / "__init__.py"), "content": "x"})
        self.refused("write_file", {"path": str(d.R / "plugins" / "tether" / "new.py"), "content": "x"})
        self.refused("patch", {"mode": "patch", "patch": f"*** Begin Patch\n*** Update File: {d.R}/config.yaml\n@@\n-a: 1\n+a: 2\n*** End Patch\n"})
        self.refused("search_files", {"pattern": SECRET, "path": str(d.home)})
        self.assertEqual(self.calls, [], "a protected call reached Hermes")

    def test_a_hard_link_to_a_secret_is_refused(self):
        link = self.dev.home / "work" / "key-link"
        os.link(self.dev.data / "identity.key.enc", link)
        self.refused("read_file", {"path": str(link)})
        self.assertEqual(self.calls, [])

    def test_the_workspace_and_the_persons_files_are_not_refused(self):
        ws = self.ws.ensure("s1")
        self.runner._run("write_file", {"path": str(ws / "a.txt"), "content": "x"}, "s1")
        self.runner._run("read_file", {"path": str(self.dev.home / "work")}, "s1")
        self.runner._run("search_files", {"pattern": "x"}, "s1")
        self.assertEqual([c[0] for c in self.calls], ["write_file", "read_file", "search_files"])
        self.assertEqual(self.calls[-1][1]["path"], str(ws))          # the session's folder, named explicitly


class AnnounceTests(unittest.TestCase):
    def test_the_host_keeps_files_locked_and_tells_the_agent(self):
        from tether.machine import clean_announce, model_view
        from tether import forward
        self.assertIs(model_view({"os": "Darwin", "files_locked": True}).get("files_locked"), True)
        self.assertNotIn("files_locked", clean_announce({"os": "Darwin", "files_locked": "yes"}))
        self.assertIn("locked", forward._LOCKED_NOTE.format(target="mac"))


if __name__ == "__main__":
    unittest.main()


class VenvBaseTests(unittest.TestCase):
    def test_the_hermes_venv_base_python_is_protected_whatever_python_runs_the_gateway(self):
        """Hermes 0.23.3 runs its gateway on its own Python 3.14 runtime while its venv links libpython to the base
        Python it was made from. Without that base in the protected set the hard-link check refused every command
        on the real Mac (first live test, 2026-11-22)."""
        import tempfile
        from tether import lock
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            base = root / "uv" / "cpython-3.11"
            (base / "bin").mkdir(parents=True)
            install = root / "hermes-agent"
            (install / "venv").mkdir(parents=True)
            (install / "venv" / "pyvenv.cfg").write_text(f"home = {base / 'bin'}\nversion_info = 3.11\n")
            got = lock._venv_bases(lock._real(install))
            self.assertIn(lock._real(base), got, "the venv's base Python is not protected")
            self.assertEqual(lock._venv_bases(None), [], "no install must mean no extra roots")
            (install / "venv" / "pyvenv.cfg").write_text("home = /nonexistent/python/bin\n")
            self.assertEqual(lock._venv_bases(lock._real(install)), [], "a missing base must not be added")
