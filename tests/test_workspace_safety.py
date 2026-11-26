"""D39: the device's session cleanup stays inside Tether's own sessions folder, whatever a session's commands did to
it. Links (in place of the sessions folder, a workspace, skills, or deeper) are removed, never followed; a hard-linked
file of the person's keeps its mode; locked or ACL-protected entries never crash a close, the sweeper or a device start.
Also the D39 clean-up parts that had no test (F96) and the session-id check (F53).

Every folder here is a throwaway temp folder; "the person's files" are dummy files made by the test."""
from __future__ import annotations

import asyncio
import glob
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "plugin" / "tether"))
sys.path.insert(1, str(Path(os.environ.get("HERMES_AGENT_SRC") or Path.home() / ".hermes" / "hermes-agent")))

from tether import device_exec, store, tlslink, workspace  # noqa: E402
from tether.device import DeviceService  # noqa: E402
from tether.device_exec import LocalExec, SessionControl, job_paths  # noqa: E402
from tether.identity import MemorySecretStore, load_or_create  # noqa: E402
from tether.store import HostPin, OpenSessions  # noqa: E402
from tether.workspace import Workspaces, check_session  # noqa: E402

from test_link_loopback import FakePrompt, consent_gate, temp_dir  # noqa: E402
import test_windows_device as _windows  # noqa: E402

MAC = sys.platform == "darwin"


def mode(p) -> int:
    return stat.S_IMODE(os.lstat(p).st_mode)


def listing(p: Path) -> list[str]:
    return sorted(os.listdir(p))


def unlock_tree(top: Path) -> None:
    """Test clean-up only: take locks, ACLs and missing permissions off a test folder so it can be removed. Never
    acts on a link or through one."""
    try:
        st = os.lstat(top)
    except OSError:
        return
    if stat.S_ISLNK(st.st_mode):
        if MAC:
            subprocess.run(["chflags", "-h", "nouchg", str(top)], capture_output=True)
        return
    if hasattr(os, "chflags"):
        try:
            os.chflags(top, 0, follow_symlinks=False)
        except OSError:
            pass
    if MAC:
        subprocess.run(["chmod", "-N", str(top)], capture_output=True)      # one real entry, never -R
    if stat.S_ISDIR(st.st_mode):
        try:
            os.chmod(top, 0o700)
            names = os.listdir(top)
        except OSError:
            return
        for name in names:
            unlock_tree(top / name)


def user_folder(test, prefix: str = "hp-person-") -> Path:
    d = temp_dir(test, prefix)
    test.addCleanup(unlock_tree, d)
    return d


def skill_tar(text: bytes = b"# HOST cad skill") -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        info = tarfile.TarInfo("SKILL.md")
        info.size = len(text)
        tar.addfile(info, io.BytesIO(text))
    return buf.getvalue()


class _WorkspaceCase(unittest.TestCase):
    def setUp(self):
        self.data = temp_dir(self, "hp-data-")             # stands for <hermes home>/tether
        self.addCleanup(unlock_tree, self.data)
        self.ws = Workspaces(self.data / "sessions")

    def person(self) -> Path:
        """Dummy 'person's own' folders and files outside the workspace, mode 0755."""
        home = user_folder(self)
        for sub in ("Photos", "Thesis"):
            (home / sub).mkdir()
            (home / sub / "keep.txt").write_text("the person's own")
        (home / "loose.txt").write_text("x")
        os.chmod(home, 0o755)
        return home


class SessionsFolderLinkTests(_WorkspaceCase):
    """F9: the sessions folder itself swapped for a link by the agent's own command."""

    def plant(self, target: Path) -> None:
        """Whatever is at <data>/sessions now is moved aside and a link to target put in its place."""
        n = len(os.listdir(self.data))
        os.rename(self.data / "sessions", self.data / f"sessions.old{n}")
        os.symlink(target, self.data / "sessions")

    def test_a_link_in_place_of_the_sessions_folder_is_removed_never_followed(self):
        home = self.person()
        self.ws.ensure("live")
        self.plant(home)                     # cd ../.. && mv sessions sessions.old && ln -s ~ sessions
        self.assertEqual(self.ws.sweep({"live"}), 0)                      # the device's minute sweep
        self.assertEqual(listing(home), ["Photos", "Thesis", "loose.txt"])
        self.plant(home)
        self.assertEqual(self.ws.wipe_all(), 0)
        self.plant(home)
        again = Workspaces(self.data / "sessions")                        # a device start
        self.assertEqual(again.wipe_all(), 0)
        self.assertEqual(listing(home), ["Photos", "Thesis", "loose.txt"])
        self.assertEqual(mode(home), 0o755)                               # never chmod-ed through the link
        self.assertFalse((self.data / "sessions").is_symlink())           # a real folder of Tether's again
        self.assertEqual(mode(self.data / "sessions"), 0o700)

    def test_a_link_in_place_of_the_data_folder_is_never_followed(self):
        hermes = temp_dir(self, "hp-home-")
        data = hermes / "tether"
        data.mkdir()
        ws = Workspaces(data / "sessions")
        ws.ensure("s1")
        other = user_folder(self)                                         # a person's folder that has a "sessions"
        (other / "sessions" / "Important").mkdir(parents=True)
        (other / "sessions" / "Important" / "notes.txt").write_text("keep")
        os.chmod(other, 0o755)
        os.rename(data, hermes / "tether.old")
        os.symlink(other, data)
        ws.sweep(set())                                                   # works in Tether's own folder only
        self.assertTrue((other / "sessions" / "Important" / "notes.txt").exists())
        with self.assertRaises(PermissionError):                          # its path no longer leads to Tether's folder
            ws.ensure("s1")
        with self.assertRaises(PermissionError):                          # a device start refuses a linked data folder
            Workspaces(data / "sessions")
        self.assertTrue((other / "sessions" / "Important" / "notes.txt").exists())
        self.assertEqual(mode(other), 0o755)


class WorkspaceLinkTests(_WorkspaceCase):
    """F51: a link named skills, or the workspace itself swapped for a link."""

    def own_skills(self) -> Path:
        own = user_folder(self, "hp-own-skills-")                         # stands for the device's ~/.hermes/skills
        (own / "cad").mkdir()
        (own / "cad" / "notes.txt").write_text("DEVICE OWN cad skill")
        os.chmod(own, 0o755)
        return own

    def test_a_skills_link_is_replaced_by_a_real_folder(self):
        own = self.own_skills()
        os.symlink(own, self.ws.ensure("s1") / "skills")                  # ln -s ~/.hermes/skills skills
        dest = self.ws.put_skill("s1", "cad", skill_tar())
        self.assertTrue((own / "cad" / "notes.txt").exists())
        self.assertFalse((own / "cad" / "SKILL.md").exists())
        self.assertEqual(mode(own), 0o755)
        self.assertFalse((self.ws.path("s1") / "skills").is_symlink())
        self.assertTrue(os.path.realpath(dest).startswith(os.path.realpath(self.ws.root) + os.sep))
        self.assertEqual((dest / "SKILL.md").read_text(), "# HOST cad skill")
        self.assertTrue(self.ws.wipe("s1"))
        self.assertTrue((own / "cad" / "notes.txt").exists())

    def test_a_workspace_swapped_for_a_link_gets_its_own_folder_back(self):
        fake_home = user_folder(self, "hp-fakehome-")                     # stands for the person's home
        (fake_home / "skills" / "cad").mkdir(parents=True)
        (fake_home / "skills" / "cad" / "notes.txt").write_text("DEVICE OWN")
        real = self.ws.ensure("s1")
        os.rename(real, self.ws.root / "s1.old")                          # cd .. && mv s1 s1.old
        os.symlink(fake_home, real)                                       # && ln -s <dir> s1
        dest = self.ws.put_skill("s1", "cad", skill_tar())
        self.assertTrue((fake_home / "skills" / "cad" / "notes.txt").exists())
        self.assertFalse(self.ws.path("s1").is_symlink())
        self.assertTrue(os.path.realpath(dest).startswith(os.path.realpath(self.ws.root) + os.sep))
        self.assertEqual(self.ws.ensure("s1"), real)
        self.assertFalse(real.is_symlink())


class HardLinkTests(_WorkspaceCase):
    """F50: a hard link shares its mode with the person's own file."""

    def test_a_wipe_keeps_the_mode_of_hard_linked_user_files(self):
        home = user_folder(self)
        tool, signed = home / "deploy.sh", home / "signed.pdf"
        tool.write_text("#!/bin/sh\necho deploy\n")
        signed.write_text("%PDF")
        os.chmod(tool, 0o755)
        os.chmod(signed, 0o444)
        tool_mode, signed_mode = mode(tool), mode(signed)                # what this OS keeps of those modes
        ws = self.ws.ensure("s1")
        os.link(tool, ws / "deploy-link.sh")                              # ln ~/deploy.sh .
        (ws / "ro").mkdir()
        os.link(signed, ws / "ro" / "signed.pdf")
        os.chmod(ws / "ro", 0o500)                                        # inside a read-only folder too
        self.assertTrue(self.ws.wipe("s1"))
        self.assertFalse(ws.exists())
        self.assertEqual(mode(tool), tool_mode)
        self.assertEqual(mode(signed), signed_mode)
        self.assertEqual(os.stat(tool).st_nlink, 1)

    @unittest.skipUnless(shutil.which("git"), "git not installed")
    def test_closing_after_a_local_git_clone_keeps_the_repos_object_modes(self):
        repo = user_folder(self) / "project"
        env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
               "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid", "GIT_CONFIG_NOSYSTEM": "1",
               "HOME": str(repo.parent)}
        repo.mkdir()
        subprocess.run("git init -q && echo hi > a.txt && git add a.txt && git commit -qm init", shell=True,
                       cwd=repo, env=env, check=True, capture_output=True)
        objects = [p for p in (repo / ".git" / "objects").rglob("*") if p.is_file()]
        before = {str(p): mode(p) for p in objects}
        gate = consent_gate(prompt=FakePrompt(True))
        grant = asyncio.run(gate.require("fp", "Test host", "s1"))
        control = SessionControl(gate, self.ws, LocalExec(self.ws), lambda: "fp")
        subprocess.run(["git", "clone", "-q", str(repo), "clone"], cwd=self.ws.ensure("s1"), env=env, check=True,
                       capture_output=True)                               # what the agent's command does
        self.assertTrue(any(os.stat(p).st_nlink > 1 for p in objects))    # git hard-linked them
        out, _ = asyncio.run(control.close_session({"session": "s1", "grant": grant}, b""))
        self.assertTrue(out["workspace_removed"])
        self.assertEqual({str(p): mode(p) for p in objects}, before)


class LinkInsideTests(_WorkspaceCase):
    """F87, F75: links inside a workspace are removed themselves; what they point to is never chmod-ed."""

    def test_links_to_outside_files_and_folders_are_removed_and_never_chmodded(self):
        home = user_folder(self)
        tool = home / "tool.sh"
        tool.write_text("#!/bin/sh\n")
        os.chmod(tool, 0o755)
        (home / "sub").mkdir()
        os.chmod(home / "sub", 0o755)
        for wipe in (lambda: self.ws.sweep(set()), self.ws.wipe_all, lambda: self.ws.wipe("s1")):
            ws = self.ws.ensure("s1")
            os.symlink(tool, ws / "file-link")
            os.symlink(home / "sub", ws / "dir-link")
            (ws / "ro").mkdir()
            os.symlink(tool, ws / "ro" / "deep-link")
            os.chmod(ws / "ro", 0o500)
            wipe()
            self.assertFalse(ws.exists())
            self.assertEqual(mode(tool), 0o755)
            self.assertEqual(mode(home / "sub"), 0o755)
            self.assertTrue(tool.exists())

    @unittest.skipUnless(MAC, "macOS file flags")
    def test_a_locked_link_is_removed_and_its_target_keeps_its_mode(self):
        home = user_folder(self)
        (home / "Sites").mkdir()
        os.chmod(home / "Sites", 0o755)
        ws = self.ws.ensure("s1")
        os.symlink(home / "Sites", ws / "site")
        os.lchflags(ws / "site", stat.UF_IMMUTABLE)                       # ln -s ~/Sites site && chflags -h uchg site
        self.assertTrue(self.ws.wipe("s1"))
        self.assertFalse(ws.exists())
        self.assertEqual(mode(home / "Sites"), 0o755)


class LockedEntryTests(_WorkspaceCase):
    """F20, F76: entries a session locked never crash a close, the sweeper or a start."""

    def test_folders_without_any_permission_are_removed_without_raising(self):
        ws = self.ws.ensure("s1")
        (ws / "trap" / "inner").mkdir(parents=True)
        (ws / "trap" / "inner" / "f.txt").write_text("x")
        os.chmod(ws / "trap" / "inner", 0)
        os.chmod(ws / "trap", 0)                                          # mkdir trap && chmod 000 trap
        os.chmod(ws, 0)                                                   # && chmod 000 .
        self.assertTrue(self.ws.wipe("s1"))
        self.assertFalse(os.path.lexists(ws))

    @unittest.skipUnless(MAC, "macOS ACLs")
    def test_a_folder_that_denies_listing_is_removed_by_close_sweep_and_start(self):
        for run in (lambda: self.ws.wipe("s1"), lambda: self.ws.sweep(set()), self.ws.wipe_all,
                    lambda: Workspaces(self.data / "sessions").wipe_all()):
            ws = self.ws.ensure("s1")
            (ws / "trap").mkdir()
            (ws / "trap" / "secret-scratch.txt").write_text("x")
            subprocess.run(["chmod", "+a", "everyone deny list", str(ws / "trap")], check=True)
            run()                                                         # never raises
            self.assertFalse(os.path.lexists(ws))

    @unittest.skipUnless(MAC, "macOS file flags")
    def test_a_finder_locked_copy_is_removed(self):
        ws = self.ws.ensure("s1")
        (ws / "copy.txt").write_text("private contract text")
        os.chflags(ws / "copy.txt", stat.UF_IMMUTABLE)                    # cp -p of a Finder-locked file
        (ws / "locked-dir").mkdir()
        (ws / "locked-dir" / "inside.txt").write_text("x")
        os.chmod(ws / "locked-dir", 0o100)                                # search only, then locked: no chmod works
        os.chflags(ws / "locked-dir", stat.UF_IMMUTABLE)
        self.assertTrue(self.ws.wipe("s1"))
        self.assertFalse(os.path.lexists(ws))

    @unittest.skipUnless(MAC, "macOS file flags")
    def test_a_locked_hard_link_is_left_and_the_persons_file_keeps_its_lock(self):
        home = user_folder(self)
        own = home / "contract.txt"
        own.write_text("the person's own")
        ws = self.ws.ensure("s1")
        os.link(own, ws / "contract.txt")
        os.chflags(ws / "contract.txt", stat.UF_IMMUTABLE)                # locks the person's file too (one inode)
        self.assertFalse(self.ws.wipe("s1"))                              # held, logged, retried; nothing raised
        self.assertTrue(os.lstat(own).st_flags & stat.UF_IMMUTABLE)       # Tether never unlocked the person's file

    def test_a_folder_of_another_file_system_is_never_entered(self):
        ws = self.ws.ensure("s1")
        (ws / "mnt" / "volume-data").mkdir(parents=True)                  # stands for a mounted disk image's content
        real_stat, real_fstat = os.stat, os.fstat
        mnt_ino = os.lstat(ws / "mnt").st_ino

        def other_device(st):                                             # 'mnt' reports another device id, as a
            if st.st_ino == mnt_ino and stat.S_ISDIR(st.st_mode):         # mount point does to stat and fstat alike
                extra = {k: getattr(st, k) for k in dir(st) if k.startswith("st_") and k not in
                         ("st_mode", "st_ino", "st_dev", "st_nlink", "st_uid", "st_gid", "st_size")}
                return os.stat_result((st.st_mode, st.st_ino, st.st_dev + 1) + tuple(st)[3:], extra)
            return st
        with mock.patch("os.stat", lambda *a, **k: other_device(real_stat(*a, **k))), \
                mock.patch("os.fstat", lambda *a, **k: other_device(real_fstat(*a, **k))):
            self.assertFalse(self.ws.wipe("s1"))
        self.assertTrue((ws / "mnt" / "volume-data").exists())


class SweepNameTests(_WorkspaceCase):
    """B1's twin ids (F10 hardening): macOS and Windows treat another letter case as the same folder, so the sweeper
    compares folder names case-folded and never removes a live session's folder under its twin's spelling."""

    def test_the_sweeper_keeps_a_live_sessions_folder_in_another_letter_case(self):
        folder = self.ws.ensure("abc")                                    # made by an earlier session "abc"
        (folder / "work.txt").write_text("live session's scratch")
        self.assertEqual(self.ws.sweep({"ABC"}), 0)                       # "ABC" is live and works in that folder
        self.assertTrue((folder / "work.txt").exists())
        self.assertEqual(self.ws.sweep(set()), 1)


class _PathVariant:
    """The same checks through the path-based code that Windows runs (Python has no dir_fd calls there)."""

    def setUp(self):
        patch = mock.patch.object(workspace, "_USE_FDS", False, create=True)
        patch.start()
        self.addCleanup(patch.stop)
        super().setUp()


class SessionsFolderLinkPathTests(_PathVariant, SessionsFolderLinkTests):
    pass


class WorkspaceLinkPathTests(_PathVariant, WorkspaceLinkTests):
    pass


class HardLinkPathTests(_PathVariant, HardLinkTests):
    pass


class LinkInsidePathTests(_PathVariant, LinkInsideTests):
    test_a_locked_link_is_removed_and_its_target_keeps_its_mode = None      # BSD flags: macOS only, fd code


class PermissionPathTests(_PathVariant, _WorkspaceCase):
    test_folders_without_any_permission_are_removed_without_raising = \
        LockedEntryTests.test_folders_without_any_permission_are_removed_without_raising


class WindowsReadOnlyTests(_PathVariant, _WorkspaceCase):
    """F50 on Windows: deleting a read-only file there needs its read-only mark cleared, and on a hard link that mark
    is the person's own file's. Windows' refusal is simulated; the path-based code is the one Windows runs."""

    def _setup(self):
        home = user_folder(self)
        own = home / "signed.pdf"
        own.write_text("%PDF")
        os.chmod(own, 0o444)
        ws = self.ws.ensure("s1")
        (ws / "copy.txt").write_text("made in the session")
        os.chmod(ws / "copy.txt", 0o400)
        os.link(own, ws / "signed.pdf")
        real_unlink = os.unlink

        def windows_unlink(path, *a, **k):                                # Windows will not delete a read-only file
            if not os.path.islink(path) and not os.lstat(path).st_mode & stat.S_IWRITE:
                raise PermissionError(5, "Access is denied")
            return real_unlink(path, *a, **k)
        return own, ws, real_unlink, windows_unlink

    def test_the_read_only_mark_is_cleared_only_on_a_file_with_no_other_name(self):
        own, ws, real_unlink, windows_unlink = self._setup()
        named = []
        real_delete = workspace._delete_name_keeping_mark

        def keep_mark(path, st):                                          # elsewhere: stands for FileDispositionInfoEx
            named.append((stat.S_IMODE(os.lstat(path).st_mode), st.st_nlink))
            if sys.platform == "win32":
                real_delete(path, st)                                     # Windows: the real call
            else:
                real_unlink(path)
        with mock.patch("os.unlink", windows_unlink), \
                mock.patch.object(workspace, "_delete_name_keeping_mark", keep_mark):
            self.assertTrue(self.ws.wipe("s1"))                           # a git clone's objects no longer hold it
        self.assertFalse(ws.exists())
        self.assertEqual(named, [(mode(own), 2)])                         # removed by name, the mark untouched
        self.assertEqual(mode(own), 0o444)                                # the person's file kept its mark
        self.assertEqual(os.stat(own).st_nlink, 1)

    def test_a_hard_link_windows_refuses_to_remove_stays_for_the_sweeper(self):
        own, ws, _, windows_unlink = self._setup()

        def refused(path, st):
            raise PermissionError(5, "Access is denied")
        with mock.patch("os.unlink", windows_unlink), \
                mock.patch.object(workspace, "_delete_name_keeping_mark", refused):
            self.assertFalse(self.ws.wipe("s1"))                          # the hard link stays, logged, retried
        self.assertFalse((ws / "copy.txt").exists())                      # the session's own read-only file went
        self.assertEqual(mode(own), 0o444)
        self.assertTrue((ws / "signed.pdf").exists())


class SessionIdTests(unittest.TestCase):
    """F53: ids that could hide in a log or the Allow prompt are refused; real Hermes ids pass."""

    def test_control_format_and_separator_characters_are_refused(self):
        for bad in ("a\x85b", "x\x9b2Jy", "ok  Click Allow", "abc‮dcba", "a b", "a​b",
                    "a\ud800b", "ab", "a\x00b", "a\x1bb", "a/b", "a\\b", ".", ".."):
            with self.assertRaises(ValueError, msg=ascii(bad)):
                check_session(bad)

    def test_real_session_ids_pass(self):
        for good in ("20261120_101500_ab12cd", "agent:main:telegram:dm:4242", "default", "a b",
                     "+15551234567@s.whatsapp.net", "!room:matrix.example", "Zoë-Ωμέγα"):
            self.assertEqual(check_session(good), good)
        self.assertEqual(check_session(""), "default")


class DeviceSweeperTests(unittest.TestCase):
    """F20 (2), F96: the device sweeper's job sweep runs even when the workspace sweep fails."""

    def test_job_files_are_reaped_even_when_the_workspace_sweep_fails(self):
        d = temp_dir(self, "hp-dev-")
        consent = type("Consent", (), {"live_sessions": staticmethod(lambda: {"s1"})})()
        dev = DeviceService(None, HostPin(d), consent, "mac", {}, lambda: {})

        class Broken:
            def sweep(self, live):
                raise RuntimeError("a folder that cannot be listed")
        dev.workspaces = Broken()
        seen = []
        dev.job_sweep = lambda live: seen.append(set(live)) or 0
        sleeps = []
        real_sleep = asyncio.sleep

        async def one_pass(_seconds):
            sleeps.append(_seconds)
            if len(sleeps) > 1:
                raise asyncio.CancelledError
            await real_sleep(0)

        async def run():
            with mock.patch("tether.device.asyncio.sleep", one_pass), self.assertLogs("tether.device", "WARNING"):
                try:
                    await dev._sweep()
                except asyncio.CancelledError:
                    pass
        asyncio.run(run())
        self.assertEqual(seen, [{"s1"}])


_START_CHILD = textwrap.dedent("""
    import json, os, sys
    from pathlib import Path
    from unittest import mock
    tests = Path(sys.argv[1])
    sys.path.insert(0, str(tests))
    sys.path.insert(1, str(Path(os.environ.get("HERMES_AGENT_SRC") or Path.home() / ".hermes" / "hermes-agent")))
    from test_plugin_register import Ctx, load_plugin
    plugin = load_plugin()
    error = ""
    with mock.patch.object(sys, "argv", ["hermes", "gateway", "run"]):
        try:
            plugin.register(Ctx({"role": "device", "name": "mac"}))
        except Exception as e:
            error = type(e).__name__
    handle = sys.modules.get("tether_runtime_handle")
    print(json.dumps({"error": error, "device": bool(handle and handle.runtime and handle.runtime.device)}), flush=True)
    os._exit(0)
""")


class DeviceStartTests(unittest.TestCase):
    """F20 (3), F96: the device role starts past a leftover it cannot list at first, and reaps recorded jobs. Runs
    the plugin's register() in a child process with its own temp Hermes home (as the gateway would)."""

    def test_the_device_role_starts_past_a_locked_leftover_and_reaps_recorded_jobs(self):
        try:
            import agent.terminal_env_provider  # noqa: F401
        except Exception:  # noqa: BLE001
            self.skipTest("Hermes source not importable")
        home = temp_dir(self, "hp-home-")
        self.addCleanup(unlock_tree, home)
        sessions = home / "tether" / "sessions"
        trap = sessions / "old-session" / "trap"
        trap.mkdir(parents=True)
        (sessions / "old-session" / "notes.txt").write_text("scratch")
        os.chmod(trap, 0)
        os.chmod(sessions / "old-session", 0)                             # mkdir trap && chmod 000 trap && chmod 000 .
        job = "proc_" + "ab" * 6                                          # recorded by an earlier run; its files are
        (home / "tether" / "bg_jobs.json").write_text(json.dumps([job]))  # gone, so it has ended
        env = {k: v for k, v in os.environ.items() if not k.startswith("HERMES_SESSION")}
        env["HERMES_HOME"] = str(home)
        out = subprocess.run([sys.executable, "-c", _START_CHILD, str(Path(__file__).resolve().parent)],
                             capture_output=True, text=True, timeout=120, env=env)
        lines = [line for line in out.stdout.splitlines() if line.startswith("{")]
        self.assertTrue(lines, "the child printed no result")
        result = json.loads(lines[-1])
        self.assertEqual(result, {"error": "", "device": True})          # the device role started
        self.assertFalse(os.path.lexists(sessions / "old-session"))
        self.assertFalse((home / "tether" / "bg_jobs.json").exists())    # reap_recorded ran at the start


class CleanupPartsTests(unittest.TestCase):
    """F96: D39 parts that no test reached."""

    def test_a_temporary_certificate_copy_is_deleted_right_after_loading(self):
        d = temp_dir(self, "hp-id-")
        ident = load_or_create(d, MemorySecretStore(), "tether-x")
        (d / "identity.crt").write_bytes(b"stale certificate")             # no longer matches: the temp branch runs
        seen = []
        real = tlslink._cert_path

        def spy(i):
            out = real(i)
            seen.append(out)
            return out
        with mock.patch.object(tlslink, "_cert_path", spy):
            tlslink.client_context(ident, None)
        self.assertEqual(len(seen), 1)
        path, temp = seen[0]
        self.assertTrue(temp)
        self.assertFalse(os.path.exists(path))
        self.assertEqual(glob.glob(os.path.join(tempfile.gettempdir(), "tether-*.crt")), [])

    def test_a_link_in_place_of_the_data_folder_never_has_its_target_chmodded(self):
        """The key's folder is set to 0700 itself; a link put in its place never passes that on to what it names."""
        target = user_folder(self)
        os.chmod(target, 0o755)
        link = temp_dir(self, "hp-id-") / "tether"
        os.symlink(target, link)
        load_or_create(link, MemorySecretStore(), "tether-x")
        self.assertEqual(mode(target), 0o755, "the folder a link pointed to was chmodded")

    def test_a_failed_state_write_leaves_no_temporary_file(self):
        d = temp_dir(self, "hp-store-")
        with mock.patch("os.replace", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                store._write(d / "settings.json", {"a": 1})
        self.assertEqual(os.listdir(d), [])

    def test_a_planted_temporary_link_is_never_written_through(self):
        d = temp_dir(self, "hp-store-")
        victim = user_folder(self) / "thesis.txt"
        victim.write_text("the person's own")
        os.chmod(victim, 0o644)
        for name in ("settings.tmp", ".settings.json.tmp"):
            os.symlink(victim, d / name)
        store._write(d / "settings.json", {"a": 1})
        self.assertEqual(victim.read_text(), "the person's own")
        self.assertEqual(mode(victim), 0o644)
        self.assertEqual(json.loads((d / "settings.json").read_text()), {"a": 1})

    def test_the_link_socket_goes_when_its_owner_exits_normally(self):
        d = temp_dir(self, "hp-sock-")
        child = textwrap.dedent("""
            import asyncio, sys
            from pathlib import Path
            sys.path.insert(0, sys.argv[1])
            from tether.hostlink import HostLink
            class Svc:
                async def start(self): pass
                async def close(self): pass
                def status(self): return []
            link = HostLink(Path(sys.argv[2]), Svc)
            asyncio.run(link.ensure())
            print(link.role, (Path(sys.argv[2]) / "link.sock").exists())
        """)
        plugin = str(Path(__file__).resolve().parents[1] / "plugin" / "tether")
        out = subprocess.run([sys.executable, "-c", child, plugin, str(d)], capture_output=True, text=True, timeout=60)
        self.assertEqual(out.stdout.split(), ["owner", "True"])
        self.assertFalse((d / "link.sock").exists())

    def test_closing_releases_the_sessions_file_tool_state(self):
        ws = Workspaces(temp_dir(self, "hp-ws-") / "sessions")
        gate = consent_gate(prompt=FakePrompt(True))
        grant = asyncio.run(gate.require("fp", "Test host", "s1"))
        released = []
        with mock.patch.object(device_exec, "_release_file_tasks", released.append):
            asyncio.run(SessionControl(gate, ws, LocalExec(ws), lambda: "fp").close_session(
                {"session": "s1", "grant": grant}, b""))
        self.assertEqual(released, ["s1"])

    def test_a_closed_session_leaves_no_targets_entry(self):
        from tether.runtime import get_runtime
        rt = get_runtime()
        self.addCleanup(setattr, rt, "host", rt.host)
        rt.host = None
        rt.targets["hp-closed"] = "mac"
        rt.close_device("hp-closed", "closed by the test")
        self.assertNotIn("hp-closed", rt.targets)

    def test_windows_never_probes_a_background_jobs_pid(self):
        job = "proc_" + "cd" * 6

        class WindowsOs:
            name = "nt"

            def __getattr__(self, attr):
                return getattr(os, attr)

            def kill(self, *a):
                raise AssertionError("Windows must never probe a pid (os.kill would end the process there)")
        with mock.patch.object(device_exec, "os", WindowsOs()):
            log, pid_path, exit_path = job_paths(job)                     # Windows: in the temp folder
            Path(pid_path).write_text(str(os.getpid()))
            self.addCleanup(lambda: [Path(p).unlink(missing_ok=True) for p in (log, pid_path, exit_path)])
            self.assertFalse(device_exec._job_ended(job))                 # fresh, no .exit: still running
            old = time.time() - device_exec.JOB_MAX_AGE_S - 60
            os.utime(pid_path, (old, old))
            self.assertTrue(device_exec._job_ended(job))                  # past the age limit: ended

    def test_a_damaged_open_session_record_does_not_break_reading_or_writing_it(self):
        d = temp_dir(self, "hp-open-")
        for bad in ("yesterday", [1], {"x": 1}, "nan", "inf"):
            (d / store.OPEN_FILE).write_text(json.dumps({"other": {"device": "mac", "pid": 999999999, "at": bad}}))
            book = OpenSessions(d)
            book.all()
            book.put("s1", "mac")
            self.assertIn("s1", book.all())
            book.drop("s1")
            self.assertNotIn("s1", book.all())


class HeldFilePathTests(_PathVariant, _windows.HeldFileWipeTests):
    pass


class ReservedNamePathTests(_PathVariant, _windows.ReservedNameWipeTests):
    test_extended_paths = None


if __name__ == "__main__":
    unittest.main()
