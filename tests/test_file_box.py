"""The file tools a remote session uses run inside its session lock (D79): on a Mac, macOS itself refuses Tether's
and Hermes's files to them however a path names them ('..' after a link, the data-volume prefix, /.vol, several
paths in one search, a relative path inside a patch, a link flipped between the check and the use), the person's
own files and the workspace keep working, and a call that cannot be put in the lock is refused, never run in this
process. Skill copies never write through a link swapped in while they run (R4-1). Every path is inside this run's
temp folder; the secrets are dummy values and are never printed."""
from __future__ import annotations

import asyncio
import contextlib
import io
import json
import os
import sys
import tarfile
import time
import unittest
from pathlib import Path
from unittest import mock

HERMES_SRC = Path(os.environ.get("HERMES_AGENT_SRC") or Path.home() / ".hermes" / "hermes-agent")
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "plugin" / "tether"))
sys.path.insert(1, str(HERMES_SRC))

from test_link_loopback import isolated_plugins, no_plugin_discovery, temp_dir  # noqa: E402

try:
    no_plugin_discovery()
    import model_tools  # noqa: F401
    import tools.file_tools  # noqa: F401
    HAVE_HERMES = True
except Exception:  # noqa: BLE001
    HAVE_HERMES = False

from test_session_lock import ON_MAC, SECRET, FakeDevice  # noqa: E402


def _no_early_check(*args, **kwargs):
    """Tether's path check switched off: what is left is the lock itself."""
    return None


class EarlyCheckTests(unittest.TestCase):
    """The path checks stay as the early, friendlier refusal; they now see what Hermes will use (S1-1, S1-2, S2-1)."""

    def setUp(self):
        self.dev = FakeDevice(self)
        self.ws = self.dev.home / "ws"
        self.ws.mkdir()
        os.symlink(self.dev.R / "plugins", self.ws / "link")

    def refusal(self, name, args):
        return self.dev.lock.tool_refusal(name, args, base=str(self.ws), workspace=str(self.ws))

    def test_dotdot_after_a_link_is_judged_where_it_leads(self):
        self.assertIsNotNone(self.refusal("read_file", {"path": f"{self.ws}/link/../tether/identity.key.enc"}))
        self.assertIsNotNone(self.refusal("write_file", {"path": f"{self.ws}/link/../zz.txt", "content": "x"}))

    def test_every_part_of_a_multi_path_search_is_checked(self):
        for path in (f"{self.ws}/nope,{self.dev.data}", f"{self.ws}/nope {self.dev.data}"):
            self.assertIsNotNone(self.refusal("search_files", {"pattern": "x", "path": path}), path)

    @unittest.skipUnless(sys.platform == "darwin", "macOS data volume")
    def test_the_data_volume_prefix_names_the_same_files(self):
        path = f"/System/Volumes/Data{self.dev.data}/identity.key.enc"
        self.assertIsNotNone(self.refusal("read_file", {"path": path}))


@unittest.skipUnless(HAVE_HERMES and ON_MAC, "macOS sandbox and Hermes source needed")
class BoxedFileToolTests(unittest.TestCase):
    """Through the device's real path: ToolRunner -> Hermes's handle_function_call -> registry -> the session's
    helper inside its lock. Most cases switch Tether's path check off, so the lock alone is what refuses."""

    def setUp(self):
        self.dev = d = FakeDevice(self)
        for name in ("authenticator.json", "authenticator_state.json", "paired_host.json"):
            (d.data / name).write_text(f'{{"sealed": "{SECRET}"}}\n')
        (d.data / "settings.json").write_text("{}\n")
        (d.home / "work" / "notes.txt").write_text("mine\n")
        manager = isolated_plugins(self)
        from hermes_cli.plugins_context import PluginContext
        from hermes_cli.plugins_manifest import PluginManifest
        from tether import forward
        from tether.device_exec import LocalExec, ToolRunner, set_plugin_context
        from tether.workspace import Workspaces
        # As register() sets it up: tether's middleware in the chain, the plugin's ctx kept for the lent tools.
        manager._middleware.setdefault("tool_execution", []).append(forward.tool_execution)
        self.ctx = PluginContext(PluginManifest(name="tether"), manager)
        set_plugin_context(self.ctx)
        self.addCleanup(set_plugin_context, None)
        self.workspaces = Workspaces(d.data / "sessions")
        self.addCleanup(self.workspaces.close)
        self.loc = LocalExec(self.workspaces)
        self.addCleanup(self.loc.close_all)
        self.runner = ToolRunner(self.ctx, self.loc, self.workspaces)
        self.ws = self.workspaces.ensure("s1")
        self.before = {p: p.read_bytes() for p in d.data.glob("*.json")}

    def run_cmd(self, command: str) -> str:
        _, body = asyncio.run(self.loc.exec({"command": command, "session": "s1", "host_gate": True,
                                             "timeout": 30}, b""))
        return body.decode(errors="replace")

    def call(self, name: str, args: dict, early: bool = False) -> str:
        patch = contextlib.nullcontext() if early else mock.patch("tether.lock.tool_refusal", _no_early_check)
        with patch:
            try:
                _, body = self.runner._run(name, dict(args), "s1")
            except PermissionError as e:
                return f"REFUSED {e}"
        return body.decode(errors="replace")

    def assertUntouched(self):
        d = self.dev
        self.assertEqual({p: p.read_bytes() for p in d.data.glob("*.json")}, self.before)
        self.assertEqual((d.proj / "__init__.py").read_text(), "# live\n")
        self.assertEqual(sorted(p.name for p in d.proj.iterdir()), ["__init__.py"])
        self.assertEqual(sorted(p.name for p in (d.R / "plugins").iterdir()), ["tether"])
        self.assertFalse((d.R / "zz.txt").exists())
        self.assertEqual((d.R / "config.yaml").read_text(), "a: 1\n")

    def test_dotdot_after_a_link_reaches_nothing(self):
        """S1-1: a link made by the session's own command, then '..' after it."""
        self.run_cmd(f"ln -s {self.dev.R}/plugins {self.ws}/link")
        for name in ("identity.key.enc", "authenticator.json"):
            self.assertNotIn(SECRET, self.call("read_file", {"path": f"{self.ws}/link/../tether/{name}"}))
        self.call("write_file", {"path": f"{self.ws}/link/../zz.txt", "content": "x"})
        self.call("write_file", {"path": f"{self.ws}/link/../plugins/tether/evil.py", "content": "x"})
        self.call("write_file", {"path": f"{self.ws}/link/../tether/settings.json",
                                 "content": '{"allow_unlocked_commands": true}'})
        self.assertNotIn(SECRET, self.call("search_files", {"pattern": "dummy", "path": f"{self.ws}/link/../tether"}))
        self.assertUntouched()

    def test_several_paths_in_one_search_reach_nothing(self):
        """S1-2 / S2-3: Hermes splits a search path on commas and spaces."""
        for path in (f"{self.ws}/nope,{self.dev.data}", f"{self.ws}/nope {self.dev.data}", f"nope,{self.dev.R}"):
            out = self.call("search_files", {"pattern": "dummy", "path": path})
            self.assertNotIn(SECRET, out, path)
            out = self.call("search_files", {"pattern": "", "target": "files", "path": path})
            self.assertNotIn("identity.key.enc", out, path)

    def test_relative_patch_paths_do_not_land_in_hermess_folder(self):
        """S1-3 / S2-2: this process's folder is the Hermes home, as the gateway's launch agent sets it."""
        here = os.getcwd()
        os.chdir(self.dev.R)
        self.addCleanup(os.chdir, here)
        self.call("patch", {"mode": "patch", "patch": "*** Begin Patch\n*** Update File: tether/settings.json\n@@\n-{}"
                                                      "\n+{\"allow_unlocked_commands\": true}\n*** End Patch\n"})
        self.call("patch", {"mode": "patch", "patch": "*** Begin Patch\n*** Add File: plugins/zz/__init__.py\n"
                                                      "+import os\n*** End Patch\n"})
        self.call("patch", {"mode": "patch", "patch": "*** Begin Patch\n*** Delete File: tether/authenticator.json\n"
                                                      "*** End Patch\n"})
        self.assertFalse((self.dev.R / "plugins" / "zz").exists())
        self.assertUntouched()

    def test_a_link_flipped_after_the_check_reaches_nothing(self):
        """S1-4 / S3-1: the session's background job flips a workspace link; here it flips at the worst moment,
        right after Tether's check passed."""
        from tether import lock
        (self.ws / "ok").mkdir()
        os.symlink(self.ws / "ok", self.ws / "d")
        real = lock.tool_refusal

        def check_then_flip(*args, **kwargs):
            why = real(*args, **kwargs)
            os.unlink(self.ws / "d")
            os.symlink(self.dev.R, self.ws / "d")
            return why

        with mock.patch("tether.lock.tool_refusal", check_then_flip):
            try:
                self.runner._run("write_file", {"path": f"{self.ws}/d/plugins/zz/__init__.py", "content": "x"}, "s1")
            except PermissionError:
                pass
        self.assertFalse((self.dev.R / "plugins" / "zz").exists(), "written through the flipped link")
        self.assertUntouched()

    def test_other_names_for_the_same_files_reach_nothing(self):
        """S2-1 (/System/Volumes/Data) and S2-4 (/.vol/<fs>/<inode>)."""
        key = self.dev.data / "identity.key.enc"
        firm = f"/System/Volumes/Data{key}"
        st = os.stat(key)
        for path in (firm, f"/.vol/{st.st_dev}/{st.st_ino}"):
            self.assertNotIn(SECRET, self.call("read_file", {"path": path}), path)
        self.assertNotIn(SECRET, self.call("search_files", {"pattern": "dummy",
                                                            "path": f"/System/Volumes/Data{self.dev.data}"}))
        self.call("write_file", {"path": f"/System/Volumes/Data{self.dev.proj}/evil.py", "content": "x"})
        self.call("patch", {"mode": "patch", "patch": f"*** Begin Patch\n*** Add File: /System/Volumes/Data"
                                                      f"{self.dev.R}/plugins/tether/x.py\n+x\n*** End Patch\n"})
        self.assertUntouched()

    def test_the_persons_files_and_the_workspace_still_work(self):
        """Everything a session did before in the person's projects still works, now inside the lock."""
        w = self.dev.home / "work"
        out = self.call("write_file", {"path": str(w / "new.py"), "content": "a = 1\n"}, early=True)
        self.assertNotIn("error", json.loads(out), out)
        self.assertIn("mine", self.call("read_file", {"path": str(w / "notes.txt")}, early=True))
        out = self.call("patch", {"path": str(w / "new.py"), "old_string": "a = 1", "new_string": "a = 2"}, early=True)
        self.assertNotIn("error", json.loads(out), out)
        self.assertEqual((w / "new.py").read_text(), "a = 2\n")
        out = self.call("patch", {"mode": "patch", "patch": "*** Begin Patch\n*** Add File: rel.txt\n+hi\n"
                                                            "*** End Patch\n"}, early=True)
        self.assertEqual((self.ws / "rel.txt").read_text().strip(), "hi", out)    # relative: the session's folder
        self.assertIn("a = 2", self.call("search_files", {"pattern": "a = ", "path": str(w)}, early=True))
        self.assertIn("rel.txt", self.call("search_files", {"pattern": "hi"}, early=True))
        self.assertEqual(self.loc._boxes["s1"].started, 1, "the calls did not run in the session's one helper")
        t = time.perf_counter()
        for _ in range(10):
            self.call("search_files", {"pattern": "mine", "path": str(w)}, early=True)
        self.assertLess((time.perf_counter() - t) / 10, 1.0, "a file call inside the lock is too slow")

    def test_no_sandbox_refuses_and_nothing_runs_here(self):
        """Fail closed: where the lock cannot start, the call is refused; it never runs in this process."""
        target = self.dev.home / "work" / "never.txt"
        with mock.patch.object(self.dev.lock, "SANDBOX_EXEC", str(self.dev.home / "no-sandbox-exec")):
            out = self.call("write_file", {"path": str(target), "content": "x"}, early=True)
        self.assertTrue(out.startswith("REFUSED"), out)
        self.assertFalse(target.exists())

    def test_a_session_call_reaching_hermes_without_its_helper_is_refused(self):
        """Tether's middleware refuses a remote session's lent file tool that no locked helper serves (it never runs
        in this process); the device's own calls are untouched."""
        from tools import terminal_tool
        if "default" not in terminal_tool._active_environments:      # the own call below makes Hermes's shared
            from tools.file_tools import clear_file_ops_cache            # terminal here: not left for other tests
            from tools.terminal_tool_lifecycle import cleanup_vm
            self.addCleanup(clear_file_ops_cache, "default")
            self.addCleanup(cleanup_vm, "default")
        target = self.dev.home / "work" / "direct.txt"
        out = self.ctx.run_tool_call("write_file", {"path": str(target), "content": "x"}, task_key="zz")
        self.assertIn("was not run", str(out))
        self.assertFalse(target.exists())
        import model_tools
        model_tools.handle_function_call("write_file", {"path": str(target), "content": "own"}, task_id="default")
        self.assertEqual(target.read_text(), "own")

    def test_the_helper_ends_with_the_session(self):
        self.call("read_file", {"path": str(self.dev.home / "work" / "notes.txt")}, early=True)
        box = self.loc._boxes["s1"]
        proc = box._proc
        self.assertIsNotNone(proc)
        self.loc.drop("s1")
        self.assertIsNotNone(proc.poll(), "the helper outlived its session")
        self.assertTrue(box.closed)


class SkillCopyTests(unittest.TestCase):
    """R4-1: the copy writes inside folders held open; a link swapped in after the check is never written through."""

    @unittest.skipIf(os.name == "nt", "folder-relative calls: macOS and Linux")
    def test_a_link_swapped_in_after_the_check_is_not_written_through(self):
        from tether.workspace import Workspaces
        base = temp_dir(self, "hp-skill-")
        outside = base / "outside"
        outside.mkdir()
        self.addCleanup(os.system, f"chmod -R u+rwx '{base}' 2>/dev/null")    # the copy is read-only
        ws = Workspaces(base / "data" / "sessions")
        self.addCleanup(ws.close)
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            for name, data in (("SKILL.md", b"# skill\n"), ("sub/pwned.txt", b"x\n")):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        real = Workspaces._leads_to

        def check_then_swap(path, fd):
            out = real(path, fd)
            if path.name == "pwn":                   # the skill's folder: the session swaps it for a link now
                os.rename(path, base / "moved")
                os.symlink(outside, path)
            return out

        with mock.patch.object(Workspaces, "_leads_to", staticmethod(check_then_swap)):
            try:
                ws.put_skill("s1", "pwn", buf.getvalue())
            except Exception:  # noqa: BLE001 - a copy that stops is fine; one that writes outside is not
                pass
        self.assertEqual(list(outside.iterdir()), [], "the skill copy wrote through the swapped link")


if __name__ == "__main__":
    unittest.main()
