"""Windows device support, simulated on any OS: the approval code box (a masked PowerShell form; D63) and a
workspace wipe that survives files a running program still holds open."""
from __future__ import annotations

import asyncio
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "plugin" / "tether"))

from tether import consent, workspace  # noqa: E402
from test_link_loopback import temp_dir  # noqa: E402


def fake_powershell(test, answer: str) -> str:
    """A stand-in for powershell.exe: records its arguments and environment, prints the box's answer."""
    d = temp_dir(test, "hp-ps-")
    script = d / "powershell"
    script.write_text("#!/bin/sh\n"
                      f'printf "%s\\n" "$@" > "{d}/args"\n'
                      f'printf "%s" "$TETHER_BOX_TEXT|$TETHER_BOX_TIMEOUT|$TETHER_BOX_TITLE" > "{d}/env"\n'
                      f'printf "%s" "{answer}"\n')
    script.chmod(0o755)
    return str(script)


class PromptChoiceTests(unittest.TestCase):
    def test_prompt_per_os(self):
        for system, expected in (("Darwin", consent.macos_code_box), ("Windows", consent.windows_code_box),
                                 ("Linux", consent.unsupported_box)):
            with mock.patch.object(consent.platform, "system", lambda s=system: s):
                self.assertIs(consent.default_prompt(), expected, system)


@unittest.skipIf(sys.platform == "win32", "uses a POSIX shell stand-in for powershell.exe")
class WindowsPromptTests(unittest.TestCase):
    def ask(self, answer: str, text: str = "Hermes on nas wants to use this computer"):
        exe = fake_powershell(self, answer)
        with mock.patch.object(consent, "_powershell", lambda: exe):
            typed = asyncio.run(consent.windows_code_box(text, 45))
        d = Path(exe).parent
        return typed, (d / "args").read_text(), (d / "env").read_text()

    def test_only_what_was_typed_comes_back_and_nothing_else_approves(self):
        self.assertEqual(self.ask("CODE:12 34 56")[0], "12 34 56")    # handed to the check, never judged here
        for answer in ("CANCEL", "TIMEOUT", "6", "", "Approve", "CODE:" + "1" * 65):
            self.assertIsNone(self.ask(answer)[0], answer)          # the old Yes ("6") is no answer at all

    def test_text_never_enters_the_command(self):
        hostile = "x'); Remove-Item C:\\ -Recurse; ('"
        typed, args, env = self.ask("CANCEL", hostile)
        self.assertIsNone(typed)
        self.assertNotIn("Remove-Item", args)          # the script is fixed; the text only travels in the env
        self.assertIn("Remove-Item", env)
        self.assertTrue(env.endswith(f"|45|{consent.BOX_TITLE_WINDOWS}"))
        self.assertIn("-NonInteractive", args)
        self.assertIn("UseSystemPasswordChar = $true", args)   # what is typed shows masked

    def test_prompts_never_get_hermes_secrets(self):
        seen = []

        async def capture(*args, **kwargs):
            seen.append(kwargs.get("env"))
            raise OSError("not started")
        with mock.patch.dict(os.environ, {"OPENROUTER_API_KEY": "sk-secret", "PATH": "/usr/bin", "HOME": "/h"}), \
                mock.patch("asyncio.create_subprocess_exec", capture):
            self.assertIsNone(asyncio.run(consent.windows_code_box("x", 5)))
            self.assertIsNone(asyncio.run(consent.macos_code_box("x", 5)))
        win, mac = seen
        self.assertNotIn("OPENROUTER_API_KEY", win)
        self.assertEqual(win["PATH"], "/usr/bin")
        self.assertEqual(win["TETHER_BOX_TIMEOUT"], "5")
        self.assertEqual(mac, {"PATH": "/usr/bin", "HOME": "/h"} | ({"LANG": os.environ["LANG"]}
                                                                    if os.environ.get("LANG") else {}))

    def test_missing_powershell_denies(self):
        with mock.patch.object(consent, "_powershell", lambda: "/nonexistent/powershell.exe"):
            self.assertIsNone(asyncio.run(consent.windows_code_box("x", 5)))


class HeldFileWipeTests(unittest.TestCase):
    def test_held_file_is_left_for_the_sweeper(self):
        ws = workspace.Workspaces(temp_dir(self, "hp-wsw-") / "sessions")
        p = ws.ensure("s1")
        (p / "locked.txt").write_text("in use")
        (p / "free.txt").write_text("x")
        os.chmod(p / "free.txt", stat.S_IRUSR)          # read-only, as skill copies are
        real_unlink = os.unlink

        def unlink(path, *a, **k):
            if str(path).endswith("locked.txt"):
                raise PermissionError(32, "The process cannot access the file because it is being used")
            return real_unlink(path, *a, **k)

        with mock.patch("os.unlink", unlink):
            self.assertFalse(ws.wipe("s1"))              # not gone yet, and the close does not fail
        self.assertTrue((p / "locked.txt").exists())
        self.assertFalse((p / "free.txt").exists())     # everything else went, read-only included
        self.assertEqual(ws.sweep(set()), 1)            # the program let go: the sweeper finishes it
        self.assertFalse(p.exists())


class ReservedNameWipeTests(unittest.TestCase):
    """Live 2026-11-08: a Unix-style shell's ``> nul`` left a file named ``nul``; ``os.chmod`` on it fails on
    Windows (WinError 1), which crashed the close and every sweep."""

    def test_chmod_failure_does_not_stop_the_wipe(self):
        ws = workspace.Workspaces(temp_dir(self, "hp-wsn-") / "sessions")
        p = ws.ensure("s1")
        (p / "nul").write_text("")
        (p / "skills").mkdir()
        real_chmod = os.chmod

        def chmod(target, *a, **k):
            if str(target).endswith("nul"):
                raise OSError(22, "Incorrect function")
            return real_chmod(target, *a, **k)

        with mock.patch("os.chmod", chmod):
            self.assertTrue(ws.wipe("s1"))
        self.assertFalse(p.exists())

    def test_extended_paths(self):
        self.assertEqual(workspace._extended("C:\\Users\\z\\nul"), "\\\\?\\C:\\Users\\z\\nul")
        self.assertEqual(workspace._extended("\\\\srv\\share\\w"), "\\\\?\\UNC\\srv\\share\\w")
        self.assertEqual(workspace._extended("\\\\?\\C:\\w"), "\\\\?\\C:\\w")


if __name__ == "__main__":
    unittest.main()
