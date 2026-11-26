"""The maintainers' Hermes watcher (scripts/hermes_watch.py, scripts/hermes_watch_cron.sh; replaces the on-device
Hermes source pin, owner's ruling H2/W). Offline: a small fake Hermes source and a local git repository; the real
Hermes source is only read (never cloned or fetched)."""
from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import hermes_watch as hw  # noqa: E402
from test_link_loopback import remove_tree  # noqa: E402

HERMES = Path(os.environ.get("HERMES_AGENT_SRC") or Path.home() / ".hermes" / "hermes-agent")

FAKE = {
    "tools/__init__.py": "",
    "tools/environments/__init__.py": "",
    "tools/environments/base.py": (
        "class BaseEnvironment:\n"
        "    def execute(self, cmd):\n"
        "        return self._run_bash(cmd)\n\n"
        "    def init_session(self):\n"
        "        self._run_bash('snapshot', login=True)\n\n"
        "    def describe(self):\n"
        "        return 'base'\n"),
    "tools/environments/local.py": (
        "import subprocess\n"
        "from tools.environments.base import BaseEnvironment\n\n\n"
        "def _find_bash():\n"
        "    return '/bin/bash'\n\n\n"
        "class LocalEnvironment(BaseEnvironment):\n"
        "    def __init__(self, cwd='', timeout=60, env=None):\n"
        "        self.cwd = cwd\n\n"
        "    def _run_bash(self, cmd, login=False):\n"
        "        \"\"\"Start bash.\"\"\"\n"
        "        return subprocess.Popen([_find_bash(), '-c', cmd])\n\n"
        "    def get_temp_dir(self):\n"
        "        return '/tmp'\n"),
    "tools/askpass.py": "def probe(env):\n    return env._run_bash('sudo -n true')\n",
    "agent/__init__.py": "",
    "agent/ctx.py": "def is_child():\n    return False\n",
    "model_tools.py": "def _execute_tool(x):\n    return x\n",
    "hermes_constants.py": "HOME = '~/.hermes'\n\n\ndef get_hermes_home():\n    return HOME\n",
}
PLUGIN = {
    "lock.py": (
        "def make():\n"
        "    import tools.environments.local as L\n"
        "    from tools.environments.local import LocalEnvironment\n\n"
        "    class Locked(LocalEnvironment):\n"
        "        def _run_bash(self, cmd, login=False):\n"
        "            return L._find_bash(), self.get_temp_dir()\n"
        "    return Locked\n"),
    "other.py": (
        "import sys\n"
        "from hermes_constants import get_hermes_home\n"
        "SURFACES = ((\"agent.ctx\", \"is_child\", \"why it matters\"),)\n\n\n"
        "def f():\n"
        "    mt = sys.modules.get('model_tools')\n"
        "    return getattr(mt, '_execute_tool', None), get_hermes_home()\n"),
}
EXPECTED = {
    "agent.ctx.is_child", "hermes_constants.get_hermes_home", "model_tools", "model_tools._execute_tool",
    "tools.environments.local", "tools.environments.local.LocalEnvironment",
    "tools.environments.local.LocalEnvironment._run_bash", "tools.environments.local.LocalEnvironment.get_temp_dir",
    "tools.environments.local._find_bash",
    # the spawn surface: where Hermes starts processes for the environment Tether subclasses
    "tools.environments.base.BaseEnvironment.execute", "tools.environments.base.BaseEnvironment.init_session",
    "tools.askpass.probe",
}


def write_tree(root: Path, files: dict) -> None:
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)


class Fake(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="hw-"))
        self.addCleanup(remove_tree, self.tmp)
        self.src, self.plugin, self.base = self.tmp / "hermes", self.tmp / "plugin", self.tmp / "baseline.json"
        write_tree(self.src, FAKE)
        write_tree(self.plugin, PLUGIN)

    def watch(self, *extra) -> tuple[int, str]:
        out = io.StringIO()
        with redirect_stdout(out):
            rc = hw.main([str(self.src), "--baseline", str(self.base), "--plugin", str(self.plugin), *extra])
        return rc, out.getvalue()

    def edit(self, rel: str, old: str, new: str) -> None:
        p = self.src / rel
        text = p.read_text()
        self.assertIn(old, text)
        p.write_text(text.replace(old, new))


class DeriveTests(Fake):
    def test_every_kind_of_use_is_on_the_watch_list(self):
        names = set(hw.derive_names(self.plugin, hw.Source(self.src)))
        self.assertEqual(names, EXPECTED)


class CompareTests(Fake):
    def test_silent_when_nothing_changed_or_only_formatting_did(self):
        self.assertEqual(self.watch("--write-baseline"), (0, ""))
        self.assertEqual(self.watch(), (0, ""))
        self.edit("tools/environments/local.py", '"""Start bash."""', '"""Start bash (reworded)."""\n        # a note')
        self.edit("tools/environments/base.py", "class BaseEnvironment:\n", "class BaseEnvironment:\n\n\n")
        self.assertEqual(self.watch(), (0, ""), "a docstring, comment or blank-line change was reported")

    def test_one_line_per_changed_or_missing_name(self):
        self.watch("--write-baseline")
        self.edit("tools/environments/local.py", "[_find_bash(), '-c', cmd]", "[_find_bash(), '-lc', cmd]")
        self.edit("tools/environments/local.py", "    def get_temp_dir(self):\n        return '/tmp'\n", "")
        self.edit("tools/environments/base.py", "return self._run_bash(cmd)", "return self._run_bash(cmd, login=True)")
        rc, out = self.watch()
        self.assertEqual(rc, 1)
        self.assertEqual(out.splitlines(), [
            "changed: tools.environments.base.BaseEnvironment.execute",
            "changed: tools.environments.local.LocalEnvironment",
            "changed: tools.environments.local.LocalEnvironment._run_bash",
            "missing: tools.environments.local.LocalEnvironment.get_temp_dir",
        ])

    def test_a_new_spawn_path_or_a_new_use_is_reported(self):
        self.watch("--write-baseline")
        (self.src / "tools" / "jobs.py").write_text("def spawn(env):\n    return env._spawn_long_lived(['x'], None)\n")
        (self.plugin / "more.py").write_text("from agent.ctx import is_child as c\n")
        rc, out = self.watch()
        self.assertEqual(rc, 1)
        self.assertIn("not in baseline: tools.jobs.spawn", out)
        self.assertNotIn("agent.ctx", out, "a name already in the baseline was reported as new")

    def test_an_unreadable_baseline_or_source_is_an_error_not_silence(self):
        rc, _ = self.watch()
        self.assertEqual(rc, 2, "a missing baseline must not read as 'nothing changed'")
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(hw.main([str(self.tmp / "nothing-here"), "--baseline", str(self.base)]), 2)


@unittest.skipUnless((HERMES / "tools" / "environments" / "local.py").is_file(), "the local Hermes source is needed")
class RealHermesTests(unittest.TestCase):
    def setUp(self):
        self.data = json.loads((SCRIPTS / "hermes_watch_baseline.json").read_text())

    def test_the_baseline_names_the_hermes_it_was_made_from(self):
        self.assertTrue(self.data["hermes"]["version"].startswith("v0.23.3"), "the baseline is not Hermes 0.23.3")
        self.assertEqual(len(self.data["hermes"]["commit"]), 40)

    def test_the_baseline_covers_everything_the_plugin_uses(self):
        derived = set(hw.derive_names(ROOT / "plugin", hw.Source(HERMES)))
        self.assertEqual(sorted(derived - set(self.data["names"])), [],
                         "the plugin uses Hermes names the baseline does not know: verify, then write it again")
        for name in ("tools.environments.local.LocalEnvironment.wrap_argv",
                     "tools.environments.local.LocalEnvironment._run_bash",
                     "tools.environments.base.BaseEnvironment.execute",
                     "tools.environments.base.BaseEnvironment.init_session"):
            self.assertIn(name, self.data["names"], f"the session lock depends on {name}")

    def test_silent_on_the_hermes_the_baseline_was_made_from(self):
        head = subprocess.run(["git", "-C", str(HERMES), "rev-parse", "HEAD"], capture_output=True, text=True).stdout
        if head.strip() != self.data["hermes"]["commit"]:
            self.skipTest("the local Hermes is not the baseline's commit")
        out = io.StringIO()
        with redirect_stdout(out):
            rc = hw.main([str(HERMES)])
        self.assertEqual((rc, out.getvalue()), (0, ""))


@unittest.skipUnless(shutil.which("git") and shutil.which("bash"), "git and bash are needed")
class CronTests(Fake):
    def setUp(self):
        super().setUp()
        self.repo, self.cache = self.tmp / "upstream", self.tmp / "cache"
        gitconfig = self.tmp / "gitconfig"
        gitconfig.write_text("[user]\n\tname = t\n\temail = t@example.invalid\n")
        self.env = {**os.environ, "GIT_CONFIG_GLOBAL": str(gitconfig), "GIT_CONFIG_NOSYSTEM": "1",
                    "GIT_ALLOW_PROTOCOL": "file", "TMPDIR": str(self.tmp),
                    "TETHER_WATCH_REPO": str(self.repo), "TETHER_WATCH_BASELINE": str(self.base),
                    "TETHER_WATCH_PLUGIN": str(self.plugin), "TETHER_WATCH_PYTHON": sys.executable}
        self.day = 0
        shutil.copytree(self.src, self.repo)
        self.git("init", "-q")
        self.commit_and_tag("v1.0.0")
        self.watch("--write-baseline")

    def git(self, *args: str, cwd: Path | None = None) -> None:
        subprocess.run(["git", *args], cwd=cwd or self.repo, env=self.env, check=True, capture_output=True)

    def commit_and_tag(self, tag: str) -> None:
        self.day += 1
        when = f"2030-01-{self.day:02d}T12:00:00Z"
        env = {**self.env, "GIT_COMMITTER_DATE": when, "GIT_AUTHOR_DATE": when}
        subprocess.run(["git", "add", "-A"], cwd=self.repo, env=env, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-q", "--allow-empty", "-m", tag], cwd=self.repo, env=env, check=True,
                       capture_output=True)
        subprocess.run(["git", "tag", "-a", tag, "-m", tag], cwd=self.repo, env=env, check=True, capture_output=True)

    def cron(self) -> tuple[int, str]:
        proc = subprocess.run(["bash", str(SCRIPTS / "hermes_watch_cron.sh"), str(self.cache)], env=self.env,
                              capture_output=True, text=True, timeout=120)
        return proc.returncode, proc.stdout

    def test_reports_a_new_release_that_changes_a_wrapped_name_once(self):
        local = self.repo / "tools" / "environments" / "local.py"
        local.write_text(local.read_text().replace("'-c', cmd", "'-lc', cmd"))
        self.commit_and_tag("v1.1.0")
        rc, out = self.cron()
        self.assertEqual(rc, 0)
        lines = out.splitlines()
        self.assertTrue(lines[0].startswith("Hermes v1.1.0 changes what Tether wraps"), out)
        self.assertIn("verify Tether before updating", lines[0])
        self.assertIn("changed: tools.environments.local.LocalEnvironment._run_bash", lines)
        self.assertEqual(self.cron(), (0, ""), "the same release was reported twice")
        self.assertEqual((self.cache / "last_checked_tag").read_text().strip(), "v1.1.0")

    def test_quiet_for_releases_that_change_nothing_tether_uses_and_for_canaries(self):
        (self.repo / "tools" / "unrelated.py").write_text("def g():\n    return 1\n")
        self.commit_and_tag("v1.0.1")
        self.assertEqual(self.cron(), (0, ""))
        self.assertEqual((self.cache / "last_checked_tag").read_text().strip(), "v1.0.1")
        local = self.repo / "tools" / "environments" / "local.py"
        local.write_text(local.read_text().replace("'-c', cmd", "'-lc', cmd"))
        self.commit_and_tag("v1.1.0+canary.20300105")
        self.assertEqual(self.cron(), (0, ""), "a canary tag was treated as a release")

    def test_a_failing_fetch_is_reported_only_on_the_third_run_in_a_row(self):
        self.env["TETHER_WATCH_REPO"] = str(self.tmp / "no-such-repo")
        self.assertEqual(self.cron(), (0, ""))
        self.assertEqual(self.cron(), (0, ""))
        rc, out = self.cron()
        self.assertEqual(rc, 0)
        self.assertIn("could not fetch Hermes release tags 3 times in a row", out)


if __name__ == "__main__":
    unittest.main()
