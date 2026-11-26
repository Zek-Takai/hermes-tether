"""register(ctx) per role, with a stand-in plugin context (no gateway, no network)."""
from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path
from test_link_loopback import isolate_session, temp_dir  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(1, str(Path(os.environ.get("HERMES_AGENT_SRC") or Path.home() / ".hermes" / "hermes-agent")))


def load_plugin():
    spec = importlib.util.spec_from_file_location("hp_plugin_under_test", ROOT / "plugin/tether/__init__.py",
                                                  submodule_search_locations=[str(ROOT / "plugin/tether")])
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class Ctx:
    def __init__(self, settings):
        self.settings, self.calls = settings, []

    def get_config(self, key, default=None):
        return self.settings.get(key, default)

    def __getattr__(self, name):
        if name.startswith("register_"):
            return lambda *a, **k: self.calls.append((name, a, k))
        raise AttributeError(name)


class RegisterTests(unittest.TestCase):
    def setUp(self):
        try:
            import agent.terminal_env_provider  # noqa: F401
        except Exception:  # noqa: BLE001
            self.skipTest("Hermes source not importable")
        isolate_session(self)      # register() records this process's origin: never from a live session's shell
        self.plugin = load_plugin()
        self._home = os.environ.get("HERMES_HOME")
        os.environ["HERMES_HOME"] = str(temp_dir(self, "hp-home-"))     # never the real ~/.hermes
        self.addCleanup(self._restore)

    def _restore(self):
        if self._home is None:
            os.environ.pop("HERMES_HOME", None)
        else:
            os.environ["HERMES_HOME"] = self._home
        handle = sys.modules.get("tether_runtime_handle")
        if handle is not None:
            handle.host_factory = None
            if handle.runtime is not None:
                handle.runtime.host = None

    def kinds(self, ctx):
        return sorted(c[0] for c in ctx.calls)

    # register_session_env is not a manifest surface (plugin.yaml is unchanged): it keeps the passphrase names out of
    # Hermes's shell snapshots, in every process the plugin loads in, whatever the role.
    SURFACES = ["register_cli_command", "register_hook", "register_hook", "register_hook",
                "register_middleware", "register_session_env",
                "register_terminal_environment_provider", "register_tool"]

    def test_off_registers_inert_surfaces_only(self):
        ctx = Ctx({})
        self.plugin.register(ctx)
        self.assertEqual(self.kinds(ctx), self.SURFACES)          # declared == registered (catalog validator)
        hooks = sorted(c[1][0] for c in ctx.calls if c[0] == "register_hook")
        self.assertEqual(hooks, ["post_llm_call", "pre_llm_call", "transform_tool_result"])
        mw = next(c for c in ctx.calls if c[0] == "register_middleware")
        self.assertEqual(mw[1][0], "tool_execution")

    def test_host_and_device_register_the_same_surfaces(self):
        for settings in ({"role": "host", "listen": "127.0.0.1:9130"}, {"role": "device", "name": "mac"}):
            ctx = Ctx(settings)
            self.plugin.register(ctx)
            self.assertEqual(self.kinds(ctx), self.SURFACES)
        provider = next(c[1][0] for c in ctx.calls if c[0] == "register_terminal_environment_provider")
        self.assertEqual(provider.name, "tether")
        self.assertFalse(provider.skip_container_guards)       # Hermes approvals stay on
        self.assertTrue(provider.is_remote)

    def _forget_passphrase(self):
        """What register() held and masked is dropped again (the dummy value must not outlive the test)."""
        sys.modules["hp_plugin_under_test.tether.identity"]._HELD.clear()
        try:
            from agent.redact import clear_vault_redaction_values
            clear_vault_redaction_values()
        except Exception:  # noqa: BLE001
            pass

    def test_register_takes_the_passphrase_out_of_the_environment_in_every_role(self):
        """register() is what removes the passphrase in every Hermes process (F95), whatever the role."""
        self.addCleanup(self._forget_passphrase)
        names = ("TETHER_KEY_PASSPHRASE", "HOMEPORT_KEY_PASSPHRASE")
        for settings in ({}, {"role": "host", "listen": "127.0.0.1:9130"}, {"role": "device", "name": "mac"}):
            for name in names:
                os.environ[name] = "dummy-passphrase-value-123"
            with mock.patch.object(self.plugin, "_in_gateway", return_value=False):
                self.plugin.register(Ctx(settings))
            for name in names:
                self.assertFalse(name in os.environ, f"still in the environment with {settings or 'no role'}")

    def test_a_bad_setting_does_not_leave_the_passphrase_in_the_environment(self):
        """A typo in a setting fails the plugin's load; the passphrase is already out by then (F74)."""
        self.addCleanup(self._forget_passphrase)
        for settings in ({"role": "device", "name": "mac", "grant_idle_minutes": "ten"},
                         {"role": "host", "listen": "127.0.0.1:91x0"}):
            os.environ["TETHER_KEY_PASSPHRASE"] = "dummy-passphrase-value-123"
            with mock.patch.object(self.plugin, "_in_gateway", return_value=False), self.assertRaises(ValueError):
                self.plugin.register(Ctx(settings))
            self.assertFalse("TETHER_KEY_PASSPHRASE" in os.environ, "still in the environment")

    def test_a_missing_hermes_function_is_named_at_role_start(self):
        """A Hermes that lacks a public seam tether relies on is said in the log (F81)."""
        import importlib
        real = importlib.import_module

        def without_review(name, *a, **k):
            if name == "tools.skill_provenance":
                raise ImportError(name)
            return real(name, *a, **k)

        with mock.patch.object(importlib, "import_module", without_review), \
                self.assertLogs(self.plugin.logger, level="WARNING") as logs:
            lost = self.plugin._check_hermes_surfaces()
        self.assertEqual(lost, ["a background review is recognised by its thread name only"])
        self.assertTrue(any("tools.skill_provenance.is_background_review" in line for line in logs.output))
        self.assertEqual(self.plugin._check_hermes_surfaces(), [])       # this Hermes has every seam
    def test_a_missing_hermes_attribute_seam_is_named(self):
        """Gauntlet 3.1 F1: seam G is an attribute, not a function; its absence is named too."""
        from tools.environments.base import BaseEnvironment
        with mock.patch.object(BaseEnvironment, "supports_session_kernel", None), \
                self.assertLogs(self.plugin.logger, level="WARNING") as logs:
            lost = self.plugin._check_hermes_surfaces()
        self.assertEqual(len(lost), 1)
        self.assertIn("execute_code is refused over tether", lost[0])
        self.assertTrue(any("BaseEnvironment.supports_session_kernel" in line for line in logs.output))

    def test_inert_in_hermes_plugin_host_process(self):
        """Gauntlet 3.1 lock F2: in Hermes's separate plugin host no session or turn crosses over; tether starts
        nothing there whatever its role."""
        started = []
        with mock.patch.dict(os.environ, {"HERMES_PLUGIN_HOST_PROCESS": "1"}), \
                mock.patch.object(self.plugin, "_start_services", lambda *a: started.append(a)), \
                self.assertLogs(self.plugin.logger, level="WARNING") as logs:
            self.plugin.register(Ctx({"role": "host"}))
        self.assertEqual(started, [])
        self.assertTrue(any("plugin host process" in line for line in logs.output))

    def test_register_records_whether_this_process_came_from_an_agents_shell(self):
        """F84: register() is where the process origin is recorded, before any shell of this process runs. In a
        Hermes started from an agent's shell (HERMES_SESSION_KEY in its environment) the answer is kept as True."""
        handle = sys.modules["tether_runtime_handle"]
        self.addCleanup(setattr, handle, "started_from_agent_shell", False)
        handle.started_from_agent_shell = None                  # this process has not decided yet
        with mock.patch.dict(os.environ, {"HERMES_SESSION_KEY": "agent:main:telegram:dm:1"}):
            self.plugin.register(Ctx({}))
        self.assertIs(handle.started_from_agent_shell, True)

    def test_source_never_names_the_computer_use_contract(self):
        # Hermes files any plugin whose source mentions it as kind "exclusive" (DESIGN.md, Packaging).
        for f in (ROOT / "plugin/tether").rglob("*.py"):
            text = f.read_text()
            for word in ("ComputerUseBackend", "register_computer_use_provider"):
                self.assertNotIn(word, text, f"{f.name} mentions {word}")


class GatewayDetectionTests(unittest.TestCase):
    """Hermes discovers plugins for `gateway run` on a background thread that can beat the gateway.run import."""

    def test_command_line_counts_before_gateway_run_is_imported(self):
        plugin = load_plugin()
        with mock.patch.dict(sys.modules):
            sys.modules.pop("gateway.run", None)
            for argv, expected in ((["main.py", "gateway", "run"], True),
                                   (["main.py", "--profile", "default", "gateway", "run", "--quiet"], True),
                                   (["main.py", "gateway", "restart"], False),
                                   (["main.py", "tether", "status"], False),
                                   (["main.py", "chat", "gateway"], False)):
                with mock.patch.object(sys, "argv", argv):
                    self.assertEqual(plugin._in_gateway(), expected, argv)


if __name__ == "__main__":
    unittest.main()
