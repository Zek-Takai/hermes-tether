"""register(ctx) per role, with a stand-in plugin context (no gateway, no network)."""
from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(1, str(Path.home() / ".hermes" / "hermes-agent"))


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
        self.plugin = load_plugin()
        self._home = os.environ.get("HERMES_HOME")
        os.environ["HERMES_HOME"] = tempfile.mkdtemp(prefix="hp-home-")     # never the real ~/.hermes
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

    SURFACES = ["register_cli_command", "register_hook", "register_hook", "register_hook", "register_middleware",
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
