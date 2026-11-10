"""tether: a remote Hermes agent with the local capabilities of paired desktop machines.

Inert until ``plugins.entries.tether.settings.role`` is set (design D7/D18): installing it opens no port and
dials nowhere. Every surface is registered in every role (so what the manifest declares is what registers) and
does nothing until a role is set: the devices tool and the terminal backend are unavailable, the middleware
passes calls through, the per-turn hook adds nothing.
- host: every Hermes process on the host reaches the link (one owner, the rest relay, hostlink.py); while a
  device is a session's target the session works ON that device (design D22, forward.py).
- device: the gateway process dials the host and runs its calls through this machine's own Hermes.
"""
from __future__ import annotations

import logging
import sys

logger = logging.getLogger(__name__)

PLUGIN_ID = "tether"


def _in_gateway() -> bool:
    """True in the gateway process. Hermes discovers plugins for `gateway run` on a background thread that can
    finish before gateway.run is imported (seen live on Windows), so the command line counts too."""
    if "gateway.run" in sys.modules:           # the same test Hermes uses for its own gateway process
        return True
    args = sys.argv[1:]
    return any(a == "gateway" and args[i + 1:i + 2] == ["run"] for i, a in enumerate(args))


def register(ctx) -> None:
    from .tether import cli, forward, tools
    from .tether.config import read_settings
    from .tether.provider import make_provider

    def get(key, default=None):
        try:
            return ctx.get_config(key, default)
        except Exception:  # noqa: BLE001 - inert on any doubt
            return default

    ctx.register_cli_command("tether", "Pair devices with this Hermes and check the link", cli.setup,
                             cli.main_for(get), description="tether: remote agent, local capabilities")
    ctx.register_tool("devices", "tether", tools.SCHEMA, tools.handler, check_fn=tools.check,
                      description=tools.SCHEMA["description"], emoji="🛰")
    ctx.register_terminal_environment_provider(make_provider())
    ctx.register_middleware("tool_execution", forward.tool_execution)
    ctx.register_hook("pre_llm_call", forward.turn_context)
    ctx.register_hook("post_llm_call", forward.turn_closed)
    ctx.register_hook("transform_tool_result", forward.skill_files)
    s = read_settings(get)
    if not s.roles:
        logger.debug("tether: role is off; surfaces registered but inert")
        return
    _start_services(s, ctx)   # host: every process gets the link (owner or relay); device: gateway only


def _start_services(s, ctx) -> None:
    from .tether.runtime import get_runtime, set_host_factory
    from .tether.store import HostPin, data_dir

    if "host" in s.roles:
        from .tether.config import identity
        from .tether.host import HostService
        from .tether.hostlink import HostLink

        def make_service():
            return HostService(identity(s), _pins(), s.listen_host, s.listen_port, label=f"Hermes on {s.name}")

        def _pins():
            from .tether.store import DevicePins
            return DevicePins(data_dir())

        set_host_factory(lambda: HostLink(data_dir(), make_service))
        rt = get_runtime()                         # every host process: tether_screen finds it via the handle
        if _in_gateway():                          # claim the link at boot so devices connect before any call
            rt.submit(rt.host.ensure())
            logger.info("tether: host role on %s:%s", s.listen_host, s.listen_port)
    if "device" in s.roles and _in_gateway():
        rt = get_runtime()
        if rt.device is not None:
            return
        from .tether.config import identity
        from .tether.consent import ConsentGate
        from .tether.device import DeviceService
        from .tether.device_exec import LocalExec, SessionControl, ToolRunner, capabilities
        from .tether.device_screen import ScreenExec
        from .tether.workspace import Workspaces
        gate = ConsentGate(idle_minutes=s.grant_idle_minutes, timeout_s=s.consent_timeout_seconds)
        gate.events_dir = data_dir()
        rt.consent = gate
        screen = ScreenExec(gate)
        workspaces = Workspaces(data_dir() / "sessions")
        removed = workspaces.wipe_all()               # anything left by a crash or a hard stop goes now
        if removed:
            logger.info("tether: removed %d leftover session workspace(s)", removed)
        local_exec = LocalExec(workspaces)
        pin = HostPin(data_dir())
        control = SessionControl(gate, workspaces, local_exec, lambda: (pin.get() or {}).get("fp", ""))

        def device_capabilities():
            caps = capabilities()
            caps["rules"] = {**caps.get("rules", {}), "grant_idle_minutes": gate.idle_s / 60,
                             "workspace_root": str(workspaces.root)}
            return {**caps, "computer_use": screen.available()}

        rt.device = DeviceService(identity(s), pin, gate, s.name,
                                  {"exec": local_exec.exec, "cu": screen.call, "tool": ToolRunner(ctx, local_exec, workspaces).run,
                                   "close_session": control.close_session, "skill_put": control.skill_put},
                                  device_capabilities)
        rt.device.workspaces = workspaces
        rt.loop.call_soon_threadsafe(rt.device.start)
        logger.info("tether: device role as %s", s.name)
