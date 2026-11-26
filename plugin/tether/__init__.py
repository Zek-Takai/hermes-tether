"""tether: a remote Hermes agent with the local capabilities of paired desktop machines.

Inert until ``plugins.entries.tether.settings.role`` is set (design D7/D18): installing it opens no port and
dials nowhere. Whatever the role, it first takes the key passphrase out of the process environment (D40).
Every surface is registered in every role (so what the manifest declares is what registers) and does nothing
until a role is set: the devices tool and the terminal backend are unavailable, the middleware passes calls
through (after taking the passphrase out of the environment again), the per-turn hook adds nothing.
- host: every Hermes process on the host reaches the link (one owner, the rest relay, hostlink.py); while a
  device is a session's target the session works ON that device (design D22, forward.py).
- device: the gateway process dials the host and runs its calls through this machine's own Hermes.
"""
from __future__ import annotations

import logging
import os
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

    from .tether.device_exec import set_plugin_context
    set_plugin_context(ctx)             # lent file tools run through ctx.run_tool_call (device role)
    forward.record_process_origin()     # before any shell of this process runs: was it started from an agent's shell?
    # First, whatever the role and before any setting is parsed (a typo there must not leave the passphrase in
    # this process's environment, F74): every Hermes process the plugin loads in.
    _protect_passphrase(ctx)
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
    if os.environ.get("HERMES_PLUGIN_HOST_PROCESS") == "1":
        # Hermes's separate plugin host (plugins.isolation: host): no session, turn or sender crosses into it, so
        # tether could not tell one session or one sender from another. It stays inert there (gauntlet 3.1 lock F2).
        logger.warning("tether: loaded in Hermes's plugin host process, where sessions cannot be told apart; it "
                       "stays off here. Run it in-process (plugins.isolation: in_process).")
        return
    _check_hermes_surfaces()
    _start_services(s, ctx)   # host: every process gets the link (owner or relay); device: gateway only


# Public Hermes seams tether relies on (F81): (module, name, what happens without it). Every protection fails closed
# without its seam (the call or command is refused); the warning says why.
_HERMES_SURFACES = (
    ("hermes_cli.middleware", "authorize_tool_call",
     "file tools meant for a device are refused (Hermes's checks of the call cannot run here)"),
    ("tools.patch_parser", "patch_file_paths", "V4A patches meant for a device are refused"),
    ("agent.terminal_env_provider", "current_command_context", "the tether terminal backend refuses every command"),
    ("tools.environments.base", "BaseEnvironment.supports_session_kernel",
     "execute_code is refused over tether (its persistent kernel cannot be kept off a tethered machine)"),
    ("tools.approval", "check_dangerous_command",
     "a command a device's rules flag cannot be put to the person here, so it does not run"),
    ("tools.approval_judge", "judge_command", "this device refuses every command from its host"),
    ("tools.interrupt", "InterruptScope", "this device refuses remote work (a stop could not reach it)"),
    ("tools.interrupt", "is_interrupted", "this device refuses remote work (a stop could not reach it)"),
    ("tools.environments.local", "LocalEnvironment.wrap_argv",
     "this Mac refuses remote commands (the session lock cannot be applied)"),
    ("agent.redact_vault_values", "register_plugin_redaction_value",
     "the key passphrase will not be masked in Hermes's own tool output"),
    ("tools.skill_provenance", "is_background_review",
     "a background review is recognised by its thread name only"),
    ("hermes_cli.plugin_session", "in_delegated_child",
     "a delegated child process is recognised by its platform and environment only"),
    ("hermes_cli.plugin_session", "turn_event",
     "a forwarded or bot-written gateway message is recognised by its text only"),
)


def _check_hermes_surfaces() -> list:
    """At role start: log, once per lost protection, each public Hermes seam tether relies on that this Hermes lacks
    (an older Hermes). Returns what is lost (tests)."""
    import importlib
    lost: list = []
    for module, name, effect in _HERMES_SURFACES:
        try:
            found = importlib.import_module(module)
            for part in name.split("."):
                found = getattr(found, part, None)
            ok = callable(found) if "." not in name else found is not None   # Class.attr: the attribute exists
        except Exception:  # noqa: BLE001
            ok = False
        if not ok and effect not in lost:
            lost.append(effect)
            logger.warning("tether: this Hermes lacks %s.%s, so %s", module, name, effect)
    return lost


def _protect_passphrase(ctx) -> None:
    """Take the key passphrase out of this process's environment (identity.protect_passphrase). Every Hermes process
    the plugin loads in runs this, whatever its role, not only the one that loads the key."""
    try:
        from .tether.identity import LEGACY_PASSPHRASE_SECRETS, PASSPHRASE_SECRET, HermesSecretStore, protect_passphrase
        protect_passphrase(HermesSecretStore())
    except Exception:  # noqa: BLE001 - logged inside protect_passphrase; the link itself still starts
        logger.warning("tether: passphrase protection not applied in this process")
        return
    names = [PASSPHRASE_SECRET, *LEGACY_PASSPHRASE_SECRETS]
    # Declared as session env so Hermes never bakes the names into a terminal's shell snapshot. The None value does
    # NOT unset them in a child on Hermes 0.23.3: Hermes drops a session-env value for any name a terminal provider
    # lists in strip_env_keys (provider.py), and those lists must stay for background children (DESIGN 5.1).
    try:
        ctx.register_session_env(names, lambda _session: {name: None for name in names})
    except Exception:  # noqa: BLE001 - another plugin holds the names
        logger.debug("tether: session env names not registered")


def _start_services(s, ctx) -> None:
    from .tether.runtime import get_runtime, set_host_factory
    from .tether.store import HostPin, data_dir

    if "host" in s.roles and os.name == "nt":
        logger.warning("tether: the host role needs macOS or Linux (Windows runs the device role only); "
                       "host not started")
    elif "host" in s.roles:
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
        from .tether.lock import set_unlocked
        from .tether.store import read_panel_settings
        from .tether.workspace import Workspaces
        from .tether.authcode import SETUP_COMMAND, CodeChecker
        from .tether.seedstore import NONE, SeedStore
        # D73: allow_unlocked_commands (the panel's choice wins over config.yaml; unset: on for Windows, off for
        # macOS). Off on macOS: every session command runs inside the session lock. Off on Windows: none runs.
        set_unlocked(read_panel_settings(data_dir()).get("allow_unlocked_commands", s.allow_unlocked_commands))
        # D63, D66, D68: the approval box checks codes from the person's authenticator app against the seed, opened
        # now from its sealed file in this data folder (sealed with Tether's key passphrase, the secret that unlocks
        # identity.key.enc) and then held in memory; each code step is recorded as used in a state file sealed with
        # a key derived from the seed, so it is never accepted twice. No authenticator: every session is refused
        # before any box (no fallback). No prompt, keychain or administrator dialog of any kind (D66).
        seeds = SeedStore(data_dir(), publish=True, secret=lambda: identity(s).passphrase)
        gate = ConsentGate(idle_minutes=s.grant_idle_minutes, timeout_s=s.consent_timeout_seconds,
                           codes=CodeChecker(seeds, data_dir(), narrow=True))
        if seeds.status() == NONE:
            logger.warning("tether: remote use of this device is off until its authenticator is set up: run `%s` in "
                           "a terminal on this machine", SETUP_COMMAND)
        gate.events_dir = data_dir()
        rt.consent = gate
        try:
            workspaces = Workspaces(data_dir() / "sessions")
        except Exception as e:  # noqa: BLE001 - not Tether's own folder (a link in its place): no session work here
            logger.error("tether: the device role did not start: %s", e)
            return
        removed = workspaces.wipe_all()               # anything left by a crash or a hard stop goes now (never raises)
        if removed:
            logger.info("tether: removed %d leftover session workspace(s)", removed)
        local_exec = LocalExec(workspaces, record_dir=data_dir())
        local_exec.reap_recorded()                    # background jobs left running by an earlier process
        screen = ScreenExec(gate, local_exec)         # screen actions join their session's stop handles
        gate.screen_drain = screen.drain              # the box opens only once no screen action is running (D65)
        pin = HostPin(data_dir())
        control = SessionControl(gate, workspaces, local_exec, lambda: (pin.get() or {}).get("fp", ""))

        def device_capabilities():
            caps = capabilities()
            # consent_wait_seconds: the host's opening call waits this long plus start-up for the person here
            caps["rules"] = {**caps.get("rules", {}), "grant_idle_minutes": gate.idle_s / 60,
                             "consent_wait_seconds": gate.timeout_s, "workspace_root": str(workspaces.root)}
            return {**caps, "computer_use": screen.available()}

        rt.device = DeviceService(identity(s), pin, gate, s.name,
                                  {"exec": local_exec.exec, "cu": screen.call, "tool": ToolRunner(ctx, local_exec, workspaces).run,
                                   "close_session": control.close_session, "skill_put": control.skill_put},
                                  device_capabilities)
        rt.device.workspaces = workspaces
        rt.device.seeds = seeds
        seeds.refresh()        # reads the record again whenever another process (the setup command) changed it
        rt.device.job_sweep = local_exec.sweep_jobs           # ends sessions whose grant ended (D39)
        rt.device.busy_sessions = local_exec.busy_sessions    # ...but never one with a call in flight
        rt.loop.call_soon_threadsafe(rt.device.start)
        logger.info("tether: device role as %s", s.name)
