"""`hermes tether ...`: pair (host), join (device), status, unpair, pause/resume and authenticator (device)."""
from __future__ import annotations

import argparse
import asyncio
import getpass
import sys
import time

from . import pairing
from .config import Settings, identity
from .machine import clean_os, clean_version
from .store import RESERVED_LABELS, DevicePins, HostPin, data_dir

PAUSE_FILE = "paused"


def key_text(fp: str) -> str:
    """A certificate's key as both sides show it (host prompt and device line), so the owner can compare."""
    return f"{fp[:16]}…"


def pair_prompt(name: str, details: dict) -> str:
    """The owner's question. The key comes first, on its own line; the device's words are only checked facts."""
    os_name, hermes = clean_os(details.get("os")), clean_version(details.get("hermes"))
    return (f"\nDevice '{name}' wants to pair: key {key_text(details['fp'])}\n"
            f"  reported by the device: os {os_name}, Hermes {hermes}")


def device_key_line(fp: str) -> str:
    return (f"This device's key is {key_text(fp)}. The host shows the same key before its owner answers; "
            "if it shows a different one, answer N there.")


def pair_instructions(link: str) -> str:
    # The link is a secret for 10 minutes: pasted at a prompt it stays out of argv (ps) and shell history.
    return ("One-time pairing link (valid 10 minutes, one device). On the device run:\n\n"
            "  hermes tether join\n\n"
            "and paste this link at its prompt (it is not shown while you paste):\n\n"
            f"  {link}\n\n"
            "Carry it yourself (paste, AirDrop, type). Do not give it to an agent or post it anywhere.\n"
            "Waiting for the device…")


def _ask_link() -> str:
    stdin = sys.stdin
    if stdin is not None and not stdin.isatty():
        # a piped link (pbpaste | hermes tether join): getpass would read the terminal and ignore the pipe
        return stdin.readline().strip()
    print("Paste the tether:// link (it is not shown while you paste).")
    try:
        return getpass.getpass("link: ").strip()
    except Exception:  # noqa: BLE001  - no usable terminal for getpass: plain input
        return input("Paste the tether:// link: ").strip()


def setup(parser: argparse.ArgumentParser) -> None:
    sub = parser.add_subparsers(dest="tether_cmd")
    p = sub.add_parser("pair", help="host: make a one-time link for a new device and wait for it")
    p.add_argument("device", help="name for the device (e.g. mac)")
    p.add_argument("--advertise", default="", help="address the device dials (default: the listen address)")
    j = sub.add_parser("join", help="device: pair with a host using the link `pair` printed there")
    j.add_argument("link", nargs="?", default="",
                   help="tether://... (omit and paste it at the prompt; an argument is visible to other programs)")
    u = sub.add_parser("unpair", help="host: forget a device; device: forget the host")
    u.add_argument("device", nargs="?", default="")
    sub.add_parser("status", help="show pairing state")
    sub.add_parser("pause", help="device: refuse all remote use now (ends every session grant)")
    sub.add_parser("resume", help="device: allow remote use again (each session still asks)")
    a = sub.add_parser("authenticator", help="device: set up, replace or remove the authenticator every remote "
                                             "session needs (run it yourself at this machine)")
    a_sub = a.add_subparsers(dest="auth_cmd")
    a_sub.add_parser("setup", help="turn the authenticator on, or replace it (boxes on this screen)")
    e = a_sub.add_parser("export", help="make a one-time transfer file so another machine can use this authenticator")
    e.add_argument("folder", nargs="?", default="",
                   help="folder to write tether-authenticator.transfer in (default: your Downloads folder)")
    j = a_sub.add_parser("join", help="join this machine with a transfer file from another machine")
    j.add_argument("file", help="the tether-authenticator.transfer file from the other machine")
    a_sub.add_parser("remove", help="turn it off; remote use is then refused")
    a_sub.add_parser("recovery-codes", help="make new recovery codes; the old ones stop working")
    a_sub.add_parser("unlock", help="take codes again after too many wrong ones (with a recovery code)")


def run(args: argparse.Namespace, s: Settings) -> int:
    cmd = getattr(args, "tether_cmd", None)
    d = data_dir()
    if cmd == "pair":
        return _pair(args, s)
    if cmd == "join":
        return _join(args, s)
    if cmd == "unpair":
        if "host" in s.roles and args.device:
            name = args.device.strip().lower()          # stored as `pair` stores it (F67)
            ok = DevicePins(d).remove(name)
            print(f"unpaired {name}" if ok else f"no paired device named {name}")
            return 0 if ok else 1
        if "device" in s.roles:
            print("forgot the host" if HostPin(d).clear() else "not paired with a host")
            return 0
        print("usage: hermes tether unpair <device> (host)  |  hermes tether unpair (device)")
        return 2
    if cmd == "authenticator":
        return _authenticator(args, s)
    if cmd in ("pause", "resume"):
        flag = d / PAUSE_FILE
        flag.touch() if cmd == "pause" else flag.unlink(missing_ok=True)
        print("remote use paused on this device" if cmd == "pause" else "remote use allowed again")
        return 0
    return _status(s)


def _status(s: Settings) -> int:
    d = data_dir()
    print(f"tether roles: {', '.join(sorted(s.roles)) or 'off'}   this machine: {s.name}")
    if "host" in s.roles:
        print(f"listening on {s.listen_host}:{s.listen_port}")
        pins = DevicePins(d).all()
        live = _live_rows()
        for name, rec in sorted(pins.items()):
            row = live.get(name) if isinstance(live, dict) else None
            state = ("online, " + row["link"].get("suite", "")) if row and row["online"] else \
                ("offline" if isinstance(live, dict) else live)
            print(f"  device {name:<12} fp {key_text(rec['fp'])}  {state}")
        if not pins:
            print("  no paired devices (hermes tether pair <name>)")
    if "device" in s.roles:
        rec = HostPin(d).get()
        print(f"  host {rec.get('host_label') or rec['host']} at {rec['host']}:{rec['port']}" if rec
              else "  not paired (hermes tether join)")
        if (d / PAUSE_FILE).exists():
            print("  remote use is PAUSED (hermes tether resume)")
        print(f"  {authenticator_line(d)}")
    return 0


def authenticator_line(d) -> str:
    """The device's authenticator as the person reads it (D63, D66-D68). Reads no secret: the record file's outside,
    what the running Hermes last published, and the code state's counters (display only)."""
    from . import authcode, enroll, seedstore
    if enroll.busy(d):
        return "authenticator: a setup is running now (remote use is paused until it ends)"
    pointer = seedstore.pointer_state(d)
    if pointer == seedstore.NONE:
        return seedstore.STATUS_TEXT[seedstore.NONE]
    if pointer == seedstore.MISSING:
        return seedstore.STATUS_TEXT[seedstore.MISSING]
    published = seedstore.read_published(d) or {}
    status = published.get("status")
    if status is None:
        return "authenticator: set up; its state is unknown (is this device's Hermes running?)"
    if status != seedstore.READY:
        return seedstore.STATUS_TEXT[status]
    left = published.get("recovery_left")
    line = "authenticator: on" + (f" (recovery codes left: {left})" if isinstance(left, int) else "")
    held = authcode.peek_state(d) or {}
    if held.get("locked"):
        return (f"{line}; code entry is LOCKED after too many wrong codes (or a changed state file), so remote use is "
                f"refused; unlock it here with `{authcode.UNLOCK_COMMAND}`")
    paused = held.get("paused_until", 0) - time.time()
    if paused > 0:
        return f"{line}; code entry is paused after several wrong codes (about {max(1, round(paused / 60))} min left)"
    return line + "; each new remote session asks for a code from your app in a box on this screen"


def _authenticator(args: argparse.Namespace, s: Settings) -> int:
    """Set up, replace or remove this device's authenticator, make new recovery codes or unlock code entry (D67);
    Takes no secret from argv or stdin and prints none: every answer goes into a box on this screen."""
    from . import enroll, seedstore
    if "device" not in s.roles:
        print("this machine is not a tether device (set plugins.entries.tether.settings.role: device)")
        return 2
    command = getattr(args, "auth_cmd", None)
    d = data_dir()
    if not command:
        print(authenticator_line(d))
        print("usage: hermes tether authenticator setup | export [folder] | join <file> | remove | recovery-codes | "
              "unlock")
        return 0
    arg = getattr(args, "folder", "") or getattr(args, "file", "")
    why = enroll.refuse_reason()
    if why:
        print(why)
        return 2
    try:
        me = identity(s)        # the record is sealed with Tether's key passphrase (D66): the same as join uses
    except Exception as e:  # noqa: BLE001 - an incomplete identity says how to fix it, never a value
        print(f"Stopped: {e}. Nothing changed.")
        return 1
    store = seedstore.SeedStore(d, secret=lambda: me.passphrase)
    if not store.backend.available():
        print("This machine has no usable secret store for the authenticator key, so it cannot be set up here; "
              "remote use stays off.")
        return 2
    print("Follow the boxes on this screen. Remote use of this machine is paused until this ends.")
    try:
        result = asyncio.run(enroll.run(command, d, s.name, store, enroll.default_ui(s.name), arg))
    except enroll.EnrollError as e:
        print(f"Stopped: {e}. Nothing changed.")
        return 1
    except KeyboardInterrupt:
        print(f"\n{enroll.CANCELLED}")
        return 1
    print(result.message)
    return 0 if result.ok else 1


def _live_rows():
    """Ask this host's link owner (usually the gateway) through the relay; never take the link from here."""
    try:
        from .runtime import get_runtime
        rt = get_runtime()
        if rt.host is None:
            return "link state unknown"
        return {r["name"]: r for r in rt.run(rt.host.list_devices(may_own=False), 10)}
    except Exception:  # noqa: BLE001
        return "link not running (is the gateway up?)"


def _pair(args: argparse.Namespace, s: Settings) -> int:
    if "host" not in s.roles:
        print("this machine is not a tether host (set plugins.entries.tether.settings.role: host)")
        return 2
    from .host import HostService
    name = args.device.strip().lower()
    if name in RESERVED_LABELS:          # 'local' means this host to the devices tool; the panel refuses these too
        print(f"{name!r} is reserved; pair the device under another name (and set that name on the device)")
        return 2
    advertise = args.advertise or s.listen_host
    if advertise in ("0.0.0.0", "::", ""):
        print("listen is a wildcard address; pass --advertise <address the device can reach>")
        return 2
    svc = HostService(identity(s), DevicePins(data_dir()), s.listen_host, s.listen_port, label=f"Hermes on {s.name}")

    async def confirm(name: str, details: dict) -> bool:
        print(pair_prompt(name, details))
        answer = await asyncio.to_thread(input, "Pair it? [y/N] ")
        return answer.strip().lower() in ("y", "yes")

    def show(link: str) -> None:
        print(pair_instructions(link))

    try:
        res = asyncio.run(svc.pair(name, advertise, s.pairing_port, confirm, show))
    except (pairing.PairingError, OSError) as e:
        print(f"pairing failed: {e}")
        return 1
    except KeyboardInterrupt:
        print("\npairing cancelled; the link is dead")
        return 1
    print(f"paired {res['name']}. The running gateway picks it up within a few seconds.")
    return 0


def _join(args: argparse.Namespace, s: Settings) -> int:
    if "device" not in s.roles:
        print("this machine is not a tether device (set plugins.entries.tether.settings.role: device)")
        return 2
    from . import enroll
    from .consent import ConsentGate
    from .device import DeviceService
    if enroll.in_remote_shell():         # D67: a remote session must not re-pair this device to a host of its choice
        print(enroll.JOIN_REMOTE_TEXT)
        return 2
    if args.link:
        print("A link on the command line is visible to other programs on this machine and saved in shell "
              "history. Next time run `hermes tether join` and paste the link at the prompt.")
    link = args.link or _ask_link()
    ident = identity(s)
    svc = DeviceService(ident, HostPin(data_dir()), ConsentGate(), s.name, {}, dict)
    print(device_key_line(ident.fp))
    print("Contacting the host; its owner confirms there…")
    try:
        res = asyncio.run(svc.join(link))
    except (pairing.PairingError, OSError, ValueError) as e:
        print(f"joining failed: {e}")
        return 1
    who = res['host_label'] or res['host']
    from .seedstore import NONE, MISSING, pointer_state
    if pointer_state(data_dir()) not in (NONE, MISSING):
        print(f"paired with {who}. The running Hermes connects within a few seconds; each new remote session asks "
              "for a code from your authenticator app in a box on this screen.")
    else:
        print(f"paired with {who}. Remote use stays off until you set up the authenticator on this machine: run "
              f"`hermes tether authenticator setup` here, with your phone at hand. It takes about two minutes.")
    return 0


def main_for(get_config) -> callable:
    def handler(args):
        from .config import read_settings
        sys.exit(run(args, read_settings(get_config)))
    return handler
