"""`hermes tether ...`: pair (host), join (device), status, unpair, pause/resume (device)."""
from __future__ import annotations

import argparse
import asyncio
import sys

from . import pairing
from .config import Settings, identity
from .store import DevicePins, HostPin, data_dir

PAUSE_FILE = "paused"


def setup(parser: argparse.ArgumentParser) -> None:
    sub = parser.add_subparsers(dest="tether_cmd")
    p = sub.add_parser("pair", help="host: make a one-time link for a new device and wait for it")
    p.add_argument("device", help="name for the device (e.g. mac)")
    p.add_argument("--advertise", default="", help="address the device dials (default: the listen address)")
    j = sub.add_parser("join", help="device: pair with a host using the link `pair` printed there")
    j.add_argument("link", nargs="?", default="", help="tether://... (omit to paste it at a prompt)")
    u = sub.add_parser("unpair", help="host: forget a device; device: forget the host")
    u.add_argument("device", nargs="?", default="")
    sub.add_parser("status", help="show pairing state")
    sub.add_parser("pause", help="device: refuse all remote use now (ends every session grant)")
    sub.add_parser("resume", help="device: allow remote use again (each session still asks)")


def run(args: argparse.Namespace, s: Settings) -> int:
    cmd = getattr(args, "tether_cmd", None)
    d = data_dir()
    if cmd == "pair":
        return _pair(args, s)
    if cmd == "join":
        return _join(args, s)
    if cmd == "unpair":
        if "host" in s.roles and args.device:
            ok = DevicePins(d).remove(args.device)
            print(f"unpaired {args.device}" if ok else f"no paired device named {args.device}")
            return 0 if ok else 1
        if "device" in s.roles:
            print("forgot the host" if HostPin(d).clear() else "not paired with a host")
            return 0
        print("usage: hermes tether unpair <device> (host)  |  hermes tether unpair (device)")
        return 2
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
            print(f"  device {name:<12} fp {rec['fp'][:16]}…  {state}")
        if not pins:
            print("  no paired devices (hermes tether pair <name>)")
    if "device" in s.roles:
        rec = HostPin(d).get()
        print(f"  host {rec.get('host_label') or rec['host']} at {rec['host']}:{rec['port']}" if rec
              else "  not paired (hermes tether join <link>)")
        if (d / PAUSE_FILE).exists():
            print("  remote use is PAUSED (hermes tether resume)")
    return 0


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
    advertise = args.advertise or s.listen_host
    if advertise in ("0.0.0.0", "::", ""):
        print("listen is a wildcard address; pass --advertise <address the device can reach>")
        return 2
    svc = HostService(identity(s), DevicePins(data_dir()), s.listen_host, s.listen_port, label=f"Hermes on {s.name}")

    async def confirm(name: str, details: dict) -> bool:
        print(f"\nDevice '{name}' wants to pair: {details['os']}, Hermes {details['hermes']}, "
              f"key {details['fp'][:16]}…")
        answer = await asyncio.to_thread(input, "Pair it? [y/N] ")
        return answer.strip().lower() in ("y", "yes")

    def show(link: str) -> None:
        print("One-time pairing link (valid 10 minutes, one device). On the device run:\n")
        print(f"  hermes tether join '{link}'\n")
        print("Carry it yourself (paste, AirDrop, type). Do not give it to an agent or post it anywhere.")
        print("Waiting for the device…")

    try:
        res = asyncio.run(svc.pair(args.device.lower(), advertise, s.pairing_port, confirm, show))
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
    from .consent import ConsentGate
    from .device import DeviceService
    link = args.link or input("Paste the tether:// link: ").strip()
    svc = DeviceService(identity(s), HostPin(data_dir()), ConsentGate(), s.name, {}, dict)
    print("Contacting the host; its owner confirms there…")
    try:
        res = asyncio.run(svc.join(link))
    except (pairing.PairingError, OSError, ValueError) as e:
        print(f"joining failed: {e}")
        return 1
    print(f"paired with {res['host_label'] or res['host']}. The running Hermes connects within a few seconds;"
          " the first remote use of each session asks you on this screen.")
    return 0


def main_for(get_config) -> callable:
    def handler(args):
        from .config import read_settings
        sys.exit(run(args, read_settings(get_config)))
    return handler
