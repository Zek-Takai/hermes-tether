"""The `devices` tool (host): list paired devices, choose where this session's terminal and screen go."""
from __future__ import annotations

import json
import re
import time
from typing import Any

from .machine import describe
from .runtime import explain, get_runtime

CONSENT_WAIT_S = 90.0     # covers the device's consent timeout (15 s default) plus prompt start-up

# "untether" closes only as a message of its own (case and a trailing . or ! are free); in a sentence it does nothing.
_UNTETHER_SOLO = re.compile(r"\s*untether\s*[.!]?\s*", re.I)
UNTETHER_HINT = "send 'untether' as a message on its own; it does nothing inside a longer message"


def names_device(text: str, name: str) -> bool:
    """True when the user's words name this device ("tether mac", "tether studio pc" for a device paired as studio-pc)."""
    words = [re.escape(w) for w in re.split(r"[\s_-]+", name.strip()) if w]
    if not words:
        return False
    pattern = r"[\s_-]+".join(words)
    return bool(re.search(rf"(?<![A-Za-z0-9_-]){pattern}(?![A-Za-z0-9_-])", text or "", re.I))


def asked_to_open(text: str, name: str) -> bool:
    """True only when the user wrote the phrase 'tether <device>' ("tether mac", "Tether studio-pc"). Naming the device
    alone ("open Bambu Studio on the mac") never opens a connection, so ordinary talk cannot trigger one."""
    words = [re.escape(w) for w in re.split(r"[\s_-]+", name.strip()) if w]
    if not words:
        return False
    pattern = r"[\s_-]+".join(words)
    return bool(re.search(rf"(?<![A-Za-z0-9_-])tether[\s_-]+{pattern}(?![A-Za-z0-9_-])", text or "", re.I))


def asked_to_close(text: str, device: str = "") -> bool:
    """True only when the user's whole message is the word 'untether'. "untether mac", "ok untether" or "thanks,
    untether" do not close; the agent then tells the user to send 'untether' on its own."""
    return bool(_UNTETHER_SOLO.fullmatch(text or ""))

SCHEMA = {
    "name": "devices",
    "description": (
        "Paired desktop machines reachable over tether. Only the user opens or closes a device connection. "
        "Call action=use device=<name> ONLY when the user's own message contains the words 'tether <name>' "
        "(for example 'tether mac', 'tether studio pc'). If the user asks for work on a device without saying "
        "'tether <name>' (for example 'open Bambu Studio on the mac'), do not call use and do not try another "
        "way: refuse and tell them to say 'tether <name>'. Call action=close ONLY when the user's whole "
        "message is 'untether'. If they ask to close it any other way (or put 'untether' inside a longer "
        "message), do not call close: tell them to send 'untether' as a message on its own. action=list shows each device (online, or offline "
        "since when; what it offers) and which one this session's terminal, file and computer-use tools act on. "
        "action=use with device=<name> sends this session's terminal/file/computer-use tools to that machine; "
        "device=local sends them back to this host. action=use waits until the person at that machine clicks "
        "Allow on its own screen; only when it returns active are you connected, so never say you are "
        "connected before that. If it returns an error, you are not connected. While a device is active, THAT device's own Hermes rules and "
        "permissions apply (its file read/write rules, its write fence, its approvals), not this host's; a refusal "
        "from the device is final, so report it and never route around it through the terminal or another tool. "
        "If any call reports a tether problem (offline, not allowed, link down), tell the user and stop: do not "
        "retry, work around it or investigate."),
    "parameters": {
        "type": "object",
        "properties": {
            "action": {"type": "string", "enum": ["list", "use", "close"]},
            "device": {"type": "string", "description": "device name from list, or 'local' (action=use)"},
        },
        "required": ["action"],
    },
}


def check() -> bool:
    """Shown only where this Hermes runs the host role (every such process reaches the link, hostlink.py)."""
    rt = get_runtime(create=False)
    return bool(rt is not None and rt.host is not None)


def handler(args: dict[str, Any], **kwargs: Any) -> str:
    try:
        rt = get_runtime()
        if rt.host is None:
            return json.dumps({"error": explain(ConnectionError("the tether plugin is not set up as a host "
                                                                "on this machine"))})
        session = rt.current_session()
        rows = rt.run(rt.host.list_devices(), 20)
        names = {r["name"] for r in rows}
        action = args.get("action")
        text = rt.turn_text.get(session, "")
        current = rt.active_target(session)
        if action == "close" or (action == "use" and str(args.get("device") or "").strip().lower() == "local"):
            if current == "local":
                return json.dumps({"active": "local", "rules": "this host's own Hermes rules apply"})
            if not asked_to_close(text, current):
                return json.dumps({"error": f"Not closed: only the user can close the {current} connection, and only "
                                            f"by sending 'untether' as a message on its own (nothing else in "
                                            f"the message). Tell the user that. Keep working on {current}."})
            rt.close_device(session, "closed by the user")
            rt.closed_note.pop(session, None)
            return json.dumps({"active": "local", "rules": f"the {current} connection is closed; this host's own "
                                                         "Hermes rules apply again"})
        if action == "use":
            name = str(args.get("device") or "").strip().lower()
            if name not in names:
                return json.dumps({"error": f"no paired device named {name!r}", "devices": sorted(names)})
            if name != current and not asked_to_open(text, name):
                return json.dumps({"error": f"Not opened: a connection to {name} opens only when the user's own "
                                            f"message says 'tether {name}'. Do not do this task on {name} any "
                                            f"other way; tell the user to say 'tether {name}' if they want it."})
            if name != current and not any(r["name"] == name and r["online"] for r in rows):
                return json.dumps({"error": f"Not connected: {name} is offline right now (its Hermes is not "
                                            "running or not linked). Tell the user; do not retry."})
            if name != current:
                # Ask the device for consent now, before reporting the connection: a harmless guarded
                # call makes the device show its Allow prompt and blocks until the person answers.
                try:
                    rt.run(rt.host.call(name, "exec", {"command": "true", "session": session, "timeout": 10},
                                        b"", CONSENT_WAIT_S), CONSENT_WAIT_S + 15)
                except Exception as e:  # noqa: BLE001 - denied, timed out or link down: not connected
                    return json.dumps({"error": "Not connected. " + explain(e, name)})
            facts = next((r.get("capabilities") for r in rows if r["name"] == name), None)
            rt.learn_rules(name, facts)
            rt.open_device(session, name)
            out: dict[str, Any] = {"active": name, "rules": (
                f"{name}'s own Hermes rules and permissions now apply to this session's terminal, file and "
                "computer-use calls; this host's file rules do not. Stay on it for the whole task. If the device "
                "refuses something, report it to the user; do not work around it with another tool.")}
            about = describe(facts or {})
            if about:
                out["machine"] = about
            return json.dumps(out)
        for row in rows:
            seen = row.pop("last_seen", None)
            if not row["online"] and seen:
                row["offline_since"] = time.strftime("%Y-%m-%d %H:%M", time.localtime(seen))
        return json.dumps({"active": rt.active_target(session), "devices": rows})
    except Exception as e:  # noqa: BLE001 - tool handlers never raise
        return json.dumps({"error": explain(e)})
