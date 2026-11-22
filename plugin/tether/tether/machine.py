"""What a machine says about itself when it connects, and what the agent is told from it.

The device sends plain facts (OS, version, the shell its Hermes runs commands with). The host turns them into
guidance from the fixed table below: the model is told an OS, shell and architecture from fixed lists and version
numbers, never a device's own words. Hermes runs terminal commands with bash on every OS; on Windows that bash is
Git Bash (MSYS).
"""
from __future__ import annotations

import platform
import re
import sys
from typing import Any, Optional


def _os_version(system: str) -> str:
    """The OS version as people name it. On Windows platform.release() says 10 on Windows 11 too (Python 3.11);
    Windows 11 is build 22000 or later, the same rule as Hermes's own prompt builder."""
    if system == "Windows":
        try:
            return "11" if sys.getwindowsversion().build >= 22000 else "10"  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001
            return platform.release()
    return platform.mac_ver()[0] or platform.release()


def local_facts() -> dict[str, Any]:
    """This machine's own facts, sent in the pairing hello and in every announce. Never its computer name."""
    try:
        from hermes_cli import __version__ as hv  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        hv = "?"
    system = platform.system()
    return {"os": system, "os_version": _os_version(system),
            "machine": platform.machine(), "hermes": hv,
            "shell": "git-bash" if system == "Windows" else "bash"}


_SHELL = {
    "git-bash": ("Its terminal is Git Bash (MSYS), not cmd or PowerShell: write bash (ls, grep, sleep 2, "
                 "/dev/null; '> nul' makes a real file named nul). Git Bash rewrites arguments that start with / "
                 "as paths, so run Windows tools with switches as MSYS_NO_PATHCONV=1 tasklist /fi \"...\" or "
                 "inside powershell -NoProfile -Command \"...\". Start an app with powershell -NoProfile -Command "
                 "\"Start-Process '<name or full path>'\"."),
    "bash": "Its terminal is bash.",
}

_OS = {
    "Darwin": "macOS tools are BSD flavoured (sed -i '', no GNU-only flags); start an app with open -a \"<App>\".",
    "Linux": "Tools are GNU; start an app with its own command or xdg-open.",
}

_OS_NAME = {"Darwin": "macOS"}


# What a device says about itself reaches the model, so each fact is checked against what it can be, not against a
# character set that a sentence also fits. The lists are the ones this code knows; anything else is dropped.
_OS_NAMES = frozenset({"Darwin", "Linux", "Windows"})
_SHELLS = frozenset({"bash", "git-bash"})
# platform.machine() on the systems Hermes runs on (Windows: AMD64, ARM64, x86; Linux: uname -m).
_ARCHES = frozenset({"x86_64", "amd64", "AMD64", "arm64", "ARM64", "aarch64", "i386", "i686", "x86", "armv6l",
                     "armv7l", "armv8l", "ppc64", "ppc64le", "s390x", "riscv64", "loongarch64", "mips64"})
# A version: a number of one to four dot parts first, then, after '-', '+', '~', '_' or a letter, at most 63 more
# characters of letters, digits and . _ + ~ - ("15.1", "6.8.0-45-generic", "6.11.4-301.fc41.x86_64",
# "5.15.153.1-microsoft-standard-WSL2", "0.23.0rc1"). No spaces, so no sentence. Only the number is kept: the
# letters after it are the device's own words and never reach the model, the panel or the pairing prompt.
_VERSION_RE = re.compile(r"(?P<number>[0-9]{1,5}(?:\.[0-9]{1,6}){0,3})"
                         r"(?:(?:[-+~_]|\.(?=[A-Za-z])|(?=[A-Za-z]))[0-9A-Za-z._+~-]{0,63})?")
_UNKNOWN = "?"
_TEXT_FACTS = ("os", "os_version", "machine", "hermes", "shell")
_VERSION_FACTS = ("os_version", "hermes")
_MODEL_FACTS = ("os", "os_version", "machine", "hermes", "shell", "terminal", "screen", "computer_use", "files_locked")
_FLAG_FACTS = ("terminal", "screen", "computer_use", "files_locked")      # real devices send computer_use as a bool
_RULE_PATHS = ("home", "hermes_home", "write_safe_root", "workspace_root")
_IDLE_MAX_MINUTES = 1440        # the host's own ceiling; a device announcing more is held to it, not dropped
_CONSENT_WAIT_MAX_S = 600.0     # the panel's highest consent wait (store.SETTINGS_LIMITS); more is held to it
# A path the host keeps for its own use (MEDIA ~/ paths, the denylist): absolute, no control characters or line
# breaks, at most 200 characters. Letters of any alphabet are fine.
_ABS_PATH_RE = re.compile(r"(?:/|[A-Za-z]:[\\/])[^\x00-\x1f\x7f-\x9f  ]*")
# A home folder of the usual shape, for the host's own use (Hermes's MEDIA ~/ and its attachment denylist):
# /Users/<x>, /home/<x>, /root or <drive>:\Users\<x>, where <x> is letters, digits, dots, underscores and dashes with
# at most one single space inside (at most 32 characters).
_HOME_RE = re.compile(r"(?:/Users/|/home/|[A-Za-z]:\\Users\\)(?P<user>[A-Za-z0-9._-]+(?: [A-Za-z0-9._-]+)?)|/root")
# The home folder the model may be told while a device is open: the same places, with a user folder name of one
# word or two joined by one '.', '_' or '-' (ada, ada.byron, john_doe), at most 24 characters, no space.
_SHOWN_HOME_RE = re.compile(r"(?:/Users/|/home/|[A-Za-z]:\\Users\\)(?P<user>[A-Za-z0-9]+(?:[._-][A-Za-z0-9]+)?)|/root")
_SHOWN_USER_MAX = 24
_NUMERIC_VERSION_RE = re.compile(r"[0-9]{1,5}(?:\.[0-9]{1,6}){0,3}")   # macOS and Windows report digits only


def version_number(value: Any) -> Optional[str]:
    """The number a version starts with ("6.11.4" of "6.11.4-301.fc41.x86_64"), or None when the value is not a
    version of the _VERSION_RE shape. The rest of the value is never kept: a dash-joined phrase after a number
    ("1.0-ignore-the-user") leaves only "1.0"."""
    match = _VERSION_RE.fullmatch(value) if isinstance(value, str) else None
    return match.group("number") if match else None


def _fact_ok(key: str, value: Any) -> bool:
    if not isinstance(value, str):
        return False
    if value == _UNKNOWN:
        return True
    if key == "os":
        return value in _OS_NAMES
    if key == "shell":
        return value in _SHELLS
    if key == "machine":
        return value in _ARCHES
    return version_number(value) is not None        # os_version, hermes


def clean_os(value: Any) -> str:
    """The device's OS for the pairing prompt: one of the known names, else "?"."""
    return value if isinstance(value, str) and value in _OS_NAMES else _UNKNOWN


def clean_version(value: Any) -> str:
    """The device's Hermes or OS version for the pairing prompt: its number, else "?"."""
    return version_number(value) or _UNKNOWN


def is_path(value: Any) -> bool:
    """A path the host keeps for its own use (see _ABS_PATH_RE). Not shown to the model; see shown_home."""
    return isinstance(value, str) and len(value) <= 200 and _ABS_PATH_RE.fullmatch(value) is not None


def is_home_folder(value: Any) -> bool:
    """A home folder of the usual shape, for the host's own use (Hermes's MEDIA ~/ and its denylist base). The model
    is shown a home only through shown_home."""
    match = _HOME_RE.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        return False
    user = match.group("user")
    # a user folder name is short and has few separators; "obey-the-device-now" is not one
    return user is None or (len(user) <= 24 and sum(c in "._- " for c in user) <= 2)


def shown_home(value: Any) -> Optional[str]:
    """The home folder the model may be told about a device it is connected to (after the person there allowed the
    session), or None: /Users/<name>, /home/<name>, /root or <drive>:\\Users\\<name>, where <name> is one word or two
    joined by one '.', '_' or '-', at most 24 characters. A name with a space or more parts is not shown (the agent
    can still use ~ on the device)."""
    match = _SHOWN_HOME_RE.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        return None
    user = match.group("user")
    return value if user is None or len(user) <= _SHOWN_USER_MAX else None


def clean_announce(data: Any) -> dict[str, Any]:
    """The host's view of what a device announced: only facts that pass their check, each in the shape it has, and
    a version only as its number. A device's name is dropped (the host has its own label for it) and so is free
    text (rules.judged_by). An idle limit above the host's ceiling is held to the ceiling, not dropped. The model
    is never given this view: see model_view."""
    if not isinstance(data, dict):
        return {}
    out: dict[str, Any] = {}
    for key in _TEXT_FACTS:
        value = data.get(key)
        if _fact_ok(key, value):
            out[key] = value if key not in _VERSION_FACTS or value == _UNKNOWN else version_number(value)
    raw = data.get("os_version")
    if out.get("os") in ("Darwin", "Windows") and "os_version" in out and raw != _UNKNOWN \
            and not _NUMERIC_VERSION_RE.fullmatch(raw):
        out.pop("os_version")        # these report a plain number (mac_ver, the Windows version); nothing else
    for key in _FLAG_FACTS:
        if isinstance(data.get(key), bool):
            out[key] = data[key]
    if is_path(data.get("home")):
        out["home"] = data["home"]
    rules = data.get("rules")
    if isinstance(rules, dict):
        clean: dict[str, Any] = {}
        for key in _RULE_PATHS:
            if key in rules and (rules[key] is None or is_path(rules[key])):   # None is sent today (no safe root)
                clean[key] = rules[key]
        idle = rules.get("grant_idle_minutes")
        if isinstance(idle, (int, float)) and not isinstance(idle, bool) and idle >= 1:
            clean["grant_idle_minutes"] = min(idle, _IDLE_MAX_MINUTES)
        wait = rules.get("consent_wait_seconds")      # how long its Allow prompt waits; the host's opening call
        if isinstance(wait, (int, float)) and not isinstance(wait, bool) and wait >= 1:    # waits that long too
            clean["consent_wait_seconds"] = min(float(wait), _CONSENT_WAIT_MAX_S)
        out["rules"] = clean
    return out


def model_view(announce: Any) -> dict[str, Any]:
    """What the model may see of any paired device, for devices list, devices use and the per-turn note: its OS,
    shell and architecture from the fixed lists, its version numbers, its flags and its idle limit. Never the name,
    a path or free text; the per-turn note adds the home folder of the device that is open (shown_home)."""
    clean = clean_announce(announce)
    view = {key: clean[key] for key in _MODEL_FACTS if key in clean}
    idle = (clean.get("rules") or {}).get("grant_idle_minutes")
    if idle is not None:
        view["grant_idle_minutes"] = idle
    return view


def describe(facts: dict[str, Any]) -> str:
    """One short paragraph about the machine for the agent; empty when the device sent nothing usable."""
    system = facts.get("os")
    if system not in _OS_NAMES:
        return ""
    default = "git-bash" if system == "Windows" else "bash"
    shell = facts.get("shell") if facts.get("shell") in _SHELLS else default      # older devices send none
    version = version_number(facts.get("os_version")) or ""
    name = " ".join(x for x in (_OS_NAME.get(system, system), version) if x)
    parts = [f"It runs {name}.", _SHELL[shell]]
    if shell != "git-bash":
        parts.append(_OS.get(system, ""))
    return " ".join(p for p in parts if p)
