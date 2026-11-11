"""What a machine says about itself when it connects, and what the agent is told from it.

The device sends plain facts (OS, version, the shell its Hermes runs commands with). The host turns them into
guidance from the fixed table below, so a device never writes free text into the agent's prompt. Hermes runs
terminal commands with bash on every OS; on Windows that bash is Git Bash (MSYS).
"""
from __future__ import annotations

import platform
import re
from typing import Any


def local_facts() -> dict[str, Any]:
    """This machine's own facts, sent in the pairing hello and in every announce. Never its computer name."""
    try:
        from hermes_cli import __version__ as hv  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        hv = "?"
    system = platform.system()
    return {"os": system, "os_version": platform.mac_ver()[0] or platform.release(),
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


_VERSION_RE = re.compile(r"[A-Za-z0-9 ._()-]{1,40}")


def describe(facts: dict[str, Any]) -> str:
    """One short paragraph about the machine for the agent; empty when the device sent nothing usable."""
    system = str(facts.get("os") or "")
    if not _VERSION_RE.fullmatch(system):
        return ""
    shell = str(facts.get("shell") or ("git-bash" if system == "Windows" else "bash"))   # older devices
    version = str(facts.get("os_version") or "")
    if not _VERSION_RE.fullmatch(version):
        version = ""                       # device-announced: only a plain version string reaches the model
    name = " ".join(x for x in (_OS_NAME.get(system, system), version) if x)
    parts = [f"It runs {name}.", _SHELL.get(shell, "")]
    if shell != "git-bash":
        parts.append(_OS.get(system, ""))
    return " ".join(p for p in parts if p)
