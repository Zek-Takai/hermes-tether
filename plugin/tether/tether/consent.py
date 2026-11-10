"""Presence-based session consent on the device (design D10).

- The first remote call of a host session asks the person AT this device (a prompt on this screen).
- One "Allow" covers that session; ``grant_idle_minutes`` without use and it lapses; a new session asks again.
- No answer within the timeout = deny. Prompts are one at a time.
- While a prompt is open, ``screen_frozen`` is set and the device refuses all screen input from every session,
  so an agent can never click its own consent (rule D10.7).
"""
from __future__ import annotations

import asyncio
import logging
import platform
import subprocess
import time
from dataclasses import dataclass
from typing import Awaitable, Callable, Optional

logger = logging.getLogger(__name__)

PromptFn = Callable[[str, float], Awaitable[bool]]


@dataclass
class Grant:
    host_fp: str
    session: str
    granted_at: float
    last_used: float


def _applescript_quote(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


async def macos_prompt(text: str, timeout_s: float) -> bool:
    """Native dialog on this Mac's screen. Default button Deny; give-up (no answer) = deny."""
    script = (
        "try\n"
        f"  set r to display dialog {_applescript_quote(text)} buttons {{\"Deny\", \"Allow for this session\"}} "
        f"default button \"Deny\" cancel button \"Deny\" with title \"tether — allow remote use?\" "
        f"with icon caution giving up after {int(timeout_s)}\n"
        "  if gave up of r then return \"TIMEOUT\"\n"
        "  return button returned of r\n"
        "on error number -128\n  return \"Deny\"\nend try")
    proc = await asyncio.create_subprocess_exec("/usr/bin/osascript", "-", stdin=subprocess.PIPE,
                                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        out, _ = await asyncio.wait_for(proc.communicate(script.encode()), timeout_s + 15)
    except asyncio.TimeoutError:
        proc.kill()
        return False
    return out.decode(errors="replace").strip() == "Allow for this session"


WINDOWS_POPUP_FLAGS = 4 + 32 + 256 + 4096    # Yes/No, question icon, default button No, system-modal (on top)
WINDOWS_YES = "6"                            # Popup returns 6 (Yes), 7 (No) or -1 (timed out)
WINDOWS_SCRIPT = (
    "$ws = New-Object -ComObject WScript.Shell; "
    "$r = $ws.Popup($env:TETHER_PROMPT_TEXT, [int]$env:TETHER_PROMPT_TIMEOUT, "
    "'Hermes Tether - allow remote use?', [int]$env:TETHER_PROMPT_FLAGS); "
    "[Console]::Out.Write($r)")


def _powershell() -> str:
    import os
    root = os.environ.get("SystemRoot", r"C:\Windows")
    return os.path.join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")


async def windows_prompt(text: str, timeout_s: float) -> bool:
    """Windows' own timed message box (WScript.Shell Popup) on this PC's screen. Default button No; no answer
    within the timeout = deny. The text travels in an environment variable, never inside the script, so nothing
    in it can run. Needs Hermes running in the signed-in user's session (a background service has no screen to
    show it on, and then every session is denied)."""
    import os
    env = {**os.environ, "TETHER_PROMPT_TEXT": text + "\n\nAllow (Yes) or deny (No)?",
           "TETHER_PROMPT_TIMEOUT": str(int(timeout_s)), "TETHER_PROMPT_FLAGS": str(WINDOWS_POPUP_FLAGS)}
    try:
        proc = await asyncio.create_subprocess_exec(
            _powershell(), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", WINDOWS_SCRIPT,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    except OSError:
        logger.warning("tether: could not start PowerShell for the consent prompt; refusing remote use")
        return False
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout_s + 15)
    except asyncio.TimeoutError:
        proc.kill()
        return False
    return out.decode(errors="replace").strip() == WINDOWS_YES


async def unsupported_prompt(text: str, timeout_s: float) -> bool:
    logger.warning("tether: no consent prompt on %s yet; refusing remote use (macOS and Windows only)",
                   platform.system())
    return False


def default_prompt() -> PromptFn:
    system = platform.system()
    if system == "Darwin":
        return macos_prompt
    if system == "Windows":
        return windows_prompt
    return unsupported_prompt


class ConsentGate:
    def __init__(self, *, idle_minutes: float = 15.0, timeout_s: float = 15.0,
                 prompt: Optional[PromptFn] = None, clock: Callable[[], float] = time.monotonic) -> None:
        self.idle_s = max(1.0, float(idle_minutes)) * 60.0
        self.timeout_s = float(timeout_s)
        self._prompt = prompt or default_prompt()
        self._clock = clock
        self._grants: dict[tuple[str, str], Grant] = {}
        self._asking = asyncio.Lock()
        self.screen_frozen = False
        self.events_dir = None          # the device's tether data folder (connection log); set by the plugin

    def set_idle_minutes(self, minutes: float) -> None:
        self.idle_s = max(1.0, float(minutes)) * 60.0       # applies to existing grants at the next check

    def _live(self, key: tuple[str, str]) -> Optional[Grant]:
        g = self._grants.get(key)
        if g and self._clock() - g.last_used > self.idle_s:
            self._grants.pop(key, None)
            logger.info("tether: grant for session %s lapsed after idle", key[1])
            self._log("lapsed", key[1], reason=f"idle {self.idle_s / 60:.0f} min")
            return None
        return g

    async def require(self, host_fp: str, host_label: str, session: str, session_title: str = "") -> None:
        """Raise PermissionError unless the person at this device allowed this session."""
        key = (host_fp, session or "default")
        if (g := self._live(key)) is not None:
            g.last_used = self._clock()
            return
        async with self._asking:                       # one prompt at a time
            if (g := self._live(key)) is not None:     # allowed while we waited
                g.last_used = self._clock()
                return
            text = (f"{host_label} wants to use this machine for session "
                    f"\"{session_title or session}\":\n\n• screen   • terminal   • files   • tools\n\n"
                    "Only allow if you started this. It lasts for this session until it is idle.")
            self.screen_frozen = True
            try:
                allowed = await self._prompt(text, self.timeout_s)
            finally:
                self.screen_frozen = False
            if not allowed:
                logger.info("tether: remote use DENIED for %s, session %s", host_label, key[1])
                self._log("denied", key[1], host=host_label)
                raise PermissionError("the person at this device did not allow remote use for this session")
            now = self._clock()
            self._grants[key] = Grant(host_fp, key[1], now, now)
            logger.info("tether: remote use ALLOWED for %s, session %s (lapses after %.0f idle minutes)",
                        host_label, key[1], self.idle_s / 60)
            self._log("allowed", key[1], host=host_label)

    def _log(self, kind: str, session: str, **fields) -> None:
        from .store import log_event
        log_event(self.events_dir, kind, session=session, **fields)

    def revoke(self, host_fp: str, session: str) -> bool:
        return self._grants.pop((host_fp, session or "default"), None) is not None

    def live_sessions(self) -> set[str]:
        return {g.session for g in self.active()}

    def revoke_all(self) -> int:
        n = len(self._grants)
        self._grants.clear()
        return n

    def active(self) -> list[Grant]:
        return [g for k, g in list(self._grants.items()) if self._live(k)]
