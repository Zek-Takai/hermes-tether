"""Session approval on the device with a code from the person's authenticator app (design D10, D33, D63-D65, D68).

- The first remote call of a host session opens the approval box on THIS device's screen. The box asks for the
  6-digit code from the authenticator app on the person's phone (authcode.py). A valid code typed into the box
  approves; Cancel, no answer, a closed box or wrong codes deny. There is no Allow button: nothing that can only
  click (another program, the agent's own screen actions, someone at the machine without the phone) can approve.
- The code is checked here and never leaves this device: the host only ever learns approved or not.
- A device with no authenticator set up (or one not unlocked since Hermes started, or one that must be set up
  again) shows no box and refuses (no Yes/No fallback).
- One approval covers that session; ``grant_idle_minutes`` without use and it lapses; a new session asks again.
- An approval belongs to the program that asked for it (D33). The device answers that first call with a random
  grant token, and every later call for the session must present it. Any other caller that names the session
  (another program on the host, the same session after the host restarted) has no token, so the box opens
  again; nothing rides on an approval it did not get.
- A call that presents the token its own caller held when it got the approval (its reply carrying the new token
  was lost) is that same caller: it rides the grant and is handed the current token (D45). This never creates a
  grant. An empty token never matches.
- Idle time counts from the END of a session's last call, as on the host, and a call still running is never idle
  (D44).
- Boxes are one at a time. After a box closes without a valid code the same session cannot ask again for a
  minute, and the device shows at most a few boxes in a short time, whoever asks.
- The box shows the host's label as recorded here at pairing and the session id, never text the caller chose.
  A session id that would share a live session's workspace folder is refused without a box (D46).
- While a box is open, ``screen_frozen`` is set and the device refuses every screen action from every session
  (input and screenshots); a screen action already running is waited for before the box opens (D65).
"""
from __future__ import annotations

import asyncio
import hmac
import logging
import math
import os
import platform
import re
import secrets
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Awaitable, Callable, Optional

from . import authcode
from .store import DEFAULT_GRANT_IDLE_MINUTES

logger = logging.getLogger(__name__)

# A box function shows the approval box with this text for at most this many seconds and returns what the person
# typed (a str), or None for Cancel, no answer, a closed box or any failure. Anything that is not a str never
# approves.
BoxFn = Callable[[str, float], Awaitable[Optional[str]]]
PromptFn = BoxFn                 # the name the rest of the plugin and its tests use

# Refusals the host reads. Every one contains runtime.DENIED ("did not allow remote use"), so the host closes the
# connection on it; tools._opening_error turns each into a fixed sentence.
DENIED_TEXT = "the person at this device did not allow remote use for this session"
# No box at all when no code can be checked (seedstore.SeedStore.refusal): no authenticator, not unlocked since
# Hermes started, one that must be set up again, no safe store on this machine (authcode.STORE_REFUSALS).
NO_AUTHENTICATOR_TEXT = authcode.NO_AUTHENTICATOR_TEXT
LOCKED_TEXT = ("this device did not allow remote use: its approval box is locked after too many wrong codes "
               "until its owner unlocks it at that computer")
PAUSED_CODES_TEXT = ("this device did not allow remote use: its approval box is paused after several wrong codes "
                     "(about {minutes} min left)")
UNAVAILABLE_TEXT = ("this device did not allow remote use: it could not check the approval code (its "
                    "authenticator key or code record could not be read)")
FOLDER_SHARED_TEXT = ("another session on this device uses the same workspace folder name; this session id is "
                      "refused")
LATE_TEXT = ("this device did not show its approval box: the call would have ended before the person there could "
             "enter a code, so nothing ran")
SCREEN_BUSY_TEXT = ("this device did not show its approval box: its screen was busy with another session's action, "
                    "so nothing ran")
FROZEN_TEXT = "this device's screen is frozen while its approval box is open; nothing was done on the screen"

DENY_COOLDOWN_S = 60.0       # after a box closed without a valid code, the same session cannot ask again for this long
PROMPT_SLACK_S = 3.0         # a box gives up this long before its caller stops waiting (start-up, the reply's trip)
MIN_PROMPT_S = 20.0          # a box shorter than this is not shown at all: nobody can read a code in less
MIN_RETRY_S = 10.0           # a retyped box is shown only with at least this long left
PROMPT_WINDOW_S = 300.0
PROMPTS_PER_WINDOW = 8       # approval requests this device shows per window, whoever asks
SCREEN_DRAIN_S = 5.0         # how long a box waits for a screen action already running to finish
_REFUSAL_REASON = {authcode.NO_AUTHENTICATOR_TEXT: "no authenticator set up",
                   authcode.SET_UP_AGAIN_TEXT: "authenticator must be set up again",
                   authcode.NO_SAFE_STORE_TEXT: "no safe store for an authenticator"}
_TITLE_RE = re.compile(r"[A-Za-z0-9 ._:#@+-]{1,80}")
BOX_TITLE = "Hermes Tether \u2014 approve remote use"
BOX_TITLE_WINDOWS = "Hermes Tether - approve remote use"
MAX_TYPED = 64               # a box answer longer than this is not a code


@dataclass
class Grant:
    host_fp: str
    session: str
    granted_at: float
    last_used: float
    token: str = ""          # every call must present it: an approval belongs to the caller that received it
    idle_s: float = 0.0      # the idle limit when the code was accepted; later settings only shorten it
    wall_used: float = 0.0   # wall-clock twin of last_used, so time asleep counts as idle too
    asked_with: str = ""     # the token the call that got this approval presented (its caller's previous one), or ""


def _minimal_env(keys: tuple[str, ...], extra: Optional[dict[str, str]] = None) -> dict[str, str]:
    """Only what the box process needs: never Hermes's own environment (provider keys, tokens), never a code."""
    env = {k: os.environ[k] for k in keys if os.environ.get(k)}
    env.update(extra or {})
    return env


MAC_ENV_KEYS = ("PATH", "HOME", "LANG")
WINDOWS_ENV_KEYS = ("PATH", "SystemRoot", "TEMP", "TMP", "USERPROFILE", "LANG", "LC_ALL")
OSASCRIPT = "/usr/bin/osascript"


def _applescript_quote(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def macos_script(text: str, timeout_s: float) -> str:
    """The AppleScript of the box. It reaches osascript on stdin (never in its arguments); the typed code comes back
    on stdout as "CODE:<typed>". A hidden answer is a secure text field: what is typed shows as dots and other
    programs' key taps do not see it."""
    return (
        f"set boxText to {_applescript_quote(text)}\n"
        "activate\n"
        "try\n"
        "  set r to display dialog boxText default answer \"\" with hidden answer "
        "buttons {\"Cancel\", \"Approve\"} default button \"Approve\" cancel button \"Cancel\" "
        f"with title {_applescript_quote(BOX_TITLE)} with icon caution giving up after {max(1, int(timeout_s))}\n"
        "on error number -128\n"
        "  return \"CANCEL\"\n"
        "end try\n"
        "if gave up of r then return \"TIMEOUT\"\n"
        "return \"CODE:\" & (text returned of r)\n")


def _typed(out: bytes) -> Optional[str]:
    """The code from a box process's stdout, or None. Nothing of it is logged."""
    text = out.decode(errors="replace").strip()
    if not text.startswith("CODE:"):
        return None
    typed = text[len("CODE:"):]
    return typed if len(typed) <= MAX_TYPED else None


async def macos_code_box(text: str, timeout_s: float) -> Optional[str]:
    """The approval box on this Mac's screen (osascript display dialog with a hidden answer). Cancel, give-up (no
    answer) or any failure = None."""
    try:
        proc = await asyncio.create_subprocess_exec(OSASCRIPT, "-", stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                                    stderr=subprocess.DEVNULL, env=_minimal_env(MAC_ENV_KEYS))
    except OSError:
        logger.warning("tether: could not start osascript for the approval box; refusing remote use")
        return None
    try:
        out, _ = await asyncio.wait_for(proc.communicate(macos_script(text, timeout_s).encode()), timeout_s + 15)
    except asyncio.TimeoutError:
        return None
    finally:
        await _close_dialog(proc)
    return _typed(out) if proc.returncode == 0 else None


async def _close_dialog(proc) -> None:
    """A box that ends unanswered for any reason (its own time-out, the host's Stop, the host giving up, a dropped
    link, Pause) takes its dialog with it: the process that shows the dialog is killed, and the caller (which keeps
    the screen frozen until it returns) waits for it to be gone. Killing osascript or PowerShell closes its dialog."""
    if proc.returncode is not None:
        return
    try:
        proc.kill()
    except ProcessLookupError:
        return
    # Wait for the process itself to be gone (its return code), not for its pipes: proc.wait() also waits for every
    # pipe to close, which a leftover child of the dialog program could hold open.
    for _ in range(100):
        if proc.returncode is not None:
            return
        await asyncio.sleep(0.05)


# The Windows box: a small always-on-top form with a masked text field (UseSystemPasswordChar), Approve and Cancel.
# The script is fixed; every word shown travels in an environment variable, never inside the script. The typed code
# comes back on stdout as "CODE:<typed>". Untested on a Windows machine (see spec): checked only with a stand-in.
WINDOWS_SCRIPT = (
    "$ErrorActionPreference = 'Stop'; "
    "Add-Type -AssemblyName System.Windows.Forms; Add-Type -AssemblyName System.Drawing; "
    "[System.Windows.Forms.Application]::EnableVisualStyles(); "
    "$f = New-Object System.Windows.Forms.Form; $f.Text = $env:TETHER_BOX_TITLE; $f.TopMost = $true; "
    "$f.FormBorderStyle = 'FixedDialog'; $f.MinimizeBox = $false; $f.MaximizeBox = $false; "
    "$f.StartPosition = 'CenterScreen'; $f.AutoSize = $true; $f.AutoSizeMode = 'GrowAndShrink'; "
    "$f.Padding = New-Object System.Windows.Forms.Padding(12); "
    "$p = New-Object System.Windows.Forms.FlowLayoutPanel; $p.FlowDirection = 'TopDown'; $p.AutoSize = $true; "
    "$p.WrapContents = $false; "
    "$l = New-Object System.Windows.Forms.Label; $l.Text = $env:TETHER_BOX_TEXT; $l.AutoSize = $true; "
    "$l.MaximumSize = New-Object System.Drawing.Size(480, 0); "
    "$t = New-Object System.Windows.Forms.TextBox; $t.UseSystemPasswordChar = $true; $t.MaxLength = 16; "
    "$t.Width = 160; "
    "$b = New-Object System.Windows.Forms.FlowLayoutPanel; $b.FlowDirection = 'LeftToRight'; $b.AutoSize = $true; "
    "$ok = New-Object System.Windows.Forms.Button; $ok.Text = 'Approve'; "
    "$ok.DialogResult = [System.Windows.Forms.DialogResult]::OK; "
    "$no = New-Object System.Windows.Forms.Button; $no.Text = 'Cancel'; "
    "$no.DialogResult = [System.Windows.Forms.DialogResult]::Cancel; "
    "$b.Controls.Add($ok); $b.Controls.Add($no); "
    "$p.Controls.Add($l); $p.Controls.Add($t); $p.Controls.Add($b); $f.Controls.Add($p); "
    "$f.AcceptButton = $ok; $f.CancelButton = $no; "
    "$script:gaveUp = $false; "
    "$timer = New-Object System.Windows.Forms.Timer; $timer.Interval = 1000 * [int]$env:TETHER_BOX_TIMEOUT; "
    "$timer.Add_Tick({ $script:gaveUp = $true; $timer.Stop(); $f.Close() }); "
    "$f.Add_Shown({ $f.Activate(); [void]$t.Focus(); $timer.Start() }); "
    "$r = $f.ShowDialog(); "
    "if ($script:gaveUp) { [Console]::Out.Write('TIMEOUT') } "
    "elseif ($r -eq [System.Windows.Forms.DialogResult]::OK) { [Console]::Out.Write('CODE:' + $t.Text) } "
    "else { [Console]::Out.Write('CANCEL') }")


def _powershell() -> str:
    root = os.environ.get("SystemRoot", r"C:\Windows")
    return os.path.join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")


async def windows_code_box(text: str, timeout_s: float) -> Optional[str]:
    """The approval box on this PC's screen. Cancel, no answer within the timeout or any failure = None. Needs
    Hermes running in the signed-in user's session (a background service has no screen to show it on, and then
    every session is refused)."""
    env = _minimal_env(WINDOWS_ENV_KEYS, {"TETHER_BOX_TEXT": text, "TETHER_BOX_TITLE": BOX_TITLE_WINDOWS,
                                          "TETHER_BOX_TIMEOUT": str(max(1, int(timeout_s)))})
    try:
        proc = await asyncio.create_subprocess_exec(
            _powershell(), "-NoProfile", "-NonInteractive", "-Sta", "-ExecutionPolicy", "Bypass",
            "-Command", WINDOWS_SCRIPT, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, env=env)
    except OSError:
        logger.warning("tether: could not start PowerShell for the approval box; refusing remote use")
        return None
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout_s + 15)
    except asyncio.TimeoutError:
        return None
    finally:
        await _close_dialog(proc)
    return _typed(out) if proc.returncode == 0 else None


async def unsupported_box(text: str, timeout_s: float) -> Optional[str]:
    logger.warning("tether: no approval box on %s yet; refusing remote use (macOS and Windows only)",
                   platform.system())
    return None


def clamp_consent_wait(seconds: float) -> float:
    """The box wait held to the range the panel accepts (store.SETTINGS_LIMITS, 20-600 s)."""
    from .store import SETTINGS_LIMITS
    lo, hi = SETTINGS_LIMITS["consent_timeout_seconds"]
    return min(max(float(seconds), lo), hi)


def default_prompt() -> BoxFn:
    system = platform.system()
    if system == "Darwin":
        return macos_code_box
    if system == "Windows":
        return windows_code_box
    return unsupported_box


def _date(wall: object) -> str:
    """'2 Nov 2026' for a Unix time, '' otherwise (no locale-dependent day padding, works on Windows too)."""
    if not isinstance(wall, (int, float)) or isinstance(wall, bool) or not 0 < wall < 1e11:
        return ""
    t = time.localtime(wall)
    return f"{t.tm_mday} {time.strftime('%b %Y', t)}"


def box_text(host_label: str, session: str, *, again: bool, idle_minutes: float, closes_at: float,
             seconds: float, entry: str = "", paired_at: object = None, note: str = "", unlocked: bool = False) -> str:
    """The words of the approval box (macOS and Windows show the same text). host_label is the label recorded on
    this device at pairing (already checked by shape); session is the id itself, never caller-chosen text."""
    shown = session if _TITLE_RE.fullmatch(session) else session[-12:]
    paired = _date(paired_at)
    where = f"\nHost paired here on {paired}." if paired else ""
    which = f' (entry "{entry}")' if entry else ""
    if again:
        head = (f"{host_label} asks AGAIN to use this computer for session {shown}.{where}\n\n"
                "This session is already approved here for another program on that host. Approving hands it to "
                "the program asking now (for example after Hermes restarted there).")
    else:
        head = (f"{host_label} wants to use this computer.\nSession: {shown}{where}\n\n"
                "If you approve, it can work on this computer as you (screen, terminal, files, tools) until the "
                f"session has been idle for {idle_minutes:g} min.")
    if unlocked and sys.platform == "darwin":
        # D73: allow_unlocked_commands is on here; the person sees it at every approval, not only in the panel.
        head += ("\n\nOn this Mac its commands run WITHOUT the session lock (allow_unlocked_commands is on in "
                 "Tether's settings), so they can change Tether's and Hermes's own files.")
    closes = time.strftime("%H:%M:%S", time.localtime(closes_at))
    return (f"{note}{head}\n\n"
            "Only approve if you just asked Hermes for this yourself. If you did not, press Cancel.\n\n"
            f"To approve, type the 6-digit code from your authenticator app{which}.\n"
            f"This box closes at {closes} ({max(1, int(seconds))} s) if no code is entered.")


def _note(verdict: str, tries_left: int) -> str:
    left = f"{tries_left} {'try' if tries_left == 1 else 'tries'} left."
    if verdict == authcode.USED:
        return f"That code was already used. Wait for the next code in your app, then type it. {left}\n\n"
    if verdict == authcode.JUST_STARTED:
        return ("Hermes on this computer started moments ago, so the codes of that minute are not taken (a code "
                "typed before a restart can never be used again). Wait for the next code in your app (up to a "
                f"minute), then type it. {left}\n\n")
    if verdict == "not a code":
        return f"Type the 6 digits from your authenticator app. {left}\n\n"
    return (f"That code was not accepted. {left} If codes keep failing, check that this computer sets its clock "
            "automatically.\n\n")


async def code_box_loop(box: BoxFn, codes: authcode.CodeChecker, make_text: Callable[[str, float], str],
                        wait: float) -> str:
    """Show the box (again after a mistyped or wrong code, up to MAX_TRIES_PER_BOX submits, all inside one
    deadline of ``wait`` seconds) until a valid code is typed. make_text(note, seconds_left) gives the box's words.
    Returns authcode.ACCEPTED or why not ("no code entered", "tries used up", "no time left", or the checker's
    PAUSED, LOCKED, UNAVAILABLE). The typed text is dropped right after it is checked and is never logged. Used by
    the gate."""
    deadline = time.monotonic() + wait
    note = ""
    for attempt in range(authcode.MAX_TRIES_PER_BOX):
        left = deadline - time.monotonic()
        if attempt and left < MIN_RETRY_S:
            return "no time left"
        typed = await box(make_text(note, left), left)
        if not isinstance(typed, str):             # Cancel, no answer, a closed box: never True, never a click
            return "no code entered"
        code, typed = authcode.normalize(typed), None
        tries_left = authcode.MAX_TRIES_PER_BOX - attempt - 1
        if code is None:
            note = _note("not a code", tries_left)
            continue
        verdict = await asyncio.to_thread(codes.check, code)
        code = None
        if verdict in (authcode.ACCEPTED, authcode.PAUSED, authcode.LOCKED, authcode.UNAVAILABLE):
            return verdict
        note = _note(verdict, tries_left)
    return "tries used up"


class ConsentGate:
    def __init__(self, *, idle_minutes: float = DEFAULT_GRANT_IDLE_MINUTES, timeout_s: float = 60.0,
                 prompt: Optional[BoxFn] = None, clock: Callable[[], float] = time.monotonic,
                 wall: Callable[[], float] = time.time, seed_store: Optional[authcode.SeedStore] = None,
                 codes: Optional[authcode.CodeChecker] = None, code_clock: Callable[[], float] = time.time) -> None:
        """seed_store: the device's authenticator seed (default: none set up, so every session is refused).
        codes: the code checker with its sealed state (the device role passes one over seedstore.SeedStore on its
        data folder; default: memory only, over seed_store). code_clock: the Unix time codes are judged by."""
        self.idle_s = max(1.0, float(idle_minutes)) * 60.0
        self.timeout_s = clamp_consent_wait(timeout_s)    # config.yaml is not range-checked elsewhere
        self._prompt = prompt or default_prompt()
        self._clock = clock
        self._wall = wall
        if codes is None:
            codes = authcode.CodeChecker(seed_store or authcode.NoSeedStore(), None, clock=code_clock, wall=wall)
        self.codes = codes
        self._grants: dict[tuple[str, str], Grant] = {}
        self._denied_until: dict[tuple[str, str], float] = {}
        self._asked: list[float] = []                   # when this device showed boxes (whoever asked)
        self._asking = asyncio.Lock()
        self._in_flight: dict[tuple[str, str], int] = {}   # (host, session) -> its guarded calls running now
        self.screen_frozen = False
        # Set by the plugin: waits until no screen action is running (ScreenExec.drain); False when one still runs.
        self.screen_drain: Optional[Callable[[float], Awaitable[bool]]] = None
        self.events_dir = None          # the device's tether data folder (connection log); set by the plugin
        self._warned_setup = False

    def set_idle_minutes(self, minutes: float) -> None:
        """New limit for new grants. A live grant keeps the shorter of this and the limit it was given under,
        so a session can be cut short from the panel but can never lengthen its own stay."""
        self.idle_s = max(1.0, float(minutes)) * 60.0

    def _live(self, key: tuple[str, str]) -> Optional[Grant]:
        g = self._grants.get(key)
        if g is None:
            return None
        if self._in_flight.get(key):
            return g                     # a call still running is not idle (D44); the clock restarts when it ends
        limit = min(g.idle_s or self.idle_s, self.idle_s)
        idle = max(self._clock() - g.last_used, self._wall() - g.wall_used)
        if idle > limit:
            self._grants.pop(key, None)
            logger.info("tether: grant for session %s lapsed after idle", key[1])
            self._log("lapsed", key[1], reason=f"idle {limit / 60:.0f} min")
            return None
        return g

    def _touch(self, g: Grant) -> None:
        g.last_used, g.wall_used = self._clock(), self._wall()

    @staticmethod
    def _holds(g: Grant, token: str) -> bool:
        return bool(token) and bool(g.token) and hmac.compare_digest(str(token).encode(), g.token.encode())

    @staticmethod
    def _asked_by(g: Grant, token: str) -> bool:
        """True when token is the one the call that got this approval presented: the same caller, whose reply with
        the new token was lost (D45). An empty token never matches."""
        return bool(token) and bool(g.asked_with) and hmac.compare_digest(str(token).encode(),
                                                                          g.asked_with.encode())

    def _ride(self, g: Optional[Grant], token: str) -> tuple[bool, Optional[str]]:
        """(this caller may use the live grant g, the token to hand back: the current one when it showed the
        earlier token, else None)."""
        if g is None:
            return False, None
        if self._holds(g, token):
            return True, None
        if self._asked_by(g, token):
            return True, g.token
        return False, None

    @staticmethod
    def _folder(session: str) -> str:
        from .workspace import safe_name
        return safe_name(session).casefold()   # safe_name is ASCII, so this matches APFS and NTFS case rules

    def folder_shared(self, session: str) -> bool:
        """True when another live session (another id) works in the same workspace folder as this id: a letter-case
        twin, or an id spelled like another id's folder name (D46)."""
        folder = self._folder(session or "default")
        return any(g.session != session and self._folder(g.session) == folder for g in self.active())

    async def require(self, host_fp: str, host_label: str, session: str, *, token: str = "",
                      passive: bool = False, expires: Optional[float] = None,
                      paired_at: Optional[float] = None) -> Optional[str]:
        """Raise PermissionError unless this session is approved on this device FOR THIS CALLER: an earlier valid
        code from the person's authenticator app, typed into this device's box, or one typed now. Returns the grant
        token the caller must keep when this call obtained the approval (or showed the token its own caller held
        when it got it, D45), otherwise None. A passive call (the host's own poll or stop of a background job)
        never asks, never extends the session and never counts toward a refusal: it works only inside a live
        approval. ``expires`` (time.monotonic()) is when the caller stops waiting for this call (its frame's
        deadline): the box gives up before then; with too little time left no box is shown and nothing counts as a
        refusal. ``host_label`` and ``paired_at`` are the host's label and pairing time as recorded on this device
        at pairing (device.py), never what the host says now."""
        key = (host_fp, session or "default")
        if passive:
            ok, _ = self._ride(self._live(key), token)
            if ok:
                return None                              # not _touch: a poll must not keep the session alive
            raise PermissionError("this session is no longer allowed on this device")
        ok, current = self._ride(g := self._live(key), token)
        if ok:
            self._touch(g)
            return current
        async with self._asking:                       # one box at a time
            ok, current = self._ride(g := self._live(key), token)
            if ok:                                     # approved while we waited
                self._touch(g)
                return current
            if g is None and self.folder_shared(key[1]):
                raise PermissionError(FOLDER_SHARED_TEXT)
            now = self._clock()
            until = self._denied_until.get(key, 0.0)
            if now < until:
                raise PermissionError(f"{DENIED_TEXT} (it was refused moments ago and can ask again in "
                                      f"{math.ceil(until - now)} s)")
            why = self.codes.refusal()                 # no code can be checked: no box at all, and no fallback
            if why is not None:
                self._log("refused", key[1], host=host_label,
                          reason=_REFUSAL_REASON.get(why, "authenticator not ready"))
                if why == authcode.NO_AUTHENTICATOR_TEXT and not self._warned_setup:
                    self._warned_setup = True
                    logger.warning("tether: remote use is refused until an authenticator is set up on this computer: "
                                   "run `%s` here", authcode.SETUP_COMMAND)
                raise PermissionError(why)
            held = await asyncio.to_thread(self.codes.blocked)    # the state file and its lock: off the loop
            if held is not None:                       # code entry paused or locked: no box
                self._log("refused", key[1], host=host_label, reason=f"code entry {held[0]}")
                raise PermissionError(self._held_text(held))
            wait = self.timeout_s
            if expires is not None:     # measured after the wait for the box lock: that time is gone too
                left = expires - time.monotonic() - PROMPT_SLACK_S
                if left < MIN_PROMPT_S:
                    raise PermissionError(LATE_TEXT)
                wait = min(wait, left)
            recent = [t for t in self._asked if now - t < PROMPT_WINDOW_S]
            if len(recent) >= PROMPTS_PER_WINDOW:
                self._asked = recent
                self._log("refused", key[1], host=host_label, reason="too many requests")
                raise PermissionError(f"{DENIED_TEXT} (too many requests in a short time; try again in a few "
                                      "minutes)")
            self._asked = recent + [now]
            again = g is not None       # a live grant someone else holds, or the same session after a restart
            self.screen_frozen = True
            try:
                if self.screen_drain is not None and not await self.screen_drain(SCREEN_DRAIN_S):
                    raise PermissionError(SCREEN_BUSY_TEXT)
                verdict = await self._ask_for_code(host_label, key[1], again, wait, paired_at)
            finally:
                self.screen_frozen = False
            if verdict != authcode.ACCEPTED:
                self._denied_until[key] = self._clock() + DENY_COOLDOWN_S
                logger.info("tether: remote use DENIED for %s, session %s (%s)", host_label, key[1], verdict)
                self._log("denied", key[1], host=host_label, reason=verdict + ("; asked again" if again else ""))
                if verdict == authcode.LOCKED:
                    raise PermissionError(LOCKED_TEXT)
                if verdict == authcode.PAUSED:
                    held = await asyncio.to_thread(self.codes.blocked)
                    raise PermissionError(self._held_text(held or (authcode.PAUSED, 60.0)))
                if verdict == authcode.UNAVAILABLE:
                    raise PermissionError(UNAVAILABLE_TEXT)
                raise PermissionError(DENIED_TEXT)
            self._denied_until.pop(key, None)
            now = self._clock()
            new_token = secrets.token_urlsafe(32)
            self._grants[key] = Grant(host_fp, key[1], now, now, new_token, self.idle_s, self._wall(),
                                      asked_with=str(token or ""))
            logger.info("tether: remote use APPROVED with a code for %s, session %s (lapses after %.0f idle "
                        "minutes)%s", host_label, key[1], self.idle_s / 60,
                        "; handed over from an earlier caller" if again else "")
            self._log("allowed", key[1], host=host_label, reason="handed over" if again else "code accepted")
            return new_token

    @staticmethod
    def _held_text(held: tuple[str, float]) -> str:
        if held[0] == authcode.PAUSED:
            return PAUSED_CODES_TEXT.format(minutes=max(1, math.ceil(held[1] / 60)))
        if held[0] == authcode.UNAVAILABLE:
            return UNAVAILABLE_TEXT
        return LOCKED_TEXT

    async def _ask_for_code(self, host_label: str, session: str, again: bool, wait: float,
                            paired_at: Optional[float]) -> str:
        from .lock import unlocked
        entry = self.codes.entry_name()
        closes_at = time.time() + wait
        loose = unlocked()

        def text(note: str, left: float) -> str:
            return box_text(host_label, session, again=again, idle_minutes=self.idle_s / 60, closes_at=closes_at,
                            seconds=left, entry=entry, paired_at=paired_at, note=note, unlocked=loose)
        return await code_box_loop(self._prompt, self.codes, text, wait)

    def _log(self, kind: str, session: str, **fields) -> None:
        from .store import log_event
        log_event(self.events_dir, kind, session=session, **fields)

    def revoke(self, host_fp: str, session: str) -> bool:
        return self._grants.pop((host_fp, session or "default"), None) is not None

    def release(self, host_fp: str, session: str, token: str) -> bool:
        """End a session's grant on the caller's word (the host closing it). True when there is nothing left
        to protect: no live grant, or the caller held it and it is now gone. False when another caller holds
        the live grant, which then stays as it is."""
        key = (host_fp, session or "default")
        g = self._live(key)
        if g is None:
            return True
        if not self._ride(g, token)[0]:
            return False
        self._grants.pop(key, None)
        return True

    def call_started(self, host_fp: str, session: str) -> None:
        """A guarded, non-passive call for this session is running (D44)."""
        key = (host_fp, session or "default")
        self._in_flight[key] = self._in_flight.get(key, 0) + 1

    def call_ended(self, host_fp: str, session: str, token: str) -> None:
        """That call ended: the session's idle clock starts again from now, as the host's does when the reply
        arrives, when the caller still holds the grant (D44)."""
        key = (host_fp, session or "default")
        left = self._in_flight.get(key, 1) - 1
        if left > 0:
            self._in_flight[key] = left
        else:
            self._in_flight.pop(key, None)
        g = self._grants.get(key)
        if g is not None and self._ride(g, token)[0]:
            self._touch(g)

    def live_sessions(self) -> set[str]:
        return {g.session for g in self.active()}

    def revoke_all(self) -> int:
        n = len(self._grants)
        self._grants.clear()
        return n

    def active(self) -> list[Grant]:
        return [g for k, g in list(self._grants.items()) if self._live(k)]
