"""Process-wide runtime: one asyncio loop on its own daemon thread (design §3, listener note).

Hermes tool handlers are synchronous and run in Hermes's worker threads; they reach the link through
``Runtime.run(coro, timeout)``, which schedules onto this loop with ``run_coroutine_threadsafe``. The gateway's
own loop is never touched. ``tether_screen`` (a separate plugin, same process) finds the same runtime
through ``get_runtime()``.
"""
from __future__ import annotations

import asyncio
import concurrent.futures
import logging
import os
import sys
import time
import threading
import types
import uuid
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Optional

logger = logging.getLogger(__name__)
_HANDLE = "tether_runtime_handle"     # a tiny module in sys.modules, shared by both plugins
BG_CLOSED_KEEP = 300                  # closed background jobs remembered, so a late poll is said so, not routed
BG_JOBS_KEEP = 256                    # running background jobs remembered at most (Hermes itself tracks 64)
BG_AWAY_S = 900.0                     # a device unreachable longer than this (with no idle limit known) ends its jobs' polls
REFUSED = ("no longer allowed", "did not allow remote use")   # the device answered: this session is not allowed there


@dataclass
class BgJob:
    """A background command Hermes started through the tether backend (provider.py). Its poll and stop go to
    ``machine`` (the device it started on, or "local"), never to whatever the session is connected to now.
    A job on this host is kept while its process lives; a device job while its session is connected (then in
    bg_closed). At most BG_JOBS_KEEP: host records go first, so no session's activity pushes out another session's
    running device job (gauntlet 3.1 lock F1)."""
    id: str
    machine: str
    session: str
    log: str
    pid_path: str
    exit_path: str
    pid: Optional[int] = None
    closed: bool = False     # its device connection closed: it can no longer be checked or stopped from here
    pgid: Optional[int] = None          # a job on "local": its own process group, for the whole-tree stop
    away_since: Optional[float] = None  # when its device stopped answering while still connected (D15)

    def finished(self) -> bool:
        """A job on this host whose process is gone: Hermes's poller has seen it end, or will on its next read from
        its exit file, which needs no record. A device job is never judged here (its session's close moves it)."""
        if self.machine != "local" or self.pid is None:
            return False
        try:
            os.kill(self.pid, 0)
        except ProcessLookupError:
            return True
        except OSError:                 # exists, owned by someone else: not ended
            return False
        return False


class Runtime:
    SWEEP_INTERVAL_S = 30.0     # how often the idle limit is enforced outside user turns too (route() checks inside)
    TURNS_KEPT = 512            # turn ids remembered with their session (turn_owner), oldest dropped first
    # The host's idle clock starts when a reply arrives, a moment after the device's (which starts when the call
    # ends there). The host closes this much early, so it never sends a call into a grant the device has let lapse.
    IDLE_MARGIN_S = 5.0

    def __init__(self) -> None:
        self.loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run, name="tether-link", daemon=True)
        self._thread.start()
        self.host = None      # host.HostService when the host role runs here
        self.device = None    # device.DeviceService when the device role runs here
        self.targets: dict[str, str] = {}   # host: session id -> device name or "local" (devices tool, use)
        self.last_device: dict[str, str] = {}   # host: session id -> the device it last worked on
        # D23: a session reaches its device only inside a turn the user started, and within the idle limit.
        self.turn_open: dict[str, bool] = {}
        self.turn_text: dict[str, str] = {}     # session -> the user's own words this turn (who may switch)
        self.turn_wrapped: dict[str, bool] = {}  # session -> this turn's message had quoted/attached/added text
        self.turn_id: dict[str, str] = {}       # session -> id of the user turn that is open (its tool calls)
        self._calls = threading.local()         # the turn id and conversation id of the tool call on this thread
        self.last_activity: dict[str, float] = {}
        self.last_wall: dict[str, float] = {}   # wall-clock twin of last_activity: time asleep counts as idle (F39)
        self._busy: dict[str, int] = {}         # session -> device calls in flight (a running call is not idle)
        # Guards every change of connection state (targets, grants, busy, closed_note) and every check of it that
        # precedes a send. Never held across an await or a network call (F92/F97/F102).
        self._state_lock = threading.Lock()
        self.open_fp: dict[str, tuple[str, str]] = {}   # session -> (device, the key it was paired with when opened)
        self._sweeper: Optional[asyncio.Task] = None   # the idle sweeper, on self.loop; see _start_sweeper
        self.idle_limit_s: dict[str, float] = {}  # device -> its announced grant_idle_minutes, in seconds
        self.closed_note: dict[str, str] = {}   # session -> why its device connection closed (said next turn)
        self.skill_copies: dict[str, dict[str, str]] = {}   # session -> host skill dir -> path on the device
        # D33: (session, device) -> the grant token that device gave THIS process when the person there
        # clicked Allow. Memory only, never written anywhere: another program on this host has no token, so
        # the device asks its person again instead of letting it ride this session's Allow.
        self.grants: dict[tuple[str, str], str] = {}
        # D43: (session, device) -> the key (fingerprint) of the link that handed over the token in grants. A token
        # is only ever sent to that key, whatever name it has now. Set and removed together with grants.
        self.grant_fp: dict[tuple[str, str], str] = {}
        # D34 state is kept per session and judged per (session, turn), never by a caller's task key: Hermes's
        # terminal environment key ('default' in the CLI, 'session:<chat key>' in the gateway) is shared by a
        # parent, its sub-agents and its /bg runs, and its file tools carry another key (the session id).
        # session -> the device its model was last told it works on (open_device, or a device call). Cleared when
        # the model is told it is back on this host: a turn-start note, a D34 refusal, its own untether or switch.
        self.working_on: dict[str, str] = {}
        # session -> (turn id, message): inside that user turn the model was told the connection is gone; the rest
        # of that turn refuses its device-meant work too, so calls it sent in one batch (before it could read the
        # first refusal) cannot land on this host. Released when that turn ends, the next one starts, or on reopen.
        self.held: dict[str, tuple[str, str]] = {}
        # turn id -> the session whose user turn it is (pre_llm_call). A call is placed by its turn, also after
        # Hermes gave the session a new id inside that turn; a turn id no user turn has is another run's.
        self.turn_owner: dict[str, str] = {}
        # session -> Hermes's conversation id (its compression-lineage root, on every tool call), recorded with each
        # device use: a session id Hermes rotated between turns is matched back to the connection it had.
        self.conversation_of: dict[str, str] = {}
        self._told_elsewhere: set[str] = set()
        self.run_id = uuid.uuid4().hex          # this process's mark on its open-session records (a pid is reused)
        self._records_dated = float("-inf")     # when this process last re-dated its open-session records (F31)
        # Background jobs by Hermes job id. A job's poll and stop use its own machine, whatever the route is
        # now (provider.py); closed ones move to bg_closed and are kept only so a late poll is said so.
        self.bg_jobs: dict[str, BgJob] = {}
        self.bg_closed: dict[str, BgJob] = {}
        self._bg_lock = threading.Lock()
        self.default_target = "local"
        self.consent = None   # device: consent.ConsentGate (tether_screen honours its screen freeze)

    def _run(self) -> None:
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    def submit(self, coro: Awaitable[Any]) -> concurrent.futures.Future:
        return asyncio.run_coroutine_threadsafe(coro, self.loop)

    def run(self, coro: Awaitable[Any], timeout: Optional[float] = None) -> Any:
        fut = self.submit(coro)
        try:
            return fut.result(timeout)
        except concurrent.futures.TimeoutError:
            fut.cancel()
            raise TimeoutError("tether call timed out") from None


    # ---------- host helpers, also used by tether_screen through this shared object ----------
    @staticmethod
    def current_session() -> str:
        try:
            from gateway.session_context import get_session_env
            sid = get_session_env("HERMES_SESSION_ID") or get_session_env("HERMES_SESSION_KEY")
        except Exception:  # noqa: BLE001
            import os
            sid = os.getenv("HERMES_SESSION_ID", "")
        return sid or "default"

    def active_target(self, session: Optional[str] = None) -> str:
        """The device this session is connected to (its intent), whether or not a turn is running."""
        return self.targets.get(session or self.current_session(), self.default_target)

    def route(self, session: Optional[str] = None) -> str:
        """Where this session's work runs right now: its device only inside a turn the user started (never a
        background review after it) and within the device's idle limit; otherwise this host."""
        sid = session or self.current_session()
        target = self.active_target(sid)
        if target == "local" or not self.turn_open.get(sid, False):
            return "local"
        if self._other_turn(sid):     # a background review, scheduled job or sub-agent: not the user's turn
            return "local"
        if self._check_connection(sid, target):
            return "local"
        return target

    def _expired(self, sid: str, target: str) -> Optional[str]:
        """Why this session's connection to target is past its idle limit (the timer counts from its last device
        call), or None. Idle time is the larger of the monotonic clock's and the wall clock's: on macOS (and Linux)
        the monotonic clock stops while the machine sleeps, and time asleep is idle too (F39, as consent.py does)."""
        limit, last = self.idle_limit(target), self.last_activity.get(sid)
        if not (limit and last):
            return None
        idle = time.monotonic() - last
        wall = self.last_wall.get(sid)
        if wall is not None:
            idle = max(idle, time.time() - wall)
        # The host's clock starts when the reply arrives, a moment after the device's: close a little early (D44).
        if idle > limit - min(self.IDLE_MARGIN_S, limit / 10):
            return f"timed out after {limit / 60:.0f} idle minutes"
        return None

    def _touch(self, sid: str) -> None:
        """The session was just used: both idle clocks restart. Call with _state_lock held (or before the session
        is visible to other threads)."""
        self.last_activity[sid], self.last_wall[sid] = time.monotonic(), time.time()

    def _check_connection(self, sid: str, target: str) -> Optional[str]:
        """Ends the session's connection to target when its key changed or it is past its idle limit. Returns the
        reason (the connection is closed by then), or None. A changed key closes the session even with a call in
        flight; the close reaches only the key the session was opened with (D43), wherever that key is paired now,
        and a key that is gone is told nothing. A session with a call in flight is not idle: the busy check, the
        idle decision and the detach are one locked step, as in sweep_idle (F102, F25), so route(), the explicit
        target check and Hermes's background-job poll never close a session under a running command."""
        reason = self._pin_gone(sid, target)      # reads the pins file: outside the state lock
        with self._state_lock:
            if not reason and not self._busy.get(sid) and self.targets.get(sid) == target:
                reason = self._expired(sid, target)
            closed = self._detach(sid, reason) if reason else None
        if closed is not None:
            self._finish_close(sid, closed[0], closed[1], reason, closed[2])
            return reason
        return None

    def _pin_gone(self, sid: str, target: str) -> Optional[str]:
        """Why the key this session was opened with is no longer target's paired key (renamed, unpaired, or paired
        again with another key), or None."""
        opened = self.open_fp.get(sid)
        pins = getattr(self.host, "pins", None)
        if not opened or opened[0] != target or not opened[1] or pins is None:
            return None
        rec = pins.all().get(target)
        if rec is not None and rec.get("fp") == opened[1]:
            return None
        renamed = self.name_for_key(opened[1])
        if renamed:
            return f"{target} was renamed to {renamed}"
        if rec is None:
            return f"{target} was unpaired"
        return f"{target} was paired again with a different key"

    def pinned_fp(self, device: str) -> str:
        """The key paired under this name now, or ""."""
        pins = getattr(self.host, "pins", None)
        try:
            rec = pins.all().get(device) if pins is not None else None
        except Exception:  # noqa: BLE001 - an unreadable pins file: no key
            rec = None
        return str((rec or {}).get("fp") or "") if isinstance(rec, dict) else ""

    def name_for_key(self, fp: str) -> Optional[str]:
        """The name a key is paired under now (after a rename, its new label), or None when it is not paired. The
        same lookup the host uses to register that key's link (DevicePins.by_fp)."""
        pins = getattr(self.host, "pins", None)
        if not fp or pins is None:
            return None
        try:
            return pins.by_fp().get(fp)
        except Exception:  # noqa: BLE001 - an unreadable pins file: no name, so nothing is sent
            return None

    def begin_call(self, turn_id: str, conversation: str = "") -> tuple[str, str]:
        """Bind the turn id (and Hermes's conversation id) of the tool call starting on this thread; returns the
        previous binding for end_call."""
        previous = (getattr(self._calls, "turn_id", ""), getattr(self._calls, "conversation", ""))
        self._calls.turn_id, self._calls.conversation = turn_id or "", conversation or ""
        return previous

    def end_call(self, previous: tuple[str, str]) -> None:
        self._calls.turn_id, self._calls.conversation = previous

    def call_turn(self) -> str:
        """The turn id bound to the tool call running on this thread; empty on Hermes's own threads (its pollers)."""
        return getattr(self._calls, "turn_id", "")

    def call_conversation(self) -> str:
        """Hermes's conversation id of the tool call running on this thread (kept across a session-id rotation;
        a sub-agent reports its parent's); empty when none is bound."""
        return getattr(self._calls, "conversation", "")

    def _other_turn(self, sid: str) -> bool:
        """True when the calling tool call belongs to a turn other than the session's open user turn. Unknown
        ids (empty) on either side count as no evidence, so the old behaviour stays."""
        here, open_turn = getattr(self._calls, "turn_id", ""), self.turn_id.get(sid, "")
        return bool(here and open_turn and here != open_turn)

    def words_for(self, session: str) -> str:
        """The user's own words of the open turn; empty when the calling tool call is from another run."""
        return "" if self._other_turn(session) else self.turn_text.get(session, "")

    def wrapped_for(self, session: str) -> bool:
        """True when the open turn's message held text Hermes added (the refusal then says why); scope as words_for."""
        return False if self._other_turn(session) else bool(self.turn_wrapped.get(session))

    def idle_limit(self, device: str) -> Optional[float]:
        """Seconds a tethered session may sit idle: the shorter of the device's own limit and the limit this
        host set for it in the Tether panel (either may be unset)."""
        limits = [x for x in (self.idle_limit_s.get(device), self._host_idle_s(device)) if x]
        return min(limits) if limits else None

    def _host_idle_s(self, device: str) -> Optional[float]:
        pins = getattr(self.host, "pins", None)
        try:
            minutes = pins.idle_minutes(device) if pins is not None else None
        except Exception:  # noqa: BLE001
            minutes = None
        return minutes * 60 if minutes else None

    def learn_rules(self, device: str, capabilities: Any) -> None:
        """The device decides its own idle timer: keep its announced grant_idle_minutes."""
        minutes = ((capabilities or {}).get("rules") or {}).get("grant_idle_minutes")
        if isinstance(minutes, (int, float)) and minutes > 0:
            self.idle_limit_s[device] = float(minutes) * 60

    def events_dir(self):
        """The host's tether data folder (connection log), or None."""
        host = self.host
        d = getattr(host, "dir", None)
        if d is None and getattr(host, "pins", None) is not None:
            d = host.pins.path.parent
        return d

    def open_device(self, session: str, device: str) -> None:
        from .store import log_event
        if self.targets.get(session) != device:
            log_event(self.events_dir(), "tethered", device=device, session=session)
        pinned = self.pinned_fp(device)
        with self._state_lock:
            again = self.targets.get(session) == device
            opened = self.open_fp.get(session)
            # The key this connection is with (checked before each use): the key that handed over the grant token
            # (D43), else the key it was opened with; a pin read now only when neither is known (no token to guard).
            fp = self.grant_fp.get((session, device)) or (opened[1] if again and opened and opened[0] == device
                                                          else "") or pinned
            self.open_fp[session] = (device, fp)
            self.targets[session] = device
            self.last_device[session] = device
            if not again or session not in self.last_activity:
                # A re-tether of the open device is no device call: it moves neither idle clock (the device's clock
                # does not move either, F11).
                self._touch(session)
            self.closed_note.pop(session, None)
        self._told_elsewhere.discard(session)
        self.end_lost(session)                  # reopened: nothing is held back any more
        self.note_device_use(None, device, session)     # the devices tool tells the model it works there now
        self._record_open(session, device)
        self._start_sweeper()

    # ---------- the idle limit outside turns: route() checks only inside one, so a session left alone would keep
    # its device workspace (and a host-set limit would never apply) until the next message ----------
    def _start_sweeper(self) -> None:
        def start() -> None:                     # on the loop thread, so there is never a second sweeper
            if self._sweeper is None or self._sweeper.done():
                self._sweeper = self.loop.create_task(self._sweep_forever())
        self.loop.call_soon_threadsafe(start)

    async def _sweep_forever(self) -> None:
        while True:
            await asyncio.sleep(self.SWEEP_INTERVAL_S)
            try:
                await asyncio.to_thread(self.sweep_idle)     # small file work: keep it off the loop
            except Exception:  # noqa: BLE001 - the sweeper must not die; the next pass tries again
                logger.warning("tether: idle sweep failed", exc_info=True)
            try:
                await asyncio.to_thread(self.date_records)   # F31: a held connection's record stays news
            except Exception:  # noqa: BLE001 - a note for later; the next pass tries again
                logger.warning("tether: open-session records not re-dated", exc_info=True)
            if not any(t != "local" for t in list(self.targets.values())):
                return                           # nothing tethered: the next open_device starts it again

    def sweep_idle(self) -> int:
        """Closes every tethered session past its idle limit, whether or not a turn is open. Returns how many."""
        closed = 0
        for sid, target in list(self.targets.items()):
            with self._state_lock:               # the in-flight check and the decision are one step (F102)
                if self.targets.get(sid) != target or target == "local" or self._busy.get(sid):
                    continue                     # a call in flight is not idle
                reason = self._expired(sid, target)
                if reason is None:
                    continue
                if self._held_elsewhere(sid):    # F91: another Hermes process holds this session now: no close
                    self._forget_locked(sid)
                    continue
                target, token, fp = self._detach(sid, reason)
            self._finish_close(sid, target, token, reason, fp)
            closed += 1
        return closed

    def _held_elsewhere(self, sid: str) -> bool:
        """True when the open-session record names a live process other than this one for this session."""
        book = self._open_sessions()
        rec = book.all().get(sid) if book is not None else None
        if not rec:
            return False
        import os
        from .store import process_alive
        return rec.get("pid") != os.getpid() and process_alive(rec.get("pid"))

    def _forget_locked(self, sid: str) -> None:
        """Drops this process's copy of a session another Hermes process now holds: quietly, with no close and no
        note (the device connection belongs to that process). Call with _state_lock held."""
        target = self.targets.pop(sid, "local")
        self.grants.pop((sid, target), None)
        self.grant_fp.pop((sid, target), None)
        self.bg_close_session(sid)
        for table in (self.last_device, self.last_activity, self.last_wall, self.skill_copies, self.open_fp,
                      self.turn_open, self.turn_id, self.turn_text, self.turn_wrapped):
            table.pop(sid, None)

    def bg_job(self, job_id: Optional[str]) -> Optional[BgJob]:
        """The record of one of Hermes's background jobs by its Hermes id (live or closed), or None."""
        with self._bg_lock:
            return (self.bg_jobs.get(job_id) or self.bg_closed.get(job_id)) if job_id else None

    def bg_start(self, job: BgJob) -> None:
        with self._bg_lock:
            self._bg_prune_locked()
            self.bg_jobs[job.id] = job
            while len(self.bg_jobs) > BG_JOBS_KEEP:     # the oldest host record first; a device job only last
                victim = next((j for j, r in self.bg_jobs.items() if r.machine == "local"), None)
                self.bg_jobs.pop(victim if victim is not None else next(iter(self.bg_jobs)), None)

    def _bg_prune_locked(self) -> None:
        """Drops the records of jobs Hermes no longer tracks (call with _bg_lock held)."""
        for table in (self.bg_jobs, self.bg_closed):
            for jid in [j for j, job in table.items() if job.finished()]:
                table.pop(jid, None)

    def bg_close_session(self, session: str) -> None:
        """The session's device connection is closing: its background jobs on that device can no longer be
        checked or stopped from here. They move to bg_closed (capped), so a late poll is said so."""
        with self._bg_lock:
            self._bg_prune_locked()
            for jid, job in list(self.bg_jobs.items()):
                if job.session == session and job.machine != "local":
                    job.closed = True
                    self.bg_jobs.pop(jid, None)
                    self.bg_closed[jid] = job
            while len(self.bg_closed) > BG_CLOSED_KEEP:
                self.bg_closed.pop(next(iter(self.bg_closed)), None)

    def bg_call(self, job: BgJob, command: str, timeout: int, stop: bool = False) -> dict[str, Any]:
        """Hermes's own poll, status read or stop of a device job, run on the machine it started on, under the job's
        own session, whoever asks. Never routed by route(): the job's session must still be connected to that
        machine. It does not refresh the idle timer (a poll must not keep a session alive) and the device treats it
        as passive: no prompt, no extension. A stop that did not happen raises (Hermes then reports an error and
        keeps the job); a poll while the device is briefly unreachable is "no news" (D15)."""
        if self.host is None:
            raise ConnectionError("the tether plugin is not set up as a host on this machine")
        session, device = job.session, job.machine
        gone = (f"this background job runs on {device}, and that connection is closed; it can no longer be "
                "checked or stopped from here")
        if job.closed or self.targets.get(session) != device:
            raise ConnectionError(gone)
        if self._check_connection(session, device):
            raise ConnectionError(gone)
        # host_gate: these exact commands are Hermes's own, already judged for what they are (not the model's).
        args = {"command": command, "cwd": "", "timeout": timeout, "session": session,
                "passive": True, "host_gate": True}
        try:
            meta, out = self.run(self.device_call(device, "exec", args, b"", timeout=timeout), timeout + 30)
        except Exception as e:  # noqa: BLE001
            if stop:
                raise RuntimeError(f"the job on {device} was not stopped: {e}") from e
            if not self._bg_away(job, e):
                raise
            # D15: the session is still on this device, which is asleep or off the network for a moment. Hermes reads
            # an empty reply as "no news" (its status read gets the same), so the job stays tracked and its output
            # offset is kept; the next poll after the device dials back collects what it wrote meanwhile.
            return {"output": "", "returncode": 1}
        job.away_since = None
        if meta.get("needs_approval"):
            raise RuntimeError(f"{device} flags this background job's own command as needing approval; "
                               "it was not run")
        text, rc = out.decode(errors="replace"), meta.get("returncode", -1)
        if stop and rc != 0:
            raise RuntimeError(f"the job on {device} was not stopped: {text.strip() or f'exit status {rc}'}")
        return {"output": text, "returncode": rc}

    def _bg_away(self, job: BgJob, error: BaseException) -> bool:
        """True when a failed poll of a device job means "unreachable for now", not "gone": the session is still
        connected to that device here, the device did not refuse the session, and it has been unreachable for no
        longer than its idle limit (BG_AWAY_S when none is known). The idle sweep closes the session in the end."""
        if job.closed or self.targets.get(job.session) != job.machine:
            return False
        if any(word in str(error) for word in REFUSED):
            return False
        now = time.monotonic()
        if job.away_since is None:
            job.away_since = now
        return now - job.away_since <= (self.idle_limit(job.machine) or BG_AWAY_S)

    def close_device(self, session: str, reason: str, notify: bool = True) -> None:
        """Back to this host; the device empties the session's workspace and ends its grant (D23/D24). The close and
        its grant token go only to the key the session was opened with (D43). notify=False: the device is not told."""
        with self._state_lock:
            target, token, fp = self._detach(session, reason)
        self._finish_close(session, target, token if notify else None, reason, fp)

    def _detach(self, session: str, reason: str) -> tuple[str, str, str]:
        """The in-memory part of a close, to be called with _state_lock held. The reason is written before the
        target is removed, so no reader sees the session off its device without the reason (F99/F101). Returns
        (the device it was on, its grant token, the key that token belongs to) for _finish_close."""
        self.bg_close_session(session)
        target = self.targets.get(session, "local")
        token, fp = "", ""
        opened = self.open_fp.pop(session, None)
        if target != "local":
            self.closed_note[session] = (f"The {target} connection is closed ({reason}); you are on your host again. "
                                         "Only the user can reopen it.")
            token = self.grants.pop((session, target), "")     # the grant ends here; the device needs it to close
            fp = self.grant_fp.pop((session, target), "") or (opened[1] if opened and opened[0] == target else "")
        self.targets.pop(session, None)                        # an entry is kept only while a session is tethered
        self.last_device.pop(session, None)
        self.last_activity.pop(session, None)
        self.last_wall.pop(session, None)
        self.skill_copies.pop(session, None)
        return target, token, fp

    def _finish_close(self, session: str, target: str, token: Optional[str], reason: str, fp: str = "") -> None:
        """The device's side and the connection log, outside the state lock: file work may wait on the data folder.
        The close goes to the key ``fp`` (the one that handed over the token) under whatever name it has now, and
        only over a link authenticated as that key (D43). token None, or a key that is no longer paired: the device
        is not told (it also ends the grant and wipes on its own when the grant lapses)."""
        if target == "local":
            return
        if token is not None:
            self._send_close(session, token, fp)
        self._record_closed(session)
        from .store import log_event
        log_event(self.events_dir(), "untethered", device=target, session=session, reason=reason)

    def _send_close(self, session: str, token: str, fp: str) -> None:
        """close_session for the session, sent to the key ``fp`` under whatever name it is paired as now (a rename
        keeps the key) and only over a link authenticated as that key (D43). A key that is no longer paired is not
        told: the grant was never sent anywhere else, and the device ends it on its own when it lapses."""
        name = self.name_for_key(fp)
        if self.host is None or not name:
            return
        try:
            fut = self.submit(self.host.call(name, "close_session", {"session": session, "grant": token or ""},
                                             b"", 30, expect_fp=fp))
            fut.add_done_callback(lambda f, s=session, n=name: _close_answer(f, s, n))
        except Exception:  # noqa: BLE001 - the device also wipes on its own when the grant lapses
            pass

    # ---------- D34: a connection that is gone is said, never silently replaced by this host ----------
    def _open_sessions(self):
        d = self.events_dir()
        if d is None:
            return None
        from .store import OpenSessions
        return OpenSessions(d)

    def _record_open(self, session: str, device: str) -> None:
        """Puts this process's open-session record. It is never removed at exit: a clean exit loses the connection
        just as a crash does, and the next process must say so (F7). untether, the idle limit, a switch, a
        re-pair and the next process's note remove it."""
        book = self._open_sessions()
        if book is not None:
            book.put(session, device, run=self.run_id)

    def _record_closed(self, session: str) -> None:
        import os
        book = self._open_sessions()
        if book is not None:
            book.drop(session, pid=os.getpid())   # only this process's record: another process's stays (F91)

    def date_records(self) -> None:
        """Re-dates this process's records of the connections it still holds (the idle sweeper calls this, at most
        every OPEN_REFRESH_S). A record's age then counts from the last time its holder was seen holding it, not
        from the open, so a connection held for days is still said after a restart (F31). Only records this
        process wrote (its pid and run id) are touched: another process's record is never re-dated or replaced."""
        import os
        from .store import OPEN_REFRESH_S
        now = time.monotonic()
        if now - self._records_dated < OPEN_REFRESH_S:
            return
        self._records_dated = now
        held = [s for s, t in list(self.targets.items()) if t != "local"]
        book = self._open_sessions()
        if held and book is not None:
            book.touch(held, os.getpid(), self.run_id)

    def note_device_use(self, task_id: Optional[str], device: str, session: Optional[str] = None) -> None:
        """A call of this session is about to run on device (or the devices tool just opened it): its model works
        there now. task_id is not used: D34 state is per session, not per caller key."""
        sid = session or self.current_session()
        self.working_on[sid] = device
        conversation = self.call_conversation()
        if conversation:
            self.conversation_of[sid] = conversation

    def forget_tasks(self, session: str) -> None:
        """The model has just been told this session is off its device (a turn-start note, or its own untether or
        switch): its work starts clean on this host."""
        self.working_on.pop(session, None)
        self.conversation_of.pop(session, None)
        self.end_lost(session)

    def end_lost(self, session: str) -> None:
        """The turn in which this session was told its connection is gone has ended (or a new turn started, or the
        user reopened it): nothing of it is held back any more."""
        self.held.pop(session, None)

    def turn_started(self, session: str, turn: str) -> None:
        """pre_llm_call of a user turn: the turn id belongs to this session, and what an earlier turn held back is
        released: the model has read that refusal. The last TURNS_KEPT turn ids are kept, and a turn that is still
        open (some session's turn_id) is never dropped, however many turns started since."""
        self.end_lost(session)
        if turn:
            self.turn_owner.pop(turn, None)
            self.turn_owner[turn] = session
            extra = len(self.turn_owner) - self.TURNS_KEPT
            if extra > 0:
                still_open = set(self.turn_id.values())
                for old in [t for t in self.turn_owner if t not in still_open][:extra]:
                    self.turn_owner.pop(old, None)

    def _whose_turn(self, session: str) -> tuple[Optional[str], Optional[str]]:
        """(owner, turn) for the calling work of session. owner is the session whose user turn it belongs to. turn is
        that open turn's id ("" for a turn that carries none), the key its hold is kept under; None when the work is
        not a tool call of that open turn (Hermes's own threads, which carry no turn id: a MEDIA delivery after the
        reply, a helper during the turn), which may be refused but never spends the note or sets a hold, since the
        model does not read its result. (None, None) for another run: a sub-agent, a side run, a background review,
        a scheduled job, whose turn id is no user turn of this session. A turn id that names a user turn decides, so
        a call made after Hermes gave the session a new id mid-turn still belongs to the turn's own session."""
        here = self.call_turn()
        owner = self.turn_owner.get(here) if here else None
        if owner is not None:
            still_open = self.turn_open.get(owner, False) and self.turn_id.get(owner, "") == here
            return owner, (here if still_open else None)
        if here and (self._other_turn(session) or not self.turn_open.get(session, False)):
            return None, None
        open_turn = self.turn_id.get(session, "")
        if self.turn_open.get(session, False) and (here or not open_turn):
            return session, open_turn or here
        return session, None

    def _hold(self, owner: str, turn: str, device: str, said: str) -> str:
        """The model of owner is told now, inside its user turn, that its device connection is gone: the same
        refusal answers the rest of that turn's device-meant work."""
        message = (f"tether: {said} This did not run anywhere, and nothing more meant for {device} runs this turn. "
                   f"Tell the user that the {device} connection is closed.")
        self.working_on.pop(owner, None)
        self.closed_note.pop(owner, None)
        self.conversation_of.pop(owner, None)
        self.held[owner] = (turn, message)
        return message

    def session_moved(self, old: str, new: str) -> None:
        """Hermes gave this conversation a new session id (compression with in_place false). The device connection
        and its Allow belong to the old id and do not carry over: that connection closes, and what the model has not
        been told yet moves to the new id, so it is said there (D34)."""
        if not old or not new or old == new:
            return
        if self.targets.get(old, "local") != "local":
            self.close_device(old, MOVED)                  # takes the state lock itself
        with self._state_lock:
            for table in (self.closed_note, self.working_on, self.conversation_of):
                if old in table:
                    table.setdefault(new, table.pop(old))
            self.held.pop(old, None)

    def adopt_conversation(self, session: str) -> None:
        """A call of session's own user turn carries Hermes's conversation id. When another session id of this
        process with connection state has the same conversation id, Hermes rotated the id between turns (the
        gateway's compression before a turn): the old connection closes and its state moves here, so this turn's
        device-meant work is refused and told instead of running on this host. Sub-agents share the conversation id,
        so only a call of the session's own open user turn counts; a session with its own state adopts nothing."""
        conversation = self.call_conversation()
        if not conversation or not session or not self.conversation_of:
            return
        with self._state_lock:
            owner, turn = self._whose_turn(session)
            if owner != session or turn is None:
                return
            if session in self.working_on or self.targets.get(session, "local") != "local":
                return
            old = next((s for s, c in list(self.conversation_of.items())
                        if c == conversation and s != session
                        and (s in self.working_on or s in self.closed_note
                             or self.targets.get(s, "local") != "local")), None)
        if old is not None:
            self.session_moved(old, session)

    def lost_device(self, task_id: Optional[str] = None, session: Optional[str] = None) -> Optional[str]:
        """D34. Work meant for a device would run on this host (route() said local, and it is not the host's own
        work). Returns one plain message for the model when that is because the session's connection is gone while
        its model may still think it works there; None when the work simply belongs to this host.
        Judged by (session, turn), never by the caller's key; task_id is not used.
        - Another run's call (a sub-agent, side run, review, job) is the host's work: None, and nothing changes.
        - A call of the user's open turn under a session id that is not the turn's own: Hermes rotated the id
          mid-turn; the connection opened under the old id closes, and the turn's owner is refused and told.
        - Inside the owner's open turn the first such call is refused with the closed note (said once) and every
          later device-meant call of that turn gets the same refusal, a call with no turn id bound included.
          The next user turn starts clean.
        - After the turn (no tool call bound, Hermes's own MEDIA delivery): refused while the model has not been
          told, and nothing is spent; the next turn's start says it.
        The decision is one step under the state lock: of calls Hermes runs side by side (read_file, search_files),
        one is told and the rest are held, none falls through to this host."""
        now = session or self.current_session()
        self.adopt_conversation(now)        # a rotation between turns, also when the middleware's own call missed it
        owner, _ = self._whose_turn(now)
        if owner is not None and now != owner and self.targets.get(owner, "local") != "local":
            self.close_device(owner, MOVED)                # outside the lock: close_device takes it itself
        with self._state_lock:
            return self._lost_locked(now)

    def _lost_locked(self, now: str) -> Optional[str]:
        """lost_device's decision; call with _state_lock held."""
        owner, turn = self._whose_turn(now)
        if owner is None:
            return None
        held = self.held.get(owner)
        if held is not None and (turn is None or held[0] == turn):
            return held[1]               # the turn that lost it is still running (a Hermes thread of it included)
        device = self.working_on.get(owner)
        if device is None:
            return None                  # its model was never on a device here, or has been told
        if now == owner and self.targets.get(owner) == device:
            return None                  # still open: work outside the user's turn stays on this host (D23)
        if turn is None:
            return f"tether: the {device} connection is closed, so this did not run anywhere."   # nothing spent
        said = self.closed_note.get(owner) or (f"The {device} connection is no longer open in this Hermes program; "
                                               f"you are on your host again. Only the user can reopen it, by saying "
                                               f"'tether {device}'.")
        return self._hold(owner, turn, device, said)

    def _denied(self, sid: str, target: str) -> None:
        """A call of sid was refused by the person at target and the connection is closed. The refusal itself tells
        the model; inside its user turn the rest of that turn's device-meant work gets the same answer (D34).
        Outside it (Hermes's attachment fallback after the turn) the closed note stays for the next turn."""
        with self._state_lock:
            owner, turn = self._whose_turn(sid)
            if owner == sid and turn is not None:
                self._hold(owner, turn, target, self.closed_note.get(owner) or f"The {target} connection is closed.")

    def lost_elsewhere(self, session: str) -> Optional[str]:
        """A device connection this conversation had that is not in this process: it lives in another Hermes
        program on this host, or it ended when Hermes stopped (a crash or a clean exit). Said once, then the model
        knows."""
        if self.targets.get(session, "local") != "local":
            return None
        book = self._open_sessions()
        rec = book.all().get(session) if book is not None else None
        if not rec:
            return None
        import os
        from .store import process_alive
        device, pid, run = str(rec.get("device") or "the device"), rec.get("pid"), rec.get("run")
        if pid == os.getpid() and run == self.run_id:
            return None
        if pid != os.getpid() and process_alive(pid):
            if session in self._told_elsewhere:
                return None
            self._told_elsewhere.add(session)
            return (f"The {device} connection of this conversation is open in another Hermes program on this "
                    f"host, not in this one: here you work on your host. Only the user can open {device} here, "
                    f"by saying 'tether {device}'.")
        book.drop(session, pid=pid)            # the ended process's record only (its pid may be ours now)
        return (f"The {device} connection is closed (Hermes restarted on this host); you are on your host "
                f"again. Only the user can reopen it.")

    async def device_call(self, target: str, kind: str, args: dict, body: bytes = b"",
                          timeout: float = 120.0, opening: bool = False) -> tuple[dict, bytes]:
        """One call to a device for ``args["session"]``, carrying that session's grant token (D33). When the
        call is the one the person at the device allowed, the device hands back a new token: keep it. ``opening``
        is the devices tool's first call, before the connection is recorded; every other call must be to the
        session's open connection, checked here together with the token read (F92/F97)."""
        session = str(args.get("session") or "default")
        key = (session, target)
        pinned = self.pinned_fp(target)          # read outside the lock; used only when no key is on record
        with self._state_lock:
            if not opening and self.targets.get(session) != target:
                raise ConnectionError(f"the {target} connection is no longer open, so this did not run anywhere")
            # A new connection carries no earlier token: it must not ride a grant left on the device (F83).
            token = "" if opening else self.grants.get(key, "")
            opened = self.open_fp.get(session)
            # D43: the call goes only over a link authenticated as the key this session's token came from (or, on
            # the opening call, the key paired under that name right now); a token is never sent anywhere else.
            recorded = "" if opening else (self.grant_fp.get(key) or
                                           (opened[1] if opened and opened[0] == target else ""))
            if token and not recorded:
                raise ConnectionError(f"the key the {target} connection was opened with is not on record, so this "
                                      "did not run anywhere")
            fp = recorded or pinned
        if opening and not fp:
            raise ConnectionError(f"no paired device named {target!r}")
        data, out = await self.host.call(target, kind, {**args, "grant": token}, body, timeout, expect_fp=fp)
        if isinstance(data, dict) and data.get("grant"):
            data = dict(data)
            grant = str(data.pop("grant"))
            with self._state_lock:
                keep = opening or self.targets.get(session) == target
                if keep:
                    self.grants[key] = grant
                    self.grant_fp[key] = fp           # the link that answered was authenticated as this key
            if not keep:
                # The connection closed while this call was out: nobody here will use its new grant, so it goes back
                # to the key that issued it, which ends it and empties the workspace (D39, D45).
                self._send_close(session, grant, fp)
        return data, out

    def forget_grant(self, session: str, device: str) -> None:
        """Drop a token this process holds for (session, device), e.g. after an opening call failed."""
        with self._state_lock:
            self.grants.pop((session, device), None)
            self.grant_fp.pop((session, device), None)

    def call_target(self, kind: str, args: dict, body: bytes = b"", timeout: float = 120.0,
                    target: Optional[str] = None, session: Optional[str] = None) -> tuple[dict, bytes]:
        """Blocking call from a Hermes worker thread to the session's active device. Raises
        ConnectionError / PermissionError / RemoteError / TimeoutError, or InterruptedError when the user
        stops the turn (the call is cancelled on the device too). An explicit ``target`` must be the session's
        open connection and within its idle limit; the attachment fallback is no exception (it reads from the
        open connection only)."""
        if self.host is None:
            raise ConnectionError("the tether plugin is not set up as a host on this machine")
        sid = session or self.current_session()   # a caller that routed by a session id sends under that same id
        if target and target != "local":
            # A caller may hold a device name read before the connection closed: it must not reach the device,
            # where it would prompt for a session the host has already closed.
            with self._state_lock:
                open_now = self.targets.get(sid) == target
            if not open_now:
                raise ConnectionError(f"the {target} connection is no longer open, so this did not run anywhere")
            reason = self._check_connection(sid, target)
            if reason:
                raise ConnectionError(f"the {target} connection is closed ({reason}), so this did not run anywhere")
        target = target or self.route(sid)
        if target == "local":
            raise ConnectionError("no device connection is open for this session; only the user can open one, "
                                  "by naming the device in their message")
        with self._state_lock:      # in flight before the call is sent: a sweep that runs now sees it (F102)
            self._busy[sid] = self._busy.get(sid, 0) + 1
        try:
            fut = self.submit(self.device_call(target, kind, {**args, "session": sid}, body, timeout=timeout))
            # The poll's own time-out is told apart from the call's: on Python 3.11 concurrent.futures.TimeoutError
            # IS the builtin TimeoutError that Peer.call raises when the call runs past its time, and a finished
            # future re-raises it on every poll (F8).
            while not concurrent.futures.wait([fut], timeout=0.25).done:
                if _interrupted():
                    fut.cancel()
                    raise InterruptedError("interrupted")
            try:
                result = fut.result()
            except Exception as e:  # noqa: BLE001 - a denial ends the connection; everything is re-raised
                if DENIED in str(e) and self.targets.get(sid) == target:
                    self.close_device(sid, f"the person at {target} did not allow it")
                    self._denied(sid, target)     # the exception tells the model; the rest of its turn is held (D34)
                raise
            with self._state_lock:
                if self.targets.get(sid) == target:
                    self._touch(sid)
            return result
        finally:
            with self._state_lock:
                left = self._busy.get(sid, 1) - 1
                if left > 0:
                    self._busy[sid] = left
                else:
                    self._busy.pop(sid, None)


def _close_answer(fut: concurrent.futures.Future, session: str, device: str) -> None:
    """A close the device refused or never confirmed is logged (it ends the grant on its own at its idle limit)."""
    try:
        err = None if fut.cancelled() else fut.exception()
    except Exception:  # noqa: BLE001
        return
    if err is not None:
        from .store import short_session
        logger.info("tether: %s did not confirm closing session %s: %s", device, short_session(session), err)


def _interrupted() -> bool:
    try:
        from tools.interrupt import is_interrupted
        return is_interrupted()
    except Exception:  # noqa: BLE001
        return False


def _handle() -> types.ModuleType:
    handle = sys.modules.get(_HANDLE)
    if handle is None:
        handle = types.ModuleType(_HANDLE)
        handle.lock = threading.Lock()
        handle.runtime = None
        handle.host_factory = None
        handle = sys.modules.setdefault(_HANDLE, handle)
    return handle


def shared(name: str, factory: Callable[[], Any]) -> Any:
    """One object per process for a plugin module's state, kept on the shared handle. Hermes re-imports the
    plugin on a forced re-discovery while terminals made by the earlier copy stay alive: each copy must see the
    same state, not its own."""
    handle = _handle()
    with handle.lock:
        obj = getattr(handle, name, None)
        if obj is None:
            obj = factory()
            setattr(handle, name, obj)
        return obj


def get_runtime(create: bool = True) -> Optional[Runtime]:
    if not create and _HANDLE not in sys.modules:
        return None
    handle = _handle()
    with handle.lock:
        if handle.runtime is None and create:
            handle.runtime = Runtime()
            if handle.host_factory is not None:
                handle.runtime.host = handle.host_factory()
        return handle.runtime


def set_host_factory(factory) -> None:
    """Host role: every process gets a ``HostLink`` (owner or relay) when it first needs the link."""
    handle = _handle()
    with handle.lock:
        handle.host_factory = factory
        if handle.runtime is not None and handle.runtime.host is None:
            handle.runtime.host = factory()


MOVED = "Hermes gave this conversation a new session id"   # why an older session id's connection ends (D34)
STOP = "Tell the user what happened; do not retry, work around it or investigate further."
# Approval happens only in the code box on the device (D63): the agent never asks for a code or coaches the person.
NO_CODES = ("Never ask the user for an approval code or tell them what to type: codes are entered only in the box "
            "on that machine.")
DENIED = "did not allow remote use"       # consent.py's refusal; the host closes the connection on it


def explain(e: BaseException, target: str = "") -> str:
    """One plain sentence for the model about a tether failure, ending in what to do (nothing)."""
    where = f" ({target})" if target and target != "local" else ""
    msg = str(e) or type(e).__name__
    if msg.startswith("no device connection is open"):
        return f"tether: {msg}. Ask the user if you need it."
    if DENIED in msg:
        return (f"tether{where}: {msg}. The connection is closed and you are on your host again; nothing ran on "
                f"that machine. Only the user can reopen it. {STOP} {NO_CODES}")
    if isinstance(e, PermissionError) or "did not allow" in msg:
        return f"tether{where}: {msg}. Only the person at that machine can approve it there. {STOP} {NO_CODES}"
    return f"tether{where}: {msg}. {STOP}"


Runtime.explain = staticmethod(explain)     # tether_screen reaches it through the handle
