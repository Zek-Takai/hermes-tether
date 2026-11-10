"""Device side: judge a host's command with THIS machine's own Hermes approval rules (design D25).

Hermes's own command gate runs in the host session first, as Hermes always runs it (its card, its
session/always answers). When it did (``host_gate``), this device adds only its floors. A command that did
not pass that gate (``host_gate`` false) gets this device's full rules:

- ``block``: one of this device's floors (hardline, runtime self-delete, ``sudo -S`` guess, its own
  ``approvals.deny`` rules). Final; nobody can approve it.
- ``ask``: this device's dangerous-command patterns flag it and nothing here pre-approves it (its approval
  mode, its permanent allowlist, its saved "always" answers). The host must get a yes from the human in the
  session and resend with ``approved_keys``.
- ``run``: clean, allowlisted, already approved, or this device runs with approvals off.

Hermes keeps these checks in ``tools.approval``; its public ``check_all_command_guards`` cannot be used here
because a device thread has no CLI or gateway attached, and Hermes then approves unattended commands. If
those helpers are missing (another Hermes version), the device fails closed: every flagged command asks.
"""
from __future__ import annotations

import logging
from typing import Any, Iterable

logger = logging.getLogger(__name__)


def judge(command: str, approved_keys: Iterable[str] = (), host_gate: bool = False) -> tuple[str, dict[str, Any]]:
    granted = {str(k) for k in approved_keys or ()}
    try:
        from tools import approval as A
        from tools import approval_context as C
    except ImportError:
        return _fallback(command, granted, host_gate)
    try:
        blocked = A._floor_block(command, sudo_guard=True)
        if blocked is not None:
            return "block", {"reason": blocked.get("message") or "blocked by this device's Hermes rules"}
        if host_gate:
            return "run", {}
        if C._get_approval_mode() == "off":
            return "run", {}
        if A._command_matches_permanent_allowlist(command):
            return "run", {}
        pending = [(k, d) for k, d in A._command_findings(command)
                   if k not in granted and not A._is_permanently_approved(k)]
    except Exception:  # noqa: BLE001 - a rule check that cannot run must not wave the command through
        logger.warning("tether: device rule check failed; asking", exc_info=True)
        return _fallback(command, granted, host_gate)
    if not pending:
        return "run", {}
    return "ask", {"pattern_keys": [k for k, _ in pending], "description": "; ".join(d for _, d in pending)}


def _fallback(command: str, granted: set[str], host_gate: bool = False) -> tuple[str, dict[str, Any]]:
    try:
        from tools.approval_detection import detect_dangerous_command, detect_hardline_command
    except ImportError:
        return "block", {"reason": "this device cannot check commands against its Hermes rules"}
    hard, why = detect_hardline_command(command)
    if hard:
        return "block", {"reason": f"blocked on this device by Hermes's hardline rules: {why}"}
    if host_gate:
        return "run", {}
    dangerous, key, description = detect_dangerous_command(command)
    if dangerous and key not in granted:
        return "ask", {"pattern_keys": [key], "description": description}
    return "run", {}
