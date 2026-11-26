"""Device side: judge a host's command with THIS machine's own Hermes approval rules (design D25).

Hermes's own command gate runs in the host session first, as Hermes always runs it (its card, its
session/always answers). When a person or Hermes's rules approved the command there (``host_gate``), this
device adds only its floors. A command that did not pass that gate (``host_gate`` false) gets this device's
full rules, through Hermes's public ``tools.approval_judge.judge_command``:

- ``block``: one of this device's floors (hardline, runtime self-delete, ``sudo -S`` guess, its own
  ``approvals.deny`` rules), a command its hardline scan cannot read to the end while approvals are off, or a
  rule check that could not run. Final; nobody can approve it.
- ``ask``: this device's dangerous-command patterns flag it and nothing here pre-approves it (its approval
  mode, its permanent allowlist, its saved "always" answers). The host must get a yes from the human in the
  session and resend with ``approved_keys``.
- ``run``: clean, allowlisted, already approved, or this device runs with approvals off.

Without that seam (an older Hermes) every command is refused.
"""
from __future__ import annotations

from typing import Any, Iterable

NO_JUDGE = "this device cannot check commands against its Hermes rules (its Hermes is too old for this Tether)"


def judge(command: str, approved_keys: Iterable[str] = (), host_gate: bool = False) -> tuple[str, dict[str, Any]]:
    try:
        from tools.approval_judge import judge_command
    except ImportError:
        return "block", {"reason": NO_JUDGE}
    verdict = judge_command(command, approved_keys=approved_keys or (), gate_approved=bool(host_gate))
    if verdict.verdict == "block":
        return "block", {"reason": verdict.reason or "blocked by this device's Hermes rules"}
    if verdict.verdict == "ask":
        return "ask", {"pattern_keys": list(verdict.pattern_keys), "description": verdict.description or ""}
    return "run", {}
