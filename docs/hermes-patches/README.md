# Hermes core patches proposed upstream

These are changes to **Hermes itself**, not to the tether plugin. Tether runs every computer-use call on the
device through the device's own Hermes backend, so a fix here reaches remote use with no plugin change, and it
fixes local Hermes the same way. Nothing here is installed by tether.

## focus-app-other-spaces.patch (Hermes 2bd378ed1b, `tools/computer_use/cua_backend_capture.py`)

**Problem (found live 2026-11-06).** `computer_use focus_app` cannot reach an app whose windows are on another
macOS Space, which includes every **fullscreen** app (each gets its own Space). Hermes's backend always asks the
driver for `list_windows` with `on_screen_only: true` (line 175) and matches only that list (line 390), so the
model gets `No on-screen window found for app 'Claude'` even with `raise_window=true`. cua-driver itself lists
windows on every Space by default and its `bring_to_front` switches Spaces.

**Change.**
1. Only for `raise_window=true` (already a separately approved foreground action): when no window on the current
   Space matches, match across all Spaces (rows that have a Space id; rows without one are hidden helper
   surfaces) and `bring_to_front` the frontmost match. Background focus keeps the current-Space rule: a window the
   user cannot see is never driven in the background.
2. Without `raise_window`, a match on another Space returns `code=window_on_other_space` with a message that says
   so and names the fix (`raise_window=true`), instead of the misleading "no on-screen window".
3. In macOS fullscreen the app's own title-bar strip is a separate window stacked above the content window, so
   cua-driver's strict check reports `bring_to_front_exact_window_unverified` although the target window has
   focus and its process is frontmost. When the driver's own observation shows exactly that (focused window ==
   target, frontmost pid == target pid), the raise counts as done (`bring_to_front_focused_own_app_above`).

4. (v2, found in the host agent's round four) When part 3 accepts the raise, the whole result now says so: `verified=true`,
   `effect=confirmed`, no `escalation`, `status=activated`; the driver's own answer is kept as `meta.driver_verdict`.
   Before this, `ok` was true but the driver's `status: partial` was still in the result, and the model read it as
   unverified.
5. (v2) Capture target on macOS: when the frontmost candidate is an untitled window and the same process has a titled
   window behind it, capture the titled one. In fullscreen the frontmost is the app's 24 px title strip, so a
   capture of fullscreen Claude came back `1440x24`. (PR NousResearch/hermes-agent#29031 prefers titled, large windows
   for explicit app captures too.)

**Live check on a real Mac** (cua-driver 0.28.2, macOS 26.6.2; Claude fullscreen on Space 435, Hermes on Space 1;
`focus-app-other-spaces-live-check.py`, Space ids only, no screenshots): see
`focus-app-other-spaces-live-result.txt`. Old code fails; new code switches to Space 1, explains the no-raise case,
and comes back to the fullscreen app on Space 435. v2 (`focus-app-other-spaces-live-check-v2.py`,
`focus-app-other-spaces-live-result-v2.txt`): capture target on Claude's Space moves from the strip (38792, untitled)
to the content window (38782, "Claude"); the accepted raise reports `verified=True effect=confirmed status=activated`.

**Upstream status (checked 2026-11-06).** Already reported: NousResearch/hermes-agent#142478 (open, same root
cause, its author runs a local patch and offers a PR) and PR NousResearch/hermes-agent#29031 (open since May, lists
all Spaces for explicit captures). So the right move is to add our live evidence and the raise-only approach to
#142478 / #29031, not a competing PR. Part 3 (fullscreen title strip) is still needed on cua-driver **0.38.0**
(tested 2026-11-06 after updating the Mac): its per-process check from trycua/cua#3785 reports
`front_in_process_on_display=false` because the app's own title strip is the process's front window
(`focus-app-other-spaces-live-result-driver-0.38.txt`). A cua-driver issue for the strip case is the upstream fix.

**Still to do before posting upstream:** run Hermes's `tests/tools/test_computer_use.py` against the patch and add
unit tests for the three cases (needs pytest, which the Mac's Hermes venv does not ship).

## Applied locally (Mac only), 2026-11-06

Applied to the Mac's Hermes checkout (`~/.hermes/hermes-agent` @ 2bd378ed1b) with `git apply -p1`, because the Mac is
the tether device and runs every computer-use call through its own Hermes backend (the home server only forwards). The
managed runtime imports the patched file (checked), and the Mac's gateway was restarted. Re-applied as v2 the same day
(installed file byte-identical to the tested one; 47 lines added).
Original: `~/Backups/hermes-patches/cua_backend_capture.py.orig-2bd378ed1b`.

Undo (one command, then restart the gateway):

    git -C ~/.hermes/hermes-agent checkout -- tools/computer_use/cua_backend_capture.py && hermes gateway restart

`hermes update` autostashes local changes (the checkout already holds `hermes-update-autostash-20261016-005809`),
so after an update the patch may sit in a stash rather than in the file: re-apply with
`git -C ~/.hermes/hermes-agent apply -p1 <this folder>/focus-app-other-spaces.patch`, or drop it once
NousResearch/hermes-agent#142478 / #29031 lands.
