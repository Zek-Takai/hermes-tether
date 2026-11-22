# Changelog

## 0.3.0 (unreleased): approval with a code from your phone, and the session lock

### Update notes

- **Update the host and every device together.** Pairings stay.
- **Set up the authenticator once for all your machines.** After the update every device refuses remote use until an
  authenticator is there, so run `hermes tether authenticator setup` yourself, at one machine (README, *Set up the
  authenticator*; about two minutes with your phone), then add each other machine with `hermes tether authenticator
  export` and `join` (below). It asks for no password and shows no administrator or User Account Control dialog.
  There is no Yes/No box any more.
- **macOS locks remote commands; Windows runs them unlocked by default.** On a Mac, every command a remote session
  runs is held by the session lock (below). Windows has no such lock, so a PC runs remote commands unlocked, as in
  0.2; each machine's owner can change this on the Tether panel (*Run remote commands unlocked*).
- **The normal risks of computer use remain.** An approved session acts as you: screen control, other programs,
  this machine's own Hermes and things left to run later are not covered by the lock (README, *What the session lock
  does not cover*).

### Changed

- **The Allow click is replaced by a code.** The first use of a session opens a box on the device that asks for
  the 6-digit code from the authenticator app on your phone (RFC 6238; 1Password, Proton Pass, Google
  Authenticator and the like). A valid code approves; Cancel, no code or wrong codes deny. Nothing that can only
  click (another program, the agent's own screen control, someone at the machine without your phone) can approve,
  and nothing on the host can approve at all: the link carries no code, so forwarded or injected text, another
  program on the host or a stolen host key can at most make the box appear. The code is checked on the device and
  never travels.
- **Each code works once**, also after a restart; codes typed before Hermes restarted are never accepted after it.
  Three tries per box; after every 5 wrong codes in a row code entry pauses (5, 10, then 20 minutes); after 20 it
  locks until you unlock it at the computer with a recovery code. The record of used codes is sealed with the
  authenticator's secret: a program that deletes or edits it locks code entry instead of resetting it.
- **The box names the host as you paired it** (and when), the session, and the time it closes; a host that renames
  itself later cannot change that.
- **Nothing reaches the screen while the box is open**, screenshots included, and the box waits for a screen action
  already running.
- The box waits 60 s by default (20-600 s; was 15 s, 5-600 s).
- **The idle limit defaults to 60 minutes** (was 15); each machine still sets its own, from 1 minute to 24 hours.
- The agent is told never to ask you for a code, and every refusal reaches it as a fixed sentence.
- The host's label recorded at pairing is checked by shape before it is kept (it names the host in the box).

### Fixed before release (security review G3)

- **File tools could reach Tether's and Hermes's files around the path check** (`..` after a link, the
  `/System/Volumes/Data` and `/.vol` names, several paths in one search, a relative path inside a patch, a link
  flipped between the check and the use): they now run inside the session lock (above).
- **The `hermes` launcher and the `ai.hermes` launch agents** could be edited by renaming their folder away and
  back; those folders are now locked against rename.
- **A skill copy** could be made to write outside the session's workspace by swapping its folder for a link while
  it ran; it now writes only inside folders it holds open.
- **Authenticator setup** crashed when a folder or a link sat where its busy marker goes, and a replacement whose
  record could not be written left code entry locked; both now end cleanly (a plain message, or the earlier state).
- **Stopping a background job** reported success when the session had written the job's exit file itself; what
  still runs of the job now decides.

### Added

- **One authenticator for all your machines, moved by a locked file** (D85). The app entry is `Hermes Tether` on
  every machine. `hermes tether authenticator export [folder]` (default: your Downloads folder), run at a machine
  that has the authenticator, first asks for the current code or a recovery code, then shows a one-time 80-bit
  transfer phrase in a box only (never in the terminal or a log) and writes `tether-authenticator.transfer` (0600,
  atomic, never overwriting, never through a link) in the folder you name. The file is JSON sealed with AES-256-GCM
  under a key made from the phrase with scrypt (n=2^15, r=8, p=1), over the seed, the recovery codes' fingerprints
  and the entry name; the header fields are associated data, so a changed header field or sealed byte is refused. On the new machine,
  `hermes tether authenticator join <file>` asks for the phrase (five tries, then nothing changes) and the 6-digit
  code your app shows for `Hermes Tether`, then commits the same seed through that machine's own seal (D78); on a
  machine that already has an authenticator it first needs that machine's current code or a recovery code. The last
  box offers to delete the file (default Delete), only when it is a plain file. A recovery code works on every
  machine that holds the same fingerprints (each machine records its own used codes). A replacement (setup or join)
  now says in a box that the other machines still use the old authenticator and must export and join again.
- **The setup shows the new key as a QR code to scan** (D84): the box on a Mac draws it with the system's own QR
  generator (Core Image), on a PC with the `qrcode` package when it is installed, and the key stays under it as
  text for an app that cannot scan. The code and the key travel only into the box (on its standard input), never
  into a terminal, a log or a file, and the code the app makes still has to match before anything is saved.
- **Tether's 2FA secret is kept the way Hermes keeps its vault key** (D78): sealed with Tether's key passphrase as
  before, or with a key in the OS keychain when Hermes is set to `vault.key_storage: keychain` and that keychain
  answers (the same keychain, the same read-back check, no step of its own); the record says which seal wrote it, a
  changed setting re-seals it, and nothing is asked of anyone.
- **The authenticator's secret is a sealed file in Tether's data folder**, `authenticator.json` next to
  `identity.key.enc` (0600, written in one step, never through a link): on a Mac sealed with Tether's key passphrase
  (AES-256-GCM), on Windows with DPAPI for your account. Hermes opens it at start without asking anything and keeps
  it in memory. No keychain, no password box. It never reaches a log, the link or the host, and devices mask it in
  their output. On a Mac the session lock keeps a session's commands and file tools away from it.
- **Setting up, replacing and removing the authenticator** (`hermes tether authenticator setup | remove |
  recovery-codes | unlock`), only at the device and only through boxes on its screen. Turning it on needs no other
  proof (remote use is refused until then, so no session can run it); replacing or removing it needs the current
  code or a recovery code; unlocking code entry needs a recovery code, never an app code. With neither ("Lost
  both"), Tether changes nothing and says how to start over by hand. The key is made on the device and shown once as
  a setup key; nothing is saved until a code from the app matched it and ten one-time recovery codes were shown. A
  first code that matches minutes away says the clock is wrong. No code or key is taken on the command line, from
  stdin or over the link, and none is printed, logged or written in plain form. Remote use is paused while a setup
  runs. The command, and `hermes tether join`, refuse to run in a remote session's or an agent's shell.
- **The session lock (macOS devices).** While a remote session is connected, every command Tether runs for it
  (terminal, background jobs, `execute_code` scripts and what they start) runs inside macOS's sandbox: it cannot
  change Tether's installed files or the device's Hermes (its home and profiles, install, Python, plugins, launcher,
  launch agents), and cannot read Hermes's home (Tether's key, pins and authenticator files, `.env`, credentials,
  settings, and that machine's own Hermes skills, memories and logs) beyond the session's workspace. Tether's file
  tools (read, write, patch, search) run inside the same sandbox, in one helper per session (this machine's Python
  running Hermes's own file tools), so macOS refuses them the same files however a path names them; Hermes's hooks
  and approvals still see each call first. The first file call of a session takes about a second longer; later
  calls cost well under a millisecond more. You and the device's own Hermes are unaffected. Where the lock cannot
  be applied the command or file call is refused, never run unlocked. Windows has no lock: file tools run in
  Hermes's process there, behind Tether's path check.
- **Run remote commands unlocked** (`allow_unlocked_commands`) on the Tether panel of each Mac and PC: off by default
  on macOS (on runs a session's commands without the lock, and the approval box says so), on by default on Windows
  (off refuses remote commands there). A change waits until no remote session is connected.
- **A computer-use disclaimer** in the README: what the session lock does not cover.
- `hermes tether status`, `hermes tether join` and the Tether panel say whether the authenticator is on and how to
  turn it on; the panel never offers to set it up.
- **For maintainers** (not shipped in the plugin): `scripts/hermes_watch.py` and a Hermes cron job
  (`scripts/hermes_watch_cron.sh`) report when a new Hermes release changes a Hermes function Tether wraps, copies or
  depends on, so Tether is checked before anyone updates Hermes. The device itself never compares Hermes's source.

## 0.2.0 (2026-11-20): security release

Update the host and every device together: the link protocol changed (major 2), and a 0.1 side is refused
with a message that says so.

### Thanks

- **@projetsjsl** found that the test suite fails when it runs from inside a live Hermes session (it cleared
  `HERMES_SESSION_ID` but not `HERMES_SESSION_KEY`) and sent the fix in
  [#1](https://github.com/Zek-Takai/hermes-tether/pull/1). Their change is in this release as they wrote it.
  Checking it led to the wider review behind this release.

### Fixed

- **An Allow belongs to the caller that got it.** Any program running as the host's user could send calls
  through the host's relay socket for a session the person at the device had already allowed. The device now
  hands its Allow to the one caller that asked (a grant token held only in that process's memory); anyone
  else is asked for again. Denials start a short cool-down and prompts are rate-limited.
- **A lost connection is said, never replaced by the host.** After a Hermes restart (a clean exit included),
  in a second Hermes process, after a time-out, a denial, a switch, a re-pair or a new session id from Hermes's
  compression, the next command or file call meant for the device ran on the host without a word. Now nothing
  more meant for that device runs in that turn, terminal and file tools alike, and the agent is told.
  Sub-agents, `/bg` runs and a new conversation share the chat's terminal but work on the host, and no longer
  use up, release or trip that refusal; the host's own files stay usable.
- **The key passphrase is kept out of sight.** The documentation promised it; 0.1 did not do it. The
  passphrase now leaves every Hermes process the plugin loads in, first thing and whatever the role (a typo in
  a setting no longer leaves it behind), including the start-up copy of the environment that `ps -E` and
  `/proc/<pid>/environ` show. No terminal the plugin makes gives it to a command, also on a gateway that serves
  several profiles and right after Hermes reloads `.env`; Hermes's own terminals lose it again at every tool
  call. It is masked in tool output, also when Hermes's home is reached through a symlink, and each device
  masks its own passphrase in everything it sends back.
- **Only the user's own words open a machine.** `tether <device>` must now start a line you typed. Quoted
  replies, forwarded mail in every client's shape, chat forwards the gateway marks, attachment notes, link
  previews, other agents' messages, scheduled jobs, sub-agents, webhook runs and third-party integrations
  (`--source tool`) no longer count, even when they contain the phrase.
- **Only the user's own turn reaches a device.** Work from a background review, a scheduled job or a
  sub-agent, from Hermes's own follow-up turns (`/goal` and `/loop` steps, heartbeats, background-job and
  sub-agent wakes, Bot Chat deliveries, other agents' messages), or after a stopped turn, stays on the host.
- **Tethering works in Telegram observe-mode groups and Slack threads.** In a Telegram group with observe
  mode on, `tether <device>` and `untether` were always refused; an `@bot tether mac` in a Slack thread that
  already had a session was always refused, and the refusal sent the user round the same loop.
- **The user's line picks the machine.** With `mac` and `mac-mini` paired, `tether mac mini` could open
  `mac`; now it opens only `mac-mini`.
- **Revoked keys stay out.** Unpairing or re-pairing a device cuts its live link within a few seconds, including
  a connection that was held open across the change; the host owner answers one pairing request at a time.
- **A device cannot steer the agent with text.** What a device says about itself is checked against what it
  can be: the agent, the panel and the pairing prompt see an OS, shell and architecture from fixed lists and
  version numbers, never the words after a number. A device's refusal of a connection and the path of a skill's
  copy no longer pass its own text to the agent, and a listing shows no home folder.
- **Real machines are described correctly.** Fedora, RHEL, Amazon Linux and WSL2 kernels keep their version
  number, more architectures are known (armv8l, x86, loongarch64, ppc64, mips64), Windows 11 is reported as 11,
  and a name re-paired with another machine no longer shows the previous machine's facts or home.
- **Work stays on the right machine.** Background jobs are checked and stopped where they started, whoever
  asks (a sub-agent's teardown, the parent, a stop from the chat) and whatever the route is now; files in
  the host's own Hermes home stay on the host (and the device's own workspace stays on the device, also when
  the device runs a named Hermes profile); `~/...` paths stay the device's on a host whose home folder is its
  Hermes home (Hermes's Docker image); a file call meant for a device never falls back to the host, even when
  the device's reply is malformed; a large host result is never copied to a device; an image in the host's
  Hermes home is read on the host.
- **Hermes's own checks apply to file calls on a device.** The host's `pre_tool_call` hooks (block, approve,
  modify), the compression-marker guard, the loop guardrails and ACP (Zed) edit approval now run before a
  file call goes to a device, and the device runs it with its own hooks.
- **A device's secrets stay out of attachments.** A Windows device's home is given to Hermes in Git Bash form,
  so Hermes's attachment denylist matches there; every file attached from a device is also checked against
  the device's own Hermes home (on Windows `%LOCALAPPDATA%\hermes`; the session workspace excepted). A
  device's home of an unusual shape is not used at all.
- **Stop reaches the device.** Stopping a turn, a timed-out call, a dropped link, closing the session or
  Pause ends the command running on the device, and a command still waiting for its terminal or a screen
  action still waiting for the driver never starts. A screen driver call that never returns no longer blocks
  the device's terminal, file and close calls.
- **Pause stops what is already running.** Pause refused new calls, but a running command finished and sent
  its output back, and a screen action waiting its turn still clicked. Within a second, Pause now drops the
  link (stopping every call in flight and closing an open Allow prompt) and ends every session.
- **The Allow prompt and the host agree on time.** With a consent wait longer than the host's fixed 90 s, an
  Allow given after 90 s never counted; and any cancelled prompt left its dialog on screen with the screen
  unfrozen. The prompt now never stays up after the host has stopped waiting, `tether <device>` waits for the
  device's own consent wait, and a prompt that ends unanswered takes its dialog with it.
- **The host's label is checked before it reaches the Allow prompt**: only a short plain name is shown.
- **A background job's stop is real, and said.** Hermes's stop ended only its own wrapper and the command ran
  on; now the whole job ends (on the device or the host). A stop that did not happen is reported as an error,
  never as "killed", and a device that drops off for a moment no longer loses its jobs. On a Windows device a
  stop does nothing and says so.
- **`execute_code` leaves nothing running.** Hermes's persistent remote kernel left a runner on the machine and
  was later probed and stopped by pid through whatever the route was then; over tether each script now runs as
  one command (no state carries over between calls).
- **A background command asks once.** Hermes's own wrapper around a command its gate already checked, and
  `execute_code`'s own clean-up, no longer show a second approval card.
- **The idle limit holds between turns**, counts time the host was asleep, never closes a session while a
  command is still running on it, and switching to another device closes the first one. A call that runs past
  its time limit now returns at once with that error instead of hanging.
- **A grant token goes only to the machine it came from.** A program that edited the host's pairings could point a
  device's name at its own key and receive the session's token when the session closed (idle sweep, time-out,
  background poll, `untether`, a switch), or when the name was re-pinned while the Allow prompt was up. Every call and
  every close now goes only to the key that issued the token; renaming a device closes its session there properly.
- **Both machines count idle time the same way.** The device counted from the start of a call, so after a long command
  it could drop the Allow (and empty the workspace under a running command) while the host still showed the connection
  open. Idle time now counts from the end of the last call on both sides, a running call never times out, and the host
  closes a moment before the device would.
- **A lost reply no longer costs the Allow.** When the call that got the Allow failed, was stopped, or was one of a
  parallel batch, the next call raised a false "a different program is asking" prompt and `untether` left the grant
  and workspace behind. The same caller now keeps its Allow, and a failed first call leaves nothing behind.
- **One workspace per live session.** A look-alike session id (other letter case, or the folder name) could empty a
  live session's workspace without its token. It is now refused, and closing never empties another live session's
  folder.
- **Pairing a device again keeps the host's idle limit for it.**
- **Tether cleans up after itself.** Closing a session removes everything Tether created for it; the link's
  temporary certificate copy is written only when the stored one does not match and is deleted right after it is
  loaded; the test suite leaves nothing behind. Files you made are never touched. A session that ends on the device
  without a close (its idle limit, Pause, a re-pair) is ended there too, its terminal and shell snapshot included, so
  a new Allow never inherits it; a live session's terminal is no longer ended by another session after 30 idle
  minutes.
- **Cleanup stays inside Tether's own folder.** A link put in place of the device's sessions folder, a
  workspace or its `skills` folder made the cleanup (or a skill copy) delete and chmod what the link pointed to;
  a file hard-linked into a workspace (a local `git clone`) lost its mode; a locked file or an ACL crashed the
  close, the sweeper and the device's start. Now links are removed and never followed, mounted volumes are
  never entered, a hard-linked file keeps its mode, lock and ACL, and nothing in a cleanup raises. Anything the
  agent moves into its workspace goes with it.
- **Session ids with control, format or line-separator characters are refused** before they reach the Allow
  prompt or a log.
- **A damaged open-session record no longer breaks `devices use` or the idle sweep.**
- **A host that cannot listen at start-up recovers on its own.** If the listen address was not up yet at boot,
  the port was taken or a pin could not be loaded, the host link stayed down in every Hermes process until a
  restart. Now the link is kept and listening is retried every few seconds.
- **Pairing says what happened.** A device that gives up while the owner reads `Pair it?` is no longer pinned
  (the owner was told the link expired); `hermes tether unpair Mac` finds a device paired as `pair Mac`; `local`,
  `host` and `all` are refused as names, as in the panel.
- **Pairing link off the command line.** `hermes tether join` now asks for the link at a hidden prompt (or
  reads it from stdin); the device shows its own key so you can compare it with the host's prompt.

### Changed

- The documentation no longer says the agent can never read the link's keys. A program running as a machine's
  user can read its key file and passphrase, the agent's terminal included (on a device, during a session its
  person allowed); Tether keeps the passphrase from showing up by accident. README, *What it does not protect
  against*, says what a stolen key allows and how to replace it; DESIGN D40.
- Tether logs a warning at start when this Hermes lacks one of the private functions it relies on for Stop,
  masking or recognising background runs.
- `tether <device>` opens only at the start of a line ("Tether mac and open Bambu Studio" works,
  "please tether mac" does not), with `tether` and the name on that one line.
- In a mail only the first line of the body counts, for `tether <device>` and for `untether`; the quote
  or forward a mail client puts below it is ignored, and a mail with a forward subject (Fwd:, FW: ...)
  counts as none.
- `/goal` and `/loop` no longer carry on device work by themselves: their follow-up turns work on the host,
  and your next message picks the work up on the device again.
- The consent prompt always shows the session id; a caller can no longer supply its own title for it.
- Saying `tether <device>` again on an open connection no longer resets the idle timer. After the limit has passed or
  the device was paired again, it asks the person at the machine again.
