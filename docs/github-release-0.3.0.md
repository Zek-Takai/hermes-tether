# Hermes Tether 0.3.0: security release

Every remote session now needs a code from your authenticator app, typed on the machine being used. This release
also fixes the security issues found in 0.1.

## Update

- Update the host and every device together (the link protocol changed; a 0.1 side is refused with a message).
- Requires Hermes 0.23.3 on both machines, on Hermes's own Python 3.14 runtime.
- Once per device: `hermes tether authenticator setup` in a terminal at that machine. Scan the QR code with your
  authenticator app, type the first code, save the ten recovery codes. Remote use is refused until this is done.
- More machines: `hermes tether authenticator export` on a set-up machine, then
  `hermes tether authenticator join <file>` on the new one (one authenticator for all machines).
- macOS runs a remote session's commands in a sandbox. Windows has no such lock, so its remote commands run unlocked
  by default (`allow_unlocked_commands` on the Tether settings page; off by default on macOS).

## Commands

**Set up, in order**

1. Install `plugin/tether` into each Hermes's plugins folder, set the host's and each device's `config.yaml`
   (README: Install), and restart each Hermes. For screen control of the devices, also install `plugin/tether_screen`
   on the host only and set `computer_use.backend: tether_screen` there: it sends Hermes's own computer-use actions to
   the tethered machine, whose Hermes performs them.
2. Host: `hermes tether pair <name>` (prints a one-time link).
3. Device: `hermes tether join` (paste the link at the prompt).
4. Device: `hermes tether authenticator setup` (scan the QR code, type the first code, save the ten recovery codes).
5. Each further device, after pairing it: `hermes tether authenticator export` on a set-up device, then
   `hermes tether authenticator join <file>` on the new one.
6. In a chat with the host's agent: `tether <name>`, then type the code from your app into the box on that machine.

**In chat**

| Command | What it does |
|---|---|
| `tether <name>` | Open a session on that machine (needs a code typed there) |
| `untether` | Close the session (a message on its own) |

**Host**

| Command | What it does |
|---|---|
| `hermes tether pair <name> [--advertise <address>]` | One-time pairing link for a new device |
| `hermes tether unpair <name>` | Forget a device |
| `hermes tether status` | Pairing state |

**Device**

| Command | What it does |
|---|---|
| `hermes tether join` | Pair with a host (paste the link) |
| `hermes tether unpair` | Forget the host |
| `hermes tether status` | Pairing state |
| `hermes tether pause` / `resume` | Refuse all remote use now / allow it again |
| `hermes tether authenticator setup` | Turn on the authenticator, or replace it |
| `hermes tether authenticator export [folder]` | Locked transfer file for another machine (needs a current code) |
| `hermes tether authenticator join <file>` | Use the authenticator from a transfer file |
| `hermes tether authenticator recovery-codes` | New recovery codes; the old ones stop working |
| `hermes tether authenticator unlock` | Take codes again after too many wrong ones (with a recovery code) |
| `hermes tether authenticator remove` | Turn it off (remote use is then refused) |

## Why the 2FA change

- The host can be fooled into asking for a machine: forwarded or quoted text, Hermes's own injected turns, another
  program on the host, or a stolen host key. In 0.1 one click on the device's Yes/No box was all that stood between
  any of these and the machine.
- A click can come from habit, from another program, or from someone else at the machine. A code from your phone
  cannot. Nothing on the host and no button on the device can approve a session.
- The code is typed into the box on the device and never travels to the host or an agent.
- No new sign-in: the secret is kept the way Hermes keeps its own vault key.
- One authenticator covers all your machines. It moves to another machine in a file locked with a one-time phrase,
  which you carry yourself; it never passes through the host or an agent, and making the file needs a current code.

## Findings and fixes

| Area | Found | Fixed |
|---|---|---|
| Approval | One click on the device approved a session | 6-digit authenticator code per session; each code once; lockout after repeated wrong codes |
| Approval | A program on the host could ride an open session or open its own | Every call needs the session's grant token; a call without it gets only a code box |
| Words gate | Forwarded mail and messages, quoted text, bot messages and Hermes's injected turns counted as the user's request | Only the user's own typed line can ask to open a machine |
| Session lock (new) | An approved session could change Tether's or Hermes's files or read their secrets | macOS: session commands and file tools run in a sandbox that refuses Tether's and Hermes's files and secrets |
| Secrets | The key passphrase stayed in the process's start-up environment and reached shells | Removed from the start-up environment; Tether's shells start without it |
| Connections | After a lost connection, device work could run on the host; sub-agents and background runs shared the parent's state | State per session and turn; device work is refused, never run on the host |
| Grant tokens | A token could reach a renamed machine; look-alike session ids shared a workspace | Token bound to the key that got it; look-alike ids refused |
| Stop and Pause | Pause and stop did not end work already running; a failed stop reported success | Pause and stop end running work; results are reported honestly |
| Background jobs | Stops went by the current route, not the job's machine | Stops and status checks go to the job's own machine |
| Cleanup | Workspace cleanup could follow links | Cleanup never follows links and removes only what Tether made |
| Paths | Some `~/` paths went to the wrong machine (Docker layouts) | Path ownership decided before forwarding |
| Pairing | Pins were written before their files; failed starts were not recovered | Write order fixed; failed starts recover |

Tested: the safeguards in this release were reviewed and attacked with Claude Code (Anthropic), through repeated
multi-agent security reviews, attack scripts and a live test, and independently inspected with Kimi K3 (Moonshot AI)
before release, which found no remaining issues. 677 unit tests pass on Python 3.11 and 3.14, 265 attack scripts are
refused, and a live test showed that an unpaired machine gets nothing, the passphrase is in no process environment,
another program on the host cannot run anything in an open session or open its own, and a session cannot read the
authenticator, Hermes's secrets, or write to Tether's files.

## Limits

- The normal risks of computer use remain: screen control can type into other apps, a session can ask other programs
  to act, and anything left to run later runs outside Tether. Approve only sessions you asked for.
- Programs running as you outside a session can read what you can read, including Tether's stored secret.
- Windows has no session lock; its remote commands run unlocked by default.
- Linux devices are refused (no code box).

## Thanks

@projetsjsl for #1 (the test environment leaked a session key into the suite).
