# tether — design v1 (draft)

> Working name. A Hermes plugin that gives one remote Hermes agent the **local capabilities of any
> paired machine**: its terminal and files, its real screen, its own MCP servers and skill tools, and
> what is installed where. Hermes connecting to Hermes. Hackathon entry, due 2026-11-11.

## 1. Decisions this design follows (the author, 2026-11-05/06)

| # | Decision |
|---|---|
| D1 | "Control my PC": one remote agent, full desktop capabilities on any paired machine; one agent, many devices. |
| D2 | **Host** = the agent's own Hermes (its sessions, memory, skills live only there). **Devices** = paired machines that lend their tools. Works through both the CLI and Desktop. |
| D3 | Hermes-to-Hermes: each device runs Hermes itself. What the remote agent may do on a device is decided by **that device's own Hermes settings** (Desktop or CLI). No second permission system. |
| D4 | **No new permission path.** Remote actions enter the device's Hermes through the same tool and approval path as local ones; OS permissions (macOS Accessibility / Screen Recording) are granted once, as for local use. The plugin's only new surface is the connection. |
| D5 | Pairing via a **master link that generates the code**; every boot an **automatic encrypted handshake**; **256-bit** encryption; no token you paste around. |
| D6 | Scope = **remote AI with local capabilities**: terminal/files, screen, opening pages and viewers, knowing what is installed and where, each skill's local tools. |
| D7 | Nothing extra for users to install beyond the plugin itself. |
| D8 | Approval UX (always-grants, phone approvals, bounded manifests) is tuned after it works end to end. |
| D9 | The CuaDriver shadow bug (hermes-agent #142314) is documented, not auto-fixed. |
| D11 | **Encryption suite is chosen automatically and non-invasively**: the user gets the best 256-bit connection for their device ↔ host pair; nothing on their system is changed. |
| D12 | **Desktop machines only.** Not for headless control: SSH already covers headless boxes, and they need no viewing or opening things. The plugin has no effect on headless or SSH setups. |
| D13 | **Keys and secrets follow Hermes's normal secure path** (the system's secure store, as Hermes already does). The plugin never asks for keychain access itself, and **the agent can never read the keys the link uses** ("Hermes should never have access to the very thing it uses"); this blocks prompt-injection exfiltration. |
| D14 | **No control-arbitration layer.** Screen control is Hermes's built-in computer use, used as is (background-first input, no forced takeover); the plugin adds and changes nothing in that skill. |
| D15 | **A grant survives a reconnect** (link drop/return within the session and idle window keeps it). |
| D16 | **Long-running/background commands**: whatever is needed, as long as it conforms to Nous's plugin rules (public plugin API only, no core changes). |
| D17 | **Protocol versioning** (Claude's call): `hello` carries a protocol version; same major version required, otherwise a clear refusal naming both versions and the fix. |
| D18 | **Exposure follows Nous's rules**: authenticated non-loopback binds only; LAN/VPN/tailnet recommended per Hermes docs; nothing internet-facing by default. Docs cover the device's Hermes needing to run, plus an "offline: Hermes not running" status. |
| D19 | **Logging = Hermes's normal method** (its agent/tool logs and session records); no separate audit store, since agents can make thousands of calls. |
| D20 | **No host→device SSH, and either Desktop route.** The plugin must work without the host having SSH to the device (that defeats the purpose; tonight's SSH terminal backend and driver wrapper are stand-ins to remove), and with Desktop attached to the host by **either** route Hermes offers: *Remote gateway* (URL + login) or *SSH gateway*. The link is independent of that route; both are in the test matrix, plus the check that the device's own local Hermes keeps running in each mode. **Verified 2026-11-08:** Remote gateway (host in Docker) and SSH gateway (host on a Linux workstation, connected as the install's own user) both tethered the Mac with no host→device SSH. |
| D21 | **The device's rules apply on the device** (the author 2026-11-06: "make sure the ai understands that local rules do not apply to remote rules and to use the hermes desktop or cli which ever its actually connected rules and permissions"). Found live: Hermes's file tools judge paths with the HOST's rules (its homes, its `HERMES_WRITE_SAFE_ROOT`), so the NAS fence blocked every Mac path and the Mac's `~/.ssh` was not in the host's credential list. While a device is the session's target, the file tools' two path checks run on the device with its own Hermes rules (`path_check`, `pathpolicy.py`); unreachable = fail closed. `devices use` and the tool description tell the model the device's rules apply and a refusal is final (no routing around it via the terminal); the device announces whose rules apply. |
| D22 | **Device mode** (the author 2026-11-06: "make the plugin treat the session as local instead of chasing each tool… uses the device as if it was her host pc"). While a device is a session's target the session works ON it, through public plugin surfaces only (catalog rule 9): `tool_execution` middleware hands the file tools (read_file, write_file, patch, search_files) whole to the device, where `ctx.dispatch_tool` runs them in the device's own Hermes (its paths, file rules, write fence, credential protections; relative paths resolve against the session's device cwd); terminal and computer use keep their paths (tether backend, tether_screen), with the session's approvals. A `pre_llm_call` hook tells the model once per turn which machine it works on and that its rules apply, so no per-tool coaching. Replaces D21's path shim (which rebound two core functions). Every surface registers in every role and is inert until a role is set (declared == registered). Next: device-side approval relay so terminal/computer use can be handed over whole too. |
| D23 | **Only the user's words open or close a device connection** (the author 2026-11-06: "this plugin trigger should be a prompt like i have been doing we are running on (device)… if i start a new session shes back on home. if the timer ends shes back on home, if i say close (device) connection it closes"). `pre_llm_call` records the user's own message: `devices use <name>` is accepted only in a turn whose user message names the device, and close only when it asks to close/disconnect/go home; the model's own calls, tool results and page text cannot switch machines. A new session starts at home; the device's `grant_idle_minutes` (announced) closes it after idle. Device work routes only inside a user turn (`pre_llm_call` → `post_llm_call`); Hermes's background review (thread `bg-review`, prompts "Review the conversation above…") never opens a turn, so its edits stay on the host. File-tool paths inside the host's own Hermes home (skills, memories) always stay on the host. Closing clears the attachment fallback (no pulling from the device after close). |
| D24 | **Per-session workspace on the device** (the author 2026-11-06: "the home folder is a temp space that allows the actions to exist… when the port closes the home folder empties so that no one can access it or action taken to try and reverse the flow"). `<device data>/tether/sessions/<session>/` (0700) is where the session's terminal starts; the rest of the machine is reached from there under the device's own rules. `skill_view` while on a device copies that skill's folder read-only into `<workspace>/skills/<name>/` (tar, `filter="data"`, 20 MB cap, via the public `transform_tool_result` hook) and tells the model the path; skills are still changed only with `skill_manage` on the host. On close (user, timer), the device revokes the session's grant and removes the workspace (`close_session`, never asks for consent); a sweeper removes workspaces of lapsed grants within a minute; a device start wipes leftovers. |
| D25 | **Hermes's own gates run, one per kind of action; the device adds its own rules** (the author 2026-11-07: "allow commands that are run must execute on the tethered device not the host. only on host when the connection is severed. the one eception is allowing the host hermes do what it does for making changes and such" and "the request tool should depend on what it is … if we cant use the direct hermes rules then copy their rules and apply them in a way the plugin can do it. i understand the mac rules but hermes has its own rules we must use and follow"). Nothing in Hermes's approval path is skipped (the tether backend is not a container): in the host session a terminal command meets Hermes's dangerous-command gate (its card, session/always answers, smart mode, yolo), `execute_code` meets the execute_code gate, computer use its per-action cards, file tools the device's own Hermes (D22). While a device is the target the command runs only there; when Hermes's command gate checked it (noted by the provider's `skip_container_guards` read, which always returns false), the device adds its floors (hardline, runtime self-delete, `sudo -S` guess, its `approvals.deny`), so nobody is asked twice. A command that reached the device without passing that gate (an `execute_code` script's commands, internal calls) is judged by the device's full Hermes rules (`device_rules.judge`), and a flagged one goes back through Hermes's public `check_dangerous_command` in the host session before it runs. If the gate checked a command for a device and the connection closed before it ran, it runs nowhere. Missing Hermes helpers on the device = every flagged command asks. Host-owned work (memory, skills, its own Hermes home) stays on the host. |
| D26 | **Exact phrase to open** (refines D23; the author, 2026-11-07: "it needs to be unique so that it cant accidently trigger when talking but the intent can come through when needed"). A connection opens only when the user's own message contains `tether <device>` (spaces, hyphens and case free). Naming a device in ordinary talk is refused with a pointer to the phrase, so neither casual talk nor injected text can open a machine. Closing stays broad (`untether`, "close the connection", "go home"): dropping back to the host is the safe direction. |
| D27 | **A denial closes the connection.** When the person at the device denies a session, the host closes the session's connection (back to the host, workspace wiped) and tells the model nothing ran and only the user can reopen it, instead of staying pointed at the device and re-prompting on the next call. |
| D28 | **Tether panel** (Desktop, right sidebar; palette "Open Hermes Tether"; `mod+shift+e`). Host view: paired devices, status, the opening phrase, idle limits, rename. Device view: the settings that machine owns (idle limit, consent wait, pause), applied live through a settings file the device polls. Both: a connection log (`events.jsonl`: kinds, times, labels, a 6-character session id; never commands, paths, keys or addresses). The panel's backend reads live status through the gateway's link relay and never takes the link itself. |
| D29 | **Labels and two idle limits.** The host can rename a paired device; its label is the word that opens it. The host may also set its own idle limit per device; the shorter of the host's and the device's limit applies, so the device's own setting stays the ceiling. |
| D30 | **A computer's own name never leaves it.** Devices do not announce their hostname, and the host strips one from older devices, so it never reaches the panel, the `devices` tool or a chat. |
| D31 | **`untether` is a solo command** (replaces the broad close of D23/D26; found in use, 2026-11-10: in a live chat, `untether` only worked dependably as a message on its own, so the plugin now accepts it only that way and says so). A connection closes on the user's words only when their whole message is `untether` (case and a trailing `.`/`!` free). "untether mac", "ok untether", "close the connection" or "go home" do not close it; the agent keeps working and tells the user to send `untether` on its own. The idle limit, a denial and a new session still close it as before. |
| D32 | **Several Desktops on one backend share it** (found in use, 2026-11-10, with a Mac and a Windows PC on one host). Each Hermes Desktop is a client of the same host Hermes, so closing one Desktop also ends the chat open in the other. This comes from Hermes's one-backend design, not from the plugin, and the plugin cannot change it; documented under Limits. |
| D10 | **No auto mode. Presence-based consent**: the first use in a session needs one approval **from the person at the device**; idle past X loses it; a new session asks again. "I have to be at the pc to allow this to work." (Supersedes D8's always-grants / phone approvals for device control.) |

## 2. What Hermes already gives us (verified 2026-11-06)

| Capability on the device | Today | Proof |
|---|---|---|
| Desktop app tools (preview pane: pages, files, dev servers; drive/read the pane) | **Works remotely** while a Desktop is attached to the session (session-scoped by Hermes design) | the host agent opened and read example.com in the Mac's Desktop pane |
| Real screen via `computer_use` | Works only through a spike (SSH wrapper as `HERMES_CUA_DRIVER_CMD` + `bot_desktop.placement: gateway`) | list_apps, capture, focus_app (approved) on the Mac from the NAS |
| Terminal and files | Works only through Hermes's SSH backend (needs an open SSH path, breaks on sleep/NAT) | `user@mac` from the host agent |
| Device MCP servers / skill tools (e.g. a printer-settings or mail MCP server) | **Nothing** forwards them | — |
| Any of it with no Desktop attached (Signal, cron, away) | **Nothing** | — |
| Pairing, encryption, many devices, sleep handling | **Nothing** | hermes-agent #18715 (47 upvotes) still open |

`mcp-serve` (official) is not a fit: stdio only, a fixed allowlist, never terminal/files/computer_use or the
profile's MCP servers. Its useful idea is kept: **tools run through the profile's own registry and hooks.**

## 3. Shape

One plugin package, two roles chosen by config. A machine can be a host, a device, or both.

```
        HOST (the agent's Hermes, e.g. NAS)                      DEVICE (e.g. the Mac's Hermes)
 ┌──────────────────────────────────────┐          ┌──────────────────────────────────────┐
 │ agent ─ tools                         │          │ tether device role                 │
 │   terminal/file tools ─▶ terminal     │          │   dials OUT to the host on boot      │
 │       provider "tether" ──┐         │  TLS 1.3 │   announces its capabilities         │
 │   computer_use ─▶ provider  ├─ link ◀─┼──────────┼─▶ runs each call through ITS OWN    │
 │       "tether" ───────────┤ listener│  mutual, │   Hermes: tool registry + approvals  │
 │   devices / device_call ────┘         │  pinned  │   ├ local terminal (its backend)     │
 │ Desktop tools: untouched (Hermes)     │          │   ├ computer_use (its cua-driver)    │
 └──────────────────────────────────────┘          │   └ its MCP servers / skill tools    │
                                                    └──────────────────────────────────────┘
```

### Host role registers (all public plugin API)
- **Terminal environment provider `tether`** (`ctx.register_terminal_environment_provider`):
  `execute(command)` → the session's active target. File tools ride on `execute()` per the Hermes
  contract ("read_file, write_file, patch and search_files go through your environment's execute()",
  terminal-environment-plugin.md; binary-safe transfer via base64 in the command is Hermes's job).
  `is_remote = True`; no `exec_prefix` (Bot Desktop never placed on a device). **`local` is always a
  target**, so the host keeps its own machine (committee: provider must not swallow host-local work).
- **Computer-use provider `tether`** (`ctx.register_computer_use_provider`): the 11 `ComputerUseBackend`
  methods (capture, click, drag, scroll, type_text, key, list_apps, list_windows, focus_app, set_value, wait)
  forwarded as calls; results carry screenshots as binary blobs.
- **Tools** (`ctx.register_tool`, toolset `tether`):
  - `devices` — list paired devices, online/asleep since, capabilities, active device; `use <device>`.
  - **Device MCP/skill tools** — registered per device **with their real schemas** as they are announced
    (`mac__bambu_status`, …; `check_fn` hides them while the device is asleep), so the model sees proper
    descriptions and arguments (committee: a generic `device_call(name, args)` makes models fumble).
    Device side reads its tool list from its own Hermes MCP configuration; if Hermes exposes no stable API
    for that, the device plugin starts its enabled MCP servers itself from its config. (Stretch: day 4.)
- **Link listener** — an asyncio server on its own event-loop thread, bound to a configured address
  (tailnet IP in our setup). Tool handlers (sync, in Hermes's worker threads) hand calls to it with
  `run_coroutine_threadsafe` and wait on a future with the call's deadline; it never touches Hermes's own
  loops. **One process owns it, every host process uses it** (found live 2026-11-06: Desktop sessions run
  in the dashboard backend, not `gateway run`; the SSH Desktop route starts its own `serve` child). The
  first process to take `tether/link.lock` owns the device listener and serves a private relay on
  `tether/link.sock` (0600 in the 0700 data folder); every other process relays through it. The gateway
  claims ownership at boot so devices connect before any call; if the owner exits, the next process that
  needs the link takes over and devices reconnect on their own (`hostlink.py`, tests/test_hostlink.py).

### Packaging: two plugins in one repo (found 2026-11-06)
Hermes loads computer-use providers from their **own plugin folders** through a limited collector
(`plugins/computer_use/__init__.py`), and classifies any plugin whose source mentions the computer-use
contract as kind `exclusive`, outside the general plugin manager (`hermes_cli/plugins_manifest.py`).
So the repo ships **`tether`** (general: link, pairing, device role, terminal provider, `devices`
tool; its source never mentions the computer-use contract) and **`tether_screen`** (computer-use
provider; `computer_use.backend: tether_screen`), which reaches `tether`'s link in the same process
through a small process-wide runtime handle. Two catalog entries, one repo (`subdir:` per entry).

### Device role
- **Desktop machines only** (D12): a device is a machine someone sits at (Mac first). Headless servers
  stay on SSH; tether changes nothing there.
- Dials out to the host on start and keeps the link (backoff reconnect). Nothing listens on the device.
- Reachable only while the device's Hermes runs (Desktop or its gateway service); otherwise the host
  shows `offline: Hermes not running` (D18).
- **Announce**: device name, OS, Hermes version, capabilities (terminal, computer_use available + doctor
  summary, MCP tool list with schemas, Desktop present or not, home path).
- **Execute** every call through the device's own Hermes:
  - terminal → the device's configured local terminal environment, through the dangerous-command gate;
  - computer_use → the device's own computer-use backend in `standard` mode (its driver, its TCC grants);
  - MCP/skill tools → the device's MCP client registry, only servers enabled on the device.
- **Presence-based session grant (D10, the author 2026-11-06).** No auto mode, ever. Control of a device must be
  allowed **by a person sitting at that device**:
  1. The first tether call of a host session (any capability) puts a **consent prompt on the device's
     own screen**: "Hermes on <host> wants to use this Mac (screen, terminal, files, tools) for session
     *<title>*. Allow for this session / Deny". Shown by the device's Hermes Desktop if it is open, else a
     native OS dialog (macOS `osascript`, Windows built-in, Linux desktop dialog). No answer = deny.
  2. **One approval covers that session**: no per-action prompts after it.
  3. The grant is keyed (host, host session id). A **new session needs a new approval**.
  4. **Idle timeout**: a session that makes no tether call for `grant_idle_minutes` (device setting,
     default 15, user-chosen; §6)
     **loses the grant**; the next call prompts on the device again.
  5. The device can end any grant at once (pause / kill switch); host session end also ends it.
  6. Hermes's built-in hard blocks still apply inside a granted session (no empty trash / force delete /
     lock / log out key combos; no `curl | bash`, `sudo rm -rf /`; no clicking permission dialogs or
     typing passwords).
  7. **The agent can never click its own consent** (found in the day-1 spike): while a consent prompt is
     open, the device **freezes all computer-use input from every session** until a human answers; no
     grant means no screen control, so the first prompt of a session is safe by construction.
  Spike result 2026-11-06: native macOS dialog works (answer back in 4 s, default Deny, timeout = deny);
  it appears on the logged-in user's physical screen even when raised from an SSH shell, so answering
  always takes a person at that screen.
  Consequences, all intended: nothing can start while nobody is at the device; a locked or sleeping
  device cannot be taken; approvals are never sent to a phone or another machine (they come from the
  device's own screen).
  Spike day 1: show the prompt on the Mac from a tether call (Desktop card or `osascript`) and get the
  answer back; confirm it cannot be answered remotely.

### Why this beats tonight's spike
The spike forwarded at the *driver* level and hit three traps (driver manifest names a local path; Bot
Desktop placement; a private daemon launched via a local `open -a`). Executing on the device inside the
device's own Hermes avoids all three: the driver, daemon and permissions are local where they belong.

## 4. Link protocol

- **Transport**: one TCP connection per device, device → host, TLS 1.3 (below). Keepalive ping 20 s.
- **Framing**: 4-byte length + JSON header, optional binary body (screenshots, file chunks).
- **`hello`** carries `protocol: {major, minor}`, plugin and Hermes versions; same major required (D17).
- **Reconnect** keeps session grants that are still inside their idle window (D15).
- **Background processes** (Hermes's start/poll/stream process tools) get their own call kinds on the link,
  implemented only through the public plugin API (D16).
  `hello` · `announce` · `call{id, kind, target, args, deadline}` · `result{id, ok, data, blobs}` ·
  `cancel{id}` · `event{…}` · `ping/pong`.
- **Calls** are request/response with per-call deadlines and cancel; the host never blocks the agent
  past the deadline. Device offline → immediate `device asleep since <t>` (queueing is v2).
- **Multiplexed**: many calls in flight on one link; every frame carries its call id. Bodies larger than
  256 KB go as `chunk{id, seq, last}` frames **interleaved** with other traffic, so a big file never stalls
  a screenshot or a command. Hard cap per call (e.g. 64 MB) with a clear error above it.
- **Sizes**: screenshots ~250 KB–1.5 MB measured (PNG; JPEG option for previews).
- **Announce is live**: the device re-announces when its tools change (MCP server added/removed), not only
  on connect.

## 5. Security

### 5.1 Identity
- Host and each device own a long-term key pair (Ed25519) and a self-signed certificate made from it,
  generated with `cryptography` (already a Hermes dependency).
- **Storage (D13)**: private keys go through **Hermes's normal secure path** for secrets (the system's
  secure store as Hermes uses it), never a file the agent's tools can read and never in any env the
  agent's commands inherit (`strip_env_keys`). The plugin itself requests no keychain access. Only the
  link code loads the key, in-process, at connect time. Certificates and pins are not secret and live in
  the plugin's data folder.
- **How, concretely (spike 2026-11-06)**: the private key is a named Hermes secret, `TETHER_LINK_KEY`
  (base64 PEM), stored the way Hermes stores every secret: `.env` by default or the user's configured
  secret source (1Password, Bitwarden, command, keychain-backed sources; `agent/secret_sources`),
  resolved by Hermes at startup. tether never calls a keychain itself. Hermes redaction already masks
  PEM and base64-PEM private keys in all model-visible output (`agent/redact.py` `_PRIVATE_KEY_RE`,
  `_is_b64_pem_key`), and tether also registers the exact value with `register_vault_redaction_value`;
  it is listed in `strip_env_keys` so the agent's commands never inherit it. Hermes's vault
  (`agent/vault_store.py`) is NOT used: its kinds are login/payment/address only.

### 5.2 Every boot: automatic handshake (D5)
- **TLS 1.3 only**, **mutual** authentication, both certificates **pinned by SHA-256 fingerprint**
  (no CA, no hostname trust). Ephemeral X25519 key exchange → forward secrecy.
- **256-bit enforced**: immediately after the handshake, **before any application byte is read or
  written**, each side checks the negotiated suite and **closes the link unless it is
  `TLS_AES_256_GCM_SHA384` or `TLS_CHACHA20_POLY1305_SHA256`**. Both Hermes Pythons (Mac 3.11/OpenSSL 3.5.6,
  NAS/OpenSSL 3.5.9) already list AES-256-GCM first; the check turns that default into a guarantee.
  Python's stdlib cannot pre-restrict TLS 1.3 suites (`set_ciphers` rejects TLS 1.3 names and leaves the
  1.3 list untouched; no `set_ciphersuites`), so the check-before-data gate is the enforcement point
  (verified 2026-11-06). `minimum_version = TLSv1_3`.
- **Suite choice is automatic and non-invasive (D11)**: both 256-bit suites are allowed and TLS negotiates
  the best one for the device ↔ host pair on every connect; nothing on the user's system is configured or
  changed (no process-wide OpenSSL config). Both suites are equally strong; AES-256-GCM wins wherever AES
  hardware exists (measured on the Mac: AES-256-GCM 8,858 MB/s vs ChaCha20-Poly1305 2,303 MB/s), and
  ChaCha20 stays available for chips without it. `devices` status shows the negotiated suite and whether
  the device has AES hardware (read-only).
- **Proven live 2026-11-06**: mutual TLS 1.3 NAS (OpenSSL 3.5.9) ↔ Mac (3.5.6) with pinned certs
  negotiated `TLS_AES_256_GCM_SHA384` on both ends; gate PASS; data flowed.
- Python stdlib `ssl` + `cryptography`; no homemade cipher or handshake.

### 5.3 Pairing: the master link (D5)
1. On the host: `hermes tether pair --name mac` (or Desktop button) → a one-time **pairing link**
   `tether://<host>:<port>/#<host_fp>.<secret>`: the **host's certificate fingerprint** plus a 128-bit
   random secret, single use, 10-minute expiry, bound to the device name; shown as text and QR.
2. On the device: `hermes tether join` reads the link from **stdin or a prompt, never argv** (no shell
   history, no `ps`), or it is pasted into Desktop.
3. The device opens TLS 1.3 to the host and **aborts unless the host certificate's fingerprint equals
   `host_fp` from the link** (a fake host at that address fails here, before anything else). The 256-bit
   gate (§5.2) runs next. The host sends a fresh 16-byte `nonce`. Each side then proves knowledge of the
   secret **without sending it**:
   - device → `HMAC-SHA256(secret, "device" ‖ host_fp ‖ device_fp ‖ name ‖ nonce)`
   - host → `HMAC-SHA256(secret, "host" ‖ host_fp ‖ device_fp ‖ name ‖ nonce)`
   Fingerprints are exchanged in the clear inside TLS so each side can recompute; a man-in-the-middle sees
   different fingerprints on each side, so neither HMAC verifies; the nonce defeats replay.
4. **The host asks its owner to confirm** the new device ("Pair 'mac' (Darwin, fp 4F2A…)? yes/no") on the
   host's own surface before pinning. A thief who races the real device with a stolen link still needs
   that yes.
5. Both pin the other's fingerprint; the secret is burned atomically (used or expired = gone). From then
   on, §5.2 every boot.
- A 128-bit secret needs no PAKE (PAKE protects low-entropy codes). Failed attempts are rate-limited and
  logged anyway.

### 5.4 Revocation and control
- Host: `hermes tether devices revoke mac` removes the pin; the device's next connect is refused.
- Device: `hermes tether unpair` removes the host pin; a device-side **pause** stops serving calls at once.
- Screen control is Hermes's built-in computer use as is (D14): its background-first input and its own
  cursor overlay show what the agent does; tether adds no takeover or arbitration logic.

### 5.5 Threat model (summary)
| Threat | Answer |
|---|---|
| Stolen pairing link | Single use, 10 min, bound to a name; after use it is worthless. |
| MITM during pairing or later | Pairing HMAC binds both fingerprints; later connects require both pins. |
| Stolen device key (e.g. a prompt-injected agent reading it via the terminal) | Prevented: keys sit in the system's secure store via Hermes's normal path, unreadable by the agent's tools (D13); if a key is lost anyway, the host revokes and the device re-pairs. |
| Mismatched plugin versions | `hello` protocol version check; clear refusal (D17). |
| Weaker crypto negotiated | Link closes unless a 256-bit suite was negotiated. |
| Prompt injection on the host | Control needs a fresh in-person grant at the device per session (D10); idle grants expire; hard blocks stay on. |
| Host compromised | Host is the trusted root by design; the device's approvals, rules and pause limit the blast radius. |
| Exposed port | Devices listen on nothing; the host binds one configured address. |
| Secret leakage via env | Provider tokens in `strip_env_keys`; Hermes redaction stays on. |

## 6. Config (sketch)

```yaml
# host (e.g. a home server)
tether:
  role: host
  listen: 192.0.2.10:9130
terminal:
  backend: tether          # agent terminal/files go to the active device
computer_use:
  backend: tether
---
# device (e.g. the Mac's Hermes)
tether:
  role: device
  name: mac
  grant_idle_minutes: 15     # D10: minutes without a tether call before the session grant lapses
  # host + pins are written by `hermes tether join`
```

**`grant_idle_minutes`** (device setting, default **15**): the user picks their own value, in whole
minutes, from the device's Desktop settings (Plugins → tether) or the CLI:
`hermes config set tether.grant_idle_minutes 30`. It lives on the **device**, so each machine's owner
decides how long their own machine stays granted; the host cannot change it. A new value applies to the
next idle check (existing grants are measured against it immediately).

## 7. Known traps (from the spike and the live tests) and how v1 handles them
Three kinds of fix: **tether** (in this plugin), **Hermes** (a Hermes core change, proposed upstream, never
installed by tether; patches and evidence in `docs/hermes-patches/`), **driver** (cua-driver, upstream).

| Trap | Handling |
|---|---|
| Driver `manifest` names an absolute local path | N/A: the driver runs on the device inside its own Hermes. |
| `bot_desktop.placement: auto` builds a Linux Xvnc on the remote | Host never uses Bot Desktop for devices (provider has no `exec_prefix`). |
| Private daemon launched via local `open -a` (bounded/unrestricted) | Device launches it locally. |
| **Fullscreen apps / other Spaces cannot be focused** (live 2026-11-06: `focus_app Claude` → "No on-screen window found" while Claude was fullscreen) | **Hermes.** Its cua backend lists windows with `on_screen_only: true` (`tools/computer_use/cua_backend_capture.py:175`) and `focus_app` matches only that list, so any window on another Space (every fullscreen app) is invisible; the driver itself lists all Spaces and `bring_to_front` switches to them. Known upstream: issue NousResearch/hermes-agent#142478 (open) and PR NousResearch/hermes-agent#29031 (open, all-Spaces listing for captures). Our proposal `docs/hermes-patches/focus-app-other-spaces.patch` looks across Spaces only for `raise_window=true`, explains the no-raise case (`window_on_other_space`), and was verified live both ways (Space 435 ↔ 1). Same behaviour locally; tether inherits the fix with no plugin change. Until it lands: the person at the Mac leaves fullscreen, or the agent reports the step as skipped. |
| Fullscreen raise reported "unverified" | **Driver** (part) + Hermes patch. In fullscreen the app's own 32 px title strip is a separate window above the content window; cua-driver 0.28.2 then reports `bring_to_front_exact_window_unverified` although the window is focused and its app frontmost. cua-driver **0.30.4** (PR trycua/cua#3785) changed the check to "frontmost process, focused, front within its process on its display"; tested 2026-11-06 after updating the Mac to **0.38.0**: still unverified, now with `front_in_process_on_display=false` (the strip is the front window of the app's own process). So the Hermes patch keeps accepting exactly that observed state (focused window == target, frontmost pid == target pid), and the strip case is worth a cua-driver issue. Patch v2 also makes the accepted result fully consistent (`verified`, `effect`, `status`), and captures of a fullscreen app target its titled content window instead of the 24 px strip. Applied locally on the Mac (device) only; undo in `docs/hermes-patches/README.md`. |
| First screen capture needs a one-time macOS consent | Documented first-run step on each device. |
| CuaDriver shadow bug #142314 | README troubleshooting with the one-line `.env` fix (D9). |
| One-shot/YOLO runs escalate computer_use mode | Device uses its own configured mode; YOLO on the host does not cross the link. |
| Hermes injects truststore; macOS rejects the pinned Ed25519 certificates ("broken key size") | **tether** (c2af7f8). The link builds stdlib TLS contexts and sets their fields through the C type; trust stays the pin plus the 256-bit gate. Regression test pairs with truststore injected. |
| Desktop sessions run in the dashboard process, not `gateway run` | **tether** (b6112e8). One process owns the link (`link.lock`), every other Hermes process relays through `link.sock`; takeover when the owner exits. |
| Files an agent attaches from the device (`MEDIA:<path>`) never reached the chat | **tether** (ac23548). The backend answers Hermes's remote-media path (`fetch_realpath`, `fetch_file`, `_remote_home`). |
| Per-action computer-use approval cards | **Hermes, by design** (`cua:<action>:<mode>` grants; `smart` approvals review terminal commands only). Answer "Always" once per action type for background input; foreground stays separately approved. tether adds only the presence prompt on the device. |

## 8. Build plan (to 2026-11-11)
| Day | Work | Done when |
|---|---|---|
| Thu 11-06 | Design review (done) + the author sign-off; **consent-prompt spike** (D10: prompt on the device, answer back) | approved design; spike says yes/no |
| Fri 11-07 | Link: keys, pairing (host_fp + nonce + host confirm), TLS 1.3 + pins + 256-bit gate, multiplexed framing, reconnect; unit tests incl. MITM / wrong-fp / weak-suite / replay | pair + reconnect NAS↔Mac, tests green |
| Sat 11-08 | Forwarding: terminal provider (+ `local`), computer_use provider, `devices`, device execution path + session grant (D10) | the host agent drives the Mac, no SSH, one approval at the Mac per session |
| Sun 11-09 | Asleep status, second device (a Windows PC or a Linux box, CLI-only), MCP tool forwarding with schemas as stretch, docs incl. #142314 | 2-device demo; MCP if time |
| Mon 11-10 | Polish, security self-review + **one final Kimi ask**, catalog YAML + `hermes plugins validate`, demo recording | validate passes, video cut |
| Tue 11-11 | Buffer; PR + X post + form before the deadline | submitted |

**Test matrix (D20)**: Desktop→host via Remote URL and via SSH gateway; in each, the host agent uses the Mac's
terminal, screen and tools over tether with NO host→device SSH (the host agent's `terminal.backend: ssh` and
the `cua-remote` wrapper removed first, restored only from their backups), and the Mac's local Hermes is
confirmed running (else a clear status and a documented fix).

Cut order if late (committee consensus, least loss first): MCP forwarding → second device → reconnect
polish. Never cut: pairing/pins/256-bit gate (D5), device rules deciding (D3/D4).

## 9. Open questions
1. **Consent prompt surface** (§3, D10) — Desktop card when the device's Desktop is open, else a native
   OS dialog; default idle timeout 15 min. Day-1 spike.
2. **Name** — "tether" is a placeholder.
3. **Host listen address/port** — tailnet IP:9130 for us; what default for other users (LAN, tailnet,
   or behind their existing Hermes dashboard port)?
4. **Active device** — per session (`devices use mac`) or per call (`device=`) or both?
5. **Queue while asleep** — v1 fails fast; is a queue needed for the demo?
6. **Where "always" grants live** — device only (D3), or host + device?

## 10. Review log

### Committee v1 (glm-5.2, deepseek-v4-pro, kimi-k2.6), 2026-11-06 — full text: `docs/reviews/committee-v1.txt`

**Adopted**
| Finding (who) | Change |
|---|---|
| Pairing link had no host anchor: a fake host at the URL could be pinned (deepseek, kimi) | Link carries `host_fp`; device aborts on mismatch before anything else (§5.3) |
| Stolen link could race the real device (glm) | Host owner confirms each new device before pinning (§5.3) |
| Pairing HMAC replayable within the window (glm, kimi) | Host nonce in the HMAC; atomic burn (§5.3) |
| Secret in argv / shell history (kimi) | `join` reads the link from stdin/prompt only (§5.3) |
| Data could flow before the suite check (glm, deepseek, kimi) | Gate runs before any application byte (§5.2) |
| One stream stalls on big transfers (glm, kimi) | Multiplexed calls, interleaved 256 KB chunks (§4) |
| Approvals need a session the device lacks (all) | Device rules decide, human asked in the host session (§3) |
| Generic `device_call` loses schemas (glm, kimi) | Device tools registered with real schemas (§3) |
| Terminal provider would swallow host-local work (glm) | `local` stays a target (§3) |
| Listener thread vs the gateway loop (glm, deepseek, kimi) | Own loop thread + `run_coroutine_threadsafe` (§3) |
| Tool list only at connect (deepseek) | Live re-announce (§4) |
| Scope: cut multi-device / MCP first (all) | Cut order in §8; MCP is the stretch |

**Rejected, with reasons**
| Suggestion (who) | Why not |
|---|---|
| Restrict suites with `set_ciphers("TLS_AES_256…")` (glm, deepseek, kimi) | Verified impossible in Python stdlib: `set_ciphers` rejects TLS 1.3 names, no `set_ciphersuites`; the check-before-data gate is the enforcement |
| Bind HMAC to `export_keying_material` (deepseek) | Not in Python stdlib (only `tls-unique`, undefined for TLS 1.3); mutual TLS already proves both private keys, the nonce covers replay |
| Per-boot nonce signed by the device key (deepseek) | Mutual TLS 1.3 already proves possession of the device key on every connect |
| Use Tailscale + a bearer token instead of our link (kimi) | Violates D5 (no pasted token) and D7 (would require Tailscale); TLS via stdlib is about a day |
| Run devices auto-approve/YOLO for the demo (glm, kimi) | Violates D4; approval routing (§3) keeps the rules on the device without anyone at the device |
| Drop device-Hermes execution for raw subprocess + cua-driver (glm) | Violates D3; and the driver-level path is what hit three traps in the spike |
| `register_computer_use_provider` does not exist (kimi) | It does: `tools/computer_use/backend.py` ComputerUseProvider + docs `ctx.register_computer_use_provider()` |
| File tools bypass the terminal provider (kimi) | Hermes docs: file tools go through the environment's `execute()` |
| Keys in the OS keychain (kimi) | Good, v2; v1 keeps 0600 under `HERMES_HOME` like Hermes's own secrets |
| Cut the catalog YAML / validate (deepseek) | Entry *requires* a catalog PR |

### Gap review with the author, 2026-11-06
| Gap | Decision |
|---|---|
| Devices with no screen | Out of scope (D12): headless stays on SSH |
| Device secrets / tether's own key readable by a granted shell | System secure store via Hermes's normal path; agent can never read the link's keys (D13) |
| Two controllers on one screen | No arbitration; Hermes computer use as is, no forced takeover (D14) |
| Grant across a reconnect | Survives (D15) |
| Long-running commands | As needed within Nous plugin rules (D16) |
| Version mismatch | Protocol version in `hello` (D17) |
| Host exposure | Nous rules; LAN/VPN/tailnet recommended (D18) |
| Device Hermes not running | Documented + status (D18) |
| Audit log | Hermes's normal logging (D19) |
| Judges' setup guide, catalog capabilities, the name | During testing |
