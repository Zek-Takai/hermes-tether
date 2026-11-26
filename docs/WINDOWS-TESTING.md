# Windows device: validation checklist

The checks used to validate a Windows device: the Windows consent prompt and a workspace wipe that survives
files a running program holds open. Run them again after changes to the device side.

## Set up the PC

1. Install a Hermes that has the public plugin seams Tether 0.3.1 uses (see the README's Setup) and run it **in your signed-in session** (Hermes Desktop or `hermes`
   in a terminal). A background Windows service has no screen to show the consent box on, so every session
   would be denied.
2. Copy `plugin/tether` from this repository into `%LOCALAPPDATA%\hermes\plugins\tether` (Hermes's home on Windows), then in
   `config.yaml`:
   ```yaml
   plugins:
     enabled: [tether]
     entries:
       tether:
         settings:
           role: device
           name: studio-pc
   ```
3. `hermes gateway restart`.
4. Pair: on the host `hermes tether pair studio-pc`; on the PC run `hermes tether join` and paste the link at its
   prompt (a link on the command line is visible to other programs and kept in shell history).

## Checks

| # | Do | Expect |
|---|---|---|
| 1 | Host chat: `tether studio pc` | A Windows box **"Hermes Tether - allow remote use?"** on top of other windows, default button **No** |
| 2 | Click **No** | The agent reports it was not allowed; the connection closes |
| 3 | `tether studio pc` again, wait out the timeout (15 s default) | Denied, like No |
| 4 | `tether studio pc`, click **Yes**, run `hostname` / `ver` | Runs on the PC |
| 5 | Ask for a command Hermes flags (`mkdir t && rmdir /s /q t` or the PowerShell equivalent) | Hermes's dangerous-command card in the host chat |
| 6 | Open an app from the workspace, then `untether` | Connection closes; the workspace is emptied, or within a minute if the app still held a file |
| 7 | Tether panel on the host | `studio-pc` online beside `mac`: two machines, one agent |

Validated on Windows 11 (Hermes 0.23.0): all seven checks passed on a real PC.

Tether 0.3.1 on Windows 11 (Hermes built with the seams): a session approved with an authenticator code, commands and execute_code on the PC, and on untether the session folder removed, including a local git clone's read-only objects and a file another program held open (removed once it was released).
