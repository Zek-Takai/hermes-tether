# Windows device: validation checklist

The checks used to validate a Windows device: the Windows consent prompt and a workspace wipe that survives
files a running program holds open. Run them again after changes to the device side.

## Set up the PC

1. Install Hermes 0.23.0 or newer and run it **in your signed-in session** (Hermes Desktop or `hermes`
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
4. Pair: on the host `hermes tether pair studio-pc`; on the PC `hermes tether join "<link>"`.

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
