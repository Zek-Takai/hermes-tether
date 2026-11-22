# Maintainer scripts (not part of the plugin)

Nothing here is shipped in `plugin/` or runs on a user's machine.

## Hermes release watcher

Tether wraps, copies, overrides and imports parts of Hermes by name: most of all the session lock's copy of Hermes's
`LocalEnvironment._run_bash` (`plugin/tether/tether/lock.py`), and every place Hermes starts a process for that
environment. The device never compares Hermes's source itself (DESIGN D72). Instead, the maintainers check each new
Hermes release before telling people to update.

- `hermes_watch.py <hermes-source>` derives the watch list from `plugin/` (every Hermes name Tether imports, looks
  up, subclasses or overrides, plus Hermes's process-start paths for the environment the lock wraps), computes a
  normalized hash of each one in that source (AST without comments, docstrings or formatting), and compares them
  with `hermes_watch_baseline.json`. No output when everything matches; otherwise one line per name:
  `changed:`, `missing:` or `not in baseline:`. Exit 0, 1 (something printed) or 2 (error).
- `hermes_watch_baseline.json` records the Hermes it was made from (now Hermes `v0.23.3`, commit `caafe53`).
  After Tether has been checked against a new Hermes (rerun the tests and the attack scripts), write a new one:
  `scripts/hermes_watch.py <that hermes source> --write-baseline`, and commit it.
- `hermes_watch_cron.sh <cache-folder>` is for a Hermes cron job in script-only mode. It keeps a clone of the public
  `hermes-agent` repository in `<cache-folder>/hermes-agent`, fetches its tags, and when the newest release tag
  (`vX.Y.Z`, canary and channel tags ignored) differs from the last one it checked, runs the watcher on that release.
  It prints only when something changed, for example:

  ```
  Hermes v0.23.4 changes what Tether wraps (1 name(s)); verify Tether before updating:
  changed: tools.environments.local.LocalEnvironment._run_bash
  ```

  A failed fetch is reported only after 3 runs in a row. It needs `git`, `bash` and `python3`, and network access
  to GitHub (set `TETHER_WATCH_REPO` to use another clone URL).

### Register it on the machine that runs Hermes (the NAS)

Hermes runs a cron script only from `~/.hermes/scripts/`, by file name, with no arguments, so add a two-line
wrapper there that names this repository's checkout and a cache folder:

```sh
cat > ~/.hermes/scripts/tether-hermes-watch.sh <<'EOF'
#!/usr/bin/env bash
exec "$HOME/Projects/hermes-homeport/scripts/hermes_watch_cron.sh" "$HOME/.cache/tether-hermes-watch"
EOF
```

Then create the job in script-only mode (stdout is delivered as it is; empty output sends nothing):

```sh
hermes cron create "0 */6 * * *" --name "Tether: Hermes release watch" \
  --script tether-hermes-watch.sh --no-agent --deliver telegram
```

Use your own `--deliver` target. `hermes cron list` shows the job; `hermes cron runs` shows its runs. The first
run clones the repository (a few minutes) and checks the newest release.

To be told only when a release changes what Tether wraps (and never about fetch or check trouble), let the wrapper
pass on only that report and log the rest, and send cron failure notices nowhere:

```sh
out=$("$HOME/Projects/hermes-homeport/scripts/hermes_watch_cron.sh" "$HOME/.cache/tether-hermes-watch" 2>&1)
case "$out" in
  "") ;;
  "Hermes "*"changes what Tether wraps"*) printf "%s\n" "$out" ;;
  *) printf "%s %s\n" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$out" >> "$HOME/.cache/tether-hermes-watch/watch-errors.log" ;;
esac
```

and add `--failure-deliver local` to `hermes cron create`. Where the watcher runs from a copy of this repository's
`scripts/` and `plugin/` (a container), refresh that copy whenever Tether changes, so the watch list follows the
code.
