#!/usr/bin/env bash
# Maintainers' Hermes release watcher for a Hermes cron job in script-only mode (no_agent: stdout is delivered
# verbatim, and EMPTY stdout sends nothing). Not shipped in the plugin; see scripts/README.md.
#
# usage: hermes_watch_cron.sh <cache-folder>
#
# Keeps a clone of the public hermes-agent repository in <cache-folder>/hermes-agent, fetches its tags, and when
# the newest release tag (vX.Y.Z, no +canary/+channel suffix, newest by tag date) differs from the last one checked,
# runs scripts/hermes_watch.py on that release. It prints a short report only when that release changes a Hermes
# name Tether wraps, copies, overrides or depends on; otherwise it prints nothing. A fetch that fails is retried on
# the next run and reported only after 3 failures in a row.
#
# Environment (all optional): TETHER_WATCH_REPO (default: the public repository), TETHER_WATCH_PYTHON (default:
# python3), TETHER_WATCH_BASELINE and TETHER_WATCH_PLUGIN (default: next to this script / the repo's plugin folder).
set -u

here=$(cd "$(dirname "$0")" && pwd)
cache=${1:-}
if [ -z "$cache" ]; then
  echo "hermes watch: no cache folder given (usage: hermes_watch_cron.sh <cache-folder>)"
  exit 2
fi
repo_url=${TETHER_WATCH_REPO:-https://github.com/NousResearch/hermes-agent.git}
python=${TETHER_WATCH_PYTHON:-python3}
baseline=${TETHER_WATCH_BASELINE:-$here/hermes_watch_baseline.json}
plugin=${TETHER_WATCH_PLUGIN:-$here/../plugin}
clone="$cache/hermes-agent"
last_file="$cache/last_checked_tag"
fail_file="$cache/fetch_failures"

mkdir -p "$cache" || exit 2
export GIT_TERMINAL_PROMPT=0

fetch_failed() {
  n=$(( $(cat "$fail_file" 2>/dev/null || echo 0) + 1 ))
  echo "$n" > "$fail_file"
  if [ "$n" -eq 3 ]; then
    echo "hermes watch: could not fetch Hermes release tags 3 times in a row ($1); Tether's Hermes check is not running"
  fi
  exit 0
}

if [ ! -d "$clone/.git" ]; then
  rm -rf "$clone"
  err=$(git clone --quiet --no-checkout "$repo_url" "$clone" 2>&1) || fetch_failed "clone: ${err##*$'\n'}"
fi
err=$(git -C "$clone" fetch --quiet --tags --force origin 2>&1) || fetch_failed "fetch: ${err##*$'\n'}"
rm -f "$fail_file"

newest=$(git -C "$clone" for-each-ref --sort=-creatordate --format='%(refname:short)' refs/tags \
         | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | head -n 1)
[ -n "$newest" ] || exit 0
last=$(cat "$last_file" 2>/dev/null || true)
[ "$newest" = "$last" ] && exit 0

work=$(mktemp -d "${TMPDIR:-/tmp}/hermes-watch.XXXXXX") || exit 2
trap 'rm -rf "$work"' EXIT
if ! git -C "$clone" archive --format=tar "$newest" | tar -x -C "$work"; then
  echo "hermes watch: could not unpack Hermes $newest from the cache clone"
  exit 0
fi

out=$("$python" "$here/hermes_watch.py" "$work" --baseline "$baseline" --plugin "$plugin" 2>&1)
rc=$?
echo "$newest" > "$last_file"
case $rc in
  0) exit 0 ;;
  1)
    n=$(printf '%s\n' "$out" | grep -c .)
    echo "Hermes $newest changes what Tether wraps ($n name(s)); verify Tether before updating:"
    printf '%s\n' "$out" | head -n 25
    [ "$n" -gt 25 ] && echo "... and $((n - 25)) more (run scripts/hermes_watch.py on that release for all)"
    exit 0 ;;
  *)
    echo "hermes watch: the check of Hermes $newest failed: $(printf '%s' "$out" | tail -n 1)"
    exit 0 ;;
esac
