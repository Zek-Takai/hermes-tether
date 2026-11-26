"""The session lock (design D70-D77): while a remote session is connected, nothing Tether runs or does for the remote
agent can change Tether's live files or this device's Hermes (its install, Python, plugins, settings), or read their
secrets (Tether's key and pins, the authenticator records, Hermes's .env, credentials and vault). The person's own
terminal and apps, and this device's own Hermes agent, are not affected: only what Tether starts for a remote session
is locked, and only while it runs ("a Chinese finger trap": the agent may improve Tether in a copy of its project; the
person at the machine swaps it in).

Two halves share one protected set (protected_set):
- commands (terminal, background jobs, execute_code scripts and everything they start) run inside macOS's own
  sandbox: /usr/bin/sandbox-exec -p <profile>, the profile built in memory for each session (session_profile) and
  never written to a file. LockedEnvironment is Hermes's LocalEnvironment with every process it starts wrapped so.
- the file tools Tether lends (read_file, write_file, patch, search_files) run, on a Mac with the lock on, in one
  helper per session inside the same profile (filebox, D79); Hermes's hooks still run here first. tool_refusal checks
  the path first (real path with links resolved before '..', the name itself when it is a link, case and Unicode
  folding, the data-volume prefix, every part of a search path, a file's other names) as the early refusal only.
Where the lock cannot be applied the command is refused and the agent is told why; it never runs unlocked (D73),
unless the person at the machine turned on allow_unlocked_commands in Tether's settings (on by default on Windows,
which has no lock; off by default on macOS). Tether never compares Hermes's own source here: whether a Hermes update
changes what LockedEnvironment copies is checked by the maintainers before a release (scripts/hermes_watch.py).
"""
from __future__ import annotations

import contextlib

import logging
import os
import shlex
import re
import shutil
import subprocess
import sys
import threading
import time
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional

logger = logging.getLogger(__name__)

SANDBOX_EXEC = "/usr/bin/sandbox-exec"
FIND = "/usr/bin/find"
SCAN_TTL_S = 300.0            # how long one hard-link check counts (D74)
SCAN_TIMEOUT_S = 60.0
_HIDDEN_OK = ("bin", "node")  # runtimes Hermes puts on the terminal's PATH from inside its home stay readable
_NEVER_READABLE = frozenset({"tether", "plugins", "credentials", "vault", "sessions", "memories", "logs", "profiles"})


class LockError(PermissionError):
    """A refusal: one sentence for the agent. Nothing was run or touched."""


# ---------- the sentences the agent sees (exact; tests compare them) ----------
NO_SANDBOX = ("tether: this command was not run: this device's session lock could not start ({why}). Commands in a "
              "remote session run only inside it; the person at the machine can see the reason in Hermes's log")
NOT_LOCKABLE = ("tether: this command was not run: on {system} this device cannot keep a remote session's commands "
                "away from Tether's and Hermes's own files, so it does not run them. File tools and computer use "
                "still work; the person at the machine can turn on allow_unlocked_commands in Tether's settings to "
                "accept that risk")
LINKED = ("tether: this was not run: a protected file on this device has another name outside the protected folders "
          "({path}), so the session lock cannot hold. The person at the machine can remove that extra name, or "
          "reinstall with copies instead of links")
PATH_REFUSED = ("tether: {path} is one of this device's protected files (Tether's and Hermes's own files, locked "
                "while a remote session is connected); {verb} it is refused. To change Tether, work on a copy of its "
                "project; the person at the machine installs it")
SEARCH_REFUSED = ("tether: {path} contains this device's protected files ({root}); search a folder that does not "
                  "contain them, or use the terminal, whose commands cannot read them")
PATCH_UNREAD = "tether: this patch could not be read to check the files it names, so it was not applied"
BAD_PATH = "tether: the protected path {path!r} has a character the session lock cannot name, so nothing was run"

_unlocked: Optional[bool] = None   # the device setting allow_unlocked_commands; None: this system's default


def set_unlocked(flag: Optional[bool]) -> None:
    """allow_unlocked_commands as the device decided it (config.yaml, then the panel; device.py applies a panel
    change only while no remote session is connected). None: this system's default."""
    global _unlocked
    _unlocked = None if flag is None else bool(flag)


def unlocked() -> bool:
    """Whether a remote session's commands run without the session lock: the setting, or by default on Windows
    (no lock there) and off everywhere else."""
    return (_system() == "windows") if _unlocked is None else _unlocked


# ---------- the protected set ----------
def _real(p: Any) -> str:
    """Absolute, '~' expanded, every link resolved (a missing tail is kept as written)."""
    return os.path.realpath(os.path.abspath(os.path.expanduser(str(p))))


def _ancestors(p: str) -> list[str]:
    out, cur = [], os.path.dirname(p)
    while cur and cur != os.path.dirname(cur):          # stop before the filesystem root
        out.append(cur)
        cur = os.path.dirname(cur)
    return out


def _fold(p: str) -> str:
    """macOS and Windows volumes are normally case- and normalization-insensitive: compare folded."""
    if sys.platform in ("darwin", "win32"):
        return unicodedata.normalize("NFD", p).casefold()
    return p


def _under(p: str, root: str) -> bool:
    p, root = _fold(p), _fold(root)
    return p == root or p.startswith(root.rstrip(os.sep) + os.sep)


def _homes() -> tuple[str, str]:
    """(the Hermes root that holds every profile, the active Hermes home), both resolved."""
    try:
        from hermes_constants import get_default_hermes_root, get_hermes_home
        home = Path(get_hermes_home())
        try:
            root = Path(get_default_hermes_root())
        except Exception:  # noqa: BLE001
            root = home
    except Exception:  # noqa: BLE001 - outside Hermes (tests, the CLI before Hermes is importable)
        home = Path(os.environ.get("HERMES_HOME") or Path.home() / ".hermes")
        root = home.parent.parent if home.parent.name == "profiles" else home
    return _real(root), _real(home)


def _system() -> str:
    """"darwin", "windows" or the platform's own name (tests replace it)."""
    return "windows" if os.name == "nt" else sys.platform


def _interpreter() -> tuple[Optional[str], list[str], list[str]]:
    """(the device's Hermes code: the folder holding its ``tools`` package; this Python's prefixes; its import path).
    Everything the device's Hermes imports at its next start comes from these (tests and attack scripts replace it)."""
    try:
        import tools
        install: Optional[str] = _real(Path(tools.__file__).resolve().parent.parent)
    except Exception:  # noqa: BLE001
        install = None
    prefixes = sorted({_real(p) for p in (sys.prefix, sys.base_prefix, sys.exec_prefix) if p}
                      | set(_venv_bases(install)))
    paths = [_real(e) for e in sys.path if e and os.path.isdir(e)]
    return install, prefixes, paths


def _venv_bases(install: Optional[str]) -> list[str]:
    """The base Pythons of the virtual environments inside the device's Hermes install (its pyvenv.cfg 'home').
    Hermes 0.23.3 runs its gateway on its own Python 3.14 runtime while its venv still links its libpython to the
    base Python it was made from: that base is protected too, whichever Python runs this process, or the hard-link
    check finds a protected file with a name outside the protected folders and (rightly) refuses every command."""
    out: list[str] = []
    if not install:
        return out
    for cfg in (Path(install) / "venv" / "pyvenv.cfg", Path(install) / ".venv" / "pyvenv.cfg"):
        try:
            text = cfg.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            key, _, value = line.partition("=")
            if key.strip().lower() == "home" and value.strip():
                home = Path(value.strip())
                base = home.parent if home.name in ("bin", "Scripts") else home
                if base.is_dir():
                    out.append(_real(base))
    return out


def _plugin_dirs(homes: Iterable[str]) -> list[str]:
    """Every plugin folder this device's Hermes may load, links resolved: <home>/plugins/* of every profile, the
    project plugins when they are on, and Tether's own two folders wherever they really are."""
    out: list[str] = []
    for home in homes:
        for folder in [Path(home) / "plugins", *sorted(Path(home).glob("profiles/*/plugins"))]:
            out.append(_real(folder))
            try:
                out.extend(_real(child) for child in folder.iterdir())
            except OSError:
                pass
    if os.environ.get("HERMES_ENABLE_PROJECT_PLUGINS", "").strip().lower() in ("1", "true", "yes", "on"):
        out.append(_real(Path.cwd() / ".hermes" / "plugins"))
    mine = Path(__file__).resolve().parents[1]          # plugin/tether (the folder with plugin.yaml)
    out.append(_real(mine))
    if (mine.parent / "tether_screen" / "plugin.yaml").exists():
        out.append(_real(mine.parent / "tether_screen"))
    return out


@dataclass(frozen=True)
class Protected:
    no_write: tuple[str, ...]           # folders and files: nothing in them may be created, changed, renamed or removed
    no_write_names: tuple[str, ...]     # single names (ancestors, the hermes launcher): not renamed, removed or replaced
    no_write_patterns: tuple[str, ...]  # Seatbelt regexes (this device's Hermes launch agents)
    no_read: tuple[str, ...]            # folders whose file contents stay unreadable: the Hermes homes
    readable: tuple[str, ...]           # inside no_read but readable: the install and the runtimes on the terminal PATH
    scan_roots: tuple[str, ...]         # code: where the hard-link check looks, at most every SCAN_TTL_S (D74)
    fresh_roots: tuple[str, ...]        # secrets: small folders checked on every call (D74)
    scan_files: tuple[str, ...]         # the files at the top of each Hermes home (.env, config.yaml, auth.json, ...)


def protected_set(path_dirs: Iterable[str] = ()) -> Protected:
    """The exact set for this device and this moment. path_dirs: the PATH a session's terminal gets."""
    root, home = _homes()
    homes = [root] if _under(home, root) else [root, home]
    user_home = _real(Path.home())
    install, prefixes, import_path = _interpreter()
    no_write: list[str] = [*homes]
    if install:
        no_write.append(install)
    no_write.extend(prefixes)
    no_write.extend(import_path)        # the device's Hermes imports from these at its next start
    plugins = _plugin_dirs(homes)
    no_write.extend(plugins)
    # Never the user's home or anything above it (a '' or cwd entry in sys.path would otherwise lock everything).
    no_write = [p for p in dict.fromkeys(no_write) if not _under(user_home, p)]
    names: list[str] = []
    for launcher in {shutil.which("hermes"), str(Path.home() / ".local" / "bin" / "hermes")}:
        if launcher and os.path.lexists(launcher):
            names.append(os.path.abspath(launcher))     # the name itself (a link is not followed) ...
            no_write.append(_real(launcher))            # ... and what it leads to
            # ... and every folder above the name, as written and resolved: renaming ~/.local/bin away, editing
            # the launcher there and renaming it back would otherwise change it in place (S1-5).
            for top in (os.path.abspath(launcher), os.path.join(_real(os.path.dirname(os.path.abspath(launcher))),
                                                                os.path.basename(launcher))):
                names.extend(_ancestors(top))
    patterns: list[str] = []
    if _system() == "darwin":
        agents_name = os.path.abspath(Path.home() / "Library" / "LaunchAgents")
        agents = _real(agents_name)
        patterns.append("^" + _rx(agents) + r"/ai\.hermes\.")
        # The folder itself (as written and resolved) and every folder above it: not renamed, removed or replaced,
        # so the ai.hermes launch agents cannot be edited in a renamed copy and put back (S1-5).
        for top in (agents_name, agents):
            names.extend([top, *_ancestors(top)])
    for p in no_write:
        names.extend(_ancestors(p))
    names = [n for n in dict.fromkeys(names) if n]
    readable: list[str] = []
    if install:
        readable.append(install)
    for d in path_dirs:
        if not d or not os.path.isabs(d):
            continue
        r = _real(d)
        for h in homes:
            if _under(r, h) and r != h:
                rel = os.path.relpath(r, h).split(os.sep)
                part = rel[2] if rel[0] == "profiles" and len(rel) > 2 else rel[0]
                if part.casefold() in _NEVER_READABLE or part.startswith("."):
                    continue            # a PATH entry never opens Tether's data, plugins or secrets to reading
                readable.append(os.path.join(h, *rel[:3]) if rel[0] == "profiles" else os.path.join(h, rel[0]))
    # The Python this process runs on and the folders it imports from, where they sit inside a Hermes home (Hermes
    # 0.23.3's own runtime in <home>/tools and its environment in <home>/installs): readable, never writable, so the
    # file-tool helper (filebox) can start on the same Python with the same imports. Code only: a folder under
    # Tether's data, the plugins or a secret store never opens this way.
    for d in [*prefixes, *import_path]:
        r = _real(d)
        for h in homes:
            if _under(r, h) and r != h:
                rel = os.path.relpath(r, h).split(os.sep)
                if rel[0].casefold() in _NEVER_READABLE or rel[0].startswith(".") or rel[0] == "profiles":
                    continue
                readable.append(r)
    for h in homes:
        for name in _HIDDEN_OK:
            if os.path.isdir(os.path.join(h, name)):
                readable.append(os.path.join(h, name))
    data = _data_dir_real(home)
    scan_roots = [p for p in dict.fromkeys([install or "", *prefixes, *plugins,
                                             *(os.path.join(h, n) for h in homes for n in ("bin", "hooks"))])
                  if p and os.path.isdir(p) and _system() == "darwin"]   # Windows: no find, no sandbox (D74)
    fresh_roots = [p for p in dict.fromkeys([data, *(os.path.join(h, n) for h in homes
                                                     for n in ("credentials", "vault"))]) if os.path.isdir(p)]
    scan_files = [os.path.join(h, f) for h in homes for f in os.listdir(h)
                  if os.path.isfile(os.path.join(h, f))] if all(os.path.isdir(h) for h in homes) else []
    return Protected(tuple(dict.fromkeys(no_write)), tuple(dict.fromkeys(names)), tuple(patterns),
                     tuple(homes), tuple(dict.fromkeys(readable)), tuple(scan_roots), tuple(fresh_roots),
                     tuple(scan_files))


def _data_dir_real(home: str) -> str:
    return _real(Path(home) / "tether")


# ---------- the hard-link check (D74) ----------
_scan_lock = threading.Lock()
_scan_cache: dict[tuple, tuple[float, Optional[str], frozenset]] = {}


def _linked_files(roots: tuple[str, ...]) -> list[str]:
    """Every regular file with more than one name under roots (macOS: /usr/bin/find; elsewhere a walk)."""
    if not roots:
        return []
    if os.path.exists(FIND) and _system() == "darwin":
        proc = subprocess.run([FIND, *roots, "-xdev", "-type", "f", "-links", "+1", "-print0"],
                              capture_output=True, timeout=SCAN_TIMEOUT_S)
        if proc.returncode != 0:
            raise LockError(NO_SANDBOX.format(why="the check for linked files could not read every protected folder"))
        return [p for p in proc.stdout.decode(errors="surrogateescape").split("\0") if p]
    out = []
    for root in roots:
        for dirpath, _dirs, files in os.walk(root):
            for f in files:
                p = os.path.join(dirpath, f)
                try:
                    st = os.lstat(p)
                except OSError:
                    continue
                if st.st_nlink > 1 and (st.st_mode & 0o170000) == 0o100000:
                    out.append(p)
    return out


def _excluded(p: str, prot: Protected) -> bool:
    """The session workspaces are not protected (a link made there is checked through its other name)."""
    return any(_under(p, os.path.join(h, "tether", "sessions")) for h in prot.no_read)


def _gather(paths: Iterable[str], prot: Protected, found: dict) -> None:
    for p in paths:
        if _excluded(p, prot):
            continue
        try:
            st = os.lstat(p)
        except OSError:
            continue
        if st.st_nlink > 1 and (st.st_mode & 0o170000) == 0o100000:
            found.setdefault((st.st_dev, st.st_ino), [st.st_nlink, set()])[1].add(p)


def _walk_files(roots: Iterable[str], prot: Protected) -> list[str]:
    out = []
    for root in roots:
        for dirpath, dirs, files in os.walk(root):
            dirs[:] = [d for d in dirs if not _excluded(os.path.join(dirpath, d), prot)]
            out.extend(os.path.join(dirpath, f) for f in files)
    return out


def linked_inodes(prot: Protected) -> tuple[Optional[str], frozenset]:
    """(a protected file that has a name outside the protected set, or None; the (dev, inode) of every protected file
    with more than one name). A name is outside when fewer of its names were found inside than it has. The code
    folders are scanned at most every SCAN_TTL_S (about half a second for a full install); the secret files (Tether's
    data folder, Hermes's credentials and vault, the files at the top of each home) on every call."""
    key = prot.scan_roots
    now = time.monotonic()
    with _scan_lock:
        hit = _scan_cache.get(key)
    if hit and now - hit[0] < SCAN_TTL_S:
        code = hit[1]
    else:
        code = {}
        _gather(_linked_files(prot.scan_roots), prot, code)
        with _scan_lock:
            _scan_cache[key] = (now, code)
    found = {k: [v[0], set(v[1])] for k, v in code.items()}
    _gather([*_walk_files(prot.fresh_roots, prot), *prot.scan_files], prot, found)
    leak = next((sorted(names)[0] for (n, names) in found.values() if len(names) < n), None)
    return leak, frozenset(found)


def reset_scan_cache() -> None:
    with _scan_lock:
        _scan_cache.clear()


# ---------- commands: the sandbox ----------
def check_commands() -> None:
    """Raises LockError when this device must not run a remote session's command (D73); returns when it may.
    allow_unlocked_commands on: it may (unlocked, any system). Otherwise macOS: sandbox-exec present and no protected
    file with an outside name; anything else: refused."""
    system = _system()
    if unlocked():
        return
    if system == "darwin":
        if not os.access(SANDBOX_EXEC, os.X_OK):
            raise LockError(NO_SANDBOX.format(why=f"{SANDBOX_EXEC} is missing"))
        leak, _ = linked_inodes(protected_set())
        if leak:
            raise LockError(LINKED.format(path=leak))
        return
    raise LockError(NOT_LOCKABLE.format(system="Windows" if system == "windows" else (system or "this system")))


def locked() -> bool:
    """Whether this device's commands run inside the lock (announced to the host as files_locked)."""
    return _system() == "darwin" and not unlocked() and os.access(SANDBOX_EXEC, os.X_OK)


def files_boxed() -> bool:
    """Whether a remote session's file tools must run inside its lock (filebox, D79): macOS with the lock on. No
    sandbox-exec does not turn this off: the tools are then refused, never run in this process."""
    return _system() == "darwin" and not unlocked()


def _q(p: str) -> str:
    """A path as an SBPL string. A quote, backslash or control character is refused: never guessed at."""
    if any(c in p for c in '"\\') or any(ord(c) < 32 for c in p):
        raise LockError(BAD_PATH.format(path=p))
    return f'"{p}"'


def _rx(p: str) -> str:
    """A path as part of an SBPL regex (POSIX extended), every special character escaped."""
    _q(p)
    return re.sub(r"([.^$*+?()\[\]{}|])", r"\\\1", p)


def session_profile(*, workspace: str, temp_dir: str, own_id: str, path: str = "",
                    prot: Optional[Protected] = None) -> str:
    """The Seatbelt profile for one session's terminal (D71). Later rules win over earlier ones."""
    prot = prot or protected_set(path.split(os.pathsep) if path else ())
    ws, tmp = _real(workspace), _real(temp_dir)
    own = re.sub(r"[^A-Za-z0-9_-]", "", own_id)
    if not own:
        raise LockError(NO_SANDBOX.format(why="the terminal has no session id"))
    lines = ["(version 1)", "(allow default)"]
    deny_w = [f"(subpath {_q(p)})" for p in prot.no_write] + [f"(literal {_q(p)})" for p in prot.no_write_names]
    deny_w += [f'(regex #"{rx}")' for rx in prot.no_write_patterns]
    lines.append("(deny file-write* " + " ".join(deny_w) + ")")
    lines.append("(deny file-read-data " + " ".join(f"(subpath {_q(p)})" for p in prot.no_read) + ")")
    if prot.readable:
        lines.append("(allow file-read-data " + " ".join(f"(subpath {_q(p)})" for p in prot.readable) + ")")
    # This device's Hermes listens on sockets inside its home (gateway.sock): not for a remote session's commands.
    lines.append("(deny network-outbound " + " ".join(f"(remote unix-socket (subpath {_q(p)}))" for p in prot.no_read)
                 + ")")
    # Disk images and mounts are made by system services outside this sandbox: one mounted over a protected folder
    # would replace Tether's code for the next import (D75).
    lines.append('(deny mach-lookup (global-name-prefix "com.apple.DiskArbitration") '
                 '(global-name-prefix "com.apple.diskimages") (xpc-service-name-prefix "com.apple.diskimages"))')
    lines.append("(deny file-mount)")
    # Other terminals' snapshots in the shared temp folder (this device's own Hermes, other sessions) are sourced by
    # their next command outside this sandbox: never readable or writable from here; this terminal's own are.
    lines.append(f'(deny file-read-data file-write* (regex #"^{_rx(tmp)}/hermes-(snap|cwd)-"))')
    lines.append(f'(allow file-read-data file-write* (regex #"^{_rx(tmp)}/hermes-(snap|cwd)-{own}"))')
    guarded = (*prot.no_write, *prot.no_read)
    allow = []
    for folder in (ws, tmp):
        # Opened again only when it lies inside a protected folder (the workspace always does; Hermes's own temp
        # folder does when no TMPDIR is set) and holds nothing protected itself (never the home, never a root).
        if any(_under(folder, p) for p in guarded) and not any(_under(p, folder) for p in guarded):
            allow.append(f"(subpath {_q(folder)})")
    if allow:
        # file-read-data, never file-read*: a wildcard allow does not undo the file-read-data deny above (checked
        # on macOS 27.2.1: getcwd and every read in the workspace failed with file-read*).
        lines.append("(allow file-read-data file-write* " + " ".join(dict.fromkeys(allow)) + ")")
    return "\n".join(lines) + "\n"


def verify_profile(profile: str) -> None:
    """Starts /usr/bin/true inside the profile once; a profile the system refuses is a LockError, never ignored."""
    try:
        proc = subprocess.run([SANDBOX_EXEC, "-p", profile, "/usr/bin/true"], capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as e:
        raise LockError(NO_SANDBOX.format(why=type(e).__name__)) from None
    if proc.returncode != 0:
        why = (proc.stderr.decode(errors="replace").strip().splitlines() or [f"exit {proc.returncode}"])[0][:160]
        raise LockError(NO_SANDBOX.format(why=why))


_LOCKED_CLASS: Any = None


def locked_environment(*, cwd: str, timeout: int, env: dict, workspace: str) -> Any:
    """The session's terminal: Hermes's LocalEnvironment, locked (macOS) or plainly (allow_unlocked_commands on).
    check_commands() decides first, so nothing is made where nothing may run."""
    check_commands()
    if _system() != "darwin" or unlocked():
        from tools.environments.local import LocalEnvironment
        return LocalEnvironment(cwd=cwd, timeout=timeout, env=env)
    global _LOCKED_CLASS
    if _LOCKED_CLASS is None:
        _LOCKED_CLASS = _make_locked_class()
    terminal = _LOCKED_CLASS(cwd=cwd, timeout=timeout, env=env, workspace=workspace)
    try:
        _check_applied(terminal)
    except BaseException:
        with contextlib.suppress(Exception):
            terminal.cleanup()
        raise
    return terminal


NOT_APPLIED = ("tether: this device's Hermes did not run the session's commands inside the session lock ({why}), so "
               "no remote command runs here. Update Tether and Hermes together.")


def _check_applied(terminal: Any) -> None:
    """The lock holds only if Hermes sends this terminal's processes through wrap_argv (gauntlet 3.1 F2). Checked
    when the terminal is made, with one probe command: it must go through the hook (whose profile is built and
    verified there; a profile the system refuses keeps its own reason), and, where this device has a protected Hermes
    file this process can read, the probe must not be able to read it. Any failure: LockError."""
    target = next((p for p in protected_set().scan_files if os.path.isfile(p) and os.access(p, os.R_OK)), None)
    probe = f"cat {shlex.quote(target)} >/dev/null 2>&1" if target else "true"
    result = terminal.execute(probe, timeout=30)
    error = getattr(terminal, "_tether_error", None)
    if error is not None:
        raise error
    if getattr(terminal, "_tether_profile", None) is None:
        raise LockError(NOT_APPLIED.format(why="its commands did not go through the lock"))
    if target and int(result.get("returncode", 1)) == 0:
        raise LockError(NOT_APPLIED.format(why="a protected file was readable"))


def _make_locked_class() -> Any:
    from tools.environments.local import LocalEnvironment

    class LockedEnvironment(LocalEnvironment):
        """Every process this terminal starts runs as /usr/bin/sandbox-exec -p <this session's profile> <command>,
        through Hermes's public LocalEnvironment.wrap_argv hook (its commands, its login shell and its long-lived
        children). A confined LocalEnvironment sends Hermes's file tools through execute(), so they see what its
        commands see (Hermes sets uses_host_filesystem False for it)."""

        def __init__(self, *, workspace: str, **kwargs: Any) -> None:
            self._tether_workspace = str(workspace)
            self._tether_profile: Optional[str] = None
            self._tether_error: Optional[BaseException] = None    # the first reason the lock could not start
            self._tether_run_env: Optional[dict] = None
            self._tether_lock = threading.Lock()
            super().__init__(**kwargs)          # init_session starts the first (login) shell: already locked

        def _tether_prefix(self, run_env: dict) -> list[str]:
            with self._tether_lock:
                if self._tether_profile is None:
                    profile = session_profile(workspace=self._tether_workspace, temp_dir=self.get_temp_dir(),
                                              own_id=str(getattr(self, "_session_id", "")),
                                              path=str(run_env.get("PATH") or ""))
                    verify_profile(profile)
                    self._tether_profile = profile
                return [SANDBOX_EXEC, "-p", self._tether_profile]

        def wrap_argv(self, argv: list[str], env: dict, *, purpose: str) -> list[str]:
            if purpose in ("command", "login"):
                self._tether_run_env = dict(env)        # the environment this terminal's commands get
            try:
                return [*self._tether_prefix(env), *argv]
            except LockError as e:
                self._tether_error = self._tether_error or e
                raise

        def tether_box_spec(self) -> tuple[list[str], dict, str]:
            """(the sandbox prefix with this session's profile, the environment its commands get, its temp folder):
            what the session's file-tool helper is started with (filebox, D79), so it runs in the same lock. The
            environment is the one Hermes handed wrap_argv for this terminal's shell (its login shell ran at start)."""
            run_env = dict(self._tether_run_env or {})
            return self._tether_prefix(run_env), run_env, self.get_temp_dir()

    return LockedEnvironment


# ---------- file tools: the early check (D76; since D79 the lock itself holds, see filebox) ----------
_FIRMLINK = "/System/Volumes/Data"


def _candidates(path: str, base: Optional[str]) -> list[str]:
    p = os.path.expanduser(path)
    if not os.path.isabs(p):
        p = os.path.join(base or os.getcwd(), p)
    # Never normalized before the links are resolved: 'link/..' is the folder above the link's target (S1-1).
    full = os.path.realpath(p)                                           # every link followed, in order
    head, tail = os.path.split(p.rstrip(os.sep) or os.sep)
    own = os.path.normpath(os.path.join(os.path.realpath(head or os.sep), tail))   # the name itself, not followed
    out = [full, own]
    for c in (full, own):                       # the data volume's own name for the same files (S2-1)
        if _fold(c).startswith(_fold(_FIRMLINK) + os.sep):
            out.append(c[len(_FIRMLINK):])
    return list(dict.fromkeys(out))


def _blocked(p: str, prot: Protected, workspace: Optional[str], write: bool) -> bool:
    if workspace and _under(p, _real(workspace)):
        return False
    if write:
        if any(_under(p, r) for r in prot.no_write) or any(_fold(p) == _fold(n) for n in prot.no_write_names):
            return True
        if any(re.search(rx, p, re.IGNORECASE if sys.platform == "darwin" else 0) for rx in prot.no_write_patterns):
            return True
    if any(_under(p, r) for r in prot.no_read) and not any(_under(p, r) for r in prot.readable):
        return True
    return False


def path_refusal(path: str, *, write: bool, base: Optional[str], workspace: Optional[str],
                 prot: Optional[Protected] = None) -> Optional[str]:
    """None when a file tool may use path for this session; otherwise the sentence for the agent."""
    prot = prot or protected_set()
    verb = "changing" if write else "reading"
    for c in _candidates(path, base):
        if _blocked(c, prot, workspace, write):
            return PATH_REFUSED.format(path=path, verb=verb)
    try:
        st = os.stat(_candidates(path, base)[0])
    except OSError:
        return None
    if st.st_nlink > 1 and (st.st_mode & 0o170000) == 0o100000:
        leak, inodes = linked_inodes(prot)
        if (st.st_dev, st.st_ino) in inodes:
            return PATH_REFUSED.format(path=path, verb=verb)
    return None


UNCHECKABLE = ("tether: this file tool's arguments are not in a form this device can check (a path must be text), so "
               "it was refused. Send the path as text.")


def tool_refusal(name: str, args: dict, *, base: Optional[str], workspace: Optional[str]) -> Optional[str]:
    """The check every lent file tool passes before Hermes runs it here (D76)."""
    prot = protected_set()
    leak, _ = linked_inodes(prot)
    if leak:
        return LINKED.format(path=leak)
    path = args.get("path")
    # A value this check cannot read is refused, never passed through (gauntlet 3.1 F3).
    if (path is not None and not isinstance(path, str)) or (name == "patch" and args.get("patch") is not None
                                                            and not isinstance(args.get("patch"), str)):
        return UNCHECKABLE
    if name == "read_file":
        return path_refusal(str(path or ""), write=False, base=base, workspace=workspace, prot=prot)
    if name == "write_file":
        return path_refusal(str(path or ""), write=True, base=base, workspace=workspace, prot=prot)
    if name == "search_files":
        whole = str(path or ".")
        # Hermes splits a search path that does not exist on commas and whitespace and searches every part (S1-2).
        for root in dict.fromkeys([whole, *(p for p in re.split(r"[,\s]+", whole) if p)]):
            hit = path_refusal(root, write=False, base=base, workspace=workspace, prot=prot)
            if hit:
                return hit
            for real in _candidates(root, base):
                for r in prot.no_read:
                    if _under(r, real):
                        return SEARCH_REFUSED.format(path=root, root=r)
        return None
    if name == "patch":
        paths = [str(path)] if path else []
        text = args.get("patch")
        if isinstance(text, str) and text.strip():
            try:
                from tools.patch_parser import parse_v4a_patch
                ops, error = parse_v4a_patch(text)
            except Exception:  # noqa: BLE001
                return PATCH_UNREAD
            if error and not ops:
                return PATCH_UNREAD
            for op in ops:
                paths.extend(p for p in (getattr(op, "file_path", None), getattr(op, "new_path", None)) if p)
        for p in paths:
            hit = path_refusal(p, write=True, base=base, workspace=workspace, prot=prot)
            if hit:
                return hit
        return None
    return None
