"""The agent's per-session home on a device (design D24, the author 2026-11-06).

While a host session works ON this device, its terminal starts in ``<data>/sessions/<session>/`` (0700): scratch
files, staging and read-only copies of the skills the agent opened live there. From there it reaches the rest of
the machine under this device's own Hermes rules. When the connection closes (the user said so, the idle timer
ran out, the grant lapsed) the folder is emptied and removed, and a device start wipes any left by a crash, so
nothing in it outlives the session or can be pulled back later.
"""
from __future__ import annotations

import io
import logging
import os
import re
import shutil
import sys
import stat
import tarfile
from pathlib import Path

logger = logging.getLogger(__name__)


def safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", str(value or "default"))[:120] or "default"


def _extended(abs_path: str) -> str:
    """Windows' extended-length form of an absolute path (``\\\\?\\C:\\...``, ``\\\\?\\UNC\\server\\...``). Through it,
    names Windows reserves for devices (``nul``, ``con``, ``aux``, ``com1``...) are ordinary files, so a stray ``nul``
    that a Unix-style shell wrote with ``> nul`` can be removed like any other file."""
    if abs_path.startswith("\\\\?\\"):
        return abs_path
    if abs_path.startswith("\\\\"):
        return "\\\\?\\UNC\\" + abs_path[2:]
    return "\\\\?\\" + abs_path


def _chmod(target: str, mode: int) -> None:
    try:
        os.chmod(target, mode)
    except OSError:   # a reserved name, a file another program holds: rmtree below still tries, then reports
        pass


def _force_rmtree(path: Path) -> bool:
    """Remove a workspace even where read-only files would stop it. True when it is gone. Windows also refuses
    to delete a file or folder a running program still holds open (an app started from the workspace): those
    are left, logged, and removed by the sweeper on a later pass instead of failing the close."""
    if not path.exists():
        return True
    top = _extended(os.path.abspath(path)) if os.name == "nt" else str(path)
    for root, dirs, files in os.walk(top):
        for d in dirs:
            _chmod(os.path.join(root, d), stat.S_IRWXU)
        for f in files:
            full = os.path.join(root, f)
            if not os.path.islink(full):
                _chmod(full, stat.S_IRUSR | stat.S_IWUSR)
    _chmod(top, stat.S_IRWXU)
    held: list[str] = []

    def retry(func, target, *_):
        try:
            os.chmod(target, stat.S_IRWXU)
            func(target)
        except OSError:
            held.append(str(target))

    if sys.version_info >= (3, 12):
        shutil.rmtree(top, onexc=retry)
    else:  # pragma: no cover - older Pythons
        shutil.rmtree(top, onerror=retry)
    if held or os.path.exists(top):
        logger.warning("tether: workspace %s partly in use (%d item(s)); the sweeper retries", path.name, len(held))
        return False
    return True


class Workspaces:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)

    def path(self, session: str) -> Path:
        return self.root / safe_name(session)

    def ensure(self, session: str) -> Path:
        p = self.path(session)
        p.mkdir(mode=0o700, exist_ok=True)
        return p

    def wipe(self, session: str) -> bool:
        p = self.path(session)
        if not p.exists():
            return False
        if not _force_rmtree(p):
            return False
        logger.info("tether: workspace for session %s emptied and removed", session)
        return True

    def wipe_all(self) -> int:
        n = 0
        for child in list(self.root.iterdir()):
            if child.is_dir():
                _force_rmtree(child)
                n += 1
        return n

    def sweep(self, live_sessions: set[str]) -> int:
        """Remove every workspace whose session no longer holds a grant on this device."""
        keep = {safe_name(s) for s in live_sessions}
        n = 0
        for child in list(self.root.iterdir()):
            if child.is_dir() and child.name not in keep and _force_rmtree(child):
                logger.info("tether: workspace %s removed (its grant lapsed)", child.name)
                n += 1
        return n

    def put_skill(self, session: str, name: str, packed: bytes) -> Path:
        """Unpack a host skill's folder (tar.gz) read-only into this session's workspace."""
        skills = self.ensure(session) / "skills"
        skills.mkdir(mode=0o700, exist_ok=True)
        os.chmod(skills, 0o700)                       # owner only, like the workspace itself
        dest = skills / safe_name(name)
        _force_rmtree(dest)
        dest.mkdir(mode=0o700)
        with tarfile.open(fileobj=io.BytesIO(packed), mode="r:gz") as tar:
            tar.extractall(dest, filter="data")          # no absolute paths, no '..', no links outside, no devices
        for root, dirs, files in os.walk(dest):
            for f in files:
                os.chmod(os.path.join(root, f), stat.S_IRUSR)
            for d in dirs:
                os.chmod(os.path.join(root, d), stat.S_IRUSR | stat.S_IXUSR)
        os.chmod(dest, stat.S_IRUSR | stat.S_IXUSR)
        return dest
