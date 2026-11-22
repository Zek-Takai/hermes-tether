"""The agent's per-session home on a device (design D24, the author 2026-11-06; cleanup rules D39).

While a host session works ON this device, its terminal starts in ``<data>/sessions/<session>/`` (0700): scratch
files, staging and read-only copies of the skills the agent opened live there. From there it reaches the rest of
the machine under this device's own Hermes rules. When the connection closes (the user said so, the idle timer
ran out, the grant lapsed) the folder is emptied and removed, and a device start wipes any left by a crash, so
nothing in it outlives the session or can be pulled back later.

Everything here stays inside Tether's own sessions folder, whatever a session's commands did to it (D39):
- On macOS and Linux every name is reached inside a folder held open (``dir_fd``), never through a path, so a link
  put anywhere (in place of the sessions folder, a workspace, ``skills``, or deeper) is removed itself and never
  followed, even when it appears while a cleanup runs.
- A folder of another file system mounted inside a workspace (a disk image, a network share) is never entered.
- Only folders are chmod-ed. A file's lock flag and ACL (macOS) are cleared only when the file has no other name:
  a hard link (``ln``, a local ``git clone``) shares its mode, flags and ACL with the person's own file.
- What cannot be removed (a file a program holds open, a lock Tether may not clear) is left, logged and retried by
  the sweeper; a cleanup never raises.
Windows has no folder-relative calls in Python: there each name is checked with lstat right before it is used
(links, junctions and other reparse points are removed themselves, never entered).
"""
from __future__ import annotations

import contextlib
import hashlib
import io
import logging
import os
import re
import shutil
import stat
import sys
import tarfile
import unicodedata
from pathlib import Path
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

_SLASHES = re.compile(r"[/\\]")


def check_session(value: Any) -> str:
    """The session id a host sent, as text. Raises ValueError for one that could name another folder or hide in a
    log or the Allow prompt: ``.``, ``..``, anything with a slash or a backslash, any control or format character
    (C0 and C1 controls, direction marks, unpaired surrogates, unassigned code points), a line or paragraph separator,
    or an overlong one. A missing id is the shared ``default`` session, as before."""
    session = str(value or "default")
    if session in (".", "..") or len(session) > 200 or _SLASHES.search(session):
        raise ValueError("unusable session id")
    for ch in session:
        kind = unicodedata.category(ch)
        if kind[0] == "C" or kind in ("Zl", "Zp"):
            raise ValueError("unusable session id")
    return session


def safe_name(value: str) -> str:
    """A folder name for a session id (or a skill name). Anything but letters, digits, dot, dash and underscore
    becomes ``_``; leading and trailing dots go, so ``.`` and ``..`` can never name a folder; and whenever the
    name had to change, a short digest of the original is added. Two ids can still meet in one name (an id spelled
    like another id's folder name, or the same letters in another case on macOS and Windows), so the sweeper
    compares names case-folded."""
    raw = str(value or "default")
    clean = re.sub(r"[^A-Za-z0-9._-]", "_", raw)[:80].strip(".") or "session"
    if clean != raw:
        clean += "-" + hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:10]
    return clean


def _extended(abs_path: str) -> str:
    """Windows' extended-length form of an absolute path (``\\\\?\\C:\\...``, ``\\\\?\\UNC\\server\\...``). Through it,
    names Windows reserves for devices (``nul``, ``con``, ``aux``, ``com1``...) are ordinary files, so a stray ``nul``
    that a Unix-style shell wrote with ``> nul`` can be removed like any other file."""
    if abs_path.startswith("\\\\?\\"):
        return abs_path
    if abs_path.startswith("\\\\"):
        return "\\\\?\\UNC\\" + abs_path[2:]
    return "\\\\?\\" + abs_path


class WorkspaceError(PermissionError):
    """The sessions folder, or a path into it, is not Tether's own folder any more: refused, nothing touched."""


_USE_FDS = os.name != "nt"          # Windows: Python has no folder-relative (dir_fd) calls there
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_DIR_OPEN = os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC
_FILE_OPEN = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | _O_NOFOLLOW | _O_CLOEXEC   # never waits on a pipe
_LOCKS = getattr(stat, "UF_IMMUTABLE", 0) | getattr(stat, "UF_APPEND", 0)   # macOS: Finder's "Locked", append-only
_REPARSE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_ACL_TYPE_EXTENDED = 0x00000100     # macOS <sys/acl.h>
_libc: Any = None


@contextlib.contextmanager
def _closing(fd: int):
    try:
        yield fd
    finally:
        os.close(fd)


def _names(fd: int) -> list[str]:
    with os.scandir(fd) as it:
        return [entry.name for entry in it]


def _darwin_libc() -> Any:
    """libc's fchflags and ACL calls (macOS), loaded once; None when they cannot be loaded."""
    global _libc
    if _libc is None:
        try:
            import ctypes
            import ctypes.util
            lib = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
            lib.fchflags.argtypes = [ctypes.c_int, ctypes.c_uint32]
            lib.acl_init.restype = ctypes.c_void_p
            lib.acl_init.argtypes = [ctypes.c_int]
            lib.acl_set_fd_np.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
            lib.acl_free.argtypes = [ctypes.c_void_p]
            _libc = lib
        except Exception:  # noqa: BLE001 - no ctypes: locked entries are left for the sweeper and logged
            _libc = False
    return _libc or None


def _unlock_fd(fd: int, st: os.stat_result) -> None:
    """macOS: clear the lock flags and the ACL of the entry held open as fd. Through its descriptor, never by name,
    so never through a link."""
    lib = _darwin_libc() if sys.platform == "darwin" else None
    if lib is None:
        return
    flags = getattr(st, "st_flags", 0) or 0
    if flags & _LOCKS:
        lib.fchflags(fd, flags & ~_LOCKS)
    acl = lib.acl_init(0)
    if acl:
        try:
            lib.acl_set_fd_np(fd, acl, _ACL_TYPE_EXTENDED)
        finally:
            lib.acl_free(acl)


def _chmod_at(dir_fd: int, name: str, mode: int, folder: bool) -> None:
    """chmod one entry of an open folder by name, never through a link. macOS and current Linux do it in one call;
    older Linux (no chmod that refuses links) changes the entry held open, after checking what it is."""
    try:
        os.chmod(name, mode, dir_fd=dir_fd, follow_symlinks=False)
        return
    except NotImplementedError:
        pass
    with _closing(os.open(name, _DIR_OPEN if folder else _FILE_OPEN, dir_fd=dir_fd)) as fd:
        here = os.fstat(fd)
        if stat.S_ISDIR(here.st_mode) if folder else (stat.S_ISREG(here.st_mode) and here.st_nlink == 1):
            os.fchmod(fd, mode)


def _open_folder(dir_fd: int, name: str, st: os.stat_result) -> int:
    """Open the folder `name` of an open folder, to list and empty it: never through a link (O_NOFOLLOW), only the
    very folder looked at (st), with owner rwx (read-only skill copies) and, on macOS, without a lock flag or an ACL
    that denies listing. Raises OSError when it cannot."""
    try:
        fd = os.open(name, _DIR_OPEN, dir_fd=dir_fd)
    except PermissionError:
        with contextlib.suppress(OSError):
            _chmod_at(dir_fd, name, stat.S_IMODE(st.st_mode) | stat.S_IRWXU, folder=True)
        try:
            fd = os.open(name, _DIR_OPEN, dir_fd=dir_fd)
        except PermissionError:
            if sys.platform != "darwin":
                raise
            # An ACL that denies listing, or a lock flag that refused the chmod: O_SEARCH needs only search. Clear both
            # through that descriptor, give the owner rwx, then open.
            with _closing(os.open(name, os.O_SEARCH | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC, dir_fd=dir_fd)) as sfd:
                here = os.fstat(sfd)
                if not os.path.samestat(here, st):
                    raise OSError(f"{name!r} changed while it was being opened") from None
                _unlock_fd(sfd, here)
                os.fchmod(sfd, stat.S_IMODE(here.st_mode) | stat.S_IRWXU)
            fd = os.open(name, _DIR_OPEN, dir_fd=dir_fd)
    try:
        here = os.fstat(fd)
        if not os.path.samestat(here, st):
            raise OSError(f"{name!r} changed while it was being opened")
        if (getattr(here, "st_flags", 0) or 0) & _LOCKS:
            _unlock_fd(fd, here)
        if stat.S_IMODE(here.st_mode) & stat.S_IRWXU != stat.S_IRWXU:
            os.fchmod(fd, stat.S_IMODE(here.st_mode) | stat.S_IRWXU)
    except BaseException:
        os.close(fd)
        raise
    return fd


def _is_link(st: os.stat_result) -> bool:
    """A link, or on Windows a junction or any other reparse point: removed itself, never entered or followed."""
    return stat.S_ISLNK(st.st_mode) or bool(getattr(st, "st_file_attributes", 0) & _REPARSE)


class _Cleanup:
    """One removal inside Tether's sessions folder (D39). A link is removed itself and never followed; a folder of
    another file system mounted inside is never entered; only folders are chmod-ed, and a lock flag or ACL is cleared
    only on an entry with no other name (a hard link shares them with the person's own file). What cannot go is
    listed in ``held``; nothing raises."""

    def __init__(self, dev: int) -> None:
        self.dev = dev                        # the sessions folder's file system
        self.held: list[str] = []

    def remove_at(self, dir_fd: int, name: str, where: str) -> None:
        """Remove `name` inside the open folder dir_fd (a folder is emptied first)."""
        try:
            st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        except Exception:  # noqa: BLE001
            self.held.append(where)
            return
        try:
            if stat.S_ISDIR(st.st_mode):
                if st.st_dev != self.dev:     # a disk image or share mounted here: never entered, never emptied
                    self.held.append(where)
                    return
                with _closing(_open_folder(dir_fd, name, st)) as fd:
                    for child in _names(fd):
                        self.remove_at(fd, child, f"{where}/{child}")
                self._gone(os.rmdir, dir_fd, name, st)
            else:                             # a file, a link (removed itself, never followed), a pipe or a socket
                self._gone(os.unlink, dir_fd, name, st)
        except Exception:  # noqa: BLE001 - one entry never stops a close, the sweeper or a device start
            logger.debug("tether: %r was not removed", where, exc_info=True)
            self.held.append(where)

    def _gone(self, remove: Callable, dir_fd: int, name: str, st: os.stat_result) -> None:
        try:
            remove(name, dir_fd=dir_fd)
            return
        except FileNotFoundError:
            return
        except PermissionError:               # macOS: a lock flag, or an ACL that denies deleting
            if not self._unlock(dir_fd, name, st):
                raise
        remove(name, dir_fd=dir_fd)

    @staticmethod
    def _unlock(dir_fd: int, name: str, st: os.stat_result) -> bool:
        """Clear the lock flag and ACL of one entry (macOS), through a descriptor of that very entry. Never on a file
        with another name elsewhere: its flags and ACL are the person's own file's too."""
        if sys.platform != "darwin":
            return False
        if stat.S_ISDIR(st.st_mode):
            how = os.O_SEARCH | _O_DIRECTORY | _O_NOFOLLOW
        elif st.st_nlink != 1:
            return False
        elif stat.S_ISLNK(st.st_mode):
            how = os.O_SYMLINK                # opens the link itself, never what it points to
        elif stat.S_ISREG(st.st_mode):
            how = _FILE_OPEN
        else:
            return False
        with _closing(os.open(name, how | _O_CLOEXEC, dir_fd=dir_fd)) as fd:
            here = os.fstat(fd)
            if not os.path.samestat(here, st) or (not stat.S_ISDIR(here.st_mode) and here.st_nlink != 1):
                return False
            _unlock_fd(fd, here)
            return True


class _PathCleanup:
    """Windows: the rules of _Cleanup by path, each name checked with lstat right before it is used."""

    def __init__(self, dev: int) -> None:
        self.dev = dev
        self.held: list[str] = []

    def remove(self, path: str, where: str) -> None:
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            return
        except Exception:  # noqa: BLE001
            self.held.append(where)
            return
        try:
            if stat.S_ISDIR(st.st_mode) and not _is_link(st):
                if st.st_dev != self.dev:
                    self.held.append(where)
                    return
                if not st.st_mode & stat.S_IWRITE:        # the read-only mark on a folder
                    os.chmod(path, stat.S_IRWXU)
                for child in os.listdir(path):
                    self.remove(os.path.join(path, child), f"{where}/{child}")
                self._gone(os.rmdir, path, st)
            else:                                         # a file, or a link or junction itself
                self._gone(os.unlink, path, st)
        except Exception:  # noqa: BLE001 - one entry never stops a close, the sweeper or a device start
            logger.debug("tether: %r was not removed", where, exc_info=True)
            self.held.append(where)

    @staticmethod
    def _gone(remove: Callable, path: str, st: os.stat_result) -> None:
        try:
            remove(path)
            return
        except FileNotFoundError:
            return
        except PermissionError:
            # Windows will not delete a read-only file. That mark is cleared only on a plain file with no other name
            # (a hard link shares it with the person's own file), never on a link or junction.
            if _is_link(st) or not stat.S_ISREG(st.st_mode) or st.st_nlink > 1 or st.st_mode & stat.S_IWRITE:
                raise
            os.chmod(path, stat.S_IWRITE)
        remove(path)


def _read_only(dir_fd: int, dev: int) -> None:
    """Files 0400 and folders 0500 below an open folder, by name inside open folders: never through a link, never a
    file with another name elsewhere, never into another file system."""
    for name in _names(dir_fd):
        st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        if stat.S_ISDIR(st.st_mode) and st.st_dev == dev:
            with _closing(_open_folder(dir_fd, name, st)) as fd:
                _read_only(fd, dev)
                os.fchmod(fd, stat.S_IRUSR | stat.S_IXUSR)
        elif stat.S_ISREG(st.st_mode) and st.st_nlink == 1:
            _chmod_at(dir_fd, name, stat.S_IRUSR, folder=False)


_SKILL_ROOT = "/tether-skill-copy"     # tarfile's data filter judges each name against this, by its text only


def _extract_at(top: int, tar: tarfile.TarFile) -> None:
    """Unpack a skill's files into the folder held open as ``top`` (macOS, Linux): each folder below is made and
    opened inside the one above it, each file created there (O_EXCL, O_NOFOLLOW). A link the session puts anywhere
    while the copy runs (at the skill's folder, the workspace or deeper) is never written through: the open fails and
    the copy stops (R4-1; the earlier copy wrote member by member by path). tarfile's data filter still refuses
    absolute names, '..' and links that leave the copy; devices and pipes are skipped."""
    for member in tar.getmembers():
        member = tarfile.data_filter(member, _SKILL_ROOT)
        parts = [p for p in member.name.split("/") if p not in ("", ".")]
        if not parts or ".." in parts:
            continue
        fds: list[int] = []
        try:
            parent = top
            for part in parts[:-1]:
                parent = _made_folder(parent, part)
                fds.append(parent)
            last = parts[-1]
            if member.isdir():
                fds.append(_made_folder(parent, last))
            elif member.isreg() or member.islnk():
                src = tar.extractfile(member)
                fd = os.open(last, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW | _O_CLOEXEC, 0o600,
                             dir_fd=parent)
                with os.fdopen(fd, "wb") as out:
                    if src is not None:
                        shutil.copyfileobj(src, out, 1 << 20)
            elif member.issym():
                os.symlink(member.linkname, last, dir_fd=parent)
        finally:
            for fd in fds:
                os.close(fd)


def _made_folder(parent: int, name: str) -> int:
    """The real folder ``name`` in an open folder, made when missing; a link or anything else there is an error."""
    with contextlib.suppress(FileExistsError):
        os.mkdir(name, 0o700, dir_fd=parent)
    fd = os.open(name, _DIR_OPEN, dir_fd=parent)
    if not stat.S_ISDIR(os.fstat(fd).st_mode):
        os.close(fd)
        raise WorkspaceError(f"tether: {name!r} in the skill copy is not a folder; the copy stopped")
    return fd


def _path_read_only(top: str, dev: int) -> None:
    for name in os.listdir(top):
        path = os.path.join(top, name)
        st = os.lstat(path)
        if _is_link(st):
            continue
        if stat.S_ISDIR(st.st_mode) and st.st_dev == dev:
            _path_read_only(path, dev)
            os.chmod(path, stat.S_IRUSR | stat.S_IXUSR)
        elif stat.S_ISREG(st.st_mode) and st.st_nlink <= 1:
            os.chmod(path, stat.S_IRUSR)


class Workspaces:
    """The sessions folder ``<data>/sessions`` and the workspaces in it. On macOS and Linux, Tether's data folder is held
    open for the life of this object, and every name below it is resolved inside folders held open (D39)."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self._data_fd: Optional[int] = None
        self.root.parent.mkdir(parents=True, exist_ok=True)    # normally made already (store.data_dir)
        if not _USE_FDS:
            self._path_root()
            return
        try:
            self._data_fd = os.open(self.root.parent, _DIR_OPEN)
        except OSError as e:
            raise WorkspaceError(f"tether: {self.root.parent} is not a plain folder (a link?); session workspaces "
                                 "are not kept there") from e
        try:
            os.close(self._open_root())
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        fd, self._data_fd = self._data_fd, None
        if fd is not None:
            with contextlib.suppress(Exception):
                os.close(fd)

    def __del__(self) -> None:
        with contextlib.suppress(Exception):
            self.close()

    def path(self, session: str) -> Path:
        return self.root / safe_name(session)        # always directly inside the root (see safe_name)

    # ---------- the sessions folder and the folders in it (macOS, Linux) ----------
    def _open_root(self) -> int:
        """The sessions folder, held open. A link put in its place is removed (never followed) and the folder made
        again; anything else in its place is refused."""
        if self._data_fd is None:
            raise WorkspaceError("tether: the session workspaces are closed")
        name = self.root.name
        for _ in range(3):
            try:
                st = os.stat(name, dir_fd=self._data_fd, follow_symlinks=False)
            except FileNotFoundError:
                with contextlib.suppress(FileExistsError):
                    os.mkdir(name, 0o700, dir_fd=self._data_fd)
                continue
            if stat.S_ISLNK(st.st_mode):
                logger.warning("tether: %s was replaced by a link; the link was removed, never followed, and the "
                               "folder made again", self.root)
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(name, dir_fd=self._data_fd)
                continue
            if not stat.S_ISDIR(st.st_mode):
                raise WorkspaceError(f"tether: {self.root} is not a folder; nothing in it was touched")
            fd = _open_folder(self._data_fd, name, st)
            if stat.S_IMODE(os.fstat(fd).st_mode) != 0o700:
                os.fchmod(fd, 0o700)                 # owner only: the folder itself, never what a link points to
            return fd
        raise WorkspaceError(f"tether: {self.root} keeps changing; nothing in it was touched")

    @staticmethod
    def _child(parent_fd: int, name: str) -> int:
        """The real folder `name` inside an open folder, made (0700) when missing. A link, a file or a mount in its place
        is removed first (a link itself, never what it points to)."""
        for _ in range(3):
            try:
                st = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                with contextlib.suppress(FileExistsError):
                    os.mkdir(name, 0o700, dir_fd=parent_fd)
                continue
            dev = os.fstat(parent_fd).st_dev
            if stat.S_ISDIR(st.st_mode) and st.st_dev == dev:
                return _open_folder(parent_fd, name, st)
            job = _Cleanup(dev)
            job.remove_at(parent_fd, name, name)
            if job.held:
                break
        raise WorkspaceError(f"tether: {name!r} in the session workspace is not a folder Tether can use")

    @staticmethod
    def _leads_to(path: Path, fd: int) -> Path:
        """A path handed out (a terminal's start, a file tool's base, a skill copy's place) must reach the folder just
        checked: no link anywhere above it now."""
        try:
            if os.path.samestat(os.stat(path), os.fstat(fd)):
                return path
        except OSError:
            pass
        raise WorkspaceError("tether: the session workspace's path no longer leads to Tether's own folder (a folder "
                             "above it was moved or replaced); restart Hermes on this device")

    # ---------- the same on Windows, by path ----------
    def _path_root(self) -> str:
        parent = os.lstat(self.root.parent)
        if _is_link(parent) or not stat.S_ISDIR(parent.st_mode):
            raise WorkspaceError(f"tether: {self.root.parent} is not a plain folder (a link?); session workspaces "
                                 "are not kept there")
        for _ in range(3):
            try:
                st = os.lstat(self.root)
            except FileNotFoundError:
                with contextlib.suppress(FileExistsError):
                    os.mkdir(self.root, 0o700)
                continue
            if _is_link(st):
                logger.warning("tether: %s was replaced by a link; the link was removed, never followed, and the "
                               "folder made again", self.root)
                os.unlink(self.root)
                continue
            if not stat.S_ISDIR(st.st_mode):
                raise WorkspaceError(f"tether: {self.root} is not a folder; nothing in it was touched")
            top = os.path.abspath(self.root)
            return _extended(top) if os.name == "nt" else top
        raise WorkspaceError(f"tether: {self.root} keeps changing; nothing in it was touched")

    @staticmethod
    def _path_child(parent: str, name: str) -> str:
        path = os.path.join(parent, name)
        for _ in range(3):
            try:
                st = os.lstat(path)
            except FileNotFoundError:
                with contextlib.suppress(FileExistsError):
                    os.mkdir(path, 0o700)
                continue
            dev = os.lstat(parent).st_dev
            if stat.S_ISDIR(st.st_mode) and not _is_link(st) and st.st_dev == dev:
                return path
            job = _PathCleanup(dev)
            job.remove(path, name)
            if job.held:
                break
        raise WorkspaceError(f"tether: {name!r} in the session workspace is not a folder Tether can use")

    # ---------- what the device uses ----------
    def ensure(self, session: str) -> Path:
        """The session's workspace (0700), made when missing: always a real folder directly inside Tether's own sessions
        folder, and the path handed back leads there."""
        name = safe_name(session)
        if not _USE_FDS:
            self._path_child(self._path_root(), name)
            return self.root / name
        with _closing(self._open_root()) as root, _closing(self._child(root, name)) as ws:
            return self._leads_to(self.root / name, ws)

    def wipe(self, session: str) -> bool:
        name = safe_name(session)
        try:
            job = self._remove(name)
        except Exception:  # noqa: BLE001 - a close never fails on its workspace
            logger.warning("tether: workspace %r not removed", name, exc_info=True)
            return False
        if job is None:
            return False
        if job.held:
            logger.warning("tether: workspace %r partly in use (%d item(s)); the sweeper retries", name, len(job.held))
            return False
        logger.info("tether: workspace for session %s emptied and removed", session)
        return True

    def _remove(self, name: str) -> Any:
        """Remove one entry of the sessions folder; None when there is nothing by that name."""
        if not _USE_FDS:
            top = self._path_root()
            path = os.path.join(top, name)
            if not os.path.lexists(path):
                return None
            job = _PathCleanup(os.lstat(top).st_dev)
            job.remove(path, name)
            return job
        with _closing(self._open_root()) as root:
            try:
                os.stat(name, dir_fd=root, follow_symlinks=False)
            except FileNotFoundError:
                return None
            job = _Cleanup(os.fstat(root).st_dev)
            job.remove_at(root, name, name)
            return job

    def wipe_all(self) -> int:
        """Device start: remove every workspace (and any link) left in the sessions folder. Returns how many
        workspaces went."""
        return self._clear(lambda name: True, "left by an earlier run")

    def sweep(self, live_sessions: set[str]) -> int:
        """Remove every workspace whose session no longer holds a grant on this device (names compared case-folded:
        macOS and Windows treat other letter case as the same folder)."""
        keep = {safe_name(s).casefold() for s in live_sessions}
        return self._clear(lambda name: name.casefold() not in keep, "its grant lapsed")

    def _clear(self, drop: Callable[[str], bool], why: str) -> int:
        """Remove every link, and every folder `drop` picks, in the sessions folder. Never raises."""
        n = 0
        try:
            if _USE_FDS:
                with _closing(self._open_root()) as root:
                    dev = os.fstat(root).st_dev
                    for name in _names(root):
                        try:
                            st = os.stat(name, dir_fd=root, follow_symlinks=False)
                        except OSError:
                            continue
                        if stat.S_ISLNK(st.st_mode) or (stat.S_ISDIR(st.st_mode) and drop(name)):
                            job = _Cleanup(dev)
                            job.remove_at(root, name, name)
                            n += self._report(name, st, job.held, why)
            else:
                top = self._path_root()
                dev = os.lstat(top).st_dev
                for name in os.listdir(top):
                    path = os.path.join(top, name)
                    try:
                        st = os.lstat(path)
                    except OSError:
                        continue
                    if _is_link(st) or (stat.S_ISDIR(st.st_mode) and drop(name)):
                        job = _PathCleanup(dev)
                        job.remove(path, name)
                        n += self._report(name, st, job.held, why)
        except Exception:  # noqa: BLE001 - the sweeper and a device start go on
            logger.warning("tether: the session workspaces were not swept", exc_info=True)
        return n

    @staticmethod
    def _report(name: str, st: os.stat_result, held: list[str], why: str) -> int:
        if held:
            logger.warning("tether: workspace %r partly in use (%d item(s)); the sweeper retries", name, len(held))
            return 0
        if _is_link(st) or not stat.S_ISDIR(st.st_mode):
            return 0                                  # a link is never a workspace: removed, not counted
        logger.info("tether: workspace %r removed (%s)", name, why)
        return 1

    def put_skill(self, session: str, name: str, packed: bytes) -> Path:
        """Unpack a host skill's folder (tar.gz) read-only into this session's workspace, at skills/<name>. Every level
        is Tether's own folder: a link put at the workspace, at skills or at the skill's name is removed, never
        followed (D39)."""
        ws_name, skill = safe_name(session), safe_name(name)
        dest = self.root / ws_name / "skills" / skill
        if not _USE_FDS:
            skills = self._path_child(self._path_child(self._path_root(), ws_name), "skills")
            dev = os.lstat(skills).st_dev
            job = _PathCleanup(dev)
            job.remove(os.path.join(skills, skill), skill)        # the earlier copy of this skill
            if job.held:
                raise WorkspaceError("tether: the earlier copy of this skill could not be removed; it was not copied")
            os.mkdir(os.path.join(skills, skill), 0o700)
            with tarfile.open(fileobj=io.BytesIO(packed), mode="r:gz") as tar:
                tar.extractall(dest, filter="data")              # no absolute paths, no '..', no links outside
            _path_read_only(os.path.join(skills, skill), dev)
            os.chmod(os.path.join(skills, skill), stat.S_IRUSR | stat.S_IXUSR)
            return dest
        with _closing(self._open_root()) as root, _closing(self._child(root, ws_name)) as ws, \
                _closing(self._child(ws, "skills")) as skills:
            os.fchmod(skills, 0o700)                              # owner only, like the workspace itself
            dev = os.fstat(root).st_dev
            job = _Cleanup(dev)
            job.remove_at(skills, skill, skill)                   # the earlier copy of this skill
            if job.held:
                raise WorkspaceError("tether: the earlier copy of this skill could not be removed; it was not copied")
            os.mkdir(skill, 0o700, dir_fd=skills)
            with _closing(_open_folder(skills, skill, os.stat(skill, dir_fd=skills, follow_symlinks=False))) as fd:
                self._leads_to(dest, fd)                          # nothing above the copy was swapped for a link
                with tarfile.open(fileobj=io.BytesIO(packed), mode="r:gz") as tar:
                    _extract_at(fd, tar)                          # inside the folder held open, never by path
                _read_only(fd, dev)
                os.fchmod(fd, stat.S_IRUSR | stat.S_IXUSR)
        return dest
