"""Reading the tail of a log file, only from directories the operator has allowed.

The path is resolved first (symlinks and ``..`` included) and must end up inside an allowed directory. Then
the file is opened without following a final symlink and without blocking, the open file must be a regular
file, and the path the *open file* really has (from /proc/self/fd) is checked against the allowed directories
again. That last step closes the gap between "checked the name" and "opened the file".
"""

from __future__ import annotations

import os
import stat
from datetime import UTC, datetime
from pathlib import Path

WINDOW = 1 << 20  # at most this much of the end of a file is read
MAX_PATH = 4096


class Refused(Exception):
    """The request is not allowed. The message says why, and is safe to show."""


def within(path: Path, roots: list[Path]) -> bool:
    return any(path == r or r in path.parents for r in roots)


def describe_roots(roots: list[Path]) -> str:
    return ", ".join(str(r) for r in roots) if roots else "none"


def resolve(path: str, roots: list[Path]) -> Path:
    """The real path for ``path``, or ``Refused``."""
    if not roots:
        raise Refused("no log directory is allowed; start the server with --allow-dir")
    if len(path) > MAX_PATH or "\0" in path:
        raise Refused("that is not a usable path")
    if not path.startswith("/"):
        raise Refused(f"give an absolute path inside an allowed directory ({describe_roots(roots)})")
    real = Path(os.path.realpath(path))
    if not within(real, roots):
        raise Refused(f"{real} is outside the allowed directories ({describe_roots(roots)})")
    return real


def open_checked(real: Path, roots: list[Path]) -> int:
    """An open, read-only file descriptor for a regular file inside the roots, or ``Refused``."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC | getattr(os, "O_NOCTTY", 0)
    try:
        fd = os.open(real, flags)
    except FileNotFoundError:
        raise Refused(f"{real} does not exist") from None
    except PermissionError:
        raise Refused(f"{real} cannot be read by the user the server runs as") from None
    except OSError as exc:
        raise Refused(f"{real} cannot be opened: {exc.strerror}") from None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise Refused(f"{real} is not a regular file")
        try:
            actual = Path(os.readlink(f"/proc/self/fd/{fd}"))
        except OSError:
            raise Refused("cannot confirm which file was opened") from None
        if not within(actual, roots):
            raise Refused(f"{actual} is outside the allowed directories ({describe_roots(roots)})")
        return fd
    except BaseException:
        os.close(fd)
        raise


def tail(fd: int, max_lines: int, contains: str | None = None) -> tuple[list[str], bool, int]:
    """(last lines, whether older lines were left out, file size).

    Reads at most ``WINDOW`` bytes from the end. A file with a NUL byte in that window is refused as binary.
    ``contains`` keeps only lines with that text in them (case-insensitive, plain text, no pattern).
    """
    size = os.fstat(fd).st_size
    window = min(size, WINDOW)
    data = os.pread(fd, window, size - window) if window else b""
    if b"\0" in data:
        raise Refused("this looks like a binary file, not a text log")
    lines = data.decode("utf-8", errors="replace").splitlines()
    cut = window < size
    if cut and len(lines) > 1:
        lines = lines[1:]  # the first line is probably half of one
    if contains:
        needle = contains.lower()
        lines = [ln for ln in lines if needle in ln.lower()]
    left_out = cut or len(lines) > max_lines
    return lines[-max_lines:], left_out, size


def list_logs(roots: list[Path], limit: int, depth: int = 2) -> tuple[list[dict], bool]:
    """Regular files under the roots (symlinks are skipped entirely), newest first."""
    found: list[dict] = []

    def walk(directory: Path, level: int) -> None:
        try:
            entries = list(os.scandir(directory))
        except OSError:
            return
        for entry in entries:
            try:
                if entry.is_symlink():
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if level < depth:
                        walk(Path(entry.path), level + 1)
                elif entry.is_file(follow_symlinks=False):
                    st = entry.stat(follow_symlinks=False)
                    found.append(
                        {
                            "path": entry.path,
                            "size_bytes": st.st_size,
                            "modified": datetime.fromtimestamp(st.st_mtime, UTC).strftime(
                                "%Y-%m-%dT%H:%M:%SZ"
                            ),
                            "readable": os.access(entry.path, os.R_OK),
                        }
                    )
            except OSError:
                continue

    for root in roots:
        walk(root, 0)
    found.sort(key=lambda f: (f["modified"], f["path"]), reverse=True)
    return found[:limit], len(found) > limit
