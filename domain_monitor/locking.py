"""Single-instance file lock, cross-platform.

A zone transfer plus diff can take longer than the cron interval. Without a lock, two
runs would stage into the same tables and race on domain state. A whole-file exclusive
lock is the right weight for one host -- no distributed coordination is warranted.

POSIX and Windows have no common stdlib lock primitive, so this picks between the two
the platform actually offers rather than adding a dependency for it: ``fcntl.flock``
on POSIX, ``msvcrt.locking`` on Windows. Both are non-blocking-acquire, whole-process
locks tied to the open file description, and both raise ``OSError`` immediately if
another process already holds it -- which is the only contract the rest of this module
relies on.
"""

from __future__ import annotations

import contextlib
import logging
import os
import sys
from collections.abc import Iterator
from pathlib import Path

logger = logging.getLogger(__name__)

WINDOWS = sys.platform == "win32"

if WINDOWS:
    import msvcrt
else:
    import fcntl


class AlreadyRunning(Exception):
    """Another instance holds the lock."""


def _acquire(handle) -> None:
    """Raise OSError immediately if another process already holds the lock."""
    if WINDOWS:
        # msvcrt.locking() locks nbytes starting at the current seek position, and
        # documents that this may extend past the current end of file -- so a 1-byte
        # lock at offset 0 is well-defined even on a freshly created, empty file.
        # LK_NBLCK is the non-blocking variant: raise OSError at once rather than the
        # CRT's default behaviour of retrying for ~10 seconds.
        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
    else:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)


def _release(handle) -> None:
    if WINDOWS:
        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
    else:
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


@contextlib.contextmanager
def process_lock(path: Path | str) -> Iterator[None]:
    """Hold an exclusive lock for the duration of the block.

    Raises :class:`AlreadyRunning` immediately rather than waiting: a queued run would
    just transfer a zone that the running instance is already transferring.
    """
    path = Path(path)
    if path.parent and str(path.parent) not in ("", "."):
        path.parent.mkdir(parents=True, exist_ok=True)

    # Opened for read+write, created but never truncated, in binary mode so a seek(0)
    # actually seeks (text mode and "a"/append mode both risk the write landing
    # somewhere other than where msvcrt.locking() thinks it locked). The file must
    # exist before "r+b" will open it, hence the touch.
    if not path.exists():
        path.touch()

    handle = open(path, "r+b")
    try:
        try:
            _acquire(handle)
        except OSError as exc:
            raise AlreadyRunning(
                f"another domain-monitor run holds {path}; skipping this invocation"
            ) from exc

        handle.seek(0)
        handle.write(str(os.getpid()).encode("ascii"))
        handle.truncate()
        handle.flush()
        try:
            yield
        finally:
            _release(handle)
    finally:
        handle.close()
