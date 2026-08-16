"""Single-instance file lock.

A zone transfer plus diff can take longer than the cron interval. Without a lock, two
runs would stage into the same tables and race on domain state. A ``flock`` on a local
file is the right weight for one host -- no distributed coordination is warranted.
"""

from __future__ import annotations

import contextlib
import fcntl
import logging
import os
from collections.abc import Iterator
from pathlib import Path

logger = logging.getLogger(__name__)


class AlreadyRunning(Exception):
    """Another instance holds the lock."""


@contextlib.contextmanager
def process_lock(path: Path | str) -> Iterator[None]:
    """Hold an exclusive lock for the duration of the block.

    Raises :class:`AlreadyRunning` immediately rather than waiting: a queued run would
    just transfer a zone that the running instance is already transferring.
    """
    path = Path(path)
    if path.parent and str(path.parent) not in ("", "."):
        path.parent.mkdir(parents=True, exist_ok=True)

    handle = open(path, "w")
    try:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise AlreadyRunning(
                f"another domain-monitor run holds {path}; skipping this invocation"
            ) from exc

        handle.write(str(os.getpid()))
        handle.flush()
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    finally:
        handle.close()
