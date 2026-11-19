"""
The sample spool (PLAN.md 12.9): where a queued sample waits for a worker.

- A private directory on the data volume (`<YARADUDE_SCAN_DIR>/spool`,
  mode 0700), files mode 0600, created with O_EXCL and O_NOFOLLOW.
- File names are 256-bit random tokens, stored only in `ScanJob.spool_token`
  (never in task arguments, results, logs or anything shown to users).
- The worker deletes the file in a `finally` as soon as the scan ends; the
  submitter deletes it if creating the job fails; `sweep()` removes files no
  queued or running job refers to (crashed workers, crashed submitters).
"""

from __future__ import annotations

import logging
import os
import secrets
import stat
import time
from pathlib import Path

from django.conf import settings

logger = logging.getLogger(__name__)

# Files younger than this are never swept: the submitter writes the file
# before its job row commits.
SWEEP_GRACE_SECONDS = 300


def spool_dir() -> Path:
    directory = Path(settings.YARADUDE_SCAN_DIR) / "spool"
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if stat.S_IMODE(directory.stat().st_mode) != 0o700:
        directory.chmod(0o700)
    return directory


def _path(token: str) -> Path:
    if not token or not token.replace("-", "").replace("_", "").isalnum():
        raise ValueError("invalid spool token")
    return spool_dir() / token


def write(data: bytes) -> str:
    """Store sample bytes under a new random name; returns the token."""
    token = secrets.token_urlsafe(32)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(_path(token), flags, 0o600)
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            view = view[written:]
    except BaseException:
        os.close(fd)
        _path(token).unlink(missing_ok=True)
        raise
    os.close(fd)
    return token


def read(token: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(_path(token), flags)
    with os.fdopen(fd, "rb") as f:
        return f.read()


def delete(token: str) -> None:
    if token:
        _path(token).unlink(missing_ok=True)


def exists(token: str) -> bool:
    return bool(token) and _path(token).exists()


def sweep(keep: set[str], grace: float = SWEEP_GRACE_SECONDS) -> int:
    """Delete spool files not in `keep` and older than `grace` seconds; returns the count."""
    removed = 0
    cutoff = time.time() - grace
    for entry in os.scandir(spool_dir()):
        if entry.name in keep:
            continue
        try:
            if entry.stat(follow_symlinks=False).st_mtime > cutoff:
                continue
            os.unlink(entry.path)
            removed += 1
        except FileNotFoundError:
            continue
    if removed:
        logger.warning("Removed %d orphaned spool file(s)", removed)
    return removed
