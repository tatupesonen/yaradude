"""
Per-key rate limiting shared by every worker process on one host, without
Redis or any other service.

Each key has a token bucket in its own small file under a directory on the
local filesystem (YARADUDE_API_RATE_DIR). A request opens the file, takes an
exclusive `fcntl.flock`, reads the bucket (tokens, last refill time), refills
it for the time passed, takes one token if there is one, writes it back and
unlocks. `flock` locks belong to the open file description, so the lock
serialises threads of one process as well as separate worker processes
(gunicorn or ASGI workers alike), and the kernel drops it if a worker dies
while holding it.

Guarantee: for one key, across all processes that use the same directory on
the same host, at most `capacity + rate * t` requests are admitted in any
interval of t seconds (capacity = YARADUDE_API_RATE_LIMIT, rate = capacity
per YARADUDE_API_RATE_WINDOW seconds). Limits: the directory must be local
to the host (flock on network filesystems is unreliable), several web
containers or hosts each keep their own buckets (the limit multiplies by
their number), and buckets start full again if the directory is emptied (for
example a container restart with the directory on a tmpfs). The file name is
derived from the key's public id, never from its secret.

This module imports nothing from Django so that it can be exercised from
plain worker processes in the tests.
"""

from __future__ import annotations

import fcntl
import hashlib
import math
import os
import struct
import time
from dataclasses import dataclass
from pathlib import Path

_STATE = struct.Struct("<dd")  # tokens, last refill (time.time())


@dataclass(frozen=True)
class Decision:
    allowed: bool
    remaining: int
    retry_after: int  # seconds until one token is available again; 0 when allowed


def bucket_path(directory: Path, bucket: str) -> Path:
    name = hashlib.sha256(bucket.encode()).hexdigest()[:32]
    return directory / f"{name}.bucket"


def take(
    directory: Path, bucket: str, capacity: int, window: float, now: float | None = None
) -> Decision:
    """Take one token from `bucket`, refilled at `capacity` tokens per `window` seconds."""
    if capacity <= 0:
        return Decision(allowed=True, remaining=0, retry_after=0)
    rate = capacity / window
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(bucket_path(directory, bucket), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        now = time.time() if now is None else now
        raw = os.pread(fd, _STATE.size, 0)
        if len(raw) == _STATE.size:
            tokens, last = _STATE.unpack(raw)
            tokens = min(capacity, tokens + max(0.0, now - last) * rate)
        else:
            tokens = float(capacity)
        if tokens >= 1:
            tokens -= 1
            decision = Decision(allowed=True, remaining=int(tokens), retry_after=0)
        else:
            wait = math.ceil((1 - tokens) / rate)
            decision = Decision(allowed=False, remaining=0, retry_after=max(1, wait))
        os.pwrite(fd, _STATE.pack(tokens, now), 0)
    finally:
        os.close(fd)  # also releases the lock
    return decision
