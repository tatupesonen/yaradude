"""Worker for the cross-process rate-limit test; imports nothing from Django."""

from pathlib import Path

from api import ratelimit


def hammer(directory: str, bucket: str, attempts: int, results) -> None:
    for _ in range(attempts):
        results.put(ratelimit.take(Path(directory), bucket, 50, 3600).allowed)
