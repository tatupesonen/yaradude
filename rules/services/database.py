"""
SQLite housekeeping (PLAN.md 8.1): planner statistics and the WAL file.

The connection settings themselves (WAL, cache, memory map, temp store,
journal size limit) are applied to every connection by `init_command` in
config/settings.py; `pragmas()` reads them back.
"""

import logging
from dataclasses import dataclass

from django.db import connections
from django.db.backends.base.base import BaseDatabaseWrapper

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Checkpoint:
    busy: bool  # a reader or writer prevented a complete checkpoint
    wal_pages: int  # pages in the WAL before the checkpoint (-1 if not in WAL mode)
    checkpointed: int


def _connection(connection: BaseDatabaseWrapper | None) -> BaseDatabaseWrapper:
    return connection if connection is not None else connections["default"]


def _usable(connection: BaseDatabaseWrapper) -> bool:
    return connection.vendor == "sqlite" and not connection.in_atomic_block


def optimize(connection: BaseDatabaseWrapper | None = None) -> None:
    """`PRAGMA optimize`: refresh planner statistics where they are stale (cheap when not)."""
    connection = _connection(connection)
    if not _usable(connection):
        return
    try:
        with connection.cursor() as cursor:
            cursor.execute("PRAGMA optimize")
    except Exception:
        logger.warning("PRAGMA optimize failed", exc_info=True)


def checkpoint(connection: BaseDatabaseWrapper | None = None) -> Checkpoint | None:
    """
    Copy the WAL into the database and truncate it to zero bytes. Waits up to
    the busy timeout for readers; if they keep it busy the result says so and
    the next run tries again. SQLite's automatic checkpoints (every 1000
    pages) are passive and never shrink the file; this one does.
    """
    connection = _connection(connection)
    if not _usable(connection):
        return None
    with connection.cursor() as cursor:
        cursor.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        row = cursor.fetchone()
    assert row is not None  # wal_checkpoint always returns one row
    busy, wal_pages, checkpointed = row
    result = Checkpoint(bool(busy), wal_pages, checkpointed)
    if result.busy:
        logger.info("WAL checkpoint incomplete (busy): %s", result)
    return result


def maintain(connection: BaseDatabaseWrapper | None = None) -> Checkpoint | None:
    """The periodic maintenance pass: optimize, then checkpoint."""
    optimize(connection)
    return checkpoint(connection)


def pragmas(connection: BaseDatabaseWrapper | None = None) -> dict[str, int | str]:
    """The tuning PRAGMAs as the current connection sees them."""
    values: dict[str, int | str] = {}
    with _connection(connection).cursor() as cursor:
        for name in (
            "journal_mode",
            "synchronous",
            "cache_size",
            "mmap_size",
            "temp_store",
            "journal_size_limit",
            "busy_timeout",
            "foreign_keys",
        ):
            cursor.execute(f"PRAGMA {name}")
            row = cursor.fetchone()
            assert row is not None  # these PRAGMAs always return one row
            values[name] = row[0]
    return values
