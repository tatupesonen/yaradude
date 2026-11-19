import tempfile
from pathlib import Path
from typing import Any

from django.conf import settings
from django.db import connections
from django.db.backends.base.base import BaseDatabaseWrapper
from django.test import TestCase

from rules.services import database


class PragmaTests(TestCase):
    def file_connection(self) -> BaseDatabaseWrapper:
        """A connection with the project's settings to a real database file."""
        directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        default = connections["default"]
        settings_dict: Any = {**default.settings_dict, "NAME": str(directory / "db.sqlite3")}
        wrapper = default.__class__(settings_dict, alias="pragma-check")
        self.addCleanup(wrapper.close)
        return wrapper

    def test_tuning_pragmas_take_effect(self) -> None:
        wrapper = self.file_connection()
        values = database.pragmas(wrapper)
        self.assertEqual(
            values,
            {
                "journal_mode": "wal",
                "synchronous": 1,  # NORMAL
                "cache_size": -settings.YARADUDE_DB_CACHE_MIB * 1024,
                "mmap_size": settings.YARADUDE_DB_MMAP_MIB * 1024 * 1024,
                "temp_store": 2,  # MEMORY
                "journal_size_limit": 64 * 1024 * 1024,
                "busy_timeout": 20_000,
                "foreign_keys": 1,
            },
        )

    def test_web_process_does_not_keep_connections(self) -> None:
        # Under the ASGI server a persistent connection is never reused
        # (PLAN.md 8.1); only task workers keep theirs.
        self.assertEqual(settings.DATABASES["default"]["CONN_MAX_AGE"], 0)
        self.assertTrue(settings.DATABASES["default"]["CONN_HEALTH_CHECKS"])

    def test_checkpoint_truncates_the_wal(self) -> None:
        wrapper = self.file_connection()
        with wrapper.cursor() as cursor:
            cursor.execute("CREATE TABLE t (x TEXT)")
            for _ in range(200):
                cursor.execute("INSERT INTO t VALUES (?)", ["x" * 4000])
        wal = Path(wrapper.settings_dict["NAME"] + "-wal")
        self.assertGreater(wal.stat().st_size, 0)
        result = database.maintain(wrapper)
        assert result is not None
        self.assertFalse(result.busy)
        self.assertEqual(wal.stat().st_size, 0)


class MaintenanceTaskTests(TestCase):
    def test_registered_as_a_recurring_maintenance_task(self) -> None:
        from rules.tasks import database_maintenance
        from scans.queues import MAINTENANCE_QUEUE
        from scans.recurring import registered

        entries = {entry.task: entry for entry in registered()}
        self.assertIn(database_maintenance, entries)
        self.assertEqual(database_maintenance.queue_name, MAINTENANCE_QUEUE)
        database_maintenance.call()  # runs on the test database without error
