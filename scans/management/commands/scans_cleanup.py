from typing import Any

from django.core.management.base import BaseCommand

from scans import maintenance


class Command(BaseCommand):
    help = (
        "Delete scan jobs and task results past YARADUDE_SCAN_RETENTION_DAYS, fail jobs of "
        "dead workers and remove orphaned spool files. A maintenance worker also does this."
    )

    def handle(self, *args: Any, **options: Any) -> None:
        done = maintenance.cleanup()
        fixed = maintenance.repair()
        self.stdout.write(
            f"Deleted {done.jobs} jobs, {done.task_results} task results, {done.workers} stale "
            f"worker records; failed {fixed.lost_running + fixed.lost_queued} lost jobs; "
            f"removed {fixed.spool_removed} spool files."
        )
