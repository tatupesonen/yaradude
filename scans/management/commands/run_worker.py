from argparse import ArgumentParser
from typing import Any

from django.core.management.base import BaseCommand

from scans.worker import ROLES, run_role


class Command(BaseCommand):
    help = (
        "Run one worker process: 'scan' (scans queue), 'maintenance' (maintenance queue) "
        "or 'builder' (compiled rule set). Normally started by run_workers."
    )

    def add_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument("role", choices=ROLES)
        parser.add_argument("--worker-id", default=None, help="Unique id (default: generated).")
        parser.add_argument(
            "--max-tasks", type=int, default=None, help="Exit after this many tasks."
        )

    def handle(
        self, *args: Any, role: str, worker_id: str | None, max_tasks: int | None, **options: Any
    ) -> None:
        run_role(role, worker_id, max_tasks=max_tasks)
