import os
import signal
from argparse import ArgumentParser
from typing import Any

from django.conf import settings
from django.core.management.base import BaseCommand
from django.utils import autoreload

from scans.worker import Supervisor

# django.utils.autoreload.DJANGO_AUTORELOAD_ENV (absent from the django-types stubs)
RELOADER_CHILD = "RUN_MAIN"


class Command(BaseCommand):
    help = (
        "Start the task workers: scan workers (scans queue), maintenance workers "
        "(maintenance queue) and the compiled rule set builder; restart them if they exit."
    )

    def add_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument(
            "--scan-workers",
            type=int,
            default=None,
            help="Scan worker processes (default: YARADUDE_SCAN_WORKERS).",
        )
        parser.add_argument(
            "--maintenance-workers",
            type=int,
            default=None,
            help="Maintenance worker processes (default: YARADUDE_MAINTENANCE_WORKERS).",
        )
        parser.add_argument("--no-builder", action="store_true", help="Do not start the builder.")
        parser.add_argument(
            "--reload", action="store_true", help="Restart the workers when code changes (dev)."
        )

    def handle(
        self,
        *args: Any,
        scan_workers: int | None,
        maintenance_workers: int | None,
        no_builder: bool,
        reload: bool,
        **options: Any,
    ) -> None:
        scans: int = settings.YARADUDE_SCAN_WORKERS if scan_workers is None else scan_workers
        maint: int = (
            settings.YARADUDE_MAINTENANCE_WORKERS
            if maintenance_workers is None
            else maintenance_workers
        )
        supervisor = Supervisor(scans, maint, builder=not no_builder)
        if reload:
            if os.environ.get(RELOADER_CHILD) == "true":
                signal.signal(signal.SIGTERM, supervisor.shutdown)
            autoreload.run_with_reloader(supervisor.run)
        else:
            signal.signal(signal.SIGTERM, supervisor.shutdown)
            signal.signal(signal.SIGINT, supervisor.shutdown)
            supervisor.run()
