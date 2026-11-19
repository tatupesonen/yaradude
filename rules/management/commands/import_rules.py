from pathlib import Path
from typing import Any

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError, CommandParser

from rules.models import ImportRun
from rules.services.importer import import_directory


class Command(BaseCommand):
    help = (
        "Import YARA rule files (*.yar, *.yara) from a directory, by default "
        "YARADUDE_RULES_DIR. Exits non-zero if any file failed."
    )

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument(
            "path", nargs="?", help="Directory to import (default: YARADUDE_RULES_DIR)"
        )

    def handle(self, *args: Any, path: str | None = None, **options: Any) -> None:
        root = Path(path) if path else Path(settings.YARADUDE_RULES_DIR)
        if not root.is_dir():
            raise CommandError(f"Not a directory: {root}")
        run = import_directory(root, origin=ImportRun.Origin.CLI)
        for file in run.files.all():
            line = f"{file.get_status_display()}: {file.path}"
            if file.message:
                line += f" — {file.message}"
            self.stdout.write(line)
        self.stdout.write(run.summary)
        if run.files_failed:
            raise CommandError(f"{run.files_failed} file(s) failed to import.")
