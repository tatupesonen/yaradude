from argparse import ArgumentParser
from typing import Any

from django.core.management.base import BaseCommand, CommandError

from rules.services import scanner


class Command(BaseCommand):
    help = (
        "Build the compiled rule set file now if it is out of date (or always with --force) "
        "and print its status. The builder worker normally does this."
    )

    def add_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument("--force", action="store_true")

    def handle(self, *args: Any, force: bool, **options: Any) -> None:
        outcome = scanner.build_compiled_set(force=force, wait=True)
        if outcome is None:
            raise CommandError("Another build did not finish in time.")
        info = outcome.info
        verb = "Built" if outcome.built else "Up to date:"
        self.stdout.write(
            f"{verb} revision {info.revision}, {info.rules} rules in {info.rulesets} rulesets, "
            f"{info.left_out} left out, {info.slow} slow, built {info.built_at:%Y-%m-%d %H:%M:%S} "
            f"in {info.build_seconds:.1f} s"
        )
