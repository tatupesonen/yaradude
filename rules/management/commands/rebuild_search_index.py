from typing import Any

from django.core.management.base import BaseCommand, CommandError

from rules.services.search import index_is_consistent, rebuild_index


class Command(BaseCommand):
    help = (
        "Rebuild the full-text search index of rules from the rule table. The "
        "index is kept in sync by database triggers; this repairs it if it was "
        "ever damaged (for example by restoring the rule table on its own)."
    )

    def handle(self, *args: Any, **options: Any) -> None:
        count = rebuild_index()
        if not index_is_consistent():
            raise CommandError("The search index failed its integrity check after the rebuild.")
        self.stdout.write(self.style.SUCCESS(f"Search index rebuilt: {count} rules."))
