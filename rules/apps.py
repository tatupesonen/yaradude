from typing import Any

from django.apps import AppConfig
from django.core import checks


def check_full_text_search(**kwargs: Any) -> list[checks.CheckMessage]:
    """Rule search needs SQLite's FTS5 with the trigram tokenizer (PLAN.md 12.5)."""
    from rules.services.search import fts_support

    if problem := fts_support():
        return [
            checks.Error(
                problem,
                hint="Use a Python linked against SQLite 3.34+ with FTS5, such as "
                "the python:3.13-slim-bookworm base image (SQLite 3.40).",
                id="rules.E001",
            )
        ]
    return []


def ensure_search_index(using: str = "default", **kwargs: Any) -> None:
    """post_migrate: restore the search index triggers if a migration dropped them."""
    from django.db import connections

    from rules.services.search import ensure_index

    if connections[using].vendor == "sqlite":
        ensure_index(using)


class RulesConfig(AppConfig):
    name = "rules"

    def ready(self) -> None:
        from django.db.models.signals import post_migrate

        checks.register(check_full_text_search)
        post_migrate.connect(ensure_search_index, sender=self, dispatch_uid="rules.search_index")
