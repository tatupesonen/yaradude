"""Recurring maintenance tasks of the rules app (registered through scans.recurring)."""

from django.tasks import task  # ty: ignore[import-not-found]  # Django 6.0 module absent from django-types 0.24

from rules.services import database
from scans.queues import MAINTENANCE_QUEUE
from scans.recurring import recurring


@recurring("YARADUDE_DB_MAINTENANCE_INTERVAL")
@task(queue_name=MAINTENANCE_QUEUE)
def database_maintenance() -> None:
    """`PRAGMA optimize` and a truncating WAL checkpoint."""
    database.maintain()
