"""Module-level tasks used by the scans tests (tasks must be importable by path)."""

from scans.queues import MAINTENANCE_QUEUE
from scans.recurring import recurring
from scans.tasking import task

calls: list[str] = []


@recurring("TEST_RECURRING_INTERVAL")
@task(queue_name=MAINTENANCE_QUEUE)
def tick() -> None:
    calls.append("tick")


@recurring("TEST_RECURRING_INTERVAL")
@task(queue_name=MAINTENANCE_QUEUE)
def boom() -> None:
    calls.append("boom")
    raise RuntimeError("pass failed")
