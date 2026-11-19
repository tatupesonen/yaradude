"""
Recurring tasks on Django Tasks (PLAN.md 5.7, "Recurring tasks").

Django Tasks has no scheduler. A recurring task here is an ordinary task
registered with an interval setting; its next occurrence is an ordinary
queued task with `run_after` (django-tasks-db stores it and its workers
skip it until then), so nothing sleeps.

Guarantees:
- At most one pending occurrence (queued or running) per recurring task.
  The id of that occurrence lives in `RecurringSchedule`; every change to
  it happens inside one IMMEDIATE transaction, which SQLite serialises
  across processes, so simultaneous starts cannot create duplicates.
- The next occurrence is scheduled when an occurrence finishes, whether it
  succeeded or raised (`task_finished` signal), at the later of "now" and
  "start of the finished run + interval". A run longer than the interval is
  followed at once by exactly one new run: no pile-up.
- A lost schedule is repaired by `ensure_all_scheduled()`: missing schedule
  row (fresh database), pending occurrence deleted (queue emptied), pending
  occurrence still "running" although its worker is gone (killed mid-run),
  or a finished occurrence whose follow-up was never written. Every worker
  process calls it at start, and maintenance workers call it every
  REPAIR_SECONDS while idle.
- Interval 0 (or less) turns the task off: a waiting occurrence is
  removed and nothing is scheduled; a running one is allowed to finish.

Declaring one::

    from scans.tasking import task
    from scans.queues import MAINTENANCE_QUEUE
    from scans.recurring import recurring

    @recurring("YARADUDE_RULES_WATCH_INTERVAL")  # setting name, seconds
    @task(queue_name=MAINTENANCE_QUEUE)
    def watch_rules_directory() -> None: ...

in an app's `tasks.py` (imported in every process by `scans.apps`). The
task takes no arguments.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from django.conf import settings
from django.db import transaction
from django.utils import timezone
from django_tasks_db.models import DBTaskResult, get_date_max

from scans import heartbeat
from scans.models import RecurringSchedule
from scans.tasking import Task, TaskResult, TaskResultStatus, task_finished, task_started

logger = logging.getLogger(__name__)

REPAIR_SECONDS = 30  # how often idle maintenance workers run ensure_all_scheduled()


@dataclass(frozen=True)
class Recurring:
    task: Task[[], Any]
    interval_setting: str

    @property
    def name(self) -> str:
        return self.task.module_path

    @property
    def interval(self) -> float:
        """Seconds between starts; 0 or less means off."""
        value: float = getattr(settings, self.interval_setting, 0) or 0
        return float(value)


_registry: dict[str, Recurring] = {}


def recurring(interval_setting: str) -> Callable[[Task[[], Any]], Task[[], Any]]:
    """Register a task (applied on top of `@task`) to run every `interval_setting` seconds."""

    def register(task: Task[[], Any]) -> Task[[], Any]:
        if not isinstance(task, Task):
            raise TypeError("@recurring goes above @task(...)")
        _registry[task.module_path] = Recurring(task, interval_setting)
        return task

    return register


def registered() -> list[Recurring]:
    return sorted(_registry.values(), key=lambda r: r.name)


def _lookup(task: Task[[], Any] | str) -> Recurring:
    name = task if isinstance(task, str) else task.module_path
    try:
        return _registry[name]
    except KeyError:
        raise LookupError(f"{name} is not a registered recurring task") from None


@dataclass(frozen=True)
class RecurringStatus:
    name: str
    interval: float  # seconds; 0 = off
    enabled: bool
    scheduled_for: (
        datetime | None
    )  # when the waiting occurrence becomes due (None: none, or due now)
    waiting: bool  # an occurrence is queued
    running: bool  # an occurrence is running now
    last_started_at: datetime | None
    last_finished_at: datetime | None
    last_succeeded: bool | None
    last_error: str  # exception class of the last failed run, or "worker lost"
    runs: int


def _mark_lost(result_id: str) -> None:
    DBTaskResult.objects.filter(id=result_id, status=TaskResultStatus.RUNNING).update(
        status=TaskResultStatus.FAILED,
        finished_at=timezone.now(),
        exception_class_path="scans.recurring.WorkerLost",
        traceback="The worker running this task stopped.",
    )


def ensure_scheduled(task: Task[[], Any] | str) -> RecurringStatus:
    """
    Make sure exactly one occurrence is pending (or none, when off); repair
    a lost schedule. Idempotent and safe to call from any process.
    """
    entry = _lookup(task)
    interval = entry.interval
    now = timezone.now()
    with transaction.atomic():
        schedule, _ = RecurringSchedule.objects.get_or_create(name=entry.name)
        pending = (
            DBTaskResult.objects.filter(id=schedule.task_result_id).first()
            if schedule.task_result_id
            else None
        )
        if pending is not None and pending.status == TaskResultStatus.RUNNING:
            worker = pending.worker_ids[-1] if pending.worker_ids else ""
            if heartbeat.is_alive(worker):
                return status(entry.name)
            logger.warning("Recurring task %s: its worker %s is gone", entry.name, worker)
            _mark_lost(str(pending.id))
            schedule.last_succeeded = False
            schedule.last_error = "worker lost"
            schedule.last_finished_at = now
            pending = None

        if interval <= 0:
            if pending is not None and pending.status == TaskResultStatus.READY:
                pending.delete()
            schedule.task_result_id = ""
            schedule.save()
            return status(entry.name)

        due = now
        if schedule.last_started_at is not None:
            due = max(now, schedule.last_started_at + timedelta(seconds=interval))
        if pending is not None and pending.status == TaskResultStatus.READY:
            # Already waiting; pull it forward if the interval was shortened.
            if pending.run_after != get_date_max() and pending.run_after > due:
                pending.run_after = due
                pending.save(update_fields=["run_after"])
            schedule.save()
            return status(entry.name)

        result = _enqueue(entry, due if due > now else None)
        schedule.task_result_id = str(result.id)
        schedule.save()
    return status(entry.name)


def _enqueue(entry: Recurring, run_after: datetime | None) -> TaskResult[[], Any]:
    task = entry.task.using(run_after=run_after) if run_after else entry.task
    return task.enqueue()


def ensure_all_scheduled() -> None:
    """ensure_scheduled() for every registered recurring task; errors are logged."""
    for entry in registered():
        try:
            ensure_scheduled(entry.name)
        except Exception:
            logger.exception("Could not schedule recurring task %s", entry.name)


def run_now(task: Task[[], Any] | str) -> RecurringStatus:
    """Make the waiting occurrence due now (schedules one if none is pending)."""
    entry = _lookup(task)
    ensure_scheduled(entry.name)
    with transaction.atomic():
        schedule = RecurringSchedule.objects.get(name=entry.name)
        if schedule.task_result_id:
            DBTaskResult.objects.filter(
                id=schedule.task_result_id, status=TaskResultStatus.READY
            ).update(run_after=get_date_max())
    return status(entry.name)


def status(task: Task[[], Any] | str) -> RecurringStatus:
    """When a recurring task last ran and whether (and when) it is scheduled."""
    entry = _lookup(task)
    schedule = RecurringSchedule.objects.filter(name=entry.name).first()
    pending = None
    if schedule is not None and schedule.task_result_id:
        pending = (
            DBTaskResult.objects.filter(id=schedule.task_result_id)
            .values_list("status", "run_after")
            .first()
        )
    waiting = pending is not None and pending[0] == TaskResultStatus.READY
    run_after = pending[1] if pending is not None and waiting else None
    return RecurringStatus(
        name=entry.name,
        interval=entry.interval,
        enabled=entry.interval > 0,
        scheduled_for=run_after if run_after and run_after != get_date_max() else None,
        waiting=waiting,
        running=pending is not None and pending[0] == TaskResultStatus.RUNNING,
        last_started_at=schedule.last_started_at if schedule else None,
        last_finished_at=schedule.last_finished_at if schedule else None,
        last_succeeded=schedule.last_succeeded if schedule else None,
        last_error=schedule.last_error if schedule else "",
        runs=schedule.runs if schedule else 0,
    )


def _on_started(sender: Any, task_result: TaskResult[Any, Any], **kwargs: Any) -> None:
    # Signal receivers must never raise: an exception here would be recorded
    # as the task's own failure. A missed update is repaired by
    # ensure_all_scheduled().
    try:
        name = task_result.task.module_path
        if name in _registry:
            RecurringSchedule.objects.update_or_create(
                name=name, defaults={"last_started_at": task_result.started_at or timezone.now()}
            )
    except Exception:
        logger.exception("Recurring bookkeeping failed at start")


def _on_finished(sender: Any, task_result: TaskResult[Any, Any], **kwargs: Any) -> None:
    try:
        name = task_result.task.module_path
        if name not in _registry:
            return
        succeeded = task_result.status == TaskResultStatus.SUCCESSFUL
        error = (
            ""
            if succeeded
            else (task_result.errors[-1].exception_class_path if task_result.errors else "failed")
        )
        with transaction.atomic():
            schedule, _ = RecurringSchedule.objects.get_or_create(name=name)
            schedule.last_finished_at = task_result.finished_at or timezone.now()
            schedule.last_succeeded = succeeded
            schedule.last_error = error
            schedule.runs += 1
            schedule.save()
        ensure_scheduled(name)
    except Exception:
        logger.exception("Recurring bookkeeping failed at finish")


def connect_signals() -> None:
    task_started.connect(_on_started, dispatch_uid="scans.recurring.started")
    task_finished.connect(_on_finished, dispatch_uid="scans.recurring.finished")
