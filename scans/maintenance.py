"""
Housekeeping for scan jobs: repair after crashed workers, orphaned spool
files, and retention.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta

from django.conf import settings
from django.db.models import Q
from django.utils import timezone
from django_tasks_db.models import DBTaskResult

from scans import heartbeat, spool
from scans.models import ScanJob, WorkerProcess
from scans.queues import SCAN_QUEUE
from scans.tasking import TaskResultStatus

logger = logging.getLogger(__name__)

WORKER_LOST = "The scan worker stopped before the scan finished; submit the sample again."
QUEUE_LOST = "The job was lost from the queue; submit the sample again."


@dataclass(frozen=True)
class Repair:
    lost_running: int
    lost_queued: int
    spool_removed: int


def _fail(jobs: list[ScanJob], message: str) -> int:
    now = timezone.now()
    count = 0
    for job in jobs:
        spool.delete(job.spool_token)
        count += ScanJob.objects.filter(pk=job.pk, state=job.state).update(
            state=ScanJob.State.FAILED,
            phase=ScanJob.Phase.DONE,
            finished_at=now,
            updated_at=now,
            error=message,
            spool_token="",
        )
    return count


def repair() -> Repair:
    """
    Fail jobs whose worker is gone (or that ran far past the timeout), fail
    queued jobs whose task vanished, mark the scan tasks of dead workers
    failed, and delete spool files no live job refers to.
    """
    alive = set(
        WorkerProcess.objects.filter(last_seen__gte=heartbeat.alive_since()).values_list(
            "worker_id", flat=True
        )
    )
    timeout: int = settings.YARADUDE_SCAN_TIMEOUT
    overdue = timezone.now() - timedelta(seconds=timeout) - heartbeat.lost_after()
    running = list(
        ScanJob.objects.filter(state=ScanJob.State.RUNNING).only(
            "pk", "state", "worker_id", "started_at", "spool_token"
        )
    )
    lost = [
        job
        for job in running
        if job.worker_id not in alive or (job.started_at and job.started_at < overdue)
    ]
    lost_running = _fail(lost, WORKER_LOST)

    for result in DBTaskResult.objects.filter(
        status=TaskResultStatus.RUNNING, queue_name=SCAN_QUEUE
    ).only("id", "worker_ids"):
        if not result.worker_ids or result.worker_ids[-1] not in alive:
            DBTaskResult.objects.filter(id=result.id, status=TaskResultStatus.RUNNING).update(
                status=TaskResultStatus.FAILED,
                finished_at=timezone.now(),
                exception_class_path="scans.maintenance.WorkerLost",
                traceback="The worker running this task stopped.",
            )

    queued = list(
        ScanJob.objects.filter(state=ScanJob.State.QUEUED).only(
            "pk", "state", "task_id", "spool_token"
        )
    )
    waiting = {
        str(pk)
        for pk in DBTaskResult.objects.filter(
            id__in=[job.task_id for job in queued if job.task_id],
            status__in=[TaskResultStatus.READY, TaskResultStatus.RUNNING],
        ).values_list("id", flat=True)
    }
    lost_queued = _fail([job for job in queued if job.task_id not in waiting], QUEUE_LOST)

    keep = set(
        ScanJob.objects.filter(state__in=[ScanJob.State.QUEUED, ScanJob.State.RUNNING])
        .exclude(spool_token="")
        .values_list("spool_token", flat=True)
    )
    removed = spool.sweep(keep)
    if lost_running or lost_queued:
        logger.warning(
            "Failed %d lost running and %d lost queued scan jobs", lost_running, lost_queued
        )
    return Repair(lost_running, lost_queued, removed)


def forget_worker(worker_id: str) -> Repair:
    """A worker is known to be dead (its supervisor saw it exit): repair at once."""
    heartbeat.forget(worker_id)
    return repair()


@dataclass(frozen=True)
class Cleanup:
    jobs: int
    task_results: int
    workers: int


def cleanup(now: datetime | None = None) -> Cleanup:
    """Delete finished jobs and task results older than the retention, and stale heartbeats."""
    now = now or timezone.now()
    days: int = settings.YARADUDE_SCAN_RETENTION_DAYS
    cutoff = now - timedelta(days=days)
    jobs, _ = ScanJob.objects.filter(
        state__in=list(ScanJob.TERMINAL), finished_at__lt=cutoff
    ).delete()
    results, _ = DBTaskResult.objects.filter(
        Q(status=TaskResultStatus.SUCCESSFUL) | Q(status=TaskResultStatus.FAILED),
        finished_at__lt=cutoff,
    ).delete()
    workers, _ = WorkerProcess.objects.filter(last_seen__lt=now - timedelta(days=1)).delete()
    if jobs or results:
        logger.info("Retention: deleted %d scan jobs and %d task results", jobs, results)
    return Cleanup(jobs, results, workers)
