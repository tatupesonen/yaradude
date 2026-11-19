"""
Worker heartbeats: every worker process records itself in `WorkerProcess`
and refreshes `last_seen` from a background thread, so a task or job whose
worker died can be told from one that is still running.
"""

from __future__ import annotations

import logging
import os
import socket
import threading
from datetime import datetime, timedelta

from django.conf import settings
from django.db import close_old_connections, connection
from django.utils import timezone

from scans.models import WorkerProcess

logger = logging.getLogger(__name__)

HEARTBEAT_SECONDS = 5

# Set by the worker command in worker processes; recorded on the jobs they run.
current_worker_id: str = ""


def lost_after() -> timedelta:
    """
    A worker silent for this long is gone. A scan holds the GIL, which can
    starve the heartbeat thread for up to the scan timeout, so the margin is
    the timeout plus a minute.
    """
    timeout: int = settings.YARADUDE_SCAN_TIMEOUT
    return timedelta(seconds=max(timeout, 30) + 60)


def alive_since() -> datetime:
    return timezone.now() - lost_after()


def is_alive(worker_id: str) -> bool:
    if not worker_id:
        return False
    return WorkerProcess.objects.filter(worker_id=worker_id, last_seen__gte=alive_since()).exists()


def alive_workers() -> dict[str, int]:
    """Live worker processes per role."""
    counts: dict[str, int] = {}
    for role in WorkerProcess.objects.filter(last_seen__gte=alive_since()).values_list(
        "role", flat=True
    ):
        counts[role] = counts.get(role, 0) + 1
    return counts


def register(worker_id: str, role: str) -> None:
    now = timezone.now()
    WorkerProcess.objects.update_or_create(
        worker_id=worker_id,
        defaults={
            "role": role,
            "hostname": socket.gethostname()[:255],
            "pid": os.getpid(),
            "started_at": now,
            "last_seen": now,
        },
    )


def forget(worker_id: str) -> None:
    WorkerProcess.objects.filter(worker_id=worker_id).delete()


class Heartbeat(threading.Thread):
    """Refreshes this worker's `last_seen` every few seconds until stopped."""

    def __init__(self, worker_id: str, role: str) -> None:
        super().__init__(name=f"heartbeat-{worker_id}", daemon=True)
        self.worker_id = worker_id
        self.role = role
        self.stopped = threading.Event()

    def run(self) -> None:
        try:
            while not self.stopped.wait(HEARTBEAT_SECONDS):
                try:
                    close_old_connections()
                    updated = WorkerProcess.objects.filter(worker_id=self.worker_id).update(
                        last_seen=timezone.now()
                    )
                    if not updated:  # removed by a cleanup while we were busy
                        register(self.worker_id, self.role)
                except Exception:
                    logger.exception("Heartbeat of %s failed", self.worker_id)
        finally:
            connection.close()

    def stop(self) -> None:
        self.stopped.set()
