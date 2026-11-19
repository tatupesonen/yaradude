"""
Worker processes (PLAN.md 12.9).

Roles, one per process:
- `scan`: runs tasks of the `scans` queue; holds the compiled rule set and
  loads a newer file while idle, so a job never waits for it.
- `maintenance`: runs tasks of the `maintenance` queue (directory passes,
  cleanup); every REPAIR_SECONDS while idle it repairs recurring schedules
  and lost jobs.
- `builder`: no queue; rebuilds the compiled rule set file whenever the rules
  revision moves (checked every BUILD_CHECK_SECONDS). The build lock keeps
  this the only build even if several builders run.

`Supervisor` starts and restarts the children (`manage.py run_workers`).

Queue workers are django-tasks-db workers (claiming, running and recording
tasks exactly as its `db_worker`), with a different wait: an idle worker
checks for due work with a read-only indexed query every
YARADUDE_WORKER_POLL_MS and opens the exclusive claiming transaction only
when there is some. The stock worker takes SQLite's write lock on every
poll.
"""

from __future__ import annotations

import atexit
import logging
import os
import signal
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from types import FrameType

from django.conf import settings
from django.db import close_old_connections, connection
from django.db.utils import OperationalError
from django.utils.crypto import get_random_string
from django_tasks_db.management.commands.db_worker import Worker
from django_tasks_db.models import DBTaskResult
from django_tasks_db.utils import exclusive_transaction, is_locked_database_exception

from rules.services import revision, scanner
from scans import heartbeat, maintenance, recurring
from scans.queues import MAINTENANCE_QUEUE, SCAN_QUEUE

logger = logging.getLogger(__name__)

ROLE_SCAN = "scan"
ROLE_MAINTENANCE = "maintenance"
ROLE_BUILDER = "builder"
ROLES = (ROLE_SCAN, ROLE_MAINTENANCE, ROLE_BUILDER)
ROLE_QUEUES = {ROLE_SCAN: SCAN_QUEUE, ROLE_MAINTENANCE: MAINTENANCE_QUEUE}

REPAIR_SECONDS = recurring.REPAIR_SECONDS
BUILD_CHECK_SECONDS = 0.5


def new_worker_id(role: str) -> str:
    return f"{role}-{get_random_string(12)}"


class QueueWorker(Worker):
    """A django-tasks-db worker for one queue with a cheap idle wait."""

    def __init__(self, role: str, worker_id: str, *, max_tasks: int | None = None) -> None:
        poll_ms: int = settings.YARADUDE_WORKER_POLL_MS
        super().__init__(
            queue_names=[ROLE_QUEUES[role]],
            interval=poll_ms / 1000,
            batch=False,
            backend_name="default",
            startup_delay=False,
            max_tasks=max_tasks,
            worker_id=worker_id,
            excluded_queue_names=[],
        )
        self.role = role
        self.parent = os.getppid()
        self.last_repair = 0.0

    def ready_tasks(self):  # noqa: ANN201  (a django-tasks-db queryset)
        return DBTaskResult.objects.ready().filter(
            backend_name=self.backend_name, queue_name__in=self.queue_names
        )

    def startup(self) -> None:
        maintenance.repair()
        recurring.ensure_all_scheduled()
        if self.role == ROLE_SCAN:
            try:
                scanner.compiled_set()  # warm: the first job does not load it
            except scanner.ScanError:
                logger.exception("No compiled rule set yet")
        self.last_repair = time.monotonic()

    def idle(self) -> None:
        """Between tasks: keep the compiled set fresh, repair now and then."""
        if self.role == ROLE_SCAN and scanner.loaded_set() is not None:
            try:
                scanner.refresh_loaded_set()
            except Exception:
                logger.exception("Could not load the new compiled rule set")
        if self.role == ROLE_MAINTENANCE and time.monotonic() - self.last_repair > REPAIR_SECONDS:
            self.last_repair = time.monotonic()
            try:
                recurring.ensure_all_scheduled()
                maintenance.repair()
            except OperationalError:
                logger.exception("Repair pass failed")

    def orphaned(self) -> bool:
        """The supervisor died: stop instead of running unsupervised."""
        return self.parent != 1 and os.getppid() != self.parent

    def run_once(self) -> bool:
        """Claim and run one due task; False when there was none."""
        tasks = self.ready_tasks()
        if not tasks.exists():
            return False
        task_result = None
        with exclusive_transaction(tasks.db):
            try:
                task_result = tasks.get_locked()
                if task_result is not None:
                    task_result.claim(self.worker_id)
            except OperationalError as error:
                if not is_locked_database_exception(error):
                    raise
                task_result = None
        if task_result is None:
            return False
        self.run_task(task_result)
        return True

    def run(self) -> None:
        logger.info("Starting %s worker %s (queue %s)", self.role, self.worker_id, self.queue_names)
        self.startup()
        while self.running:
            close_old_connections()
            if self.orphaned():
                logger.warning("Supervisor gone; worker %s exits", self.worker_id)
                return
            ran = self.run_once()
            if self.max_tasks is not None and self._run_tasks >= self.max_tasks:
                return
            if not ran and self.running:
                self.idle()
                time.sleep(self.interval)


class Builder:
    """Rebuilds the compiled rule set file when the rules revision moves."""

    def __init__(self, worker_id: str) -> None:
        self.worker_id = worker_id
        self.running = True
        self.parent = os.getppid()

    def shutdown(self, signum: int, frame: FrameType | None) -> None:
        self.running = False

    def check(self) -> scanner.BuildOutcome | None:
        """One check: build if the file does not match the current revision."""
        info = scanner.read_info()
        if info is not None and info["key"] == scanner.set_key(revision.current()):
            return None
        return scanner.build_compiled_set()

    def run(self) -> None:
        logger.info("Starting compiled rule set builder %s", self.worker_id)
        while self.running:
            close_old_connections()
            if self.parent != 1 and os.getppid() != self.parent:
                return
            try:
                self.check()
            except Exception:
                logger.exception("Building the compiled rule set failed")
                time.sleep(5)
            time.sleep(BUILD_CHECK_SECONDS)


def run_role(role: str, worker_id: str | None = None, *, max_tasks: int | None = None) -> None:
    """Run one worker process of `role` until it is stopped."""
    worker_id = worker_id or new_worker_id(role)
    heartbeat.current_worker_id = worker_id
    heartbeat.register(worker_id, role)
    beat = heartbeat.Heartbeat(worker_id, role)
    beat.start()

    def goodbye() -> None:
        beat.stop()
        try:
            close_old_connections()
            heartbeat.forget(worker_id)
        except Exception:  # the database may be gone at exit
            logger.debug("Could not remove heartbeat of %s", worker_id)

    atexit.register(goodbye)
    try:
        if role == ROLE_BUILDER:
            builder = Builder(worker_id)
            signal.signal(signal.SIGTERM, builder.shutdown)
            signal.signal(signal.SIGINT, builder.shutdown)
            builder.run()
        else:
            worker = QueueWorker(role, worker_id, max_tasks=max_tasks)
            worker.configure_signals()
            worker.run()
    finally:
        goodbye()
        atexit.unregister(goodbye)
        connection.close()


@dataclass
class Child:
    role: str
    worker_id: str = ""
    process: subprocess.Popen[bytes] | None = None
    restarts: int = 0
    started: float = 0.0
    next_start: float = 0.0


@dataclass
class Supervisor:
    """
    Starts `scan_workers` scan workers, `maintenance_workers` maintenance
    workers and (unless `builder` is False) one builder as child processes,
    restarts any that exit (with back-off) and fails the jobs of a child that
    died at once. SIGTERM / SIGINT stop the children gracefully: a running
    task is finished first, up to the scan timeout.
    """

    scan_workers: int
    maintenance_workers: int
    builder: bool = True
    command: Callable[[str, str], list[str]] | None = None
    children: list[Child] = field(default_factory=list)
    running: bool = True

    def child_command(self, role: str, worker_id: str) -> list[str]:
        if self.command is not None:
            return self.command(role, worker_id)
        manage = str(settings.BASE_DIR / "manage.py")
        return [sys.executable, manage, "run_worker", role, "--worker-id", worker_id]

    def start(self, child: Child) -> None:
        child.worker_id = new_worker_id(child.role)
        child.process = subprocess.Popen(self.child_command(child.role, child.worker_id))
        child.started = time.monotonic()
        logger.info("Started %s worker %s (pid %s)", child.role, child.worker_id, child.process.pid)

    def shutdown(self, signum: int, frame: FrameType | None) -> None:
        self.running = False

    def stop_children(self) -> None:
        timeout: int = settings.YARADUDE_SCAN_TIMEOUT
        for child in self.children:
            if child.process and child.process.poll() is None:
                child.process.terminate()
        deadline = time.monotonic() + timeout + 5
        for child in self.children:
            if child.process is None:
                continue
            try:
                child.process.wait(max(0.1, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                child.process.kill()
                child.process.wait()

    def run(self) -> None:
        self.children = [
            *(Child(ROLE_SCAN) for _ in range(self.scan_workers)),
            *(Child(ROLE_MAINTENANCE) for _ in range(self.maintenance_workers)),
            *([Child(ROLE_BUILDER)] if self.builder else []),
        ]
        atexit.register(self.stop_children)
        for child in self.children:
            self.start(child)
        while self.running:
            time.sleep(0.5)
            for child in self.children:
                process = child.process
                if process is None:
                    if time.monotonic() >= child.next_start and self.running:
                        self.start(child)
                    continue
                if process.poll() is None:
                    continue
                logger.warning(
                    "%s worker %s exited with %s", child.role, child.worker_id, process.returncode
                )
                try:
                    close_old_connections()
                    maintenance.forget_worker(child.worker_id)
                except Exception:
                    logger.exception("Repair after %s failed", child.worker_id)
                # Quick crash loops back off up to 30 s; a long-lived child restarts at once.
                lived = time.monotonic() - child.started
                child.restarts = 0 if lived > 60 else child.restarts + 1
                child.next_start = time.monotonic() + min(30, 2**child.restarts - 1)
                child.process = None
        self.stop_children()
        atexit.unregister(self.stop_children)
