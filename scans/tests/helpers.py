"""Shared helpers for the scans tests."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
from typing import Any

from django.contrib.auth.models import Group
from django.test import SimpleTestCase, override_settings

from accounts.models import User
from rules.services import scanner
from scans import heartbeat
from scans.worker import QueueWorker


def make_user(username: str = "viewer", *, group: str | None = "Viewers", **extra: Any) -> User:
    user = User.objects.create_user(username=username, password="x", **extra)
    if group:
        user.groups.add(Group.objects.get(name=group))
    return user


class ScanDirMixin(SimpleTestCase):
    """A private YARADUDE_SCAN_DIR per test, compiled-set cache on, no set loaded."""

    scan_dir: Path
    cache = True

    def setUp(self) -> None:
        super().setUp()
        self.scan_dir = Path(tempfile.mkdtemp(prefix="yaradude-scan-test-"))
        self._override = override_settings(
            YARADUDE_SCAN_DIR=self.scan_dir, YARADUDE_SCAN_COMPILED_CACHE=self.cache
        )
        self._override.enable()
        scanner.forget_loaded_set()

    def tearDown(self) -> None:
        scanner.forget_loaded_set()
        self._override.disable()
        shutil.rmtree(self.scan_dir, ignore_errors=True)
        super().tearDown()


def worker(role: str = "scan", worker_id: str | None = None) -> QueueWorker:
    """An in-process queue worker with a live heartbeat row."""
    worker_id = worker_id or f"{role}-test"
    heartbeat.register(worker_id, role)
    heartbeat.current_worker_id = worker_id
    return QueueWorker(role, worker_id)


def drain(queue_worker: QueueWorker, limit: int = 20) -> int:
    """Run due tasks until none is left; returns how many ran."""
    ran = 0
    while ran < limit and queue_worker.run_once():
        ran += 1
    return ran
