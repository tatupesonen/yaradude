from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any

from django.conf import settings
from django.db import models
from django.utils import timezone

if TYPE_CHECKING:
    from accounts.models import User


class ScanJob(models.Model):
    """
    One sample scanned (or to be scanned) against the compiled rule set.
    Shared with the team: everyone with `rules.scan_rules` sees every job and
    who submitted it. The sample's bytes are never stored here; while the job
    is queued they live in the spool directory under `spool_token`.
    """

    class State(models.TextChoices):
        QUEUED = "queued", "Queued"
        RUNNING = "running", "Running"
        FINISHED = "finished", "Finished"
        FAILED = "failed", "Failed"

    class Phase(models.TextChoices):
        QUEUED = "queued", "Waiting for a worker"
        LOADING = "loading_rules", "Loading the compiled rules"
        SCANNING = "scanning", "Scanning"
        DONE = "done", "Done"

    TERMINAL = (State.FINISHED, State.FAILED)

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user: models.ForeignKey[User | None] = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="scan_jobs",
        help_text="Who submitted the sample (null once that user is deleted).",
    )
    batch = models.UUIDField(
        null=True, blank=True, help_text="Jobs submitted together share a batch id."
    )
    sample_name = models.CharField(max_length=255, blank=True)
    sample_size = models.PositiveBigIntegerField(default=0)
    sample_sha256 = models.CharField(max_length=64, blank=True)
    options: models.JSONField[dict[str, Any]] = models.JSONField(
        default=dict, blank=True, help_text='Limits: {"path": str, "tag": str, "rulesets": [id]}.'
    )
    state = models.CharField(max_length=16, choices=State.choices, default=State.QUEUED)
    phase = models.CharField(max_length=16, choices=Phase.choices, default=Phase.QUEUED)
    inline = models.BooleanField(default=False, help_text="Scanned at once, without the queue.")
    created_at = models.DateTimeField(default=timezone.now)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(default=timezone.now, help_text="Last state change.")
    error = models.TextField(blank=True)
    result: models.JSONField[dict[str, Any] | None] = models.JSONField(null=True, blank=True)
    match_count = models.PositiveIntegerField(default=0)
    revision = models.PositiveIntegerField(
        null=True, blank=True, help_text="Rules revision of the compiled set used."
    )
    rules_pending = models.BooleanField(
        default=False, help_text="Rules had changed and the newer compiled set was not ready."
    )
    task_id = models.CharField(max_length=64, blank=True)
    worker_id = models.CharField(max_length=64, blank=True)
    # Name of the spool file while queued; never shown, never in task arguments.
    spool_token = models.CharField(max_length=64, blank=True, editable=False)

    class Meta:
        ordering = ["-created_at", "-pk"]
        indexes = [
            models.Index(fields=["-created_at"], name="scanjob_created_idx"),
            models.Index(fields=["updated_at"], name="scanjob_updated_idx"),
            models.Index(fields=["state"], name="scanjob_state_idx"),
        ]

    def __str__(self) -> str:
        return f"{self.sample_name or '(unnamed)'} ({self.get_state_display()})"

    @property
    def done(self) -> bool:
        return self.state in self.TERMINAL

    @property
    def submitted_by(self) -> str:
        """Display name of the submitter."""
        return self.user.get_username() if self.user else "deleted user"


class WorkerProcess(models.Model):
    """Heartbeat of a running worker process (scan, maintenance or builder)."""

    worker_id = models.CharField(max_length=64, unique=True)
    role = models.CharField(max_length=16)
    hostname = models.CharField(max_length=255, blank=True)
    pid = models.PositiveIntegerField(default=0)
    started_at = models.DateTimeField(default=timezone.now)
    last_seen = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["role", "worker_id"]

    def __str__(self) -> str:
        return f"{self.role} {self.worker_id}"


class RecurringSchedule(models.Model):
    """
    State of one recurring task (scans.recurring): the id of its single
    pending occurrence and when it last ran.
    """

    name = models.CharField(max_length=255, unique=True, help_text="Task module path.")
    task_result_id = models.CharField(max_length=64, blank=True)
    last_started_at = models.DateTimeField(null=True, blank=True)
    last_finished_at = models.DateTimeField(null=True, blank=True)
    last_succeeded = models.BooleanField(null=True, blank=True)
    last_error = models.TextField(blank=True)
    runs = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["name"]

    def __str__(self) -> str:
        return self.name
