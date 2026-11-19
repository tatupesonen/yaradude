"""
Scan jobs (PLAN.md 12.9 and the service API in 5.7).

A scan is a `ScanJob`. `submit_samples` scans a single small sample at once
in the calling process (the fast path) and records it as a finished job;
everything else is written to the spool and queued for the scan workers
(`scans.tasks.run_scan_job`). Results are stored as JSON without any sample
bytes: offsets and lengths of the matches, never previews.

Jobs are shared with the team: every user with `rules.scan_rules` may list
and open every job; users without it see none.
"""

from __future__ import annotations

import hashlib
import logging
import threading
import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import PurePath
from typing import Any

from django.conf import settings
from django.core.files import File
from django.db import transaction
from django.db.models import QuerySet
from django.utils import timezone

from accounts.models import User
from rules.models import Ruleset
from rules.services import scanner
from rules.services.scanner import ScanError, ScanResult, ScanTimeout
from scans import heartbeat, recurring, spool
from scans.models import ScanJob

logger = logging.getLogger(__name__)

SCAN_PERMISSION = "rules.scan_rules"

# At most one fast-path scan at a time per process; while it is busy, small
# samples go through the queue instead of waiting (the engine holds the GIL).
_inline_lane = threading.Lock()


def can_scan(user: object) -> bool:
    """Signed in, active and allowed to scan (`rules.scan_rules`)."""
    return isinstance(user, User) and user.is_active and user.has_perm(SCAN_PERMISSION)


# ---------------------------------------------------------------------------
# Submitting


def _options(path: str, tag: str, rulesets: Iterable[Ruleset | int] | None) -> dict[str, Any]:
    ids = (
        sorted({r if isinstance(r, int) else r.pk for r in rulesets})
        if rulesets is not None
        else None
    )
    return {"path": path.strip()[:1024], "tag": tag.strip()[:128], "rulesets": ids}


def _limit(options: dict[str, Any]) -> scanner.ScanLimit:
    return scanner.limit_for(
        path=options.get("path") or "",
        tag=options.get("tag") or "",
        rulesets=options.get("rulesets"),
    )


def result_json(result: ScanResult) -> dict[str, Any]:
    """The stored form of a scan result: no sample bytes (offsets and lengths only)."""
    return {
        "matches": [
            {
                "rule_id": match.rule.pk,
                "rule": match.rule.name,
                "ruleset_id": match.rule.ruleset_id,
                "ruleset": match.ruleset.name,
                "ruleset_path": match.ruleset.path,
                "tags": match.tags,
                "patterns": [
                    {
                        "identifier": pattern.identifier,
                        "count": pattern.count,
                        "instances": [
                            {"offset": i.offset, "length": i.length} for i in pattern.instances
                        ],
                    }
                    for pattern in match.patterns
                ],
            }
            for match in result.matches
        ],
        "rules_scanned": result.rules_scanned,
        "rulesets": len(result.rulesets),
        "left_out": [
            {
                "rule_id": rule.pk,
                "rule": rule.name,
                "ruleset_id": rule.ruleset_id,
                "ruleset": rule.ruleset.name,
            }
            for rule in result.left_out
        ],
        "unmapped": result.unmapped,
        "compiled": {
            "revision": result.revision,
            "built_at": result.built_at.isoformat() if result.built_at else None,
            "pending": result.pending,
        },
        "scan_seconds": round(result.scan_seconds, 6),
    }


def _finished_fields(result: ScanResult) -> dict[str, Any]:
    now = timezone.now()
    return {
        "state": ScanJob.State.FINISHED,
        "phase": ScanJob.Phase.DONE,
        "finished_at": now,
        "updated_at": now,
        "result": result_json(result),
        "match_count": len(result.matches),
        "revision": result.revision,
        "rules_pending": result.pending,
        "error": "",
    }


def _failed_fields(message: str) -> dict[str, Any]:
    now = timezone.now()
    return {
        "state": ScanJob.State.FAILED,
        "phase": ScanJob.Phase.DONE,
        "finished_at": now,
        "updated_at": now,
        "error": message,
    }


def inline_max_bytes() -> int:
    value: int = settings.YARADUDE_SCAN_INLINE_MAX_BYTES
    return value


def submit_samples(
    samples: Sequence[File],
    user: User,
    *,
    path: str = "",
    tag: str = "",
    rulesets: Iterable[Ruleset | int] | None = None,
) -> list[ScanJob]:
    """
    Create one job per sample. A single sample of at most
    YARADUDE_SCAN_INLINE_MAX_BYTES is scanned at once here and returned
    finished (or failed); everything else is returned queued. A sample over
    YARADUDE_SCAN_MAX_BYTES becomes a failed job without being read. Options
    limit which matches are reported (path as on the rule list, tag, ruleset
    ids). Raises ScanError for an empty or too long list.
    """
    max_samples: int = settings.YARADUDE_SCAN_MAX_SAMPLES
    max_bytes: int = settings.YARADUDE_SCAN_MAX_BYTES
    inline_timeout: int = settings.YARADUDE_SCAN_INLINE_TIMEOUT
    if not samples:
        raise ScanError("Choose at least one sample.")
    if len(samples) > max_samples:
        raise ScanError(f"At most {max_samples} samples can be scanned at once.")

    options = _options(path, tag, rulesets)
    batch = uuid.uuid4() if len(samples) > 1 else None
    threshold = inline_max_bytes()
    jobs: list[ScanJob] = []
    for sample in samples:
        name = PurePath(sample.name or "").name[:255]
        job = ScanJob(user=user, batch=batch, sample_name=name, options=options)
        size = sample.size or 0
        if size > max_bytes:
            job.sample_size = size
            for key, value in _failed_fields(_too_large()).items():
                setattr(job, key, value)
            job.save()
            jobs.append(job)
            continue
        sample.seek(0)
        data: bytes = sample.read()
        job.sample_size = len(data)
        job.sample_sha256 = hashlib.sha256(data).hexdigest()
        if len(data) > max_bytes:
            for key, value in _failed_fields(_too_large()).items():
                setattr(job, key, value)
            job.save()
            jobs.append(job)
            continue

        if (
            len(samples) == 1
            and threshold > 0
            and len(data) <= threshold
            and _inline_lane.acquire(blocking=False)
        ):
            try:
                job.inline = True
                job.started_at = timezone.now()
                result = scanner.scan_bytes(
                    data, name, _limit(options), timeout=inline_timeout, previews=False
                )
            except ScanTimeout:
                # Too slow for the fast path: give it to a worker with the
                # full timeout instead of stalling this process.
                job.inline = False
                job.started_at = None
            except ScanError as error:
                for key, value in _failed_fields(str(error)).items():
                    setattr(job, key, value)
                job.save()
                jobs.append(job)
                continue
            else:
                for key, value in _finished_fields(result).items():
                    setattr(job, key, value)
                job.save()
                jobs.append(job)
                continue
            finally:
                _inline_lane.release()

        jobs.append(_queue(job, data))
    return jobs


def _too_large() -> str:
    try:
        scanner.check_size(settings.YARADUDE_SCAN_MAX_BYTES + 1)
    except ScanError as error:
        return str(error)
    return "The sample is too large."  # pragma: no cover


def _queue(job: ScanJob, data: bytes) -> ScanJob:
    from scans.tasks import run_scan_job

    token = spool.write(data)
    try:
        with transaction.atomic():
            job.spool_token = token
            job.state = ScanJob.State.QUEUED
            job.phase = ScanJob.Phase.QUEUED
            task_result = run_scan_job.enqueue(str(job.pk))
            job.task_id = str(task_result.id)
            job.save()
    except BaseException:
        spool.delete(token)
        raise
    return job


# ---------------------------------------------------------------------------
# Running (scan workers)


def execute_job(job_id: str) -> None:
    """
    Run a queued job: read its spool file, scan, store the result. The spool
    file is deleted in a `finally`, whatever happens. Never raises for scan
    problems; they become a failed job.
    """
    job = ScanJob.objects.filter(pk=job_id).first()
    if job is None:
        return
    token = job.spool_token
    try:
        now = timezone.now()
        claimed = ScanJob.objects.filter(pk=job.pk, state=ScanJob.State.QUEUED).update(
            state=ScanJob.State.RUNNING,
            phase=ScanJob.Phase.LOADING,
            started_at=now,
            updated_at=now,
            worker_id=heartbeat.current_worker_id,
        )
        if not claimed:
            return
        try:
            data = spool.read(token)
        except (FileNotFoundError, ValueError):
            _store(job, _failed_fields("The sample is no longer available; submit it again."))
            return
        if len(data) != job.sample_size or hashlib.sha256(data).hexdigest() != job.sample_sha256:
            _store(job, _failed_fields("The stored sample is damaged; submit it again."))
            return
        scanner.compiled_set()
        _store(job, {"phase": ScanJob.Phase.SCANNING, "updated_at": timezone.now()})
        result = scanner.scan_bytes(data, job.sample_name, _limit(job.options), previews=False)
        del data
        _store(job, _finished_fields(result))
    except ScanError as error:
        _store(job, _failed_fields(str(error)))
    except Exception:
        logger.exception("Scan job %s failed", job.pk)
        _store(job, _failed_fields("The scan failed because of an internal error."))
    finally:
        spool.delete(token)
        ScanJob.objects.filter(pk=job.pk).update(spool_token="")


def _store(job: ScanJob, fields: dict[str, Any]) -> None:
    """Update a running job (a job a repair already failed is left alone)."""
    ScanJob.objects.filter(pk=job.pk, state=ScanJob.State.RUNNING).update(**fields)


# ---------------------------------------------------------------------------
# Reading


def visible_jobs(user: object) -> QuerySet[ScanJob]:
    """
    All jobs, newest first, with the submitter loaded and without the result
    column (load it with `get_job`); none for users without scan permission.
    """
    if not can_scan(user):
        return ScanJob.objects.none()
    return ScanJob.objects.select_related("user").defer("result")


def get_job(user: object, job_id: uuid.UUID | str) -> ScanJob:
    """One job with its result; raises ScanJob.DoesNotExist (also for no permission)."""
    try:
        key = uuid.UUID(str(job_id))
    except ValueError:
        raise ScanJob.DoesNotExist from None
    if not can_scan(user):
        raise ScanJob.DoesNotExist
    return ScanJob.objects.select_related("user").get(pk=key)


def job_json(job: ScanJob, *, with_result: bool = True) -> dict[str, Any]:
    """A job as JSON-able data (the WebSocket `job` object, PLAN.md 5.7)."""

    def ts(value: Any) -> str | None:
        return value.isoformat() if value else None

    data: dict[str, Any] = {
        "id": str(job.pk),
        "batch": str(job.batch) if job.batch else None,
        "state": job.state,
        "phase": job.phase,
        "inline": job.inline,
        "sample_name": job.sample_name,
        "sample_size": job.sample_size,
        "sample_sha256": job.sample_sha256,
        "submitted_by": job.submitted_by,
        "options": job.options,
        "created_at": ts(job.created_at),
        "started_at": ts(job.started_at),
        "finished_at": ts(job.finished_at),
        "updated_at": ts(job.updated_at),
        "error": job.error,
        "match_count": job.match_count,
        "revision": job.revision,
        "rules_pending": job.rules_pending,
    }
    if with_result:
        data["result"] = job.result if job.state == ScanJob.State.FINISHED else None
    return data


@dataclass(frozen=True)
class SystemStatus:
    compiled: scanner.CompiledSetStatus
    workers: dict[str, int]  # live processes per role: "scan", "maintenance", "builder"
    queued: int  # scan jobs waiting for a worker
    running: int  # scan jobs being scanned
    recurring: list[recurring.RecurringStatus]


def system_status() -> SystemStatus:
    """Compiled set, workers, queue depth and recurring tasks, for status pages."""
    states = dict.fromkeys((ScanJob.State.QUEUED, ScanJob.State.RUNNING), 0)
    for state in ScanJob.objects.filter(state__in=list(states)).values_list("state", flat=True):
        states[ScanJob.State(state)] += 1
    return SystemStatus(
        compiled=scanner.compiled_status(),
        workers=heartbeat.alive_workers(),
        queued=states[ScanJob.State.QUEUED],
        running=states[ScanJob.State.RUNNING],
        recurring=[recurring.status(entry.name) for entry in recurring.registered()],
    )
