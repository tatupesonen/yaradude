"""
Scan jobs (PLAN.md 12.9): submit one or many samples, follow the jobs, and
read the state of the compiled rule set and the workers. Jobs are shared
with the team: everyone with the scan permission sees every job and who
submitted it (scans.services decides).
"""

from __future__ import annotations

import uuid

from django.conf import settings
from django.http import Http404, HttpResponse
from django.urls import reverse

from api.endpoints.common import COMMON_ERRORS, PAGE, page_data
from api.http import ApiError, Call, json_response
from api.registry import Body, BodyField, Param, Reply, endpoint
from api.serializers import ts
from rules.services.scanner import ScanError
from rules.views.base import paginate
from scans import services
from scans.models import ScanJob

SCAN = ("rules.scan_rules",)


def _job(call: Call, job: ScanJob, *, with_result: bool) -> dict:
    return {
        **services.job_json(job, with_result=with_result),
        "url": call.absolute(reverse("api:scan_job", kwargs={"job_id": job.pk})),
    }


@endpoint(
    "POST",
    "scans/",
    operation="scan_submit",
    group="Scan",
    summary="Submit samples as scan jobs",
    permissions=SCAN,
    body=Body(
        "multipart",
        (
            BodyField(
                "samples",
                "One or more files (repeat the field). Held in memory or the private "
                "spool until scanned, never kept.",
                type="file",
                required=True,
                repeated=True,
                example="suspicious.bin",
            ),
            BodyField(
                "path",
                "Optional: report only matches of rulesets whose path contains this "
                "(ending in `/` = directory prefix).",
            ),
            BodyField("tag", "Optional: report only matches of rules with this tag."),
        ),
    ),
    replies=(
        Reply(
            201,
            "One job per sample, in order. A single small sample is scanned at once and "
            "comes back `finished`; others are `queued` — poll the job URL.",
            schema="ScanJobList",
        ),
        Reply(
            400,
            "No sample, too many samples, or the upload was too large (`invalid`).",
            schema="Error",
        ),
        *COMMON_ERRORS,
    ),
)
def scan_submit(call: Call) -> HttpResponse:
    samples = call.request.FILES.getlist("samples")
    path = call.request.POST.get("path", "").strip()
    tag = call.request.POST.get("tag", "").strip()
    if len(path) > 1024 or len(tag) > 128:
        raise ApiError(400, "invalid", "`path` or `tag` is too long.")
    try:
        jobs = services.submit_samples(samples, call.user, path=path, tag=tag)
    except ScanError as error:
        raise ApiError(400, "invalid", str(error), fields={"samples": [str(error)]}) from None
    return json_response({"jobs": [_job(call, job, with_result=True) for job in jobs]}, status=201)


@endpoint(
    "GET",
    "scans/",
    operation="scan_jobs",
    group="Scan",
    summary="List scan jobs",
    permissions=SCAN,
    params=(
        Param("batch", "Only the jobs of one multi-sample submission (its `batch` id)."),
        PAGE,
    ),
    replies=(
        Reply(
            200,
            "Jobs of everyone, newest first, 100 per page, without results.",
            schema="ScanJobPage",
        ),
        *COMMON_ERRORS,
    ),
)
def scan_jobs(call: Call) -> HttpResponse:
    jobs = services.visible_jobs(call.user)
    batch = call.request.GET.get("batch", "").strip()
    if batch:
        try:
            jobs = jobs.filter(batch=uuid.UUID(batch))
        except ValueError:
            jobs = jobs.none()
    page = paginate(call.request, jobs)
    return json_response(page_data(call, page, lambda job: _job(call, job, with_result=False)))


@endpoint(
    "GET",
    "scans/<uuid:job_id>/",
    operation="scan_job",
    group="Scan",
    summary="Read a scan job",
    permissions=SCAN,
    replies=(
        Reply(200, "The job; `result` is set once it is `finished`.", schema="ScanJob"),
        Reply(404, "No such job.", schema="Error"),
        *COMMON_ERRORS,
    ),
    description="Poll until `state` is `finished` or `failed`. Stored results carry offsets "
    "and lengths of string matches but no byte previews (the sample is not kept).",
)
def scan_job(call: Call, job_id: uuid.UUID) -> HttpResponse:
    try:
        job = services.get_job(call.user, job_id)
    except ScanJob.DoesNotExist:
        raise Http404("No such scan job.") from None
    return json_response(_job(call, job, with_result=True))


@endpoint(
    "GET",
    "scans/status/",
    operation="scan_status",
    group="Scan",
    summary="Scanning status",
    permissions=SCAN,
    replies=(
        Reply(200, "The compiled rule set, workers and queue.", schema="ScanStatus"),
        *COMMON_ERRORS,
    ),
)
def scan_status(call: Call) -> HttpResponse:
    status = services.system_status()
    compiled = status.compiled
    info = compiled.set
    return json_response(
        {
            "compiled": {
                "available": compiled.available,
                "revision": info.revision if info else None,
                "built_at": ts(info.built_at) if info else None,
                "engine": info.engine if info else None,
                "rules": info.rules if info else None,
                "rulesets": info.rulesets if info else None,
                "left_out": info.left_out if info else None,
                "current_revision": compiled.current_revision,
                "pending": compiled.pending,
                "building": compiled.building,
            },
            "workers": status.workers,
            "queued": status.queued,
            "running": status.running,
            "limits": {
                "max_bytes": settings.YARADUDE_SCAN_MAX_BYTES,
                "max_samples": settings.YARADUDE_SCAN_MAX_SAMPLES,
                "inline_max_bytes": services.inline_max_bytes(),
            },
        }
    )
