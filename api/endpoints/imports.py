"""Import: upload rule files, import the rules directory, import history."""

from __future__ import annotations

from pathlib import Path

from django.conf import settings
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from django.urls import reverse

from api import serializers
from api.endpoints.common import COMMON_ERRORS, INVALID, NOT_FOUND, PAGE, page_data
from api.http import ApiError, Call, form_error, json_response
from api.registry import Body, BodyField, Reply, endpoint
from rules.forms import UploadForm
from rules.models import ImportRun
from rules.services import importer
from rules.views.base import paginate
from rules.views.imports import directory_status

VIEW = ("rules.view_importrun",)
IMPORT = ("rules.import_rules",)


def _created(call: Call, run: ImportRun) -> HttpResponse:
    location = call.absolute(reverse("api:import_detail", kwargs={"pk": run.pk}))
    return json_response(
        serializers.import_run_detail(call, run, list(_files(run))),
        status=201,
        headers={"Location": location},
    )


def _files(run: ImportRun):
    return (
        run.files.select_related("ruleset")
        .defer("ruleset__original_content")
        .order_by("status", "path")
    )


@endpoint(
    "GET",
    "imports/",
    operation="import_list",
    group="Import",
    summary="List import runs",
    permissions=VIEW,
    params=(PAGE,),
    replies=(
        Reply(200, "One page of 25 import runs, newest first.", schema="ImportRunPage"),
        *COMMON_ERRORS,
    ),
)
def import_list(call: Call) -> HttpResponse:
    # The same query and page size as the import history on the Import page.
    page = paginate(call.request, ImportRun.objects.select_related("user"), per_page=25)
    return json_response(
        page_data(call, page, lambda run: serializers.import_run_summary(call, run))
    )


@endpoint(
    "GET",
    "imports/<int:pk>/",
    operation="import_detail",
    group="Import",
    summary="Read an import run",
    permissions=VIEW,
    replies=(
        Reply(200, "Counters and the files that changed or failed.", schema="ImportRun"),
        NOT_FOUND,
        *COMMON_ERRORS,
    ),
)
def import_detail(call: Call, pk: int) -> HttpResponse:
    run = get_object_or_404(ImportRun.objects.select_related("user"), pk=pk)
    return json_response(serializers.import_run_detail(call, run, list(_files(run))))


@endpoint(
    "POST",
    "imports/upload/",
    operation="import_upload",
    group="Import",
    summary="Upload rule files",
    permissions=IMPORT,
    body=Body(
        "multipart",
        (
            BodyField(
                "rule_files",
                f"One or more {' / '.join(importer.RULE_SUFFIXES)} files (repeat the field). "
                "Each file becomes one ruleset, identified by its file name.",
                type="file",
                required=True,
                repeated=True,
                example="first.yar",
            ),
        ),
    ),
    replies=(
        Reply(
            201, "The import run; failed files are listed with their message.", schema="ImportRun"
        ),
        INVALID,
        *COMMON_ERRORS,
    ),
    description="The same form and import service as the upload on the Import page. Files "
    "are read in memory.",
)
def import_upload(call: Call) -> HttpResponse:
    form = UploadForm(call.request.POST, call.request.FILES)
    if not form.is_valid():
        raise form_error(form)
    return _created(call, importer.import_uploads(form.cleaned_data["rule_files"], user=call.user))


@endpoint(
    "GET",
    "imports/directory/",
    operation="import_directory",
    group="Import",
    summary="Rules directory status",
    permissions=IMPORT,
    replies=(
        Reply(
            200,
            "The configured rules directory, how many rule files it holds and "
            "the last directory import.",
            schema="Directory",
        ),
        *COMMON_ERRORS,
    ),
)
def import_directory(call: Call) -> HttpResponse:
    status = directory_status(Path(settings.YARADUDE_RULES_DIR))
    last = ImportRun.objects.select_related("user").filter(origin=ImportRun.Origin.SCAN).first()
    return json_response(
        {
            "path": str(settings.YARADUDE_RULES_DIR),
            "exists": status.exists,
            "importable": status.importable,
            "skipped": [
                {"path": path, "reason": reason}
                for reason, paths in status.reasons
                for path in paths
            ],
            "last_scan": serializers.import_run_summary(call, last) if last else None,
        }
    )


@endpoint(
    "POST",
    "imports/scan/",
    operation="import_scan",
    group="Import",
    summary="Import the rules directory",
    permissions=IMPORT,
    replies=(
        Reply(201, "The import run.", schema="ImportRun"),
        Reply(
            409,
            "The configured directory is missing or holds no rule files "
            "(`directory_missing`, `directory_empty`: also when every file would be skipped).",
            schema="Error",
        ),
        *COMMON_ERRORS,
    ),
    description="Always imports the configured rules directory (`YARADUDE_RULES_DIR`); the "
    "API, like the UI, never takes a path from the request. No body. Runs within the request.",
)
def import_scan(call: Call) -> HttpResponse:
    # The same pre-check and messages as the Import page's button.
    status = directory_status(Path(settings.YARADUDE_RULES_DIR))
    if not status.importable:
        if not status.exists:
            raise ApiError(
                409, "directory_missing", "The configured rules directory does not exist."
            )
        raise ApiError(
            409,
            "directory_empty",
            "No rule file in the configured rules directory can be imported."
            if status.skipped
            else "The configured rules directory contains no .yar or .yara files.",
        )
    return _created(call, importer.import_directory(settings.YARADUDE_RULES_DIR, user=call.user))
