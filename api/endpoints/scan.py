"""
Test scan of an uploaded sample. The sample is held in memory by the
upload handlers (FILE_UPLOAD_HANDLERS), passed to the scanner and dropped:
it is never stored, and no API code logs request bodies or file contents.

Job-based scanning (PLAN.md 12.9) is to be added beside this resource under
/api/v1/scans/; this synchronous endpoint stays as it is.
"""

from __future__ import annotations

from django.http import HttpResponse

from api import serializers
from api.endpoints.common import COMMON_ERRORS, INVALID
from api.http import ApiError, Call, form_error, json_response
from api.registry import Body, BodyField, Param, Reply, endpoint
from rules.forms import ScanForm
from rules.services.scanner import ScanError, scan_sample
from rules.views.rules import rulesets_by_path
from rules.views.scan import limit_summary

SCAN = ("rules.scan_rules",)
PATH_HELP = (
    "Optional limit: only rulesets whose path contains this text; end it with `/` to "
    "select a directory, e.g. `signature-base/`."
)


@endpoint(
    "POST",
    "scan/",
    operation="scan",
    group="Scan",
    summary="Scan a sample",
    permissions=SCAN,
    body=Body(
        "multipart",
        (
            BodyField(
                "sample",
                "The file to scan (up to YARADUDE_SCAN_MAX_BYTES). Scanned in "
                "memory and never stored.",
                type="file",
                required=True,
                example="suspicious.bin",
            ),
            BodyField("path", PATH_HELP, example="signature-base/"),
        ),
    ),
    replies=(
        Reply(
            200,
            "Matched rules with string instances, and the rules left out because "
            "they do not compile.",
            schema="ScanResult",
        ),
        Reply(
            400,
            "No sample, or it is too large (a body over the upload limit arrives "
            "without its file).",
            schema="Error",
        ),
        Reply(422, "The scan failed or timed out (`scan_failed`).", schema="Error"),
        *COMMON_ERRORS,
    ),
    description="Synchronous: the answer comes when the scan is finished.",
)
def scan(call: Call) -> HttpResponse:
    form = ScanForm(call.request.POST, call.request.FILES)
    if not form.is_valid():
        raise form_error(form)
    path = form.cleaned_data["path"].strip()
    try:
        result = scan_sample(form.cleaned_data["sample"], rulesets_by_path(path) if path else None)
    except ScanError as error:
        raise ApiError(422, "scan_failed", str(error)) from None
    return json_response(serializers.scan_result(call, result))


@endpoint(
    "GET",
    "scan/limit/",
    operation="scan_limit",
    group="Scan",
    summary="Check a scan limit",
    permissions=SCAN,
    params=(Param("path", PATH_HELP, example="signature-base/"),),
    replies=(
        Reply(
            200,
            "How many active rules and rulesets a scan with this limit uses.",
            schema="ScanLimit",
        ),
        INVALID,
        *COMMON_ERRORS,
    ),
    description="The Check limit button of the Test scan page.",
)
def scan_limit(call: Call) -> HttpResponse:
    path = call.request.GET.get("path", "").strip()
    if len(path) > 1024:
        raise ApiError(
            400,
            "invalid",
            "The request is not valid.",
            fields={"path": ["At most 1024 characters."]},
        )
    return json_response({"path": path, **limit_summary(path)})
