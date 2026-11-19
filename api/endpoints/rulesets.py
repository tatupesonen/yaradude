"""Dashboard and rulesets: counts, list, detail, downloads, delete."""

from __future__ import annotations

from django.db.models import Count, Prefetch, Q
from django.http import HttpResponse
from django.shortcuts import get_object_or_404

from api import serializers
from api.endpoints.common import COMMON_ERRORS, NOT_FOUND, PAGE, page_data, ui_context
from api.http import ApiError, Call, file_response, json_response, no_content
from api.registry import Param, Reply, endpoint
from rules.forms import RulesetFilterForm
from rules.models import Ruleset, Tag
from rules.services import editing, exporter
from rules.views.base import paginate
from rules.views.dashboard import DashboardView
from rules.views.rulesets import SORTS

VIEW = ("rules.view_ruleset",)


@endpoint(
    "GET",
    "dashboard/",
    operation="dashboard",
    group="Dashboard",
    summary="Dashboard counts",
    permissions=("rules.view_rule",),
    replies=(
        Reply(
            200,
            "The dashboard's counts, recent import runs and recently updated rules.",
            schema="Dashboard",
        ),
        *COMMON_ERRORS,
    ),
)
def dashboard(call: Call) -> HttpResponse:
    context = ui_context(DashboardView, call)
    return json_response(
        {
            "counts": {
                **context["counts"],
                "rulesets": context["ruleset_count"],
                "tags": context["tag_count"],
            },
            "recent_imports": [
                serializers.import_run_summary(call, run) for run in context["recent_runs"]
            ],
            "recent_rules": [
                serializers.rule_summary(call, rule)
                for rule in context["recent_rules"].prefetch_related("tags")
            ],
        }
    )


# Per-ruleset counts. The UI's rules.views.rulesets.with_counts counts rules
# over a join, which bypasses the default manager and so still counts deleted
# rules (PLAN.md 5.7, "Joins do not apply managers"); until it is fixed and
# extracted (12.8, "Shared query logic") the API counts here.
ACTIVE = Q(rules__removed_at__isnull=True, rules__deleted_at__isnull=True)
REMOVED = Q(rules__removed_at__isnull=False, rules__deleted_at__isnull=True)


def with_counts(queryset):
    return queryset.annotate(
        active_count=Count("rules", filter=ACTIVE),
        failing_count=Count("rules", filter=ACTIVE & ~Q(rules__compile_error="")),
        removed_count=Count("rules", filter=REMOVED),
    )


@endpoint(
    "GET",
    "rulesets/",
    operation="ruleset_list",
    group="Rulesets",
    summary="List and search rulesets",
    permissions=VIEW,
    params=(
        Param(
            "q", "Search in name and path (case-insensitive substring).", example="signature-base/"
        ),
        Param(
            "origin",
            "Only rulesets of this origin.",
            enum=tuple(value for value, _ in Ruleset.Origin.choices),
        ),
        Param(
            "sort",
            "Sort key, `-` for descending (default `name`).",
            enum=tuple(str(value) for value, _ in RulesetFilterForm.base_fields["sort"].choices),
            example="-updated",
        ),
        PAGE,
    ),
    replies=(
        Reply(200, "One page of 100 rulesets with rule counts.", schema="RulesetPage"),
        *COMMON_ERRORS,
    ),
    description="Search, filter, sort and pagination as on the Rulesets page (the same form "
    "and sort keys); invalid values are ignored.",
)
def ruleset_list(call: Call) -> HttpResponse:
    values = RulesetFilterForm(call.request.GET).values()
    rulesets = Ruleset.objects.defer("original_content")
    if values["q"]:
        rulesets = rulesets.filter(Q(name__icontains=values["q"]) | Q(path__icontains=values["q"]))
    if values["origin"]:
        rulesets = rulesets.filter(origin=values["origin"])
    fields = SORTS[values["sort"].lstrip("-")]
    if values["sort"].startswith("-"):
        fields = [f"-{field}" for field in fields]
    page = paginate(call.request, with_counts(rulesets).order_by(*fields))
    return json_response(
        page_data(call, page, lambda ruleset: serializers.ruleset_summary(call, ruleset))
    )


@endpoint(
    "GET",
    "rulesets/<int:pk>/",
    operation="ruleset_detail",
    group="Rulesets",
    summary="Read a ruleset with its rules",
    permissions=VIEW,
    replies=(
        Reply(
            200, "The ruleset and its rules in file order, removed rules last.", schema="Ruleset"
        ),
        NOT_FOUND,
        *COMMON_ERRORS,
    ),
)
def ruleset_detail(call: Call, pk: int) -> HttpResponse:
    ruleset = get_object_or_404(with_counts(Ruleset.objects.defer("original_content")), pk=pk)
    rules = list(
        ruleset.rules.defer("source", "meta")
        .prefetch_related(Prefetch("tags", queryset=Tag.objects.order_by("name")))
        .order_by("removed_at", "position", "pk")
    )
    for rule in rules:
        rule.ruleset = ruleset
    has_original = Ruleset.objects.filter(pk=pk).exclude(original_content="").exists()
    return json_response(serializers.ruleset_detail(call, ruleset, rules, has_original))


@endpoint(
    "DELETE",
    "rulesets/<int:pk>/",
    operation="ruleset_delete",
    group="Rulesets",
    summary="Delete a ruleset",
    permissions=("rules.delete_ruleset",),
    replies=(Reply(204, "Deleted (recoverable)."), NOT_FOUND, *COMMON_ERRORS),
    description="Recoverable: the ruleset and its rules are flagged deleted with their "
    "history kept, and listed under deleted rulesets, from where they can be restored (or "
    "purged by an administrator). Imports skip the ruleset's file while it is deleted.",
)
def ruleset_delete(call: Call, pk: int) -> HttpResponse:
    ruleset = get_object_or_404(Ruleset.objects.defer("original_content"), pk=pk)
    editing.delete_ruleset(ruleset, user=call.user)
    return no_content()


@endpoint(
    "GET",
    "rulesets/<int:pk>/download/",
    operation="ruleset_download",
    group="Rulesets",
    summary="Download a ruleset (rebuilt)",
    permissions=VIEW,
    replies=(
        Reply(
            200,
            "The ruleset rebuilt from its current active rules.",
            file="text/plain; charset=utf-8",
        ),
        NOT_FOUND,
        *COMMON_ERRORS,
    ),
)
def ruleset_download(call: Call, pk: int) -> HttpResponse:
    return file_response(exporter.export_ruleset(get_object_or_404(Ruleset, pk=pk)))


@endpoint(
    "GET",
    "rulesets/<int:pk>/original/",
    operation="ruleset_original",
    group="Rulesets",
    summary="Download a ruleset's original file",
    permissions=VIEW,
    replies=(
        Reply(200, "The file as last imported, verbatim.", file="text/plain; charset=utf-8"),
        Reply(
            404,
            "No such ruleset, or it was not imported from a file (`no_original`).",
            schema="Error",
        ),
        *COMMON_ERRORS,
    ),
)
def ruleset_original(call: Call, pk: int) -> HttpResponse:
    ruleset = get_object_or_404(Ruleset, pk=pk)
    if not ruleset.original_content:
        raise ApiError(404, "no_original", "This ruleset was not imported from a file.")
    return file_response(exporter.export_ruleset_original(ruleset))
