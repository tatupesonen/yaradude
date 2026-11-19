"""
Recoverable deletes (PLAN.md 12.11): list deleted rules and rulesets,
restore them, and purge them for good (administrators only).
"""

from __future__ import annotations

from django.db.models import Count, Q
from django.http import HttpResponse
from django.shortcuts import get_object_or_404

from api import serializers
from api.endpoints.common import COMMON_ERRORS, PAGE, page_data
from api.endpoints.rulesets import with_counts
from api.http import ApiError, Call, json_response, no_content
from api.registry import Reply, endpoint
from rules.models import Rule, Ruleset
from rules.services import editing
from rules.views.base import paginate

NOT_DELETED = Reply(404, "No such deleted rule or ruleset.", schema="Error")


def _deleted_rule(pk: int) -> Rule:
    return get_object_or_404(
        Rule.all_objects.deleted()
        .select_related("ruleset", "deleted_by")
        .defer("ruleset__original_content"),
        pk=pk,
    )


def _deleted_ruleset(pk: int) -> Ruleset:
    return get_object_or_404(
        Ruleset.all_objects.deleted().select_related("deleted_by").defer("original_content"),
        pk=pk,
    )


@endpoint(
    "GET",
    "rules/deleted/",
    operation="deleted_rule_list",
    group="Rules",
    summary="List deleted rules",
    permissions=("rules.view_rule",),
    params=(PAGE,),
    replies=(
        Reply(200, "Deleted rules, most recently deleted first.", schema="DeletedRulePage"),
        *COMMON_ERRORS,
    ),
    description="Rules deleted on their own and rules deleted together with their ruleset "
    "(`deleted_with_ruleset`; restore the ruleset to bring those back).",
)
def deleted_rule_list(call: Call) -> HttpResponse:
    rules = (
        Rule.all_objects.deleted()
        .select_related("ruleset", "deleted_by")
        .defer("source", "meta", "ruleset__original_content")
        .order_by("-deleted_at", "-pk")
    )
    page = paginate(call.request, rules)
    return json_response(page_data(call, page, lambda r: serializers.deleted_rule(call, r)))


@endpoint(
    "POST",
    "rules/deleted/<int:pk>/restore/",
    operation="deleted_rule_restore",
    group="Rules",
    summary="Restore a deleted rule",
    permissions=("rules.delete_rule",),
    replies=(
        Reply(200, "Restored with the content it had.", schema="Saved"),
        NOT_DELETED,
        Reply(
            409,
            "Not restored: its ruleset is deleted (restore that instead), or it was "
            "restored meanwhile (`cannot_restore`).",
            schema="Error",
        ),
        *COMMON_ERRORS,
    ),
    description="Needs the permission to delete rules. The next import re-reads the rule's "
    "file and, if the file changed meanwhile, updates the rule under the normal rules.",
)
def deleted_rule_restore(call: Call, pk: int) -> HttpResponse:
    result = editing.restore_rule(_deleted_rule(pk), user=call.user)
    if not result.ok or result.rule is None:
        raise ApiError(409, "cannot_restore", result.error)
    rule = get_object_or_404(
        Rule.objects.select_related("ruleset").defer("ruleset__original_content"), pk=pk
    )
    return json_response(serializers.saved(call, rule, result, changed=True))


@endpoint(
    "DELETE",
    "rules/deleted/<int:pk>/",
    operation="deleted_rule_purge",
    group="Rules",
    summary="Purge a deleted rule",
    permissions=("rules.purge_rule",),
    replies=(Reply(204, "Gone for good, with its history."), NOT_DELETED, *COMMON_ERRORS),
    description="Permanent: removes a deleted rule and its version history. Only for "
    "accounts with `rules.purge_rule` (administrators; neither role has it). Delete the rule "
    "first.",
)
def deleted_rule_purge(call: Call, pk: int) -> HttpResponse:
    editing.purge_rule(_deleted_rule(pk))
    return no_content()


@endpoint(
    "GET",
    "rulesets/deleted/",
    operation="deleted_ruleset_list",
    group="Rulesets",
    summary="List deleted rulesets",
    permissions=("rules.view_ruleset",),
    params=(PAGE,),
    replies=(
        Reply(200, "Deleted rulesets, most recently deleted first.", schema="DeletedRulesetPage"),
        *COMMON_ERRORS,
    ),
)
def deleted_ruleset_list(call: Call) -> HttpResponse:
    rulesets = (
        Ruleset.all_objects.deleted()
        .select_related("deleted_by")
        .defer("original_content")
        .annotate(rules_deleted=Count("rules", filter=Q(rules__deleted_with_ruleset=True)))
        .order_by("-deleted_at", "-pk")
    )
    page = paginate(call.request, rulesets)
    return json_response(page_data(call, page, lambda r: serializers.deleted_ruleset(call, r)))


@endpoint(
    "POST",
    "rulesets/deleted/<int:pk>/restore/",
    operation="deleted_ruleset_restore",
    group="Rulesets",
    summary="Restore a deleted ruleset",
    permissions=("rules.delete_ruleset",),
    replies=(
        Reply(200, "Restored with the rules deleted together with it.", schema="RulesetSummary"),
        NOT_DELETED,
        *COMMON_ERRORS,
    ),
    description="Needs the permission to delete rulesets. Rules deleted on their own before "
    "stay deleted. The next import re-reads the ruleset's file.",
)
def deleted_ruleset_restore(call: Call, pk: int) -> HttpResponse:
    editing.restore_ruleset(_deleted_ruleset(pk), user=call.user)
    ruleset = get_object_or_404(with_counts(Ruleset.objects.defer("original_content")), pk=pk)
    return json_response(serializers.ruleset_summary(call, ruleset))


@endpoint(
    "DELETE",
    "rulesets/deleted/<int:pk>/",
    operation="deleted_ruleset_purge",
    group="Rulesets",
    summary="Purge a deleted ruleset",
    permissions=("rules.purge_ruleset",),
    replies=(Reply(204, "Gone for good, with its rules and history."), NOT_DELETED, *COMMON_ERRORS),
    description="Permanent: removes a deleted ruleset with all its rules and their history; "
    "import runs keep their records. Only for accounts with `rules.purge_ruleset`.",
)
def deleted_ruleset_purge(call: Call, pk: int) -> HttpResponse:
    editing.purge_ruleset(_deleted_ruleset(pk))
    return no_content()
