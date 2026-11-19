"""Rules: list, read, create, edit, validate, delete, versions, restore, export; tags."""

from __future__ import annotations

from django.db.models import Count, Prefetch, Q
from django.http import HttpResponse, QueryDict
from django.shortcuts import get_object_or_404
from django.urls import reverse

from api import serializers
from api.endpoints.common import (
    COMMON_ERRORS,
    INVALID,
    NOT_FOUND,
    PAGE,
    id_list,
    int_field,
    page_data,
    text_field,
)
from api.http import ApiError, Call, file_response, form_error, json_response, no_content
from api.registry import Body, BodyField, Param, Reply, endpoint
from rules.forms import (
    NEW_RULESET,
    SORT_CHOICES,
    STATUS_CHOICES,
    ExportForm,
    RuleCreateForm,
    RuleFilterForm,
    RuleUpdateForm,
)
from rules.models import Rule, RuleVersion, Tag
from rules.services import editing, exporter
from rules.services.diffing import diff_versions, previous_version
from rules.services.editing import EditResult
from rules.views.base import paginate
from rules.views.rules import filtered_rules

VIEW = ("rules.view_rule",)
VIEW_VERSIONS = ("rules.view_rule", "rules.view_ruleversion")

FILTERS = (
    Param(
        "q",
        "Search in name, description, author and source: the whole input is one literal, "
        "case-insensitive substring (full-text index; no query syntax).",
        example="mimikatz",
    ),
    Param("ruleset", "Only rules of this ruleset (id).", type="integer"),
    Param(
        "path",
        "Ruleset path: ending in `/` selects a directory prefix (e.g. `signature-base/`), "
        "anything else matches anywhere in the path.",
    ),
    Param("tag", "Only rules with this tag (exact name)."),
    Param(
        "status",
        "Default: active rules. `error`: do not compile; `warnings`: compile with warnings; "
        "`modified`: changed locally since the last import; `removed`; `all`.",
        enum=tuple(value for value, _ in STATUS_CHOICES if value),
        example="error",
    ),
    Param(
        "sort",
        "Sort key, `-` for descending; ties are broken by the rule id. The default is "
        "`relevance` while searching (`q`), else `name`.",
        enum=tuple(value for value, _ in SORT_CHOICES),
    ),
)

RULE_TEXT = BodyField(
    "text",
    "Optional `import` lines followed by exactly one rule.",
    required=True,
    example='rule api_example { strings: $a = "example" condition: $a }',
)
TARGET_FIELDS = (
    BodyField(
        "ruleset",
        "Id of the ruleset to add the rule to (any ruleset). Give this or `collection`.",
        type="integer",
        example=7,
    ),
    BodyField(
        "collection",
        "Name of a manual collection; created if it does not exist (needs `add_ruleset`). "
        "At most 100 characters, no line breaks or control characters.",
    ),
)
REFUSED = Reply(
    422,
    "The rule was not saved: it does not parse, does not compile, or its name is taken.",
    schema="Error",
)


def _filtered(data: QueryDict):
    """The rules list's filters, search and sort: the UI's form and query."""
    return filtered_rules(RuleFilterForm(data).values())


def _rule(pk: int) -> Rule:
    return get_object_or_404(
        Rule.objects.select_related("ruleset").defer("ruleset__original_content"), pk=pk
    )


def _detail(call: Call, rule: Rule) -> dict:
    versions = list(rule.versions.select_related("created_by").order_by("-number"))
    return serializers.rule_detail(call, rule, versions)


def _refused(result: EditResult, pk: int | None = None) -> ApiError:
    """
    422 for text that cannot be saved; 409 when the service reports a
    concurrent change (`conflict`), with the rule's version now if it exists.
    """
    if result.conflict:
        current = Rule.objects.filter(pk=pk).values_list("version", flat=True).first()
        if current is None:
            return ApiError(409, "conflict", result.error)
        return ApiError(409, "version_conflict", result.error, extra={"current_version": current})
    return ApiError(
        422, "rule_rejected", result.error, extra={"result": serializers.edit_result(result)}
    )


def _create_form(call: Call) -> RuleCreateForm:
    """The UI's new-rule form filled from the JSON body, so validation is identical."""
    data = call.json()
    text = text_field(data, "text")
    ruleset = int_field(data, "ruleset", required=False)
    collection = text_field(data, "collection", required=False)
    if (ruleset is None) == (not collection):
        raise ApiError(
            400,
            "invalid",
            "The request is not valid.",
            fields={"ruleset": ["Give either `ruleset` or `collection`."]},
        )
    form = RuleCreateForm(
        {
            "text": text,
            "ruleset": NEW_RULESET if ruleset is None else str(ruleset),
            "new_ruleset": collection,
        }
    )
    if not form.is_valid():
        if ruleset is not None and "ruleset" in form.errors:
            raise ApiError(404, "not_found", f"There is no ruleset with id {ruleset}.")
        raise form_error(form)
    return form


@endpoint(
    "GET",
    "rules/",
    operation="rule_list",
    group="Rules",
    summary="List and search rules",
    permissions=VIEW,
    params=(*FILTERS, PAGE),
    replies=(Reply(200, "One page of 100 rules.", schema="RulePage"), *COMMON_ERRORS),
    description="Search, filters, sorting and pagination work exactly as on the Rules page "
    "(the same form and query); invalid filter values are ignored rather than refused.",
)
def rule_list(call: Call) -> HttpResponse:
    rules = (
        _filtered(call.request.GET)
        .select_related("ruleset")
        .prefetch_related(Prefetch("tags", queryset=Tag.objects.order_by("name")))
        .defer("source", "meta", "ruleset__original_content")
    )
    page = paginate(call.request, rules)
    return json_response(page_data(call, page, lambda rule: serializers.rule_summary(call, rule)))


@endpoint(
    "POST",
    "rules/",
    operation="rule_create",
    group="Rules",
    summary="Create a rule",
    permissions=("rules.add_rule",),
    body=Body("json", (RULE_TEXT, *TARGET_FIELDS)),
    replies=(
        Reply(201, "Saved; `broken` lists sibling rules the new rule breaks.", schema="Saved"),
        INVALID,
        NOT_FOUND,
        Reply(
            409,
            "A concurrent change: the name was just taken, or the ruleset was deleted "
            "meanwhile (`conflict`).",
            schema="Error",
        ),
        REFUSED,
        *COMMON_ERRORS,
    ),
    description="Appends the rule to a ruleset, or to a manual collection by name.",
)
def rule_create(call: Call) -> HttpResponse:
    form = _create_form(call)
    text = form.cleaned_data["text"]
    if form.cleaned_data["ruleset"] != NEW_RULESET:
        result = editing.create_rule(form.cleaned_data["ruleset_obj"], text, user=call.user)
    else:
        if not call.user.has_perm("rules.add_ruleset"):
            raise ApiError(
                403,
                "permission_denied",
                "Creating a collection needs the permission rules.add_ruleset.",
            )
        # An unsaved collection is created together with the rule, or not at all.
        ruleset = editing.manual_ruleset(form.cleaned_data["new_ruleset"], save=False)
        result = editing.create_rule(ruleset, text, user=call.user)
    if not result.ok or result.rule is None:
        raise _refused(result)
    rule = _rule(result.rule.pk)
    return json_response(
        serializers.saved(call, rule, result, changed=True),
        status=201,
        headers={"Location": call.absolute(reverse("api:rule_detail", kwargs={"pk": rule.pk}))},
    )


@endpoint(
    "POST",
    "rules/validate/",
    operation="rule_validate_new",
    group="Rules",
    summary="Validate a new rule without saving",
    permissions=("rules.add_rule",),
    body=Body("json", (RULE_TEXT, *TARGET_FIELDS)),
    replies=(
        Reply(
            200,
            "The validation result (`ok` false with `error` and `line` when the "
            "rule would be refused).",
            schema="Validation",
        ),
        INVALID,
        NOT_FOUND,
        *COMMON_ERRORS,
    ),
    description="The editor's Validate button for a new rule: checks the text in the "
    "context of the target ruleset. Nothing is written.",
)
def rule_validate_new(call: Call) -> HttpResponse:
    form = _create_form(call)
    text = form.cleaned_data["text"]
    if form.cleaned_data["ruleset"] != NEW_RULESET:
        result = editing.validate_rule_text(form.cleaned_data["ruleset_obj"], text)
    else:
        ruleset = editing.manual_ruleset(form.cleaned_data["new_ruleset"], save=False)
        result = editing.validate_rule_text(ruleset, text)
    return json_response(serializers.edit_result(result))


@endpoint(
    "GET",
    "rules/<int:pk>/",
    operation="rule_detail",
    group="Rules",
    summary="Read a rule",
    permissions=VIEW,
    replies=(
        Reply(200, "The rule with its source and version list.", schema="Rule"),
        NOT_FOUND,
        *COMMON_ERRORS,
    ),
)
def rule_detail(call: Call, pk: int) -> HttpResponse:
    rule = get_object_or_404(
        Rule.objects.select_related("ruleset")
        .defer("ruleset__original_content")
        .prefetch_related("tags"),
        pk=pk,
    )
    return json_response(_detail(call, rule))


@endpoint(
    "PUT",
    "rules/<int:pk>/",
    operation="rule_update",
    group="Rules",
    summary="Edit a rule",
    permissions=("rules.change_rule",),
    body=Body(
        "json",
        (
            RULE_TEXT,
            BodyField(
                "version",
                "The rule's version your change is based on (`version` from the rule). "
                "If the rule has changed since, nothing is saved and the answer is 409.",
                type="integer",
                required=True,
                example=3,
            ),
        ),
    ),
    replies=(
        Reply(
            200,
            "Saved as a new version, or `changed` false when the text is identical.",
            schema="Saved",
        ),
        INVALID,
        NOT_FOUND,
        Reply(
            409,
            "The rule was changed after `version`; `current_version` says to what.",
            schema="Error",
        ),
        REFUSED,
        *COMMON_ERRORS,
    ),
)
def rule_update(call: Call, pk: int) -> HttpResponse:
    data = call.json()
    form = RuleUpdateForm({"text": text_field(data, "text"), "version": int_field(data, "version")})
    rule = _rule(pk)
    if not form.is_valid():
        raise form_error(form)
    if form.cleaned_data["version"] != rule.version:
        raise ApiError(
            409,
            "version_conflict",
            f"This rule was changed (now version {rule.version}) after version "
            f"{form.cleaned_data['version']}. Read it again and reapply your change.",
            extra={"current_version": rule.version},
        )
    old_version = rule.version
    result = editing.update_rule(
        rule,
        form.cleaned_data["text"],
        user=call.user,
        expected_version=form.cleaned_data["version"],
    )
    if not result.ok or result.rule is None:
        raise _refused(result, pk)
    saved = _rule(result.rule.pk)
    return json_response(
        serializers.saved(call, saved, result, changed=saved.version != old_version)
    )


@endpoint(
    "DELETE",
    "rules/<int:pk>/",
    operation="rule_delete",
    group="Rules",
    summary="Delete a rule",
    permissions=("rules.delete_rule",),
    replies=(Reply(204, "Deleted (recoverable)."), NOT_FOUND, *COMMON_ERRORS),
    description="Recoverable: the rule is flagged deleted with its history kept, left out "
    "of lists, scans and exports, and listed under deleted rules, from where it can be "
    "restored (or purged by an administrator). Imports do not bring it back.",
)
def rule_delete(call: Call, pk: int) -> HttpResponse:
    editing.delete_rule(_rule(pk), user=call.user)
    return no_content()


@endpoint(
    "POST",
    "rules/<int:pk>/validate/",
    operation="rule_validate",
    group="Rules",
    summary="Validate an edit without saving",
    permissions=("rules.change_rule",),
    body=Body("json", (RULE_TEXT,)),
    replies=(
        Reply(200, "The validation result.", schema="Validation"),
        INVALID,
        NOT_FOUND,
        *COMMON_ERRORS,
    ),
    description="The editor's Validate button: checks new text for this rule in the context "
    "of its ruleset, including sibling rules the change would break. Nothing is written.",
)
def rule_validate(call: Call, pk: int) -> HttpResponse:
    data = call.json()
    form = RuleUpdateForm({"text": text_field(data, "text"), "version": 1})
    rule = _rule(pk)
    if not form.is_valid():
        raise form_error(form)
    result = editing.validate_rule_text(rule.ruleset, form.cleaned_data["text"], rule)
    return json_response(serializers.edit_result(result))


@endpoint(
    "GET",
    "rules/<int:pk>/download/",
    operation="rule_download",
    group="Rules",
    summary="Download a rule",
    permissions=VIEW,
    replies=(
        Reply(200, "`<name>.yar` with the rule and its imports.", file="text/plain; charset=utf-8"),
        NOT_FOUND,
        *COMMON_ERRORS,
    ),
)
def rule_download(call: Call, pk: int) -> HttpResponse:
    return file_response(exporter.export_rule(get_object_or_404(Rule, pk=pk)))


EXPORT_FORMAT = Param(
    "format",
    "`yar` (default): one combined file; `zip`: one .yar file per ruleset.",
    enum=("yar", "zip"),
    example="zip",
)


def _export(call: Call, data: QueryDict) -> HttpResponse:
    """The UI's export: the same form, filter and services."""
    form = ExportForm(data)
    if not form.is_valid():
        raise form_error(form)
    if form.cleaned_data["scope"] == "selected":
        rules = Rule.objects.filter(pk__in=form.cleaned_data["ids"])
    else:
        rules = _filtered(data)
    selected = list(rules.active().select_related("ruleset"))
    if not selected:
        raise ApiError(404, "nothing_to_export", "Nothing to export: no active rules match.")
    if form.cleaned_data.get("format") == "zip":
        return file_response(exporter.export_zip(selected))
    return file_response(exporter.export_combined(selected))


EXPORT_REPLIES = (
    Reply(
        200,
        "`yaradude-rules.yar` or `yaradude-rules.zip`; removed rules are skipped.",
        file="application/zip",
    ),
    INVALID,
    Reply(404, "No active rule matches.", schema="Error"),
    *COMMON_ERRORS,
)


@endpoint(
    "GET",
    "rules/export/",
    operation="rule_export",
    group="Rules",
    summary="Export the rules matching a filter",
    permissions=VIEW,
    params=(
        *FILTERS,
        Param(
            "ids",
            "Export exactly these rule ids instead of the filter.",
            type="integer",
            repeated=True,
        ),
        EXPORT_FORMAT,
    ),
    replies=EXPORT_REPLIES,
    description="Takes the same filters as the rules list. Removed rules are never exported.",
)
def rule_export(call: Call) -> HttpResponse:
    data = call.request.GET.copy()
    data["scope"] = "selected" if data.getlist("ids") else "filter"
    return _export(call, data)


@endpoint(
    "POST",
    "rules/export/",
    operation="rule_export_selected",
    group="Rules",
    summary="Export selected rules",
    permissions=VIEW,
    body=Body(
        "json",
        (
            BodyField(
                "ids",
                "Rule ids to export.",
                type="integer",
                repeated=True,
                required=True,
                example=[42, 43],
            ),
            BodyField("format", "`yar` (default) or `zip`.", example="yar"),
        ),
    ),
    replies=EXPORT_REPLIES,
    description="For selections too long for a query string.",
)
def rule_export_selected(call: Call) -> HttpResponse:
    body = call.json()
    data = QueryDict(mutable=True)
    data.setlist("ids", [str(pk) for pk in id_list(body, "ids")])
    data["scope"] = "selected"
    data["format"] = text_field(body, "format", required=False)
    return _export(call, data)


@endpoint(
    "GET",
    "rules/<int:pk>/versions/",
    operation="rule_versions",
    group="Rules",
    summary="List a rule's versions",
    permissions=VIEW_VERSIONS,
    replies=(
        Reply(200, "Versions, newest first.", schema="VersionList"),
        NOT_FOUND,
        *COMMON_ERRORS,
    ),
)
def rule_versions(call: Call, pk: int) -> HttpResponse:
    rule = get_object_or_404(Rule.objects.only("pk"), pk=pk)
    versions = rule.versions.select_related("created_by").order_by("-number")
    return json_response(
        {"results": [serializers.version_summary(call, version) for version in versions]}
    )


@endpoint(
    "GET",
    "rules/<int:pk>/versions/<int:number>/",
    operation="rule_version",
    group="Rules",
    summary="Read a version with its diff",
    permissions=VIEW_VERSIONS,
    replies=(
        Reply(
            200, "The version's text and its diff against the previous version.", schema="Version"
        ),
        NOT_FOUND,
        *COMMON_ERRORS,
    ),
)
def rule_version(call: Call, pk: int, number: int) -> HttpResponse:
    version = get_object_or_404(
        RuleVersion.objects.select_related("rule", "created_by"),
        rule_id=pk,
        rule__deleted_at__isnull=True,
        number=number,
    )
    previous = previous_version(version)
    following = (
        version.rule.versions.filter(number__gt=number).order_by("number").only("number").first()
    )
    return json_response(
        serializers.version_detail(
            call,
            version,
            previous,
            following.number if following else None,
            diff_versions(previous, version),
        )
    )


@endpoint(
    "POST",
    "rules/<int:pk>/versions/<int:number>/restore/",
    operation="rule_restore",
    group="Rules",
    summary="Restore a version",
    permissions=("rules.change_rule",),
    body=Body(
        "json",
        (
            BodyField(
                "version",
                "Optional: the rule's current version as you know it; 409 if it has moved on.",
                type="integer",
            ),
        ),
    ),
    replies=(
        Reply(
            200,
            "The old text is the rule's new version (`changed` false if it is the "
            "current content).",
            schema="Saved",
        ),
        NOT_FOUND,
        Reply(409, "The rule was changed after `version`.", schema="Error"),
        REFUSED,
        *COMMON_ERRORS,
    ),
    description="The old text becomes a new version, with the same checks as an edit. "
    "The body may be empty.",
)
def rule_restore(call: Call, pk: int, number: int) -> HttpResponse:
    has_body = call.request.content_type == "application/json" and call.request.body
    expected = int_field(call.json(), "version", required=False) if has_body else None
    version = get_object_or_404(
        RuleVersion.objects.select_related("rule__ruleset"),
        rule_id=pk,
        rule__deleted_at__isnull=True,
        number=number,
    )
    old_version = version.rule.version
    if expected is not None and expected != old_version:
        raise ApiError(
            409,
            "version_conflict",
            f"This rule was changed (now version {old_version}) after version {expected}.",
            extra={"current_version": old_version},
        )
    result = editing.restore_version(version, user=call.user, expected_version=expected)
    if not result.ok or result.rule is None:
        raise _refused(result, pk)
    rule = _rule(result.rule.pk)
    return json_response(serializers.saved(call, rule, result, changed=rule.version != old_version))


@endpoint(
    "GET",
    "tags/",
    operation="tag_list",
    group="Rules",
    summary="List tags",
    permissions=("rules.view_tag",),
    params=(PAGE,),
    replies=(
        Reply(200, "Tags by name with their number of active rules.", schema="TagPage"),
        *COMMON_ERRORS,
    ),
    description="Use a tag name with the `tag` filter of the rules list.",
)
def tag_list(call: Call) -> HttpResponse:
    tags = Tag.objects.annotate(
        rule_count=Count(
            "rules", filter=Q(rules__removed_at__isnull=True, rules__deleted_at__isnull=True)
        )
    ).order_by("name")
    page = paginate(call.request, tags)
    return json_response(
        page_data(call, page, lambda tag: {"name": tag.name, "rules": tag.rule_count})
    )
