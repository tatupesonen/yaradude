"""
Model instances and service results as JSON-ready dicts. The shapes are
documented in api.schemas, and the tests check every response against them.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from django.urls import reverse

from api.http import Call
from api.models import ApiKey
from rules.models import ImportFile, ImportRun, Rule, Ruleset, RuleVersion
from rules.services.compiler import BrokenRule
from rules.services.diffing import Diff
from rules.services.editing import EditResult
from rules.services.scanner import ScanResult

Data = dict[str, Any]


def ts(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _username(user: Any) -> str | None:
    return user.get_username() if user is not None else None


def ruleset_ref(call: Call, ruleset: Ruleset) -> Data:
    return {
        "id": ruleset.pk,
        "name": ruleset.name,
        "path": ruleset.path,
        "origin": ruleset.origin,
        "url": call.absolute(reverse("api:ruleset_detail", kwargs={"pk": ruleset.pk})),
    }


def rule_status(rule: Rule) -> str:
    """The same order of precedence as the UI's status badge."""
    if rule.is_removed:
        return "removed"
    if rule.compile_error:
        return "error"
    if rule.compile_warnings:
        return "warnings"
    return "ok"


def rule_summary(call: Call, rule: Rule) -> Data:
    """A row of the rules list (no source: it is deferred on list queries)."""
    return {
        "id": rule.pk,
        "name": rule.name,
        "ruleset": ruleset_ref(call, rule.ruleset),
        "tags": [tag.name for tag in rule.tags.all()],
        "description": rule.description,
        "author": rule.author,
        "version": rule.version,
        "status": rule_status(rule),
        "modified": rule.is_modified,
        "created_at": ts(rule.created_at),
        "updated_at": ts(rule.updated_at),
        "removed_at": ts(rule.removed_at),
        "url": call.absolute(reverse("api:rule_detail", kwargs={"pk": rule.pk})),
        "web_url": call.absolute(rule.get_absolute_url()),
    }


def rule_detail(call: Call, rule: Rule, versions: list[RuleVersion]) -> Data:
    return {
        **rule_summary(call, rule),
        "text": rule.text,
        "source": rule.source,
        "imports": rule.imports,
        "meta": rule.meta,
        "is_private": rule.is_private,
        "is_global": rule.is_global,
        "position": rule.position,
        "sha256": rule.sha256,
        "imported_sha256": rule.imported_sha256,
        "compile_error": rule.compile_error,
        "compile_warnings": rule.compile_warnings,
        "download_url": call.absolute(reverse("api:rule_download", kwargs={"pk": rule.pk})),
        "versions": [version_summary(call, version) for version in versions],
    }


def version_summary(call: Call, version: RuleVersion) -> Data:
    return {
        "number": version.number,
        "origin": version.origin,
        "sha256": version.sha256,
        "created_at": ts(version.created_at),
        "created_by": _username(version.created_by),
        "import_run": version.import_run_id,
        "url": call.absolute(
            reverse("api:rule_version", kwargs={"pk": version.rule_id, "number": version.number})
        ),
    }


def diff_data(diff: Diff) -> Data:
    return {
        "added": diff.added,
        "removed": diff.removed,
        "lines": [
            {
                "kind": line.kind,
                "text": line.text,
                "old_number": line.old_number,
                "new_number": line.new_number,
            }
            for line in diff.lines
        ],
    }


def version_detail(
    call: Call,
    version: RuleVersion,
    previous: RuleVersion | None,
    next_number: int | None,
    diff: Diff,
) -> Data:
    return {
        **version_summary(call, version),
        "rule": version.rule_id,
        "text": version.text,
        "is_current": version.sha256 == version.rule.sha256,
        "previous": previous.number if previous else None,
        "next": next_number,
        "diff": diff_data(diff),
    }


def broken(item: BrokenRule) -> Data:
    return {"id": item.rule.pk, "name": item.rule.name, "error": item.error}


def edit_result(result: EditResult) -> Data:
    """The outcome of a validation or of a refused save."""
    return {
        "ok": result.ok,
        "error": result.error,
        "line": result.line,
        "warnings": result.warnings,
        "broken": [broken(item) for item in result.broken],
        "name": result.parsed.name if result.parsed else None,
    }


def saved(call: Call, rule: Rule, result: EditResult, changed: bool) -> Data:
    """The outcome of a successful create, edit or restore."""
    return {
        "changed": changed,
        "warnings": result.warnings,
        "broken": [broken(item) for item in result.broken],
        "rule": rule_detail(call, rule, list(rule.versions.select_related("created_by"))),
    }


def ruleset_summary(call: Call, ruleset: Ruleset) -> Data:
    """A row of the rulesets list; expects the counts of rules.views.rulesets.with_counts."""
    counts: Any = ruleset  # annotated attributes
    return {
        **ruleset_ref(call, ruleset),
        "compile_error": ruleset.compile_error,
        "rules_active": counts.active_count,
        "rules_failing": counts.failing_count,
        "rules_removed": counts.removed_count,
        "sha256": ruleset.sha256,
        "created_at": ts(ruleset.created_at),
        "updated_at": ts(ruleset.updated_at),
        "last_imported_at": ts(ruleset.last_imported_at),
        "web_url": call.absolute(ruleset.get_absolute_url()),
    }


def ruleset_detail(call: Call, ruleset: Ruleset, rules: list[Rule], has_original: bool) -> Data:
    pk = ruleset.pk
    return {
        **ruleset_summary(call, ruleset),
        "download_url": call.absolute(reverse("api:ruleset_download", kwargs={"pk": pk})),
        "original_url": (
            call.absolute(reverse("api:ruleset_original", kwargs={"pk": pk}))
            if has_original
            else None
        ),
        "rules": [rule_summary(call, rule) for rule in rules],
    }


def import_run_summary(call: Call, run: ImportRun) -> Data:
    return {
        "id": run.pk,
        "origin": run.origin,
        "source": run.source,
        "user": _username(run.user),
        "started_at": ts(run.started_at),
        "finished_at": ts(run.finished_at),
        "files_seen": run.files_seen,
        "files_changed": run.files_changed,
        "files_unchanged": run.files_unchanged,
        "files_failed": run.files_failed,
        "files_skipped": run.files_skipped,
        "rules_created": run.rules_created,
        "rules_updated": run.rules_updated,
        "rules_removed": run.rules_removed,
        "rules_unchanged": run.rules_unchanged,
        "rules_skipped": run.rules_skipped,
        "summary": run.summary,
        "url": call.absolute(reverse("api:import_detail", kwargs={"pk": run.pk})),
        "web_url": call.absolute(run.get_absolute_url()),
    }


def import_file(call: Call, item: ImportFile) -> Data:
    return {
        "path": item.path,
        "status": item.status,
        # A deleted ruleset is not linked (its API URL would answer 404).
        "ruleset": (
            ruleset_ref(call, item.ruleset)
            if item.ruleset and not item.ruleset.is_deleted
            else None
        ),
        "rules_created": item.rules_created,
        "rules_updated": item.rules_updated,
        "rules_removed": item.rules_removed,
        "rules_unchanged": item.rules_unchanged,
        "rules_skipped": item.rules_skipped,
        "message": item.message,
    }


def import_run_detail(call: Call, run: ImportRun, files: list[ImportFile]) -> Data:
    return {**import_run_summary(call, run), "files": [import_file(call, f) for f in files]}


def scan_result(call: Call, result: ScanResult) -> Data:
    return {
        "sample": {
            "name": result.sample_name,
            "size": result.sample_size,
            "sha256": result.sample_sha256,
        },
        "rules_scanned": result.rules_scanned,
        "rulesets_scanned": len(result.rulesets),
        "elapsed": round(result.elapsed, 3),
        "scan_seconds": round(result.scan_seconds, 3),
        "compiled": {
            "revision": result.revision,
            "built_at": ts(result.built_at),
            "pending": result.pending,
        },
        "unmapped": result.unmapped,
        "matches": [
            {
                "rule": {
                    "id": match.rule.pk,
                    "name": match.rule.name,
                    "ruleset": ruleset_ref(call, match.ruleset),
                    "url": call.absolute(reverse("api:rule_detail", kwargs={"pk": match.rule.pk})),
                },
                "tags": match.tags,
                "patterns": [
                    {
                        "identifier": pattern.identifier,
                        "count": pattern.count,
                        "instances": [
                            {
                                "offset": i.offset,
                                "length": i.length,
                                "hex": i.hex,
                                "ascii": i.ascii,
                                "truncated": i.truncated,
                            }
                            for i in pattern.instances
                        ],
                    }
                    for pattern in match.patterns
                ],
            }
            for match in result.matches
        ],
        "left_out": [
            {"id": rule.pk, "name": rule.name, "ruleset": rule.ruleset_id}
            for rule in result.left_out
        ],
    }


def deleted_rule(call: Call, rule: Rule) -> Data:
    return {
        "id": rule.pk,
        "name": rule.name,
        "ruleset": {
            "id": rule.ruleset_id,
            "name": rule.ruleset.name,
            "path": rule.ruleset.path,
            "deleted": rule.ruleset.is_deleted,
        },
        "version": rule.version,
        "deleted_at": ts(rule.deleted_at),
        "deleted_by": _username(rule.deleted_by),
        "deleted_with_ruleset": rule.deleted_with_ruleset,
        "restore_url": call.absolute(reverse("api:deleted_rule_restore", kwargs={"pk": rule.pk})),
    }


def deleted_ruleset(call: Call, ruleset: Ruleset) -> Data:
    counts: Any = ruleset  # annotated attribute
    return {
        "id": ruleset.pk,
        "name": ruleset.name,
        "path": ruleset.path,
        "origin": ruleset.origin,
        "rules_deleted": counts.rules_deleted,
        "deleted_at": ts(ruleset.deleted_at),
        "deleted_by": _username(ruleset.deleted_by),
        "restore_url": call.absolute(
            reverse("api:deleted_ruleset_restore", kwargs={"pk": ruleset.pk})
        ),
    }


def api_key(key: ApiKey) -> Data:
    return {
        "prefix": key.prefix,
        "name": key.name,
        "created_at": ts(key.created_at),
        "last_used_at": ts(key.last_used_at),
        "expires_at": ts(key.expires_at),
    }
