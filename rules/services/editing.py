"""
Create, edit, restore and delete rules from the web editor.

The editor text holds optional `import` lines followed by exactly one rule.
A save is refused when the text does not parse, the rule name is taken in
the ruleset, or the edited rule itself does not compile; an edit that breaks
sibling rules is saved and the breakage is reported.

Saves compile before taking the write lock. Inside the transaction the rule
and its siblings are read again: a rule that changed since the editor was
opened (or since it was validated) is a conflict reported as an EditResult
error, and the stored diagnostics are recompiled only if the siblings changed
in between (PLAN.md section 13, findings 1 and 2).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING

from django.db import IntegrityError, transaction
from django.db.models import Max
from django.utils import timezone

from rules.models import Rule, Ruleset, RuleVersion, Tag
from rules.services import revision
from rules.services.compiler import (
    BrokenRule,
    EditPlan,
    RuleEntry,
    check_ruleset,
    plan_edit,
    ruleset_entries,
    store_check,
)
from rules.services.parser import ParsedRule, RuleParseError, parse_rule_text

if TYPE_CHECKING:
    from accounts.models import User


@dataclass(frozen=True)
class EditResult:
    """
    Outcome of validating or saving editor text. `error` and `line` (relative
    to the editor text) explain why the text cannot be saved; `warnings` and
    `broken` are informational. `rule` is set once the rule has been saved.
    `conflict` is True when the save was refused because the rule or its
    ruleset changed concurrently (the text itself may be fine).
    """

    error: str = ""
    line: int | None = None
    warnings: list[str] = field(default_factory=list)
    broken: list[BrokenRule] = field(default_factory=list)
    parsed: ParsedRule | None = None
    rule: Rule | None = None
    conflict: bool = False

    @property
    def ok(self) -> bool:
        return not self.error


@dataclass(frozen=True)
class _Validated:
    result: EditResult
    plan: EditPlan | None  # set when the text parsed and the name is free


def _name_holder(ruleset: Ruleset, name: str, rule: Rule | None) -> Rule | None:
    """The other rule of the ruleset holding `name`, deleted and removed rules included."""
    if ruleset.pk is None:
        return None
    clash = Rule.all_objects.filter(ruleset=ruleset, name=name)
    if rule is not None:
        clash = clash.exclude(pk=rule.pk)
    return clash.only("pk", "deleted_at").first()


def _name_taken_error(parsed: ParsedRule, holder: Rule, conflict: bool = False) -> EditResult:
    if holder.is_deleted:
        error = (
            f'A deleted rule named "{parsed.name}" still holds this name in this ruleset. '
            "Restore it, or purge it to free the name."
        )
    else:
        error = f'A rule named "{parsed.name}" already exists in this ruleset.'
    return EditResult(error=error, line=parsed.line, parsed=parsed, conflict=conflict)


def _validate(ruleset: Ruleset, text: str, rule: Rule | None) -> _Validated:
    try:
        parsed = parse_rule_text(text)
    except RuleParseError as error:
        return _Validated(EditResult(error=error.message, line=error.line), None)
    if (holder := _name_holder(ruleset, parsed.name, rule)) is not None:
        return _Validated(_name_taken_error(parsed, holder), None)
    plan = plan_edit(ruleset, rule, parsed)
    validation = plan.validation
    result = EditResult(
        error=validation.error,
        line=validation.line,
        warnings=validation.warnings,
        broken=validation.broken,
        parsed=parsed,
    )
    return _Validated(result, plan)


def validate_rule_text(ruleset: Ruleset, text: str, rule: Rule | None = None) -> EditResult:
    """
    Check editor text for `rule` (None for a new rule) without saving it.
    `ruleset` may be unsaved (a collection that does not exist yet); it then
    has no other rules.
    """
    return _validate(ruleset, text, rule).result


def _conflict(message: str, parsed: ParsedRule | None = None) -> EditResult:
    return EditResult(error=message, parsed=parsed, conflict=True)


def _store_diagnostics(ruleset: Ruleset, plan: EditPlan) -> None:
    """
    Store the diagnostics compiled before the transaction if the ruleset's
    active rules are still exactly what was compiled; otherwise compile again
    (another writer got in between).
    """
    rules, active = ruleset_entries(ruleset)
    if [RuleEntry.of(rule) for rule in active] == plan.entries:
        store_check(ruleset, rules, plan.results, changed=True)
    else:
        check_ruleset(ruleset, changed=True)


def create_rule(ruleset: Ruleset, text: str, user: User | None = None) -> EditResult:
    """
    Validate editor text and, if valid, add it as a new rule at the end of
    `ruleset`. An unsaved `ruleset` (see `manual_ruleset(..., save=False)`)
    is created together with the rule, so a refused save leaves nothing behind.
    """
    validated = _validate(ruleset, text, None)
    result, plan = validated.result, validated.plan
    parsed = result.parsed
    if not result.ok or parsed is None or plan is None:  # a valid result carries both
        return result
    now = timezone.now()
    try:
        with transaction.atomic():
            if ruleset.pk is None:
                ruleset, _ = Ruleset.all_objects.get_or_create(
                    origin=ruleset.origin, path=ruleset.path, defaults={"name": ruleset.name}
                )
            if not Ruleset.objects.filter(pk=ruleset.pk).exists():
                return _conflict(
                    "This ruleset has been deleted; restore it before adding rules.", parsed
                )
            if (holder := _name_holder(ruleset, parsed.name, None)) is not None:
                return _name_taken_error(parsed, holder, conflict=True)
            last = ruleset.rules.aggregate(last=Max("position"))["last"]
            rule = Rule(
                ruleset=ruleset,
                position=0 if last is None else last + 1,
                created_at=now,
                updated_at=now,
            )
            rule.apply_parsed(parsed)
            rule.save()
            rule.set_tags(parsed.tags)
            rule.record_version(RuleVersion.Origin.CREATE, user=user)
            _content_changed(ruleset, now, plan)
    except IntegrityError:
        # A concurrent create of the same name that slipped past the check.
        return _conflict(f'A rule named "{parsed.name}" was just created by someone else.', parsed)
    rule.refresh_from_db()
    return _saved(result, rule)


def update_rule(
    rule: Rule,
    text: str,
    user: User | None = None,
    origin: RuleVersion.Origin = RuleVersion.Origin.EDIT,
    *,
    expected_version: int | None = None,
) -> EditResult:
    """
    Validate editor text and, if valid, store it as the rule's new version.
    Text identical to the current content saves nothing.

    `expected_version` is the version the editor was rendered with; when
    omitted, the version of the `rule` instance passed in is expected. If the
    stored rule has moved on (another save, an import) or was deleted, nothing
    is saved and the result is an error with `conflict` set.
    """
    expected = rule.version if expected_version is None else expected_version
    ruleset = rule.ruleset
    if rule.version != expected:
        return _changed_meanwhile(rule.version)
    validated = _validate(ruleset, text, rule)
    result, plan = validated.result, validated.plan
    parsed = result.parsed
    if not result.ok or parsed is None or plan is None:  # a valid result carries both
        return result
    if parsed.sha256 == rule.sha256:
        return _saved(result, rule)
    now = timezone.now()
    try:
        with transaction.atomic():
            current = Rule.objects.filter(pk=rule.pk).first()
            if current is None:
                return _conflict("This rule was deleted meanwhile.", parsed)
            if current.version != expected:
                return EditResult(
                    error=_changed_meanwhile(current.version).error, parsed=parsed, conflict=True
                )
            if (holder := _name_holder(ruleset, parsed.name, current)) is not None:
                return _name_taken_error(parsed, holder, conflict=True)
            current.apply_parsed(parsed)
            current.version += 1
            current.updated_at = now
            current.save()
            current.set_tags(parsed.tags)
            current.record_version(origin, user=user)
            _content_changed(ruleset, now, plan)
    except IntegrityError:
        return _conflict("This rule was changed by someone else at the same time.", parsed)
    current.refresh_from_db()
    rule.refresh_from_db()  # callers holding `rule` see the saved state, as before
    return _saved(result, current)


def _changed_meanwhile(version: int) -> EditResult:
    return _conflict(
        f"This rule was changed (now version {version}) after you opened the editor. "
        "Copy your text, reload the page and apply your change again."
    )


def restore_version(
    version: RuleVersion, user: User | None = None, *, expected_version: int | None = None
) -> EditResult:
    """
    Make an old version the rule's current content, as a new version. The
    same checks as for an edit apply, including `expected_version` (the
    rule's current version as shown on the page).
    """
    return update_rule(
        version.rule,
        version.text,
        user,
        origin=RuleVersion.Origin.RESTORE,
        expected_version=expected_version,
    )


def delete_rule(rule: Rule, user: User | None = None) -> None:
    """
    Delete a rule recoverably (PLAN.md 12.11): flag it deleted (when, by
    whom), keep it with its history and tags, and re-check its ruleset. A
    deleted rule is left out of lists, compiles, scans and exports, still
    holds its name, and is not touched by imports. Deleting a deleted rule
    does nothing.
    """
    now = timezone.now()
    with transaction.atomic():
        if not Rule.objects.filter(pk=rule.pk).update(
            deleted_at=now, deleted_by=user, deleted_with_ruleset=False
        ):
            return
        rule.deleted_at, rule.deleted_by, rule.deleted_with_ruleset = now, user, False
        _content_changed(rule.ruleset, now)


def delete_ruleset(ruleset: Ruleset, user: User | None = None) -> None:
    """
    Delete a ruleset recoverably, together with its rules (each flagged as
    deleted with the ruleset, so restoring the ruleset brings back exactly
    those). Imports of its file are skipped until it is restored. Deleting a
    deleted ruleset does nothing.
    """
    now = timezone.now()
    with transaction.atomic():
        if not Ruleset.objects.filter(pk=ruleset.pk).update(deleted_at=now, deleted_by=user):
            return
        ruleset.deleted_at, ruleset.deleted_by = now, user
        Rule.objects.filter(ruleset=ruleset).update(
            deleted_at=now, deleted_by=user, deleted_with_ruleset=True
        )
        revision.bump()


def restore_rule(rule: Rule, user: User | None = None) -> EditResult:
    """
    Bring back a deleted rule with the content it had when deleted, and
    re-check its ruleset. If its file moved on meanwhile, the next import
    updates it under the normal rules (the ruleset's file hash is cleared so
    the next import reads the file again). A rule of a deleted ruleset is
    restored by restoring the ruleset. `user` is kept for attribution.
    """
    ruleset = Ruleset.all_objects.get(pk=rule.ruleset_id)
    if ruleset.is_deleted:
        return EditResult(error="Its ruleset is deleted; restore the ruleset instead.")
    now = timezone.now()
    with transaction.atomic():
        if not Rule.all_objects.filter(pk=rule.pk, deleted_at__isnull=False).update(
            deleted_at=None, deleted_by=None, deleted_with_ruleset=False
        ):
            return _conflict("This rule is not deleted (anymore).")
        _needs_reimport(ruleset)
        _content_changed(ruleset, now)
    restored = Rule.objects.get(pk=rule.pk)
    rule.refresh_from_db()
    return EditResult(warnings=restored.compile_warnings, rule=restored)


def restore_ruleset(ruleset: Ruleset, user: User | None = None) -> None:
    """
    Bring back a deleted ruleset with the rules deleted together with it
    (rules deleted on their own before stay deleted), and re-check it. The
    next import of its file reads it again.
    """
    with transaction.atomic():
        if not Ruleset.all_objects.filter(pk=ruleset.pk, deleted_at__isnull=False).update(
            deleted_at=None, deleted_by=None
        ):
            return
        ruleset.deleted_at = ruleset.deleted_by = None
        Rule.all_objects.filter(ruleset=ruleset, deleted_with_ruleset=True).update(
            deleted_at=None, deleted_by=None, deleted_with_ruleset=False
        )
        _needs_reimport(ruleset)
        check_ruleset(ruleset, changed=True)


def purge_rule(rule: Rule) -> None:
    """
    Permanently delete a rule with its history (the old hard delete). Views
    require the `rules.purge_rule` permission, which no role group has.
    """
    ruleset = Ruleset.all_objects.get(pk=rule.ruleset_id)
    with transaction.atomic():
        Rule.all_objects.filter(pk=rule.pk).delete()
        Tag.objects.unused().delete()
        if ruleset.is_deleted:
            revision.bump()
        else:
            _content_changed(ruleset, timezone.now())


def purge_ruleset(ruleset: Ruleset) -> None:
    """
    Permanently delete a ruleset with its rules and their history (the old
    hard delete; requires `rules.purge_ruleset`). Import runs keep their
    per-file records, which lose the link to the ruleset.
    """
    with transaction.atomic():
        Ruleset.all_objects.filter(pk=ruleset.pk).delete()
        Tag.objects.unused().delete()
        revision.bump()


def _needs_reimport(ruleset: Ruleset) -> None:
    """Make the next import read the ruleset's file even if it has not changed."""
    Ruleset.all_objects.filter(pk=ruleset.pk).update(sha256="")
    ruleset.sha256 = ""


def manual_ruleset(name: str, save: bool = True) -> Ruleset:
    """
    The manual ruleset with this name, created if needed. With `save=False`
    a missing ruleset is returned unsaved instead; validate_rule_text accepts
    it and create_rule creates it together with the rule. A deleted ruleset
    of that name is returned as it is (`is_deleted`); create_rule refuses it.
    """
    if not save:
        existing = Ruleset.all_objects.filter(origin=Ruleset.Origin.MANUAL, path=name).first()
        return existing or Ruleset(name=name, origin=Ruleset.Origin.MANUAL, path=name)
    ruleset, _ = Ruleset.all_objects.get_or_create(
        origin=Ruleset.Origin.MANUAL, path=name, defaults={"name": name}
    )
    return ruleset


def _content_changed(ruleset: Ruleset, now: datetime, plan: EditPlan | None = None) -> None:
    Tag.objects.unused().delete()
    ruleset.updated_at = now
    ruleset.save(update_fields=["updated_at"])
    if plan is None:
        check_ruleset(ruleset, changed=True)
    else:
        _store_diagnostics(ruleset, plan)


def _saved(result: EditResult, rule: Rule) -> EditResult:
    return EditResult(
        warnings=rule.compile_warnings,
        broken=result.broken,
        parsed=result.parsed,
        rule=rule,
    )
