"""
Create, edit, restore and delete rules from the web editor.

The editor text holds optional `import` lines followed by exactly one rule.
A save is refused when the text does not parse, the rule name is taken in
the ruleset, or the edited rule itself does not compile; an edit that breaks
sibling rules is saved and the breakage is reported.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING

from django.db import transaction
from django.db.models import Max
from django.utils import timezone

from rules.models import Rule, Ruleset, RuleVersion, Tag
from rules.services.compiler import BrokenRule, check_ruleset, validate_edit
from rules.services.parser import ParsedRule, RuleParseError, parse_rule_text

if TYPE_CHECKING:
    from accounts.models import User


@dataclass(frozen=True)
class EditResult:
    """
    Outcome of validating or saving editor text. `error` and `line` (relative
    to the editor text) explain why the text cannot be saved; `warnings` and
    `broken` are informational. `rule` is set once the rule has been saved.
    """

    error: str = ""
    line: int | None = None
    warnings: list[str] = field(default_factory=list)
    broken: list[BrokenRule] = field(default_factory=list)
    parsed: ParsedRule | None = None
    rule: Rule | None = None

    @property
    def ok(self) -> bool:
        return not self.error


def validate_rule_text(ruleset: Ruleset, text: str, rule: Rule | None = None) -> EditResult:
    """Check editor text for `rule` (None for a new rule) without saving it."""
    try:
        parsed = parse_rule_text(text)
    except RuleParseError as error:
        return EditResult(error=error.message, line=error.line)
    clash = ruleset.rules.filter(name=parsed.name)
    if rule is not None:
        clash = clash.exclude(pk=rule.pk)
    if clash.exists():
        return EditResult(
            error=f'A rule named "{parsed.name}" already exists in this ruleset.',
            line=parsed.line,
            parsed=parsed,
        )
    validation = validate_edit(ruleset, rule, parsed)
    return EditResult(
        error=validation.error,
        line=validation.line,
        warnings=validation.warnings,
        broken=validation.broken,
        parsed=parsed,
    )


def create_rule(ruleset: Ruleset, text: str, user: User | None = None) -> EditResult:
    """Validate editor text and, if valid, add it as a new rule at the end of `ruleset`."""
    result = validate_rule_text(ruleset, text)
    parsed = result.parsed
    if not result.ok or parsed is None:  # a valid result always carries `parsed`
        return result
    now = timezone.now()
    with transaction.atomic():
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
        _content_changed(ruleset, now)
    rule.refresh_from_db()
    return _saved(result, rule)


def update_rule(
    rule: Rule,
    text: str,
    user: User | None = None,
    origin: RuleVersion.Origin = RuleVersion.Origin.EDIT,
) -> EditResult:
    """
    Validate editor text and, if valid, store it as the rule's new version.
    Text identical to the current content saves nothing.
    """
    ruleset = rule.ruleset
    result = validate_rule_text(ruleset, text, rule)
    parsed = result.parsed
    if not result.ok or parsed is None:  # a valid result always carries `parsed`
        return result
    if parsed.sha256 == rule.sha256:
        return _saved(result, rule)
    now = timezone.now()
    with transaction.atomic():
        rule.apply_parsed(parsed)
        rule.version += 1
        rule.updated_at = now
        rule.save()
        rule.set_tags(parsed.tags)
        rule.record_version(origin, user=user)
        _content_changed(ruleset, now)
    rule.refresh_from_db()
    return _saved(result, rule)


def restore_version(version: RuleVersion, user: User | None = None) -> EditResult:
    """
    Make an old version the rule's current content, as a new version. The
    same checks as for an edit apply.
    """
    return update_rule(version.rule, version.text, user, origin=RuleVersion.Origin.RESTORE)


def delete_rule(rule: Rule) -> None:
    """Delete a rule with its history and re-check its ruleset."""
    ruleset = rule.ruleset
    with transaction.atomic():
        rule.delete()
        _content_changed(ruleset, timezone.now())


def delete_ruleset(ruleset: Ruleset) -> None:
    """
    Delete a ruleset with its rules and their history. Import runs keep their
    per-file records, which lose the link to the ruleset.
    """
    with transaction.atomic():
        ruleset.delete()
        Tag.objects.unused().delete()


def manual_ruleset(name: str) -> Ruleset:
    """The manual ruleset with this name, created if needed."""
    ruleset, _ = Ruleset.objects.get_or_create(
        origin=Ruleset.Origin.MANUAL, path=name, defaults={"name": name}
    )
    return ruleset


def _content_changed(ruleset: Ruleset, now: datetime) -> None:
    Tag.objects.unused().delete()
    ruleset.updated_at = now
    ruleset.save(update_fields=["updated_at"])
    check_ruleset(ruleset)


def _saved(result: EditResult, rule: Rule) -> EditResult:
    return EditResult(
        warnings=rule.compile_warnings,
        broken=result.broken,
        parsed=result.parsed,
        rule=rule,
    )
