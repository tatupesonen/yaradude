"""Unified line diffs between rule versions."""

import difflib
from dataclasses import dataclass

from rules.models import RuleVersion


@dataclass(frozen=True)
class DiffLine:
    kind: str  # "hunk", "context", "added" or "removed"
    text: str
    old_number: int | None = None  # 1-based line number in the old text
    new_number: int | None = None  # 1-based line number in the new text


@dataclass(frozen=True)
class Diff:
    lines: list[DiffLine]
    added: int
    removed: int

    @property
    def changed(self) -> bool:
        return bool(self.added or self.removed)


def diff_texts(old: str, new: str, context: int = 3) -> Diff:
    """Unified diff of two texts, with `context` unchanged lines around each change."""
    old_lines = old.splitlines()
    new_lines = new.splitlines()
    matcher = difflib.SequenceMatcher(a=old_lines, b=new_lines, autojunk=False)
    lines: list[DiffLine] = []
    added = removed = 0
    for group in matcher.get_grouped_opcodes(context):
        first, last = group[0], group[-1]
        old_start, old_count = first[1], last[2] - first[1]
        new_start, new_count = first[3], last[4] - first[3]
        lines.append(
            DiffLine("hunk", f"@@ -{old_start + 1},{old_count} +{new_start + 1},{new_count} @@")
        )
        for tag, i1, i2, j1, j2 in group:
            if tag == "equal":
                lines.extend(
                    DiffLine("context", old_lines[i], i + 1, j + 1)
                    for i, j in zip(range(i1, i2), range(j1, j2), strict=True)
                )
                continue
            if tag in ("replace", "delete"):
                lines.extend(
                    DiffLine("removed", old_lines[i], old_number=i + 1) for i in range(i1, i2)
                )
                removed += i2 - i1
            if tag in ("replace", "insert"):
                lines.extend(
                    DiffLine("added", new_lines[j], new_number=j + 1) for j in range(j1, j2)
                )
                added += j2 - j1
    return Diff(lines=lines, added=added, removed=removed)


def diff_versions(old: RuleVersion | None, new: RuleVersion, context: int = 3) -> Diff:
    """Diff of a version against the previous one (None for the first version)."""
    return diff_texts(old.text if old is not None else "", new.text, context)


def previous_version(version: RuleVersion) -> RuleVersion | None:
    """The version before `version` of the same rule, if any."""
    return (
        RuleVersion.objects.filter(rule_id=version.rule_id, number__lt=version.number)
        .order_by("-number")
        .first()
    )
