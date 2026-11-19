"""Export rules as .yar text or as a .zip with one .yar file per ruleset."""

import io
import posixpath
import zipfile
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from itertools import groupby
from pathlib import PurePath

from rules.models import Rule, Ruleset
from rules.services.compiler import build_source, combine_rules

YAR_CONTENT_TYPE = "text/plain; charset=utf-8"


@dataclass(frozen=True)
class ExportFile:
    filename: str
    content: bytes
    content_type: str


def export_rule(rule: Rule) -> ExportFile:
    """One rule with its imports as a .yar file."""
    return ExportFile(f"{rule.name}.yar", rule.text.encode(), YAR_CONTENT_TYPE)


def export_ruleset(ruleset: Ruleset) -> ExportFile:
    """The ruleset rebuilt from its current active rules."""
    return ExportFile(ruleset_filename(ruleset), build_source(ruleset).encode(), YAR_CONTENT_TYPE)


def export_ruleset_original(ruleset: Ruleset) -> ExportFile:
    """The file as last imported, verbatim."""
    return ExportFile(
        ruleset_filename(ruleset), ruleset.original_content.encode(), YAR_CONTENT_TYPE
    )


def export_combined(rules: Iterable[Rule]) -> ExportFile:
    """
    The active rules among `rules` as one .yar file: imports at the top, one
    section per ruleset, and a warning comment if rule names repeat across
    rulesets (YARA-X will not compile such a file as a whole).
    """
    groups = _grouped(rules)
    all_rules = [rule for _, group in groups for rule in group]
    duplicates = sorted(name for name, n in Counter(r.name for r in all_rules).items() if n > 1)

    header = [f"// Exported from yaradude: {len(all_rules)} rules from {len(groups)} rulesets."]
    if duplicates:
        header.append(
            "// WARNING: these rule names occur in more than one ruleset, so this file"
            " does not compile as a whole: " + ", ".join(duplicates)
        )
    imports = dict.fromkeys(module for rule in all_rules for module in rule.imports)
    parts = ["\n".join(header) + "\n"]
    if imports:
        parts.append("".join(f'import "{module}"\n' for module in imports))
    for ruleset, group in groups:
        parts.append(f"// ---- {ruleset.name} ({ruleset.get_origin_display()}: {ruleset.path})\n")
        parts.extend(f"{rule.source}\n" for rule in group)
    return ExportFile("yaradude-rules.yar", "\n".join(parts).encode(), YAR_CONTENT_TYPE)


def export_zip(rules: Iterable[Rule]) -> ExportFile:
    """The active rules among `rules` as a .zip with one .yar file per ruleset."""
    buffer = io.BytesIO()
    used: set[str] = set()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for ruleset, group in _grouped(rules):
            name = ruleset_filename(ruleset, keep_directories=True)
            if name in used:
                stem, suffix = posixpath.splitext(name)
                name = f"{stem}-{ruleset.pk}{suffix}"
            used.add(name)
            archive.writestr(name, combine_rules(group))
    return ExportFile("yaradude-rules.zip", buffer.getvalue(), "application/zip")


def ruleset_filename(ruleset: Ruleset, keep_directories: bool = False) -> str:
    """
    A safe file name for a ruleset ending in .yar or .yara. With
    `keep_directories`, rules-directory rulesets keep their relative path.
    """
    path = PurePath(ruleset.path)
    if keep_directories and ruleset.origin == Ruleset.Origin.DIRECTORY and not path.is_absolute():
        parts = [part for part in path.parts if part not in ("", ".", "..")]
    else:
        parts = [path.name]
    name = "/".join(parts) or f"ruleset-{ruleset.pk}"
    if not name.lower().endswith((".yar", ".yara")):
        name += ".yar"
    return name


def _grouped(rules: Iterable[Rule]) -> list[tuple[Ruleset, list[Rule]]]:
    rules = sorted(
        (rule for rule in rules if not rule.is_removed),
        key=lambda r: (r.ruleset.name, r.ruleset_id, r.position, r.pk),
    )
    groups = (list(group) for _, group in groupby(rules, key=lambda r: r.ruleset_id))
    return [(group[0].ruleset, group) for group in groups]
