"""
Import YARA files from a directory or from browser uploads.

Each file is imported in its own transaction; see PLAN.md section 5.3 for
the rules on unchanged files, local edits and removed rules.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePath
from typing import TYPE_CHECKING

from django.conf import settings
from django.core.files import File
from django.db import transaction
from django.utils import timezone

from rules.models import ImportFile, ImportRun, Rule, Ruleset, RuleVersion, Tag
from rules.services.compiler import check_ruleset, compiled_identifiers
from rules.services.parser import ParsedRule, RuleParseError, parse

if TYPE_CHECKING:
    from accounts.models import User

RULE_SUFFIXES: tuple[str, ...] = (".yar", ".yara")
MAX_FILE_BYTES = 10 * 1024 * 1024


class ImportFailed(Exception):
    """A file could not be imported; nothing was changed."""


@dataclass
class _Counts:
    created: int = 0
    updated: int = 0
    removed: int = 0
    unchanged: int = 0


def decode(content: bytes) -> str:
    """Decode a rule file: UTF-8 (with or without BOM), else Latin-1."""
    try:
        return content.decode("utf-8-sig")
    except UnicodeDecodeError:
        return content.decode("latin-1")


def import_directory(
    root: Path | str,
    user: User | None = None,
    origin: ImportRun.Origin = ImportRun.Origin.SCAN,
) -> ImportRun:
    """
    Import every *.yar / *.yara file below `root`, skipping hidden files and
    directories. Files below YARADUDE_RULES_DIR are identified by their path
    relative to it, other files by their absolute path. Files that are absent
    change nothing.
    """
    root = Path(root).resolve()
    rules_dir = Path(settings.YARADUDE_RULES_DIR).resolve()
    run = ImportRun.objects.create(origin=origin, source=str(root), user=user)
    paths = sorted(
        path
        for path in root.rglob("*")
        if path.suffix.lower() in RULE_SUFFIXES
        and path.is_file()
        and not any(part.startswith(".") for part in path.relative_to(root).parts)
    )
    for path in paths:
        identity = (
            path.relative_to(rules_dir).as_posix() if path.is_relative_to(rules_dir) else str(path)
        )
        if path.stat().st_size > MAX_FILE_BYTES:
            _record_failure(run, identity, f"File is larger than {MAX_FILE_BYTES} bytes.")
            continue
        _import_file(run, Ruleset.Origin.DIRECTORY, identity, path.read_bytes())
    return _finish(run)


def import_uploads(files: Iterable[File], user: User | None = None) -> ImportRun:
    """Import uploaded rule files; each is identified by its file name."""
    files = list(files)
    names = ", ".join(PurePath(f.name).name for f in files)
    run = ImportRun.objects.create(origin=ImportRun.Origin.UPLOAD, source=names[:1024], user=user)
    for upload in files:
        name = PurePath(upload.name).name
        if not name.lower().endswith(RULE_SUFFIXES):
            _record_failure(run, name, "Only .yar and .yara files can be imported.")
        elif upload.size > MAX_FILE_BYTES:
            _record_failure(run, name, f"File is larger than {MAX_FILE_BYTES} bytes.")
        else:
            upload.seek(0)
            _import_file(run, Ruleset.Origin.UPLOAD, name, upload.read())
    return _finish(run)


def _finish(run: ImportRun) -> ImportRun:
    run.finished_at = timezone.now()
    run.save()
    return run


def _record_failure(run: ImportRun, path: str, message: str) -> None:
    run.files_seen += 1
    run.files_failed += 1
    ImportFile.objects.create(run=run, path=path, status=ImportFile.Status.FAILED, message=message)


def _import_file(run: ImportRun, origin: Ruleset.Origin, path: str, content: bytes) -> None:
    try:
        with transaction.atomic():
            _import_text(run, origin, path, decode(content))
    except ImportFailed as error:
        _record_failure(run, path, str(error))
    else:
        run.files_seen += 1


def _import_text(run: ImportRun, origin: Ruleset.Origin, path: str, text: str) -> None:
    now = timezone.now()
    sha256 = hashlib.sha256(text.encode()).hexdigest()
    ruleset = Ruleset.objects.filter(origin=origin, path=path).first()
    if ruleset is not None and ruleset.sha256 == sha256:
        ruleset.last_imported_at = now
        ruleset.save(update_fields=["last_imported_at"])
        run.files_unchanged += 1
        run.rules_unchanged += ruleset.rules.active().count()
        return

    try:
        parsed = parse(text)
    except RuleParseError as error:
        raise ImportFailed(f"Parse error: {error}") from None
    identifiers = compiled_identifiers(text)
    if identifiers is not None and identifiers != [rule.name for rule in parsed.rules]:
        raise ImportFailed(
            "The rules found in this file do not match what YARA-X compiles; "
            "the file was not imported."
        )

    created = ruleset is None
    if created:
        ruleset = Ruleset.objects.create(name=path, origin=origin, path=path, created_at=now)
    version_origin = (
        RuleVersion.Origin.UPLOAD if origin == Ruleset.Origin.UPLOAD else RuleVersion.Origin.IMPORT
    )
    counts = _sync_rules(run, ruleset, parsed.rules, version_origin, now)
    Tag.objects.unused().delete()

    ruleset.original_content = text
    ruleset.sha256 = sha256
    ruleset.last_imported_at = now
    ruleset.updated_at = now
    ruleset.save()
    check_ruleset(ruleset)

    message = ""
    if parsed.includes:
        message = "include statements are not supported and were ignored: " + ", ".join(
            parsed.includes
        )
    ImportFile.objects.create(
        run=run,
        path=path,
        status=ImportFile.Status.CREATED if created else ImportFile.Status.UPDATED,
        ruleset=ruleset,
        rules_created=counts.created,
        rules_updated=counts.updated,
        rules_removed=counts.removed,
        rules_unchanged=counts.unchanged,
        message=message,
    )
    run.files_changed += 1
    run.rules_created += counts.created
    run.rules_updated += counts.updated
    run.rules_removed += counts.removed
    run.rules_unchanged += counts.unchanged


def _sync_rules(
    run: ImportRun,
    ruleset: Ruleset,
    parsed_rules: list[ParsedRule],
    version_origin: RuleVersion.Origin,
    now: datetime,
) -> _Counts:
    counts = _Counts()
    existing = {rule.name: rule for rule in ruleset.rules.all()}
    for position, parsed in enumerate(parsed_rules):
        rule = existing.pop(parsed.name, None)
        if rule is None:
            rule = Rule(ruleset=ruleset, position=position, created_at=now, updated_at=now)
            rule.apply_parsed(parsed)
            rule.imported_sha256 = parsed.sha256
            rule.save()
            rule.set_tags(parsed.tags)
            rule.record_version(version_origin, import_run=run)
            counts.created += 1
            continue

        restored = rule.is_removed
        rule.position = position
        rule.removed_at = None
        if parsed.sha256 == rule.imported_sha256:
            # The disk version has not changed since the last import, so a
            # local edit (if any) is kept.
            rule.save(update_fields=["position", "removed_at"])
        elif parsed.sha256 == rule.sha256:
            # Disk now has what was already stored, e.g. the same edit made
            # locally and on disk.
            rule.imported_sha256 = parsed.sha256
            rule.save(update_fields=["position", "removed_at", "imported_sha256"])
        else:
            rule.apply_parsed(parsed)
            rule.imported_sha256 = parsed.sha256
            rule.version += 1
            rule.updated_at = now
            rule.save()
            rule.set_tags(parsed.tags)
            rule.record_version(version_origin, import_run=run)
            counts.updated += 1
            continue
        if restored:
            counts.updated += 1
        else:
            counts.unchanged += 1

    # Rules that came from disk and are gone from the file are flagged;
    # rules created locally in this ruleset are kept as they are. Rules after
    # the file's rules keep their relative order.
    for offset, rule in enumerate(sorted(existing.values(), key=lambda r: (r.position, r.pk))):
        rule.position = len(parsed_rules) + offset
        fields = ["position"]
        if rule.imported_sha256 and not rule.is_removed:
            rule.removed_at = now
            fields.append("removed_at")
            counts.removed += 1
        rule.save(update_fields=fields)
    return counts
