"""
Import YARA files from a directory or from browser uploads.

See PLAN.md section 5.3 for the rules on unchanged files, local edits,
renamed and removed rules. Each file is read, hashed, parsed and compiled
before its write transaction starts, so the database write lock is held only
for the writes themselves; inside the transaction the ruleset is read again
and the plan recomputed, and the precompiled diagnostics are used only if
they still describe exactly the rules being stored. A file that fails for any
reason is recorded as failed and the run continues.
"""

from __future__ import annotations

import hashlib
import logging
import os
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path, PurePath
from typing import TYPE_CHECKING

from django.conf import settings
from django.core.files import File
from django.db import transaction
from django.utils import timezone

from rules.models import ImportFile, ImportRun, Rule, Ruleset, RuleVersion, Tag
from rules.services import database
from rules.services.compiler import (
    RuleDiagnostics,
    RuleEntry,
    compile_entries,
    compiled_identifiers,
    store_check,
)
from rules.services.parser import ParsedFile, ParsedRule, RuleParseError, parse

if TYPE_CHECKING:
    from accounts.models import User

logger = logging.getLogger(__name__)

RULE_SUFFIXES: tuple[str, ...] = (".yar", ".yara")


def max_file_bytes() -> int:
    """The per-file size limit for rule files (setting YARADUDE_MAX_RULE_FILE_BYTES)."""
    limit: int = settings.YARADUDE_MAX_RULE_FILE_BYTES
    return limit


# The limit as configured at start-up, for forms and templates; services read
# max_file_bytes() so that overriding the setting takes effect.
MAX_FILE_BYTES: int = settings.YARADUDE_MAX_RULE_FILE_BYTES

_COUNTERS = [
    "files_seen",
    "files_changed",
    "files_unchanged",
    "files_failed",
    "rules_created",
    "rules_updated",
    "rules_removed",
    "rules_unchanged",
    "files_skipped",
    "rules_skipped",
]


class ImportFailed(Exception):
    """A file could not be imported; nothing was changed. The message is shown to users."""


@dataclass
class _Counts:
    created: int = 0
    updated: int = 0
    removed: int = 0
    unchanged: int = 0
    skipped: int = 0


def decode(content: bytes) -> str:
    """Decode a rule file: UTF-8 (with or without BOM), else Latin-1."""
    try:
        return content.decode("utf-8-sig")
    except UnicodeDecodeError:
        return content.decode("latin-1")


def _too_large_message(limit: int) -> str:
    return f"File is larger than {limit} bytes."


# --- Selecting files -------------------------------------------------------


@dataclass(frozen=True)
class RuleFile:
    """
    A rule file a directory import reads. `identity` is the ruleset path:
    relative to YARADUDE_RULES_DIR when below it, else absolute. `error` is
    set for a file that is selected but will be recorded as failed (too
    large) rather than read.
    """

    path: Path
    identity: str
    size: int
    mtime_ns: int
    error: str = ""


def _is_rule_name(name: str) -> bool:
    return name.lower().endswith(RULE_SUFFIXES)


def rule_files(root: Path | str) -> list[RuleFile]:
    """
    The rule files below `root` that `import_directory(root)` imports, in
    import order: `*.yar` / `*.yara` (any case), not hidden and not in a
    hidden directory (those are ignored silently). Directory symlinks are
    not descended into; a file symlink is followed only if its target lies
    inside `root`. Files that will not be imported are still listed, with
    `error` set, so the import records them as failed and the Import page
    can show them: symlinks leading outside `root` or nowhere, files over
    the size limit. A missing or unreadable `root` yields no files.
    """
    root = Path(root).resolve()
    rules_dir = Path(settings.YARADUDE_RULES_DIR).resolve()
    limit = max_file_bytes()
    found: list[RuleFile] = []
    for directory, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if not d.startswith("."))
        for name in filenames:
            if name.startswith(".") or not _is_rule_name(name):
                continue
            path = Path(directory) / name
            identity = (
                path.relative_to(rules_dir).as_posix()
                if path.is_relative_to(rules_dir)
                else str(path)
            )
            if path.is_symlink() and not _inside(path, root):
                # Listed, not followed: the target is neither statted nor read.
                try:
                    link = path.lstat()
                except OSError:
                    continue  # vanished
                found.append(RuleFile(path, identity, 0, link.st_mtime_ns, _OUTSIDE_LINK))
                continue
            try:
                stat = path.stat()
            except OSError:
                continue  # vanished or unreadable
            if not path.is_file():
                continue
            error = _too_large_message(limit) if stat.st_size > limit else ""
            found.append(RuleFile(path, identity, stat.st_size, stat.st_mtime_ns, error))
    found.sort(key=lambda f: f.path)
    return found


_OUTSIDE_LINK = (
    "Not imported: a symbolic link that leads outside the rules directory, or to a file "
    "that does not exist."
)


def _inside(path: Path, root: Path) -> bool:
    try:
        return path.resolve(strict=True).is_relative_to(root)
    except OSError:
        return False


def read_rule_file(file: RuleFile, root: Path | str) -> bytes:
    """
    Read a selected rule file, at most the size limit: the target of a
    symlink is checked again at read time, and a file that grew past the
    limit after it was listed fails rather than being read in full.
    """
    root = Path(root).resolve()
    if file.path.is_symlink() and not _inside(file.path, root):
        raise ImportFailed(_OUTSIDE_LINK)
    limit = max_file_bytes()
    with open(file.path, "rb") as handle:
        content = handle.read(limit + 1)
    if len(content) > limit:
        raise ImportFailed(_too_large_message(limit))
    return content


# --- Runs ------------------------------------------------------------------


def import_directory(
    root: Path | str,
    user: User | None = None,
    origin: ImportRun.Origin = ImportRun.Origin.SCAN,
) -> ImportRun:
    """
    Import every rule file `rule_files(root)` selects. Files below
    YARADUDE_RULES_DIR are identified by their path relative to it, other
    files by their absolute path. Files that are absent change nothing.
    """
    root = Path(root).resolve()
    run = ImportRun.objects.create(origin=origin, source=str(root), user=user)
    try:
        for file in rule_files(root):
            if file.error:
                _record_failure(run, file.identity, file.error)
                _save_counters(run)
                continue
            import_file(
                run, Ruleset.Origin.DIRECTORY, file.identity, lambda f=file: read_rule_file(f, root)
            )
    finally:
        _finish(run)
    return run


def import_uploads(files: Iterable[File], user: User | None = None) -> ImportRun:
    """Import uploaded rule files; each is identified by its file name."""
    files = list(files)
    names = ", ".join(PurePath(f.name or "").name for f in files)
    run = ImportRun.objects.create(origin=ImportRun.Origin.UPLOAD, source=names[:1024], user=user)
    limit = max_file_bytes()
    try:
        for upload in files:
            name = PurePath(upload.name or "").name
            if not _is_rule_name(name):
                _record_failure(run, name, "Only .yar and .yara files can be imported.")
            elif upload.size is None or upload.size > limit:
                _record_failure(run, name, _too_large_message(limit))
            else:
                import_file(run, Ruleset.Origin.UPLOAD, name, lambda u=upload: _read_upload(u))
                continue
            _save_counters(run)
    finally:
        _finish(run)
    return run


def _read_upload(upload: File) -> bytes:
    upload.seek(0)
    content: bytes = upload.read()
    return content


def _finish(run: ImportRun) -> None:
    run.finished_at = timezone.now()
    try:
        run.save()
    except Exception:
        logger.exception("Could not finish import run %s", run.pk)
        return
    optimize_database()


def optimize_database() -> None:
    """Let SQLite refresh its planner statistics where they are stale (cheap when not)."""
    database.optimize()


def _save_counters(run: ImportRun) -> None:
    """Persist the counters after each file, so an interrupted run shows its progress."""
    try:
        ImportRun.objects.filter(pk=run.pk).update(
            **{name: getattr(run, name) for name in _COUNTERS}
        )
    except Exception:
        logger.exception("Could not update the counters of import run %s", run.pk)


def _record_failure(run: ImportRun, path: str, message: str) -> ImportFile | None:
    run.files_seen += 1
    run.files_failed += 1
    try:
        return ImportFile.objects.create(
            run=run, path=path, status=ImportFile.Status.FAILED, message=message
        )
    except Exception:
        logger.exception("Could not record the failure of %s in import run %s", path, run.pk)
        return None


def import_file(
    run: ImportRun,
    origin: Ruleset.Origin,
    path: str,
    read: Callable[[], bytes],
) -> ImportFile | None:
    """
    Import one file into `run`: `read` returns its content and may raise.
    Never raises: any failure is recorded as a failed ImportFile whose message
    does not include file content, and unexpected errors are logged with
    their traceback. Returns the ImportFile recorded for a changed or failed
    file, None for an unchanged one.
    """
    try:
        try:
            outcome = _import_content(run, origin, path, read())
        except ImportFailed as error:
            return _record_failure(run, path, str(error))
        except OSError as error:
            reason = error.strerror or "I/O error"
            return _record_failure(run, path, f"The file could not be read ({reason}).")
        except Exception as error:
            logger.exception("Unexpected error importing %s in import run %s", path, run.pk)
            return _record_failure(
                run,
                path,
                f"Unexpected error ({type(error).__name__}); the details are in the server log.",
            )
        run.files_seen += 1
        return outcome
    finally:
        _save_counters(run)


# --- One file --------------------------------------------------------------


@dataclass
class _Step:
    """What happens to one rule of the file."""

    parsed: ParsedRule
    rule: Rule | None  # the existing rule it matched, None to create one
    # "create", "update", "keep" (disk unchanged), "catch_up" (disk == local),
    # "skip" (the rule is deleted in yaradude and stays as it is)
    action: str


@dataclass
class _Plan:
    steps: list[_Step]
    # Rules of the ruleset that are not in the file, in order, and whether
    # this import flags them removed.
    leftovers: list[tuple[Rule, bool]] = field(default_factory=list)

    def entries(self) -> list[RuleEntry]:
        """The ruleset's active rules after the import, in compile order."""
        entries: list[RuleEntry] = []
        for step in self.steps:
            if step.action == "skip":
                continue
            if step.action == "keep" and step.rule is not None:
                entries.append(RuleEntry.of(step.rule))
            else:
                parsed = step.parsed
                entries.append(RuleEntry(parsed.name, parsed.imports, parsed.source))
        entries.extend(
            RuleEntry.of(rule)
            for rule, remove in self.leftovers
            if not remove and not rule.is_removed and not rule.is_deleted
        )
        return entries


def _plan(existing: list[Rule], parsed_rules: list[ParsedRule]) -> _Plan:
    """
    Match the file's rules to the ruleset's rules (removed and deleted ones
    included) and decide what happens to each; pure, no database access.
    Deleted rules are matched like any other but left alone ("skip"), and
    keep their names.

    Matching (PLAN.md section 5.3): first by the name the rule had when it was
    last imported (`imported_name`, so a rule renamed in the editor is still
    the same rule), then by the hash of its content as last imported (rules
    renamed before `imported_name` existed), then by current name for rules
    that never came from a file. Raises ImportFailed when the result would
    give two rules one name.
    """
    unmatched = {rule.pk: rule for rule in existing}
    by_imported_name = {rule.imported_name: rule for rule in existing if rule.imported_name}
    by_imported_hash = {rule.imported_sha256: rule for rule in existing if rule.imported_sha256}
    by_name = {rule.name: rule for rule in existing if not rule.imported_name}
    matches: dict[int, Rule] = {}  # index in parsed_rules -> rule
    for index_of_lookup in (
        lambda p: by_imported_name.get(p.name),
        lambda p: by_imported_hash.get(p.sha256),
        lambda p: by_name.get(p.name),
    ):
        for index, parsed in enumerate(parsed_rules):
            if index in matches:
                continue
            rule = index_of_lookup(parsed)
            if rule is not None and rule.pk in unmatched:
                matches[index] = unmatched.pop(rule.pk)

    steps: list[_Step] = []
    for index, parsed in enumerate(parsed_rules):
        rule = matches.get(index)
        if rule is None:
            action = "create"
        elif rule.is_deleted:
            action = "skip"
        elif parsed.sha256 == rule.imported_sha256:
            # The disk version has not changed since the last import, so a
            # local edit (if any, including a rename) is kept.
            action = "keep"
        elif parsed.sha256 == rule.sha256:
            # Disk now has what was already stored, e.g. the same edit made
            # locally and on disk.
            action = "catch_up"
        else:
            action = "update"
        steps.append(_Step(parsed, rule, action))

    # Rules that came from disk and are gone from the file are flagged;
    # rules created locally in this ruleset are kept as they are. Rules after
    # the file's rules keep their relative order.
    leftovers = [
        (rule, bool(rule.imported_sha256) and not rule.is_removed and not rule.is_deleted)
        for rule in sorted(unmatched.values(), key=lambda r: (r.position, r.pk))
    ]
    plan = _Plan(steps, leftovers)

    final_names = [
        step.rule.name
        if step.action in ("keep", "skip") and step.rule is not None
        else step.parsed.name
        for step in steps
    ] + [rule.name for rule, _ in leftovers]
    clashes = sorted(name for name, n in Counter(final_names).items() if n > 1)
    if clashes:
        raise ImportFailed(
            f'Importing this file would give two rules of the ruleset the name "{clashes[0]}": '
            "a rule renamed or created locally has a name the file also uses. Rename it in "
            "the editor and import again."
        )
    return plan


@dataclass(frozen=True)
class _Prepared:
    """Everything about a file that can be worked out before taking the write lock."""

    text: str
    sha256: str
    parsed: ParsedFile
    entries: list[RuleEntry]
    results: list[RuleDiagnostics]


def _existing_ruleset(origin: Ruleset.Origin, path: str) -> Ruleset | None:
    """The ruleset with this identity, deleted or not (deletion is sticky across imports)."""
    return Ruleset.all_objects.defer("original_content").filter(origin=origin, path=path).first()


def _ruleset_rules(ruleset: Ruleset) -> list[Rule]:
    """All rules of a ruleset, deleted ones included."""
    return list(Rule.all_objects.filter(ruleset=ruleset))


def _skip_deleted_ruleset(
    run: ImportRun, ruleset: Ruleset, path: str, sha256: str
) -> ImportFile | None:
    """A file whose ruleset is deleted: counted as skipped and left alone."""
    run.files_skipped += 1
    if ruleset.sha256 == sha256:
        return None
    return ImportFile.objects.create(
        run=run,
        path=path,
        status=ImportFile.Status.SKIPPED,
        ruleset=ruleset,
        message="The ruleset is deleted in yaradude; restore it to import this file again.",
    )


def _import_content(
    run: ImportRun, origin: Ruleset.Origin, path: str, content: bytes
) -> ImportFile | None:
    text = decode(content)
    sha256 = hashlib.sha256(text.encode()).hexdigest()
    ruleset = _existing_ruleset(origin, path)
    if ruleset is not None and ruleset.is_deleted:
        return _skip_deleted_ruleset(run, ruleset, path, sha256)
    if ruleset is not None and ruleset.sha256 == sha256:
        _unchanged(run, ruleset)
        return None

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
    existing = _ruleset_rules(ruleset) if ruleset is not None else []
    entries = _plan(existing, parsed.rules).entries()
    prepared = _Prepared(text, sha256, parsed, entries, compile_entries(entries))

    with transaction.atomic():
        return _write(run, origin, path, prepared)


def _unchanged(run: ImportRun, ruleset: Ruleset) -> None:
    Ruleset.objects.filter(pk=ruleset.pk).update(last_imported_at=timezone.now())
    run.files_unchanged += 1
    run.rules_unchanged += ruleset.rules.active().count()


def _write(
    run: ImportRun, origin: Ruleset.Origin, path: str, prepared: _Prepared
) -> ImportFile | None:
    """The write phase, inside the transaction: re-read, re-plan, write."""
    now = timezone.now()
    ruleset = _existing_ruleset(origin, path)
    if ruleset is not None and ruleset.is_deleted:
        # Deleted meanwhile.
        return _skip_deleted_ruleset(run, ruleset, path, prepared.sha256)
    if ruleset is not None and ruleset.sha256 == prepared.sha256:
        # Imported meanwhile by another run.
        _unchanged(run, ruleset)
        return None
    created = ruleset is None
    if ruleset is None:
        ruleset = Ruleset.objects.create(name=path, origin=origin, path=path, created_at=now)
    plan = _plan(_ruleset_rules(ruleset), prepared.parsed.rules)
    version_origin = (
        RuleVersion.Origin.UPLOAD if origin == Ruleset.Origin.UPLOAD else RuleVersion.Origin.IMPORT
    )
    counts, rules, changed = _apply(run, ruleset, plan, version_origin, now)
    Tag.objects.unused().delete()

    ruleset.original_content = prepared.text
    ruleset.sha256 = prepared.sha256
    ruleset.last_imported_at = now
    ruleset.updated_at = now
    ruleset.save(update_fields=["original_content", "sha256", "last_imported_at", "updated_at"])
    entries = plan.entries()
    results = prepared.results if entries == prepared.entries else compile_entries(entries)
    store_check(ruleset, rules, results, changed=changed)

    message = ""
    if prepared.parsed.includes:
        message = "include statements are not supported and were ignored: " + ", ".join(
            prepared.parsed.includes
        )
    file = ImportFile.objects.create(
        run=run,
        path=path,
        status=ImportFile.Status.CREATED if created else ImportFile.Status.UPDATED,
        ruleset=ruleset,
        rules_created=counts.created,
        rules_updated=counts.updated,
        rules_removed=counts.removed,
        rules_unchanged=counts.unchanged,
        rules_skipped=counts.skipped,
        message=message,
    )
    run.files_changed += 1
    run.rules_created += counts.created
    run.rules_updated += counts.updated
    run.rules_removed += counts.removed
    run.rules_unchanged += counts.unchanged
    run.rules_skipped += counts.skipped
    return file


def _apply(
    run: ImportRun,
    ruleset: Ruleset,
    plan: _Plan,
    version_origin: RuleVersion.Origin,
    now: datetime,
) -> tuple[_Counts, list[Rule], bool]:
    """
    Write a plan. Returns the counts, the ruleset's rules that are not
    deleted in compile order, and whether anything the compiled rule set
    depends on changed (content, active or removed, order of active rules).
    Deleted rules are not written.
    """
    counts = _Counts()
    rules: list[Rule] = []
    moved = False

    # A rule taking back its imported name may need a name another rule of
    # this plan is giving up; park renamed rules on unique names first so the
    # (ruleset, name) constraint holds after every statement.
    renamed = [
        step.rule
        for step in plan.steps
        if step.rule is not None and step.action == "update" and step.rule.name != step.parsed.name
    ]
    for rule in renamed:
        Rule.objects.filter(pk=rule.pk).update(name=f"~renaming~{rule.pk}")

    for position, step in enumerate(plan.steps):
        parsed = step.parsed
        rule = step.rule
        if step.action == "skip":
            counts.skipped += 1
            continue
        if rule is None:
            rule = Rule(ruleset=ruleset, position=position, created_at=now, updated_at=now)
            rule.apply_parsed(parsed)
            rule.imported_sha256 = parsed.sha256
            rule.imported_name = parsed.name
            rule.save()
            rule.set_tags(parsed.tags)
            rule.record_version(version_origin, user=run.user, import_run=run)
            counts.created += 1
            rules.append(rule)
            continue

        restored = rule.is_removed
        moved |= rule.position != position
        rule.position = position
        rule.removed_at = None
        rule.imported_name = parsed.name
        if step.action == "keep":
            rule.save(update_fields=["position", "removed_at", "imported_name"])
        elif step.action == "catch_up":
            rule.imported_sha256 = parsed.sha256
            rule.save(update_fields=["position", "removed_at", "imported_name", "imported_sha256"])
        else:
            rule.apply_parsed(parsed)
            rule.imported_sha256 = parsed.sha256
            rule.version += 1
            rule.updated_at = now
            rule.save()
            rule.set_tags(parsed.tags)
            rule.record_version(version_origin, user=run.user, import_run=run)
            counts.updated += 1
            rules.append(rule)
            continue
        if restored:
            counts.updated += 1
        else:
            counts.unchanged += 1
        rules.append(rule)

    for offset, (rule, remove) in enumerate(plan.leftovers):
        if rule.is_deleted:
            continue
        if not remove and not rule.is_removed:
            moved |= rule.position != len(plan.steps) + offset
        rule.position = len(plan.steps) + offset
        fields = ["position"]
        if remove:
            rule.removed_at = now
            fields.append("removed_at")
            counts.removed += 1
        rule.save(update_fields=fields)
        rules.append(rule)
    changed = moved or bool(counts.created or counts.updated or counts.removed)
    return counts, rules, changed
