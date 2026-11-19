"""
Scan samples against one compiled set of all active rules (PLAN.md 12.4).

A scan never compiles. One compiled set of every active, compiling rule (one
YARA-X namespace per ruleset) is kept as a file beside the database and
rebuilt by a builder process when the rules revision moves
(`rules.services.revision`). Every process that scans loads the newest
complete file once and keeps it in memory; a scan limited by ruleset, path
or tag scans with the full set and filters the matches.

File layout (`<YARADUDE_SCAN_DIR>/compiled/rules.ydset`): an 8-byte magic,
then two length-prefixed JSON blocks (a small `info` block and the `index`
mapping compiled rules back to `Rule` rows), then `yara_x.Rules` as
serialised by the engine. The file is written to a temporary name, synced
and renamed over the old one, so a crashed build leaves the previous set in
place; an exclusive `flock` on `build.lock` keeps two builds from running at
once. Building reads the rules with one SELECT outside any transaction, so it
never holds the SQLite write lock.

Samples may be malware: this module keeps them in memory, never writes them
anywhere and never logs their contents.
"""

from __future__ import annotations

import dataclasses
import fcntl
import hashlib
import importlib.metadata
import json
import logging
import os
import struct
import tempfile
import threading
import time
from collections.abc import Generator, Iterable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from functools import cached_property
from pathlib import Path, PurePath
from typing import Any, NamedTuple, TypedDict, overload

import yara_x
from django.conf import settings
from django.core.files import File
from django.template.defaultfilters import filesizeformat
from django.utils import timezone

from rules.models import Rule, Ruleset
from rules.services import revision
from rules.services.compiler import new_compiler
from rules.services.parser import rule_text

logger = logging.getLogger(__name__)

MAX_INSTANCES = 5  # string instances shown per pattern
MAX_MATCHES_PER_PATTERN = 1000
PREVIEW_BYTES = 32

# Bump when the file layout or the index changes; older files are rebuilt.
FORMAT_VERSION = 1
ENGINE_VERSION = importlib.metadata.version("yara-x")
_MAGIC = b"YDRSET\x00\x01"
_LENGTH = struct.Struct("<Q")
SET_FILENAME = "rules.ydset"
LOCK_FILENAME = "build.lock"


class ScanError(Exception):
    """The sample could not be scanned (too large, timeout, engine error)."""


class ScanTimeout(ScanError):
    """The scan exceeded its time limit."""


# ---------------------------------------------------------------------------
# Results


@dataclass(frozen=True)
class PatternInstance:
    offset: int
    length: int
    hex: str  # preview of the matched bytes, e.g. "4d 5a 90"
    ascii: str  # the same bytes with non-printable characters as "."
    truncated: bool  # the match is longer than the preview


@dataclass(frozen=True)
class PatternMatch:
    identifier: str
    count: int  # matches found, capped at MAX_MATCHES_PER_PATTERN
    instances: list[PatternInstance]  # the first MAX_INSTANCES


@dataclass(frozen=True)
class RuleMatch:
    rule: Rule  # loaded without `source` (deferred) and with its ruleset
    tags: list[str]
    patterns: list[PatternMatch]

    @property
    def ruleset(self) -> Ruleset:
        return self.rule.ruleset


class RulesetList(Sequence[Ruleset]):
    """
    The rulesets that took part in a scan, loaded on first iteration (in
    name order, without `original_content`). `len()` needs no query, so a
    page can say "N rulesets" without loading thousands of rows.
    """

    def __init__(self, ids: Iterable[int]) -> None:
        self.ids = sorted(set(ids))

    @cached_property
    def _items(self) -> list[Ruleset]:
        if not self.ids:
            return []
        rulesets = Ruleset.objects.filter(pk__in=self.ids).defer("original_content")
        return sorted(rulesets, key=lambda r: (r.name, r.pk))

    def __len__(self) -> int:
        return len(self.ids)

    @overload
    def __getitem__(self, index: int) -> Ruleset: ...
    @overload
    def __getitem__(self, index: slice) -> Sequence[Ruleset]: ...
    def __getitem__(self, index: int | slice) -> Ruleset | Sequence[Ruleset]:
        return self._items[index]

    def __iter__(self) -> Iterator[Ruleset]:
        return iter(self._items)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Sequence):
            return list(self) == list(other)
        return NotImplemented

    def __repr__(self) -> str:
        return f"RulesetList({self.ids!r})"


@dataclass(frozen=True)
class ScanResult:
    sample_name: str
    sample_size: int
    sample_sha256: str
    matches: list[RuleMatch]
    rulesets: Sequence[Ruleset]  # rulesets that took part (a RulesetList)
    rules_scanned: int  # non-private rules that took part
    left_out: list[Rule]  # rules not in the compiled set because they do not compile
    elapsed: float  # seconds for the whole call (server time)
    revision: int = 0  # rules revision the compiled set reflects
    built_at: datetime | None = None  # when that set was built
    pending: bool = False  # rules changed since; a newer set is not ready yet
    unmapped: list[str] = field(default_factory=list)  # "namespace:identifier" skipped
    scan_seconds: float = 0.0  # time inside the engine


def _preview(data: bytes, offset: int, length: int) -> PatternInstance:
    chunk = data[offset : offset + min(length, PREVIEW_BYTES)]
    return PatternInstance(
        offset=offset,
        length=length,
        hex=chunk.hex(" "),
        ascii="".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk),
        truncated=length > PREVIEW_BYTES,
    )


# ---------------------------------------------------------------------------
# Limits


@dataclass(frozen=True)
class ScanLimit:
    """
    Which matches a scan reports: rules of the given rulesets (None = all)
    carrying `tag` (blank = any). The scan itself always uses the full set;
    rulesets are separate namespaces, so filtering the matches gives exactly
    what compiling only the selected rulesets would.
    """

    ruleset_ids: frozenset[int] | None = None
    tag: str = ""

    def allows(self, ruleset_id: int, tags: Sequence[str]) -> bool:
        if self.ruleset_ids is not None and ruleset_id not in self.ruleset_ids:
            return False
        return not self.tag or self.tag in tags

    @property
    def unlimited(self) -> bool:
        return self.ruleset_ids is None and not self.tag


def ruleset_ids_for_path(path: str) -> frozenset[int]:
    """
    Rulesets selected by a path filter, as on the rule list: a value ending in
    "/" is a directory prefix (e.g. "signature-base/"), anything else matches
    anywhere in the path.
    """
    rulesets = (
        Ruleset.objects.filter(path__startswith=path)
        if path.endswith("/")
        else Ruleset.objects.filter(path__icontains=path)
    )
    return frozenset(rulesets.values_list("pk", flat=True))


def limit_for(
    path: str = "", tag: str = "", rulesets: Iterable[Ruleset | int] | None = None
) -> ScanLimit:
    """A ScanLimit from the user-facing options (all optional, combined with AND)."""
    ids: frozenset[int] | None = None
    if rulesets is not None:
        ids = frozenset(r if isinstance(r, int) else r.pk for r in rulesets)
    if path:
        by_path = ruleset_ids_for_path(path)
        ids = by_path if ids is None else ids & by_path
    return ScanLimit(ruleset_ids=ids, tag=tag.strip())


# ---------------------------------------------------------------------------
# The compiled set


class _Entry(NamedTuple):
    rule_id: int
    ruleset_id: int
    private: bool
    tags: tuple[str, ...]


class _Info(TypedDict):
    key: str
    format: int
    engine: str
    settings: str
    revision: int
    revision_changed_at: str | None
    built_at: str
    build_seconds: float
    rules: int  # non-private rules in the set
    rulesets: int
    left_out: int
    slow: int
    unmapped: int


class _Index(TypedDict):
    # [rule id, ruleset id, identifier, private, tags]
    entries: list[tuple[int, int, str, bool, list[str]]]
    left_out: list[tuple[int, int]]  # [rule id, ruleset id]
    # [rule id, ruleset id, rule name, warning code, warning title]
    slow: list[tuple[int, int, str, str, str]]


@dataclass(frozen=True)
class SlowRule:
    """A rule YARA-X warned may slow every scan down (slow pattern or loop)."""

    rule_id: int
    ruleset_id: int
    name: str
    code: str  # e.g. "slow_pattern", "potentially_slow_loop"
    message: str


@dataclass(frozen=True)
class CompiledSetInfo:
    """What a compiled set file contains, without the rules themselves."""

    revision: int
    revision_changed_at: datetime | None
    built_at: datetime
    build_seconds: float
    engine: str
    rules: int  # non-private rules in the set
    rulesets: int
    left_out: int  # active rules not in the set because they do not compile
    slow: int  # rules with slow-pattern / slow-loop warnings

    @classmethod
    def of(cls, info: _Info) -> CompiledSetInfo:
        changed = info["revision_changed_at"]
        return cls(
            revision=info["revision"],
            revision_changed_at=datetime.fromisoformat(changed) if changed else None,
            built_at=datetime.fromisoformat(info["built_at"]),
            build_seconds=info["build_seconds"],
            engine=info["engine"],
            rules=info["rules"],
            rulesets=info["rulesets"],
            left_out=info["left_out"],
            slow=info["slow"],
        )


@dataclass(frozen=True)
class CompiledSetStatus:
    """compiled_status(): the set scans use now, and whether a newer one is due."""

    available: bool  # a compiled set file exists
    set: CompiledSetInfo | None
    current_revision: int  # the rules revision in the database
    current_changed_at: datetime | None
    pending: bool  # rules changed since the set was built (or there is no set)
    building: bool  # a build is running right now

    @property
    def revision(self) -> int | None:
        return self.set.revision if self.set else None

    @property
    def built_at(self) -> datetime | None:
        return self.set.built_at if self.set else None


@dataclass(frozen=True)
class CompiledSet:
    """A loaded compiled set: engine rules plus the index back to `Rule` rows."""

    key: str
    info: CompiledSetInfo
    rules: yara_x.Rules
    entries: dict[tuple[str, str], _Entry]  # (namespace, identifier) -> entry
    counts: dict[int, int]  # ruleset id -> non-private rules in the set
    left_out: list[tuple[int, int]]
    slow: list[SlowRule]
    path: Path | None = None
    stat: tuple[int, int, int] | None = None  # (inode, mtime_ns, size) of the file read

    def rules_scanned(self, limit: ScanLimit) -> tuple[int, set[int]]:
        """How many non-private rules a limited scan uses, and from which rulesets."""
        if not limit.tag:
            ids = set(self.counts)
            if limit.ruleset_ids is not None:
                ids &= limit.ruleset_ids
            return sum(self.counts[i] for i in ids), ids
        used: set[int] = set()
        count = 0
        for entry in self.entries.values():
            if limit.allows(entry.ruleset_id, entry.tags):
                used.add(entry.ruleset_id)
                count += not entry.private
        return count, used


def scan_dir() -> Path:
    path: Path = Path(settings.YARADUDE_SCAN_DIR)
    return path


def compiled_dir() -> Path:
    return scan_dir() / "compiled"


def compiled_path() -> Path:
    return compiled_dir() / SET_FILENAME


def _settings_digest() -> str:
    relaxed: bool = settings.YARADUDE_RELAXED_RE_SYNTAX
    globals_: dict[str, str] = settings.YARADUDE_GLOBALS
    text = json.dumps({"relaxed": relaxed, "globals": globals_}, sort_keys=True)
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def _db_key(rev: revision.Revision) -> str:
    """The part of the set key that comes from the database: the rules revision."""
    changed = rev.changed_at.isoformat() if rev.changed_at else "-"
    return f"{rev.number}@{changed}"


def set_key(rev: revision.Revision) -> str:
    """Everything a compiled set depends on; a file with another key is stale."""
    return f"{FORMAT_VERSION}|{ENGINE_VERSION}|{_settings_digest()}|{_db_key(rev)}"


def _compatible(key: str) -> bool:
    """Same format, engine and compile settings (the rules may be older)."""
    return key.split("|")[:3] == set_key(revision.Revision(0, None)).split("|")[:3]


def _warnings(compiler: yara_x.Compiler) -> list[dict[str, Any]]:
    """`compiler.warnings()`, which the yara_x stub types as Any."""
    warnings: list[dict[str, Any]] = compiler.warnings()
    return warnings


def _compile(rev: revision.Revision) -> tuple[_Info, _Index, yara_x.Rules]:
    """
    Compile all active rules, one namespace per ruleset, leaving out rules
    that do not compile. One SELECT, outside any transaction: SQLite gives a
    single statement a consistent snapshot, and the revision was read before
    it, so the set is never labelled newer than its content.
    """
    started = time.monotonic()
    rows = (
        Rule.objects.active()
        .order_by("ruleset_id", "position", "pk")
        .values_list("pk", "ruleset_id", "name", "imports", "source", "is_private", "compile_error")
    )
    compiler = new_compiler()
    left_out: list[tuple[int, int]] = []
    added: dict[tuple[str, str], tuple[int, int, bool]] = {}
    names: dict[int, tuple[int, str]] = {}
    namespace: str | None = None
    for pk, ruleset_id, name, imports, source, is_private, compile_error in rows.iterator(
        chunk_size=2000
    ):
        if compile_error:
            left_out.append((pk, ruleset_id))
            continue
        if namespace != str(ruleset_id):
            namespace = str(ruleset_id)
            compiler.new_namespace(namespace)
        try:
            compiler.add_source(rule_text(imports, source), origin=str(pk))
        except yara_x.CompileError:
            # The stored status is stale, or the rule depends on one that
            # does not compile.
            left_out.append((pk, ruleset_id))
            continue
        added[namespace, name] = (pk, ruleset_id, is_private)
        names[pk] = (ruleset_id, name)

    slow: list[tuple[int, int, str, str, str]] = []
    for warning in _warnings(compiler):
        code = str(warning.get("code", ""))
        if "slow" not in code:
            continue
        origins = {label.get("code_origin") for label in warning.get("labels", [])}
        for origin in sorted(o for o in origins if o and o.isdigit()):
            if (owner := names.get(int(origin))) is not None:
                slow.append((int(origin), owner[0], owner[1], code, str(warning.get("title", ""))))

    rules = compiler.build()
    entries: list[tuple[int, int, str, bool, list[str]]] = []
    unmapped = 0
    for compiled in rules:
        match = added.get((compiled.namespace, compiled.identifier))
        if match is None:
            # The identifier in the source differs from the stored name
            # (data changed behind the services' back). Matches of this rule
            # are reported as unmapped.
            unmapped += 1
            continue
        pk, ruleset_id, is_private = match
        entries.append((pk, ruleset_id, compiled.identifier, is_private, list(compiled.tags)))

    info: _Info = {
        "key": set_key(rev),
        "format": FORMAT_VERSION,
        "engine": ENGINE_VERSION,
        "settings": _settings_digest(),
        "revision": rev.number,
        "revision_changed_at": rev.changed_at.isoformat() if rev.changed_at else None,
        "built_at": timezone.now().isoformat(),
        "build_seconds": round(time.monotonic() - started, 3),
        "rules": sum(1 for e in entries if not e[3]),
        "rulesets": len({e[1] for e in entries}),
        "left_out": len(left_out),
        "slow": len({s[0] for s in slow}),
        "unmapped": unmapped,
    }
    return info, {"entries": entries, "left_out": left_out, "slow": slow}, rules


def _make_set(
    info: _Info,
    index: _Index,
    rules: yara_x.Rules,
    path: Path | None = None,
    stat: tuple[int, int, int] | None = None,
) -> CompiledSet:
    entries: dict[tuple[str, str], _Entry] = {}
    counts: dict[int, int] = {}
    for rule_id, ruleset_id, identifier, private, tags in index["entries"]:
        entries[str(ruleset_id), identifier] = _Entry(rule_id, ruleset_id, private, tuple(tags))
        counts[ruleset_id] = counts.get(ruleset_id, 0) + (not private)
    return CompiledSet(
        key=info["key"],
        info=CompiledSetInfo.of(info),
        rules=rules,
        entries=entries,
        counts=counts,
        left_out=[(pk, rs) for pk, rs in index["left_out"]],
        slow=[SlowRule(*row) for row in index["slow"]],
        path=path,
        stat=stat,
    )


def _stat(path: Path) -> tuple[int, int, int] | None:
    try:
        st = path.stat()
    except FileNotFoundError:
        return None
    return st.st_ino, st.st_mtime_ns, st.st_size


def _read_block(f: Any) -> Any:
    (length,) = _LENGTH.unpack(f.read(_LENGTH.size))
    return json.loads(f.read(length))


def read_info(path: Path | None = None) -> _Info | None:
    """The small info block of a compiled set file; None if missing or unreadable."""
    path = path or compiled_path()
    try:
        with path.open("rb") as f:
            if f.read(len(_MAGIC)) != _MAGIC:
                return None
            info: _Info = _read_block(f)
            return info
    except FileNotFoundError:
        return None
    except (OSError, ValueError, struct.error):
        logger.warning("Unreadable compiled rule set %s", path)
        return None


def _read_set(path: Path, reuse: CompiledSet | None) -> CompiledSet | None:
    """Load a compiled set file; None when it is missing, unreadable or incompatible."""
    stat = _stat(path)
    try:
        with path.open("rb") as f:
            if f.read(len(_MAGIC)) != _MAGIC:
                return None
            info: _Info = _read_block(f)
            if reuse is not None and reuse.key == info["key"]:
                return dataclasses.replace(reuse, path=path, stat=stat)
            if not _compatible(info["key"]):
                return None
            index: _Index = _read_block(f)
            started = time.monotonic()
            rules = yara_x.Rules.deserialize_from(f)
    except FileNotFoundError:
        return None
    except (OSError, ValueError, struct.error, yara_x.ScanError):
        logger.exception("Unreadable compiled rule set %s", path)
        return None
    logger.info(
        "Loaded compiled rule set revision %s (%s rules) in %.2f s",
        info["revision"],
        info["rules"],
        time.monotonic() - started,
    )
    return _make_set(info, index, rules, path, stat)


def _write_set(path: Path, info: _Info, index: _Index, rules: yara_x.Rules) -> None:
    """Write atomically: temporary file, fsync, rename over the old file, fsync dir."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=".rules-", suffix=".tmp")
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(_MAGIC)
            for block in (info, index):
                data = json.dumps(block, separators=(",", ":")).encode()
                f.write(_LENGTH.pack(len(data)))
                f.write(data)
            rules.serialize_into(f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        dir_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        tmp.unlink(missing_ok=True)


def _remove_stale_temporaries(directory: Path) -> None:
    """Temporary files of builds that crashed (only called while holding the lock)."""
    for leftover in directory.glob(".rules-*.tmp"):
        leftover.unlink(missing_ok=True)


@contextmanager
def _build_lock(wait: bool, timeout: float) -> Generator[bool]:
    """Exclusive flock on build.lock; yields False if not acquired. Released on crash."""
    directory = compiled_dir()
    directory.mkdir(parents=True, exist_ok=True)
    fd = os.open(directory / LOCK_FILENAME, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if not wait or time.monotonic() > deadline:
                    yield False
                    return
                time.sleep(0.05)
        try:
            yield True
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def build_running() -> bool:
    """Whether a build holds the lock right now."""
    lock = compiled_dir() / LOCK_FILENAME
    if not lock.exists():
        return False
    fd = os.open(lock, os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return True
    else:
        fcntl.flock(fd, fcntl.LOCK_UN)
        return False
    finally:
        os.close(fd)


@dataclass(frozen=True)
class BuildOutcome:
    built: bool  # False: the file was already up to date
    info: CompiledSetInfo


def build_compiled_set(
    *, force: bool = False, wait: bool = False, timeout: float = 900
) -> BuildOutcome | None:
    """
    Rebuild the compiled set file if it does not match the current rules
    revision (always with `force`). Returns None, without waiting, when
    another process is building (with `wait`, waits up to `timeout` seconds
    for it and then checks again). Never holds the database write lock.
    """
    with _build_lock(wait, timeout) as acquired:
        if not acquired:
            return None
        path = compiled_path()
        _remove_stale_temporaries(path.parent)
        rev = revision.current()
        if not force and (existing := read_info(path)) and existing["key"] == set_key(rev):
            return BuildOutcome(built=False, info=CompiledSetInfo.of(existing))
        info, index, rules = _compile(rev)
        _write_set(path, info, index, rules)
        logger.info(
            "Built compiled rule set revision %s: %s rules in %s rulesets, %s left out, %.1f s",
            info["revision"],
            info["rules"],
            info["rulesets"],
            info["left_out"],
            info["build_seconds"],
        )
        return BuildOutcome(built=True, info=CompiledSetInfo.of(info))


_state_lock = threading.Lock()
_current: CompiledSet | None = None


def compiled_set() -> CompiledSet:
    """
    The newest complete compiled set, loaded into this process once per
    file. When rules changed and the new file is not ready, this is the
    previous set (the scan result then says `pending`). Only when there is
    no usable file at all does it build one and wait (first start).

    With YARADUDE_SCAN_COMPILED_CACHE off (the test default) every call
    compiles the current rules in memory and nothing is written.
    """
    global _current
    if not settings.YARADUDE_SCAN_COMPILED_CACHE:
        rev = revision.current()
        info, index, rules = _compile(rev)
        return _make_set(info, index, rules)

    path = compiled_path()
    current = _current
    if current is not None and current.path == path and current.stat == _stat(path):
        return current
    with _state_lock:
        current = _current
        if current is not None and current.path != path:
            current = None  # the scan directory changed (tests)
        stat = _stat(path)
        if current is not None and current.stat == stat:
            return current
        if stat is not None and (loaded := _read_set(path, current)) is not None:
            _current = loaded
            return loaded
        if current is not None and _compatible(current.key):
            return current  # keep answering while the file is replaced
        # Last resort: nothing usable on disk. Build (or wait for the
        # builder) and load the result.
        build_compiled_set(wait=True)
        loaded = _read_set(path, None)
        if loaded is None:
            raise ScanError("The compiled rule set is not available. Try again shortly.")
        _current = loaded
        return loaded


def loaded_set() -> CompiledSet | None:
    """The set this process holds, if any (no loading)."""
    return _current


def refresh_loaded_set() -> bool:
    """
    Load a newer file if one appeared (for idle workers, so the next job does
    not wait for it). Returns True when a different set is now loaded.
    """
    before = _current
    if before is None:
        return False
    after = compiled_set()
    return after is not before and after.key != before.key


def forget_loaded_set() -> None:
    """Drop the set held by this process (tests)."""
    global _current
    with _state_lock:
        _current = None


def compiled_status() -> CompiledSetStatus:
    """The compiled set on disk and the current rules revision. Cheap: no rules loaded."""
    rev = revision.current()
    loaded = _current
    path = compiled_path()
    info = read_info(path)
    if loaded is not None and loaded.path == path and info and info["key"] == loaded.key:
        set_info: CompiledSetInfo | None = loaded.info
    else:
        set_info = CompiledSetInfo.of(info) if info and _compatible(info["key"]) else None
    return CompiledSetStatus(
        available=set_info is not None,
        set=set_info,
        current_revision=rev.number,
        current_changed_at=rev.changed_at,
        pending=info is None or info["key"] != set_key(rev),
        building=build_running(),
    )


def slow_rules() -> list[SlowRule]:
    """Rules YARA-X warned are slow, from the current compiled set (empty if none)."""
    loaded = _current
    path = compiled_path()
    if loaded is not None and loaded.path == path and loaded.stat == _stat(path):
        return list(loaded.slow)
    try:
        with path.open("rb") as f:
            if f.read(len(_MAGIC)) != _MAGIC:
                return []
            _read_block(f)
            index: _Index = _read_block(f)
    except (OSError, ValueError, struct.error):
        return []
    return [SlowRule(*row) for row in index["slow"]]


# ---------------------------------------------------------------------------
# Scanning


def scan_bytes(
    data: bytes,
    name: str = "",
    limit: ScanLimit | None = None,
    *,
    timeout: int | None = None,
    previews: bool = True,
) -> ScanResult:
    """
    Match `data` against the compiled set in one pass and report the matches
    allowed by `limit`. One query maps the matched rules back to `Rule`
    rows (without their sources); a match that maps to no rule is skipped
    and listed in `unmapped`. With `previews=False` the instances carry
    offsets and lengths only (hex/ascii empty), for results that are stored.

    Raises ScanTimeout / ScanError.
    """
    started = time.monotonic()
    limit = limit or ScanLimit()
    seconds: int = timeout if timeout is not None else settings.YARADUDE_SCAN_TIMEOUT
    globals_: dict[str, str] = settings.YARADUDE_GLOBALS
    name = PurePath(name or "").name

    compiled = compiled_set()
    pending = set_key(revision.current()) != compiled.key

    scanner = yara_x.Scanner(compiled.rules)
    scanner.set_timeout(seconds)
    scanner.max_matches_per_pattern(MAX_MATCHES_PER_PATTERN)
    if "filename" in globals_:
        scanner.set_global("filename", name)
    if "extension" in globals_:
        scanner.set_global("extension", PurePath(name).suffix)
    engine_started = time.monotonic()
    try:
        results = scanner.scan(data)
    except yara_x.TimeoutError:
        raise ScanTimeout(f"The scan was stopped after {seconds} seconds.") from None
    except yara_x.ScanError as error:
        raise ScanError(f"The scan failed: {error}") from None
    scan_seconds = time.monotonic() - engine_started

    found: list[tuple[int, list[str], list[PatternMatch]]] = []
    unmapped: list[str] = []
    for matched in results.matching_rules:
        entry = compiled.entries.get((matched.namespace, matched.identifier))
        if entry is None:
            unmapped.append(f"{matched.namespace}:{matched.identifier}")
            continue
        tags = list(matched.tags)
        if not limit.allows(entry.ruleset_id, tags):
            continue
        patterns = [
            PatternMatch(
                identifier=pattern.identifier,
                count=len(pattern.matches),
                instances=[
                    _preview(data, m.offset, m.length)
                    if previews
                    else PatternInstance(m.offset, m.length, "", "", m.length > PREVIEW_BYTES)
                    for m in pattern.matches[:MAX_INSTANCES]
                ],
            )
            for pattern in matched.patterns
            if pattern.matches
        ]
        found.append((entry.rule_id, tags, patterns))

    lean = Rule.objects.select_related("ruleset").defer("source", "ruleset__original_content")
    rules = lean.in_bulk([rule_id for rule_id, _, _ in found]) if found else {}
    matches: list[RuleMatch] = []
    for rule_id, tags, patterns in found:
        rule = rules.get(rule_id)
        if rule is None:  # deleted since the set was built
            unmapped.append(f"rule {rule_id}")
            continue
        matches.append(RuleMatch(rule=rule, tags=tags, patterns=patterns))
    if unmapped:
        logger.warning("Scan matches mapping to no stored rule were skipped: %s", unmapped[:10])

    left_ids = [pk for pk, rs in compiled.left_out if limit.allows(rs, ())]
    left_out: list[Rule] = []
    if left_ids:
        left = lean.filter(pk__in=left_ids)
        if limit.tag:
            left = left.filter(tags__name=limit.tag)
        left_out = list(left.order_by("ruleset_id", "position", "pk"))
    rules_scanned, ruleset_ids = compiled.rules_scanned(limit)

    return ScanResult(
        sample_name=name,
        sample_size=len(data),
        sample_sha256=hashlib.sha256(data).hexdigest(),
        matches=matches,
        rulesets=RulesetList(ruleset_ids),
        rules_scanned=rules_scanned,
        left_out=left_out,
        elapsed=time.monotonic() - started,
        revision=compiled.info.revision,
        built_at=compiled.info.built_at,
        pending=pending,
        unmapped=unmapped,
        scan_seconds=scan_seconds,
    )


def check_size(size: int) -> None:
    """Raise ScanError if a sample of `size` bytes exceeds YARADUDE_SCAN_MAX_BYTES."""
    limit: int = settings.YARADUDE_SCAN_MAX_BYTES
    if size > limit:
        raise ScanError(f"The sample is larger than the limit of {filesizeformat(limit)}.")


def scan_sample(sample: File, rulesets: Iterable[Ruleset] | None = None) -> ScanResult:
    """
    Match an uploaded sample in memory against the active rules of
    `rulesets` (all rulesets when None), using the compiled set. Rules that
    do not compile are left out and listed in the result. Runs in the
    calling process; new code should submit scan jobs (scans.services).

    Raises ScanError if the sample exceeds YARADUDE_SCAN_MAX_BYTES or the
    scan exceeds YARADUDE_SCAN_TIMEOUT seconds.
    """
    check_size(sample.size or 0)
    sample.seek(0)
    data: bytes = sample.read()
    check_size(len(data))
    limit = limit_for(rulesets=rulesets) if rulesets is not None else ScanLimit()
    return scan_bytes(data, sample.name or "", limit)
