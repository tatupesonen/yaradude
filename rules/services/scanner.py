"""
Test-scan an uploaded sample against the stored rules.

The sample may be malware: it is matched in memory only, never written to
the database or to disk, and its contents are never logged.
"""

import hashlib
import time
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import PurePath

import yara_x
from django.conf import settings
from django.core.files import File
from django.template.defaultfilters import filesizeformat

from rules.models import Rule, Ruleset
from rules.services.compiler import new_compiler

MAX_INSTANCES = 5  # string instances shown per pattern
MAX_MATCHES_PER_PATTERN = 1000
PREVIEW_BYTES = 32


class ScanError(Exception):
    """The sample could not be scanned (too large, timeout, engine error)."""


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
    rule: Rule
    tags: list[str]
    patterns: list[PatternMatch]

    @property
    def ruleset(self) -> Ruleset:
        return self.rule.ruleset


@dataclass(frozen=True)
class ScanResult:
    sample_name: str
    sample_size: int
    sample_sha256: str
    matches: list[RuleMatch]
    rulesets: list[Ruleset]  # rulesets that took part
    rules_scanned: int
    left_out: list[Rule]  # rules not used because they do not compile
    elapsed: float  # seconds spent compiling and scanning


def _preview(data: bytes, offset: int, length: int) -> PatternInstance:
    chunk = data[offset : offset + min(length, PREVIEW_BYTES)]
    return PatternInstance(
        offset=offset,
        length=length,
        hex=chunk.hex(" "),
        ascii="".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk),
        truncated=length > PREVIEW_BYTES,
    )


def scan_sample(sample: File, rulesets: Iterable[Ruleset] | None = None) -> ScanResult:
    """
    Match an uploaded sample against the active rules of `rulesets` (all
    rulesets when None), one YARA-X namespace per ruleset. Rules that do not
    compile are left out and listed in the result.

    Raises ScanError if the sample exceeds YARADUDE_SCAN_MAX_BYTES or the
    scan exceeds YARADUDE_SCAN_TIMEOUT seconds.
    """
    limit: int = settings.YARADUDE_SCAN_MAX_BYTES
    timeout: int = settings.YARADUDE_SCAN_TIMEOUT
    if sample.size > limit:
        raise ScanError(f"The sample is larger than the limit of {filesizeformat(limit)}.")
    sample.seek(0)
    data: bytes = sample.read()
    name = PurePath(sample.name or "").name

    started = time.monotonic()
    rules = Rule.objects.active().select_related("ruleset").order_by("ruleset_id", "position", "pk")
    if rulesets is not None:
        rules = rules.filter(ruleset__in=list(rulesets))

    compiler = new_compiler()
    by_key: dict[tuple[str, str], Rule] = {}
    used_rulesets: dict[int, Ruleset] = {}
    left_out: list[Rule] = []
    namespace: str | None = None
    for rule in rules:
        if not rule.compiles:
            left_out.append(rule)
            continue
        if namespace != str(rule.ruleset_id):
            namespace = str(rule.ruleset_id)
            compiler.new_namespace(namespace)
        try:
            compiler.add_source(rule.text, origin=rule.name)
        except yara_x.CompileError:
            # The stored compile status is stale, or the rule depends on one
            # that does not compile.
            left_out.append(rule)
            continue
        by_key[namespace, rule.name] = rule
        used_rulesets[rule.ruleset_id] = rule.ruleset

    scanner = yara_x.Scanner(compiler.build())
    scanner.set_timeout(timeout)
    scanner.max_matches_per_pattern(MAX_MATCHES_PER_PATTERN)
    scanner.set_global("filename", name)
    scanner.set_global("extension", PurePath(name).suffix)
    try:
        results = scanner.scan(data)
    except yara_x.TimeoutError:
        raise ScanError(f"The scan was stopped after {timeout} seconds.") from None
    except yara_x.ScanError as error:
        raise ScanError(f"The scan failed: {error}") from None

    matches: list[RuleMatch] = []
    for matched in results.matching_rules:
        patterns = [
            PatternMatch(
                identifier=pattern.identifier,
                count=len(pattern.matches),
                instances=[
                    _preview(data, m.offset, m.length) for m in pattern.matches[:MAX_INSTANCES]
                ],
            )
            for pattern in matched.patterns
            if pattern.matches
        ]
        rule = by_key[matched.namespace, matched.identifier]
        matches.append(RuleMatch(rule=rule, tags=list(matched.tags), patterns=patterns))

    return ScanResult(
        sample_name=name,
        sample_size=len(data),
        sample_sha256=hashlib.sha256(data).hexdigest(),
        matches=matches,
        rulesets=sorted(used_rulesets.values(), key=lambda r: (r.name, r.pk)),
        rules_scanned=sum(1 for rule in by_key.values() if not rule.is_private),
        left_out=left_out,
        elapsed=time.monotonic() - started,
    )
