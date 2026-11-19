"""
Compile rules with YARA-X and attribute diagnostics to individual rules.

All engine access goes through this module and scanner.py. Each rule is
added to the compiler as its own source (its imports followed by the rule),
in position order inside one namespace, so every failing rule gets its own
error with line numbers relative to its standalone text, and a failing rule
does not hide the errors of the rules after it.
"""

import re
from dataclasses import dataclass, field
from functools import cache
from typing import TypedDict

import yara_x
from django.conf import settings
from django.db import transaction

from rules.models import Rule, Ruleset
from rules.services.parser import ParsedRule, referenced_names, rule_text

_UNKNOWN_IDENTIFIER = re.compile(r"unknown identifier `([^`]+)`")


class _Span(TypedDict):
    start: int
    end: int


class _Label(TypedDict):
    level: str
    code_origin: str | None  # the `origin` passed to add_source, if any
    line: int
    column: int
    span: _Span
    text: str


class _Footer(TypedDict):
    level: str
    text: str


class _Diagnostic(TypedDict):
    """One entry of `Compiler.errors()` / `Compiler.warnings()` (PLAN.md section 2)."""

    type: str
    code: str
    title: str
    line: int
    column: int
    labels: list[_Label]
    footers: list[_Footer]
    text: str


def _errors(compiler: yara_x.Compiler) -> list[_Diagnostic]:
    """`compiler.errors()`, which the yara_x stub types as Any."""
    return compiler.errors()


def _warnings(compiler: yara_x.Compiler) -> list[_Diagnostic]:
    """`compiler.warnings()`, which the yara_x stub types as Any."""
    return compiler.warnings()


def new_compiler() -> yara_x.Compiler:
    """
    A compiler with includes disabled (they would read files from the
    server's disk), the configured regex strictness and the default globals.
    """
    relaxed_re_syntax: bool = settings.YARADUDE_RELAXED_RE_SYNTAX
    globals_: dict[str, str] = settings.YARADUDE_GLOBALS
    compiler = yara_x.Compiler(relaxed_re_syntax=relaxed_re_syntax, includes_enabled=False)
    for name, value in globals_.items():
        compiler.define_global(name, value)
    return compiler


@cache
def available_modules() -> frozenset[str]:
    """The YARA modules this YARA-X build provides."""
    return frozenset(yara_x.module_names())  # ty: ignore[missing-attribute]  # exists at runtime, absent from the yara_x 1.23 stub


@dataclass(frozen=True)
class RuleDiagnostics:
    """The compile result of one rule; line numbers refer to its standalone text."""

    name: str
    error: str = ""
    line: int | None = None
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.error


@dataclass(frozen=True)
class _Entry:
    name: str
    imports: list[str]
    source: str


def _missing_imports(entry: _Entry) -> list[str]:
    used = referenced_names(entry.source) & available_modules()
    return sorted(used - set(entry.imports))


def _compile_entries(entries: list[_Entry]) -> list[RuleDiagnostics]:
    """Compile rules in order in one namespace; one result per entry."""
    compiler = new_compiler()
    errors: dict[str, tuple[str, int | None]] = {}
    for entry in entries:
        # An import stays in effect for later sources in the namespace, so a
        # rule relying on an earlier rule's import would compile here but not
        # on its own. Such a rule is not added, like any other failing rule.
        if missing := _missing_imports(entry):
            names = ", ".join(f'"{module}"' for module in missing)
            errors[entry.name] = (f"module {names} is used but not imported", None)
            continue
        try:
            compiler.add_source(rule_text(entry.imports, entry.source), origin=entry.name)
        except yara_x.CompileError:
            error = _errors(compiler)[-1]
            text = error["text"]
            if error["code"] == "E009":
                match = _UNKNOWN_IDENTIFIER.search(error["title"])
                if match and match.group(1) in errors:
                    text = f'depends on rule "{match.group(1)}", which does not compile\n\n{text}'
            errors[entry.name] = (text, error["line"])

    warnings: dict[str, list[str]] = {}
    for warning in _warnings(compiler):
        # Every source is added with its rule name as origin.
        origins = {
            origin for label in warning["labels"] if (origin := label["code_origin"]) is not None
        }
        for origin in origins:
            warnings.setdefault(origin, []).append(warning["text"])

    return [
        RuleDiagnostics(
            name=entry.name,
            error=errors.get(entry.name, ("", None))[0],
            line=errors.get(entry.name, ("", None))[1],
            warnings=warnings.get(entry.name, []),
        )
        for entry in entries
    ]


@dataclass(frozen=True)
class RulesetCheck:
    """Result of check_ruleset: the diagnostics of each active rule, by rule."""

    ruleset: Ruleset
    diagnostics: dict[Rule, RuleDiagnostics]

    @property
    def failing(self) -> list[Rule]:
        return [rule for rule, result in self.diagnostics.items() if not result.ok]

    @property
    def ok(self) -> bool:
        return not self.failing

    @property
    def summary(self) -> str:
        failing = self.failing
        if not failing:
            return ""
        names = ", ".join(rule.name for rule in failing[:5])
        if len(failing) > 5:
            names += ", …"
        return f"{len(failing)} of {len(self.diagnostics)} rules do not compile: {names}"


def check_ruleset(ruleset: Ruleset) -> RulesetCheck:
    """
    Compile the active rules of a ruleset and store the results: each rule's
    own `compile_error` and `compile_warnings`, and a summary in
    `Ruleset.compile_error`. Removed rules are not compiled and are cleared.
    """
    rules = list(ruleset.rules.order_by("position", "pk"))
    active = [rule for rule in rules if not rule.is_removed]
    results = _compile_entries([_Entry(r.name, r.imports, r.source) for r in active])
    check = RulesetCheck(ruleset, dict(zip(active, results, strict=True)))

    changed: list[Rule] = []
    for rule in rules:
        result = check.diagnostics.get(rule, RuleDiagnostics(rule.name))
        if (rule.compile_error, rule.compile_warnings) != (result.error, result.warnings):
            rule.compile_error, rule.compile_warnings = result.error, result.warnings
            changed.append(rule)
    with transaction.atomic():
        Rule.objects.bulk_update(changed, ["compile_error", "compile_warnings"])
        if ruleset.compile_error != check.summary:
            ruleset.compile_error = check.summary
            ruleset.save(update_fields=["compile_error"])
    return check


@dataclass(frozen=True)
class BrokenRule:
    rule: Rule
    error: str


@dataclass(frozen=True)
class EditValidation:
    """
    Result of validate_edit. `error`, `line` and `warnings` belong to the
    edited rule; `line` is relative to the text the rule was parsed from
    (the editor text), while the line numbers inside the `error` diagnostic
    refer to the rule's normalised text (`ParsedRule.text`). `broken` lists
    sibling rules that compile now but would fail with the edit.
    """

    error: str = ""
    line: int | None = None
    warnings: list[str] = field(default_factory=list)
    broken: list[BrokenRule] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.error


def validate_edit(ruleset: Ruleset, rule: Rule | None, parsed: ParsedRule) -> EditValidation:
    """
    Compile a proposed rule in the context of the ruleset's other active
    rules: in place of `rule` when editing, after the last rule when creating.
    Does not write to the database.
    """
    siblings = list(ruleset.rules.active().order_by("position", "pk"))
    if rule is not None:
        siblings = [sibling for sibling in siblings if sibling.pk != rule.pk]
    proposed = _Entry(parsed.name, parsed.imports, parsed.source)
    position = rule.position if rule is not None else None
    before = [s for s in siblings if position is None or s.position <= position]
    after = [s for s in siblings if position is not None and s.position > position]
    ordered = [*before, None, *after]

    entries = [proposed if s is None else _Entry(s.name, s.imports, s.source) for s in ordered]
    results = _compile_entries(entries)
    own = results[ordered.index(None)]
    broken = [
        BrokenRule(sibling, result.error)
        for sibling, result in zip(ordered, results, strict=True)
        if sibling is not None and not result.ok and sibling.compiles
    ]
    line = parsed.parsed_line(own.line) if own.line is not None else None
    return EditValidation(error=own.error, line=line, warnings=own.warnings, broken=broken)


def build_source(ruleset: Ruleset) -> str:
    """The ruleset as one text: de-duplicated imports, then active rules by position."""
    return combine_rules(list(ruleset.rules.active().order_by("position", "pk")))


def combine_rules(rules: list[Rule]) -> str:
    """Rules as one text, with all their imports de-duplicated at the top."""
    imports = dict.fromkeys(module for rule in rules for module in rule.imports)
    parts: list[str] = []
    if imports:
        parts.append("".join(f'import "{module}"\n' for module in imports))
    parts.extend(f"{rule.source}\n" for rule in rules)
    return "\n".join(parts)


def compiled_identifiers(text: str) -> list[str] | None:
    """Identifiers of the rules in `text` if it compiles as a whole, else None."""
    compiler = new_compiler()
    try:
        compiler.add_source(text)
    except yara_x.CompileError:
        return None
    return [rule.identifier for rule in compiler.build()]
