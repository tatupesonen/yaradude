"""
Split YARA source text into individual rules.

This is a small hand-written tokenizer plus a top-level grammar; it does not
validate rule bodies (the YARA engine does that) but finds rule boundaries
reliably, which only requires treating strings, regular expressions and
comments as opaque tokens. See PLAN.md section 2 for the lexical rules.

The parser streams over the text: tokens are small tuples produced lazily,
whitespace is never materialised, and only a rule's `meta:` section is kept
as tokens, so memory stays proportional to the text plus the parsed rules
(PLAN.md section 13, finding 1).
"""

import hashlib
import re
from collections.abc import Iterator
from dataclasses import dataclass, field, replace

type MetaValue = str | int | float | bool


class RuleParseError(Exception):
    """The text cannot be split into rules. `line` is 1-based."""

    def __init__(self, message: str, line: int) -> None:
        super().__init__(f"line {line}: {message}")
        self.message = message
        self.line = line


@dataclass(frozen=True, slots=True)
class Token:
    """A token as returned by `tokenize` (whitespace is never returned)."""

    kind: str  # "comment", "string", "regex", "word", "var", "number", "punct"
    text: str
    start: int
    end: int
    line: int


@dataclass(frozen=True)
class ParsedRule:
    name: str
    tags: list[str]
    is_private: bool
    is_global: bool
    # The rule text from its first modifier (or its attached leading
    # comments) through the closing brace. Line endings are "\n".
    source: str
    meta: list[tuple[str, MetaValue]]
    # The modules of the file's imports that this rule references, and the
    # line of each one's import statement.
    imports: list[str]
    import_lines: list[int]
    # 1-based line of the rule keyword (or first modifier) in the file.
    line: int
    # 1-based line in the file where `source` starts.
    source_line: int

    def meta_value(self, key: str) -> str:
        """The first meta value with this key as text, or ''."""
        for meta_key, value in self.meta:
            if meta_key == key:
                return str(value)
        return ""

    @property
    def description(self) -> str:
        return self.meta_value("description")

    @property
    def author(self) -> str:
        return self.meta_value("author")

    @property
    def text(self) -> str:
        return rule_text(self.imports, self.source)

    @property
    def sha256(self) -> str:
        return content_sha256(self.imports, self.source)

    def parsed_line(self, text_line: int) -> int | None:
        """
        Map a line of `self.text` (where YARA-X reports errors) to the line in
        the text this rule was parsed from; None for the blank separator line.
        """
        header = len(self.imports) + 1 if self.imports else 0
        if text_line > header:
            return self.source_line + text_line - header - 1
        if 1 <= text_line <= len(self.imports):
            return self.import_lines[text_line - 1]
        return None


@dataclass(frozen=True)
class ParsedFile:
    imports: list[str]
    includes: list[str]
    rules: list[ParsedRule] = field(default_factory=list)


def normalize_newlines(text: str) -> str:
    """
    Convert CRLF line endings to LF. This is the one place line endings are
    normalised: rule sources and their hashes always use "\\n", so a file
    from disk, the same rule saved from a browser textarea (which submits
    CRLF) and its hash agree. A lone CR is left alone, because it may be part
    of a string literal.
    """
    return text.replace("\r\n", "\n")


def rule_text(imports: list[str], source: str) -> str:
    """The standalone text of one rule: its import lines, a blank line, the rule."""
    if not imports:
        return f"{source}\n"
    header = "".join(f'import "{module}"\n' for module in imports)
    return f"{header}\n{source}\n"


def content_sha256(imports: list[str], source: str) -> str:
    """Hash identifying a rule's content (its imports and source)."""
    return hashlib.sha256(rule_text(imports, source).encode()).hexdigest()


_TOKEN_RE = re.compile(
    r"""
      (?P<space>\s+)
    | (?P<comment>//[^\n]*|/\*.*?\*/)
    | (?P<string>"(?:\\.|[^"\\\n])*")
    | (?P<regex>/(?:\\.|[^/\\\n])+/[is]*)
    | (?P<word>[A-Za-z_]\w*)
    | (?P<var>[$#@!]\w*\*?)
    | (?P<number>0x[0-9A-Fa-f]+|0o[0-7]+|\d+(?:\.\d+)?(?:KB|MB)?)
    | (?P<punct>[^\s"/])
    | (?P<error>["/])
    """,
    re.VERBOSE | re.DOTALL,
)

_ESCAPES: dict[str, str] = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\"}
_MODIFIERS: frozenset[str] = frozenset({"global", "private"})
_HEX_BYTE = re.compile(r"[0-9A-Fa-f]{2}")

# A lexed token: (kind, start, end, line). Its text is `text[start:end]`.
type _Lexeme = tuple[str, int, int, int]


def _lex(text: str) -> Iterator[_Lexeme]:
    """
    Yield the non-whitespace tokens of `text` lazily, raising RuleParseError
    on unterminated literals.
    """
    line = 1
    for match in _TOKEN_RE.finditer(text):
        kind = match.lastgroup
        assert kind is not None  # every alternative of _TOKEN_RE is a named group
        start, end = match.span()
        if kind == "space":
            line += text.count("\n", start, end)
            continue
        if kind == "error":
            if text.startswith("/*", start):
                raise RuleParseError("unterminated comment", line)
            if text[start] == '"':
                raise RuleParseError("unterminated string", line)
            raise RuleParseError("unterminated regular expression", line)
        yield kind, start, end, line
        if kind == "comment":
            line += text.count("\n", start, end)


def tokenize(text: str) -> list[Token]:
    """All non-whitespace tokens of `text`; raises RuleParseError on unterminated literals."""
    return [Token(kind, text[start:end], start, end, line) for kind, start, end, line in _lex(text)]


def unescape_string(literal: str, line: int = 0) -> str:
    """Decode a YARA text string literal, including its quotes."""
    body = literal[1:-1]
    if "\\" not in body:
        return body
    out: list[str] = []
    i = 0
    while i < len(body):
        char = body[i]
        if char != "\\":
            out.append(char)
            i += 1
            continue
        escape = body[i + 1]
        if escape in _ESCAPES:
            out.append(_ESCAPES[escape])
            i += 2
        elif escape == "x" and _HEX_BYTE.fullmatch(body, i + 2, i + 4):
            out.append(chr(int(body[i + 2 : i + 4], 16)))
            i += 4
        else:
            raise RuleParseError(f"invalid escape sequence \\{escape} in string", line)
    return "".join(out)


def _parse_number(text: str, line: int) -> int | float:
    multiplier = 1
    if text.endswith("KB"):
        text, multiplier = text[:-2], 1024
    elif text.endswith("MB"):
        text, multiplier = text[:-2], 1024 * 1024
    if text.startswith("0o"):
        return int(text[2:], 8) * multiplier
    if text.startswith("0x"):
        return int(text[2:], 16) * multiplier
    if "." in text:
        # YARA-X accepts floats in meta, but not with a size suffix.
        if multiplier != 1:
            suffix = "KB" if multiplier == 1024 else "MB"
            raise RuleParseError(f"invalid meta value {text}{suffix}", line)
        return float(text)
    return int(text) * multiplier


@dataclass(frozen=True, slots=True)
class _Significant:
    """A non-comment token with the start of the comment run attached above it."""

    kind: str
    text: str
    start: int
    end: int
    line: int
    attached_start: int
    attached_line: int


def _significant(text: str) -> Iterator[_Significant]:
    """
    The grammar's tokens (no comments), each carrying where its attached
    leading comments start: the run of comments directly above it, each
    starting its own line, with no blank line between them or before the
    token. Without such comments that is the token itself.
    """
    previous_end = 0
    seen_any = False
    run: tuple[int, int] | None = None  # (offset, line) of the current comment run
    for kind, start, end, line in _lex(text):
        gap_newlines = text.count("\n", previous_end, start)
        if kind == "comment":
            starts_line = not seen_any or gap_newlines > 0
            if not starts_line:
                run = None
            elif run is None or gap_newlines > 1:
                run = (start, line)
        else:
            if run is not None and gap_newlines <= 1:
                attached_start, attached_line = run
            else:
                attached_start, attached_line = start, line
            yield _Significant(
                kind, text[start:end], start, end, line, attached_start, attached_line
            )
            run = None
        previous_end = end
        seen_any = True


class _Parser:
    def __init__(self, text: str) -> None:
        self.text = text
        self.tokens = _significant(text)
        self.lookahead: _Significant | None = None
        self.last_line = 1
        self.advance()

    def advance(self) -> None:
        self.lookahead = next(self.tokens, None)
        if self.lookahead is not None:
            self.last_line = self.lookahead.line

    def peek(self) -> _Significant | None:
        return self.lookahead

    def next(self, expected: str) -> _Significant:
        token = self.lookahead
        if token is None:
            raise RuleParseError(f"unexpected end of file, expected {expected}", self.last_line)
        self.advance()
        return token

    def parse(self) -> ParsedFile:
        imports: dict[str, int] = {}
        includes: list[str] = []
        rules: list[tuple[ParsedRule, set[str]]] = []
        seen: set[str] = set()
        while (token := self.peek()) is not None:
            if token.kind == "word" and token.text in ("import", "include"):
                self.advance()
                literal = self.next("a string")
                if literal.kind != "string":
                    raise RuleParseError(f"expected a string after {token.text}", literal.line)
                value = unescape_string(literal.text, literal.line)
                if token.text == "include":
                    includes.append(value)
                else:
                    imports.setdefault(value, token.line)
            elif token.kind == "word" and (token.text == "rule" or token.text in _MODIFIERS):
                rule, referenced = self.parse_rule()
                if rule.name in seen:
                    raise RuleParseError(f'duplicate rule identifier "{rule.name}"', rule.line)
                seen.add(rule.name)
                rules.append((rule, referenced))
            else:
                raise RuleParseError(f'unexpected "{token.text}"', token.line)
        return ParsedFile(
            imports=list(imports),
            includes=includes,
            rules=[_with_imports(rule, referenced, imports) for rule, referenced in rules],
        )

    def parse_rule(self) -> tuple[ParsedRule, set[str]]:
        first = self.next('"rule"')
        token = first
        modifiers: set[str] = set()
        while token.text in _MODIFIERS:
            modifiers.add(token.text)
            token = self.next('"rule"')
        if token.text != "rule":
            raise RuleParseError(f'expected "rule", got "{token.text}"', token.line)
        name_token = self.next("a rule name")
        if name_token.kind != "word":
            raise RuleParseError(f'invalid rule name "{name_token.text}"', name_token.line)

        tags: list[str] = []
        token = self.next('"{"')
        if token.text == ":":
            while (token := self.next('"{"')).kind == "word":
                tags.append(token.text)
            if not tags:
                raise RuleParseError("expected a tag after ':'", token.line)
        if token.text != "{":
            raise RuleParseError(f'expected "{{", got "{token.text}"', token.line)

        # Walk the body once: count braces, keep the tokens of a leading
        # `meta:` section, and collect the names used before a "." that is
        # not itself preceded by "." (the candidates for module references).
        meta_tokens: list[_Significant] = []
        in_meta: bool | None = None  # None until the first body token
        referenced: set[str] = set()
        before_previous: _Significant | None = None
        previous: _Significant = token
        depth = 1
        while True:
            token = self.peek()
            if token is None:
                raise RuleParseError(f'unterminated rule "{name_token.text}"', first.line)
            self.advance()
            text = token.text
            if text == "{":
                depth += 1
            elif text == "}":
                depth -= 1
                if not depth:
                    break
            elif (
                text == "."
                and previous.kind == "word"
                and (before_previous is None or before_previous.text != ".")
            ):
                referenced.add(previous.text)
            if in_meta is None:
                in_meta = text == "meta"
            if in_meta:
                if text == ":" and previous.text in ("strings", "condition") and meta_tokens:
                    # `strings:` / `condition:` ends the meta section; drop
                    # its keyword, which was collected as a would-be key.
                    meta_tokens.pop()
                    in_meta = False
                else:
                    meta_tokens.append(token)
            before_previous, previous = previous, token

        rule = ParsedRule(
            name=name_token.text,
            tags=tags,
            is_private="private" in modifiers,
            is_global="global" in modifiers,
            source=self.text[first.attached_start : token.end],
            meta=_parse_meta(meta_tokens),
            imports=[],
            import_lines=[],
            line=first.line,
            source_line=first.attached_line,
        )
        return rule, referenced


def _parse_meta(body: list[_Significant]) -> list[tuple[str, MetaValue]]:
    """Parse the tokens of a `meta:` section (starting with `meta`, `:`)."""
    if len(body) < 2 or body[0].text != "meta" or body[1].text != ":":
        return []
    meta: list[tuple[str, MetaValue]] = []
    i = 2
    while i < len(body):
        key = body[i]
        if key.kind != "word":
            raise RuleParseError(f'invalid meta identifier "{key.text}"', key.line)
        if i + 2 >= len(body) or body[i + 1].text != "=":
            raise RuleParseError(f'expected "=" after meta identifier "{key.text}"', key.line)
        value_token = body[i + 2]
        i += 3
        value: MetaValue
        if value_token.kind == "string":
            value = unescape_string(value_token.text, value_token.line)
        elif value_token.kind == "number":
            value = _parse_number(value_token.text, value_token.line)
        elif value_token.text in ("true", "false"):
            value = value_token.text == "true"
        elif value_token.text == "-" and i < len(body) and body[i].kind == "number":
            value = -_parse_number(body[i].text, body[i].line)
            i += 1
        else:
            raise RuleParseError(
                f'invalid value for meta "{key.text}": "{value_token.text}"',
                value_token.line,
            )
        meta.append((key.text, value))
    return meta


def _with_imports(rule: ParsedRule, referenced: set[str], imports: dict[str, int]) -> ParsedRule:
    """Copy of `rule` listing the imported modules its source references."""
    if not imports:
        return rule
    used = [module for module in imports if module in referenced]
    if not used:
        return rule
    return replace(rule, imports=used, import_lines=[imports[module] for module in used])


def parse(text: str) -> ParsedFile:
    """
    Split a YARA file into its imports, includes and rules. CRLF line endings
    are normalised to LF first (`normalize_newlines`).

    Raises RuleParseError for unterminated strings, regular expressions,
    comments or rules, unexpected top-level tokens, invalid meta values and
    duplicate rule identifiers.
    """
    return _Parser(normalize_newlines(text)).parse()


def referenced_names(source: str) -> set[str]:
    """
    Identifiers used as the start of a dotted expression, such as `pe` in
    `pe.is_pe`: the candidates for module references.
    """
    names: set[str] = set()
    before_previous: _Lexeme | None = None
    previous: _Lexeme | None = None
    for token in _lex(source):
        kind, start, end, _ = token
        if kind == "comment":
            continue
        if (
            previous is not None
            and source[start:end] == "."
            and previous[0] == "word"
            and (before_previous is None or source[before_previous[1] : before_previous[2]] != ".")
        ):
            names.add(source[previous[1] : previous[2]])
        before_previous, previous = previous, token
    return names


def parse_rule_text(text: str) -> ParsedRule:
    """
    Parse editor text: optional import lines followed by exactly one rule.

    Raises RuleParseError if the text holds no rule, more than one rule, or an
    include statement.
    """
    parsed = parse(text)
    if parsed.includes:
        raise RuleParseError("include statements are not supported", _line_of(text, "include"))
    if not parsed.rules:
        raise RuleParseError("no rule found", 1)
    if len(parsed.rules) > 1:
        raise RuleParseError("only one rule can be edited at a time", parsed.rules[1].line)
    return parsed.rules[0]


def _line_of(text: str, word: str) -> int:
    for kind, start, end, line in _lex(text):
        if kind == "word" and text[start:end] == word:
            return line
    return 1
