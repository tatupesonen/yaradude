"""
Split YARA source text into individual rules.

This is a small hand-written tokenizer plus a top-level grammar; it does not
validate rule bodies (the YARA engine does that) but finds rule boundaries
reliably, which only requires treating strings, regular expressions and
comments as opaque tokens. See PLAN.md section 2 for the lexical rules.
"""

import hashlib
import re
from dataclasses import dataclass, field, replace

type MetaValue = str | int | bool


class RuleParseError(Exception):
    """The text cannot be split into rules. `line` is 1-based."""

    def __init__(self, message: str, line: int) -> None:
        super().__init__(f"line {line}: {message}")
        self.message = message
        self.line = line


@dataclass(frozen=True)
class Token:
    kind: str  # "space", "comment", "string", "regex", "word", "var", "number", "punct"
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
    # comments) through the closing brace.
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
    """,
    re.VERBOSE | re.DOTALL,
)

_ESCAPES: dict[str, str] = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\"}
_MODIFIERS: set[str] = {"global", "private"}


def tokenize(text: str) -> list[Token]:
    """Split text into tokens, raising RuleParseError on unterminated literals."""
    tokens: list[Token] = []
    pos = 0
    line = 1
    while pos < len(text):
        match = _TOKEN_RE.match(text, pos)
        if match is None:
            if text.startswith("/*", pos):
                raise RuleParseError("unterminated comment", line)
            if text[pos] == '"':
                raise RuleParseError("unterminated string", line)
            raise RuleParseError("unterminated regular expression", line)
        kind = match.lastgroup
        assert kind is not None  # every alternative of _TOKEN_RE is a named group
        tokens.append(Token(kind, match.group(), pos, match.end(), line))
        line += match.group().count("\n")
        pos = match.end()
    return tokens


def unescape_string(literal: str, line: int = 0) -> str:
    """Decode a YARA text string literal, including its quotes."""
    body = literal[1:-1]
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
        elif escape == "x" and re.fullmatch(r"[0-9A-Fa-f]{2}", body[i + 2 : i + 4]):
            out.append(chr(int(body[i + 2 : i + 4], 16)))
            i += 4
        else:
            raise RuleParseError(f"invalid escape sequence \\{escape} in string", line)
    return "".join(out)


def _parse_number(text: str, line: int) -> int:
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
        raise RuleParseError(f"meta value {text} is not an integer", line)
    return int(text) * multiplier


class _Parser:
    def __init__(self, text: str) -> None:
        self.text = text
        self.tokens = tokenize(text)
        # Indexes into self.tokens of the significant (non-space, non-comment)
        # tokens, which is what the grammar looks at.
        self.significant = [
            i for i, token in enumerate(self.tokens) if token.kind not in ("space", "comment")
        ]
        self.pos = 0

    def peek(self) -> Token | None:
        if self.pos < len(self.significant):
            return self.tokens[self.significant[self.pos]]
        return None

    def next(self, expected: str) -> Token:
        token = self.peek()
        if token is None:
            last_line = self.tokens[-1].line if self.tokens else 1
            raise RuleParseError(f"unexpected end of file, expected {expected}", last_line)
        self.pos += 1
        return token

    def parse(self) -> ParsedFile:
        imports: dict[str, int] = {}
        includes: list[str] = []
        rules: list[ParsedRule] = []
        seen: set[str] = set()
        while (token := self.peek()) is not None:
            if token.kind == "word" and token.text in ("import", "include"):
                self.pos += 1
                literal = self.next("a string")
                if literal.kind != "string":
                    raise RuleParseError(f"expected a string after {token.text}", literal.line)
                value = unescape_string(literal.text, literal.line)
                if token.text == "include":
                    includes.append(value)
                else:
                    imports.setdefault(value, token.line)
            elif token.kind == "word" and (token.text == "rule" or token.text in _MODIFIERS):
                rule = self.parse_rule()
                if rule.name in seen:
                    raise RuleParseError(f'duplicate rule identifier "{rule.name}"', rule.line)
                seen.add(rule.name)
                rules.append(rule)
            else:
                raise RuleParseError(f'unexpected "{token.text}"', token.line)
        rules = [self.with_imports(rule, imports) for rule in rules]
        return ParsedFile(imports=list(imports), includes=includes, rules=rules)

    def parse_rule(self) -> ParsedRule:
        first_index = self.significant[self.pos]
        first = self.tokens[first_index]
        modifiers: set[str] = set()
        while (token := self.next('"rule"')).text in _MODIFIERS:
            modifiers.add(token.text)
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

        body_start = self.pos
        depth = 1
        while depth:
            token = self.peek()
            if token is None:
                raise RuleParseError(f'unterminated rule "{name_token.text}"', first.line)
            self.pos += 1
            if token.text == "{":
                depth += 1
            elif token.text == "}":
                depth -= 1
        body = [self.tokens[i] for i in self.significant[body_start : self.pos - 1]]
        closing = token

        start = self.tokens[self.attached_comment_start(first_index)]
        return ParsedRule(
            name=name_token.text,
            tags=tags,
            is_private="private" in modifiers,
            is_global="global" in modifiers,
            source=self.text[start.start : closing.end],
            meta=self.parse_meta(body),
            imports=[],
            import_lines=[],
            line=first.line,
            source_line=start.line,
        )

    def attached_comment_start(self, index: int) -> int:
        """
        Index of the first token of the comment run directly above the token
        at `index`: comments separated from it and from each other by no blank
        line, each starting its own line.
        """
        start = index
        i = index - 1
        while i >= 0:
            token = self.tokens[i]
            if token.kind == "space":
                if token.text.count("\n") > 1:
                    break
            elif token.kind == "comment" and self.starts_line(i):
                start = i
            else:
                break
            i -= 1
        return start

    def starts_line(self, index: int) -> bool:
        if index == 0:
            return True
        previous = self.tokens[index - 1]
        return previous.kind == "space" and ("\n" in previous.text or index == 1)

    @staticmethod
    def parse_meta(body: list[Token]) -> list[tuple[str, MetaValue]]:
        """Parse the `meta:` section, which can only open a rule body."""
        if len(body) < 2 or body[0].text != "meta" or body[1].text != ":":
            return []
        meta: list[tuple[str, MetaValue]] = []
        i = 2
        while i < len(body):
            key = body[i]
            if (
                key.text in ("strings", "condition")
                and i + 1 < len(body)
                and body[i + 1].text == ":"
            ):
                break
            if key.kind != "word":
                raise RuleParseError(f'invalid meta identifier "{key.text}"', key.line)
            if i + 2 >= len(body) or body[i + 1].text != "=":
                raise RuleParseError(f'expected "=" after meta identifier "{key.text}"', key.line)
            value_token = body[i + 2]
            i += 3
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

    @staticmethod
    def with_imports(rule: ParsedRule, imports: dict[str, int]) -> ParsedRule:
        """Copy of `rule` listing the imported modules its source references."""
        if not imports:
            return rule
        used = [module for module in imports if module in referenced_names(rule.source)]
        return replace(rule, imports=used, import_lines=[imports[module] for module in used])


def parse(text: str) -> ParsedFile:
    """
    Split a YARA file into its imports, includes and rules.

    Raises RuleParseError for unterminated strings, regular expressions,
    comments or rules, unexpected top-level tokens, invalid meta values and
    duplicate rule identifiers.
    """
    return _Parser(text).parse()


def referenced_names(source: str) -> set[str]:
    """
    Identifiers used as the start of a dotted expression, such as `pe` in
    `pe.is_pe`: the candidates for module references.
    """
    tokens = [t for t in tokenize(source) if t.kind not in ("space", "comment")]
    return {
        token.text
        for i, token in enumerate(tokens[:-1])
        if token.kind == "word"
        and tokens[i + 1].text == "."
        and (i == 0 or tokens[i - 1].text != ".")
    }


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
    for token in tokenize(text):
        if token.kind == "word" and token.text == word:
            return token.line
    return 1
