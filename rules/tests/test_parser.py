from django.test import SimpleTestCase

from rules.services.parser import (
    RuleParseError,
    content_sha256,
    parse,
    parse_rule_text,
    referenced_names,
    rule_text,
    tokenize,
)


class TokenizerTests(SimpleTestCase):
    def kinds(self, text: str) -> list[tuple[str, str]]:
        return [(t.kind, t.text) for t in tokenize(text) if t.kind != "space"]

    def test_regex_with_braces_quotes_and_double_slash(self) -> None:
        regex = r'/a{2,3}"[}{]\/\/b/is'
        self.assertEqual(
            self.kinds(f"$a = {regex}"), [("var", "$a"), ("punct", "="), ("regex", regex)]
        )

    def test_unescaped_slash_terminates_regex_inside_class(self) -> None:
        self.assertEqual(self.kinds("/a[/]"), [("regex", "/a[/"), ("punct", "]")])

    def test_escaped_quote_in_string(self) -> None:
        self.assertEqual(self.kinds(r'"a\"b}" x'), [("string", r'"a\"b}"'), ("word", "x")])

    def test_comment_markers_inside_string_and_regex_are_opaque(self) -> None:
        self.assertEqual(
            self.kinds(r'"http://x/*y" /a\/\/b/'),
            [("string", '"http://x/*y"'), ("regex", r"/a\/\/b/")],
        )

    def test_comments(self) -> None:
        self.assertEqual(
            self.kinds("a // rule { \n /* } rule\n { */ b"),
            [
                ("word", "a"),
                ("comment", "// rule { "),
                ("comment", "/* } rule\n { */"),
                ("word", "b"),
            ],
        )

    def test_backslash_is_division_not_regex(self) -> None:
        self.assertEqual(
            [k for k, _ in self.kinds(r"filesize \ 2 == 1")],
            ["word", "punct", "number", "punct", "punct", "number"],
        )

    def test_line_numbers(self) -> None:
        tokens = [t for t in tokenize('a\n/* x\ny */ b\n"c"') if t.kind != "space"]
        self.assertEqual([t.line for t in tokens], [1, 2, 3, 4])

    def test_unterminated_literals(self) -> None:
        cases = [
            ('rule a {\n strings: $a = "abc\n condition: $a }', "unterminated string", 2),
            (
                "rule a {\n\n strings: $a = /abc\n condition: $a }",
                "unterminated regular expression",
                3,
            ),
            ("x\n/* never closed", "unterminated comment", 2),
            ("rule a { condition: 1 }\n/", "unterminated regular expression", 2),
        ]
        for text, message, line in cases:
            with self.subTest(message=message), self.assertRaises(RuleParseError) as ctx:
                tokenize(text)
            self.assertEqual((ctx.exception.message, ctx.exception.line), (message, line))


class ParseTests(SimpleTestCase):
    def test_hex_strings_with_jumps_alternatives_and_comments(self) -> None:
        text = """rule hex {
    strings:
        $a = { 4D 5A [2-4] ( 90 | 91 ?? ) /* } */ ~00 4? ?F // }
               [-] 00 }
    condition:
        $a
}
rule after { condition: true }"""
        parsed = parse(text)
        self.assertEqual([r.name for r in parsed.rules], ["hex", "after"])
        self.assertTrue(parsed.rules[0].source.endswith("$a\n}"))

    def test_comments_containing_braces_and_rule_keyword(self) -> None:
        text = """rule a {
    // } rule fake {
    condition: /* } */ true
}
/* rule b { condition: true } */
rule c { condition: true }"""
        self.assertEqual([r.name for r in parse(text).rules], ["a", "c"])

    def test_regex_with_braces_quotes_and_escaped_slashes(self) -> None:
        text = r"""rule r {
    strings:
        $re = /\{"x"\}{1,2}[{}]\/\/ // not a comment/ nocase
    condition: $re
}
rule s { condition: true }"""
        parsed = parse(text)
        self.assertEqual([r.name for r in parsed.rules], ["r", "s"])
        self.assertIn("// not a comment/ nocase", parsed.rules[0].source)

    def test_escaped_quotes_and_braces_in_strings(self) -> None:
        text = r'rule q { strings: $a = "}\"{" condition: $a } rule z { condition: true }'
        self.assertEqual([r.name for r in parse(text).rules], ["q", "z"])

    def test_several_rules_on_one_line(self) -> None:
        text = (
            "rule a { condition: true } rule b : t { condition: a }  private rule c {condition:b}"
        )
        parsed = parse(text)
        self.assertEqual([r.name for r in parsed.rules], ["a", "b", "c"])
        self.assertEqual(parsed.rules[1].source, "rule b : t { condition: a }")
        self.assertEqual([r.line for r in parsed.rules], [1, 1, 1])

    def test_modifiers(self) -> None:
        text = """global rule g { condition: true }
private rule p { condition: true }
global private rule gp { condition: true }
private global rule pg { condition: true }
rule plain { condition: true }"""
        flags = [(r.name, r.is_global, r.is_private) for r in parse(text).rules]
        self.assertEqual(
            flags,
            [
                ("g", True, False),
                ("p", False, True),
                ("gp", True, True),
                ("pg", True, True),
                ("plain", False, False),
            ],
        )
        self.assertTrue(parse(text).rules[2].source.startswith("global private rule gp"))

    def test_tags(self) -> None:
        rules = parse(
            "rule a : one two_2 Three { condition: true }\nrule b { condition: true }"
        ).rules
        self.assertEqual(rules[0].tags, ["one", "two_2", "Three"])
        self.assertEqual(rules[1].tags, [])

    def test_imports_and_includes(self) -> None:
        text = """import "pe"
import "math"
import "pe"
include "other.yar"
rule uses_pe { condition: pe.is_pe }
rule uses_both { condition: pe.is_dll() and math.entropy(0, filesize) > 7 }
rule uses_none { condition: true }"""
        parsed = parse(text)
        self.assertEqual(parsed.imports, ["pe", "math"])
        self.assertEqual(parsed.includes, ["other.yar"])
        self.assertEqual([r.imports for r in parsed.rules], [["pe"], ["pe", "math"], []])

    def test_module_field_named_like_module_is_not_a_reference(self) -> None:
        self.assertEqual(referenced_names("rule a { condition: x.math.y and pe.z }"), {"x", "pe"})

    def test_attached_leading_comments(self) -> None:
        text = """import "pe"
// Not attached: separated by a blank line.

// Line one.
/* Block
   comment. */
// Line three.
rule a { condition: true } // trailing comment of a
// Attached to b.
rule b { condition: true }
  /* indented */ rule c { condition: true }"""
        rules = parse(text).rules
        self.assertEqual(
            rules[0].source,
            "// Line one.\n/* Block\n   comment. */\n// Line three.\nrule a { condition: true }",
        )
        self.assertEqual(rules[1].source, "// Attached to b.\nrule b { condition: true }")
        self.assertEqual(rules[2].source, "/* indented */ rule c { condition: true }")
        self.assertEqual([r.line for r in rules], [8, 10, 11])

    def test_comment_at_start_of_file_is_attached(self) -> None:
        rule = parse("// About a\nrule a { condition: true }").rules[0]
        self.assertEqual(rule.source, "// About a\nrule a { condition: true }")

    def test_comment_after_previous_rule_on_same_line_is_not_attached(self) -> None:
        rules = parse("rule a { condition: true } /* about a */\nrule b { condition: true }").rules
        self.assertEqual(rules[1].source, "rule b { condition: true }")

    def test_meta_value_types(self) -> None:
        text = r"""rule m {
    meta:
        text = "quote \" backslash \\ tab \t newline \n hex \x41"
        empty = ""
        number = 42
        negative = -7
        hex = 0x1F
        size = 2KB
        yes = true
        no = false
        text = "duplicate key"
    strings:
        $a = "meta = 1"
    condition:
        $a
}"""
        rule = parse(text).rules[0]
        self.assertEqual(
            rule.meta,
            [
                ("text", 'quote " backslash \\ tab \t newline \n hex A'),
                ("empty", ""),
                ("number", 42),
                ("negative", -7),
                ("hex", 31),
                ("size", 2048),
                ("yes", True),
                ("no", False),
                ("text", "duplicate key"),
            ],
        )

    def test_description_and_author_from_meta(self) -> None:
        rule = parse('rule a { meta: author = "Ann" version = 2 condition: true }').rules[0]
        self.assertEqual((rule.description, rule.author), ("", "Ann"))
        self.assertEqual(rule.meta_value("version"), "2")

    def test_meta_section_only_at_condition(self) -> None:
        self.assertEqual(parse("rule a { condition: true }").rules[0].meta, [])

    def test_empty_and_comment_only_files(self) -> None:
        self.assertEqual(parse("").rules, [])
        self.assertEqual(parse("// nothing\n/* here */\n").rules, [])

    def test_crlf_line_endings(self) -> None:
        text = (
            "// about a\r\nrule a {\r\n condition: true\r\n}\r\n\r\n"
            "// x\r\n\r\nrule b { condition: true }"
        )
        rules = parse(text).rules
        self.assertEqual(rules[0].source, "// about a\r\nrule a {\r\n condition: true\r\n}")
        self.assertEqual(rules[1].source, "rule b { condition: true }")
        self.assertEqual(rules[1].line, 8)

    def test_text_and_hash(self) -> None:
        rule = parse('import "pe"\nrule a { condition: pe.is_pe }').rules[0]
        self.assertEqual(rule.text, 'import "pe"\n\nrule a { condition: pe.is_pe }\n')
        self.assertEqual(rule.sha256, content_sha256(["pe"], rule.source))
        self.assertNotEqual(rule.sha256, content_sha256([], rule.source))
        self.assertEqual(rule_text([], "rule a {}"), "rule a {}\n")


class ParseErrorTests(SimpleTestCase):
    def assertParseError(self, text: str, message: str, line: int) -> None:
        with self.assertRaises(RuleParseError) as ctx:
            parse(text)
        self.assertEqual(ctx.exception.message, message)
        self.assertEqual(ctx.exception.line, line)
        self.assertEqual(str(ctx.exception), f"line {line}: {message}")

    def test_unterminated_rule(self) -> None:
        self.assertParseError(
            "rule ok { condition: true }\n\nrule broken {\n condition: true\n",
            'unterminated rule "broken"',
            3,
        )

    def test_unterminated_rule_with_nested_hex(self) -> None:
        self.assertParseError(
            "rule a {\n strings: $a = { 41 42\n condition: $a\n}", 'unterminated rule "a"', 1
        )

    def test_unterminated_string(self) -> None:
        self.assertParseError(
            'rule a {\n meta:\n x = "abc\n condition: true }', "unterminated string", 3
        )

    def test_unterminated_regex(self) -> None:
        self.assertParseError(
            "rule a {\n strings:\n $a = /abc\n condition: $a }",
            "unterminated regular expression",
            3,
        )

    def test_unexpected_top_level_token(self) -> None:
        self.assertParseError(
            "rule a { condition: true }\n\nrul b { condition: true }", 'unexpected "rul"', 3
        )
        self.assertParseError("rule a { condition: true }\n}", 'unexpected "}"', 2)
        self.assertParseError(
            "import pe\nrule a { condition: true }", "expected a string after import", 1
        )

    def test_duplicate_identifier(self) -> None:
        self.assertParseError(
            "rule a { condition: true }\n// again\nrule a { condition: false }",
            'duplicate rule identifier "a"',
            3,
        )

    def test_malformed_rule_header(self) -> None:
        self.assertParseError("private\nprivate x", 'expected "rule", got "x"', 2)
        self.assertParseError("rule 1abc { condition: true }", 'invalid rule name "1"', 1)
        self.assertParseError("rule a :\n{ condition: true }", "expected a tag after ':'", 2)
        self.assertParseError("rule a\ncondition: true }", 'expected "{", got "condition"', 2)
        self.assertParseError("rule", "unexpected end of file, expected a rule name", 1)

    def test_invalid_meta(self) -> None:
        self.assertParseError(
            "rule a {\n meta:\n x = 1.5\n condition: true }", "meta value 1.5 is not an integer", 3
        )
        self.assertParseError(
            "rule a {\n meta:\n x = $a\n condition: true }", 'invalid value for meta "x": "$a"', 3
        )
        self.assertParseError(
            'rule a {\n meta:\n x "y"\n condition: true }',
            'expected "=" after meta identifier "x"',
            3,
        )
        self.assertParseError(
            'rule a {\n meta:\n x = "\\q"\n condition: true }',
            "invalid escape sequence \\q in string",
            3,
        )


class ParseRuleTextTests(SimpleTestCase):
    def test_imports_and_one_rule(self) -> None:
        rule = parse_rule_text('import "pe"\nimport "math"\n\nrule a : t { condition: pe.is_pe }')
        self.assertEqual((rule.name, rule.imports, rule.tags, rule.line), ("a", ["pe"], ["t"], 4))

    def test_parsed_line_maps_normalised_text_lines_back(self) -> None:
        text = (
            '// header\n\nimport "math"\nimport "pe"  // unused here\n\n'
            "// about a\nrule a {\n  condition:\n    math.entropy(0, 1) > 1\n}"
        )
        rule = parse_rule_text(text)
        self.assertEqual(rule.text.splitlines()[0], 'import "math"')
        self.assertEqual((rule.import_lines, rule.source_line), ([3], 6))
        # rule.text: 1 import "math", 2 blank, 3 // about a, 4 rule a {, ...
        self.assertEqual([rule.parsed_line(n) for n in range(1, 7)], [3, None, 6, 7, 8, 9])
        plain = parse_rule_text("\n\nrule b { condition: true }")
        self.assertEqual(plain.parsed_line(1), 3)

    def test_errors(self) -> None:
        cases = [
            ("// nothing", "no rule found", 1),
            (
                "rule a { condition: true }\nrule b { condition: true }",
                "only one rule can be edited at a time",
                2,
            ),
            (
                '\ninclude "x.yar"\nrule a { condition: true }',
                "include statements are not supported",
                2,
            ),
            ("rule a {", 'unterminated rule "a"', 1),
        ]
        for text, message, line in cases:
            with self.subTest(message=message), self.assertRaises(RuleParseError) as ctx:
                parse_rule_text(text)
            self.assertEqual((ctx.exception.message, ctx.exception.line), (message, line))
