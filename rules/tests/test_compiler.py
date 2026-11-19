from pathlib import Path

import yara_x
from django.conf import settings
from django.test import TestCase, override_settings

from rules.models import Rule
from rules.services.compiler import (
    build_source,
    check_ruleset,
    compiled_identifiers,
    new_compiler,
    validate_edit,
)
from rules.services.parser import parse, parse_rule_text
from rules.tests.helpers import make_ruleset

EXAMPLES = Path(settings.BASE_DIR) / "yara-rules" / "examples"


class NewCompilerTests(TestCase):
    def test_include_is_refused_without_reading_the_file(self) -> None:
        for path in ((EXAMPLES / "documents.yar").resolve(), Path("/etc/passwd")):
            with self.subTest(path=path):
                compiler = new_compiler()
                with self.assertRaises(yara_x.CompileError):
                    compiler.add_source(f'include "{path}"\nrule a {{ condition: true }}')
                self.assertEqual(compiler.errors()[-1]["code"], "E044")
                # The included file holds valid rules; had it been read, they
                # would be in the compiled set. A failed source still adds its
                # other rules.
                self.assertEqual([r.identifier for r in compiler.build()], ["a"])

    def test_default_globals_are_defined(self) -> None:
        compiler = new_compiler()
        compiler.add_source(
            'rule g { condition: filename == "" and filepath == "" and extension == ""'
            ' and filetype == "" and owner == "" }'
        )
        rules = compiler.build()
        self.assertEqual(
            [m.identifier for m in yara_x.Scanner(rules).scan(b"").matching_rules], ["g"]
        )

    def test_relaxed_regex_syntax_setting(self) -> None:
        source = r"rule r { strings: $a = /a\Rb{/ condition: $a }"
        with self.assertRaises(yara_x.CompileError):
            new_compiler().add_source(source)
        with override_settings(YARADUDE_RELAXED_RE_SYNTAX=True):
            new_compiler().add_source(source)

    def test_compiled_identifiers(self) -> None:
        self.assertEqual(
            compiled_identifiers("rule b { condition: true }\nprivate rule a { condition: b }"),
            ["b", "a"],
        )
        self.assertIsNone(compiled_identifiers("rule b { condition: nope }"))
        self.assertIsNone(compiled_identifiers(f'include "{EXAMPLES / "documents.yar"}"'))


class ExampleFilesTests(TestCase):
    """The splitter agrees with YARA-X on every example file."""

    def test_examples_compile_and_split_like_yara_x(self) -> None:
        files = sorted(EXAMPLES.rglob("*.yar*"))
        self.assertGreaterEqual(len(files), 3)
        for path in files:
            with self.subTest(path=path.name):
                text = path.read_text()
                compiler = new_compiler()
                compiler.add_source(text)
                compiled = list(compiler.build())
                parsed = parse(text)
                self.assertEqual([r.identifier for r in compiled], [r.name for r in parsed.rules])
                for rule, parsed_rule in zip(compiled, parsed.rules, strict=True):
                    self.assertEqual(list(rule.tags), parsed_rule.tags)
                    metadata = [
                        (key, value.decode() if isinstance(value, bytes) else value)
                        for key, value in rule.metadata
                    ]
                    self.assertEqual(metadata, parsed_rule.meta)


class CheckRulesetTests(TestCase):
    def test_compiling_ruleset(self) -> None:
        ruleset = make_ruleset(
            'import "pe"\n'
            "private rule p { condition: uint16(0) == 0x5A4D }\n"
            "rule a : t { condition: p and pe.is_pe }\n"
        )
        check = check_ruleset(ruleset)
        self.assertTrue(check.ok)
        self.assertEqual(check.summary, "")
        ruleset.refresh_from_db()
        self.assertEqual(ruleset.compile_error, "")
        self.assertFalse(Rule.objects.failing().exists())

    def test_each_failing_rule_has_its_own_error_with_rule_relative_line(self) -> None:
        ruleset = make_ruleset(
            'import "pe"\n'
            "rule ok1 { condition: true }\n"
            "rule bad1 {\n"
            "    condition:\n"
            "        pe.is_pe and nope\n"
            "}\n"
            "rule ok2 { condition: ok1 }\n"
            "rule bad2 {\n"
            "    strings:\n"
            '        $unused = "abc"\n'
            "    condition:\n"
            "        true\n"
            "}\n"
        )
        check = check_ruleset(ruleset)
        rules = {rule.name: rule for rule in Rule.objects.all()}
        self.assertEqual(sorted(r.name for r in check.failing), ["bad1", "bad2"])
        self.assertEqual(rules["ok1"].compile_error, "")
        self.assertEqual(rules["ok2"].compile_error, "")

        # bad1's text is 'import "pe"', a blank line, then the rule: the
        # error on the rule's third line is line 5 of its text.
        self.assertIn("error[E009]: unknown identifier `nope`", rules["bad1"].compile_error)
        self.assertIn("--> bad1:5:", rules["bad1"].compile_error)
        self.assertEqual(check.diagnostics[rules["bad1"]].line, 5)
        self.assertIn("E022", rules["bad2"].compile_error)
        self.assertEqual(check.diagnostics[rules["bad2"]].line, 3)

        ruleset.refresh_from_db()
        self.assertEqual(ruleset.compile_error, "2 of 4 rules do not compile: bad1, bad2")

    def test_errors_are_cleared_once_fixed(self) -> None:
        ruleset = make_ruleset("rule a { condition: nope }")
        check_ruleset(ruleset)
        rule = Rule.objects.get()
        self.assertNotEqual(rule.compile_error, "")
        Rule.objects.filter(pk=rule.pk).update(source="rule a { condition: true }")
        check_ruleset(ruleset)
        rule.refresh_from_db()
        ruleset.refresh_from_db()
        self.assertEqual((rule.compile_error, ruleset.compile_error), ("", ""))

    def test_rule_depending_on_failing_rule_says_so(self) -> None:
        ruleset = make_ruleset(
            "private rule base { condition: nope }\nrule user { condition: base }\n"
        )
        check_ruleset(ruleset)
        user = Rule.objects.get(name="user")
        self.assertTrue(
            user.compile_error.startswith('depends on rule "base", which does not compile')
        )

    def test_forward_reference_fails(self) -> None:
        ruleset = make_ruleset("rule a { condition: b }\nrule b { condition: true }\n")
        check = check_ruleset(ruleset)
        self.assertEqual([r.name for r in check.failing], ["a"])

    def test_warnings_are_stored_per_rule(self) -> None:
        ruleset = make_ruleset(
            'rule slow { strings: $a = "a" condition: $a }\n'
            "rule clean { condition: filesize > 0 }\n"
            "rule odd { condition: true and 1 }\n"
        )
        check_ruleset(ruleset)
        rules = {rule.name: rule for rule in Rule.objects.all()}
        self.assertEqual(len(rules["slow"].compile_warnings), 1)
        self.assertIn("slow pattern", rules["slow"].compile_warnings[0])
        self.assertEqual(rules["clean"].compile_warnings, [])
        self.assertEqual(len(rules["odd"].compile_warnings), 2)
        self.assertTrue(all(rule.compile_error == "" for rule in rules.values()))

    def test_unknown_module(self) -> None:
        ruleset = make_ruleset(
            'import "magic"\nimport "cuckoo"\n'
            'rule m { condition: magic.type() == "x" }\n'
            "rule c { condition: cuckoo.network.host(/x/) }\n"
        )
        check = check_ruleset(ruleset)
        self.assertEqual([r.name for r in check.failing], ["m"])
        # Used as well as imported, the unavailable module is reported where
        # it is used (E009); imported only, it is E010 on the import line.
        self.assertIn("unknown identifier `magic`", Rule.objects.get(name="m").compile_error)

    def test_unavailable_module_import_only(self) -> None:
        compiler = new_compiler()
        with self.assertRaises(yara_x.CompileError):
            compiler.add_source('import "magic"\nrule a { condition: filesize > 0 }')
        self.assertEqual(
            (compiler.errors()[-1]["code"], compiler.errors()[-1]["line"]), ("E010", 1)
        )

    def test_default_globals(self) -> None:
        ruleset = make_ruleset("rule f { condition: filename matches /\\.exe$/ }")
        self.assertTrue(check_ruleset(ruleset).ok)
        with override_settings(YARADUDE_GLOBALS={}):
            self.assertFalse(check_ruleset(ruleset).ok)

    def test_module_used_without_its_own_import(self) -> None:
        # The second rule would compile after the first rule's import, but not
        # on its own.
        ruleset = make_ruleset(
            'import "pe"\nrule a { condition: pe.is_pe }\nrule b { condition: true }'
        )
        Rule.objects.filter(name="b").update(source="rule b { condition: pe.is_dll() }")
        check = check_ruleset(ruleset)
        self.assertEqual([r.name for r in check.failing], ["b"])
        self.assertEqual(
            Rule.objects.get(name="b").compile_error, 'module "pe" is used but not imported'
        )

    def test_removed_rules_are_not_compiled(self) -> None:
        ruleset = make_ruleset("rule a { condition: nope }\nrule b { condition: true }")
        check_ruleset(ruleset)
        Rule.objects.filter(name="a").update(removed_at="2026-01-01T00:00Z")
        check = check_ruleset(ruleset)
        self.assertTrue(check.ok)
        self.assertEqual(Rule.objects.get(name="a").compile_error, "")

    def test_build_source(self) -> None:
        ruleset = make_ruleset(
            'import "pe"\nimport "math"\n'
            "rule a { condition: pe.is_pe }\n"
            "rule b { condition: pe.is_dll() and math.entropy(0, 1) > 1 }\n"
            "rule gone { condition: true }\n"
        )
        Rule.objects.filter(name="gone").update(removed_at="2026-01-01T00:00Z")
        source = build_source(ruleset)
        self.assertEqual(
            source,
            'import "pe"\nimport "math"\n\n'
            "rule a { condition: pe.is_pe }\n\n"
            "rule b { condition: pe.is_dll() and math.entropy(0, 1) > 1 }\n",
        )
        self.assertEqual(compiled_identifiers(source), ["a", "b"])


class ValidateEditTests(TestCase):
    def setUp(self) -> None:
        self.ruleset = make_ruleset(
            "private rule base { condition: uint8(0) == 0x4D }\n"
            "rule uses_base { condition: base }\n"
            "rule other { condition: true }\n"
        )
        check_ruleset(self.ruleset)
        self.base = Rule.objects.get(name="base")

    def test_valid_edit(self) -> None:
        parsed = parse_rule_text("private rule base { condition: uint8(0) == 0x5A }")
        result = validate_edit(self.ruleset, self.base, parsed)
        self.assertTrue(result.ok)
        self.assertEqual(result.broken, [])

    def test_error_in_this_rule_with_editor_relative_line(self) -> None:
        parsed = parse_rule_text('import "pe"\n\nrule base {\n  condition:\n    nope\n}')
        result = validate_edit(self.ruleset, self.base, parsed)
        self.assertFalse(result.ok)
        self.assertEqual(result.line, 5)
        self.assertIn("unknown identifier `nope`", result.error)

    def test_edit_that_breaks_a_sibling(self) -> None:
        parsed = parse_rule_text("private rule renamed { condition: true }")
        result = validate_edit(self.ruleset, self.base, parsed)
        self.assertTrue(result.ok)
        self.assertEqual([b.rule.name for b in result.broken], ["uses_base"])
        self.assertIn("unknown identifier `base`", result.broken[0].error)

    def test_already_failing_sibling_is_not_reported_as_broken(self) -> None:
        Rule.objects.filter(name="other").update(source="rule other { condition: nope }")
        check_ruleset(self.ruleset)
        parsed = parse_rule_text("private rule base { condition: true }")
        result = validate_edit(self.ruleset, self.base, parsed)
        self.assertTrue(result.ok)
        self.assertEqual(result.broken, [])

    def test_new_rule_is_compiled_after_existing_rules(self) -> None:
        parsed = parse_rule_text("rule new { condition: base and uses_base }")
        self.assertTrue(validate_edit(self.ruleset, None, parsed).ok)

    def test_edit_cannot_reference_a_later_rule(self) -> None:
        parsed = parse_rule_text("private rule base { condition: other }")
        result = validate_edit(self.ruleset, self.base, parsed)
        self.assertFalse(result.ok)

    def test_error_in_earlier_rule_does_not_hide_error_in_edited_rule(self) -> None:
        Rule.objects.filter(name="base").update(source="private rule base { condition: nope }")
        other = Rule.objects.get(name="other")
        parsed = parse_rule_text("rule other { condition: also_nope }")
        result = validate_edit(self.ruleset, other, parsed)
        self.assertIn("also_nope", result.error)

    def test_does_not_write(self) -> None:
        parsed = parse_rule_text("private rule base { condition: nope }")
        validate_edit(self.ruleset, self.base, parsed)
        self.base.refresh_from_db()
        self.assertEqual(self.base.compile_error, "")
        self.assertIn("0x4D", self.base.source)
