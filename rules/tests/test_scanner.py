from django.apps import apps
from django.conf import settings
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings

from rules.models import Rule
from rules.services.compiler import check_ruleset
from rules.services.scanner import MAX_INSTANCES, ScanError, scan_sample
from rules.tests.helpers import make_ruleset

SAMPLE = b"MZ" + b"\x00" * 14 + b"hello world, hello again: hello hello hello hello!" + b"\x90" * 40


def sample(content: bytes = SAMPLE, name: str = "sample.exe") -> SimpleUploadedFile:
    return SimpleUploadedFile(name, content)


class ScannerTests(TestCase):
    def setUp(self) -> None:
        self.first = make_ruleset(
            "private rule is_mz { condition: uint16(0) == 0x5A4D }\n"
            "rule greets : text demo {\n"
            '  strings:\n    $hello = "hello"\n    $nop = { 90 [32] 90 }\n'
            "  condition:\n    is_mz and $hello and $nop\n}\n"
            'rule absent { strings: $x = "not in the sample" condition: $x }\n'
            "rule broken { condition: nope }\n",
            name="first",
        )
        self.second = make_ruleset(
            # Same rule name as in the first ruleset: one namespace per ruleset.
            'rule greets { strings: $h = "world" condition: $h }\n'
            'rule by_name { condition: filename == "sample.exe" and extension == ".exe" }\n',
            name="second",
        )
        check_ruleset(self.first)
        check_ruleset(self.second)

    def test_matches_are_mapped_back_to_rules(self) -> None:
        result = scan_sample(sample())
        matched = sorted((m.rule.ruleset.name, m.rule.name) for m in result.matches)
        self.assertEqual(
            matched, [("first", "greets"), ("second", "by_name"), ("second", "greets")]
        )
        first_greets = next(m for m in result.matches if m.ruleset == self.first)
        self.assertEqual(first_greets.rule, Rule.objects.get(ruleset=self.first, name="greets"))
        self.assertEqual(first_greets.tags, ["text", "demo"])
        self.assertEqual(result.sample_name, "sample.exe")
        self.assertEqual(result.sample_size, len(SAMPLE))
        self.assertEqual(len(result.sample_sha256), 64)
        self.assertEqual([r.name for r in result.rulesets], ["first", "second"])
        # Private rules are used but not counted or reported.
        self.assertEqual(result.rules_scanned, 4)

    def test_string_instances(self) -> None:
        result = scan_sample(sample())
        greets = next(m for m in result.matches if m.ruleset == self.first)
        hello, nop = greets.patterns
        self.assertEqual((hello.identifier, hello.count), ("$hello", 6))
        self.assertEqual(len(hello.instances), MAX_INSTANCES)
        first = hello.instances[0]
        self.assertEqual((first.offset, first.length), (16, 5))
        self.assertEqual(
            (first.hex, first.ascii, first.truncated), ("68 65 6c 6c 6f", "hello", False)
        )
        self.assertEqual(nop.identifier, "$nop")
        long_match = nop.instances[0]
        self.assertEqual(long_match.length, 34)
        self.assertTrue(long_match.truncated)
        self.assertEqual(long_match.ascii, "." * 32)
        self.assertEqual(long_match.hex, " ".join(["90"] * 32))

    def test_patterns_without_matches_are_omitted(self) -> None:
        Rule.objects.filter(ruleset=self.second, name="greets").update(
            source='rule greets { strings: $h = "world" $z = "zzz" condition: $h or $z }'
        )
        result = scan_sample(sample(), rulesets=[self.second])
        greets = next(m for m in result.matches if m.rule.name == "greets")
        self.assertEqual([p.identifier for p in greets.patterns], ["$h"])

    def test_selected_rulesets(self) -> None:
        result = scan_sample(sample(), rulesets=[self.second])
        self.assertEqual({m.ruleset for m in result.matches}, {self.second})
        self.assertEqual(result.rulesets, [self.second])

    def test_non_compiling_rules_are_left_out_and_listed(self) -> None:
        result = scan_sample(sample())
        self.assertEqual([r.name for r in result.left_out], ["broken"])

    def test_stale_compile_status_and_dependents_are_left_out(self) -> None:
        # Break the private rule without re-checking: the scanner finds out
        # itself, and the rule depending on it is left out too.
        Rule.objects.filter(name="is_mz").update(source="private rule is_mz { condition: nope }")
        result = scan_sample(sample(), rulesets=[self.first])
        self.assertEqual(sorted(r.name for r in result.left_out), ["broken", "greets", "is_mz"])
        self.assertEqual(result.matches, [])

    def test_removed_rules_are_not_used(self) -> None:
        Rule.objects.filter(ruleset=self.second).update(removed_at="2026-01-01T00:00Z")
        result = scan_sample(sample())
        self.assertNotIn(self.second, {m.ruleset for m in result.matches})
        self.assertEqual(result.rulesets, [self.first])

    def test_global_rule_applies_to_its_ruleset_only(self) -> None:
        global_set = make_ruleset(
            "global rule tiny { condition: filesize < 10 }\n"
            'rule also_greets { strings: $h = "hello" condition: $h }\n',
            name="global",
        )
        check_ruleset(global_set)
        result = scan_sample(sample())
        names = {(m.ruleset.name, m.rule.name) for m in result.matches}
        self.assertNotIn(("global", "also_greets"), names)
        self.assertIn(("first", "greets"), names)

    @override_settings(YARADUDE_SCAN_MAX_BYTES=10)
    def test_size_limit(self) -> None:
        with self.assertRaisesMessage(ScanError, "larger than the limit of 10"):
            scan_sample(sample())
        scan_sample(sample(b"0123456789"))

    @override_settings(YARADUDE_SCAN_TIMEOUT=1)
    def test_timeout(self) -> None:
        slow = make_ruleset(
            "rule slow { condition: for all i in (0..filesize) : "
            "( for all j in (0..filesize) : ( uint8(i) != uint8(j) or i >= 0 ) ) }",
            name="slow",
        )
        check_ruleset(slow)
        with self.assertRaisesMessage(ScanError, "stopped after 1 seconds"):
            scan_sample(sample(b"a" * 200_000), rulesets=[slow])

    def test_sample_is_never_persisted(self) -> None:
        counts = {model: model.objects.count() for model in apps.get_models()}
        # One read query for the rules, nothing written.
        with self.assertNumQueries(1):
            scan_sample(sample())
        self.assertEqual(counts, {model: model.objects.count() for model in apps.get_models()})
        self.assertEqual(
            settings.FILE_UPLOAD_HANDLERS,
            ["django.core.files.uploadhandler.MemoryFileUploadHandler"],
        )

    def test_empty_database(self) -> None:
        Rule.objects.all().delete()
        result = scan_sample(sample())
        self.assertEqual((result.matches, result.rules_scanned, result.left_out), ([], 0, []))
