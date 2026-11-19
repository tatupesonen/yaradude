import os
import shutil
import tempfile
import threading
from pathlib import Path
from unittest import mock

from django.apps import apps
from django.conf import settings
from django.core.files.uploadedfile import SimpleUploadedFile
from django.db import connection
from django.test import SimpleTestCase, TestCase, override_settings
from django.test.utils import CaptureQueriesContext

from rules.models import Rule
from rules.services import revision, scanner
from rules.services.compiler import check_ruleset
from rules.services.scanner import MAX_INSTANCES, ScanError, scan_sample
from rules.tests.helpers import make_ruleset

SAMPLE = b"MZ" + b"\x00" * 14 + b"hello world, hello again: hello hello hello hello!" + b"\x90" * 40


def sample(content: bytes = SAMPLE, name: str = "sample.exe") -> SimpleUploadedFile:
    return SimpleUploadedFile(name, content)


class ScannerTests(TestCase):
    """The scan contract (compiled set compiled per call, the test default)."""

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
        self.assertEqual(len(result.rulesets), 2)
        # Private rules are used but not counted or reported.
        self.assertEqual(result.rules_scanned, 4)
        self.assertEqual(result.unmapped, [])
        self.assertFalse(result.pending)

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

    def test_without_previews(self) -> None:
        result = scanner.scan_bytes(SAMPLE, "s", previews=False)
        greets = next(m for m in result.matches if m.ruleset == self.first)
        instance = greets.patterns[0].instances[0]
        self.assertEqual(
            (instance.offset, instance.length, instance.hex, instance.ascii), (16, 5, "", "")
        )

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
        self.assertEqual(result.rules_scanned, 2)
        self.assertEqual(result.left_out, [])  # "broken" is in the first ruleset

    def test_limit_by_path_and_tag(self) -> None:
        by_path = scanner.scan_bytes(SAMPLE, "sample.exe", scanner.limit_for(path="seco"))
        self.assertEqual({m.ruleset for m in by_path.matches}, {self.second})
        by_tag = scanner.scan_bytes(SAMPLE, "sample.exe", scanner.limit_for(tag="demo"))
        self.assertEqual(
            [(m.ruleset, m.rule.name) for m in by_tag.matches], [(self.first, "greets")]
        )
        self.assertEqual(by_tag.rules_scanned, 1)
        self.assertEqual(by_tag.left_out, [])
        none = scanner.scan_bytes(SAMPLE, "x", scanner.limit_for(path="first", tag="nope"))
        self.assertEqual(none.matches, [])

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

    def test_unmappable_match_is_skipped_and_reported(self) -> None:
        # Review finding 13.6: the stored name no longer matches the
        # identifier in the source (an edit behind the services' back).
        Rule.objects.filter(ruleset=self.second, name="greets").update(name="renamed")
        with self.assertLogs("rules.services.scanner", "WARNING"):
            result = scan_sample(sample())
        names = sorted((m.ruleset.name, m.rule.name) for m in result.matches)
        self.assertEqual(names, [("first", "greets"), ("second", "by_name")])
        self.assertEqual(result.unmapped, [f"{self.second.pk}:greets"])

    def test_match_of_a_rule_deleted_since_the_build_is_skipped(self) -> None:
        compiled = scanner.compiled_set()
        Rule.objects.filter(ruleset=self.second, name="greets").delete()
        with (
            mock.patch.object(scanner, "compiled_set", return_value=compiled),
            self.assertLogs("rules.services.scanner", "WARNING"),
        ):
            result = scan_sample(sample())
        self.assertNotIn(
            "greets", {m.rule.name for m in result.matches if m.ruleset == self.second}
        )
        self.assertEqual(len(result.unmapped), 1)

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
        with self.assertRaisesMessage(scanner.ScanTimeout, "stopped after 1 seconds"):
            scan_sample(sample(b"a" * 200_000), rulesets=[slow])

    def test_sample_is_never_persisted(self) -> None:
        counts = {model: model.objects.count() for model in apps.get_models()}
        with CaptureQueriesContext(connection) as queries:
            scan_sample(sample())
        self.assertTrue(all(q["sql"].lstrip().upper().startswith("SELECT") for q in queries))
        self.assertEqual(counts, {model: model.objects.count() for model in apps.get_models()})
        self.assertEqual(
            settings.FILE_UPLOAD_HANDLERS,
            ["django.core.files.uploadhandler.MemoryFileUploadHandler"],
        )

    def test_empty_database(self) -> None:
        Rule.objects.all().delete()
        result = scan_sample(sample())
        self.assertEqual((result.matches, result.rules_scanned, result.left_out), ([], 0, []))


class SubsetEqualsFilterTests(TestCase):
    """
    A limited scan uses the full set and filters the matches; that must equal
    compiling only the selected rulesets (global and private rules act only
    within their own namespace).
    """

    def test_every_selection_equals_compiling_the_subset(self) -> None:
        texts = {
            "a": "global rule small { condition: filesize < 100 }\n"
            'rule a1 { strings: $h = "hello" condition: $h }\n',
            "b": "private rule mz { condition: uint16(0) == 0x5A4D }\n"
            'rule b1 { strings: $h = "hello" condition: mz and $h }\n'
            'rule b2 { strings: $w = "world" condition: $w }\n',
            "c": 'rule c1 : t { strings: $h = "again" condition: $h }\n'
            "global rule nothing { condition: false }\n",
            "d": 'rule d1 : t { strings: $w = "world" condition: $w }\n',
        }
        rulesets = {name: make_ruleset(text, name=name) for name, text in texts.items()}
        for ruleset in rulesets.values():
            check_ruleset(ruleset)
        full = scanner.compiled_set()

        def keys(result: scanner.ScanResult) -> set[tuple[str, str]]:
            return {(m.ruleset.name, m.rule.name) for m in result.matches}

        selections = [["a"], ["b"], ["c"], ["d"], ["a", "b"], ["b", "d"], ["a", "c", "d"]]
        for names in selections:
            with self.subTest(names=names):
                chosen = [rulesets[n] for n in names]
                filtered = scanner.scan_bytes(SAMPLE, "s", scanner.limit_for(rulesets=chosen))
                # Compile only the subset: hide the other rulesets' rules.
                others = Rule.objects.exclude(ruleset__in=chosen)
                hidden = list(others.values_list("pk", flat=True))
                others.update(removed_at="2026-01-01T00:00Z")
                try:
                    subset = scanner.scan_bytes(SAMPLE, "s")
                finally:
                    Rule.objects.filter(pk__in=hidden).update(removed_at=None)
                self.assertEqual(keys(filtered), keys(subset))
                self.assertEqual(filtered.rules_scanned, subset.rules_scanned)
        self.assertEqual(full.info.rulesets, 4)
        # Tag filter: exactly the matches of the full scan that carry the tag.
        everything = scanner.scan_bytes(SAMPLE, "s")
        tagged = scanner.scan_bytes(SAMPLE, "s", scanner.limit_for(tag="t"))
        self.assertEqual(
            keys(tagged),
            {(m.ruleset.name, m.rule.name) for m in everything.matches if "t" in m.tags},
        )
        self.assertEqual(keys(tagged), {("d", "d1")})  # c1 is vetoed by its global rule


class CompiledSetMixin(SimpleTestCase):
    """The file-backed compiled set in a private directory."""

    def setUp(self) -> None:
        super().setUp()
        self.directory = Path(tempfile.mkdtemp(prefix="yaradude-compiled-test-"))
        self.override = override_settings(
            YARADUDE_SCAN_DIR=self.directory, YARADUDE_SCAN_COMPILED_CACHE=True
        )
        self.override.enable()
        scanner.forget_loaded_set()

    def tearDown(self) -> None:
        scanner.forget_loaded_set()
        self.override.disable()
        shutil.rmtree(self.directory, ignore_errors=True)
        super().tearDown()


class CompiledSetTests(CompiledSetMixin, TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.ruleset = make_ruleset(
            'rule hello : greet { strings: $h = "hello" condition: $h }\n'
            "rule loop { condition: for any i in (0..filesize) : (uint8(i) == 0x41) }\n"
            "rule slowpat { strings: $a = /a.*/ condition: $a }\n"
            "rule broken { condition: nope }\n",
            name="set",
        )
        check_ruleset(self.ruleset)
        revision.bump()

    def test_build_writes_the_file_and_scans_never_compile(self) -> None:
        outcome = scanner.build_compiled_set()
        assert outcome is not None
        self.assertTrue(outcome.built)
        self.assertEqual(outcome.info.revision, revision.current().number)
        self.assertEqual((outcome.info.rules, outcome.info.left_out), (3, 1))
        path = scanner.compiled_path()
        self.assertTrue(path.exists())
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        # Up to date: a second build does nothing.
        again = scanner.build_compiled_set()
        assert again is not None
        self.assertFalse(again.built)

        with (
            mock.patch.object(scanner, "_compile", side_effect=AssertionError("compiled")),
            CaptureQueriesContext(connection) as queries,
        ):
            result = scanner.scan_bytes(b"hello there", "x")
        self.assertEqual([m.rule.name for m in result.matches], ["hello"])
        self.assertEqual([r.name for r in result.left_out], ["broken"])
        # The revision, the matched rules, the left-out rules; no rule sources.
        self.assertEqual(len(queries), 3)
        for query in queries:
            self.assertNotIn('"rules_rule"."source"', query["sql"])
            self.assertNotIn("original_content", query["sql"])

    def test_first_start_without_a_file_builds_and_waits(self) -> None:
        self.assertFalse(scanner.compiled_path().exists())
        result = scanner.scan_bytes(b"hello", "x")
        self.assertEqual([m.rule.name for m in result.matches], ["hello"])
        self.assertTrue(scanner.compiled_path().exists())

    def test_stale_set_answers_at_once_and_says_newer_rules_are_pending(self) -> None:
        scanner.build_compiled_set()
        built = scanner.compiled_set()
        Rule.objects.filter(name="hello").update(
            source='rule hello { strings: $h = "bye" condition: $h }'
        )
        revision.bump()
        with mock.patch.object(scanner, "_compile", side_effect=AssertionError("compiled")):
            result = scanner.scan_bytes(b"hello", "x")
        self.assertTrue(result.pending)
        self.assertEqual(result.revision, built.info.revision)
        self.assertEqual(result.built_at, built.info.built_at)
        self.assertEqual([m.rule.name for m in result.matches], ["hello"])  # the old rule
        status = scanner.compiled_status()
        self.assertTrue(status.pending)
        self.assertEqual(status.current_revision, built.info.revision + 1)
        # The builder catches up; the next scan loads the new file.
        rebuilt = scanner.build_compiled_set()
        assert rebuilt is not None
        self.assertTrue(rebuilt.built)
        result = scanner.scan_bytes(b"hello", "x")
        self.assertFalse(result.pending)
        self.assertEqual(result.matches, [])
        self.assertFalse(scanner.compiled_status().pending)

    def test_engine_or_format_change_invalidates_the_file(self) -> None:
        scanner.build_compiled_set()
        for attribute, value in (("ENGINE_VERSION", "0.0.1"), ("FORMAT_VERSION", 999)):
            with self.subTest(attribute=attribute), mock.patch.object(scanner, attribute, value):
                scanner.forget_loaded_set()
                self.assertTrue(scanner.compiled_status().pending)
                self.assertFalse(scanner.compiled_status().available)
                outcome = scanner.build_compiled_set()
                assert outcome is not None
                self.assertTrue(outcome.built)
            scanner.build_compiled_set()  # back to the real key

    def test_compile_settings_change_invalidates_the_file(self) -> None:
        scanner.build_compiled_set()
        with override_settings(YARADUDE_RELAXED_RE_SYNTAX=True):
            self.assertTrue(scanner.compiled_status().pending)

    def test_crashed_build_leaves_the_previous_file(self) -> None:
        scanner.build_compiled_set()
        path = scanner.compiled_path()
        before = path.read_bytes()
        revision.bump()

        class Crash(Exception):
            pass

        def explode(self: object, file: object) -> None:
            raise Crash

        with mock.patch("yara_x.Rules.serialize_into", explode), self.assertRaises(Crash):
            scanner.build_compiled_set()
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(
            sorted(p.name for p in path.parent.iterdir()), ["build.lock", "rules.ydset"]
        )
        # Scans keep working from the previous set and say so.
        self.assertTrue(scanner.scan_bytes(b"hello", "x").pending)

    def test_leftover_temporary_files_are_removed_by_the_next_build(self) -> None:
        scanner.build_compiled_set()
        leftover = scanner.compiled_dir() / ".rules-crashed.tmp"
        leftover.write_bytes(b"partial")
        scanner.build_compiled_set(force=True)
        self.assertFalse(leftover.exists())

    def test_two_builds_never_run_at_once(self) -> None:
        holding = threading.Event()
        release = threading.Event()

        def hold_lock() -> None:
            with scanner._build_lock(wait=False, timeout=0) as acquired:
                assert acquired
                holding.set()
                release.wait(5)

        thread = threading.Thread(target=hold_lock)
        thread.start()
        try:
            holding.wait(5)
            self.assertTrue(scanner.build_running())
            self.assertIsNone(scanner.build_compiled_set())  # skipped, not waiting
            self.assertTrue(scanner.compiled_status().building)
            self.assertFalse(scanner.compiled_path().exists())
        finally:
            release.set()
            thread.join()
        self.assertFalse(scanner.build_running())
        self.assertIsNotNone(scanner.build_compiled_set())

    def test_a_waiting_build_proceeds_when_the_lock_is_released(self) -> None:
        started = threading.Event()

        def hold_briefly() -> None:
            with scanner._build_lock(wait=False, timeout=0):
                started.set()
                threading.Event().wait(0.3)

        thread = threading.Thread(target=hold_briefly)
        thread.start()
        started.wait(5)
        outcome = scanner.build_compiled_set(wait=True, timeout=5)
        thread.join()
        assert outcome is not None
        self.assertTrue(outcome.built)

    def test_slow_rules_are_listed(self) -> None:
        scanner.build_compiled_set()
        slow = scanner.slow_rules()
        self.assertEqual(
            sorted((s.name, s.code) for s in slow),
            [("loop", "potentially_slow_loop"), ("slowpat", "slow_pattern")],
        )
        self.assertTrue(all(s.ruleset_id == self.ruleset.pk for s in slow))
        info = scanner.compiled_status().set
        assert info is not None
        self.assertEqual(info.slow, 2)

    def test_status_without_a_set(self) -> None:
        status = scanner.compiled_status()
        self.assertFalse(status.available)
        self.assertTrue(status.pending)
        self.assertIsNone(status.revision)
        self.assertEqual(scanner.slow_rules(), [])
