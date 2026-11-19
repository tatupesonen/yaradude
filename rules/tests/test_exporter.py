import io
import zipfile

from django.db.models import QuerySet
from django.test import SimpleTestCase, TestCase

from rules.models import Rule, Ruleset, RuleVersion
from rules.services.compiler import compiled_identifiers
from rules.services.diffing import diff_texts, diff_versions, previous_version
from rules.services.editing import update_rule
from rules.services.exporter import (
    export_combined,
    export_rule,
    export_ruleset,
    export_ruleset_original,
    export_zip,
    ruleset_filename,
)
from rules.services.highlight import highlight_yara
from rules.tests.helpers import make_ruleset

FIRST = """import "pe"

// Helper.
private rule is_pe_file { condition: pe.is_pe }

rule pe_dll : pe { condition: is_pe_file and pe.is_dll() }
rule gone { condition: filesize > 1 }
"""
SECOND = """import "math"
rule entropy { condition: math.entropy(0, filesize) > 7 }
rule shared_name { condition: filesize > 2 }
"""


class ExporterTests(TestCase):
    def setUp(self) -> None:
        self.first = make_ruleset(FIRST, name="malware/first.yar", origin=Ruleset.Origin.DIRECTORY)
        self.first.original_content = FIRST
        self.first.save()
        self.second = make_ruleset(SECOND, name="second.yara", origin=Ruleset.Origin.UPLOAD)
        Rule.objects.filter(name="gone").update(removed_at="2026-01-01T00:00Z")

    def rules(self) -> QuerySet[Rule]:
        return Rule.objects.select_related("ruleset")

    def test_single_rule(self) -> None:
        export = export_rule(Rule.objects.get(name="pe_dll"))
        self.assertEqual(export.filename, "pe_dll.yar")
        self.assertEqual(export.content_type, "text/plain; charset=utf-8")
        self.assertEqual(
            export.content.decode(),
            'import "pe"\n\nrule pe_dll : pe { condition: is_pe_file and pe.is_dll() }\n',
        )

    def test_ruleset_rebuilt_recompiles_and_skips_removed_rules(self) -> None:
        export = export_ruleset(self.first)
        self.assertEqual(export.filename, "first.yar")
        self.assertEqual(compiled_identifiers(export.content.decode()), ["is_pe_file", "pe_dll"])
        self.assertIn("// Helper.", export.content.decode())

    def test_ruleset_original_is_verbatim(self) -> None:
        export = export_ruleset_original(self.first)
        self.assertEqual(export.content.decode(), FIRST)

    def test_combined_recompiles(self) -> None:
        export = export_combined(self.rules())
        text = export.content.decode()
        self.assertEqual(export.filename, "yaradude-rules.yar")
        self.assertTrue(text.startswith("// Exported from yaradude: 4 rules from 2 rulesets.\n"))
        self.assertEqual(text.count('import "pe"'), 1)
        self.assertIn("// ---- malware/first.yar (Rules directory: malware/first.yar)", text)
        self.assertNotIn("WARNING", text)
        self.assertEqual(
            compiled_identifiers(text), ["is_pe_file", "pe_dll", "entropy", "shared_name"]
        )

    def test_combined_warns_about_duplicate_names(self) -> None:
        make_ruleset("rule shared_name { condition: filesize > 3 }", name="third")
        text = export_combined(self.rules()).content.decode()
        self.assertIn("WARNING: these rule names occur in more than one ruleset", text)
        self.assertIn("shared_name", text.splitlines()[1])
        self.assertIsNone(compiled_identifiers(text))

    def test_zip_has_one_compiling_file_per_ruleset(self) -> None:
        manual = make_ruleset("rule m { condition: filesize > 4 }", name="../../etc/x")
        export = export_zip(self.rules())
        self.assertEqual(
            (export.filename, export.content_type), ("yaradude-rules.zip", "application/zip")
        )
        archive = zipfile.ZipFile(io.BytesIO(export.content))
        self.assertEqual(sorted(archive.namelist()), ["malware/first.yar", "second.yara", "x.yar"])
        identifiers = {
            name: compiled_identifiers(archive.read(name).decode()) for name in archive.namelist()
        }
        self.assertEqual(
            identifiers,
            {
                "malware/first.yar": ["is_pe_file", "pe_dll"],
                "second.yara": ["entropy", "shared_name"],
                "x.yar": ["m"],
            },
        )
        self.assertEqual(ruleset_filename(manual), "x.yar")

    def test_zip_name_collisions(self) -> None:
        # A manual ruleset's file name is its base name; rulesets are written
        # in name order, so "dir/second.yara" claims "second.yara" first.
        make_ruleset("rule y { condition: filesize > 5 }", name="dir/second.yara")
        archive = zipfile.ZipFile(io.BytesIO(export_zip(self.rules()).content))
        self.assertEqual(
            sorted(archive.namelist()),
            ["malware/first.yar", f"second-{self.second.pk}.yara", "second.yara"],
        )

    def test_ruleset_filename(self) -> None:
        cases = [
            (Ruleset.Origin.DIRECTORY, "a/b/c.yar", True, "a/b/c.yar"),
            (Ruleset.Origin.DIRECTORY, "a/b/c.yar", False, "c.yar"),
            (Ruleset.Origin.DIRECTORY, "/abs/path/c.yara", True, "c.yara"),
            (Ruleset.Origin.DIRECTORY, "a/../../c.yar", True, "a/c.yar"),
            (Ruleset.Origin.MANUAL, "My rules", True, "My rules.yar"),
        ]
        for origin, path, keep, expected in cases:
            with self.subTest(path=path, keep=keep):
                ruleset = Ruleset(origin=origin, path=path, name=path)
                self.assertEqual(ruleset_filename(ruleset, keep_directories=keep), expected)


class ExportInjectionTests(TestCase):
    """Review finding 9: names and paths cannot inject text or odd member names."""

    def test_section_comment_cannot_inject_rules(self) -> None:
        evil = "x\nrule injected { condition: true }\r\u2028// "
        ruleset = make_ruleset("rule real { condition: filesize > 0 }", name=evil)
        ruleset.path = "a\nrule injected2 { condition: true }"
        ruleset.save()
        text = export_combined(Rule.objects.select_related("ruleset")).content.decode()
        self.assertEqual(compiled_identifiers(text), ["real"])
        section = [line for line in text.splitlines() if line.startswith("// ----")]
        self.assertEqual(len(section), 1)
        self.assertIn("rule injected { condition: true }", section[0])

    def test_member_names_are_safe(self) -> None:
        cases = [
            (Ruleset.Origin.DIRECTORY, "a\\..\\..\\evil.yar", True, "a_.._.._evil.yar"),
            (Ruleset.Origin.DIRECTORY, "dir/../../x\ny.yar", True, "dir/x_y.yar"),
            (Ruleset.Origin.DIRECTORY, "C:/windows/x.yar", True, "C_/windows/x.yar"),
            (Ruleset.Origin.UPLOAD, "..\\..\\up.yar", False, ".._.._up.yar"),
            (Ruleset.Origin.MANUAL, "..", False, "ruleset-None.yar"),
        ]
        for origin, path, keep, expected in cases:
            with self.subTest(path=path):
                ruleset = Ruleset(origin=origin, path=path, name=path)
                name = ruleset_filename(ruleset, keep_directories=keep)
                self.assertEqual(name, expected)
                self.assertNotIn("\\", name)
                self.assertFalse(any(part in ("", ".", "..") for part in name.split("/")))

    def test_zip_member_names_from_hostile_paths(self) -> None:
        make_ruleset(
            "rule m { condition: filesize > 4 }",
            name="..\\..\\x\n.yar",
            origin=Ruleset.Origin.DIRECTORY,
        )
        archive = zipfile.ZipFile(
            io.BytesIO(export_zip(Rule.objects.select_related("ruleset")).content)
        )
        self.assertEqual(archive.namelist(), [".._.._x_.yar"])


class HighlightTests(SimpleTestCase):
    def test_highlight(self) -> None:
        html = highlight_yara('rule a {\n  strings: $a = "<script>"\n  condition: $a\n}')
        self.assertTrue(html.startswith('<div class="highlight"><pre><span></span><code>'))
        self.assertIn('<span class="kd">rule</span>', html)
        self.assertIn("&lt;script&gt;", html)
        self.assertNotIn("<script>", html)
        self.assertNotIn("style=", html)

    def test_line_numbers(self) -> None:
        html = highlight_yara("rule a {\n  condition: true\n}", linenos=True)
        self.assertEqual(html.count('class="linenos"'), 3)
        self.assertNotIn("style=", html)


class DiffTests(TestCase):
    def test_diff_texts(self) -> None:
        old = "a\nb\nc\nd\ne\nf\ng\nh\ni\n"
        new = "a\nB\nc\nd\ne\nf\ng\nh\ni\nj\n"
        diff = diff_texts(old, new, context=1)
        self.assertEqual((diff.added, diff.removed, diff.changed), (2, 1, True))
        self.assertEqual(
            [(line.kind, line.text, line.old_number, line.new_number) for line in diff.lines],
            [
                ("hunk", "@@ -1,3 +1,3 @@", None, None),
                ("context", "a", 1, 1),
                ("removed", "b", 2, None),
                ("added", "B", None, 2),
                ("context", "c", 3, 3),
                ("hunk", "@@ -9,1 +9,2 @@", None, None),
                ("context", "i", 9, 9),
                ("added", "j", None, 10),
            ],
        )

    def test_identical(self) -> None:
        diff = diff_texts("x\n", "x\n")
        self.assertEqual((diff.lines, diff.changed), ([], False))

    def test_diff_versions(self) -> None:
        ruleset = make_ruleset("rule a { condition: filesize > 1 }")
        rule = Rule.objects.get()
        update_rule(rule, "rule a {\n  condition: filesize > 2\n}")
        first, second = rule.versions.get(number=1), rule.versions.get(number=2)
        self.assertIsNone(previous_version(first))
        self.assertEqual(previous_version(second), first)
        diff = diff_versions(first, second)
        self.assertEqual((diff.added, diff.removed), (3, 1))
        initial = diff_versions(None, first)
        self.assertEqual((initial.added, initial.removed), (1, 0))
        self.assertEqual(RuleVersion.objects.filter(rule__ruleset=ruleset).count(), 2)
