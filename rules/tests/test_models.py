from django.db import IntegrityError
from django.test import TestCase
from django.utils import timezone

from rules.models import ImportRun, Rule, Ruleset
from rules.tests.helpers import make_ruleset


class RuleModelTests(TestCase):
    def setUp(self) -> None:
        self.ruleset = make_ruleset(
            'import "pe"\nrule a : t { condition: pe.is_pe }\nrule b { condition: filesize > 0 }\n'
        )
        self.a = Rule.objects.get(name="a")
        self.b = Rule.objects.get(name="b")

    def test_str_and_text(self) -> None:
        self.assertEqual(str(self.a), "a")
        self.assertEqual(str(self.ruleset), "test")
        self.assertEqual(self.a.text, 'import "pe"\n\nrule a : t { condition: pe.is_pe }\n')
        self.assertEqual(str(self.a.versions.get()), "a v1")

    def test_absolute_urls(self) -> None:
        version = self.a.versions.get()
        run = ImportRun.objects.create(origin=ImportRun.Origin.CLI, source="/r")
        self.assertEqual(self.a.get_absolute_url(), f"/rules/{self.a.pk}/")
        self.assertEqual(self.ruleset.get_absolute_url(), f"/rulesets/{self.ruleset.pk}/")
        self.assertEqual(version.get_absolute_url(), f"/rules/{self.a.pk}/versions/1/")
        self.assertEqual(run.get_absolute_url(), f"/import/runs/{run.pk}/")

    def test_queryset_helpers(self) -> None:
        Rule.objects.filter(pk=self.b.pk).update(
            removed_at=timezone.now(), compile_error="x", imported_sha256="0" * 64
        )
        self.assertEqual(list(Rule.objects.active()), [self.a])
        self.assertEqual(list(Rule.objects.removed()), [self.b])
        self.assertEqual(list(Rule.objects.failing()), [self.b])
        self.assertEqual(list(Rule.objects.modified()), [self.b])

    def test_status_properties(self) -> None:
        self.assertFalse(self.a.is_modified)  # manual rules are never "modified"
        self.a.imported_sha256 = self.a.sha256
        self.assertFalse(self.a.is_modified)
        self.a.imported_sha256 = "0" * 64
        self.assertTrue(self.a.is_modified)
        self.assertFalse(self.a.is_removed)
        self.assertTrue(self.a.compiles)

    def test_unique_name_per_ruleset(self) -> None:
        with self.assertRaises(IntegrityError):
            Rule.objects.create(ruleset=self.ruleset, name="a", source="", sha256="")

    def test_unique_ruleset_identity(self) -> None:
        Ruleset.objects.create(name="x", origin=Ruleset.Origin.UPLOAD, path="test")
        with self.assertRaises(IntegrityError):
            Ruleset.objects.create(name="y", origin=Ruleset.Origin.MANUAL, path="test")

    def test_import_run_summary(self) -> None:
        run = ImportRun(origin=ImportRun.Origin.CLI, source="/r", files_seen=2, rules_created=3)
        self.assertEqual(
            run.summary,
            "files: 2 seen, 0 changed, 0 unchanged, 0 failed; "
            "rules: 3 created, 0 updated, 0 removed, 0 unchanged",
        )
