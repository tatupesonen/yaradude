import tempfile
from pathlib import Path
from unittest import mock

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import override_settings
from django.urls import reverse

from rules.models import ImportFile, ImportRun, Rule, Ruleset
from rules.tests.test_views_common import ViewTestCase


class ImportPageTests(ViewTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        override = override_settings(YARADUDE_RULES_DIR=self.root)
        override.enable()
        self.addCleanup(override.disable)

    def test_page_shows_directory_status_and_history(self):
        (self.root / "a.yar").write_text("rule a { condition: true }")
        (self.root / ".hidden.yar").write_text("rule h { condition: true }")
        self.login(self.editor)
        response = self.client.get(reverse("rules:import"))
        self.assertEqual(response.context["rules_dir_status"].importable, 1)
        self.assertContains(response, "1 file to import")
        self.assertContains(response, "Scan and import")
        self.assertContains(response, "sample.yar")  # history row
        self.assertNotContains(response, "disabled>Scan and import")

    def test_missing_or_empty_directory_disables_scan(self):
        self.login(self.editor)
        response = self.client.get(reverse("rules:import"))
        self.assertContains(response, "No .yar / .yara files")
        self.assertContains(response, " disabled>Scan and import")
        response = self.client.post(reverse("rules:import_scan"), follow=True)
        self.assertContains(response, "contains no .yar or .yara files")
        with override_settings(YARADUDE_RULES_DIR=self.root / "missing"):
            response = self.client.get(reverse("rules:import"))
            self.assertContains(response, "Directory not found")
            response = self.client.post(reverse("rules:import_scan"), follow=True)
            self.assertContains(response, "does not exist")

    def test_viewer_sees_history_without_forms(self):
        self.login(self.viewer)
        response = self.client.get(reverse("rules:import"))
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "Scan and import")
        self.assertNotContains(response, 'type="file"')

    def test_directory_scan_imports_configured_directory(self):
        (self.root / "sub").mkdir()
        (self.root / "sub" / "x.yar").write_text("rule from_disk { condition: true }")
        self.login(self.editor)
        response = self.client.post(reverse("rules:import_scan"), {"path": "/etc"})
        run = ImportRun.objects.get(origin=ImportRun.Origin.SCAN)
        self.assertRedirects(response, run.get_absolute_url())
        self.assertEqual(run.user, self.editor)
        self.assertEqual(run.source, str(self.root.resolve()))
        self.assertTrue(Rule.objects.filter(name="from_disk", ruleset__path="sub/x.yar").exists())

    def test_upload_multiple_files(self):
        self.login(self.editor)
        files = [
            SimpleUploadedFile("one.yar", b"rule one { condition: true }"),
            SimpleUploadedFile("two.yara", b"rule two { condition: true }"),
            SimpleUploadedFile("bad.yar", b'rule bad { condition: "unterminated }'),
        ]
        response = self.client.post(
            reverse("rules:import_upload"), {"rule_files": files}, follow=True
        )
        run = ImportRun.objects.get(origin=ImportRun.Origin.UPLOAD, user=self.editor)
        self.assertRedirects(response, run.get_absolute_url())
        self.assertEqual(run.files_failed, 1)
        self.assertContains(response, "1 failed file")
        self.assertContains(response, "badge-error")
        self.assertTrue(Ruleset.objects.filter(path="one.yar").exists())
        self.assertTrue(Ruleset.objects.filter(path="two.yara").exists())

    def test_upload_without_files_is_a_form_error(self):
        self.login(self.editor)
        response = self.client.post(reverse("rules:import_upload"), {})
        self.assertEqual(response.status_code, 400)
        self.assertContains(response, "Choose at least one file", status_code=400)

    def test_upload_never_takes_a_server_path(self):
        self.login(self.editor)
        response = self.client.post(reverse("rules:import_upload"), {"rule_files": "/etc/passwd"})
        self.assertEqual(response.status_code, 400)
        self.assertFalse(Ruleset.objects.filter(path__contains="passwd").exists())

    @override_settings(YARADUDE_MAX_RULE_FILE_BYTES=200)
    def test_counts_agree_with_what_the_import_does(self):
        (self.root / "sub").mkdir()
        (self.root / "a.yar").write_text("rule a { condition: true }")
        (self.root / "sub" / "b.YARA").write_text("rule b { condition: true }")
        (self.root / "big.yar").write_text("// " + "x" * 300 + "\nrule big { condition: true }")
        (self.root / ".hidden.yar").write_text("rule h { condition: true }")
        (self.root / "notes.txt").write_text("not a rule file")
        outside = tempfile.TemporaryDirectory()
        self.addCleanup(outside.cleanup)
        target = Path(outside.name) / "elsewhere.yar"
        target.write_text("rule elsewhere { condition: true }")
        (self.root / "link.yar").symlink_to(target)

        self.login(self.editor)
        response = self.client.get(reverse("rules:import"))
        status = response.context["rules_dir_status"]
        self.assertEqual(status.importable, 2)
        self.assertEqual([f.identity for f in status.skipped], ["big.yar"])
        self.assertContains(response, "2 files to import")
        self.assertContains(response, "1 file will be skipped")
        self.assertContains(response, "File is larger than 200 bytes.")
        self.assertContains(response, "files over 200\xa0bytes are recorded as failed")

        self.client.post(reverse("rules:import_scan"))
        run = ImportRun.objects.get(origin=ImportRun.Origin.SCAN)
        self.assertEqual(run.files_seen, status.importable + len(status.skipped))
        self.assertEqual(run.files_failed, len(status.skipped))
        self.assertEqual(run.files_changed, status.importable)
        self.assertEqual(
            sorted(
                Ruleset.objects.filter(origin=Ruleset.Origin.DIRECTORY).values_list(
                    "path", flat=True
                )
            ),
            ["a.yar", "sub/b.YARA"],
        )
        self.assertEqual(run.files.get(status="failed").path, "big.yar")

    @override_settings(YARADUDE_MAX_RULE_FILE_BYTES=10)
    def test_directory_with_only_skipped_files_cannot_be_scanned(self):
        (self.root / "big.yar").write_text("rule big { condition: true }")
        self.login(self.editor)
        response = self.client.get(reverse("rules:import"))
        self.assertContains(response, "0 files to import")
        self.assertContains(response, " disabled>Scan and import")
        response = self.client.post(reverse("rules:import_scan"), follow=True)
        self.assertContains(response, "No rule file in the configured rules directory can be")
        self.assertFalse(ImportRun.objects.filter(origin=ImportRun.Origin.SCAN).exists())

    def test_upload_help_shows_the_configured_limit(self):
        self.login(self.editor)
        with override_settings(YARADUDE_MAX_RULE_FILE_BYTES=2 * 1024 * 1024):
            response = self.client.get(reverse("rules:import"))
        self.assertContains(response, "files, up to 2.0\xa0MB each")
        response = self.client.get(reverse("rules:import"))
        self.assertContains(response, "files, up to 4.0\xa0MB each")

    def test_viewer_page_does_not_list_the_directory(self):
        self.login(self.viewer)
        with mock.patch("rules.views.imports.importer.rule_files") as rule_files:
            self.client.get(reverse("rules:import"))
        rule_files.assert_not_called()


class ImportRunTests(ViewTestCase):
    def test_run_detail_lists_changed_and_failed_files(self):
        self.login(self.viewer)
        response = self.client.get(reverse("rules:import_run", args=[self.import_run.pk]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "bad.yar")
        self.assertContains(response, "line 1: oops")
        self.assertContains(response, self.ruleset.get_absolute_url())

    def test_unknown_run_is_404(self):
        self.login(self.viewer)
        self.assertEqual(self.client.get(reverse("rules:import_run", args=[999])).status_code, 404)


class SkippedCounterTests(ViewTestCase):
    def test_run_page_explains_skipped_files_and_rules(self):
        run = ImportRun.objects.create(
            origin=ImportRun.Origin.SCAN, source="/rules", files_skipped=1, rules_skipped=2
        )
        ImportFile.objects.create(
            run=run, path="gone.yar", status=ImportFile.Status.SKIPPED, rules_skipped=2
        )
        self.login(self.viewer)
        response = self.client.get(run.get_absolute_url())
        self.assertContains(response, "Skipped: deleted locally")
        self.assertContains(response, "1 file belongs to a deleted ruleset")
        self.assertContains(response, "2 rules are deleted here")
        self.assertContains(response, "gone.yar")
        response = self.client.get(reverse("rules:import"))
        self.assertContains(response, "+1 file")
