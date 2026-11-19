import tempfile
from pathlib import Path

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import override_settings
from django.urls import reverse

from rules.models import ImportRun, Rule, Ruleset
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
        self.assertEqual(response.context["rules_dir_files"], 1)
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
        response = self.client.post(reverse("rules:import_upload"), {"files": files}, follow=True)
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
        response = self.client.post(reverse("rules:import_upload"), {"files": "/etc/passwd"})
        self.assertEqual(response.status_code, 400)
        self.assertFalse(Ruleset.objects.filter(path__contains="passwd").exists())


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
