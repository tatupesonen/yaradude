from unittest import mock

from django.core.files.uploadedfile import SimpleUploadedFile
from django.db import connection
from django.test import override_settings
from django.test.utils import CaptureQueriesContext
from django.urls import reverse

from rules.services.scanner import ScanError
from rules.tests.helpers import make_ruleset
from rules.tests.test_views_common import ViewTestCase

SAMPLE = b"xx hello world yy MZ secret-sample-bytes"


class ScanViewTests(ViewTestCase):
    url = reverse("rules:scan")

    def setUp(self):
        self.login(self.viewer)

    def scan(self, data=SAMPLE, **extra):
        return self.client.post(
            self.url, {"sample": SimpleUploadedFile("sample.bin", data), **extra}
        )

    def test_form_shows_limit_summary(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Scanning with all 3 active rules in 1 ruleset.")
        response = self.client.get(self.url, {"path": "nothing-here/"})
        self.assertContains(response, "This limit covers 0 active rules")

    def test_scan_shows_matches_and_left_out_rules(self):
        response = self.scan()
        self.assertEqual(response.status_code, 200)
        result = response.context["result"]
        self.assertEqual([m.rule.name for m in result.matches], ["hello_world"])
        self.assertContains(response, "1 matching rule")
        self.assertContains(response, "$hello")
        self.assertContains(response, "68 65 6c 6c 6f")  # hex preview of "hello"
        self.assertContains(response, "left out")
        self.assertContains(response, "broken_rule")

    def test_limit_by_path(self):
        make_ruleset('rule other_hello { strings: $a = "hello" condition: $a }', name="dir/o.yar")
        response = self.scan(path="dir/")
        names = [m.rule.name for m in response.context["result"].matches]
        self.assertEqual(names, ["other_hello"])

    def test_scan_error_is_shown_on_the_form(self):
        with mock.patch("rules.views.scan.scan_sample", side_effect=ScanError("timed out")):
            response = self.scan()
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "timed out")
        self.assertNotIn("result", response.context)

    @override_settings(YARADUDE_SCAN_MAX_BYTES=10)
    def test_too_large_sample(self):
        response = self.scan()
        self.assertContains(response, "larger than the limit")

    def test_missing_sample(self):
        response = self.client.post(self.url, {})
        self.assertContains(response, "Choose a file to scan")

    def test_sample_is_not_stored(self):
        with CaptureQueriesContext(connection) as queries:
            self.scan()
        writes = [
            q["sql"]
            for q in queries
            if q["sql"].lstrip().upper().startswith(("INSERT", "UPDATE", "DELETE"))
        ]
        self.assertEqual(writes, [])
        self.assertFalse(any("secret-sample-bytes" in q["sql"] for q in queries))
