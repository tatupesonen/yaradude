import io
import zipfile

from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.urls import reverse

from rules.models import Rule, RuleVersion, Ruleset
from rules.services import editing
from rules.tests.helpers import make_ruleset
from rules.tests.test_views_common import ViewTestCase

NEW_RULE = 'rule fresh_rule : fresh\n{\n    strings:\n        $a = "fresh"\n    condition:\n        $a\n}\n'


class RuleListTests(ViewTestCase):
    url = reverse("rules:rule_list")

    def names(self, response):
        return [rule.name for rule in response.context["page"].object_list]

    def setUp(self):
        self.login(self.viewer)

    def test_lists_active_rules_by_name(self):
        response = self.client.get(self.url)
        self.assertEqual(self.names(response), ["broken_rule", "hello_world", "pe_rule"])
        self.assertContains(response, "badge-error")

    def test_search_covers_name_description_author_source(self):
        for term, expected in (
            ("HELLO", ["hello_world"]),
            ("friendly greeting", ["hello_world"]),
            ("yaradude tests", ["hello_world"]),
            ("no_such_identifier", ["broken_rule"]),
        ):
            with self.subTest(term=term):
                response = self.client.get(self.url, {"q": term})
                self.assertEqual(self.names(response), expected)

    def test_filters(self):
        other = make_ruleset("rule other_rule : demo { condition: true }", name="other")
        cases = [
            ({"ruleset": other.pk}, ["other_rule"]),
            ({"tag": "greeting"}, ["hello_world"]),
            ({"tag": "demo"}, ["hello_world", "other_rule", "pe_rule"]),
            ({"status": "error"}, ["broken_rule"]),
        ]
        for params, expected in cases:
            with self.subTest(params=params):
                self.assertEqual(self.names(self.client.get(self.url, params)), expected)

    def test_status_filters_modified_removed_warnings(self):
        Rule.objects.filter(pk=self.hello.pk).update(imported_sha256="0" * 64)
        Rule.objects.filter(pk=self.pe_rule.pk).update(removed_at="2026-01-01T00:00:00Z")
        Rule.objects.filter(pk=self.broken.pk).update(
            compile_error="", compile_warnings=["warning: slow"]
        )
        self.assertEqual(self.names(self.client.get(self.url, {"status": "modified"})), ["hello_world"])
        self.assertEqual(self.names(self.client.get(self.url, {"status": "removed"})), ["pe_rule"])
        self.assertEqual(
            self.names(self.client.get(self.url, {"status": "warnings"})), ["broken_rule"]
        )
        self.assertNotIn("pe_rule", self.names(self.client.get(self.url)))
        self.assertIn("pe_rule", self.names(self.client.get(self.url, {"status": "all"})))
        response = self.client.get(self.url, {"status": "all"})
        self.assertContains(response, "badge-modified")
        self.assertContains(response, "badge-removed")
        self.assertContains(response, "badge-warn")

    def test_sort(self):
        self.assertEqual(
            self.names(self.client.get(self.url, {"sort": "-name"})),
            ["pe_rule", "hello_world", "broken_rule"],
        )
        Rule.objects.filter(pk=self.broken.pk).update(updated_at="2020-01-01T00:00:00Z")
        self.assertEqual(self.names(self.client.get(self.url, {"sort": "updated"}))[0], "broken_rule")

    def test_invalid_parameters_fall_back_to_defaults(self):
        response = self.client.get(
            self.url, {"sort": "bogus", "status": "bogus", "ruleset": "x", "page": "zz"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(self.names(response)), 3)

    def test_pagination(self):
        text = "\n".join(f"rule many_{i:03d} {{ condition: true }}" for i in range(230))
        make_ruleset(text, name="many")
        response = self.client.get(self.url, {"q": "many_"})
        page = response.context["page"]
        self.assertEqual(page.paginator.count, 230)
        self.assertEqual(len(page.object_list), 100)
        self.assertContains(response, "of 3</span>")
        response = self.client.get(self.url, {"q": "many_", "page": 3})
        self.assertEqual(self.names(response)[0], "many_200")
        self.assertContains(response, "q=many_&amp;page=2")

    def test_query_count_does_not_grow_with_rows(self):
        def count_queries():
            with CaptureQueriesContext(connection) as queries:
                response = self.client.get(self.url, {"status": "all"})
            self.assertEqual(response.status_code, 200)
            return len(queries)

        few = count_queries()
        text = "\n".join(f"rule bulk_{i:03d} : t{i % 7} {{ condition: true }}" for i in range(80))
        make_ruleset(text, name="bulk")
        self.assertEqual(count_queries(), few)
        self.assertLessEqual(few, 12)

    def test_empty_state_points_to_import(self):
        Ruleset.objects.all().delete()
        self.login(self.editor)
        response = self.client.get(self.url)
        self.assertContains(response, "No rules yet")
        self.assertContains(response, reverse("rules:import"))

    def test_no_match_state(self):
        response = self.client.get(self.url, {"q": "nothing-matches-this"})
        self.assertContains(response, "No rules match these filters.")


class RuleDetailTests(ViewTestCase):
    def setUp(self):
        self.login(self.viewer)

    def test_detail_shows_source_meta_tags_and_versions(self):
        response = self.client.get(self.hello.get_absolute_url())
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, '<div class="highlight">')
        self.assertContains(response, "Finds a friendly greeting")
        self.assertContains(response, ">true<")  # bool meta rendered as YARA writes it
        self.assertContains(response, "greeting")
        self.assertContains(response, ">pe<", html=False) if self.hello.imports else None
        self.assertContains(response, reverse("rules:rule_version", args=[self.hello.pk, 1]))
        self.assertContains(response, "badge-ok")
        self.assertContains(response, self.hello.sha256)

    def test_detail_of_failing_rule_shows_diagnostic(self):
        response = self.client.get(self.broken.get_absolute_url())
        self.assertContains(response, '<pre class="diagnostic">')
        self.assertContains(response, "no_such_identifier")

    def test_removed_rule_is_flagged(self):
        Rule.objects.filter(pk=self.hello.pk).update(removed_at="2026-01-01T00:00:00Z")
        response = self.client.get(self.hello.get_absolute_url())
        self.assertContains(response, "dropped from its source file")

    def test_download(self):
        response = self.client.get(reverse("rules:rule_download", args=[self.hello.pk]))
        self.assertEqual(response["Content-Disposition"], 'attachment; filename="hello_world.yar"')
        self.assertEqual(response.content.decode(), self.hello.text)

    def test_version_page_with_diff(self):
        self.login(self.editor)
        editing.update_rule(self.hello, self.hello.text.replace("hello world", "hello there"))
        response = self.client.get(reverse("rules:rule_version", args=[self.hello.pk, 2]))
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.context["diff"].changed)
        self.assertContains(response, '<tr class="added">')
        self.assertContains(response, '<tr class="removed">')
        self.assertTrue(response.context["is_current"])
        self.assertNotContains(response, "Restore this version")
        response = self.client.get(reverse("rules:rule_version", args=[self.hello.pk, 1]))
        self.assertContains(response, "Restore this version")
        self.assertContains(response, "First version")

    def test_unknown_version_is_404(self):
        response = self.client.get(reverse("rules:rule_version", args=[self.hello.pk, 9]))
        self.assertEqual(response.status_code, 404)


class RuleEditorTests(ViewTestCase):
    def setUp(self):
        self.login(self.editor)

    def test_create_form_preselects_ruleset(self):
        response = self.client.get(reverse("rules:rule_create"), {"ruleset": self.ruleset.pk})
        self.assertContains(response, f'<option value="{self.ruleset.pk}" selected>')

    def test_validate_does_not_save(self):
        response = self.client.post(
            reverse("rules:rule_create"),
            {"ruleset": self.ruleset.pk, "text": NEW_RULE, "action": "validate"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.context["result"].ok)
        self.assertContains(response, "Not saved yet.")
        self.assertFalse(Rule.objects.filter(name="fresh_rule").exists())

    def test_create_into_existing_ruleset(self):
        response = self.client.post(
            reverse("rules:rule_create"),
            {"ruleset": self.ruleset.pk, "text": NEW_RULE, "action": "save"},
        )
        rule = Rule.objects.get(name="fresh_rule")
        self.assertRedirects(response, rule.get_absolute_url())
        self.assertEqual(rule.ruleset, self.ruleset)
        self.assertEqual(rule.versions.get().created_by, self.editor)

    def test_create_into_new_collection(self):
        response = self.client.post(
            reverse("rules:rule_create"),
            {"ruleset": "new", "new_ruleset": "My rules", "text": NEW_RULE, "action": "save"},
        )
        rule = Rule.objects.get(name="fresh_rule")
        self.assertRedirects(response, rule.get_absolute_url())
        self.assertEqual(rule.ruleset.origin, Ruleset.Origin.MANUAL)
        self.assertEqual(rule.ruleset.name, "My rules")

    def test_new_collection_needs_a_name(self):
        response = self.client.post(
            reverse("rules:rule_create"), {"ruleset": "new", "text": NEW_RULE, "action": "save"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertFormError(response.context["form"], "new_ruleset", "Name the new collection.")

    def test_invalid_rule_in_new_collection_creates_nothing(self):
        response = self.client.post(
            reverse("rules:rule_create"),
            {"ruleset": "new", "new_ruleset": "Empty", "text": "rule x {", "action": "save"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(Ruleset.objects.filter(name="Empty").exists())

    def test_save_refused_when_rule_does_not_compile(self):
        text = "rule bad_one { condition: nope_nope }"
        response = self.client.post(
            reverse("rules:rule_create"), {"ruleset": self.ruleset.pk, "text": text, "action": "save"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.context["result"].ok)
        self.assertContains(response, "Not saved")
        self.assertContains(response, "nope_nope")
        self.assertFalse(Rule.objects.filter(name="bad_one").exists())

    def test_name_clash_refused(self):
        response = self.client.post(
            reverse("rules:rule_create"),
            {"ruleset": self.ruleset.pk, "text": "rule pe_rule { condition: true }", "action": "save"},
        )
        self.assertContains(response, "already exists")

    def test_empty_text_is_a_form_error(self):
        response = self.client.post(
            reverse("rules:rule_create"), {"ruleset": self.ruleset.pk, "text": "  ", "action": "save"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.context["form"].errors)

    def test_edit_form_holds_current_text_and_version(self):
        response = self.client.get(reverse("rules:rule_edit", args=[self.hello.pk]))
        self.assertContains(response, "hello world")
        self.assertContains(response, 'name="version" value="1"')

    def test_edit_saves_new_version(self):
        text = self.hello.text.replace("hello world", "hello there")
        response = self.client.post(
            reverse("rules:rule_edit", args=[self.hello.pk]),
            {"text": text, "version": 1, "action": "save"},
        )
        self.assertRedirects(response, self.hello.get_absolute_url())
        self.hello.refresh_from_db()
        self.assertEqual(self.hello.version, 2)
        self.assertEqual(self.hello.versions.get(number=2).origin, RuleVersion.Origin.EDIT)

    def test_edit_without_change_saves_nothing(self):
        response = self.client.post(
            reverse("rules:rule_edit", args=[self.hello.pk]),
            {"text": self.hello.text, "version": 1, "action": "save"},
            follow=True,
        )
        self.assertContains(response, "No changes to save.")
        self.hello.refresh_from_db()
        self.assertEqual(self.hello.version, 1)

    def test_stale_edit_is_refused(self):
        editing.update_rule(self.hello, self.hello.text.replace("hello world", "hi"))
        response = self.client.post(
            reverse("rules:rule_edit", args=[self.hello.pk]),
            {"text": self.hello.text.replace("hello world", "yo"), "version": 1, "action": "save"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "was changed (now version 2)")
        self.hello.refresh_from_db()
        self.assertEqual(self.hello.version, 2)

    def test_edit_that_breaks_a_sibling_warns(self):
        ruleset = make_ruleset(
            "rule base_rule { condition: true }\nrule user_rule { condition: base_rule }",
            name="deps",
        )
        from rules.services.compiler import check_ruleset

        check_ruleset(ruleset)
        base = Rule.objects.get(name="base_rule")
        response = self.client.post(
            reverse("rules:rule_edit", args=[base.pk]),
            {"text": "rule renamed_base { condition: true }\n", "version": 1, "action": "save"},
            follow=True,
        )
        self.assertContains(response, "no longer compile: user_rule")

    def test_restore(self):
        editing.update_rule(self.hello, self.hello.text.replace("hello world", "hi"))
        response = self.client.post(reverse("rules:rule_restore", args=[self.hello.pk, 1]))
        self.assertRedirects(response, self.hello.get_absolute_url())
        self.hello.refresh_from_db()
        self.assertEqual(self.hello.version, 3)
        self.assertIn("hello world", self.hello.source)
        self.assertEqual(self.hello.versions.get(number=3).origin, RuleVersion.Origin.RESTORE)

    def test_restore_refused_shows_error(self):
        # Version 1 of pe_rule uses the pe module; drop the import from the current
        # sibling context by making v1 invalid: store a version that no longer compiles.
        version = self.hello.versions.get(number=1)
        RuleVersion.objects.filter(pk=version.pk).update(
            source="rule hello_world { condition: missing_thing }"
        )
        editing.update_rule(self.hello, self.hello.text.replace("hello world", "hi"))
        response = self.client.post(
            reverse("rules:rule_restore", args=[self.hello.pk, 1]), follow=True
        )
        self.assertContains(response, "cannot be restored")
        self.hello.refresh_from_db()
        self.assertEqual(self.hello.version, 2)

    def test_delete_confirmation_and_delete(self):
        url = reverse("rules:rule_delete", args=[self.hello.pk])
        response = self.client.get(url)
        self.assertContains(response, "cannot be undone")
        self.assertContains(response, "version history" if False else "of its history")
        response = self.client.post(url)
        self.assertRedirects(response, self.ruleset.get_absolute_url())
        self.assertFalse(Rule.objects.filter(pk=self.hello.pk).exists())
        self.assertFalse(RuleVersion.objects.filter(rule_id=self.hello.pk).exists())


class ExportTests(ViewTestCase):
    url = reverse("rules:rule_export")

    def setUp(self):
        self.login(self.viewer)

    def test_export_selected_as_yar(self):
        response = self.client.post(
            self.url, {"scope": "selected", "format": "yar", "ids": [self.hello.pk, self.pe_rule.pk]}
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("attachment", response["Content-Disposition"])
        text = response.content.decode()
        self.assertIn("rule hello_world", text)
        self.assertIn("rule pe_rule", text)
        self.assertNotIn("rule broken_rule", text)
        self.assertIn('import "pe"', text)

    def test_export_filter_as_zip(self):
        response = self.client.post(
            self.url, {"scope": "filter", "format": "zip", "tag": "demo"}
        )
        self.assertEqual(response["Content-Type"], "application/zip")
        with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
            (name,) = archive.namelist()
            text = archive.read(name).decode()
        self.assertIn("rule hello_world", text)
        self.assertIn("rule pe_rule", text)
        self.assertNotIn("broken_rule", text)

    def test_export_filter_by_get(self):
        response = self.client.get(self.url, {"scope": "filter", "q": "hello"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("rule hello_world", response.content.decode())

    def test_export_skips_removed_rules(self):
        Rule.objects.filter(pk=self.hello.pk).update(removed_at="2026-01-01T00:00:00Z")
        response = self.client.post(
            self.url, {"scope": "selected", "ids": [self.hello.pk]}, follow=True
        )
        self.assertContains(response, "Nothing to export")

    def test_nothing_selected_redirects_back_with_filters(self):
        response = self.client.post(self.url, {"scope": "selected", "q": "hello"})
        self.assertRedirects(response, f"{reverse('rules:rule_list')}?q=hello")

    def test_invalid_request_is_404(self):
        response = self.client.post(self.url, {"scope": "bogus"})
        self.assertEqual(response.status_code, 404)
