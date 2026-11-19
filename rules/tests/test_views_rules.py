import io
import zipfile
from unittest import mock

from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.urls import reverse

from rules.models import Rule, Ruleset, RuleVersion
from rules.services import editing, search
from rules.tests.helpers import make_ruleset
from rules.tests.test_views_common import ViewTestCase

NEW_RULE = (
    'rule fresh_rule : fresh\n{\n    strings:\n        $a = "fresh"\n'
    "    condition:\n        $a\n}\n"
)


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
        self.assertEqual(
            self.names(self.client.get(self.url, {"status": "modified"})), ["hello_world"]
        )
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
        self.assertEqual(
            self.names(self.client.get(self.url, {"sort": "updated"}))[0], "broken_rule"
        )

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
        self.assertFormError(  # ty: ignore[missing-argument]  # Django 4.1+ signature (form, field, errors); django-types 0.24 has the old one
            response.context["form"], "new_ruleset", "Name the new collection."
        )

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
            reverse("rules:rule_create"),
            {"ruleset": self.ruleset.pk, "text": text, "action": "save"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.context["result"].ok)
        self.assertContains(response, "Not saved")
        self.assertContains(response, "nope_nope")
        self.assertFalse(Rule.objects.filter(name="bad_one").exists())

    def test_name_clash_refused(self):
        response = self.client.post(
            reverse("rules:rule_create"),
            {
                "ruleset": self.ruleset.pk,
                "text": "rule pe_rule { condition: true }",
                "action": "save",
            },
        )
        self.assertContains(response, "already exists")

    def test_empty_text_is_a_form_error(self):
        response = self.client.post(
            reverse("rules:rule_create"),
            {"ruleset": self.ruleset.pk, "text": "  ", "action": "save"},
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
        self.assertContains(response, "someone else changed this rule")
        self.assertEqual(response.context["conflict"]["current"], 2)
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
        response = self.client.post(
            reverse("rules:rule_restore", args=[self.hello.pk, 1]), {"version": 2}
        )
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
            reverse("rules:rule_restore", args=[self.hello.pk, 1]), {"version": 2}, follow=True
        )
        self.assertContains(response, "cannot be restored")
        self.hello.refresh_from_db()
        self.assertEqual(self.hello.version, 2)

    def test_delete_confirmation_and_delete(self):
        url = reverse("rules:rule_delete", args=[self.hello.pk])
        response = self.client.get(url)
        # Deletes are recoverable (PLAN.md 12.11): the page must not claim otherwise.
        self.assertContains(response, "It is not destroyed")
        self.assertContains(response, "can be restored")
        self.assertNotContains(response, "cannot be undone")
        self.assertNotContains(response, "Permanently")
        response = self.client.post(url, follow=True)
        self.assertRedirects(response, self.ruleset.get_absolute_url())
        self.assertContains(response, "hidden, not destroyed")
        self.assertFalse(Rule.objects.filter(pk=self.hello.pk).exists())
        deleted = Rule.all_objects.get(pk=self.hello.pk)
        self.assertEqual(deleted.deleted_by, self.editor)
        self.assertTrue(RuleVersion.objects.filter(rule_id=self.hello.pk).exists())
        # Its version pages are gone with it, as is restoring one of them.
        version_url = reverse("rules:rule_version", args=[self.hello.pk, 1])
        self.assertEqual(self.client.get(version_url).status_code, 404)
        restore_url = reverse("rules:rule_restore", args=[self.hello.pk, 1])
        self.assertEqual(self.client.post(restore_url, {"version": 1}).status_code, 404)
        self.assertEqual(self.client.get(self.hello.get_absolute_url()).status_code, 404)


class ExportTests(ViewTestCase):
    url = reverse("rules:rule_export")

    def setUp(self):
        self.login(self.viewer)

    def test_export_selected_as_yar(self):
        response = self.client.post(
            self.url,
            {"scope": "selected", "format": "yar", "ids": [self.hello.pk, self.pe_rule.pk]},
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("attachment", response["Content-Disposition"])
        text = response.content.decode()
        self.assertIn("rule hello_world", text)
        self.assertIn("rule pe_rule", text)
        self.assertNotIn("rule broken_rule", text)
        self.assertIn('import "pe"', text)

    def test_export_filter_as_zip(self):
        response = self.client.post(self.url, {"scope": "filter", "format": "zip", "tag": "demo"})
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


class ReviewFixTests(ViewTestCase):
    def setUp(self):
        self.login(self.editor)

    def test_collection_name_rejects_control_characters(self):
        for name in ("evil\nrule x { condition: true }", "tab\there", "nul\x00", "ls x"):
            with self.subTest(name=repr(name)):
                response = self.client.post(
                    reverse("rules:rule_create"),
                    {"ruleset": "new", "new_ruleset": name, "text": NEW_RULE, "action": "save"},
                )
                self.assertEqual(response.status_code, 200)
                self.assertTrue(response.context["form"].errors)
        self.assertFalse(Rule.objects.filter(name="fresh_rule").exists())
        self.assertFalse(Ruleset.objects.filter(origin=Ruleset.Origin.MANUAL).exists())

    def test_collection_name_is_trimmed_and_limited(self):
        response = self.client.post(
            reverse("rules:rule_create"),
            {"ruleset": "new", "new_ruleset": "x" * 101, "text": NEW_RULE, "action": "save"},
        )
        self.assertTrue(response.context["form"].errors)
        self.client.post(
            reverse("rules:rule_create"),
            {"ruleset": "new", "new_ruleset": "  Trimmed  ", "text": NEW_RULE, "action": "save"},
        )
        self.assertTrue(Ruleset.objects.filter(name="Trimmed").exists())

    def test_validate_in_new_collection_creates_nothing(self):
        response = self.client.post(
            reverse("rules:rule_create"),
            {"ruleset": "new", "new_ruleset": "Scratch", "text": NEW_RULE, "action": "validate"},
        )
        self.assertTrue(response.context["result"].ok)
        self.assertFalse(Ruleset.objects.filter(name="Scratch").exists())

    def test_create_form_offers_only_manual_collections_and_the_chosen_ruleset(self):
        manual = make_ruleset("rule m { condition: true }", name="Manual one")
        response = self.client.get(reverse("rules:rule_create"))
        choices = dict(response.context["form"].fields["ruleset"].choices)
        self.assertIn(str(manual.pk), choices)
        self.assertNotIn(str(self.ruleset.pk), choices)  # an uploaded file
        response = self.client.get(reverse("rules:rule_create"), {"ruleset": self.ruleset.pk})
        self.assertIn(
            str(self.ruleset.pk), dict(response.context["form"].fields["ruleset"].choices)
        )


class ScalingTests(ViewTestCase):
    def setUp(self):
        self.login(self.viewer)

    def test_list_query_carries_no_large_columns(self):
        with CaptureQueriesContext(connection) as queries:
            self.client.get(reverse("rules:rule_list"), {"page": 1})
        rows = [
            q["sql"] for q in queries if 'FROM "rules_rule"' in q["sql"] and "LIMIT" in q["sql"]
        ]
        self.assertTrue(rows)
        for sql in rows:
            self.assertNotIn("original_content", sql)
            self.assertNotIn('"rules_rule"."source"', sql)

    def test_default_sort_is_by_indexed_name_and_id(self):
        with CaptureQueriesContext(connection) as queries:
            self.client.get(reverse("rules:rule_list"))
        (sql,) = [
            q["sql"] for q in queries if 'FROM "rules_rule"' in q["sql"] and "LIMIT" in q["sql"]
        ]
        self.assertIn('ORDER BY "rules_rule"."name" ASC, "rules_rule"."id" ASC LIMIT', sql, sql)

    def test_ruleset_filter_is_a_path_field_not_a_dropdown(self):
        for i in range(40):
            make_ruleset(f"rule p{i} {{ condition: true }}", name=f"coll/sub/{i}.yar")
        response = self.client.get(reverse("rules:rule_list"))
        self.assertNotContains(response, 'name="ruleset"')
        self.assertContains(response, 'name="path"')
        response = self.client.get(reverse("rules:rule_list"), {"path": "coll/"})
        self.assertEqual(response.context["page"].paginator.count, 40)
        self.assertContains(response, "Path starts with")
        response = self.client.get(reverse("rules:rule_list"), {"path": "sub/1"})
        self.assertEqual(response.context["page"].paginator.count, 11)  # 1, 10-19
        self.assertContains(response, "Path contains")

    def test_ruleset_id_filter_shows_a_removable_chip(self):
        response = self.client.get(reverse("rules:rule_list"), {"ruleset": self.ruleset.pk})
        self.assertContains(response, "Ruleset: <span")
        self.assertContains(response, 'aria-label="Remove ruleset filter"')

    def test_scan_page_has_no_per_ruleset_checkboxes(self):
        for i in range(20):
            make_ruleset(f"rule s{i} {{ condition: true }}", name=f"many/{i}.yar")
        response = self.client.get(reverse("rules:scan"))
        self.assertNotContains(response, 'type="checkbox"')
        self.assertContains(response, 'name="path"')

    def test_many_pages_have_a_page_number_field(self):
        make_ruleset(
            "\n".join(f"rule q{i:04d} {{ condition: true }}" for i in range(450)), name="q"
        )
        response = self.client.get(reverse("rules:rule_list"), {"page": 3})
        self.assertContains(response, 'type="number"')
        self.assertContains(response, 'max="5"')
        self.assertEqual(response.content.decode().count('rel="next"'), 1)


class EditConflictTests(ViewTestCase):
    """Simultaneous edits (review finding 2): the editing service is the only check."""

    def setUp(self):
        self.login(self.editor)
        self.url = reverse("rules:rule_edit", args=[self.hello.pk])
        self.base_text = self.hello.text

    def text(self, marker):
        return self.base_text.replace("hello world", marker)

    def test_second_save_from_the_same_form_is_a_conflict(self):
        rendered = self.client.get(self.url).context["form"]["version"].value()
        self.assertEqual(rendered, 1)
        first = self.client.post(
            self.url, {"text": self.text("first_saver"), "version": rendered, "action": "save"}
        )
        self.assertRedirects(first, self.hello.get_absolute_url())
        versions = RuleVersion.objects.filter(rule=self.hello).count()

        second = self.client.post(
            self.url, {"text": self.text("second_saver"), "version": rendered, "action": "save"}
        )
        self.assertEqual(second.status_code, 200)
        self.assertContains(second, "Not saved: someone else changed this rule")
        self.assertContains(second, "second_saver")  # the user's text stays in the editor
        version_2 = reverse("rules:rule_version", args=[self.hello.pk, 2])
        self.assertContains(second, f'href="{version_2}"')  # current version and its diff
        self.assertEqual(RuleVersion.objects.filter(rule=self.hello).count(), versions)
        self.hello.refresh_from_db()
        self.assertEqual(self.hello.version, 2)
        self.assertIn("first_saver", self.hello.source)

        # The conflict page carries the current version: saving from it is a
        # deliberate overwrite after merging by hand.
        self.assertEqual(second.context["form"]["version"].value(), "2")
        self.assertContains(second, "Save over version 2")
        third = self.client.post(
            self.url, {"text": self.text("merged_text"), "version": 2, "action": "save"}
        )
        self.assertRedirects(third, self.hello.get_absolute_url())
        self.hello.refresh_from_db()
        self.assertEqual(self.hello.version, 3)

    def test_change_between_page_load_and_save_is_caught_by_the_service(self):
        # Another save lands after the view loaded the rule, i.e. inside the
        # service's own window: only its in-transaction check can see it.
        real_update = editing.update_rule

        def racing_update(rule, text, *args, **kwargs):
            other = Rule.objects.get(pk=rule.pk)
            real_update(other, other.text.replace("hello world", "other_user"))
            return real_update(rule, text, *args, **kwargs)

        with mock.patch("rules.views.rules.editing.update_rule", side_effect=racing_update):
            response = self.client.post(
                self.url, {"text": self.text("mine"), "version": 1, "action": "save"}
            )
        self.assertContains(response, "Not saved: someone else changed this rule")
        self.assertEqual(response.context["conflict"]["current"], 2)
        self.hello.refresh_from_db()
        self.assertEqual(self.hello.version, 2)
        self.assertIn("other_user", self.hello.source)

    def test_rule_deleted_while_editing(self):
        real_update = editing.update_rule

        def deleting_update(rule, text, *args, **kwargs):
            editing.delete_rule(Rule.objects.get(pk=rule.pk))
            return real_update(rule, text, *args, **kwargs)

        with mock.patch("rules.views.rules.editing.update_rule", side_effect=deleting_update):
            response = self.client.post(
                self.url, {"text": self.text("orphan_text"), "version": 1, "action": "save"}
            )
        self.assertContains(response, "Not saved: someone else deleted this rule")
        self.assertContains(response, "orphan_text")
        self.assertNotContains(response, 'value="save"')
        self.assertFalse(Rule.objects.filter(pk=self.hello.pk).exists())

    def test_view_passes_the_rendered_version_to_the_service(self):
        with mock.patch(
            "rules.views.rules.editing.update_rule", wraps=editing.update_rule
        ) as update:
            self.client.post(self.url, {"text": self.text("x1"), "version": 1, "action": "save"})
        self.assertEqual(update.call_args.kwargs["expected_version"], 1)


class RestoreConflictTests(ViewTestCase):
    def setUp(self):
        self.login(self.editor)
        editing.update_rule(self.hello, self.hello.text.replace("hello world", "second"))
        self.restore_url = reverse("rules:rule_restore", args=[self.hello.pk, 1])

    def test_version_page_posts_the_current_version(self):
        response = self.client.get(reverse("rules:rule_version", args=[self.hello.pk, 1]))
        self.assertContains(response, '<input type="hidden" name="version" value="2">')

    def test_restore_after_someone_else_saved_is_refused(self):
        # The version page was rendered at version 2; someone saves version 3.
        editing.update_rule(self.hello, self.hello.text.replace("second", "third"))
        response = self.client.post(self.restore_url, {"version": 2}, follow=True)
        self.assertRedirects(response, reverse("rules:rule_version", args=[self.hello.pk, 1]))
        self.assertContains(response, "Not restored: someone else changed this rule")
        self.assertContains(
            response, f'href="{reverse("rules:rule_version", args=[self.hello.pk, 3])}"'
        )
        self.hello.refresh_from_db()
        self.assertEqual(self.hello.version, 3)
        self.assertFalse(self.hello.versions.filter(number=4).exists())
        # The refreshed page carries version 3; restoring from it works.
        response = self.client.post(self.restore_url, {"version": 3})
        self.assertRedirects(response, self.hello.get_absolute_url())
        self.hello.refresh_from_db()
        self.assertEqual(self.hello.version, 4)
        self.assertIn("hello world", self.hello.source)

    def test_restore_without_the_shown_version_is_refused(self):
        response = self.client.post(self.restore_url, {}, follow=True)
        self.assertContains(response, "out of date")
        self.hello.refresh_from_db()
        self.assertEqual(self.hello.version, 2)

    def test_restore_of_a_deleted_rule(self):
        real_restore = editing.restore_version

        def deleting_restore(version, *args, **kwargs):
            editing.delete_rule(Rule.objects.get(pk=version.rule_id))
            return real_restore(version, *args, **kwargs)

        with mock.patch("rules.views.rules.editing.restore_version", side_effect=deleting_restore):
            response = self.client.post(self.restore_url, {"version": 2}, follow=True)
        self.assertRedirects(response, self.ruleset.get_absolute_url())
        self.assertContains(response, "someone else deleted the rule hello_world")


class NewCollectionTests(ViewTestCase):
    """A new collection is created by the service together with its first rule."""

    def setUp(self):
        self.login(self.editor)

    def post(self, name, text, action="save"):
        return self.client.post(
            reverse("rules:rule_create"),
            {"ruleset": "new", "new_ruleset": name, "text": text, "action": action},
        )

    def test_service_gets_an_unsaved_collection(self):
        with mock.patch(
            "rules.views.rules.editing.create_rule", wraps=editing.create_rule
        ) as create:
            response = self.post("Fresh collection", NEW_RULE)
        ruleset = create.call_args.args[0]
        self.assertIsNone(ruleset.pk)  # the view created nothing itself
        rule = Rule.objects.get(name="fresh_rule")
        self.assertRedirects(response, rule.get_absolute_url())
        self.assertEqual(rule.ruleset.name, "Fresh collection")

    def test_refused_save_leaves_no_collection_behind(self):
        for text in ("rule not_compiling { condition: nope_nope }", "rule x {"):
            with self.subTest(text=text):
                response = self.post("Never created", text)
                self.assertEqual(response.status_code, 200)
                self.assertFalse(response.context["result"].ok)
                self.assertContains(response, "Not saved")
        self.assertFalse(Ruleset.objects.filter(name="Never created").exists())

    def test_validate_checks_against_an_unsaved_collection(self):
        response = self.post("Scratch", "rule v { condition: nope_nope }", action="validate")
        self.assertContains(response, "Does not compile")
        self.assertFalse(Ruleset.objects.filter(name="Scratch").exists())

    def test_existing_collection_name_adds_to_it(self):
        manual = editing.manual_ruleset("Mine")
        response = self.post("Mine", NEW_RULE)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(Rule.objects.get(name="fresh_rule").ruleset, manual)
        self.assertEqual(Ruleset.objects.filter(name="Mine").count(), 1)

    def test_names_with_invisible_or_control_characters_are_rejected(self):
        for name in ("bidi‮override", "zero​width", "line sep", "tab\tname"):
            with self.subTest(name=repr(name)):
                response = self.post(name, NEW_RULE)
                self.assertEqual(response.status_code, 200)
                self.assertFormError(  # ty: ignore[missing-argument]  # Django 4.1+ signature (form, field, errors); django-types 0.24 has the old one
                    response.context["form"],
                    "new_ruleset",
                    "The name must be a single line of visible text: no line breaks, tabs, "
                    "control characters or invisible formatting characters.",
                )
        self.assertFalse(Rule.objects.filter(name="fresh_rule").exists())


class MetaRenderingTests(ViewTestCase):
    def test_float_meta_values(self):
        ruleset = make_ruleset(
            "rule floats {\n  meta:\n    score = 1.5\n    ratio = -0.25\n"
            "    whole = 3.0\n    huge = 100000000000000000000.0\n"
            "  condition:\n    true\n}\n",
            name="floats",
        )
        rule = ruleset.rules.get()
        self.assertIn(["score", 1.5], rule.meta)
        self.login(self.viewer)
        response = self.client.get(rule.get_absolute_url())
        for shown in ("1.5", "-0.25", "3.0", "100000000000000000000.0"):
            self.assertContains(response, f'<dd class="text-sm break-words">{shown}</dd>')
        self.assertNotContains(response, "e+20")

    def test_meta_value_filter(self):
        from rules.templatetags.yaradude import meta_value

        self.assertEqual(meta_value(True), "true")
        self.assertEqual(meta_value(7), "7")
        self.assertEqual(meta_value(0.1), "0.1")
        self.assertEqual(meta_value(1e-7), "0.0000001")
        self.assertEqual(meta_value("1.5"), "1.5")


class SearchTests(ViewTestCase):
    """The `q` filter goes through search.search_rules (FTS5, literal phrase)."""

    url = reverse("rules:rule_list")

    def setUp(self):
        self.login(self.viewer)
        make_ruleset(
            'rule hostile_input {\n  meta:\n    description = "say \\"AND\\" name: -x *star* (OR"\n'
            "  condition:\n    true\n}\n",
            name="hostile",
        )

    def names(self, response):
        return [rule.name for rule in response.context["page"].object_list]

    def test_hostile_input_is_literal(self):
        for text in ('"', "AND", "name:", "-x", "*", "(OR", '\\"AND\\"', "*star* (OR"):
            with self.subTest(text=text):
                response = self.client.get(self.url, {"q": text})
                self.assertEqual(response.status_code, 200)
                self.assertIn("hostile_input", self.names(response))
        response = self.client.get(self.url, {"q": "NEAR(name)"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.names(response), [])

    def test_view_uses_the_search_service(self):
        with mock.patch(
            "rules.views.rules.search_rules", wraps=search.search_rules
        ) as search_rules:
            response = self.client.get(self.url, {"q": "greeting"})
        self.assertEqual(search_rules.call_args.args[1], "greeting")
        self.assertTrue(search_rules.call_args.kwargs["rank"])
        self.assertEqual(self.names(response), ["hello_world"])

    def test_relevance_is_the_default_and_only_offered_while_searching(self):
        response = self.client.get(self.url, {"q": "hello"})
        self.assertEqual(response.context["values"]["sort"], "relevance")
        self.assertContains(response, ">Relevance</option>")
        # The default option submits no value, so a new search starts by relevance.
        self.assertContains(response, '<option value="" selected>Relevance</option>')
        response = self.client.get(self.url, {"q": "hello", "sort": "name"})
        self.assertEqual(response.context["values"]["sort"], "name")
        response = self.client.get(self.url)
        self.assertEqual(response.context["values"]["sort"], "name")
        self.assertNotContains(response, ">Relevance</option>")
        self.assertContains(response, '<option value="" selected>Name</option>')
        response = self.client.get(self.url, {"sort": "relevance"})
        self.assertEqual(response.context["values"]["sort"], "name")

    def test_short_input_falls_back_to_substring(self):
        response = self.client.get(self.url, {"q": "pe"})
        self.assertIn("pe_rule", self.names(response))

    def test_search_keeps_query_count_and_deferred_columns(self):
        def run(**params):
            with CaptureQueriesContext(connection) as queries:
                self.client.get(self.url, params)
            return queries

        few = run(q="rule")
        make_ruleset(
            "\n".join(f"rule many_{i} {{ condition: true }}" for i in range(30)), name="many"
        )
        many = run(q="rule")
        self.assertEqual(len(few), len(many))
        for params in ({"q": "rule"}, {"q": "rule", "sort": "-updated"}):
            rows = [
                q["sql"]
                for q in run(**params)
                if 'FROM "rules_rule"' in q["sql"] and "LIMIT" in q["sql"]
            ]
            self.assertTrue(rows)
            for sql in rows:
                self.assertNotIn('"rules_rule"."source"', sql)
                self.assertNotIn("original_content", sql)


class DeletedRuleLeakTests(ViewTestCase):
    """Joins bypass the default manager; deleted rules must not leak through them."""

    def test_tags_used_only_by_deleted_rules_are_not_offered(self):
        ruleset = make_ruleset("rule lonely : only_here { condition: true }", name="lonely")
        lonely = ruleset.rules.get()
        self.login(self.viewer)
        response = self.client.get(reverse("rules:rule_list"))
        self.assertIn("only_here", list(response.context["tags"]))
        dashboard = self.client.get(reverse("rules:dashboard")).context["tag_count"]
        editing.delete_rule(lonely, user=self.editor)
        response = self.client.get(reverse("rules:rule_list"))
        self.assertNotIn("only_here", list(response.context["tags"]))
        self.assertIn("greeting", list(response.context["tags"]))
        response = self.client.get(reverse("rules:dashboard"))
        self.assertEqual(response.context["tag_count"], dashboard - 1)
