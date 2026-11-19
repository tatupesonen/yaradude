from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.urls import reverse

from rules.models import ImportFile, Rule, Ruleset
from rules.tests.helpers import make_ruleset
from rules.tests.test_views_common import ViewTestCase


class RulesetListTests(ViewTestCase):
    url = reverse("rules:ruleset_list")

    def setUp(self):
        self.login(self.viewer)

    def test_lists_rulesets_with_counts(self):
        response = self.client.get(self.url)
        (ruleset,) = response.context["page"].object_list
        self.assertEqual(ruleset.active_count, 3)
        self.assertEqual(ruleset.failing_count, 1)
        self.assertContains(response, "1 not compiling")

    def test_search_origin_and_sort(self):
        make_ruleset("rule zz { condition: true }", name="zeta/other.yar")
        names = lambda r: [x.name for x in r.context["page"].object_list]  # noqa: E731
        self.assertEqual(names(self.client.get(self.url, {"q": "zeta/"})), ["zeta/other.yar"])
        self.assertEqual(names(self.client.get(self.url, {"origin": "upload"})), ["sample.yar"])
        self.assertEqual(
            names(self.client.get(self.url, {"sort": "-rules"})), ["sample.yar", "zeta/other.yar"]
        )
        self.assertEqual(
            names(self.client.get(self.url, {"sort": "bogus"})), ["sample.yar", "zeta/other.yar"]
        )

    def test_query_count_and_no_file_content(self):
        def run():
            with CaptureQueriesContext(connection) as queries:
                self.client.get(self.url)
            return queries

        few = len(run())
        for i in range(30):
            make_ruleset(f"rule r{i} {{ condition: true }}", name=f"many/{i}.yar")
        queries = run()
        self.assertEqual(len(queries), few)
        self.assertFalse(any("original_content" in q["sql"] for q in queries))

    def test_empty_state(self):
        Ruleset.objects.all().delete()
        response = self.client.get(self.url)
        self.assertContains(response, "No rulesets yet")


class RulesetDetailTests(ViewTestCase):
    def setUp(self):
        self.login(self.viewer)

    def test_detail(self):
        response = self.client.get(self.ruleset.get_absolute_url())
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "hello_world")
        self.assertContains(response, "broken_rule")
        self.assertContains(response, reverse("rules:ruleset_download", args=[self.ruleset.pk]))
        self.assertContains(response, reverse("rules:ruleset_original", args=[self.ruleset.pk]))

    def test_removed_rules_listed_last(self):
        Rule.objects.filter(pk=self.hello.pk).update(removed_at="2026-01-01T00:00:00Z")
        response = self.client.get(self.ruleset.get_absolute_url())
        names = [rule.name for rule in response.context["rules"]]
        self.assertEqual(names[-1], "hello_world")
        self.assertContains(response, "badge-removed")

    def test_download_rebuilt_and_original(self):
        response = self.client.get(reverse("rules:ruleset_download", args=[self.ruleset.pk]))
        self.assertEqual(response.status_code, 200)
        self.assertIn('filename="sample.yar"', response["Content-Disposition"])
        self.assertIn("rule hello_world", response.content.decode())
        response = self.client.get(reverse("rules:ruleset_original", args=[self.ruleset.pk]))
        self.assertEqual(response.content.decode(), self.ruleset.original_content)

    def test_original_of_manual_ruleset_redirects(self):
        manual = make_ruleset("rule m { condition: true }", name="manual")
        response = self.client.get(reverse("rules:ruleset_original", args=[manual.pk]))
        self.assertRedirects(response, manual.get_absolute_url())

    def test_delete(self):
        self.login(self.editor)
        url = reverse("rules:ruleset_delete", args=[self.ruleset.pk])
        response = self.client.get(url)
        # Deletes are recoverable (PLAN.md 12.11): the page must not claim otherwise.
        self.assertContains(response, "They are not destroyed")
        self.assertContains(response, "can be restored")
        self.assertNotContains(response, "cannot be undone")
        self.assertNotContains(response, "Permanently")
        response = self.client.post(url, follow=True)
        self.assertRedirects(response, reverse("rules:ruleset_list"))
        self.assertContains(response, "hidden, not destroyed")
        self.assertFalse(Ruleset.objects.filter(pk=self.ruleset.pk).exists())
        self.assertFalse(Rule.objects.filter(ruleset_id=self.ruleset.pk).exists())
        self.assertEqual(Ruleset.all_objects.get(pk=self.ruleset.pk).deleted_by, self.editor)
        self.assertEqual(Rule.all_objects.filter(ruleset_id=self.ruleset.pk).count(), 3)
        self.assertEqual(self.client.get(self.ruleset.get_absolute_url()).status_code, 404)
        # The import history keeps its link, shown without a link to the hidden ruleset.
        self.assertTrue(ImportFile.objects.filter(path="sample.yar", ruleset=self.ruleset).exists())
        response = self.client.get(reverse("rules:import_run", args=[self.import_run.pk]))
        self.assertContains(response, "(ruleset deleted)")
        self.assertNotContains(response, f'href="{self.ruleset.get_absolute_url()}"')


class DeletedRuleCountTests(ViewTestCase):
    """Per-ruleset counts join rules without the default manager (PLAN.md 5.7)."""

    def test_individually_deleted_rules_are_not_counted(self):
        from rules.services import editing

        editing.delete_rule(self.hello, user=self.editor)  # active, compiles
        editing.delete_rule(self.broken, user=self.editor)  # active, does not compile
        self.login(self.viewer)
        response = self.client.get(reverse("rules:ruleset_list"))
        (row,) = response.context["page"].object_list
        self.assertEqual(row.active_count, 1)
        self.assertEqual(row.failing_count, 0)
        self.assertEqual(row.removed_count, 0)
        response = self.client.get(self.ruleset.get_absolute_url())
        self.assertEqual(response.context["ruleset"].active_count, 1)
        self.assertNotContains(response, "not compiling")
