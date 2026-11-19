from django.db import IntegrityError
from django.test import TestCase
from django.utils import timezone

from accounts.models import User
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


class AdminContentIsReadOnlyTests(TestCase):
    """Review finding 6: the admin cannot change rule content or version snapshots."""

    def setUp(self) -> None:
        from accounts.models import User
        from rules.services.compiler import check_ruleset

        self.ruleset = make_ruleset("rule a : t { condition: filesize > 0 }")
        check_ruleset(self.ruleset)
        self.rule = Rule.objects.get(name="a")
        admin = User.objects.create_superuser("admin", email="", password="pw")
        self.client.force_login(admin)

    def test_rule_change_is_refused(self) -> None:
        url = f"/admin/rules/rule/{self.rule.pk}/change/"
        page = self.client.get(url)
        self.assertEqual(page.status_code, 200)
        self.assertNotIn('name="source"', page.content.decode())
        response = self.client.post(url, {"name": "a", "source": "rule a { condition: false }"})
        self.assertEqual(response.status_code, 403)
        self.rule.refresh_from_db()
        self.assertIn("filesize > 0", self.rule.source)
        self.assertEqual(self.client.get("/admin/rules/rule/add/").status_code, 403)

    def test_versions_are_fully_read_only(self) -> None:
        version = self.rule.versions.get()
        base = f"/admin/rules/ruleversion/{version.pk}"
        self.assertEqual(self.client.post(f"{base}/change/", {"source": "x"}).status_code, 403)
        self.assertEqual(self.client.post(f"{base}/delete/", {"post": "yes"}).status_code, 403)
        self.assertEqual(self.client.get("/admin/rules/ruleversion/add/").status_code, 403)
        version.refresh_from_db()
        self.assertIn("filesize > 0", version.source)

    def test_ruleset_content_is_read_only(self) -> None:
        page = self.client.get(f"/admin/rules/ruleset/{self.ruleset.pk}/change/").content.decode()
        self.assertIn('name="name"', page)
        self.assertNotIn('name="original_content"', page)
        self.assertNotIn('name="path"', page)

    def test_delete_goes_through_the_service(self) -> None:
        response = self.client.post(
            f"/admin/rules/ruleset/{self.ruleset.pk}/delete/", {"post": "yes"}
        )
        self.assertEqual(response.status_code, 302)
        self.assertFalse(Ruleset.objects.exists())
        ruleset = Ruleset.all_objects.get()
        self.assertTrue(ruleset.is_deleted)
        self.assertEqual(ruleset.deleted_by, User.objects.get(username="admin"))
        self.assertTrue(Rule.all_objects.get().is_deleted)

    def test_restore_and_purge_actions(self) -> None:
        from accounts.models import User

        self.client.post(f"/admin/rules/rule/{self.rule.pk}/delete/", {"post": "yes"})
        self.assertFalse(Rule.objects.exists())
        changelist = "/admin/rules/rule/"
        self.client.post(
            changelist, {"action": "restore_selected", "_selected_action": [self.rule.pk]}
        )
        self.assertTrue(Rule.objects.filter(pk=self.rule.pk).exists())

        # Staff without the purge permission do not get the action.
        staff = User.objects.create_user("staff", is_staff=True)
        from django.contrib.auth.models import Permission

        staff.user_permissions.add(
            *Permission.objects.filter(codename__in=["view_rule", "delete_rule"])
        )
        self.client.force_login(staff)
        page = self.client.get(changelist).content.decode()
        self.assertNotIn("purge_selected", page)
        self.client.post(
            changelist, {"action": "purge_selected", "_selected_action": [self.rule.pk]}
        )
        self.assertTrue(Rule.all_objects.filter(pk=self.rule.pk).exists())

        self.client.force_login(User.objects.get(username="admin"))
        self.client.post(
            changelist, {"action": "purge_selected", "_selected_action": [self.rule.pk]}
        )
        self.assertFalse(Rule.all_objects.filter(pk=self.rule.pk).exists())
