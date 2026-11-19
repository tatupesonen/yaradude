"""Shared fixtures for the view tests, plus the shell, error-page and account-page tests."""

from django.contrib.auth.models import Group
from django.test import TestCase
from django.urls import reverse

from accounts.models import User
from accounts.roles import EDITORS, VIEWERS
from rules.models import ImportFile, ImportRun, Rule, Ruleset
from rules.services.compiler import check_ruleset
from rules.tests.helpers import make_ruleset

SAMPLE_RULES = """\
import "pe"

// Says hello.
rule hello_world : greeting demo
{
    meta:
        description = "Finds a friendly greeting"
        author = "yaradude tests"
        score = 5
        active = true
    strings:
        $hello = "hello world"
    condition:
        $hello
}

rule broken_rule
{
    condition:
        no_such_identifier
}

rule pe_rule : demo
{
    condition:
        pe.is_pe
}
"""


class ViewTestCase(TestCase):
    """Users for every role and a small ruleset with a compiling and a failing rule."""

    password = "x-test-password-123"

    @classmethod
    def setUpTestData(cls):
        cls.viewer = cls.make_user("viewer", VIEWERS)
        cls.editor = cls.make_user("editor", EDITORS)
        cls.nobody = cls.make_user("nobody", None)
        cls.ruleset = make_ruleset(SAMPLE_RULES, name="sample.yar", origin=Ruleset.Origin.UPLOAD)
        cls.ruleset.original_content = SAMPLE_RULES
        cls.ruleset.save()
        check_ruleset(cls.ruleset)
        cls.hello = Rule.objects.get(name="hello_world")
        cls.broken = Rule.objects.get(name="broken_rule")
        cls.pe_rule = Rule.objects.get(name="pe_rule")
        cls.import_run = ImportRun.objects.create(
            origin=ImportRun.Origin.UPLOAD, source="sample.yar"
        )
        ImportFile.objects.create(
            run=cls.import_run,
            path="sample.yar",
            status=ImportFile.Status.CREATED,
            ruleset=cls.ruleset,
        )
        ImportFile.objects.create(
            run=cls.import_run,
            path="bad.yar",
            status=ImportFile.Status.FAILED,
            message="line 1: oops",
        )

    @classmethod
    def make_user(cls, username, group):
        user = User.objects.create_user(username, password=cls.password)
        if group:
            user.groups.add(Group.objects.get(name=group))
        return user

    def login(self, user):
        self.client.force_login(user)


class ShellTests(ViewTestCase):
    def test_dashboard_counts_and_navigation(self):
        self.login(self.viewer)
        response = self.client.get(reverse("rules:dashboard"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["counts"]["rules"], 3)
        self.assertEqual(response.context["counts"]["failing"], 1)
        self.assertContains(response, 'aria-current="page">Dashboard')
        self.assertContains(response, "hello_world")
        # Viewers see no editor actions.
        self.assertNotContains(response, reverse("rules:rule_create"))
        self.assertContains(response, reverse("rules:scan"))

    def test_dashboard_shows_editor_actions(self):
        self.login(self.editor)
        response = self.client.get(reverse("rules:dashboard"))
        self.assertContains(response, reverse("rules:rule_create"))

    def test_empty_dashboard_points_to_import(self):
        Ruleset.objects.all().delete()
        self.login(self.editor)
        response = self.client.get(reverse("rules:dashboard"))
        self.assertContains(response, "No rules yet")
        self.assertContains(response, "Go to Import")

    def test_user_without_role_gets_explanatory_403(self):
        self.login(self.nobody)
        response = self.client.get(reverse("rules:dashboard"))
        self.assertEqual(response.status_code, 403)
        self.assertContains(response, "not in any role", status_code=403)
        self.assertContains(response, "Viewers", status_code=403)

    def test_404_page(self):
        self.login(self.viewer)
        response = self.client.get(reverse("rules:rule_detail", args=[999999]))
        self.assertEqual(response.status_code, 404)
        self.assertContains(response, "does not exist", status_code=404)

    def test_messages_are_rendered(self):
        self.login(self.editor)
        response = self.client.post(
            reverse("rules:rule_restore", args=[self.hello.pk, 1]), {"version": 1}, follow=True
        )
        self.assertContains(response, 'role="status"')


class AccountPageTests(ViewTestCase):
    def test_login_page_is_styled_and_public(self):
        response = self.client.get(reverse("login"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "registration/login.html")
        self.assertContains(response, "rules/css/yaradude.css")

    def test_login_and_logout(self):
        response = self.client.post(
            reverse("login"), {"username": "viewer", "password": self.password}
        )
        self.assertRedirects(response, reverse("rules:dashboard"))
        response = self.client.post(reverse("logout"))
        self.assertRedirects(response, reverse("login"))

    def test_bad_login_shows_error(self):
        response = self.client.post(reverse("login"), {"username": "viewer", "password": "nope"})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'role="alert"')

    def test_no_password_reset_link(self):
        response = self.client.get(reverse("login"))
        self.assertNotContains(response, "password_reset")
        self.assertNotContains(response, "Forgot")

    def test_password_change_pages(self):
        self.login(self.viewer)
        response = self.client.get(reverse("password_change"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "registration/password_change_form.html")
        self.assertContains(response, "rules/css/yaradude.css")
        response = self.client.post(
            reverse("password_change"),
            {
                "old_password": self.password,
                "new_password1": "another-long-pass-42",
                "new_password2": "another-long-pass-42",
            },
        )
        self.assertRedirects(response, reverse("password_change_done"))
        response = self.client.get(reverse("password_change_done"))
        self.assertContains(response, "Password changed")
        self.viewer.refresh_from_db()
        self.assertTrue(self.viewer.check_password("another-long-pass-42"))

    def test_password_change_errors(self):
        self.login(self.viewer)
        response = self.client.post(
            reverse("password_change"),
            {"old_password": "wrong", "new_password1": "a", "new_password2": "b"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'aria-invalid="true"')

    def test_password_change_requires_login(self):
        response = self.client.get(reverse("password_change"))
        self.assertRedirects(response, f"{reverse('login')}?next={reverse('password_change')}")

    def test_user_menu_links_password_change(self):
        self.login(self.viewer)
        response = self.client.get(reverse("rules:dashboard"))
        self.assertContains(response, reverse("password_change"))
