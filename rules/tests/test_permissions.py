"""
Every URL of the rules app: anonymous users are redirected to the sign-in
page, Viewers may read but get 403 on every write, Editors may do both,
users without a role get 403 everywhere, and state changes need POST.
"""

from django.core.files.uploadedfile import SimpleUploadedFile
from django.urls import reverse

from rules.models import Rule, Ruleset
from rules.tests.test_views_common import ViewTestCase

READ = "read"
WRITE = "write"
SCAN = "scan"


class PermissionMatrixTests(ViewTestCase):
    def cases(self):
        """(name, args, method, kind, expected status for a permitted user)."""
        rule, ruleset, run = self.hello.pk, self.ruleset.pk, self.import_run.pk
        return [
            ("dashboard", [], "get", READ, 200),
            ("rule_list", [], "get", READ, 200),
            ("rule_detail", [rule], "get", READ, 200),
            ("rule_download", [rule], "get", READ, 200),
            ("rule_version", [rule, 1], "get", READ, 200),
            ("rule_export", [], "get", READ, 200),
            ("ruleset_list", [], "get", READ, 200),
            ("ruleset_detail", [ruleset], "get", READ, 200),
            ("ruleset_download", [ruleset], "get", READ, 200),
            ("ruleset_original", [ruleset], "get", READ, 200),
            ("import", [], "get", READ, 200),
            ("import_run", [run], "get", READ, 200),
            ("scan", [], "get", SCAN, 200),
            ("rule_create", [], "get", WRITE, 200),
            ("rule_edit", [rule], "get", WRITE, 200),
            ("rule_delete", [rule], "get", WRITE, 200),
            ("ruleset_delete", [ruleset], "get", WRITE, 200),
            ("rule_create", [], "post", WRITE, 200),
            ("rule_edit", [rule], "post", WRITE, 200),
            ("rule_restore", [rule, 1], "post", WRITE, 302),
            ("import_scan", [], "post", WRITE, 302),
            ("import_upload", [], "post", WRITE, 400),
            ("scan", [], "post", SCAN, 200),
            # Destructive writes come last; each case runs in its own subTest
            # but the database is shared, so they are checked separately below.
        ]

    def request(self, method, url):
        if method == "get":
            return self.client.get(url, {"scope": "filter"} if "export" in url else None)
        return self.client.post(url, {})

    def test_anonymous_is_redirected_to_login(self):
        for name, args, method, _, _ in self.cases():
            url = reverse(f"rules:{name}", args=args)
            with self.subTest(name=name, method=method):
                response = self.request(method, url)
                self.assertEqual(response.status_code, 302)
                self.assertTrue(response["Location"].startswith(reverse("login")))

    def test_anonymous_destructive_posts_are_redirected(self):
        for name, args in (("rule_delete", [self.hello.pk]), ("ruleset_delete", [self.ruleset.pk])):
            with self.subTest(name=name):
                response = self.client.post(reverse(f"rules:{name}", args=args))
                self.assertEqual(response.status_code, 302)
                self.assertTrue(response["Location"].startswith(reverse("login")))
        self.assertTrue(Ruleset.objects.filter(pk=self.ruleset.pk).exists())

    def test_user_without_role_is_refused_everywhere(self):
        self.login(self.nobody)
        for name, args, method, _, _ in self.cases():
            with self.subTest(name=name, method=method):
                response = self.request(method, reverse(f"rules:{name}", args=args))
                self.assertEqual(response.status_code, 403)

    def test_viewer(self):
        self.login(self.viewer)
        for name, args, method, kind, expected in self.cases():
            with self.subTest(name=name, method=method):
                response = self.request(method, reverse(f"rules:{name}", args=args))
                if kind == WRITE:
                    self.assertEqual(response.status_code, 403)
                else:
                    self.assertEqual(response.status_code, expected)

    def test_viewer_cannot_delete(self):
        self.login(self.viewer)
        response = self.client.post(reverse("rules:rule_delete", args=[self.hello.pk]))
        self.assertEqual(response.status_code, 403)
        response = self.client.post(reverse("rules:ruleset_delete", args=[self.ruleset.pk]))
        self.assertEqual(response.status_code, 403)
        self.assertTrue(Rule.objects.filter(pk=self.hello.pk).exists())
        self.assertTrue(Ruleset.objects.filter(pk=self.ruleset.pk).exists())

    def test_viewer_cannot_upload_or_scan_directory(self):
        self.login(self.viewer)
        upload = SimpleUploadedFile("x.yar", b"rule x { condition: true }")
        response = self.client.post(reverse("rules:import_upload"), {"rule_files": [upload]})
        self.assertEqual(response.status_code, 403)
        self.assertFalse(Ruleset.objects.filter(path="x.yar").exists())

    def test_editor(self):
        self.login(self.editor)
        for name, args, method, _, expected in self.cases():
            with self.subTest(name=name, method=method):
                response = self.request(method, reverse(f"rules:{name}", args=args))
                self.assertEqual(response.status_code, expected)

    def test_editor_can_delete(self):
        self.login(self.editor)
        response = self.client.post(reverse("rules:rule_delete", args=[self.hello.pk]))
        self.assertRedirects(response, self.ruleset.get_absolute_url())
        response = self.client.post(reverse("rules:ruleset_delete", args=[self.ruleset.pk]))
        self.assertRedirects(response, reverse("rules:ruleset_list"))

    def test_post_only_endpoints_refuse_get(self):
        self.login(self.editor)
        for name, args in (
            ("rule_restore", [self.hello.pk, 1]),
            ("import_scan", []),
            ("import_upload", []),
        ):
            with self.subTest(name=name):
                response = self.client.get(reverse(f"rules:{name}", args=args))
                self.assertEqual(response.status_code, 405)

    def test_get_never_changes_state(self):
        """Delete pages only confirm on GET."""
        self.login(self.editor)
        self.client.get(reverse("rules:rule_delete", args=[self.hello.pk]))
        self.client.get(reverse("rules:ruleset_delete", args=[self.ruleset.pk]))
        self.assertTrue(Rule.objects.filter(pk=self.hello.pk).exists())
        self.assertTrue(Ruleset.objects.filter(pk=self.ruleset.pk).exists())

    def test_csrf_is_enforced(self):
        from django.test import Client

        client = Client(enforce_csrf_checks=True)
        client.force_login(self.editor)
        response = client.post(reverse("rules:rule_delete", args=[self.hello.pk]))
        self.assertEqual(response.status_code, 403)
        self.assertTrue(Rule.objects.filter(pk=self.hello.pk).exists())
        self.assertContains(response, "form has expired", status_code=403)

    def test_templates_hide_write_controls_from_viewers(self):
        self.login(self.viewer)
        pages = {
            "rule_detail": [self.hello.pk],
            "ruleset_detail": [self.ruleset.pk],
            "rule_version": [self.hello.pk, 1],
            "rule_list": [],
            "import": [],
        }
        forbidden = [
            reverse("rules:rule_edit", args=[self.hello.pk]),
            reverse("rules:rule_delete", args=[self.hello.pk]),
            reverse("rules:ruleset_delete", args=[self.ruleset.pk]),
            reverse("rules:rule_create"),
            reverse("rules:import_scan"),
            reverse("rules:import_upload"),
            reverse("rules:rule_restore", args=[self.hello.pk, 1]),
        ]
        for name, args in pages.items():
            response = self.client.get(reverse(f"rules:{name}", args=args))
            for url in forbidden:
                with self.subTest(page=name, url=url):
                    self.assertNotContains(response, f'"{url}')

    def test_editor_sees_write_controls(self):
        self.login(self.editor)
        response = self.client.get(reverse("rules:rule_detail", args=[self.hello.pk]))
        self.assertContains(response, reverse("rules:rule_edit", args=[self.hello.pk]))
        self.assertContains(response, reverse("rules:rule_delete", args=[self.hello.pk]))
        response = self.client.get(reverse("rules:import"))
        self.assertContains(response, reverse("rules:import_scan"))
        self.assertContains(response, reverse("rules:import_upload"))


class ObjectLookupOrderTests(ViewTestCase):
    """A user without the permission gets 403 whether or not the id exists."""

    def test_missing_and_existing_ids_look_the_same_without_permission(self):
        self.login(self.viewer)
        for name, existing, missing in (
            ("rule_edit", [self.hello.pk], [999999]),
            ("rule_delete", [self.hello.pk], [999999]),
            ("rule_restore", [self.hello.pk, 1], [999999, 1]),
            ("ruleset_delete", [self.ruleset.pk], [999999]),
        ):
            for method in ("get", "post"):
                with self.subTest(name=name, method=method):
                    request = getattr(self.client, method)
                    first = request(reverse(f"rules:{name}", args=existing))
                    second = request(reverse(f"rules:{name}", args=missing))
                    if not (name == "rule_restore" and method == "get"):
                        self.assertEqual(first.status_code, 403)
                        self.assertEqual(second.status_code, 403)

    def test_nobody_gets_403_for_missing_read_objects(self):
        self.login(self.nobody)
        for name, args in (
            ("rule_detail", [999999]),
            ("ruleset_detail", [999999]),
            ("import_run", [999999]),
            ("rule_version", [999999, 1]),
        ):
            with self.subTest(name=name):
                self.assertEqual(
                    self.client.get(reverse(f"rules:{name}", args=args)).status_code, 403
                )


class NewCollectionPermissionTests(ViewTestCase):
    def test_creating_a_collection_needs_add_ruleset(self):
        from django.contrib.auth.models import Permission

        user = self.make_user("rule-adder", None)
        user.user_permissions.add(
            *Permission.objects.filter(
                content_type__app_label="rules", codename__in=["view_rule", "add_rule"]
            )
        )
        self.login(user)
        text = "rule brand_new { condition: true }"
        response = self.client.post(
            reverse("rules:rule_create"),
            {"ruleset": "new", "new_ruleset": "Mine", "text": text, "action": "save"},
        )
        self.assertEqual(response.status_code, 403)
        self.assertFalse(Ruleset.objects.filter(name="Mine").exists())
        # Adding to an existing ruleset only needs add_rule.
        response = self.client.post(
            reverse("rules:rule_create"),
            {"ruleset": self.ruleset.pk, "text": text, "action": "save"},
        )
        self.assertEqual(response.status_code, 302)
        # Naming an existing manual collection creates nothing: add_rule is enough.
        from rules.services import editing

        existing = editing.manual_ruleset("Shared")
        response = self.client.post(
            reverse("rules:rule_create"),
            {
                "ruleset": "new",
                "new_ruleset": "Shared",
                "text": "rule into_existing { condition: true }",
                "action": "save",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(Rule.objects.get(name="into_existing").ruleset, existing)
