import re
from unittest import mock

from django.db import DatabaseError
from django.test import TestCase, override_settings

from accounts.models import User


class HealthzTests(TestCase):
    def test_open_to_anonymous(self) -> None:
        response = self.client.get("/healthz/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b"ok\n")
        self.assertIn("no-cache", response["Cache-Control"])
        self.assertEqual(self.client.head("/healthz/").status_code, 200)

    def test_post_not_allowed(self) -> None:
        with self.assertLogs("django.request", "WARNING"):
            self.assertEqual(self.client.post("/healthz/").status_code, 405)

    def test_database_failure(self) -> None:
        with (
            mock.patch("config.views.connection.cursor", side_effect=DatabaseError),
            self.assertLogs("django.request", "ERROR"),
        ):
            response = self.client.get("/healthz/")
        self.assertEqual(response.status_code, 503)

    @override_settings(SECURE_SSL_REDIRECT=True, SECURE_REDIRECT_EXEMPT=[r"^healthz/$"])
    def test_exempt_from_https_redirect(self) -> None:
        self.assertEqual(self.client.get("/healthz/").status_code, 200)
        self.assertEqual(self.client.get("/").status_code, 301)


class LoginRequiredTests(TestCase):
    def test_anonymous_redirected_to_login(self) -> None:
        response = self.client.get("/")
        self.assertRedirects(response, "/accounts/login/?next=/", fetch_redirect_response=False)

    def test_admin_redirects_to_admin_login(self) -> None:
        response = self.client.get("/admin/")
        self.assertRedirects(response, "/admin/login/?next=/admin/", fetch_redirect_response=False)


class SecurityHeaderTests(TestCase):
    def test_csp_and_other_headers(self) -> None:
        response = self.client.get("/healthz/")
        csp = response["Content-Security-Policy"]
        self.assertIn("default-src 'self'", csp)
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertNotIn("unsafe-inline", csp)
        self.assertEqual(response["X-Frame-Options"], "DENY")
        self.assertEqual(response["X-Content-Type-Options"], "nosniff")

    def test_admin_works_under_csp(self) -> None:
        admin = User.objects.create_superuser("admin", email="", password="pw")
        self.client.force_login(admin)
        response = self.client.get("/admin/rules/rule/")
        self.assertEqual(response.status_code, 200)
        html = response.content.decode()
        # Every script is an external file from 'self'; no inline styles.
        self.assertEqual(re.findall(r"<script(?![^>]*\bsrc=)[^>]*>", html), [])
        self.assertNotIn("style=", html)
        self.assertIn("style-src 'self' 'nonce-", response["Content-Security-Policy"])
        for url in (
            "/admin/rules/ruleset/",
            "/admin/rules/importrun/",
            "/admin/rules/ruleversion/",
            "/admin/rules/importfile/",
            "/admin/rules/tag/",
            "/admin/accounts/user/",
        ):
            with self.subTest(url=url):
                self.assertEqual(self.client.get(url).status_code, 200)
