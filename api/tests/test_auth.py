"""Authentication, errors, sessions/CSRF, last-used writes and rate limiting."""

import multiprocessing
import tempfile
from datetime import timedelta
from pathlib import Path
from unittest import mock

from django.db import connection
from django.test import override_settings
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from django.utils import timezone

from api import keys, ratelimit
from api.models import ApiKey
from api.tests.helpers import ApiTestCase
from api.tests.ratelimit_worker import hammer

ME = "/api/v1/me/"
RULES = "/api/v1/rules/"


class AuthenticationTests(ApiTestCase):
    def assert_401(self, response, code):
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["error"]["code"], code)
        self.assertTrue(response["WWW-Authenticate"].startswith("Bearer "))

    def test_missing_key(self):
        self.assert_401(self.api("GET", RULES, None), "missing_key")

    def test_malformed_header_and_key(self):
        for header in ["Basic abc", "Bearer", "Token yd_x", "bearer   "]:
            with self.subTest(header=header):
                response = self.client.get(RULES, headers={"Authorization": header})
                self.assert_401(response, "invalid_key")
        self.assert_401(self.api("GET", RULES, "yd_short"), "invalid_key")
        self.assert_401(self.api("GET", RULES, "not-a-key-at-all"), "invalid_key")

    def test_wrong_secret_and_unknown_id(self):
        secret = self.key_for(self.viewer)
        wrong = secret[:-4] + ("AAAA" if not secret.endswith("AAAA") else "BBBB")
        self.assert_401(self.api("GET", RULES, wrong), "invalid_key")
        unknown = "yd_000000000000_" + secret.rsplit("_", 1)[-1].rjust(43, "A")[-43:]
        self.assert_401(self.api("GET", RULES, unknown), "invalid_key")

    def test_scheme_is_case_insensitive(self):
        secret = self.key_for(self.viewer)
        response = self.client.get(ME, headers={"Authorization": f"bearer {secret}"})
        self.assertEqual(response.status_code, 200)

    def test_revoked_key(self):
        key, secret = keys.create_key(self.viewer, "x")
        keys.revoke_key(key)
        self.assert_401(self.api("GET", RULES, secret), "revoked_key")

    def test_expired_key(self):
        key, secret = keys.create_key(self.viewer, "x", expires_in=timedelta(days=1))
        self.assertEqual(self.api("GET", ME, secret).status_code, 200)
        with mock.patch("api.keys.timezone.now", return_value=timezone.now() + timedelta(days=2)):
            self.assert_401(self.api("GET", RULES, secret), "expired_key")

    def test_inactive_user(self):
        secret = self.key_for(self.viewer)
        self.viewer.is_active = False
        self.viewer.save()
        self.assert_401(self.api("GET", ME, secret), "inactive_user")

    def test_user_without_role(self):
        secret = self.key_for(self.nobody)
        me = self.api("GET", ME, secret)
        self.assertEqual(me.status_code, 200)
        self.assertEqual(me.json()["roles"], [])
        response = self.api("GET", RULES, secret)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["error"]["code"], "permission_denied")
        self.assertIn("Viewers or Editors", response.json()["error"]["message"])

    def test_me_describes_user_and_key(self):
        key, secret = keys.create_key(self.editor, "laptop")
        data = self.api("GET", ME, secret).json()
        self.assertEqual(data["username"], "editor")
        self.assertEqual(data["roles"], ["Editors"])
        self.assertIn("rules.change_rule", data["permissions"])
        self.assertEqual(data["key"]["prefix"], key.prefix)
        self.assertNotIn(secret, str(data))

    def test_key_is_not_logged(self):
        secret = self.key_for(self.viewer)
        with self.assertLogs(level="DEBUG") as logs:
            self.api("GET", "/api/v1/nope/", secret)
            self.api("GET", RULES, secret[:-1] + "x")
            self.api("GET", RULES, None)
        self.assertNotIn(secret, "\n".join(logs.output))
        self.assertNotIn(secret[:-1], "\n".join(logs.output))


class SessionAndCsrfTests(ApiTestCase):
    """The API ignores browser sessions entirely, so CSRF has nothing to borrow."""

    def test_session_cookie_is_not_authentication(self):
        self.client.force_login(self.editor)
        for method, url in [
            ("GET", RULES),
            ("GET", ME),
            ("DELETE", f"/api/v1/rules/{self.hello.pk}/"),
        ]:
            with self.subTest(method=method, url=url):
                response = self.api(method, url, None)
                self.assertEqual(response.status_code, 401)
        self.assertTrue(type(self.hello).objects.filter(pk=self.hello.pk).exists())

    def test_cross_site_post_with_session_and_no_csrf_token_is_refused(self):
        client = self.client_class(enforce_csrf_checks=True)
        client.force_login(self.editor)
        response = client.post(
            RULES,
            data='{"text": "rule x { condition: true }", "collection": "c"}',
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response["Content-Type"], "application/json")

    def test_key_works_without_csrf_token_and_sets_no_cookies(self):
        client = self.client_class(enforce_csrf_checks=True)
        secret = self.key_for(self.editor)
        response = client.post(
            RULES,
            data='{"text": "rule csrf_free { condition: true }", "collection": "c"}',
            content_type="application/json",
            headers={"Authorization": f"Bearer {secret}"},
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(dict(response.cookies), {})

    def test_key_wins_over_session_user(self):
        self.client.force_login(self.editor)
        secret = self.key_for(self.viewer)
        self.assertEqual(self.api("GET", ME, secret).json()["username"], "viewer")
        response = self.api("DELETE", f"/api/v1/rules/{self.hello.pk}/", secret)
        self.assertEqual(response.status_code, 403)


class JsonErrorTests(ApiTestCase):
    def setUp(self):
        self.secret = self.key_for(self.editor)

    def test_unknown_paths_are_json_404_not_login_redirects(self):
        for url in [
            "/api/",
            "/api/v1/",
            "/api/v1/nope/",
            "/api/v2/rules/",
            "/api/v1/rules",
            "/api/v1/rules/abc/",
        ]:
            for key in (None, self.secret):
                with self.subTest(url=url, key=bool(key)):
                    response = self.api("GET", url, key)
                    self.assertEqual(response.status_code, 404)
                    self.assertEqual(response.json()["error"]["code"], "not_found")

    def test_missing_object_is_json_404(self):
        response = self.api("GET", "/api/v1/rules/999999/", self.secret)
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json()["error"]["code"], "not_found")

    def test_wrong_method_is_json_405_with_allow(self):
        response = self.api("PATCH", RULES, self.secret)
        self.assertEqual(response.status_code, 405)
        self.assertEqual(response["Allow"], "GET, POST")

    def test_validation_errors_are_json(self):
        response = self.api(
            "POST", RULES, self.secret, data="{not json", content_type="application/json"
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"]["code"], "invalid_json")
        response = self.api("POST", RULES, self.secret, data={"text": "x"})
        self.assertEqual(response.status_code, 415)
        response = self.api(
            "POST", RULES, self.secret, data={"collection": "c"}, content_type="application/json"
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("text", response.json()["error"]["fields"])

    @override_settings(DEBUG=False)
    def test_unhandled_exception_is_json_500_without_details(self):
        with (
            mock.patch("api.endpoints.account.serializers.api_key", side_effect=RuntimeError("x")),
            self.assertLogs("api.registry", level="ERROR") as logs,
        ):
            response = self.api("GET", ME, self.secret)
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json()["error"]["code"], "server_error")
        self.assertNotIn("RuntimeError", response.content.decode())
        self.assertNotIn(self.secret, "\n".join(logs.output))

    def test_head_is_get_without_body(self):
        response = self.client.head(ME, headers={"Authorization": f"Bearer {self.secret}"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b"")

    def test_answers_are_not_cached(self):
        self.assertIn("no-store", self.api("GET", ME, self.secret)["Cache-Control"])


class LastUsedTests(ApiTestCase):
    def test_last_used_is_written_once_per_interval(self):
        key, secret = keys.create_key(self.viewer, "x")
        self.assertIsNone(key.last_used_at)
        self.api("GET", ME, secret)
        key.refresh_from_db()
        first = key.last_used_at
        self.assertIsNotNone(first)
        for _ in range(3):
            with CaptureQueriesContext(connection) as queries:
                self.api("GET", ME, secret)
            writes = [q["sql"] for q in queries if q["sql"].lstrip().upper().startswith("UPDATE")]
            self.assertEqual(writes, [])
        key.refresh_from_db()
        self.assertEqual(key.last_used_at, first)
        later = timezone.now() + timedelta(seconds=301)
        with mock.patch("api.keys.timezone.now", return_value=later):
            self.api("GET", ME, secret)
        key.refresh_from_db()
        self.assertEqual(key.last_used_at, later)

    def test_touch_survives_a_locked_database(self):
        key, _ = keys.create_key(self.viewer, "x")
        from django.db import OperationalError

        with mock.patch.object(ApiKey.objects, "filter", side_effect=OperationalError("locked")):
            self.assertFalse(keys.touch(key, timezone.now()))


class RateLimitTests(ApiTestCase):
    @override_settings(YARADUDE_API_RATE_LIMIT=3, YARADUDE_API_RATE_WINDOW=60)
    def test_limit_per_key(self):
        secret = self.key_for(self.viewer)
        other = self.key_for(self.viewer, "other")
        statuses = [self.api("GET", ME, secret).status_code for _ in range(4)]
        self.assertEqual(statuses, [200, 200, 200, 429])
        response = self.api("GET", ME, secret)
        self.assertEqual(response.json()["error"]["code"], "rate_limited")
        self.assertGreaterEqual(int(response["Retry-After"]), 1)
        self.assertEqual(response["RateLimit-Remaining"], "0")
        # Another key of the same user has its own bucket.
        self.assertEqual(self.api("GET", ME, other).status_code, 200)

    @override_settings(YARADUDE_API_RATE_LIMIT=0)
    def test_zero_switches_it_off(self):
        secret = self.key_for(self.viewer)
        for _ in range(5):
            self.assertEqual(self.api("GET", ME, secret).status_code, 200)

    def test_bucket_refills_over_time(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            self.assertTrue(ratelimit.take(path, "k", 2, 10, now=100).allowed)
            self.assertTrue(ratelimit.take(path, "k", 2, 10, now=100).allowed)
            denied = ratelimit.take(path, "k", 2, 10, now=100)
            self.assertFalse(denied.allowed)
            self.assertEqual(denied.retry_after, 5)
            self.assertTrue(ratelimit.take(path, "k", 2, 10, now=105.1).allowed)

    def test_limit_holds_across_processes(self):
        """Four worker processes share one bucket: exactly `capacity` requests pass."""
        context = multiprocessing.get_context("spawn")
        with tempfile.TemporaryDirectory() as directory:
            results = context.Queue()
            workers = [
                context.Process(target=hammer, args=(directory, "shared", 30, results))
                for _ in range(4)
            ]
            for worker in workers:
                worker.start()
            outcomes = [results.get(timeout=60) for _ in range(120)]
            for worker in workers:
                worker.join(timeout=60)
        self.assertEqual(sum(outcomes), 50)

    def test_bucket_file_name_does_not_contain_the_key(self):
        key, secret = keys.create_key(self.viewer, "x")
        name = ratelimit.bucket_path(Path("/tmp"), key.public_id).name
        self.assertNotIn(key.public_id, name)
        self.assertNotIn(secret, name)


class AdminTests(ApiTestCase):
    def test_admin_lists_keys_without_secrets_and_can_revoke(self):
        key, secret = keys.create_key(self.viewer, "x")
        self.client.force_login(self.superuser)
        response = self.client.get(reverse("admin:api_apikey_changelist"))
        self.assertContains(response, key.prefix)
        self.assertNotContains(response, secret)
        self.assertNotContains(response, key.secret_sha256)
        response = self.client.post(
            reverse("admin:api_apikey_changelist"),
            {"action": "revoke", "_selected_action": [key.pk]},
        )
        key.refresh_from_db()
        self.assertTrue(key.is_revoked)
