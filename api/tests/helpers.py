"""Fixtures of the API tests: users of every role, sample rules and keys."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from django.test import override_settings

from accounts.models import User
from api import keys
from api.registry import find
from api.schemas import ref
from api.tests.schema_check import errors
from rules.tests.test_views_common import ViewTestCase

_RATE_DIR = Path(tempfile.mkdtemp(prefix="yaradude-api-test-ratelimit-"))

# Errors any endpoint can answer without listing them itself.
GENERIC_ERRORS = {400, 401, 403, 404, 405, 413, 415, 429, 500}


@override_settings(YARADUDE_API_RATE_DIR=_RATE_DIR)
class ApiTestCase(ViewTestCase):
    """ViewTestCase's users and rules, plus a superuser and API keys."""

    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.superuser = User.objects.create_superuser("root", password=cls.password, email="")

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        shutil.rmtree(_RATE_DIR, ignore_errors=True)
        _RATE_DIR.mkdir(exist_ok=True)

    def key_for(self, user: User, name: str = "test") -> str:
        _, secret = keys.create_key(user, name)
        return secret

    def api(self, method: str, url: str, key: str | None, **kwargs: Any):
        """
        An API request with `key` as Bearer token (none when key is None).
        Every answer is checked against the documentation: its status must
        be documented for the endpoint (or be a generic error) and its JSON
        must match the documented schema.
        """
        if key is not None:
            kwargs.setdefault("headers", {})["Authorization"] = f"Bearer {key}"
        response = getattr(self.client, method.lower())(url, **kwargs)
        self.assert_documented(method, url, response)
        return response

    def assert_documented(self, method: str, url: str, response) -> None:
        endpoint = find(method, urlsplit(url).path)
        replies = {r.status: r for r in endpoint.replies} if endpoint else {}
        status = response.status_code
        reply = replies.get(status)
        if reply is None:
            self.assertIn(status, GENERIC_ERRORS, f"{method} {url}: undocumented {status}")
            schema = "Error"
        elif reply.file:
            self.assertIn("attachment", response["Content-Disposition"])
            return
        elif reply.schema is None:
            self.assertEqual(response.content, b"")
            return
        else:
            schema = reply.schema
        self.assertEqual(response["Content-Type"], "application/json", f"{method} {url}")
        problems = errors(response.json(), ref(schema))
        self.assertEqual(problems, [], f"{method} {url} {status} does not match {schema}")
