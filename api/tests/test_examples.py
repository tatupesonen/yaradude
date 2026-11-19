"""
The documented examples are correct: every curl example names a real route
with the documented method, and every Python example, run with the
downloadable client against the test server, reaches its endpoint with a
body the endpoint accepts.
"""

import email.message
import io
import os
import shlex
import sys
import tempfile
import types
import urllib.error
from pathlib import Path
from typing import Any
from unittest import mock
from urllib.parse import urlsplit

from api import examples
from api.registry import ENDPOINTS, find
from api.tests.helpers import ApiTestCase

BASE = "http://testserver/api/v1"


def parse_curl(command: str) -> tuple[str, str, list[str]]:
    """Method, URL and option list of a generated curl command."""
    args = shlex.split(command.replace("\\\n", " "))
    assert args[0] == "curl"
    method = "GET"
    options = []
    url = ""
    i = 1
    while i < len(args):
        arg = args[i]
        if arg == "-X":
            method = args[i + 1]
            i += 1
        elif arg in ("-H", "-d", "-F"):
            options.append(f"{arg} {args[i + 1]}")
            if arg in ("-d", "-F") and method == "GET":
                method = "POST"
            i += 1
        elif not arg.startswith("-"):
            url = arg
        i += 1
    return method, url, options


class CurlExampleTests(ApiTestCase):
    def test_every_curl_example_targets_its_route_and_method(self):
        for e in ENDPOINTS:
            with self.subTest(e.operation):
                method, url, options = parse_curl(examples.curl(e, BASE))
                self.assertEqual(method, e.method)
                self.assertTrue(url.startswith(BASE + "/"))
                self.assertEqual(find(method, urlsplit(url).path), e)
                self.assertIn("-H Authorization: Bearer $YARADUDE_API_KEY", options)
                if e.body and e.body.kind == "json" and examples.body_of(e):
                    self.assertIn("-H Content-Type: application/json", options)
                if e.body and e.body.kind == "multipart":
                    required = [f.name for f in e.body.fields if f.required]
                    for name in required:
                        self.assertTrue(any(o.startswith(f"-F {name}=") for o in options))


class FakeResponse:
    def __init__(self, response):
        self.status = response.status_code
        self._body = response.content
        self.headers = email.message.Message()
        for name, value in response.items():
            self.headers[name] = value

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class PythonExampleTests(ApiTestCase):
    def load_client(self) -> types.ModuleType:
        module = types.ModuleType("yaradude_client")
        exec(
            compile(examples.client_source("http://testserver"), "yaradude_client.py", "exec"),
            module.__dict__,
        )
        return module

    def test_every_python_example_reaches_its_endpoint(self):
        client = self.load_client()
        seen: list[tuple[str, str, int, bytes]] = []

        def urlopen(request):
            parts = urlsplit(request.full_url)
            path = parts.path + (f"?{parts.query}" if parts.query else "")
            headers = {k: v for k, v in request.header_items() if k.lower() != "content-type"}
            # The stubs type Client.generic() as returning the request.
            generic: Any = self.client.generic
            if request.data is not None:
                assert isinstance(request.data, bytes)  # the client always sends bytes
                response = generic(
                    request.get_method(),
                    path,
                    request.data,
                    content_type=request.get_header("Content-type"),
                    headers=headers,
                )
            else:
                response = generic(request.get_method(), path, headers=headers)
            seen.append((request.get_method(), parts.path, response.status_code, response.content))
            if response.status_code >= 400:
                raise urllib.error.HTTPError(
                    request.full_url,
                    response.status_code,
                    "error",
                    FakeResponse(response).headers,
                    io.BytesIO(response.content),
                )
            return FakeResponse(response)

        # A superuser holds every permission, including purge.
        key = self.key_for(self.superuser)
        with tempfile.TemporaryDirectory() as work:
            for name in ("first.yar", "second.yar"):
                Path(work, name).write_text(f"rule example_{name[:-4]} {{ condition: true }}\n")
            Path(work, "suspicious.bin").write_bytes(b"hello world")
            old = os.getcwd()
            os.chdir(work)
            try:
                with (
                    mock.patch.dict(os.environ, {"YARADUDE_API_KEY": key}),
                    mock.patch.dict(sys.modules, {"yaradude_client": client}),
                    mock.patch.object(client.urllib.request, "urlopen", urlopen),
                ):
                    for e in ENDPOINTS:
                        with self.subTest(e.operation):
                            seen.clear()
                            try:
                                exec(examples.python(e), {"print": lambda *a: None})
                            except client.ApiError as error:
                                self.assertEqual(error.status, 404, error)
                            self.assertEqual(len(seen), 1)
                            method, path, status, body = seen[0]
                            self.assertEqual(method, e.method)
                            self.assertEqual(find(method, path), e)
                            # The body was accepted: anything but a missing
                            # example object counts as a wrong example.
                            self.assertNotIn(status, (400, 405, 415, 422), body)
                            self.assertNotIn(b"No such API endpoint", body)
            finally:
                os.chdir(old)

    def test_client_reports_api_errors(self):
        client = self.load_client()

        def urlopen(request):
            response = self.client.get(urlsplit(request.full_url).path)
            raise urllib.error.HTTPError(
                request.full_url,
                response.status_code,
                "x",
                FakeResponse(response).headers,
                io.BytesIO(response.content),
            )

        with (
            mock.patch.dict(os.environ, {"YARADUDE_API_KEY": "yd_nope"}),
            mock.patch.object(client.urllib.request, "urlopen", urlopen),
            self.assertRaises(client.ApiError) as raised,
        ):
            client.call("GET", "/me/")
        self.assertEqual(
            (raised.exception.status, raised.exception.error["code"]), (401, "missing_key")
        )
