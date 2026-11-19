"""
The Tailwind build: pinned, never downloads on its own, works offline with
the binary present, and the committed stylesheet is what the build produces.
"""

import importlib.util
import socket
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

from django.conf import settings
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import SimpleTestCase, override_settings

HAS_TAILWIND_CLI = importlib.util.find_spec("django_tailwind_cli") is not None
COMMITTED_CSS = Path(settings.BASE_DIR) / "rules" / "static" / "rules" / "css" / "yaradude.css"


@contextmanager
def no_network():
    """Fail the test if anything in this process opens a network connection."""
    attempts = []

    def refuse(*args, **kwargs):
        attempts.append(args)
        raise OSError("network access is blocked in this test")

    with (
        mock.patch.object(socket.socket, "connect", refuse),
        mock.patch.object(socket.socket, "connect_ex", refuse),
        mock.patch.object(socket, "create_connection", refuse),
        mock.patch.object(socket, "getaddrinfo", refuse),
    ):
        yield attempts


def binary_path() -> Path | None:
    from django_tailwind_cli.config import get_config

    path = get_config().cli_path
    return path if path.is_file() else None


class TailwindSettingsTests(SimpleTestCase):
    def test_version_is_pinned_and_downloads_are_off(self):
        self.assertRegex(settings.TAILWIND_CLI_VERSION, r"^\d+\.\d+\.\d+$")
        self.assertIs(settings.TAILWIND_CLI_AUTOMATIC_DOWNLOAD, False)

    def test_committed_stylesheet_exists_and_is_local_only(self):
        css = COMMITTED_CSS.read_text()
        self.assertNotIn("@import", css)
        self.assertNotIn("@font-face", css)
        self.assertNotIn("url(", css)


@unittest.skipUnless(HAS_TAILWIND_CLI, "django-tailwind-cli (dev group) is not installed")
class TailwindBuildTests(SimpleTestCase):
    def test_missing_binary_fails_fast_without_network(self):
        with (
            tempfile.TemporaryDirectory() as empty,
            override_settings(TAILWIND_CLI_PATH=empty),
            no_network() as attempts,
            self.assertRaises(CommandError) as raised,
        ):
            call_command("tailwind", "build")
        self.assertIn("download", str(raised.exception).lower())
        self.assertEqual(attempts, [])

    def test_build_offline_matches_committed_stylesheet(self):
        if binary_path() is None:
            self.skipTest("Tailwind CLI binary not installed (manage.py tailwind download_cli)")
        with tempfile.TemporaryDirectory() as out:
            target = Path(out) / "yaradude.css"
            # An absolute TAILWIND_CLI_DIST_CSS replaces the static-dir prefix.
            with override_settings(TAILWIND_CLI_DIST_CSS=str(target)), no_network() as attempts:
                call_command("tailwind", "build")
            self.assertEqual(attempts, [])
            self.assertEqual(
                target.read_bytes(),
                COMMITTED_CSS.read_bytes(),
                "rules/static/rules/css/yaradude.css is stale: run "
                "`uv run python manage.py tailwind build` and commit the result.",
            )
