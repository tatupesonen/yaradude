import io
import os
import tempfile
from pathlib import Path
from unittest import mock

from django.conf import settings
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase, override_settings

from accounts.models import User
from rules.models import ImportRun, Rule

EXAMPLES = Path(settings.BASE_DIR) / "yara-rules" / "examples"


class ImportRulesCommandTests(TestCase):
    def call(self, *args: str) -> str:
        out = io.StringIO()
        call_command("import_rules", *args, stdout=out)
        return out.getvalue()

    def test_import_examples_then_unchanged(self) -> None:
        output = self.call(str(EXAMPLES))
        self.assertIn("Created: ", output)
        run = ImportRun.objects.get()
        self.assertEqual(run.origin, ImportRun.Origin.CLI)
        self.assertEqual((run.files_seen, run.files_failed), (3, 0))
        self.assertIn(run.summary, output)
        self.assertFalse(Rule.objects.failing().exists())

        output = self.call(str(EXAMPLES))
        self.assertEqual(
            output.strip(),
            "files: 3 seen, 0 changed, 3 unchanged, 0 failed; "
            f"rules: 0 created, 0 updated, 0 removed, {Rule.objects.count()} unchanged",
        )

    def test_defaults_to_rules_dir(self) -> None:
        with override_settings(YARADUDE_RULES_DIR=EXAMPLES):
            self.call()
        self.assertEqual(
            sorted(ImportRun.objects.get().files.values_list("path", flat=True)),
            ["documents.yar", "pe_basics.yar", "scripts/web.yara"],
        )

    def test_failure_exits_non_zero(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            Path(root, "ok.yar").write_text("rule ok { condition: filesize > 0 }")
            Path(root, "bad.yar").write_text("rule bad {")
            out = io.StringIO()
            with self.assertRaisesMessage(CommandError, "1 file(s) failed to import."):
                call_command("import_rules", root, stdout=out)
        self.assertIn("Failed: ", out.getvalue())
        self.assertIn('unterminated rule "bad"', out.getvalue())
        self.assertTrue(Rule.objects.filter(name="ok").exists())

    def test_missing_directory(self) -> None:
        with self.assertRaisesMessage(CommandError, "Not a directory"):
            self.call("/nonexistent/rules")


class EnsureSuperuserCommandTests(TestCase):
    ENV = {
        "DJANGO_SUPERUSER_USERNAME": "admin",
        "DJANGO_SUPERUSER_PASSWORD": "correct horse battery staple",
        "DJANGO_SUPERUSER_EMAIL": "admin@example.test",
    }

    def call(self, env: dict[str, str]) -> str:
        out = io.StringIO()
        with mock.patch.dict(os.environ, env, clear=False):
            for name in self.ENV.keys() - env.keys():
                os.environ.pop(name, None)
            call_command("ensure_superuser", stdout=out)
        return out.getvalue()

    def test_creates_superuser(self) -> None:
        output = self.call(self.ENV)
        self.assertIn('Superuser "admin" created.', output)
        user = User.objects.get()
        self.assertTrue(user.is_superuser and user.is_staff)
        self.assertEqual(user.email, "admin@example.test")
        self.assertTrue(user.check_password("correct horse battery staple"))

    def test_never_changes_existing_user(self) -> None:
        User.objects.create_user("admin", password="original", email="old@example.test")
        output = self.call(self.ENV)
        self.assertIn("already exists; left unchanged", output)
        user = User.objects.get()
        self.assertFalse(user.is_superuser)
        self.assertTrue(user.check_password("original"))
        self.assertEqual(user.email, "old@example.test")

    def test_does_nothing_without_username(self) -> None:
        output = self.call({})
        self.assertIn("not set", output)
        self.assertFalse(User.objects.exists())

    def test_requires_password(self) -> None:
        with self.assertRaisesMessage(CommandError, "DJANGO_SUPERUSER_PASSWORD is required"):
            self.call({"DJANGO_SUPERUSER_USERNAME": "admin"})
        self.assertFalse(User.objects.exists())

    def test_weak_password_is_refused(self) -> None:
        env = {**self.ENV, "DJANGO_SUPERUSER_PASSWORD": "admin"}
        with self.assertRaisesMessage(CommandError, "DJANGO_SUPERUSER_PASSWORD is too weak"):
            self.call(env)
        self.assertFalse(User.objects.exists())

    def test_password_like_the_username_is_refused(self) -> None:
        env = {
            **self.ENV,
            "DJANGO_SUPERUSER_USERNAME": "rosalind",
            "DJANGO_SUPERUSER_PASSWORD": "rosalind1",
        }
        with self.assertRaises(CommandError):
            self.call(env)


class DeployCheckTests(TestCase):
    """`check --deploy` is clean with production environment variables (section 11)."""

    def test_check_deploy(self) -> None:
        import subprocess
        import sys

        env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith(("DJANGO_", "YARADUDE_"))
        }
        env.update(
            DJANGO_DEBUG="false",
            DJANGO_SECRET_KEY="x" * 20 + "-production-like-secret-key-0123456789abcdef",
            DJANGO_ALLOWED_HOSTS="yaradude.example.test",
            DJANGO_CSRF_TRUSTED_ORIGINS="https://yaradude.example.test",
            YARADUDE_DB_PATH=str(
                Path(self.enterContext(tempfile.TemporaryDirectory())) / "db.sqlite3"
            ),
        )
        result = subprocess.run(
            [sys.executable, "manage.py", "check", "--deploy", "--fail-level", "WARNING"],
            cwd=settings.BASE_DIR,
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("System check identified no issues", result.stdout)
