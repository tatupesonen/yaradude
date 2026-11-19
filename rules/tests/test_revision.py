import tempfile
from pathlib import Path

from django.test import TestCase, override_settings

from rules.models import Rule, Ruleset
from rules.services import editing, revision
from rules.services.compiler import check_ruleset
from rules.services.importer import import_directory, import_uploads

FILE = """rule one { condition: filesize > 1 }
rule two { condition: filesize > 2 }
rule three { condition: filesize > 3 }
"""


class RevisionTests(TestCase):
    def setUp(self) -> None:
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(override_settings(YARADUDE_RULES_DIR=self.root))
        self.path = self.root / "set.yar"
        self.path.write_text(FILE)
        import_directory(self.root)
        self.ruleset = Ruleset.objects.get()

    def assertMoves(self, action, moves: bool = True) -> None:  # noqa: ANN001
        before = revision.current()
        action()
        after = revision.current()
        if moves:
            self.assertGreater(after.number, before.number)
            assert after.changed_at is not None
        else:
            self.assertEqual(after, before)

    def reimport(self, text: str) -> None:
        self.path.write_text(text)
        import_directory(self.root)

    def test_current_is_one_query(self) -> None:
        with self.assertNumQueries(1):
            current = revision.current()
        self.assertGreater(current.number, 0)

    def test_initial_import_moves_it(self) -> None:
        from django.core.files.uploadedfile import SimpleUploadedFile

        self.assertMoves(lambda: import_uploads([]), moves=False)

        self.assertMoves(
            lambda: import_uploads(
                [SimpleUploadedFile("x.yar", b"rule x { condition: filesize > 0 }")]
            )
        )

    def test_import_update(self) -> None:
        self.assertMoves(lambda: self.reimport(FILE.replace("> 2", "> 22")))

    def test_import_removal_and_restore(self) -> None:
        self.assertMoves(
            lambda: self.reimport(FILE.replace("rule three { condition: filesize > 3 }\n", ""))
        )
        self.assertMoves(lambda: self.reimport(FILE))

    def test_import_reorder_only(self) -> None:
        lines = FILE.splitlines(keepends=True)
        self.assertMoves(lambda: self.reimport("".join(reversed(lines))))
        self.assertFalse(Rule.objects.filter(version__gt=1).exists())

    def test_identical_reimport_and_irrelevant_change_do_not_move_it(self) -> None:
        self.assertMoves(lambda: import_directory(self.root), moves=False)
        # Only a comment outside the rules changes: the file is processed, but
        # no rule's content, state or order changes.
        self.assertMoves(lambda: self.reimport(FILE + "\n// trailing comment\n"), moves=False)

    def test_recheck_that_changes_nothing(self) -> None:
        self.assertMoves(lambda: check_ruleset(self.ruleset), moves=False)

    def test_recheck_that_changes_compile_status(self) -> None:
        Rule.objects.filter(name="two").update(compile_error="stale")
        self.assertMoves(lambda: check_ruleset(self.ruleset))

    def test_edit_create_restore_delete(self) -> None:
        two = Rule.objects.get(name="two")
        self.assertMoves(lambda: editing.update_rule(two, "rule two { condition: filesize > 5 }"))
        self.assertMoves(
            lambda: editing.restore_version(two.versions.get(number=1), expected_version=2)
        )
        self.assertMoves(
            lambda: editing.create_rule(self.ruleset, "rule four { condition: filesize > 4 }")
        )
        self.assertMoves(lambda: editing.delete_rule(Rule.objects.get(name="four")))
        self.assertMoves(lambda: editing.delete_ruleset(self.ruleset))

    def test_refused_and_identical_edits_do_not_move_it(self) -> None:
        two = Rule.objects.get(name="two")
        self.assertMoves(lambda: editing.update_rule(two, "rule two { condition: nope }"), False)
        self.assertMoves(lambda: editing.update_rule(two, two.text), False)

    def test_admin_delete(self) -> None:
        from accounts.models import User

        admin = User.objects.create_superuser("admin", email="", password="pw")
        self.client.force_login(admin)
        rule = Rule.objects.get(name="one")
        before = revision.current()
        response = self.client.post(f"/admin/rules/rule/{rule.pk}/delete/", {"post": "yes"})
        self.assertEqual(response.status_code, 302)
        self.assertGreater(revision.current().number, before.number)
        self.assertFalse(Rule.objects.filter(pk=rule.pk).exists())

    def test_soft_delete_restore_and_purge(self) -> None:
        one = Rule.objects.get(name="one")
        self.assertMoves(lambda: editing.delete_rule(one))
        self.assertMoves(lambda: editing.delete_rule(one), moves=False)  # already deleted
        self.assertMoves(lambda: editing.restore_rule(one))
        self.assertMoves(lambda: editing.delete_ruleset(self.ruleset))
        self.assertMoves(lambda: editing.restore_ruleset(self.ruleset))
        self.assertMoves(lambda: editing.purge_rule(Rule.objects.get(name="two")))
        self.assertMoves(lambda: editing.purge_ruleset(self.ruleset))
