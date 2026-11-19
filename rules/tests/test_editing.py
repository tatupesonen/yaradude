from django.test import TestCase

from accounts.models import User
from rules.models import ImportFile, ImportRun, Rule, Ruleset, RuleVersion, Tag
from rules.services.compiler import check_ruleset
from rules.services.editing import (
    EditResult,
    create_rule,
    delete_rule,
    delete_ruleset,
    manual_ruleset,
    purge_rule,
    purge_ruleset,
    restore_rule,
    restore_ruleset,
    restore_version,
    update_rule,
    validate_rule_text,
)
from rules.tests.helpers import make_ruleset, saved_rule


class EditingTestCase(TestCase):
    def setUp(self) -> None:
        self.user = User.objects.create_user("editor")
        self.ruleset = make_ruleset(
            "private rule base : shared { condition: uint8(0) == 0x4D }\n"
            "rule uses_base : shared old { condition: base }\n",
            origin=Ruleset.Origin.DIRECTORY,
        )
        check_ruleset(self.ruleset)
        self.base = Rule.objects.get(name="base")
        self.uses_base = Rule.objects.get(name="uses_base")


class ValidateTests(EditingTestCase):
    def test_valid_text_is_not_saved(self) -> None:
        result = validate_rule_text(self.ruleset, "rule new { condition: base }")
        self.assertTrue(result.ok)
        assert result.parsed is not None
        self.assertEqual(result.parsed.name, "new")
        self.assertIsNone(result.rule)
        self.assertFalse(Rule.objects.filter(name="new").exists())

    def test_parse_error(self) -> None:
        result = validate_rule_text(self.ruleset, "\nrule new {\n condition: true\n")
        self.assertEqual((result.error, result.line), ('unterminated rule "new"', 2))

    def test_name_taken_including_removed_rules(self) -> None:
        Rule.objects.filter(pk=self.uses_base.pk).update(removed_at="2026-01-01T00:00Z")
        result = validate_rule_text(self.ruleset, "// c\nrule uses_base { condition: true }")
        self.assertEqual(result.error, 'A rule named "uses_base" already exists in this ruleset.')
        self.assertEqual(result.line, 2)

    def test_own_name_is_not_a_clash(self) -> None:
        result = validate_rule_text(
            self.ruleset, "rule uses_base { condition: base and filesize > 0 }", self.uses_base
        )
        self.assertTrue(result.ok)

    def test_compile_error_with_editor_line(self) -> None:
        result = validate_rule_text(
            self.ruleset, "// header\n\nrule new {\n  condition:\n    nope\n}"
        )
        self.assertFalse(result.ok)
        self.assertEqual(result.line, 5)
        self.assertIn("unknown identifier `nope`", result.error)

    def test_warnings(self) -> None:
        result = validate_rule_text(self.ruleset, 'rule new { strings: $a = "a" condition: $a }')
        self.assertTrue(result.ok)
        self.assertEqual(len(result.warnings), 1)


class CreateTests(EditingTestCase):
    def test_create(self) -> None:
        result = create_rule(
            self.ruleset,
            'import "pe"\n\nrule new : shared fresh {\n meta:\n  author = "Eve"\n'
            " condition:\n  base and pe.is_pe\n}",
            self.user,
        )
        self.assertTrue(result.ok, result.error)
        rule = saved_rule(result)
        self.assertEqual((rule.name, rule.position, rule.version), ("new", 2, 1))
        self.assertEqual((rule.imports, rule.author, rule.imported_sha256), (["pe"], "Eve", ""))
        self.assertFalse(rule.is_modified)
        self.assertEqual(rule.compile_error, "")
        self.assertEqual(sorted(rule.tags.values_list("name", flat=True)), ["fresh", "shared"])
        version = rule.versions.get()
        self.assertEqual(
            (version.number, version.origin, version.created_by, version.sha256),
            (1, RuleVersion.Origin.CREATE, self.user, rule.sha256),
        )
        self.ruleset.refresh_from_db()
        self.assertEqual(self.ruleset.updated_at, rule.updated_at)

    def test_refused_when_rule_does_not_compile(self) -> None:
        result = create_rule(self.ruleset, "rule new { condition: nope }", self.user)
        self.assertFalse(result.ok)
        self.assertIsNone(result.rule)
        self.assertFalse(Rule.objects.filter(name="new").exists())

    def test_into_new_manual_ruleset(self) -> None:
        ruleset = manual_ruleset("My rules")
        self.assertEqual(manual_ruleset("My rules"), ruleset)
        self.assertEqual(
            (ruleset.origin, ruleset.path, ruleset.name), ("manual", "My rules", "My rules")
        )
        result = create_rule(ruleset, "rule mine { condition: filesize > 0 }")
        self.assertEqual(saved_rule(result).position, 0)
        ruleset.refresh_from_db()
        self.assertEqual(ruleset.compile_error, "")


class UpdateTests(EditingTestCase):
    def test_edit(self) -> None:
        result = update_rule(
            self.uses_base,
            "rule uses_base : shared new { condition: base and filesize > 1 }",
            self.user,
        )
        self.assertTrue(result.ok, result.error)
        rule = saved_rule(result)
        self.assertEqual(rule.version, 2)
        self.assertIn("filesize > 1", rule.source)
        self.assertEqual(sorted(rule.tags.values_list("name", flat=True)), ["new", "shared"])
        self.assertFalse(Tag.objects.filter(name="old").exists())
        self.assertEqual(
            list(rule.versions.values_list("number", "origin", "created_by")),
            [(2, "edit", self.user.pk), (1, "create", None)],
        )

    def test_identical_text_saves_nothing(self) -> None:
        result = update_rule(self.uses_base, self.uses_base.text, self.user)
        self.assertTrue(result.ok)
        self.assertEqual(saved_rule(result).version, 1)
        self.assertEqual(RuleVersion.objects.filter(rule=self.uses_base).count(), 1)

    def test_refused_when_this_rule_does_not_compile(self) -> None:
        result = update_rule(self.uses_base, "rule uses_base { condition: nope }", self.user)
        self.assertFalse(result.ok)
        self.uses_base.refresh_from_db()
        self.assertEqual(self.uses_base.version, 1)

    def test_saved_when_it_breaks_a_sibling(self) -> None:
        result = update_rule(self.base, "private rule renamed { condition: true }", self.user)
        self.assertTrue(result.ok, result.error)
        self.assertEqual([b.rule.name for b in result.broken], ["uses_base"])
        self.assertEqual(saved_rule(result).name, "renamed")
        # The ruleset was re-checked.
        self.uses_base.refresh_from_db()
        self.assertIn("unknown identifier `base`", self.uses_base.compile_error)
        self.ruleset.refresh_from_db()
        self.assertEqual(self.ruleset.compile_error, "1 of 2 rules do not compile: uses_base")

    def test_rename_to_existing_name_is_refused(self) -> None:
        result = update_rule(self.uses_base, "private rule base { condition: true }")
        self.assertIn("already exists", result.error)


class RestoreAndDeleteTests(EditingTestCase):
    def test_restore(self) -> None:
        update_rule(self.uses_base, "rule uses_base : new { condition: base and filesize > 1 }")
        version_1 = self.uses_base.versions.get(number=1)
        result = restore_version(version_1, self.user)
        self.assertTrue(result.ok, result.error)
        rule = saved_rule(result)
        self.assertEqual(rule.version, 3)
        self.assertEqual(rule.source, version_1.source)
        self.assertEqual(sorted(rule.tags.values_list("name", flat=True)), ["old", "shared"])
        latest = rule.versions.first()
        assert latest is not None
        self.assertEqual(
            (latest.number, latest.origin, latest.created_by), (3, "restore", self.user)
        )

    def test_restore_refused_when_version_no_longer_compiles(self) -> None:
        update_rule(self.base, "private rule renamed { condition: true }")
        update_rule(self.uses_base, "rule uses_base { condition: renamed }")
        result = restore_version(self.uses_base.versions.get(number=1))
        self.assertFalse(result.ok)
        self.assertIn("unknown identifier `base`", result.error)

    def test_purge(self) -> None:
        update_rule(self.base, "private rule renamed : shared { condition: true }")
        self.assertTrue(Rule.objects.get(name="uses_base").compile_error)
        purge_rule(Rule.objects.get(name="uses_base"))
        self.assertFalse(Rule.objects.filter(name="uses_base").exists())
        self.assertFalse(RuleVersion.objects.filter(rule__name="uses_base").exists())
        self.assertFalse(Tag.objects.filter(name="old").exists())
        self.assertTrue(Tag.objects.filter(name="shared").exists())
        self.ruleset.refresh_from_db()
        self.assertEqual(self.ruleset.compile_error, "")

    def test_purge_ruleset_keeps_import_history(self) -> None:
        other = make_ruleset("rule elsewhere : shared { condition: filesize > 0 }", name="other")
        run = ImportRun.objects.create(origin=ImportRun.Origin.CLI, source="/rules")
        ImportFile.objects.create(
            run=run, path="test", status=ImportFile.Status.CREATED, ruleset=self.ruleset
        )
        purge_ruleset(self.ruleset)
        self.assertFalse(Ruleset.all_objects.filter(pk=self.ruleset.pk).exists())
        self.assertEqual(list(Rule.objects.values_list("name", flat=True)), ["elsewhere"])
        self.assertFalse(RuleVersion.objects.exclude(rule__ruleset=other).exists())
        self.assertEqual(sorted(Tag.objects.values_list("name", flat=True)), ["shared"])
        file = ImportFile.objects.get()
        self.assertEqual((file.run, file.ruleset, file.path), (run, None, "test"))


class ConcurrentEditTests(EditingTestCase):
    """Review finding 2: concurrent saves are conflicts, never IntegrityError."""

    def test_two_saves_from_the_same_version(self) -> None:
        first = Rule.objects.get(pk=self.uses_base.pk)
        second = Rule.objects.get(pk=self.uses_base.pk)
        self.assertTrue(update_rule(first, "rule uses_base { condition: base and true }").ok)
        result = update_rule(second, "rule uses_base { condition: base or true }")
        self.assertFalse(result.ok)
        self.assertTrue(result.conflict)
        self.assertIn("now version 2", result.error)
        rule = Rule.objects.get(pk=self.uses_base.pk)
        self.assertEqual((rule.version, rule.versions.count()), (2, 2))
        self.assertIn("base and true", rule.source)

    def test_expected_version(self) -> None:
        update_rule(self.uses_base, "rule uses_base { condition: base and true }")
        rule = Rule.objects.get(pk=self.uses_base.pk)  # fresh, version 2
        stale = update_rule(rule, "rule uses_base { condition: base }", expected_version=1)
        self.assertTrue(stale.conflict)
        ok = update_rule(rule, "rule uses_base { condition: base }", expected_version=2)
        self.assertTrue(ok.ok, ok.error)
        self.assertEqual(saved_rule(ok).version, 3)

    def test_restore_with_expected_version(self) -> None:
        update_rule(self.uses_base, "rule uses_base { condition: base and true }")
        version_1 = RuleVersion.objects.get(rule=self.uses_base, number=1)
        self.assertTrue(restore_version(version_1, expected_version=1).conflict)
        self.assertTrue(restore_version(version_1, expected_version=2).ok)

    def test_edit_racing_an_import_is_a_conflict(self) -> None:
        stale = Rule.objects.get(pk=self.uses_base.pk)
        # An import bumps the version meanwhile.
        Rule.objects.filter(pk=stale.pk).update(version=2)
        result = update_rule(stale, "rule uses_base { condition: base or true }")
        self.assertTrue(result.conflict)

    def test_deleted_meanwhile(self) -> None:
        stale = Rule.objects.get(pk=self.uses_base.pk)
        Rule.objects.filter(pk=stale.pk).delete()
        result = update_rule(stale, "rule uses_base { condition: true }")
        self.assertTrue(result.conflict)
        self.assertIn("deleted", result.error)

    def test_rename_into_a_name_taken_meanwhile(self) -> None:
        from unittest import mock

        from rules.services import compiler

        real_plan = compiler.plan_edit
        done: list[bool] = []

        def plan_then_concurrent_create(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
            plan = real_plan(*args, **kwargs)
            if not done:
                done.append(True)
                create_rule(self.ruleset, "rule fresh { condition: true }")
            return plan

        with mock.patch("rules.services.editing.plan_edit", plan_then_concurrent_create):
            result = update_rule(self.uses_base, "rule fresh { condition: base }")
        self.assertTrue(result.conflict)
        self.assertIn("already exists", result.error)
        self.assertEqual(Rule.objects.filter(name="fresh").count(), 1)

    def test_two_creates_of_the_same_name(self) -> None:
        from unittest import mock

        from rules.services import compiler

        real_plan = compiler.plan_edit
        calls: list[EditResult] = []

        def plan_then_concurrent_create(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
            plan = real_plan(*args, **kwargs)
            if not calls:
                calls.append(EditResult())  # placeholder: the nested create must not recurse
                calls[0] = create_rule(self.ruleset, "rule twin { condition: true }")
            return plan

        with mock.patch("rules.services.editing.plan_edit", plan_then_concurrent_create):
            result = create_rule(self.ruleset, "rule twin { condition: filesize > 1 }")
        self.assertTrue(calls[0].ok)
        self.assertFalse(result.ok)
        self.assertTrue(result.conflict)
        self.assertEqual(Rule.objects.filter(name="twin").count(), 1)

    def test_integrity_error_becomes_a_result(self) -> None:
        from unittest import mock

        from django.db import IntegrityError

        with mock.patch.object(Rule, "record_version", side_effect=IntegrityError("unique")):
            result = update_rule(self.uses_base, "rule uses_base { condition: base or true }")
        self.assertTrue(result.conflict)
        rule = Rule.objects.get(pk=self.uses_base.pk)
        self.assertEqual(rule.version, 1)

    def test_sibling_change_between_validation_and_save_recompiles(self) -> None:
        from unittest import mock

        from rules.services import compiler

        real_plan = compiler.plan_edit
        done: list[bool] = []

        def plan_then_break_base(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
            plan = real_plan(*args, **kwargs)
            if not done:
                done.append(True)
                # Another editor renames base meanwhile, which breaks uses_base.
                update_rule(Rule.objects.get(name="base"), "private rule other { condition: true }")
            return plan

        newcomer = "rule newcomer { condition: base }"
        with mock.patch("rules.services.editing.plan_edit", plan_then_break_base):
            result = create_rule(self.ruleset, newcomer)
        self.assertTrue(result.ok)
        # The stored diagnostics describe the rules as saved, not as validated.
        self.assertIn("unknown identifier", Rule.objects.get(name="newcomer").compile_error)


class UnsavedRulesetTests(TestCase):
    """UI gap: validating and creating a rule for a collection that does not exist yet."""

    def test_validate_without_a_saved_ruleset(self) -> None:
        ruleset = manual_ruleset("fresh collection", save=False)
        self.assertIsNone(ruleset.pk)
        result = validate_rule_text(ruleset, "rule a { condition: filesize > 0 }")
        self.assertTrue(result.ok, result.error)
        self.assertFalse(validate_rule_text(ruleset, "rule a { condition: nope }").ok)
        self.assertFalse(Ruleset.objects.exists())

    def test_create_saves_the_ruleset_with_the_rule(self) -> None:
        ruleset = manual_ruleset("fresh collection", save=False)
        refused = create_rule(ruleset, "rule a { condition: nope }")
        self.assertFalse(refused.ok)
        self.assertFalse(Ruleset.objects.exists())
        rule = saved_rule(create_rule(ruleset, "rule a { condition: filesize > 0 }"))
        self.assertEqual(
            (rule.ruleset.origin, rule.ruleset.path, rule.ruleset.name),
            (Ruleset.Origin.MANUAL, "fresh collection", "fresh collection"),
        )
        self.assertEqual(manual_ruleset("fresh collection", save=False), rule.ruleset)


class RecoverableDeleteTests(EditingTestCase):
    """PLAN.md 12.11: deleting is recoverable, purging is separate."""

    def test_delete_and_restore_rule(self) -> None:
        delete_rule(self.base, user=self.user)
        self.assertFalse(Rule.objects.filter(pk=self.base.pk).exists())
        deleted = Rule.all_objects.get(pk=self.base.pk)
        self.assertEqual((deleted.is_deleted, deleted.deleted_by), (True, self.user))
        self.assertEqual(deleted.versions.count(), 1)
        self.assertTrue(Tag.objects.filter(name="shared").exists())
        # The dependent rule now fails; the deleted rule is not compiled.
        self.assertIn("unknown identifier", Rule.objects.get(name="uses_base").compile_error)
        self.assertEqual(list(Rule.all_objects.deleted()), [deleted])
        self.assertNotIn(deleted, Rule.objects.active())
        self.assertNotIn(deleted, Rule.all_objects.active())
        self.assertNotIn(deleted, Rule.all_objects.removed())

        result = restore_rule(deleted, user=self.user)
        self.assertTrue(result.ok, result.error)
        rule = saved_rule(result)
        self.assertEqual((rule.is_deleted, rule.deleted_by, rule.version), (False, None, 1))
        self.assertEqual(Rule.objects.get(name="uses_base").compile_error, "")

    def test_deleted_rule_holds_its_name(self) -> None:
        delete_rule(self.uses_base)
        result = create_rule(self.ruleset, "rule uses_base { condition: true }")
        self.assertFalse(result.ok)
        self.assertIn("deleted rule", result.error)
        self.assertIn("Restore it, or purge it", result.error)
        rename = update_rule(self.base, "private rule uses_base { condition: true }")
        self.assertIn("deleted rule", rename.error)
        purge_rule(Rule.all_objects.get(name="uses_base"))
        self.assertTrue(create_rule(self.ruleset, "rule uses_base { condition: true }").ok)

    def test_editing_a_deleted_rule_is_refused(self) -> None:
        stale = Rule.objects.get(pk=self.uses_base.pk)
        delete_rule(self.uses_base)
        result = update_rule(stale, "rule uses_base { condition: base and true }")
        self.assertTrue(result.conflict)

    def test_delete_and_restore_ruleset_with_rules(self) -> None:
        delete_rule(self.uses_base)  # deleted on its own first
        delete_ruleset(self.ruleset, user=self.user)
        self.assertFalse(Ruleset.objects.filter(pk=self.ruleset.pk).exists())
        ruleset = Ruleset.all_objects.get(pk=self.ruleset.pk)
        self.assertEqual((ruleset.is_deleted, ruleset.deleted_by), (True, self.user))
        self.assertFalse(Rule.objects.exists())
        self.assertEqual(Rule.all_objects.deleted().count(), 2)
        self.assertTrue(create_rule(ruleset, "rule fresh { condition: true }").conflict)
        self.assertFalse(restore_rule(Rule.all_objects.get(name="base")).ok)

        restore_ruleset(ruleset, user=self.user)
        self.assertTrue(Ruleset.objects.filter(pk=self.ruleset.pk).exists())
        # Only the rule deleted together with the ruleset comes back.
        self.assertEqual(list(Rule.objects.values_list("name", flat=True)), ["base"])
        self.assertEqual(Rule.all_objects.get(name="uses_base").is_deleted, True)
        self.assertEqual(Ruleset.objects.get().sha256, "")  # next import re-reads the file

    def test_manual_ruleset_returns_a_deleted_one_as_is(self) -> None:
        manual = manual_ruleset("mine")
        delete_ruleset(manual)
        again = manual_ruleset("mine", save=False)
        self.assertEqual((again.pk, again.is_deleted), (manual.pk, True))
        self.assertFalse(create_rule(again, "rule x { condition: true }").ok)

    def test_purge_permission_is_given_to_no_role(self) -> None:
        from django.contrib.auth.models import Group

        from accounts.roles import EDITORS, VIEWERS

        for name in (VIEWERS, EDITORS):
            codenames = set(
                Group.objects.get(name=name).permissions.values_list("codename", flat=True)
            )
            self.assertFalse(codenames & {"purge_rule", "purge_ruleset"}, name)
        editor = User.objects.create_user("e")
        editor.groups.add(Group.objects.get(name=EDITORS))
        self.assertFalse(editor.has_perm("rules.purge_rule"))
        admin = User.objects.create_superuser("root", email="", password="pw")
        self.assertTrue(admin.has_perms(["rules.purge_rule", "rules.purge_ruleset"]))

    def test_deleted_rules_stay_out_of_compiles_and_exports(self) -> None:
        from rules.services.compiler import build_source
        from rules.services.exporter import export_combined, export_zip

        delete_rule(self.uses_base)
        self.assertNotIn("uses_base", build_source(self.ruleset))
        everything = Rule.all_objects.select_related("ruleset")
        self.assertNotIn(b"uses_base", export_combined(everything).content)
        self.assertNotIn(b"rule uses_base", export_zip(everything).content)
