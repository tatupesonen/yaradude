from django.test import TestCase

from accounts.models import User
from rules.models import ImportFile, ImportRun, Rule, Ruleset, RuleVersion, Tag
from rules.services.compiler import check_ruleset
from rules.services.editing import (
    create_rule,
    delete_rule,
    delete_ruleset,
    manual_ruleset,
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

    def test_delete(self) -> None:
        update_rule(self.base, "private rule renamed : shared { condition: true }")
        self.assertTrue(Rule.objects.get(name="uses_base").compile_error)
        delete_rule(Rule.objects.get(name="uses_base"))
        self.assertFalse(Rule.objects.filter(name="uses_base").exists())
        self.assertFalse(RuleVersion.objects.filter(rule__name="uses_base").exists())
        self.assertFalse(Tag.objects.filter(name="old").exists())
        self.assertTrue(Tag.objects.filter(name="shared").exists())
        self.ruleset.refresh_from_db()
        self.assertEqual(self.ruleset.compile_error, "")

    def test_delete_ruleset_keeps_import_history(self) -> None:
        other = make_ruleset("rule elsewhere : shared { condition: filesize > 0 }", name="other")
        run = ImportRun.objects.create(origin=ImportRun.Origin.CLI, source="/rules")
        ImportFile.objects.create(
            run=run, path="test", status=ImportFile.Status.CREATED, ruleset=self.ruleset
        )
        delete_ruleset(self.ruleset)
        self.assertFalse(Ruleset.objects.filter(pk=self.ruleset.pk).exists())
        self.assertEqual(list(Rule.objects.values_list("name", flat=True)), ["elsewhere"])
        self.assertFalse(RuleVersion.objects.exclude(rule__ruleset=other).exists())
        self.assertEqual(sorted(Tag.objects.values_list("name", flat=True)), ["shared"])
        file = ImportFile.objects.get()
        self.assertEqual((file.run, file.ruleset, file.path), (run, None, "test"))
