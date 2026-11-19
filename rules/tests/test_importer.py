import tempfile
from pathlib import Path

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings

from accounts.models import User
from rules.models import ImportFile, ImportRun, Rule, Ruleset, RuleVersion, Tag
from rules.services import editing
from rules.services.importer import MAX_FILE_BYTES, decode, import_directory, import_uploads

V1 = """import "pe"

// Rule one.
rule one : alpha {
    meta:
        description = "first"
        author = "Ann"
    condition:
        pe.is_pe
}

rule two : beta { condition: filesize > 10 }

rule three { condition: filesize > 20 }
"""


class DirectoryImportTestCase(TestCase):
    def setUp(self) -> None:
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(override_settings(YARADUDE_RULES_DIR=self.root))

    def write(self, name: str, content: str | bytes) -> Path:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content)
        return path

    def run_import(self, user: User | None = None) -> ImportRun:
        return import_directory(self.root, user=user)

    def counters(self, run: ImportRun) -> dict[str, int]:
        return {
            name: getattr(run, name)
            for name in (
                "files_seen",
                "files_changed",
                "files_unchanged",
                "files_failed",
                "rules_created",
                "rules_updated",
                "rules_removed",
                "rules_unchanged",
            )
        }

    def rule(self, name: str) -> Rule:
        return Rule.objects.get(name=name)


class CreateAndUnchangedTests(DirectoryImportTestCase):
    def test_create(self) -> None:
        self.write("sub/set.yar", V1)
        user = User.objects.create_user("importer")
        run = self.run_import(user=user)

        self.assertEqual(run.origin, ImportRun.Origin.SCAN)
        self.assertEqual(run.user, user)
        self.assertIsNotNone(run.finished_at)
        self.assertEqual(
            self.counters(run),
            {
                "files_seen": 1,
                "files_changed": 1,
                "files_unchanged": 0,
                "files_failed": 0,
                "rules_created": 3,
                "rules_updated": 0,
                "rules_removed": 0,
                "rules_unchanged": 0,
            },
        )
        ruleset = Ruleset.objects.get()
        self.assertEqual(
            (ruleset.origin, ruleset.path, ruleset.name),
            (Ruleset.Origin.DIRECTORY, "sub/set.yar", "sub/set.yar"),
        )
        self.assertEqual(ruleset.original_content, V1)
        self.assertEqual(ruleset.compile_error, "")
        self.assertIsNotNone(ruleset.last_imported_at)

        one = self.rule("one")
        self.assertEqual(one.source.splitlines()[0], "// Rule one.")
        self.assertEqual(one.imports, ["pe"])
        self.assertEqual(one.meta, [["description", "first"], ["author", "Ann"]])
        self.assertEqual((one.description, one.author), ("first", "Ann"))
        self.assertEqual(one.imported_sha256, one.sha256)
        self.assertEqual(one.version, 1)
        self.assertEqual(list(one.tags.values_list("name", flat=True)), ["alpha"])
        self.assertEqual([r.name for r in ruleset.rules.all()], ["one", "two", "three"])
        self.assertEqual(self.rule("two").imports, [])

        version = one.versions.get()
        self.assertEqual(
            (version.number, version.origin, version.import_run, version.sha256),
            (1, RuleVersion.Origin.IMPORT, run, one.sha256),
        )
        file = run.files.get()
        self.assertEqual(
            (file.path, file.status, file.ruleset, file.rules_created),
            ("sub/set.yar", ImportFile.Status.CREATED, ruleset, 3),
        )

    def test_identical_reimport_is_a_noop(self) -> None:
        self.write("set.yar", V1)
        self.run_import()
        ruleset = Ruleset.objects.get()
        first_import = ruleset.last_imported_at
        updated_at = ruleset.updated_at
        versions = RuleVersion.objects.count()

        run = self.run_import()
        self.assertEqual(
            self.counters(run),
            {
                "files_seen": 1,
                "files_changed": 0,
                "files_unchanged": 1,
                "files_failed": 0,
                "rules_created": 0,
                "rules_updated": 0,
                "rules_removed": 0,
                "rules_unchanged": 3,
            },
        )
        self.assertFalse(run.files.exists())
        ruleset.refresh_from_db()
        assert ruleset.last_imported_at is not None and first_import is not None
        self.assertGreater(ruleset.last_imported_at, first_import)
        self.assertEqual(ruleset.updated_at, updated_at)
        self.assertEqual(RuleVersion.objects.count(), versions)
        self.assertEqual(ImportRun.objects.count(), 2)

    def test_hidden_and_non_rule_files_are_skipped(self) -> None:
        self.write("a.yara", "rule a { condition: filesize > 0 }")
        self.write("A2.YAR", "rule a2 { condition: filesize > 0 }")
        self.write(".hidden.yar", "rule hidden { condition: filesize > 0 }")
        self.write(".git/x.yar", "rule in_hidden_dir { condition: filesize > 0 }")
        self.write("notes.txt", "rule txt { condition: filesize > 0 }")
        run = self.run_import()
        self.assertEqual(run.files_seen, 2)
        self.assertEqual(sorted(Rule.objects.values_list("name", flat=True)), ["a", "a2"])

    def test_oversized_file_fails(self) -> None:
        self.write("big.yar", "// " + "x" * MAX_FILE_BYTES)
        run = self.run_import()
        self.assertEqual((run.files_seen, run.files_failed), (1, 1))
        self.assertIn("larger than", run.files.get().message)
        self.assertFalse(Ruleset.objects.exists())

    def test_files_outside_rules_dir_use_absolute_path(self) -> None:
        other = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (other / "x.yar").write_text("rule x { condition: filesize > 0 }")
        run = import_directory(other, origin=ImportRun.Origin.CLI)
        self.assertEqual(run.origin, ImportRun.Origin.CLI)
        self.assertEqual(Ruleset.objects.get().path, str((other / "x.yar").resolve()))

    def test_absent_file_changes_nothing(self) -> None:
        path = self.write("set.yar", V1)
        self.run_import()
        path.unlink()
        run = self.run_import()
        self.assertEqual(run.files_seen, 0)
        self.assertEqual(Rule.objects.active().count(), 3)

    def test_non_compiling_rules_are_stored_and_flagged(self) -> None:
        self.write(
            "set.yar",
            'import "magic"\n'
            "rule ok { condition: filesize > 0 }\n"
            'rule m { condition: magic.type() == "x" }',
        )
        run = self.run_import()
        self.assertEqual((run.files_changed, run.files_failed), (1, 0))
        self.assertTrue(self.rule("m").compile_error)
        self.assertEqual(self.rule("ok").compile_error, "")
        self.assertEqual(Ruleset.objects.get().compile_error, "1 of 2 rules do not compile: m")

    def test_includes_are_reported_and_ignored(self) -> None:
        self.write("set.yar", 'include "/etc/passwd"\nrule a { condition: filesize > 0 }')
        run = self.run_import()
        file = run.files.get()
        self.assertEqual(file.status, ImportFile.Status.CREATED)
        self.assertIn("include statements are not supported", file.message)
        self.assertIn("/etc/passwd", file.message)
        self.assertEqual(self.rule("a").compile_error, "")


class UpdateTests(DirectoryImportTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.path = self.write("set.yar", V1)
        self.first_run = self.run_import()

    def test_update_with_version_bump(self) -> None:
        self.path.write_text(
            V1.replace("filesize > 10", "filesize > 11").replace(": beta", ": beta gamma")
        )
        run = self.run_import()
        self.assertEqual(
            self.counters(run),
            {
                "files_seen": 1,
                "files_changed": 1,
                "files_unchanged": 0,
                "files_failed": 0,
                "rules_created": 0,
                "rules_updated": 1,
                "rules_removed": 0,
                "rules_unchanged": 2,
            },
        )
        two = self.rule("two")
        self.assertEqual(two.version, 2)
        self.assertIn("filesize > 11", two.source)
        self.assertEqual(two.imported_sha256, two.sha256)
        self.assertEqual(sorted(two.tags.values_list("name", flat=True)), ["beta", "gamma"])
        self.assertEqual(
            list(two.versions.values_list("number", "origin", "import_run")),
            [(2, "import", run.pk), (1, "import", self.first_run.pk)],
        )
        self.assertEqual(self.rule("one").version, 1)
        file = run.files.get()
        self.assertEqual(
            (file.status, file.rules_updated, file.rules_unchanged),
            (ImportFile.Status.UPDATED, 1, 2),
        )

    def test_removed_and_restored(self) -> None:
        self.path.write_text(V1.replace("rule three { condition: filesize > 20 }\n", ""))
        run = self.run_import()
        self.assertEqual((run.rules_removed, run.rules_unchanged), (1, 2))
        three = self.rule("three")
        self.assertIsNotNone(three.removed_at)
        self.assertEqual(three.versions.count(), 1)
        self.assertEqual(Rule.objects.active().count(), 2)

        self.path.write_text(V1)
        run = self.run_import()
        self.assertEqual((run.rules_updated, run.rules_removed, run.rules_unchanged), (1, 0, 2))
        three.refresh_from_db()
        self.assertIsNone(three.removed_at)
        self.assertEqual(three.version, 1)

    def test_restored_with_new_content(self) -> None:
        self.path.write_text(V1.replace("rule three { condition: filesize > 20 }\n", ""))
        self.run_import()
        self.path.write_text(V1.replace("filesize > 20", "filesize > 21"))
        self.run_import()
        three = self.rule("three")
        self.assertIsNone(three.removed_at)
        self.assertEqual(three.version, 2)

    def test_reordering_updates_positions_only(self) -> None:
        self.path.write_text(
            'import "pe"\nrule three { condition: filesize > 20 }\n\n'
            "// Rule one.\n"
            + V1.split("// Rule one.\n")[1].replace(
                "\nrule three { condition: filesize > 20 }\n", ""
            )
        )
        run = self.run_import()
        self.assertEqual((run.rules_updated, run.rules_unchanged), (0, 3))
        self.assertEqual(
            list(Rule.objects.order_by("position").values_list("name", flat=True)),
            ["three", "one", "two"],
        )

    def test_local_edit_preserved_while_disk_unchanged(self) -> None:
        two = self.rule("two")
        result = editing.update_rule(two, "rule two : beta { condition: filesize > 99 }")
        self.assertTrue(result.ok, result.error)
        two.refresh_from_db()
        self.assertTrue(two.is_modified)

        # Another rule in the file changes, so the file is processed again.
        self.path.write_text(V1.replace("filesize > 20", "filesize > 21"))
        run = self.run_import()
        self.assertEqual((run.rules_updated, run.rules_unchanged), (1, 2))
        two.refresh_from_db()
        self.assertIn("filesize > 99", two.source)
        self.assertTrue(two.is_modified)
        self.assertEqual(two.version, 2)

    def test_disk_change_overrides_local_edit(self) -> None:
        two = self.rule("two")
        editing.update_rule(two, "rule two : beta { condition: filesize > 99 }")
        self.path.write_text(V1.replace("filesize > 10", "filesize > 12"))
        run = self.run_import()
        self.assertEqual(run.rules_updated, 1)
        two.refresh_from_db()
        self.assertIn("filesize > 12", two.source)
        self.assertFalse(two.is_modified)
        self.assertEqual(two.version, 3)
        # The local edit stays in the history.
        self.assertEqual(
            list(two.versions.values_list("number", "origin")),
            [(3, "import"), (2, "edit"), (1, "import")],
        )
        self.assertIn("filesize > 99", two.versions.get(number=2).source)

    def test_disk_catching_up_with_local_edit_adds_no_version(self) -> None:
        two = self.rule("two")
        editing.update_rule(two, "rule two : beta { condition: filesize > 99 }")
        self.path.write_text(V1.replace("filesize > 10", "filesize > 99"))
        run = self.run_import()
        self.assertEqual((run.rules_updated, run.rules_unchanged), (0, 3))
        two.refresh_from_db()
        self.assertFalse(two.is_modified)
        self.assertEqual(two.version, 2)

    def test_locally_created_rule_is_not_removed_by_import(self) -> None:
        ruleset = Ruleset.objects.get()
        editing.create_rule(ruleset, "rule local { condition: filesize > 1 }")
        self.path.write_text(V1.replace("filesize > 20", "filesize > 21"))
        run = self.run_import()
        self.assertEqual(run.rules_removed, 0)
        local = self.rule("local")
        self.assertIsNone(local.removed_at)
        self.assertEqual(local.position, 3)

    def test_parse_failure_leaves_data_untouched(self) -> None:
        before = list(Rule.objects.values_list("name", "sha256", "version", "removed_at"))
        ruleset = Ruleset.objects.get()
        self.path.write_text("rule broken {\n condition: true\n")
        run = self.run_import()
        self.assertEqual(
            (run.files_seen, run.files_changed, run.files_failed, run.rules_removed), (1, 0, 1, 0)
        )
        file = run.files.get()
        self.assertEqual(file.status, ImportFile.Status.FAILED)
        self.assertIsNone(file.ruleset)
        self.assertEqual(file.message, 'Parse error: line 1: unterminated rule "broken"')
        self.assertEqual(
            list(Rule.objects.values_list("name", "sha256", "version", "removed_at")), before
        )
        ruleset_after = Ruleset.objects.get()
        self.assertEqual(ruleset_after.sha256, ruleset.sha256)
        self.assertEqual(ruleset_after.last_imported_at, ruleset.last_imported_at)

    def test_splitter_disagreeing_with_yara_x_fails_the_file(self) -> None:
        # YARA-X sees one rule (the "rule b" is inside a text string that the
        # splitter would only misread if it were wrong); simulate a splitter
        # bug by patching the parser output.
        from unittest import mock

        from rules.services import importer
        from rules.services.parser import ParsedFile
        from rules.services.parser import parse as real_parse

        def bad_parse(text: str) -> ParsedFile:
            parsed = real_parse(text)
            return type(parsed)(parsed.imports, parsed.includes, parsed.rules[:1])

        self.path.write_text(V1.replace("filesize > 20", "filesize > 21"))
        with mock.patch.object(importer, "parse", bad_parse):
            run = self.run_import()
        self.assertEqual(run.files_failed, 1)
        self.assertIn("do not match what YARA-X compiles", run.files.get().message)
        self.assertEqual(Rule.objects.get(name="three").version, 1)


class EncodingTests(DirectoryImportTestCase):
    def test_latin1_input(self) -> None:
        content = 'rule latin { meta: author = "J\xfcrgen" condition: filesize > 0 }\n'.encode(
            "latin-1"
        )
        with self.assertRaises(UnicodeDecodeError):
            content.decode("utf-8")
        self.write("latin.yar", content)
        run = self.run_import()
        self.assertEqual(run.files_changed, 1)
        rule = self.rule("latin")
        self.assertEqual(rule.author, "Jürgen")
        self.assertEqual(rule.compile_error, "")

    def test_decode(self) -> None:
        self.assertEqual(decode("ä".encode()), "ä")
        self.assertEqual(decode(b"\xef\xbb\xbfrule"), "rule")
        self.assertEqual(decode(b"\xe4"), "ä")


class UploadImportTests(TestCase):
    def upload(self, name: str, content: str) -> SimpleUploadedFile:
        return SimpleUploadedFile(name, content.encode(), content_type="text/plain")

    def test_uploads(self) -> None:
        user = User.objects.create_user("uploader")
        run = import_uploads(
            [
                self.upload("../../evil/first.yar", "rule first : t { condition: filesize > 0 }"),
                self.upload("second.YARA", "rule second { condition: filesize > 0 }"),
                self.upload("notes.txt", "rule txt { condition: filesize > 0 }"),
                self.upload("broken.yar", "rule broken {"),
            ],
            user=user,
        )
        self.assertEqual(run.origin, ImportRun.Origin.UPLOAD)
        self.assertEqual(run.source, "first.yar, second.YARA, notes.txt, broken.yar")
        self.assertEqual(
            (run.files_seen, run.files_changed, run.files_failed, run.rules_created), (4, 2, 2, 2)
        )
        self.assertEqual(
            sorted(Ruleset.objects.values_list("origin", "path")),
            [("upload", "first.yar"), ("upload", "second.YARA")],
        )
        self.assertEqual(
            Rule.objects.get(name="first").versions.get().origin, RuleVersion.Origin.UPLOAD
        )
        failures = dict(run.files.filter(status="failed").values_list("path", "message"))
        self.assertEqual(failures["notes.txt"], "Only .yar and .yara files can be imported.")
        self.assertTrue(failures["broken.yar"].startswith("Parse error:"))

    def test_reupload_updates_the_same_ruleset(self) -> None:
        import_uploads([self.upload("set.yar", "rule a { condition: filesize > 0 }")])
        run = import_uploads([self.upload("set.yar", "rule a { condition: filesize > 1 }")])
        self.assertEqual((run.files_changed, run.rules_updated), (1, 1))
        self.assertEqual(Ruleset.objects.count(), 1)
        self.assertEqual(Rule.objects.get().version, 2)

    def test_unused_tags_are_deleted(self) -> None:
        import_uploads([self.upload("set.yar", "rule a : old { condition: filesize > 0 }")])
        import_uploads([self.upload("set.yar", "rule a : new { condition: filesize > 0 }")])
        self.assertEqual(list(Tag.objects.values_list("name", flat=True)), ["new"])
