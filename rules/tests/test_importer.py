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


class RenameThenReimportTests(DirectoryImportTestCase):
    """Review finding 3: a locally renamed rule must survive an import of its file."""

    def setUp(self) -> None:
        super().setUp()
        self.path = self.write("set.yar", V1)
        self.run_import()
        two = self.rule("two")
        result = editing.update_rule(two, "rule two_renamed : beta { condition: filesize > 10 }")
        self.assertTrue(result.ok, result.error)
        self.renamed = Rule.objects.get(name="two_renamed")

    def test_rename_survives_an_import_that_changes_other_rules(self) -> None:
        self.path.write_text(V1.replace("filesize > 20", "filesize > 21"))
        run = self.run_import()
        self.assertEqual(
            (run.files_failed, run.rules_created, run.rules_updated, run.rules_removed),
            (0, 0, 1, 0),
        )
        self.assertFalse(Rule.objects.filter(name="two").exists())
        renamed = Rule.objects.get(pk=self.renamed.pk)
        self.assertEqual(
            (renamed.name, renamed.removed_at, renamed.version), ("two_renamed", None, 2)
        )
        self.assertEqual(renamed.position, 1)
        self.assertTrue(renamed.is_modified)
        self.assertEqual(renamed.imported_name, "two")

    def test_disk_change_of_a_renamed_rule_wins_and_keeps_the_history(self) -> None:
        self.path.write_text(V1.replace("filesize > 10", "filesize > 12"))
        run = self.run_import()
        self.assertEqual((run.rules_created, run.rules_updated, run.rules_removed), (0, 1, 0))
        rule = Rule.objects.get(pk=self.renamed.pk)
        self.assertEqual((rule.name, rule.version, rule.is_modified), ("two", 3, False))
        self.assertIn("rule two_renamed", rule.versions.get(number=2).source)

    def test_rename_onto_a_name_the_file_brings_back_fails_the_file(self) -> None:
        # The file gains a rule with the name the local rename took.
        self.path.write_text(V1 + "\nrule two_renamed { condition: filesize > 30 }\n")
        run = self.run_import()
        self.assertEqual(run.files_failed, 1)
        self.assertIn('the name "two_renamed"', run.files.get().message)
        self.assertEqual(Rule.objects.get(pk=self.renamed.pk).name, "two_renamed")

    def test_legacy_rename_without_imported_name_matches_by_hash(self) -> None:
        # Rules renamed before imported_name was recorded.
        Rule.objects.update(imported_name="")
        self.path.write_text(V1.replace("filesize > 20", "filesize > 21"))
        run = self.run_import()
        self.assertEqual((run.rules_created, run.rules_removed), (0, 0))
        self.assertEqual(Rule.objects.get(pk=self.renamed.pk).name, "two_renamed")


class RobustRunTests(DirectoryImportTestCase):
    """Review finding 4: one bad file must not abort the run."""

    def test_unexpected_error_is_recorded_and_the_run_finishes(self) -> None:
        from unittest import mock

        from rules.services import importer

        self.write("a.yar", 'rule a { meta: secret = "TOP-SECRET" condition: filesize > 0 }')
        self.write("b.yar", "rule b { condition: filesize > 0 }")
        real_write = importer._write

        def failing_write(run, origin, path, prepared):  # noqa: ANN001, ANN202
            if path == "a.yar":
                raise RuntimeError(f"boom while writing {prepared.text}")
            return real_write(run, origin, path, prepared)

        with (
            mock.patch.object(importer, "_write", failing_write),
            self.assertLogs("rules.services.importer", "ERROR") as logs,
        ):
            run = self.run_import()
        self.assertIsNotNone(run.finished_at)
        run.refresh_from_db()
        self.assertEqual(
            (run.files_seen, run.files_changed, run.files_failed, run.rules_created), (2, 1, 1, 1)
        )
        failed = run.files.get(status=ImportFile.Status.FAILED)
        self.assertEqual(failed.path, "a.yar")
        self.assertIn("RuntimeError", failed.message)
        self.assertNotIn("TOP-SECRET", failed.message)
        self.assertIn("Traceback", "\n".join(logs.output))
        self.assertEqual(list(Rule.objects.values_list("name", flat=True)), ["b"])

    def test_unreadable_file(self) -> None:
        import os

        if os.geteuid() == 0:
            self.skipTest("root can read any file")
        path = self.write("locked.yar", "rule locked { condition: true }")
        self.write("open.yar", "rule open_rule { condition: filesize > 0 }")
        path.chmod(0)
        try:
            run = self.run_import()
        finally:
            path.chmod(0o644)
        self.assertEqual((run.files_seen, run.files_failed, run.files_changed), (2, 1, 1))
        self.assertIn("could not be read", run.files.get(status="failed").message)

    def test_counters_are_saved_after_each_file(self) -> None:
        from unittest import mock

        from rules.services import importer

        self.write("a.yar", "rule a { condition: filesize > 0 }")
        self.write("b.yar", "rule b { condition: filesize > 0 }")
        seen: list[int] = []
        real = importer._import_content

        def spy(run, origin, path, content):  # noqa: ANN001, ANN202
            stored = ImportRun.objects.get(pk=run.pk)
            seen.append(stored.files_seen)
            return real(run, origin, path, content)

        with mock.patch.object(importer, "_import_content", spy):
            self.run_import()
        self.assertEqual(seen, [0, 1])


class TransactionScopeTests(DirectoryImportTestCase):
    """Review finding 1: parse, safety-net compile and hashing run before the write lock."""

    def test_parse_and_compiles_run_outside_the_write_transaction(self) -> None:
        from unittest import mock

        from django.db import connection

        from rules.services import importer

        self.write("set.yar", V1)
        depth = len(connection.atomic_blocks)
        depths: dict[str, int] = {}

        def recording(name, function):  # noqa: ANN001, ANN202
            def wrapper(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
                depths[name] = len(connection.atomic_blocks)
                return function(*args, **kwargs)

            return wrapper

        with (
            mock.patch.object(importer, "decode", recording("decode", importer.decode)),
            mock.patch.object(importer, "parse", recording("parse", importer.parse)),
            mock.patch.object(
                importer,
                "compiled_identifiers",
                recording("compiled_identifiers", importer.compiled_identifiers),
            ),
            mock.patch.object(
                importer, "compile_entries", recording("compile_entries", importer.compile_entries)
            ),
        ):
            run = self.run_import()
        self.assertEqual(run.rules_created, 3)
        self.assertEqual(
            depths,
            {
                "decode": depth,
                "parse": depth,
                "compiled_identifiers": depth,
                "compile_entries": depth,
            },
        )
        self.assertEqual(Rule.objects.get(name="one").compile_error, "")

    @override_settings(YARADUDE_MAX_RULE_FILE_BYTES=100)
    def test_size_limit_is_a_setting(self) -> None:
        from rules.services.importer import rule_files

        self.write("small.yar", "rule small { condition: filesize > 0 }")
        self.write("big.yar", "// " + "x" * 120 + "\nrule big { condition: filesize > 0 }")
        self.assertEqual(
            [(f.identity, bool(f.error)) for f in rule_files(self.root)],
            [("big.yar", True), ("small.yar", False)],
        )
        run = self.run_import()
        self.assertEqual((run.files_seen, run.files_failed, run.rules_created), (2, 1, 1))
        self.assertEqual(run.files.get(status="failed").message, "File is larger than 100 bytes.")

    def test_file_growing_past_the_limit_after_listing_fails(self) -> None:
        from rules.services.importer import read_rule_file, rule_files

        path = self.write("grow.yar", "rule grow { condition: filesize > 0 }")
        [file] = rule_files(self.root)
        with (
            override_settings(YARADUDE_MAX_RULE_FILE_BYTES=20),
            self.assertRaisesMessage(Exception, "larger than 20 bytes"),
        ):
            read_rule_file(file, self.root)
        self.assertEqual(read_rule_file(file, self.root), path.read_bytes())


class LineEndingTests(DirectoryImportTestCase):
    """Review finding 5: CRLF files, the editor and hashes agree."""

    CRLF = V1.replace("\n", "\r\n")

    def test_crlf_file_saved_unchanged_from_the_editor_is_not_a_change(self) -> None:
        self.write("set.yar", self.CRLF.encode())
        self.run_import()
        ruleset = Ruleset.objects.get()
        self.assertEqual(ruleset.original_content, self.CRLF)  # verbatim
        two = self.rule("two")
        self.assertNotIn("\r", two.source)
        # A browser textarea submits CRLF.
        result = editing.update_rule(two, two.text.replace("\n", "\r\n"))
        self.assertTrue(result.ok, result.error)
        two.refresh_from_db()
        self.assertEqual((two.version, two.is_modified), (1, False))

    def test_crlf_and_lf_versions_of_a_file_give_the_same_rules(self) -> None:
        path = self.write("set.yar", self.CRLF.encode())
        self.run_import()
        hashes = dict(Rule.objects.values_list("name", "sha256"))
        path.write_bytes(V1.encode())
        run = self.run_import()
        self.assertEqual((run.files_changed, run.rules_updated, run.rules_unchanged), (1, 0, 3))
        self.assertEqual(dict(Rule.objects.values_list("name", "sha256")), hashes)

    def test_migration_converts_existing_crlf_rows_without_marking_them_modified(self) -> None:
        import importlib

        from django.apps import apps

        migration = importlib.import_module(
            "rules.migrations.0002_imported_name_and_lf_line_endings"
        )
        self.write("set.yar", V1)
        self.run_import()
        # Rows as the old importer stored a CRLF file: CRLF source and hashes.
        from rules.services.parser import content_sha256

        for rule in Rule.objects.all():
            source = rule.source.replace("\n", "\r\n")
            sha = content_sha256(rule.imports, source)
            Rule.objects.filter(pk=rule.pk).update(source=source, sha256=sha, imported_sha256=sha)
            rule.versions.update(source=source, sha256=sha)
        lf_hashes = {r.name: content_sha256(r.imports, r.source) for r in Rule.objects.all()}
        self.assertFalse(Rule.objects.modified().exists())

        migration.normalize_crlf(apps, None)

        self.assertFalse(Rule.objects.filter(source__contains="\r").exists())
        self.assertFalse(RuleVersion.objects.filter(source__contains="\r").exists())
        self.assertFalse(Rule.objects.modified().exists())
        for rule in Rule.objects.all():
            self.assertEqual(
                rule.sha256, content_sha256(rule.imports, rule.source.replace("\r\n", "\n"))
            )
            self.assertEqual(rule.versions.get().sha256, rule.sha256)
        self.assertEqual(len(lf_hashes), 3)


class SymlinkTests(DirectoryImportTestCase):
    """Review finding 7: symlinks are not followed outside the rules directory."""

    def setUp(self) -> None:
        super().setUp()
        self.outside = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (self.outside / "secret.yar").write_text("rule outside { condition: filesize > 0 }")
        (self.outside / "dir").mkdir()
        (self.outside / "dir" / "deep.yar").write_text("rule deep { condition: filesize > 0 }")

    def test_symlinks_leading_outside_are_skipped(self) -> None:
        from rules.services.importer import rule_files

        (self.root / "link.yar").symlink_to(self.outside / "secret.yar")
        (self.root / "linkdir").symlink_to(self.outside / "dir")
        self.write("real.yar", "rule real { condition: filesize > 0 }")
        self.write("sub/inner.yar", "rule inner { condition: filesize > 0 }")
        (self.root / "alias.yar").symlink_to(self.root / "sub" / "inner.yar")
        (self.root / "dangling.yar").symlink_to(self.root / "missing.yar")

        listed = {f.identity: f.error for f in rule_files(self.root)}
        self.assertEqual(
            sorted(listed), ["alias.yar", "dangling.yar", "link.yar", "real.yar", "sub/inner.yar"]
        )
        self.assertEqual(listed["alias.yar"], "")
        for name in ("link.yar", "dangling.yar"):
            self.assertIn("symbolic link that leads outside", listed[name])
            self.assertNotIn(str(self.outside), listed[name])
        run = self.run_import()
        self.assertEqual((run.files_seen, run.files_failed, run.files_changed), (5, 2, 3))
        self.assertEqual(
            sorted(run.files.filter(status="failed").values_list("path", flat=True)),
            ["dangling.yar", "link.yar"],
        )
        self.assertFalse(Rule.objects.filter(name__in=["outside", "deep"]).exists())

    def test_symlink_swapped_after_listing_is_refused(self) -> None:
        from rules.services.importer import ImportFailed, read_rule_file, rule_files

        self.write("sub/inner.yar", "rule inner { condition: filesize > 0 }")
        link = self.root / "alias.yar"
        link.symlink_to(self.root / "sub" / "inner.yar")
        file = rule_files(self.root)[0]
        link.unlink()
        link.symlink_to(self.outside / "secret.yar")
        with self.assertRaises(ImportFailed):
            read_rule_file(file, self.root)


class FloatMetaImportTests(DirectoryImportTestCase):
    """Review finding 8: a float meta value no longer fails the file."""

    def test_float_meta(self) -> None:
        self.write("f.yar", "rule f { meta: score = 7.5 condition: filesize > 0 }")
        run = self.run_import()
        self.assertEqual((run.files_changed, run.files_failed), (1, 0))
        rule = self.rule("f")
        self.assertEqual((rule.meta, rule.compile_error), ([["score", 7.5]], ""))


class DeletedIsStickyTests(DirectoryImportTestCase):
    """PLAN.md 12.11: imports do not bring back what was deleted in yaradude."""

    def setUp(self) -> None:
        super().setUp()
        self.path = self.write("set.yar", V1)
        self.run_import()

    def test_import_over_a_deleted_rule(self) -> None:
        editing.delete_rule(self.rule("two"))
        self.path.write_text(V1.replace("filesize > 10", "filesize > 11").replace("> 20", "> 21"))
        run = self.run_import()
        self.assertEqual((run.rules_updated, run.rules_skipped, run.rules_created), (1, 1, 0))
        self.assertIn("1 skipped (deleted)", run.summary)
        two = Rule.all_objects.get(name="two")
        self.assertEqual((two.is_deleted, two.version), (True, 1))
        self.assertIn("filesize > 10", two.source)
        self.assertEqual(run.files.get().rules_skipped, 1)

        # Restore: the stored content comes back; the next import (which
        # re-reads the file) updates it under the normal rules.
        self.assertTrue(editing.restore_rule(two).ok)
        run = self.run_import()
        self.assertEqual((run.files_changed, run.rules_updated), (1, 1))
        two = self.rule("two")
        self.assertIn("filesize > 11", two.source)
        self.assertEqual(two.version, 2)

    def test_deleted_rule_dropped_from_the_file_is_left_alone(self) -> None:
        editing.delete_rule(self.rule("three"))
        self.path.write_text(V1.replace("rule three { condition: filesize > 20 }\n", ""))
        run = self.run_import()
        self.assertEqual(run.rules_removed, 0)
        three = Rule.all_objects.get(name="three")
        self.assertEqual((three.is_deleted, three.removed_at), (True, None))

    def test_import_over_a_deleted_ruleset(self) -> None:
        editing.delete_ruleset(Ruleset.objects.get())
        run = self.run_import()  # unchanged file
        self.assertEqual((run.files_seen, run.files_skipped, run.files_changed), (1, 1, 0))
        self.assertFalse(run.files.exists())
        self.path.write_text(V1 + "\nrule four { condition: filesize > 40 }\n")
        run = self.run_import()
        self.assertEqual((run.files_skipped, run.rules_created), (1, 0))
        self.assertEqual(run.files.get().status, ImportFile.Status.SKIPPED)
        self.assertFalse(Rule.all_objects.filter(name="four").exists())
        self.assertEqual(Ruleset.all_objects.count(), 1)

        editing.restore_ruleset(Ruleset.all_objects.get())
        run = self.run_import()
        self.assertEqual((run.files_changed, run.rules_created), (1, 1))
        self.assertEqual(Rule.objects.count(), 4)

    def test_upload_over_a_deleted_ruleset(self) -> None:
        upload = SimpleUploadedFile("up.yar", b"rule up { condition: filesize > 0 }")
        import_uploads([upload])
        editing.delete_ruleset(Ruleset.objects.get(origin=Ruleset.Origin.UPLOAD))
        run = import_uploads([SimpleUploadedFile("up.yar", b"rule up { condition: filesize > 1 }")])
        self.assertEqual((run.files_skipped, run.rules_updated), (1, 0))
