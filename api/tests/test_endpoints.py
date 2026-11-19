"""Every endpoint: permissions per role, behaviour, and answers matching the documentation."""

import io
import json
import zipfile
from unittest import mock

from django.core.files.uploadedfile import SimpleUploadedFile
from django.db import connection
from django.test import override_settings
from django.test.utils import CaptureQueriesContext

from accounts.roles import VIEWER_PERMISSIONS
from api.registry import ENDPOINTS, Endpoint
from api.tests.helpers import ApiTestCase
from rules.models import ImportRun, Rule, Ruleset, RuleVersion, Tag
from rules.services import editing
from rules.services.compiler import check_ruleset
from rules.services.scanner import ScanError
from rules.tests.helpers import make_ruleset

VIEWER_SET = {f"rules.{codename}" for codename in VIEWER_PERMISSIONS}
NEW_RULE = 'rule api_new : demo { strings: $a = "api new" condition: $a }'


def as_json(data):
    return {"data": json.dumps(data), "content_type": "application/json"}


class PermissionMatrixTests(ApiTestCase):
    """Each endpoint as anonymous, no role, Viewer and Editor: the same permissions as the UI."""

    def url(self, e: Endpoint) -> str:
        kwargs = {}
        for name in e.path_params:
            if name == "number":
                kwargs[name] = 1
            elif name == "job_id":
                kwargs[name] = "0b6f1c9e-5a2d-4c1b-9f3e-7d8a6b5c4e21"
            elif e.route.startswith("rulesets/"):
                kwargs[name] = self.ruleset.pk
            elif e.route.startswith("imports/"):
                kwargs[name] = self.import_run.pk
            else:
                kwargs[name] = self.hello.pk
        return "/api/v1" + e.path.format(**kwargs)

    def test_anonymous_gets_401_everywhere(self):
        for e in ENDPOINTS:
            with self.subTest(e.operation):
                self.assertEqual(self.api(e.method, self.url(e), None).status_code, 401)

    def test_roles(self):
        nobody, viewer = self.key_for(self.nobody), self.key_for(self.viewer)
        for e in ENDPOINTS:
            with self.subTest(e.operation):
                no_role = self.api(e.method, self.url(e), nobody).status_code
                self.assertEqual(no_role, 403 if e.permissions else 200)
                status = self.api(e.method, self.url(e), viewer).status_code
                if set(e.permissions) <= VIEWER_SET:
                    self.assertNotIn(status, (401, 403))
                else:
                    self.assertEqual(status, 403)

    def test_permission_is_checked_before_the_lookup(self):
        viewer = self.key_for(self.viewer)
        for url in ("/api/v1/rules/999999/", f"/api/v1/rules/{self.hello.pk}/"):
            self.assertEqual(self.api("DELETE", url, viewer).status_code, 403)

    def test_editor_is_allowed_everywhere(self):
        editor = self.key_for(self.editor)
        safe = [e for e in ENDPOINTS if e.method == "GET"]
        for e in safe:
            with self.subTest(e.operation):
                self.assertNotIn(self.api("GET", self.url(e), editor).status_code, (401, 403))


class RuleListTests(ApiTestCase):
    def setUp(self):
        self.key = self.key_for(self.viewer)

    def names(self, query=""):
        response = self.api("GET", f"/api/v1/rules/{query}", self.key)
        self.assertEqual(response.status_code, 200)
        return [row["name"] for row in response.json()["results"]]

    def test_search_filters_and_sort_match_the_ui(self):
        self.assertEqual(self.names(), ["broken_rule", "hello_world", "pe_rule"])
        self.assertEqual(self.names("?q=greeting"), ["hello_world"])
        self.assertEqual(self.names("?tag=demo&sort=-name"), ["pe_rule", "hello_world"])
        self.assertEqual(self.names("?status=error"), ["broken_rule"])
        self.assertEqual(
            self.names(f"?ruleset={self.ruleset.pk}&sort=ruleset"),
            ["hello_world", "broken_rule", "pe_rule"],
        )
        self.assertEqual(self.names("?path=sample"), ["broken_rule", "hello_world", "pe_rule"])
        self.assertEqual(self.names("?path=other/"), [])
        # Invalid values are ignored, as on the page.
        self.assertEqual(
            self.names("?sort=bogus&status=bogus"), ["broken_rule", "hello_world", "pe_rule"]
        )

    def test_row_fields(self):
        row = self.api("GET", "/api/v1/rules/?q=hello_world", self.key).json()["results"][0]
        self.assertEqual(row["tags"], ["demo", "greeting"])
        self.assertEqual(row["ruleset"]["path"], "sample.yar")
        self.assertEqual(row["status"], "ok")
        self.assertTrue(row["url"].endswith(f"/api/v1/rules/{self.hello.pk}/"))

    def test_pagination(self):
        source = "\n".join(f"rule bulk_{i:03} {{ condition: true }}" for i in range(150))
        make_ruleset(source, name="bulk.yar")
        first = self.api("GET", "/api/v1/rules/?q=bulk_", self.key).json()
        self.assertEqual((first["count"], first["pages"], first["page_size"]), (150, 2, 100))
        self.assertEqual(len(first["results"]), 100)
        self.assertIsNone(first["previous"])
        self.assertIn("q=bulk_", first["next"])
        second = self.api("GET", first["next"].replace("http://testserver", ""), self.key).json()
        self.assertEqual(len(second["results"]), 50)
        self.assertIsNone(second["next"])
        beyond = self.api("GET", "/api/v1/rules/?q=bulk_&page=99", self.key).json()
        self.assertEqual(beyond["page"], 2)

    def test_query_count_is_bounded(self):
        def count():
            with CaptureQueriesContext(connection) as queries:
                self.assertEqual(self.api("GET", "/api/v1/rules/", self.key).status_code, 200)
            return len(queries)

        count()  # the key's first use records last_used_at
        few = count()
        make_ruleset(
            "\n".join(f"rule q_{i} : t{i} {{ condition: true }}" for i in range(40)),
            name="more.yar",
        )
        self.assertEqual(count(), few)

    def test_list_queries_do_not_select_source(self):
        with CaptureQueriesContext(connection) as queries:
            self.api("GET", "/api/v1/rules/", self.key)
        rule_selects = [q["sql"] for q in queries if 'FROM "rules_rule"' in q["sql"]]
        self.assertTrue(rule_selects)
        self.assertFalse(any('"rules_rule"."source"' in sql for sql in rule_selects))


class OtherListTests(ApiTestCase):
    def setUp(self):
        self.key = self.key_for(self.viewer)

    def bounded(self, url, grow):
        def count():
            with CaptureQueriesContext(connection) as queries:
                self.assertEqual(self.api("GET", url, self.key).status_code, 200)
            return len(queries)

        count()  # the key's first use records last_used_at
        before = count()
        grow()
        self.assertEqual(count(), before, url)

    def test_ruleset_list_matches_ui_and_is_bounded(self):
        data = self.api("GET", "/api/v1/rulesets/?q=sample&sort=-rules", self.key).json()
        row = data["results"][0]
        self.assertEqual(
            (row["name"], row["rules_active"], row["rules_failing"]), ("sample.yar", 3, 1)
        )
        self.bounded(
            "/api/v1/rulesets/",
            lambda: [make_ruleset("rule z { condition: true }", name=f"r{i}") for i in range(5)],
        )

    def test_tag_list_is_bounded(self):
        data = self.api("GET", "/api/v1/tags/", self.key).json()
        self.assertEqual(
            data["results"], [{"name": "demo", "rules": 2}, {"name": "greeting", "rules": 1}]
        )
        self.bounded("/api/v1/tags/", lambda: [Tag.objects.create(name=f"t{i}") for i in range(5)])

    def test_import_list_is_bounded(self):
        self.bounded(
            "/api/v1/imports/",
            lambda: [
                ImportRun.objects.create(origin=ImportRun.Origin.CLI, source="x", user=self.editor)
                for _ in range(5)
            ],
        )

    def test_dashboard(self):
        data = self.api("GET", "/api/v1/dashboard/", self.key).json()
        self.assertEqual(data["counts"]["rules"], 3)
        self.assertEqual(data["counts"]["failing"], 1)
        self.assertEqual(data["counts"]["rulesets"], 1)


class RuleReadTests(ApiTestCase):
    def setUp(self):
        self.key = self.key_for(self.viewer)

    def test_detail(self):
        data = self.api("GET", f"/api/v1/rules/{self.hello.pk}/", self.key).json()
        self.assertEqual(data["name"], "hello_world")
        self.assertEqual(data["imports"], [])
        self.assertIn(["score", 5], data["meta"])
        self.assertEqual([v["number"] for v in data["versions"]], [1])
        broken = self.api("GET", f"/api/v1/rules/{self.broken.pk}/", self.key).json()
        self.assertEqual(broken["status"], "error")
        self.assertIn("no_such_identifier", broken["compile_error"])

    def test_download(self):
        response = self.api("GET", f"/api/v1/rules/{self.hello.pk}/download/", self.key)
        self.assertEqual(response["Content-Type"], "text/plain; charset=utf-8")
        self.assertIn('filename="hello_world.yar"', response["Content-Disposition"])
        self.assertEqual(response.content.decode(), self.hello.text)

    def test_versions_and_diff(self):
        editor = self.key_for(self.editor)
        text = self.hello.text.replace("hello world", "hello there")
        self.api(
            "PUT",
            f"/api/v1/rules/{self.hello.pk}/",
            editor,
            **as_json({"text": text, "version": 1}),
        )
        listing = self.api("GET", f"/api/v1/rules/{self.hello.pk}/versions/", self.key).json()
        self.assertEqual([v["number"] for v in listing["results"]], [2, 1])
        self.assertEqual(listing["results"][0]["created_by"], "editor")
        version = self.api("GET", f"/api/v1/rules/{self.hello.pk}/versions/2/", self.key).json()
        self.assertTrue(version["is_current"])
        self.assertEqual((version["previous"], version["next"]), (1, None))
        self.assertEqual((version["diff"]["added"], version["diff"]["removed"]), (1, 1))
        kinds = {line["kind"] for line in version["diff"]["lines"]}
        self.assertLessEqual({"added", "removed"}, kinds)
        missing = self.api("GET", f"/api/v1/rules/{self.hello.pk}/versions/9/", self.key)
        self.assertEqual(missing.status_code, 404)

    def test_export_by_filter_and_selection(self):
        response = self.api("GET", "/api/v1/rules/export/?tag=demo&format=zip", self.key)
        self.assertEqual(response["Content-Type"], "application/zip")
        with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
            content = archive.read(archive.namelist()[0]).decode()
        self.assertIn("hello_world", content)
        self.assertNotIn("broken_rule", content)
        response = self.api("GET", f"/api/v1/rules/export/?ids={self.broken.pk}", self.key)
        self.assertIn("broken_rule", response.content.decode())
        response = self.api(
            "POST",
            "/api/v1/rules/export/",
            self.key,
            **as_json({"ids": [self.hello.pk, self.pe_rule.pk]}),
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("pe_rule", response.content.decode())
        nothing = self.api("GET", "/api/v1/rules/export/?q=no-such-rule", self.key)
        self.assertEqual(nothing.status_code, 404)
        self.assertEqual(nothing.json()["error"]["code"], "nothing_to_export")
        bad = self.api("POST", "/api/v1/rules/export/", self.key, **as_json({"ids": ["x"]}))
        self.assertEqual(bad.status_code, 400)


class RuleWriteTests(ApiTestCase):
    def setUp(self):
        self.key = self.key_for(self.editor)

    def test_create_in_ruleset_and_collection(self):
        response = self.api(
            "POST",
            "/api/v1/rules/",
            self.key,
            **as_json({"text": NEW_RULE, "ruleset": self.ruleset.pk}),
        )
        self.assertEqual(response.status_code, 201)
        data = response.json()
        self.assertTrue(data["changed"])
        self.assertEqual(data["rule"]["ruleset"]["id"], self.ruleset.pk)
        self.assertTrue(response["Location"].endswith(f"/api/v1/rules/{data['rule']['id']}/"))
        version = RuleVersion.objects.get(rule_id=data["rule"]["id"])
        self.assertEqual((version.origin, version.created_by), ("create", self.editor))
        text = NEW_RULE.replace("api_new", "in_collection")
        response = self.api(
            "POST", "/api/v1/rules/", self.key, **as_json({"text": text, "collection": "API made"})
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["rule"]["ruleset"]["origin"], "manual")

    def test_create_refusals(self):
        cases = [
            ({"text": NEW_RULE}, 400),
            ({"text": NEW_RULE, "ruleset": self.ruleset.pk, "collection": "x"}, 400),
            ({"text": NEW_RULE, "ruleset": 999999}, 404),
            ({"text": NEW_RULE, "collection": "bad\nname"}, 400),
            ({"text": 5, "collection": "x"}, 400),
            ({"text": "rule hello_world { condition: true }", "ruleset": self.ruleset.pk}, 422),
            ({"text": "rule nope { condition: what }", "collection": "never"}, 422),
            ({"text": "not yara", "collection": "never"}, 422),
        ]
        for body, status in cases:
            with self.subTest(body=body):
                response = self.api("POST", "/api/v1/rules/", self.key, **as_json(body))
                self.assertEqual(response.status_code, status)
        refused = self.api("POST", "/api/v1/rules/", self.key, **as_json(cases[6][0])).json()
        self.assertEqual(refused["error"]["code"], "rule_rejected")
        self.assertFalse(refused["error"]["result"]["ok"])
        # A refused save into a new collection leaves no collection behind.
        self.assertFalse(Ruleset.objects.filter(name="never").exists())

    def test_create_collection_needs_add_ruleset(self):
        self.editor.groups.clear()
        from django.contrib.auth.models import Permission

        self.editor.user_permissions.add(
            *Permission.objects.filter(codename__in=["add_rule", "view_rule"])
        )
        response = self.api(
            "POST",
            "/api/v1/rules/",
            self.key,
            **as_json({"text": NEW_RULE, "collection": "new one"}),
        )
        self.assertEqual(response.status_code, 403)

    def test_validate_new_and_existing(self):
        ok = self.api(
            "POST",
            "/api/v1/rules/validate/",
            self.key,
            **as_json({"text": NEW_RULE, "collection": "Only checked"}),
        ).json()
        self.assertEqual((ok["ok"], ok["name"]), (True, "api_new"))
        self.assertFalse(Ruleset.objects.filter(path="Only checked").exists())
        bad = self.api(
            "POST",
            "/api/v1/rules/validate/",
            self.key,
            **as_json({"text": "rule x { condition: y }", "ruleset": self.ruleset.pk}),
        ).json()
        self.assertFalse(bad["ok"])
        self.assertEqual(bad["line"], 1)
        rename = self.api(
            "POST",
            f"/api/v1/rules/{self.hello.pk}/validate/",
            self.key,
            **as_json({"text": "rule renamed { condition: true }"}),
        ).json()
        self.assertTrue(rename["ok"])
        self.assertEqual(Rule.objects.get(pk=self.hello.pk).name, "hello_world")

    def test_edit_with_version_check(self):
        url = f"/api/v1/rules/{self.hello.pk}/"
        text = self.hello.text.replace("hello world", "hello api")
        response = self.api("PUT", url, self.key, **as_json({"text": text, "version": 1}))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            (response.json()["changed"], response.json()["rule"]["version"]), (True, 2)
        )
        stale = self.api("PUT", url, self.key, **as_json({"text": text + " ", "version": 1}))
        self.assertEqual(stale.status_code, 409)
        self.assertEqual(stale.json()["error"]["code"], "version_conflict")
        self.assertEqual(stale.json()["error"]["current_version"], 2)
        same = self.api("PUT", url, self.key, **as_json({"text": text, "version": 2}))
        self.assertEqual((same.status_code, same.json()["changed"]), (200, False))
        missing = self.api("PUT", url, self.key, **as_json({"text": text}))
        self.assertEqual(missing.status_code, 400)
        refused = self.api(
            "PUT", url, self.key, **as_json({"text": "rule x { condition: y }", "version": 2})
        )
        self.assertEqual(refused.status_code, 422)
        self.assertEqual(Rule.objects.get(pk=self.hello.pk).version, 2)

    def test_restore(self):
        text = self.hello.text.replace("hello world", "hello api")
        editing.update_rule(self.hello, text, user=self.editor)
        url = f"/api/v1/rules/{self.hello.pk}/versions/1/restore/"
        stale = self.api("POST", url, self.key, **as_json({"version": 1}))
        self.assertEqual(stale.status_code, 409)
        response = self.api("POST", url, self.key)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            (response.json()["changed"], response.json()["rule"]["version"]), (True, 3)
        )
        self.assertEqual(RuleVersion.objects.get(rule=self.hello, number=3).origin, "restore")
        again = self.api("POST", url, self.key, **as_json({"version": 3}))
        self.assertEqual((again.status_code, again.json()["changed"]), (200, False))

    def test_delete_rule(self):
        response = self.api("DELETE", f"/api/v1/rules/{self.hello.pk}/", self.key)
        self.assertEqual(response.status_code, 204)
        self.assertFalse(Rule.objects.filter(pk=self.hello.pk).exists())
        again = self.api("DELETE", f"/api/v1/rules/{self.hello.pk}/", self.key)
        self.assertEqual(again.status_code, 404)


class RulesetTests(ApiTestCase):
    def setUp(self):
        self.key = self.key_for(self.editor)

    def test_detail_and_downloads(self):
        editing.delete_rule(self.pe_rule)
        data = self.api("GET", f"/api/v1/rulesets/{self.ruleset.pk}/", self.key).json()
        self.assertEqual([r["name"] for r in data["rules"]], ["hello_world", "broken_rule"])
        self.assertTrue(data["original_url"].endswith("/original/"))
        rebuilt = self.api("GET", f"/api/v1/rulesets/{self.ruleset.pk}/download/", self.key)
        self.assertNotIn("pe_rule", rebuilt.content.decode())
        original = self.api("GET", f"/api/v1/rulesets/{self.ruleset.pk}/original/", self.key)
        self.assertIn("pe_rule", original.content.decode())
        self.assertIn('filename="sample.yar"', original["Content-Disposition"])

    def test_detail_query_count_is_bounded(self):
        def count():
            with CaptureQueriesContext(connection) as queries:
                self.api("GET", f"/api/v1/rulesets/{self.ruleset.pk}/", self.key)
            return len(queries)

        count()  # the key's first use records last_used_at
        before = count()
        for i in range(5):
            editing.create_rule(self.ruleset, f"rule extra_{i} : t{i} {{ condition: true }}")
        self.assertEqual(count(), before)

    def test_manual_ruleset_has_no_original(self):
        manual = make_ruleset("rule m { condition: true }", name="manual")
        check_ruleset(manual)
        data = self.api("GET", f"/api/v1/rulesets/{manual.pk}/", self.key).json()
        self.assertIsNone(data["original_url"])
        response = self.api("GET", f"/api/v1/rulesets/{manual.pk}/original/", self.key)
        self.assertEqual(response.json()["error"]["code"], "no_original")

    def test_delete(self):
        response = self.api("DELETE", f"/api/v1/rulesets/{self.ruleset.pk}/", self.key)
        self.assertEqual(response.status_code, 204)
        self.assertFalse(Ruleset.objects.filter(pk=self.ruleset.pk).exists())


class ImportTests(ApiTestCase):
    def setUp(self):
        self.key = self.key_for(self.editor)

    def test_upload_round_trip(self):
        download = self.api("GET", f"/api/v1/rulesets/{self.ruleset.pk}/original/", self.key)
        files = [
            SimpleUploadedFile("round.yar", download.content),
            SimpleUploadedFile("bad.yar", b"rule {"),
        ]
        response = self.api("POST", "/api/v1/imports/upload/", self.key, data={"rule_files": files})
        self.assertEqual(response.status_code, 201)
        run = response.json()
        self.assertEqual((run["files_seen"], run["files_failed"], run["rules_created"]), (2, 1, 3))
        self.assertEqual(run["user"], "editor")
        self.assertEqual({f["status"] for f in run["files"]}, {"created", "failed"})
        detail = self.api("GET", f"/api/v1/imports/{run['id']}/", self.key).json()
        self.assertEqual(detail["id"], run["id"])
        created = Ruleset.objects.get(path="round.yar")
        rebuilt = self.api("GET", f"/api/v1/rulesets/{created.pk}/original/", self.key)
        self.assertEqual(rebuilt.content, download.content)

    def test_upload_without_files(self):
        response = self.api("POST", "/api/v1/imports/upload/", self.key, data={})
        self.assertEqual(response.status_code, 400)
        self.assertIn("rule_files", response.json()["error"]["fields"])

    def test_upload_never_takes_a_path(self):
        response = self.api(
            "POST", "/api/v1/imports/upload/", self.key, data={"rule_files": "/etc/passwd"}
        )
        self.assertEqual(response.status_code, 400)

    def test_directory_scan(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as root:
            with override_settings(YARADUDE_RULES_DIR=Path(root)):
                status = self.api("GET", "/api/v1/imports/directory/", self.key).json()
                self.assertEqual((status["exists"], status["importable"]), (True, 0))
                empty = self.api("POST", "/api/v1/imports/scan/", self.key)
                self.assertEqual(empty.json()["error"]["code"], "directory_empty")
                (Path(root) / "a.yar").write_text("rule from_dir { condition: true }\n")
                response = self.api(
                    "POST", "/api/v1/imports/scan/", self.key, data={"root": "/etc"}
                )
                self.assertEqual(response.status_code, 201)
                self.assertEqual(response.json()["origin"], "scan")
                self.assertTrue(Rule.objects.filter(name="from_dir").exists())
            with override_settings(YARADUDE_RULES_DIR=Path(root) / "missing"):
                missing = self.api("POST", "/api/v1/imports/scan/", self.key)
                self.assertEqual(missing.json()["error"]["code"], "directory_missing")


class ScanTests(ApiTestCase):
    SAMPLE = b"xx hello world yy secret-sample-bytes"

    def setUp(self):
        self.key = self.key_for(self.viewer)

    def scan(self, data=SAMPLE, **extra):
        return self.api(
            "POST",
            "/api/v1/scan/",
            self.key,
            data={"sample": SimpleUploadedFile("sample.bin", data), **extra},
        )

    def test_scan_returns_matches(self):
        with CaptureQueriesContext(connection) as queries:
            response = self.scan()
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual([m["rule"]["name"] for m in data["matches"]], ["hello_world"])
        instance = data["matches"][0]["patterns"][0]["instances"][0]
        self.assertEqual((instance["offset"], instance["ascii"]), (3, "hello world"))
        self.assertEqual([r["name"] for r in data["left_out"]], ["broken_rule"])
        self.assertEqual(data["sample"]["size"], len(self.SAMPLE))
        self.assertFalse(any("secret-sample-bytes" in q["sql"] for q in queries))

    def test_scan_limit_by_path(self):
        self.assertEqual(self.scan(path="no-such-dir/").json()["matches"], [])
        limit = self.api("GET", "/api/v1/scan/limit/?path=sample", self.key).json()
        self.assertEqual((limit["rules"], limit["rulesets"]), (3, 1))

    def test_scan_errors(self):
        self.assertEqual(self.api("POST", "/api/v1/scan/", self.key, data={}).status_code, 400)
        with override_settings(YARADUDE_SCAN_MAX_BYTES=10):
            self.assertEqual(self.scan().status_code, 400)
        with mock.patch("api.endpoints.scan.scan_sample", side_effect=ScanError("timed out")):
            response = self.scan()
        self.assertEqual(response.status_code, 422)
        self.assertEqual(response.json()["error"]["message"], "timed out")

    def test_sample_is_not_logged(self):
        with self.assertLogs(level="DEBUG") as logs:
            self.scan()
            with mock.patch("api.endpoints.scan.scan_sample", side_effect=RuntimeError("boom")):
                self.scan()
        self.assertNotIn("secret-sample-bytes", "\n".join(logs.output))


class OpenApiTests(ApiTestCase):
    def test_document_lists_every_endpoint(self):
        key = self.key_for(self.nobody)
        doc = self.api("GET", "/api/v1/openapi.json", key).json()
        self.assertEqual(doc["servers"][0]["url"], "http://testserver/api/v1")
        operations = {
            op["operationId"]: (method.upper(), path)
            for path, methods in doc["paths"].items()
            for method, op in methods.items()
        }
        self.assertEqual(operations, {e.operation: (e.method, e.path) for e in ENDPOINTS})
        refs = set()

        def collect(node):
            if isinstance(node, dict):
                if "$ref" in node:
                    refs.add(node["$ref"].rsplit("/", 1)[1])
                for value in node.values():
                    collect(value)
            elif isinstance(node, list):
                for value in node:
                    collect(value)

        collect(doc)
        self.assertLessEqual(refs, set(doc["components"]["schemas"]))


class DeletedTests(ApiTestCase):
    """Recoverable deletes: hidden everywhere, listed as deleted, restorable, purgeable."""

    def setUp(self):
        self.editor_key = self.key_for(self.editor)
        self.root_key = self.key_for(self.superuser)

    def test_deleted_rule_is_hidden_and_restorable(self):
        pk = self.hello.pk
        self.assertEqual(
            self.api("DELETE", f"/api/v1/rules/{pk}/", self.editor_key).status_code, 204
        )
        for url in (
            f"/api/v1/rules/{pk}/",
            f"/api/v1/rules/{pk}/versions/",
            f"/api/v1/rules/{pk}/versions/1/",
            f"/api/v1/rules/{pk}/download/",
        ):
            with self.subTest(url=url):
                self.assertEqual(self.api("GET", url, self.editor_key).status_code, 404)
        names = [
            r["name"]
            for r in self.api("GET", "/api/v1/rules/?status=all", self.editor_key).json()["results"]
        ]
        self.assertNotIn("hello_world", names)
        ruleset = self.api("GET", f"/api/v1/rulesets/{self.ruleset.pk}/", self.editor_key).json()
        self.assertEqual(ruleset["rules_active"], 2)
        tags = self.api("GET", "/api/v1/tags/", self.editor_key).json()["results"]
        self.assertEqual({t["name"]: t["rules"] for t in tags}["greeting"], 0)
        listed = self.api("GET", "/api/v1/rules/deleted/", self.editor_key).json()["results"]
        self.assertEqual([(r["id"], r["deleted_by"]) for r in listed], [(pk, "editor")])
        restore = self.api("POST", f"/api/v1/rules/deleted/{pk}/restore/", self.editor_key)
        self.assertEqual(restore.status_code, 200)
        self.assertEqual(self.api("GET", f"/api/v1/rules/{pk}/", self.editor_key).status_code, 200)
        again = self.api("POST", f"/api/v1/rules/deleted/{pk}/restore/", self.editor_key)
        self.assertEqual(again.status_code, 404)

    def test_purge_needs_its_own_permission(self):
        pk = self.hello.pk
        editing.delete_rule(self.hello, user=self.editor)
        denied = self.api("DELETE", f"/api/v1/rules/deleted/{pk}/", self.editor_key)
        self.assertEqual(denied.status_code, 403)
        purged = self.api("DELETE", f"/api/v1/rules/deleted/{pk}/", self.root_key)
        self.assertEqual(purged.status_code, 204)
        self.assertFalse(Rule.all_objects.filter(pk=pk).exists())

    def test_only_deleted_rules_can_be_purged(self):
        response = self.api("DELETE", f"/api/v1/rules/deleted/{self.hello.pk}/", self.root_key)
        self.assertEqual(response.status_code, 404)
        self.assertTrue(Rule.objects.filter(pk=self.hello.pk).exists())

    def test_ruleset_delete_restore_purge(self):
        pk = self.ruleset.pk
        self.assertEqual(
            self.api("DELETE", f"/api/v1/rulesets/{pk}/", self.editor_key).status_code, 204
        )
        self.assertEqual(
            self.api("GET", f"/api/v1/rulesets/{pk}/", self.editor_key).status_code, 404
        )
        listed = self.api("GET", "/api/v1/rulesets/deleted/", self.editor_key).json()["results"]
        self.assertEqual([(r["id"], r["rules_deleted"]) for r in listed], [(pk, 3)])
        rules = self.api("GET", "/api/v1/rules/deleted/", self.editor_key).json()["results"]
        self.assertTrue(all(r["deleted_with_ruleset"] and r["ruleset"]["deleted"] for r in rules))
        blocked = self.api(
            "POST", f"/api/v1/rules/deleted/{self.hello.pk}/restore/", self.editor_key
        )
        self.assertEqual(blocked.status_code, 409)
        restored = self.api("POST", f"/api/v1/rulesets/deleted/{pk}/restore/", self.editor_key)
        self.assertEqual((restored.status_code, restored.json()["rules_active"]), (200, 3))
        editing.delete_ruleset(self.ruleset, user=self.editor)
        self.assertEqual(
            self.api("DELETE", f"/api/v1/rulesets/deleted/{pk}/", self.editor_key).status_code, 403
        )
        self.assertEqual(
            self.api("DELETE", f"/api/v1/rulesets/deleted/{pk}/", self.root_key).status_code, 204
        )
        self.assertFalse(Ruleset.all_objects.filter(pk=pk).exists())

    def test_import_run_does_not_link_a_deleted_ruleset(self):
        editing.delete_ruleset(self.ruleset, user=self.editor)
        run = self.api("GET", f"/api/v1/imports/{self.import_run.pk}/", self.editor_key).json()
        self.assertTrue(all(f["ruleset"] is None for f in run["files"]))


class SearchTests(ApiTestCase):
    def test_search_defaults_to_relevance_and_accepts_name_sort(self):
        key = self.key_for(self.viewer)
        ranked = self.api("GET", "/api/v1/rules/?q=hello", key).json()["results"]
        self.assertEqual([r["name"] for r in ranked], ["hello_world"])
        by_name = self.api("GET", "/api/v1/rules/?q=rule&sort=-name", key).json()["results"]
        names = [r["name"] for r in by_name]
        self.assertEqual(names, sorted(names, reverse=True))
        literal = self.api("GET", '/api/v1/rules/?q="hello" OR name:*', key).json()
        self.assertEqual(literal["count"], 0)


@override_settings(YARADUDE_SCAN_INLINE_MAX_BYTES=1024)
class ScanJobTests(ApiTestCase):
    def setUp(self):
        self.key = self.key_for(self.viewer)

    def submit(self, *samples, **extra):
        files = [SimpleUploadedFile(f"s{i}.bin", data) for i, data in enumerate(samples)]
        return self.api("POST", "/api/v1/scans/", self.key, data={"samples": files, **extra})

    def test_single_small_sample_is_scanned_at_once(self):
        response = self.submit(b"xx hello world yy")
        self.assertEqual(response.status_code, 201)
        job = response.json()["jobs"][0]
        self.assertEqual(job["state"], "finished")
        self.assertEqual(job["submitted_by"], "viewer")
        detail = self.api("GET", job["url"].replace("http://testserver", ""), self.key).json()
        self.assertEqual([m["rule"] for m in detail["result"]["matches"]], ["hello_world"])

    def test_several_samples_are_queued_and_shared_with_the_team(self):
        jobs = self.submit(b"a", b"hello world").json()["jobs"]
        self.assertEqual({j["state"] for j in jobs}, {"queued"})
        batch = jobs[0]["batch"]
        self.assertIsNotNone(batch)
        other = self.key_for(self.editor)
        listed = self.api("GET", f"/api/v1/scans/?batch={batch}", other).json()
        self.assertEqual(listed["count"], 2)
        self.assertNotIn("result", listed["results"][0])

    def test_errors(self):
        self.assertEqual(self.api("POST", "/api/v1/scans/", self.key, data={}).status_code, 400)
        missing = self.api("GET", "/api/v1/scans/0b6f1c9e-5a2d-4c1b-9f3e-7d8a6b5c4e21/", self.key)
        self.assertEqual(missing.status_code, 404)
        self.assertEqual(self.api("GET", "/api/v1/scans/not-a-uuid/", self.key).status_code, 404)

    def test_status(self):
        data = self.api("GET", "/api/v1/scans/status/", self.key).json()
        self.assertIn("pending", data["compiled"])
        self.assertEqual(data["limits"]["inline_max_bytes"], 1024)
