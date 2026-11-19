"""
JSON Schema (OpenAPI 3.1) components of the API's responses. Every property
carries an `example`, from which the documentation builds its example
responses; objects forbid additional properties, so the tests that check
real responses against these schemas catch any drift between them and
api.serializers.
"""

from __future__ import annotations

from typing import Any

Schema = dict[str, Any]

TIME = "2026-11-19T20:41:07.123456+00:00"


def s(kind: str, example: Any, description: str = "", nullable: bool = False, **extra: Any):
    schema: Schema = {"type": [kind, "null"] if nullable else kind, "example": example, **extra}
    if description:
        schema["description"] = description
    return schema


def ref(name: str, nullable: bool = False) -> Schema:
    target = {"$ref": f"#/components/schemas/{name}"}
    return {"anyOf": [target, {"type": "null"}]} if nullable else target


def array(items: Schema, description: str = "") -> Schema:
    schema: Schema = {"type": "array", "items": items}
    if description:
        schema["description"] = description
    return schema


def obj(**properties: Schema) -> Schema:
    """An object with exactly these properties, all required (see `optional`)."""
    return {
        "type": "object",
        "properties": properties,
        "required": list(properties),
        "additionalProperties": False,
    }


def optional(schema: Schema, *names: str) -> Schema:
    """`schema` with `names` no longer required."""
    return {**schema, "required": [n for n in schema["required"] if n not in names]}


def page(item: str, description: str) -> Schema:
    return obj(
        count=s("integer", 1234, "Total number of results."),
        page=s("integer", 1),
        pages=s("integer", 13),
        page_size=s("integer", 100),
        next=s("string", "https://yaradude.example/api/v1/rules/?page=2", nullable=True),
        previous=s("string", None, nullable=True),
        results=array(ref(item), description),
    )


def url(path: str) -> Schema:
    return s("string", f"https://yaradude.example{path}", format="uri")


ORIGINS = ["directory", "upload", "manual"]
VERSION_ORIGINS = ["import", "upload", "create", "edit", "restore"]
RUN_ORIGINS = ["scan", "upload", "cli"]

RULESET_REF = {
    "id": s("integer", 7),
    "name": s("string", "apt_example.yar"),
    "path": s("string", "signature-base/yara/apt_example.yar"),
    "origin": s("string", "directory", enum=ORIGINS),
    "url": url("/api/v1/rulesets/7/"),
}

RULE_SUMMARY = {
    "id": s("integer", 42),
    "name": s("string", "hello_world"),
    "ruleset": ref("RulesetRef"),
    "tags": array(s("string", "demo")),
    "description": s("string", "Finds a friendly greeting"),
    "author": s("string", "analyst"),
    "version": s("integer", 3, "Current version number; send it back when editing."),
    "status": s(
        "string",
        "ok",
        "`removed`, `error` (does not compile), `warnings` or `ok`.",
        enum=["ok", "warnings", "error", "removed"],
    ),
    "modified": s("boolean", False, "Changed locally since the last import."),
    "created_at": s("string", TIME, "First imported or created.", format="date-time"),
    "updated_at": s("string", TIME, "Last content change.", format="date-time"),
    "removed_at": s("string", None, nullable=True, format="date-time"),
    "url": url("/api/v1/rules/42/"),
    "web_url": url("/rules/42/"),
}

VERSION_SUMMARY = {
    "number": s("integer", 2),
    "origin": s("string", "edit", enum=VERSION_ORIGINS),
    "sha256": s("string", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"),
    "created_at": s("string", TIME, format="date-time"),
    "created_by": s(
        "string",
        "editor",
        "Username; null for imports from the command line or a deleted user.",
        nullable=True,
    ),
    "import_run": s("integer", None, "Import run that wrote this version.", nullable=True),
    "url": url("/api/v1/rules/42/versions/2/"),
}

RULESET_SUMMARY = {
    **RULESET_REF,
    "compile_error": s("string", "", "Summary; blank when every active rule compiles."),
    "rules_active": s("integer", 11),
    "rules_failing": s("integer", 0),
    "rules_removed": s("integer", 1),
    "sha256": s("string", "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"),
    "created_at": s("string", TIME, format="date-time"),
    "updated_at": s("string", TIME, format="date-time"),
    "last_imported_at": s("string", TIME, nullable=True, format="date-time"),
    "web_url": url("/rulesets/7/"),
}

RUN_SUMMARY = {
    "id": s("integer", 12),
    "origin": s("string", "upload", enum=RUN_ORIGINS),
    "source": s("string", "first.yar, second.yar", "What was imported."),
    "user": s("string", "editor", nullable=True),
    "started_at": s("string", TIME, format="date-time"),
    "finished_at": s("string", TIME, nullable=True, format="date-time"),
    **{
        name: s("integer", value)
        for name, value in [
            ("files_seen", 2),
            ("files_changed", 1),
            ("files_unchanged", 1),
            ("files_failed", 0),
            ("files_skipped", 0),
            ("rules_created", 3),
            ("rules_updated", 0),
            ("rules_removed", 0),
            ("rules_unchanged", 4),
            ("rules_skipped", 0),
        ]
    },
    "summary": s(
        "string",
        "files: 2 seen, 1 changed, 1 unchanged, 0 failed; rules: 3 created, "
        "0 updated, 0 removed, 4 unchanged",
    ),
    "url": url("/api/v1/imports/12/"),
    "web_url": url("/import/runs/12/"),
}

BROKEN = obj(
    id=s("integer", 43),
    name=s("string", "uses_hello"),
    error=s("string", "error[E009]: unknown identifier `hello_world` …"),
)

VALIDATION = obj(
    ok=s("boolean", True, "Whether the text would be saved."),
    error=s(
        "string",
        "",
        "Why it would be refused (multi-line YARA-X diagnostic or parse error); blank when ok.",
    ),
    line=s("integer", None, "Line of the error in the submitted text.", nullable=True),
    warnings=array(s("string", "warning[invariant_expr]: invariant boolean expression …")),
    broken=array(
        ref("BrokenRule"), "Sibling rules this change would break (saving is still allowed)."
    ),
    name=s("string", "api_example", "The rule name parsed from the text.", nullable=True),
)

COMPONENTS: dict[str, Schema] = {
    "Error": {
        "type": "object",
        "properties": {
            "error": optional(
                obj(
                    code=s("string", "permission_denied", "Stable, machine-readable code."),
                    message=s(
                        "string",
                        "Your account lacks the permission for this: "
                        "rules.change_rule. Ask an administrator for the Viewers or "
                        "Editors role.",
                    ),
                    fields={
                        "type": "object",
                        "description": "Validation messages per request field.",
                        "additionalProperties": array({"type": "string"}),
                        "example": {"text": ["This field is required."]},
                    },
                    current_version=s(
                        "integer", 4, "With `version_conflict`: the rule's version now."
                    ),
                    result=ref("Validation"),
                ),
                "fields",
                "current_version",
                "result",
            )
        },
        "required": ["error"],
        "additionalProperties": False,
    },
    "RulesetRef": obj(**RULESET_REF),
    "RuleSummary": obj(**RULE_SUMMARY),
    "Rule": obj(
        **RULE_SUMMARY,
        text=s(
            "string",
            'rule hello_world { strings: $a = "hello" condition: $a }',
            "Imports, a blank line and the source: the editor and download text.",
        ),
        source=s("string", 'rule hello_world { strings: $a = "hello" condition: $a }'),
        imports=array(s("string", "pe")),
        meta={
            "type": "array",
            "description": "`[key, value]` pairs in order; values are strings, numbers or "
            "booleans.",
            "items": {"type": "array"},
            "example": [["description", "Finds a friendly greeting"], ["score", 5]],
        },
        is_private=s("boolean", False),
        is_global=s("boolean", False),
        position=s("integer", 0, "Order within the ruleset."),
        sha256=s("string", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"),
        imported_sha256=s("string", "", "Content as last imported; blank for manual rules."),
        compile_error=s("string", "", "YARA-X diagnostic; blank when the rule compiles."),
        compile_warnings=array(s("string", "warning[slow_pattern]: slow pattern …")),
        download_url=url("/api/v1/rules/42/download/"),
        versions=array(ref("VersionSummary"), "Newest first."),
    ),
    "VersionSummary": obj(**VERSION_SUMMARY),
    "VersionList": obj(results=array(ref("VersionSummary"), "Newest first.")),
    "Version": obj(
        **VERSION_SUMMARY,
        rule=s("integer", 42),
        text=s("string", 'rule hello_world { strings: $a = "hello" condition: $a }'),
        is_current=s("boolean", False),
        previous=s("integer", 1, nullable=True),
        next=s("integer", 3, nullable=True),
        diff=obj(
            added=s("integer", 1),
            removed=s("integer", 1),
            lines=array(
                obj(
                    kind=s("string", "added", enum=["hunk", "context", "added", "removed"]),
                    text=s("string", '    $a = "hello"'),
                    old_number=s("integer", None, nullable=True),
                    new_number=s("integer", 3, nullable=True),
                ),
                "Unified diff against the previous version.",
            ),
        ),
    ),
    "BrokenRule": BROKEN,
    "Validation": VALIDATION,
    "Saved": obj(
        changed=s("boolean", True, "False when the text equals the current content."),
        warnings=array(s("string", "warning[invariant_expr]: invariant boolean expression …")),
        broken=array(ref("BrokenRule"), "Sibling rules this change broke."),
        rule=ref("Rule"),
    ),
    "Tag": obj(name=s("string", "apt"), rules=s("integer", 120, "Active rules with the tag.")),
    "RulePage": page("RuleSummary", "Rules of this page."),
    "TagPage": page("Tag", "Tags of this page."),
    "RulesetSummary": obj(**RULESET_SUMMARY),
    "DeletedRule": obj(
        id=s("integer", 42),
        name=s("string", "hello_world"),
        ruleset=obj(
            id=s("integer", 7),
            name=s("string", "apt_example.yar"),
            path=s("string", "signature-base/yara/apt_example.yar"),
            deleted=s("boolean", False, "The ruleset is deleted too."),
        ),
        version=s("integer", 3),
        deleted_at=s("string", TIME, format="date-time"),
        deleted_by=s("string", "editor", "Null for a deleted user.", nullable=True),
        deleted_with_ruleset=s("boolean", False, "Comes back when its ruleset is restored."),
        restore_url=url("/api/v1/rules/deleted/42/restore/"),
    ),
    "DeletedRulePage": page("DeletedRule", "Deleted rules of this page."),
    "DeletedRuleset": obj(
        id=s("integer", 7),
        name=s("string", "apt_example.yar"),
        path=s("string", "signature-base/yara/apt_example.yar"),
        origin=s("string", "directory", enum=ORIGINS),
        rules_deleted=s("integer", 11, "Rules that come back with it."),
        deleted_at=s("string", TIME, format="date-time"),
        deleted_by=s("string", "editor", nullable=True),
        restore_url=url("/api/v1/rulesets/deleted/7/restore/"),
    ),
    "DeletedRulesetPage": page("DeletedRuleset", "Deleted rulesets of this page."),
    "RulesetPage": page("RulesetSummary", "Rulesets of this page."),
    "Ruleset": obj(
        **RULESET_SUMMARY,
        download_url=url("/api/v1/rulesets/7/download/"),
        original_url=s(
            "string",
            "https://yaradude.example/api/v1/rulesets/7/original/",
            "Null when the ruleset was not imported from a file.",
            nullable=True,
        ),
        rules=array(ref("RuleSummary"), "In file order, removed rules last."),
    ),
    "ImportRunSummary": obj(**RUN_SUMMARY),
    "ImportRunPage": page("ImportRunSummary", "Import runs of this page, newest first."),
    "ImportFile": obj(
        path=s("string", "first.yar"),
        status=s(
            "string",
            "created",
            enum=["created", "updated", "failed", "skipped"],
            description="`skipped`: the file belongs to a deleted ruleset.",
        ),
        ruleset=ref("RulesetRef", nullable=True),
        rules_created=s("integer", 3),
        rules_updated=s("integer", 0),
        rules_removed=s("integer", 0),
        rules_unchanged=s("integer", 0),
        rules_skipped=s("integer", 0, "Rules left alone because they are deleted here."),
        message=s("string", "", "Why the file failed, or warnings."),
    ),
    "ImportRun": obj(
        **RUN_SUMMARY,
        files=array(ref("ImportFile"), "Only files that changed or failed."),
    ),
    "Directory": obj(
        path=s("string", "/rules"),
        exists=s("boolean", True),
        importable=s("integer", 2124, "Rule files a directory import would read."),
        skipped=array(
            obj(
                path=s("string", "huge/collection.yar"),
                reason=s("string", "larger than the limit of 4.0 MB"),
            ),
            "Rule files that would be recorded as failed instead of read, with the reason.",
        ),
        last_scan=ref("ImportRunSummary", nullable=True),
    ),
    "ScanResult": obj(
        sample=obj(
            name=s("string", "suspicious.bin"),
            size=s("integer", 151234),
            sha256=s("string", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        ),
        rules_scanned=s("integer", 10231),
        rulesets_scanned=s("integer", 2124),
        elapsed=s("number", 0.04, "Seconds for the whole request on the server."),
        scan_seconds=s("number", 0.01, "Seconds inside the engine."),
        compiled=obj(
            revision=s("integer", 118, "Rules revision the compiled set reflects."),
            built_at=s("string", TIME, nullable=True, format="date-time"),
            pending=s(
                "boolean",
                False,
                "Rules changed since; a newer set is being built "
                "and this answer used the previous one.",
            ),
        ),
        unmapped=array(s("string", "12:old_name"), "Matches that map to no stored rule (skipped)."),
        matches=array(
            obj(
                rule=obj(
                    id=s("integer", 42),
                    name=s("string", "hello_world"),
                    ruleset=ref("RulesetRef"),
                    url=url("/api/v1/rules/42/"),
                ),
                tags=array(s("string", "demo")),
                patterns=array(
                    obj(
                        identifier=s("string", "$a"),
                        count=s("integer", 2, "Matches found, capped at 1000."),
                        instances=array(
                            obj(
                                offset=s("integer", 1024),
                                length=s("integer", 11),
                                hex=s("string", "68 65 6c 6c 6f 20 77 6f 72 6c 64"),
                                ascii=s("string", "hello world"),
                                truncated=s("boolean", False, "Longer than the 32-byte preview."),
                            ),
                            "The first 5 instances.",
                        ),
                    )
                ),
            )
        ),
        left_out=array(
            obj(id=s("integer", 44), name=s("string", "broken_rule"), ruleset=s("integer", 7)),
            "Rules not used because they do not compile.",
        ),
    ),
    "ScanJob": optional(
        obj(
            id=s("string", "0b6f1c9e-5a2d-4c1b-9f3e-7d8a6b5c4e21", format="uuid"),
            batch=s(
                "string",
                None,
                "Shared by the jobs of one multi-sample submission.",
                nullable=True,
                format="uuid",
            ),
            state=s("string", "finished", enum=["queued", "running", "finished", "failed"]),
            phase=s("string", "done", enum=["queued", "loading_rules", "scanning", "done"]),
            inline=s("boolean", True, "Scanned at once, without the queue."),
            sample_name=s("string", "suspicious.bin"),
            sample_size=s("integer", 151234),
            sample_sha256=s(
                "string", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            ),
            submitted_by=s("string", "analyst", "Username, or `deleted user`."),
            options={
                "type": "object",
                "description": "Limits: `path`, `tag`, `rulesets`.",
                "example": {"path": "", "tag": "", "rulesets": []},
            },
            created_at=s("string", TIME, format="date-time"),
            started_at=s("string", TIME, nullable=True, format="date-time"),
            finished_at=s("string", TIME, nullable=True, format="date-time"),
            updated_at=s("string", TIME, format="date-time"),
            error=s("string", "", "Why the job failed."),
            match_count=s("integer", 1),
            revision=s("integer", 118, "Rules revision of the compiled set used.", nullable=True),
            rules_pending=s("boolean", False, "Rules had changed and the newer set was not ready."),
            result={
                "type": ["object", "null"],
                "description": "Set for finished jobs (reading a single job): `matches` (each "
                "with `rule_id`, `rule`, `ruleset_id`, `ruleset`, `ruleset_path`, `tags`, "
                "`patterns` with `identifier`, `count`, `instances` of `offset` and `length`), "
                "`rules_scanned`, `rulesets`, `left_out`, `unmapped`, `compiled` and "
                "`scan_seconds`.",
                "example": {
                    "matches": [
                        {
                            "rule_id": 42,
                            "rule": "hello_world",
                            "ruleset_id": 7,
                            "ruleset": "apt_example.yar",
                            "ruleset_path": "signature-base/yara/apt_example.yar",
                            "tags": ["demo"],
                            "patterns": [
                                {
                                    "identifier": "$a",
                                    "count": 1,
                                    "instances": [{"offset": 3, "length": 11}],
                                }
                            ],
                        }
                    ],
                    "rules_scanned": 10231,
                    "rulesets": 2124,
                    "left_out": [],
                    "unmapped": [],
                    "compiled": {"revision": 118, "built_at": TIME, "pending": False},
                    "scan_seconds": 0.01,
                },
            },
            url=url("/api/v1/scans/0b6f1c9e-5a2d-4c1b-9f3e-7d8a6b5c4e21/"),
        ),
        "result",
    ),
    "ScanJobList": obj(jobs=array(ref("ScanJob"), "One job per sample, in order.")),
    "ScanJobPage": page("ScanJob", "Jobs of this page (without `result`)."),
    "ScanStatus": obj(
        compiled=obj(
            available=s("boolean", True, "A compiled rule set exists."),
            revision=s("integer", 118, nullable=True),
            built_at=s("string", TIME, nullable=True, format="date-time"),
            engine=s("string", "1.23.0", "YARA-X version that built the set.", nullable=True),
            rules=s("integer", 10231, nullable=True),
            rulesets=s("integer", 2124, nullable=True),
            left_out=s("integer", 0, nullable=True),
            current_revision=s("integer", 118, "Rules revision in the database."),
            pending=s("boolean", False, "The set is older than the rules."),
            building=s("boolean", False),
        ),
        workers={
            "type": "object",
            "additionalProperties": {"type": "integer"},
            "description": "Live worker processes per role.",
            "example": {"scan": 2, "maintenance": 1, "builder": 1},
        },
        queued=s("integer", 0),
        running=s("integer", 0),
        limits=obj(
            max_bytes=s("integer", 67108864, "Largest sample."),
            max_samples=s("integer", 20, "Most samples per submission."),
            inline_max_bytes=s(
                "integer", 1048576, "A single sample up to this size is scanned at once."
            ),
        ),
    ),
    "ScanLimit": obj(
        path=s("string", "signature-base/"),
        rules=s("integer", 4210, "Active rules the scan would use."),
        rulesets=s("integer", 712),
    ),
    "Dashboard": obj(
        counts=obj(
            rules=s("integer", 10231, "Active rules."),
            failing=s("integer", 0, "Active rules that do not compile."),
            warnings=s("integer", 85, "Active rules with warnings."),
            modified=s("integer", 3, "Changed locally since the last import."),
            removed=s("integer", 12),
            rulesets=s("integer", 2124),
            tags=s("integer", 950),
        ),
        recent_imports=array(ref("ImportRunSummary"), "The six newest import runs."),
        recent_rules=array(ref("RuleSummary"), "The ten most recently updated active rules."),
    ),
    "Me": obj(
        username=s("string", "analyst"),
        name=s("string", "Ada Analyst"),
        email=s("string", "analyst@example.org"),
        is_staff=s("boolean", False),
        roles=array(s("string", "Editors"), "Viewers and/or Editors; empty means no access."),
        permissions=array(s("string", "rules.view_rule")),
        key=obj(
            prefix=s("string", "yd_3f9a0c1b7d2e", "The key's visible prefix."),
            name=s("string", "nightly sync"),
            created_at=s("string", TIME, format="date-time"),
            last_used_at=s(
                "string",
                TIME,
                "Updated at most every few minutes.",
                nullable=True,
                format="date-time",
            ),
            expires_at=s("string", None, nullable=True, format="date-time"),
        ),
    ),
    "OpenAPI": {
        "type": "object",
        "description": "An OpenAPI 3.1 document.",
        "example": {"openapi": "3.1.0", "info": {"title": "yaradude API"}},
    },
}


def example(schema: Schema) -> Any:
    """An example value built from the schema's `example`s (for the documentation)."""
    if "$ref" in schema:
        return example(COMPONENTS[schema["$ref"].rsplit("/", 1)[1]])
    if "anyOf" in schema:
        return example(schema["anyOf"][0])
    if "example" in schema:
        return schema["example"]
    if schema.get("type") == "object":
        return {
            name: example(sub)
            for name, sub in schema.get("properties", {}).items()
            if name in schema.get("required", [])
        }
    if schema.get("type") == "array":
        return [example(schema["items"])]
    return None
