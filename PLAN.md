# yaradude — implementation plan

yaradude is a Django web app for managing YARA rules: import them from disk or
by upload, store them in SQLite, track when each rule was imported and updated,
edit them with compile validation, keep version history, test-scan samples and
export rule sets. It ships as an offline (air-gapped) Docker Compose stack
behind Caddy.

This file is the single source of truth for the build. Agents implementing a
work package read it first and keep it accurate: if an implementation detail
has to deviate, update the relevant section and say so in the hand-off report.

## 1. Decisions (agreed with the product owner)

| Topic | Decision |
|---|---|
| Name | `yaradude` (directory, Python project, UI brand, image names) |
| Stack | Django, **YARA-X** (`yara-x` Python package, not classic YARA / `yara-python`), SQLite, `uv` for all package management |
| Source of truth | The SQLite database. It stores every rule's full source and the verbatim original file as last imported. The disk directory is only an import source and may disappear after import. |
| Import paths | (a) scan of a server-side rules directory (UI button + management command), (b) browser upload of `.yar` / `.yara` files |
| Granularity | One record per individual rule, grouped into a ruleset (one ruleset per source file) |
| Timestamps | Per rule: first imported, last content change. Per ruleset: created, last imported, last changed. Every import run is logged. |
| Auth | Login required for everything. Two roles via Django groups: **Viewers** (browse, search, export, test-scan) and **Editors** (also import, create, edit, restore, delete). Users are managed in the Django admin. |
| Extras in v1 | In-browser editing with compile validation, version history with diffs and restore, test scan of an uploaded sample, export (.yar / .zip) |
| Rule dropped from a newer version of its file | Kept with history, flagged `removed_at`, excluded from export and scans, restored automatically if it reappears. A file that is simply absent from disk changes nothing. |
| Local edit vs. re-import | A UI edit is preserved as long as the on-disk version of that rule has not changed since the last import. If the disk version changes, disk wins and the local edit stays in the version history. |
| Production | Docker Compose: `web` (gunicorn) + `caddy` (TLS reverse proxy). HTTPS always. |
| Air gap | The stack runs with no network access at all: no CDNs, no web fonts, no runtime downloads, no ACME. It is first built on a connected machine and delivered as `docker save` tarballs, and after that the **production images must be rebuildable from source inside the air gap** (section 8.5), where development continues. |
| Architectures | `linux/amd64` and `linux/arm64`, one offline bundle per architecture |
| Dev environment | For now development runs directly on the host with `uv` (`uv run python manage.py runserver`). The dev container (VS Code `.devcontainer` backed by `compose.dev.yaml`, live reload) comes with the containers package and must itself be movable into the air gap: its image carries every runtime and dev dependency and is exported as an offline bundle like the production images. |
| UI styling | Tailwind CSS, compiled locally with the standalone CLI and served as a static file; the production image builds it at image-build time and the offline dev image carries the CLI so the watcher works without network |
| Quality bar | Django best practices throughout (section 9) |

## 2. Verified technical facts

Checked on this machine on 2026-11-19; do not re-derive, but do re-check APIs
against the installed versions rather than from memory.

- The YARA engine is **YARA-X** (PyPI `yara-x`, module `yara_x`, version
  1.23.0). Its Python API is not compatible with `yara-python`, which must
  not be a dependency.
- Python is pinned to **3.13** (`requires-python = ">=3.13,<3.14"`,
  `.python-version`) for reproducible images. `yara-x` ships `abi3` wheels
  (Python 3.9+) for `manylinux_2_28` x86_64 and aarch64 and for macOS arm64,
  so no compiler is needed in any image as long as the base image has glibc
  2.28 or newer (Debian bookworm slim), not Alpine.
- Installed: Django 6.1.3, yara-x 1.23.0, Pygments 2.21, gunicorn 27,
  whitenoise 6.12, ruff (dev group). Django 6.x ships
  `LoginRequiredMiddleware` and a built-in CSP middleware
  (`django.middleware.csp.ContentSecurityPolicyMiddleware`, helpers in
  `django.utils.csp`).
- YARA lexical facts that the rule splitter relies on (the same in YARA-X;
  `\` division and escaped-slash regexes were re-checked against `yara_x`):
  - `/` always starts a regular expression unless it begins `//` or `/*`.
    Integer division in YARA is `\`, never `/`.
  - A regex literal is `/(\\.|[^/\\\n])+/` followed by optional `i`/`s`
    flags; an unescaped `/` always terminates it, even inside `[...]`.
  - A text string is `"(\\.|[^"\\\n])*"`.
  - Hex strings `{ 41 ?? [2-4] ( 42 | 43 ) }` contain balanced braces and may
    contain comments, but never quotes or regexes.
- `yara_x` behaviour (probed on 1.23.0; the published API reference at
  https://virustotal.github.io/yara-x/docs/api/python/ omits some of it):
  - `yara_x.Compiler(relaxed_re_syntax=False, error_on_slow_pattern=False,
    includes_enabled=True, ignore_invalid_rules=False)` with
    `new_namespace(name)`, `define_global(ident, value)` (must precede the
    source that uses it), `add_source(src, origin=None)`,
    `enable_includes(bool)`, `ignore_module(name)`, `ignored_rules()`,
    `errors()`, `warnings()` and `build()` → `Rules`.
  - **Includes are enabled by default and read files from the server's
    disk.** Every compiler yaradude creates must disable them; an `include`
    then fails with error `E044` (`E043`, "include file not found", is what
    an enabled compiler reports for a missing file).
  - `add_source` raises `yara_x.CompileError` on the first error in that
    source; `str(e)` is a multi-line diagnostic. `compiler.errors()` and
    `compiler.warnings()` return dicts with `type`, `code`, `title`, `line`,
    `column`, `labels` (each with `level`, `code_origin`, `line`, `column`,
    `span`, `text`) and `text` (the full diagnostic). Line numbers are
    relative to the source passed to that `add_source` call.
  - A failed `add_source` does not poison the compiler: sources added before
    and after it still build and scan. It drops only the failing rules: other
    rules in the same source (before or after the error) are still added, so
    `add_source` failing does not mean nothing from that text compiled.
    yaradude adds one rule per `add_source` call, so a failure drops exactly
    that rule.
  - Iterating `Rules` yields every rule with `identifier`, `namespace`,
    `tags` (tuple) and `metadata` (tuple of `(key, value)` pairs);
    `rules.imports()` lists the imported modules.
  - Scanning: `yara_x.Scanner(rules)` with `set_timeout(seconds)`,
    `set_global(ident, value)`, `max_matches_per_pattern(n)` and
    `scan(bytes)` → `ScanResults.matching_rules`. Each rule has `patterns`
    (matching or not); each pattern has `identifier` and `matches` with
    `offset`, `length` and `xor_key`. Matched bytes are not returned; slice
    them from the sample. Private rules are not reported. Scans raise
    `yara_x.ScanError` and `yara_x.TimeoutError`.
  - An undefined global such as `filename` is error `E009` (unknown
    identifier) until it is declared with `define_global`.
  - Modules: `yara_x.module_names()` lists what the wheel provides. `cuckoo`
    compiles; `magic` is not available (`E010`, unknown module, on the import line when the
    module is imported but unused; `E009` at the first use otherwise).
  - A constant condition such as `condition: true` produces an
    `invariant_expr` warning.
  - YARA-X is stricter than classic YARA: an unused pattern (`E022`),
    duplicate rule modifiers, negative array indexes, base64 patterns shorter
    than 3 characters and rule-name wildcards in `of` are errors; so are
    invalid regex escapes and an unescaped `{` in a regex unless
    `relaxed_re_syntax=True`. Rule sets written for classic YARA can
    therefore import as "does not compile"; that is reported per rule, never
    hidden.
  - Rules added by separate `add_source` calls in one namespace can
    reference rules added earlier (a forward reference is `E009`); rules in
    other namespaces cannot be referenced. A rule that references a rule
    whose `add_source` failed gets `E009 unknown identifier`.
  - An `import` in one `add_source` call stays in effect for later calls in
    the same namespace, but not in other namespaces. yaradude therefore
    checks itself that every module a rule uses is in that rule's own
    imports.
  - `code_origin` in the error labels, and the `--> origin:line:col` line of
    `text`, carry the `origin` argument of `add_source`. Warnings (for
    example `slow_pattern`, `invariant_expr`) have the same shape as errors,
    with string codes. `compiler.errors()` / `.warnings()` accumulate over
    all `add_source` calls.
  - `Rules` iterates in declaration order. Metadata strings containing
    escape sequences come back as `bytes`, otherwise as `str`.
  - `Scanner.set_timeout(1)` on a quadratic condition raises
    `yara_x.TimeoutError("timeout")` after about one second.
    `yara_x.TimeoutError`, `ScanError` and `CompileError` all derive
    directly from `Exception`.

## 3. Repository layout

```
yaradude/
  PLAN.md  README.md  pyproject.toml  uv.lock  .python-version
  manage.py
  config/            settings.py, urls.py, wsgi.py, asgi.py
  accounts/          custom User model, admin, role bootstrap
  rules/
    models.py  admin.py  apps.py  forms.py  urls.py  views.py (or views/)
    services/        parser.py, compiler.py, editing.py, importer.py,
                     scanner.py, exporter.py, highlight.py, diffing.py
    management/commands/   import_rules.py, ensure_superuser.py
    templatetags/  templates/  static/rules/  migrations/  tests/
  yara-rules/examples/     a few benign example rule files for development
  Dockerfile               multi-stage: dev and prod targets
  docker/                  entrypoint.sh, caddy/Dockerfile, caddy/Caddyfile
  compose.yaml             production: web + caddy
  compose.dev.yaml         development
  .devcontainer/devcontainer.json
  scripts/build-airgap-bundle.sh
  .env.example  .dockerignore  .gitignore
```

## 4. Data model

`accounts.User(AbstractUser)` — custom user model from the first migration
(`AUTH_USER_MODEL = "accounts.User"`).

`rules.Ruleset` — one per source file, or a named manual collection.
- `name` (display), `origin` (`directory` / `upload` / `manual`), `path`
  (identity: POSIX path relative to the rules directory; absolute path when
  imported by CLI from elsewhere; upload filename; manual name)
- `original_content` (verbatim file text as last imported), `sha256` of it
- `compile_error` (short summary; blank means every active rule compiles)
- `created_at`, `updated_at` (content last changed), `last_imported_at`
- Unique on (`origin`, `path`).

`rules.Tag` — `name`, unique. Many-to-many with `Rule`.

`rules.Rule`
- `ruleset` FK, `name` (YARA identifier), `position` (order in ruleset)
- `source` (the rule text, including an attached leading comment),
  `imports` (JSON list of module names), `meta` (JSON list of `[key, value]`
  pairs, order and duplicates preserved), `description`, `author`
  (denormalised from meta for listing and search), `is_private`, `is_global`
- `sha256` (current content: imports + source), `imported_sha256` (content as
  last imported from disk; blank for manual rules). The two differing means
  "modified locally".
- `version` (current version number), `compile_error` (this rule's own
  YARA-X diagnostic; blank when it compiles), `compile_warnings` (JSON list
  of YARA-X warning texts), `removed_at` (nullable)
- `created_at` (first imported/created), `updated_at` (last content change)
- Unique on (`ruleset`, `name`); indexes on `name` and `updated_at`.
- A queryset method `active()` filters out removed rules.

`rules.RuleVersion` — immutable snapshot per content change.
- `rule` FK, `number`, `source`, `imports`, `sha256`, `origin`
  (`import` / `upload` / `create` / `edit` / `restore`), `created_at`,
  `created_by` (nullable FK to user), `import_run` (nullable FK)
- Unique on (`rule`, `number`).

`rules.ImportRun` — `origin` (`scan` / `upload` / `cli`), `source`
(description of what was imported), `user`, `started_at`, `finished_at`, and
counters: files seen / changed / unchanged / failed, rules created / updated /
removed / unchanged.

`rules.ImportFile` — per-file result of a run, stored only for files that
changed or failed: `run`, `path`, `status` (`created` / `updated` / `failed`),
`ruleset` (nullable), per-file rule counters, `message`.

Custom permissions on `Rule`: `import_rules`, `scan_rules`.

## 5. Services (business logic lives here, not in views)

### 5.1 `parser.py` — split YARA text into rules
Own tokenizer; no third-party parser. Regex-driven scan producing tokens:
whitespace, comment (`//…`, `/*…*/`), string, regex, word
(`[A-Za-z_]\w*` and `$ # @ !` identifiers), number, punctuation.

Top-level grammar: `import "mod"`, `include "file"`, and
`[global] [private] rule NAME [: tag…] { … }` where the closing brace is found
by depth counting over tokens (strings, regexes and comments are opaque).

Per rule it returns: name, tags, `is_private`, `is_global`, source slice
(first modifier through closing brace), meta pairs (parsed from the `meta:`
section: string with escapes, integer, negative integer, `true`/`false`),
and the rule's imports: those of the file's imports that the rule references
(`mod.` in its source), so each rule's stored text compiles on its own and
adding an unused import to a file does not change every rule. A run of
comments directly above a rule, each starting its own line, with no blank
line in between, is attached to that rule's source. `include` statements are
recorded and reported as unsupported (includes are disabled when compiling).

Errors (unterminated string/regex/rule, unexpected top-level token, duplicate
identifier) raise a `RuleParseError` carrying a line number.

Safety net: when the whole file compiles with YARA-X, the identifiers found
by the splitter must equal the identifiers of the compiled `Rules` in order;
otherwise the file is reported as failed rather than imported wrongly.

### 5.2 `compiler.py`
All engine access goes through this module and `scanner.py`; nothing else
imports `yara_x`.
- `new_compiler()` → a `yara_x.Compiler` with includes disabled, the
  configured regex strictness (`YARADUDE_RELAXED_RE_SYNTAX`), and the default
  globals defined (`filename`, `filepath`, `extension`, `filetype`, `owner`,
  all empty strings; the `YARADUDE_GLOBALS` setting, not an environment
  variable) so widely used public rule sets compile.
- `check_ruleset(ruleset)` → compiles the ruleset's active rules in position
  order inside one namespace and attributes diagnostics per rule: every rule
  that fails gets its own `Rule.compile_error` with a line number relative to
  that rule's source, every rule gets its `compile_warnings`, and rules that
  compile are cleared. `Ruleset.compile_error` is a short summary. A rule
  that depends on a failing rule fails too and says so. Each rule is added
  as its own `add_source` (its imports, a blank line, the rule), so line
  numbers are relative to `Rule.text`. Because an import stays in effect for
  later sources of the namespace, a rule that uses a module missing from its
  own imports is reported as failing ("module … is used but not imported")
  without being added.
- `build_source(ruleset)` → one text for export: de-duplicated imports, then
  active rules by position.
- `validate_edit(ruleset, rule_or_none, parsed_rule)` → the result of
  compiling a proposed edit in the context of its sibling rules: the edited
  rule's own error and warnings, and any sibling rules the edit would break.

### 5.3 `importer.py`
- `import_directory(root, user=None, origin=...)` walks `*.yar` / `*.yara`
  (skipping hidden files and oversized files), `import_uploads(files, user)`
  handles uploads; both return an `ImportRun`.
- Per file, inside its own transaction:
  1. Decode (UTF-8, fall back to Latin-1), hash. Same hash as the stored
     ruleset → count as unchanged, touch `last_imported_at`, stop.
  2. Parse. Failure → `ImportFile(status=failed)` with the message; nothing
     else changes.
  3. For each parsed rule: new → create with version 1; hash equals
     `imported_sha256` → unchanged (local edits survive); otherwise update,
     bump version, record a `RuleVersion`. A previously removed rule that
     reappears is restored.
  4. Rules of the ruleset missing from the file → set `removed_at`.
  5. Store `original_content`, hashes, timestamps; sync tags; run
     `check_ruleset`.
- Management command `import_rules [path]` (defaults to the configured rules
  directory) prints the run summary and exits non-zero if any file failed.

### 5.4 `scanner.py`
Compiles the active rules of all (or selected) rulesets, one YARA-X namespace
per ruleset, leaving out rules that do not compile, and matches an uploaded
sample **in memory** with a `yara_x.Scanner`. The
sample is never written to the database or kept on disk. Enforces a size
limit and a timeout. Returns matched rules (linked back to `Rule` records),
tags, and for each matched string up to a handful of instances with offset
and a hex/ASCII preview sliced from the sample. Rules left out because they
do not compile are listed in the result.

### 5.5 `exporter.py`
- Single rule → `.yar`; ruleset → `.yar` (rebuilt from current rules) and the
  verbatim original file.
- Selection or current filter → combined `.yar` (imports de-duplicated at the
  top, a section comment per ruleset, a header comment warning about
  duplicate identifiers if any) or `.zip` with one `.yar` per ruleset.

### 5.6 `highlight.py`, `diffing.py`
Server-side YARA syntax highlighting with Pygments (`YaraLexer`), and
unified diffs between versions with `difflib`. No client-side libraries.

### 5.7 Service API (contract for views)

Views call only these functions (plus ordinary ORM queries on the models in
`rules/models.py`). All modules live in `rules/services/`. Every write is
transactional and leaves the ruleset compile-checked. Dataclasses are frozen
and safe to pass straight to templates. Everything is type-annotated
(section 9.1); `user` parameters are `accounts.models.User | None`, so narrow
`request.user` before passing it.

**Models: what views and templates use** (fields as in section 4)
- `Ruleset`: `Origin` choices (`DIRECTORY`, `UPLOAD`, `MANUAL`),
  `get_origin_display()`, `get_absolute_url()` → `rules:ruleset_detail`,
  related `rules` (all, including removed) and `import_files`.
- `Rule.objects` / `Rule` querysets: `.active()`, `.removed()`,
  `.failing()` (non-blank `compile_error`), `.modified()` (changed locally).
  `Tag.objects.unused()` (tags no rule uses; the services delete them).
  Instance: `text` (imports + blank line + source: editor and download
  text), `is_modified`, `is_removed`, `compiles`, `compile_warnings` (list of
  diagnostic texts), `tags` (M2M to `Tag`), `versions` (newest first),
  `get_absolute_url()` → `rules:rule_detail`. `meta` is a list of
  `[key, value]` pairs; values are `str`, `int` or `bool`.
- `RuleVersion`: `Origin` choices (`IMPORT`, `UPLOAD`, `CREATE`, `EDIT`,
  `RESTORE`), `text`, `get_absolute_url()` → `rules:rule_version`.
- `ImportRun`: `Origin` choices (`SCAN`, `UPLOAD`, `CLI`), counters,
  `summary` (one-line text), `files` (only changed/failed files),
  `get_absolute_url()` → `rules:import_run`.
- `ImportFile`: `Status` choices (`CREATED`, `UPDATED`, `FAILED`), `path`,
  `ruleset`, per-file counters, `message`.
- Compile diagnostics (`Rule.compile_error`, warnings, `EditResult.error`)
  are multi-line YARA-X texts with a caret line: render them in `<pre>`.

**`parser.py`**
- `parse(text: str) -> ParsedFile` — raises `RuleParseError`.
- `parse_rule_text(text: str) -> ParsedRule` — editor text: import lines +
  exactly one rule; raises `RuleParseError`.
- `RuleParseError(Exception)`: `.message: str`, `.line: int`; `str()` is
  `"line N: message"`.
- `ParsedFile`: `imports: list[str]`, `includes: list[str]`,
  `rules: list[ParsedRule]`.
- `ParsedRule`: `name`, `tags: list[str]`, `is_private`, `is_global`,
  `source`, `meta: list[tuple[str, str | int | bool]]`, `imports: list[str]`
  (modules of the file's imports this rule references), `import_lines`,
  `line` (line of the `rule` keyword or first modifier), `source_line`;
  properties `description`, `author`, `text`, `sha256`;
  `meta_value(key) -> str`; `parsed_line(text_line) -> int | None`.

**`compiler.py`** (only this module and `scanner.py` import `yara_x`)
- `new_compiler() -> yara_x.Compiler` — includes disabled, configured regex
  strictness, default globals.
- `check_ruleset(ruleset: Ruleset) -> RulesetCheck` — stores per-rule
  `compile_error` / `compile_warnings` and `Ruleset.compile_error`.
- `RulesetCheck`: `ruleset`, `diagnostics: dict[Rule, RuleDiagnostics]`;
  properties `failing: list[Rule]`, `ok: bool`, `summary: str`.
- `RuleDiagnostics`: `name`, `error: str`, `line: int | None` (relative to
  `Rule.text`), `warnings: list[str]`; property `ok`.
- `validate_edit(ruleset, rule: Rule | None, parsed: ParsedRule) ->
  EditValidation` — no writes; views normally use `editing` instead.
- `EditValidation`: `error: str`, `line: int | None` (in the editor text),
  `warnings: list[str]`, `broken: list[BrokenRule]`; property `ok`.
- `BrokenRule`: `rule: Rule`, `error: str`.
- `build_source(ruleset) -> str`, `combine_rules(rules: list[Rule]) -> str`,
  `compiled_identifiers(text) -> list[str] | None`.

**`editing.py`** — the editor flow (new module, not in the original plan)
- `validate_rule_text(ruleset, text, rule=None) -> EditResult` — "Validate"
  button; no writes.
- `create_rule(ruleset, text, user=None) -> EditResult` — appends a new rule
  (version 1, origin `create`) when valid.
- `update_rule(rule, text, user=None) -> EditResult` — new version (origin
  `edit`) when valid; identical text saves nothing.
- `restore_version(version: RuleVersion, user=None) -> EditResult` — the old
  text becomes a new version (origin `restore`), with the same checks as an
  edit.
- `delete_rule(rule) -> None` — hard delete with its history, then re-check.
- `delete_ruleset(ruleset) -> None` — deletes the ruleset with its rules and
  their versions and removes unused tags; import runs and their `ImportFile`
  rows survive with `ruleset` set to null.
- `manual_ruleset(name) -> Ruleset` — get or create a manual ruleset.
- `EditResult`: `error: str`, `line: int | None` (line in the submitted
  text), `warnings: list[str]`, `broken: list[BrokenRule]` (siblings this
  change breaks; saving is still allowed), `parsed: ParsedRule | None`,
  `rule: Rule | None` (set when saved); property `ok`. A save is refused,
  with `error` set and `rule` None, when the text does not parse, the name
  is taken by another rule of the ruleset (removed rules included), or the
  rule itself does not compile.

**`importer.py`**
- `import_directory(root: Path | str, user=None, origin=ImportRun.Origin.SCAN)
  -> ImportRun` — the UI passes `settings.YARADUDE_RULES_DIR`, never a path
  from the request.
- `import_uploads(files: Iterable[File], user=None) -> ImportRun` — e.g.
  `request.FILES.getlist("files")`.
- `decode(content: bytes) -> str`; constants `RULE_SUFFIXES`,
  `MAX_FILE_BYTES` (10 MiB per rule file).

**`scanner.py`**
- `scan_sample(sample: File, rulesets: Iterable[Ruleset] | None = None) ->
  ScanResult` — raises `ScanError` (message suitable for the user) when the
  sample exceeds `YARADUDE_SCAN_MAX_BYTES`, the scan times out or YARA-X
  fails.
- `ScanResult`: `sample_name`, `sample_size`, `sample_sha256`,
  `matches: list[RuleMatch]`, `rulesets: list[Ruleset]`, `rules_scanned`,
  `left_out: list[Rule]` (not compiling, not used), `elapsed: float`.
- `RuleMatch`: `rule: Rule` (with `ruleset` loaded), `tags: list[str]`,
  `patterns: list[PatternMatch]`; property `ruleset`.
- `PatternMatch`: `identifier`, `count` (capped at 1000),
  `instances: list[PatternInstance]` (first 5).
- `PatternInstance`: `offset`, `length`, `hex` (`"4d 5a 90"`), `ascii`
  (non-printables as `.`), `truncated` (match longer than the 32-byte
  preview).
- Uploads are memory-only (`FILE_UPLOAD_HANDLERS`); a request body larger
  than `FILE_UPLOAD_MAX_MEMORY_SIZE` (scan limit + 1 MiB) arrives without
  its files, so the form should report "file missing or too large".

**`exporter.py`**
- `export_rule(rule) -> ExportFile`, `export_ruleset(ruleset) -> ExportFile`
  (rebuilt), `export_ruleset_original(ruleset) -> ExportFile`,
  `export_combined(rules: Iterable[Rule]) -> ExportFile` (`.yar`),
  `export_zip(rules: Iterable[Rule]) -> ExportFile` — removed rules are
  skipped; pass querysets with `select_related("ruleset")`.
- `ExportFile`: `filename`, `content: bytes`, `content_type`. Serve with
  `HttpResponse(f.content, content_type=f.content_type,
  headers={"Content-Disposition": content_disposition_header(True, f.filename)})`.
- `ruleset_filename(ruleset, keep_directories=False) -> str`.

**`highlight.py`**
- `highlight_yara(source: str, linenos: bool = False) -> SafeString` —
  `<div class="highlight"><pre><code>` with Pygments token classes and no
  inline styles; generate the CSS once with
  `pygmentize -S default -f html -a .highlight`.

**`diffing.py`**
- `diff_texts(old: str, new: str, context: int = 3) -> Diff`,
  `diff_versions(old: RuleVersion | None, new: RuleVersion, context=3) ->
  Diff`, `previous_version(version) -> RuleVersion | None`.
- `Diff`: `lines: list[DiffLine]`, `added`, `removed`; property `changed`.
- `DiffLine`: `kind` (`"hunk"`, `"context"`, `"added"`, `"removed"`),
  `text`, `old_number: int | None`, `new_number: int | None`.

## 6. Roles and permissions

- `LoginRequiredMiddleware` protects every view; only login, logout and
  `/healthz/` are exempt.
- Groups are created idempotently in a `post_migrate` handler:
  - **Viewers**: all `view_*` permissions of the `rules` app + `scan_rules`.
  - **Editors**: Viewers + add/change/delete on `Rule` and `Ruleset` +
    `import_rules`.
- Every view declares the permission it needs (`PermissionRequiredMixin` /
  `permission_required(..., raise_exception=True)`). Templates hide actions
  the user cannot perform, but the server check is what counts.
- A user in no group sees a clear 403 page telling them to ask an
  administrator for access.
- `ensure_superuser` creates the first admin from
  `DJANGO_SUPERUSER_USERNAME` / `_PASSWORD` / `_EMAIL` if that user does not
  exist; it never changes an existing account.

## 7. Web UI

Server-rendered Django templates styled with **Tailwind CSS**, plus a small
amount of vanilla JavaScript as progressive enhancement. Tailwind is compiled
to a static CSS file with Tailwind's standalone CLI (no Node toolchain, never
the CDN script); the design tokens live in the Tailwind theme. The exact
build and watch commands, the pinned CLI binary and the input/output paths
are recorded here by the UI package once wired, because the image builds
depend on them. Hard constraints: no external
requests of any kind (air gap), no inline `<script>`, inline event handlers
or `style=""` attributes (strict CSP `default-src 'self'`), system font
stack, light and dark themes via `prefers-color-scheme`, usable at laptop and
phone widths, accessible (labels, focus states, sufficient contrast).

Design direction: calm, dense-but-readable tool for analysts. Persistent
navigation, monospace for identifiers and code, clear status badges
(compiles / error / modified locally / removed), timestamps shown as
absolute local time with relative time as a secondary hint.

| Page | URL | Notes |
|---|---|---|
| Sign in / out | `/accounts/login/`, `/accounts/logout/` | Django auth views, styled |
| Dashboard | `/` | counts (rules, rulesets, tags, compile errors, locally modified), recent import runs, recently updated rules |
| Rules | `/rules/` | search (name, description, author, source), filters (ruleset, tag, status), sort, pagination, row selection, export of selection or of the current filter |
| Rule detail | `/rules/<id>/` | highlighted source, meta, tags, imports, ruleset, imported/updated timestamps, compile status, version list; actions: edit, download, delete |
| New / edit rule | `/rules/new/`, `/rules/<id>/edit/` | editor holds `import` lines + one rule; "Validate" and "Save"; save is refused if the compile error belongs to this rule |
| Version | `/rules/<id>/versions/<n>/` | that version's source, diff against the previous version, "Restore this version" |
| Rulesets | `/rulesets/`, `/rulesets/<id>/` | origin, path, timestamps, compile status, rules; download rebuilt or original file; delete |
| Import | `/import/` | scan the configured rules directory; upload files (multi-file, drag and drop); history of runs |
| Import run | `/import/runs/<id>/` | counters and per-file results |
| Test scan | `/scan/` | upload a sample, optionally limit to rulesets; results with matched rules and string instances |
| Admin | `/admin/` | users, groups, raw data |
| Health | `/healthz/` | unauthenticated, checks the database |

## 8. Configuration, containers and air-gapped delivery

### 8.1 Settings (single `config/settings.py`, everything from environment)

| Variable | Default | Purpose |
|---|---|---|
| `DJANGO_DEBUG` | `false` | debug mode |
| `DJANGO_SECRET_KEY` | none | required when debug is off |
| `DJANGO_ALLOWED_HOSTS` | localhost names in debug | comma-separated |
| `DJANGO_CSRF_TRUSTED_ORIGINS` | empty | comma-separated origins |
| `DJANGO_HTTPS` | `true` when debug is off | secure cookies, HSTS, trust `X-Forwarded-Proto` from the proxy |
| `DJANGO_TIME_ZONE` | `UTC` | display time zone |
| `YARADUDE_DB_PATH` | `<repo>/db.sqlite3` | SQLite file (`/data/db.sqlite3` in containers) |
| `YARADUDE_RULES_DIR` | `<repo>/yara-rules` | directory the UI scan imports from (`/rules` in containers) |
| `YARADUDE_SCAN_MAX_BYTES` | 64 MiB | sample size limit |
| `YARADUDE_SCAN_TIMEOUT` | 60 | seconds |
| `YARADUDE_RELAXED_RE_SYNTAX` | `false` | accept classic-YARA regex escapes that YARA-X rejects by default |
| `DJANGO_SUPERUSER_USERNAME` / `_PASSWORD` / `_EMAIL` | unset | first-admin bootstrap |
| `YARADUDE_SITE_ADDRESS` | `localhost` | Caddy site address |
| `YARADUDE_TLS` | `internal` | Caddy `tls` directive arguments: `internal` (Caddy's own CA) or `/certs/cert.pem /certs/key.pem` |

SQLite is configured for a web workload: WAL journal, `IMMEDIATE`
transactions, a busy timeout. Static files are served by WhiteNoise with
hashed, compressed files. Logging goes to stdout.

Implementation notes:
- Without debug there is no fallback secret key; Django raises
  `ImproperlyConfigured` when the key is first used (sessions, CSRF), so
  `collectstatic` and `makemigrations` run without one. Under
  `manage.py test` the debug-mode defaults apply to the secret key,
  `DJANGO_HTTPS` and static storage, so tests need no environment.
- With HTTPS on, `/healthz/` is exempt from the HTTPS redirect so the
  container health check can call gunicorn directly; it still has to send a
  `Host` header listed in `DJANGO_ALLOWED_HOSTS`. HSTS is one year with
  subdomains; the preload check (`security.W021`) is silenced because
  preloading does not apply to an air-gapped host.
- Uploads are handled in memory only (`MemoryFileUploadHandler`, limit
  `YARADUDE_SCAN_MAX_BYTES` + 1 MiB), so samples never reach a temporary
  file.
- CSP: `default-src 'self'`, `style-src 'self'` plus nonce (for the one
  inline `<style>` the Django admin emits on change lists without actions),
  `object-src 'none'`, `base-uri 'none'`, `form-action 'self'`,
  `frame-ancestors 'none'`.

### 8.2 Images
- `Dockerfile` (base `python:3.13-slim-bookworm`, `uv` copied from the
  official uv image at a pinned version, virtualenv outside the source tree
  so a bind mount cannot hide it):
  - `dev` target: all dependency groups, source bind-mounted, `runserver`.
    The pinned Tailwind CLI binary for the image's architecture is baked in
    at build time (checksum-verified where the release publishes one) and
    automatic download is disabled, so the Tailwind watcher and build work
    inside the air gap. Acceptance: `tailwind build`, the test suite and
    `runserver` all succeed in the dev image started with `--network none`.
  - No image and no code path may fetch the Tailwind binary on its own:
    download is opt-in, off by default, and only ever used on a connected
    machine. The production runtime image contains only the compiled CSS,
    not the CLI.
  - `prod` target: built from a builder stage with `uv sync --frozen
    --no-dev`; final image contains only the virtualenv and the app, runs as
    a non-root user, has no `uv` or build tools, collects static files at
    build time, has a `HEALTHCHECK`, and starts through an entrypoint that
    runs `migrate`, `ensure_superuser`, then `exec gunicorn`.
- `docker/caddy/Dockerfile`: official Caddy image with the `Caddyfile` baked
  in, so the air-gapped host needs no extra config files. Admin API off, no
  ACME; TLS from Caddy's internal CA by default or from mounted certificate
  files; reverse proxy to `web:8000`; compression and security headers.

### 8.3 Compose
- `compose.yaml` (production): services `web` and `caddy`; named volumes for
  the SQLite data and Caddy's state; the rules directory mounted read-only;
  only Caddy publishes ports (80 and 443); configuration from `.env`;
  restart policies and health-based start ordering; images referenced by tag
  with `pull_policy: never` so nothing is fetched on the air-gapped host.
- `compose.dev.yaml` + `.devcontainer/devcontainer.json`: one `web` service
  on the `dev` target with the repository bind-mounted and port 8000
  forwarded.

### 8.4 Offline bundle
`scripts/build-airgap-bundle.sh` (run on a connected machine) builds both
images for `linux/amd64` and `linux/arm64` and writes, per architecture,
`dist/yaradude-<version>-linux-<arch>.tar.gz` containing the `docker save`
image archive, `compose.yaml`, `.env.example` and a short install note
(`docker load`, edit `.env`, `docker compose up -d`). Care is needed that the
two architectures do not overwrite each other under one local tag.

The same script also exports the **dev image** per architecture
(`dist/yaradude-dev-<version>-linux-<arch>.tar.gz` with `compose.dev.yaml`
and `.devcontainer/`), so development can continue inside the air gap: the
image holds the complete virtualenv including the dev group, `uv` runs in
offline mode there, and tests, ruff and `runserver` work with no network.
Two limits to document rather than hide: new dependencies cannot be added
offline (rebuild the dev image on a connected machine), and VS Code's Dev
Containers extension normally downloads its server component into the
container on first attach, which needs a documented offline procedure or a
plain `docker compose -f compose.dev.yaml` workflow as the fallback.

Acceptance for the air gap: the loaded stack starts and serves the login page
over HTTPS on a Docker network with no outbound connectivity, and the browser
makes no request to any other origin.

### 8.5 Building the production images inside the air gap
After code changes made on the air-gapped side, `docker compose build` (or an
equivalent documented script) must produce new production images there with
no registry, PyPI, apt, GitHub or other network access. That shapes the
Dockerfiles:

- Every `FROM` refers to an image that the offline bundle has already loaded
  into the local Docker image store, pinned by exact tag (and digest where
  practical): the Python runtime base, the Caddy base, and a yaradude **build
  image**. No build step pulls.
- The build image (the dev image, or a sibling stage of it) carries everything
  a build needs: `uv`, a wheel cache holding every package in `uv.lock` for
  that architecture (runtime and dev groups), and the pinned Tailwind CLI.
  The production build runs `uv sync --frozen --no-dev` in offline mode
  against that cache, compiles the CSS with the baked-in CLI and runs
  `collectstatic`, then copies the result into the runtime base.
- No `apt-get`, `curl`, `pip`, or `uv` network access in any build step that
  runs in the air gap. Anything that needs the network (OS packages, wheels,
  the Tailwind binary, base images) is done once on the connected machine
  when the base and build images are made.
- Limit to document clearly: source changes can be built offline; a change to
  `uv.lock`, the Python or Caddy base, or the Tailwind version needs a new
  build image and bundle from a connected machine.

Acceptance: on a machine where the bundle has been loaded, the production
images rebuild with network access to the build disabled (`docker build
--network=none`, and base-image resolution shown not to contact a registry),
the rebuilt stack passes the same smoke test as the delivered one, and the
procedure is written down in the README.

## 9. Django best practices checklist

- Custom user model from the start; apps with a single responsibility.
- Settings from the environment; no secrets in the repository;
  `manage.py check --deploy` clean under production settings.
- Thin views, logic in services and models; constraints and indexes declared
  on models; `__str__`, `get_absolute_url`, `Meta.ordering` where sensible.
- Migrations committed; no data-dependent logic in migrations (roles are
  created in `post_migrate`).
- Queries: `select_related` / `prefetch_related` on list pages, pagination,
  no N+1; multi-step writes in `transaction.atomic`.
- Security: CSRF everywhere, POST for every state change, permission checks
  on every view, CSP, secure cookies, HSTS, `X-Content-Type-Options`,
  clickjacking protection, password validators, upload size limits, and no
  user-supplied filesystem paths in the web UI.
- Time-zone-aware datetimes (`USE_TZ`), all stored in UTC.
- User feedback through the messages framework; forms validate input.
- Admin registered for every model with useful list displays and filters.
- Tests with Django's test runner; `ruff check` and `ruff format` clean.
- Type hints throughout the application code, checked with **ty**
  (`uv run ty check`); no blanket ignores, every suppression carries a reason.

### 9.1 Static typing (ty)

- **Tool and config.** `ty` (Astral) is pinned exactly in the dev group
  (`ty==0.0.107`, because diagnostics change between 0.0.x releases) and
  configured under `[tool.ty]` in `pyproject.toml`: Python 3.13, migrations
  excluded, and these rules raised to `error` on top of the defaults:
  `blanket-ignore-comment`, `unused-ignore-comment`,
  `unused-type-ignore-comment`, `ignore-comment-unknown-rule`,
  `possibly-unresolved-reference`, `possibly-missing-attribute`. Warnings
  already fail the run (`error-on-warning` defaults to true). No rule is
  disabled. `missing-type-argument` stays off because `ModelAdmin` and
  `TabularInline` are generic in the stubs but not subscriptable at runtime.
- **Suppressions** are per line, name the rule, and give the reason on the
  same line (`# ty: ignore[rule]  # reason`). They are only for stub or
  checker gaps; `unused-ignore-comment` flags each one once the stubs catch
  up. `assert x is not None` is used only for real invariants, with a
  comment saying why it holds.
- **Django: `django-types` (dev group), not `django-stubs`, not untyped.**
  Tried all three with ty 0.0.107:
  - Untyped Django (ty reads Django's source): model fields read as `Field`
    objects (`rule.name` is a `CharField`), managers are missing; ~170 false
    positives. Unusable.
  - `django-stubs` 6.1.2 (matches Django 6.1) without its mypy plugin:
    field types, `objects` and querysets are all `Unknown`, because the
    stubs rely on the plugin to fill them in. Almost no signal.
  - `django-types` 0.24.0 (plugin-free fork written for pyright): fields
    have real types (`str`, `datetime | None`, `int`), `ForeignKey` returns
    the related model (`Ruleset`, or `User | None` when nullable),
    `<fk>_id` is `int`, `.first()` is `Model | None`, `get_FOO_display()`
    is `str`, `TextChoices` members are typed. Real findings on day one
    (unhandled `None`, missing reverse relations). Chosen.
  - Its cost: it lags behind Django 6.1. Known gaps hit so far:
    `django.utils.csp`, `login_not_required`,
    `django.utils.http.content_disposition_header`, `timesince(depth=)`,
    `assertFormError` without `form`, `choices=` given a `TextChoices`
    class, and `create_superuser` requiring `email`. Prefer an equivalent
    spelling where one exists (`choices=Origin.choices`,
    `create_superuser(..., email="")`), else a reasoned suppression.
- **Django's dynamic surface, how it is typed:**
  - Custom querysets are `models.QuerySet["Model"]` with methods returning
    `Self`. `QuerySet.as_manager()` builds its class at runtime, so
    `rules/models.py` declares `TagManager`, `RuleManager` and
    `RuleRelatedManager` inside `if TYPE_CHECKING:` (manager base +
    queryset class) and assigns
    `objects: ClassVar[RuleManager] = cast("RuleManager", RuleQuerySet.as_manager())`.
    Runtime behaviour is unchanged; `Rule.objects.active().failing()` and
    `ruleset.rules.active()` type-check.
  - Reverse relations are declared as annotations without a value on the
    target model (`Ruleset.rules`, `Ruleset.import_files`, `Rule.versions`,
    `Tag.rules`, `ImportRun.files`, `ImportRun.versions`,
    `User.import_runs`), using `RelatedManager` /
    `ManyToManyRelatedManager` imported under `TYPE_CHECKING`. Model
    modules use `from __future__ import annotations`.
  - `JSONField`s carry their content type explicitly
    (`imports: models.JSONField[list[str]]`), and `ForeignKey`s to
    `AUTH_USER_MODEL` are annotated `models.ForeignKey[User | None]`,
    because the stubs cannot resolve a model given as a string.
  - `request.user` is `AbstractUser | AnonymousUser` in the stubs. Services
    take `user: accounts.models.User | None`, which is what they need (an
    anonymous user would fail the foreign key). Views narrow first, e.g.
    `user = request.user; assert isinstance(user, User)` (the login
    middleware guarantees it) or a typed request class with `user: User`.
  - `settings.*` is `Any`. Code that reads a project setting binds it to an
    annotated local (`limit: int = settings.YARADUDE_SCAN_MAX_BYTES`).
- **`yara_x` ships its own stubs** (`py.typed` + `__init__.pyi` in the
  1.23.0 wheel), so no Protocols are needed. Three gaps, all confined to
  `rules/services/compiler.py`: `errors()` and `warnings()` return `Any`
  and are wrapped in `_errors()` / `_warnings()` that return
  `list[_Diagnostic]` (TypedDicts matching the dict shape in section 2,
  probed on 1.23.0); `module_names()` is missing from the stub and carries
  the one suppression. `scanner.py` uses only fully typed APIs. Nothing
  `Any`-typed from `yara_x` leaves these two modules.
- **Pygments** has no type information; `HtmlFormatter` and `YaraLexer` are
  imported from their defining modules (`pygments.formatters.html`,
  `pygments.lexers.yara`) because ty cannot see the lazy re-exports.
- **Completeness** of annotations is checked ad hoc with
  `uv run ruff check --select ANN <paths>` (not enabled in the ruff config);
  the only accepted findings are `ANN401` on `*args: Any` / `**kwargs: Any`
  that mirror Django's own signatures (commands, signal receivers).

## 10. Work packages

The coordinator owns this plan, briefs the agents, and verifies their output;
all code is written by subagents.

| # | Package | Runs | Scope |
|---|---|---|---|
| 1 | Foundation | first | project rename/config, `config/`, `accounts/`, `rules` models + migrations, all services, management commands, role bootstrap, admin, example rules, service/model tests, a placeholder home view and `/healthz/` so the project runs |
| 2 | Web UI | started while 1 is still running, coding against section 5.7 and the models | views, forms, URLs, templates, CSS/JS, template tags, error pages, view and permission tests |
| 3 | Containers and delivery | after 1; not needed for day-to-day development, which runs on the host until then | Dockerfile, Caddy image, compose files, dev container, entrypoint, air-gap bundle script, `.env.example`, ignore files, README |
| 4 | Review and fixes | after 2 and 3 | independent code review, coordinator runs tests and the app, findings routed back to the owning agent |

File ownership while 2 and 3 run in parallel: package 2 owns everything under
`rules/` except `services/`, `models.py`, `migrations/` and
`management/`, plus `accounts/templates/`; package 3 owns everything outside
the Python packages plus `README.md`. Either may fix a bug it finds in
foundation code but must report the change.

## 11. Testing

Tests are part of every work package, written alongside the code by the agent
that owns it, and run with Django's test runner (`uv run python manage.py
test`). No package is done while its tests are missing or failing.

| Area | What is covered |
|---|---|
| Parser | every lexical edge case in section 2 (regexes with braces, quotes, `//`, escaped slashes; escaped quotes in strings; hex strings with jumps, alternatives and comments; comments containing braces or the word `rule`; several rules on one line), modifiers, tags, imports, attached leading comments, meta value types, and every error case with its line number |
| Compiler | compiling and non-compiling rulesets, each failing rule carrying its own error with a rule-relative line, warnings stored per rule, rules referencing a sibling rule, default globals, unknown modules, `include` always refused (never reads server files), the relaxed-regex setting, edit validation distinguishing "this rule" from "a sibling it breaks" |
| Importer | create, unchanged, update with version bump, removed, restored, local edit preserved while disk is unchanged, disk change overriding a local edit, parse failure leaving data untouched, identical re-import being a no-op, Latin-1 input, run and per-file counters |
| Scanner / exporter | matches mapped back to rules, string instances, size limit, non-compiling rules left out and listed, timeout handling, sample never persisted; `.yar` and `.zip` output that recompiles with YARA-X |
| Editing | create, edit, restore and delete services record versions, sync tags and re-check the ruleset |
| Accounts | custom user model, idempotent role bootstrap with the exact permission sets, `ensure_superuser` |
| Views | every URL: anonymous → login redirect, Viewer allowed on read pages and refused (403) on every write, Editor allowed; form validation; search, filters and pagination; downloads; POST-only state changes; query counts on list pages |
| Security | CSP header present, no inline scripts or style attributes in rendered pages, `/healthz/` open, `check --deploy` clean |
| Containers | scripted smoke test: production stack up on a network without outbound access, health check green, login page served over HTTPS through Caddy, static files served, data persisted across a restart; the dev image runs the Tailwind build, the test suite and `runserver` with `--network none`; the production images rebuild from source offline (section 8.5) and the rebuilt stack passes the same smoke test |

Done means: `uv run python manage.py test` passes, `uv run ruff check .` and
`uv run ruff format --check .` are clean, `uv run ty check` is clean,
`manage.py check --deploy` is clean
with production environment variables, the dev container starts, the
production stack runs offline behind Caddy, and both offline bundles build.

## 12. Next work package: attribution and archives

Requested after the first build started. Scheduled once the typing pass on
the service layer has finished, because both touch the same files.

### 12.1 Who imported and who last changed a rule
- Every `RuleVersion` records its author: today edits, restores and creations
  do, but versions written by an import only link to the `ImportRun`. Imports
  set `created_by` to the run's user as well.
- `Rule` gains `created_by` and `updated_by` (nullable foreign keys to the
  user, `SET_NULL`), maintained in the one place versions are recorded. Null
  means a command-line import and is shown as "command line".
- Shown on the rule list (updated by), rule detail (imported by / last
  changed by, with times), every row of the version history, the ruleset page
  (last import and who ran it) and the import history. The rule list can be
  filtered by user. A deleted user leaves the history intact, shown as
  "deleted user".
- Existing development data is not back-filled; there is no production data.

### 12.2 Uploading a full rule collection as `.zip` or `.tar.gz`
- The upload form accepts single rule files and archives (`.zip`, `.tar`,
  `.tar.gz` / `.tgz`), recognised by content, not by file name.
- **Never extracted to disk.** Members are read one at a time in memory; only
  regular files ending in `.yar` / `.yara` are used, everything else
  (directories, symlinks, hard links, devices, other file types, nested
  archives) is skipped and counted. Member names are only ever used as
  identity strings, after normalising to POSIX form and refusing absolute
  paths and `..` components, so path traversal cannot write anywhere.
- **Limits against archive bombs**, enforced while reading rather than
  trusting the archive's headers: archive size, member count, per-file size
  (the existing 10 MiB) and total uncompressed size, all settings. An
  encrypted archive is refused with a clear message.
- **Identity.** An archive is a *collection*: a name taken from the archive
  file name and editable in the form. Each rule file inside becomes a ruleset
  whose path is `<collection>/<path inside the archive>`; a single common
  top-level directory (as in a GitHub download) is dropped. Uploading a newer
  archive under the same collection name therefore updates the same rulesets
  with the normal import semantics (changed rules get a new version, rules
  dropped from a file are flagged removed, local edits survive while the
  archived version of that rule is unchanged).
- **Files missing from a newer archive** change nothing by default. A
  checkbox "this archive is the complete collection" flags the rules of
  rulesets that are no longer in it as removed.
- One `ImportRun` per archive with per-file results, including skipped and
  failed members. The management command accepts an archive path as well.
- A collection is a path prefix, not a new model: the rule and ruleset lists
  filter by it, and it is the unit for collection export.

### 12.3 Downloading collections
- Export of a collection, a selection of rulesets, the current rule filter or
  everything, as `.zip` or `.tar.gz`, keeping the directory structure of the
  ruleset paths so that an export can be uploaded again unchanged (a round
  trip produces an import run with no changes).
- Two content modes: **current** (rebuilt from the stored rules, including
  local edits, without removed rules) and **original** (the files verbatim as
  last imported).
- A `MANIFEST.json` at the archive root lists each file with its SHA-256,
  rule count and export time, for checking a transfer across the air gap.
  Output is deterministic (sorted members, fixed timestamps), so identical
  content gives an identical archive.
- Single-rule and single-ruleset `.yar` downloads and the combined `.yar`
  stay as they are.

### 12.4 Scale findings from real rule sets
Measured on 2026-11-19 with 10,231 rules in 2,124 rulesets (signature-base,
Elastic protections-artifacts, ReversingLabs) in the development database.
Every file imported and every rule compiles under YARA-X, matching an
independent per-file compile; import takes about 1.2 s per 1,000 rules.
- **Test scan recompiles everything:** scanning one small file against all
  rules took 12.8 s, nearly all of it compilation. The scanner should cache
  the compiled `yara_x.Rules` (in process, optionally serialised with
  `serialize_into`) keyed by a fingerprint of the rules it was built from,
  and rebuild only when a rule changes.
- **Pickers must not list every ruleset:** dropdowns and checkbox lists of
  all rulesets do not work with thousands of them. Filtering and limiting a
  scan go by path prefix (the collection of 12.2) and tag.
- **Deep pagination** on the rule list was slow (6.9 s for page 50 against
  0.3 s for page 1) and has to cost about the same as the first page.

### 12.5 Index check
Checked on 2026-11-19 with `EXPLAIN QUERY PLAN` and timings on the same
10,231-rule database (SQLite 3.51). Lookups by key are all indexed: ruleset
by (origin, path), rule by (ruleset, name), versions by (rule, number), tags
by name and through the join table, newest-first by `updated_at`. Every page
query runs in about 20 ms or less at this size. Improvements, in order of
value, to go in with the next migration:
- Sort options tiebreak on the rule's primary key only, so the name and
  `updated_at` indexes serve the ordering without a sort (view change).
- Status filters and dashboard counts (`removed_at`, `compile_error`,
  warnings, modified) scan the wide rule table. Add partial indexes for
  failing and removed rules, and a stored boolean for "has warnings" if that
  filter stays; this matters from roughly 100,000 rules.
- Add `(ruleset, position)` for rules in file order.
- Substring search over rule source cannot use an index (20 ms now, linear in
  total rule text). Move to SQLite FTS5 with the trigram tokenizer when
  collections reach roughly ten times this size.
- The collection filter by path prefix scans; if collections become a main
  navigation axis, store the collection name in its own indexed column
  instead (revisit the "path prefix, not a model" choice in 12.2).
- No planner statistics exist; run `PRAGMA optimize` after import runs.
- Three single-column foreign-key indexes duplicate the leading column of a
  unique constraint (`rule.ruleset`, `ruleversion.rule`, the tag join table's
  `rule`). Harmless; leave unless write speed becomes a concern.

## 13. Review findings to fix

From the independent read-only review of 2026-11-19 (182 tests passing at the
time). It found no XSS, CSRF, authentication bypass or path traversal in the
web UI. Nine of the ten findings were demonstrated against a scratch
database. Each fix comes with a test that fails without it. Service-layer
fixes wait for the typing pass, which is editing the same files.

| # | Severity | Where | Problem | Fix |
|---|---|---|---|---|
| 1 | High | `parser.py`, `importer.py` | A 10 MiB rule file takes 1.65 GB and 10 s to parse, and parsing and both compiles run inside the write transaction, so every other write (including login) is locked out and can fail | Parse, safety-net compile and hash outside the transaction; slotted tokens without whitespace tokens; compute referenced names once per rule; make the per-file limit a setting with a lower default |
| 2 | Medium | `editing.py` | Two simultaneous saves of one rule (or an edit racing an import) raise `IntegrityError` | Re-fetch the rule inside the transaction, compare the expected version, turn conflicts into an `EditResult` error |
| 3 | Medium | `importer.py` | A rule renamed in the editor is flagged removed and its disk original re-created on the next import that changes the file, contradicting the rule that local edits survive | Match by the imported hash as a fallback (or keep the imported name) |
| 4 | Medium | `importer.py` | Any unexpected error (unreadable file, locked database, worker timeout) aborts the whole run and leaves it unfinished with zero counters | Catch per file, record a failed `ImportFile`, always finish the run |
| 5 | Medium-low | `parser.py` / `importer.py` | A CRLF file saved unchanged from the editor gets a new version and a "modified locally" badge | Normalise line endings in one place for rule text and hashes; keep `original_content` verbatim |
| 6 | Medium-low | `admin.py`, `scanner.py` | The admin can edit rule source and version snapshots, bypassing hashing, versioning and compile checks; a rule edited that way crashed the scanner | Content fields read-only in the admin, versions fully read-only, scanner tolerant of an unknown match |
| 7 | Low | `importer.py` | File symlinks inside the rules directory are followed outside it, and their content becomes downloadable | Skip symlinks / require the resolved path to stay under the root |
| 8 | Low | `parser.py` | A float meta value makes the whole file fail although YARA-X accepts it | Accept floats in meta (section 5.1 is wrong to omit them) |
| 9 | Low | `exporter.py`, forms | Ruleset names and paths with newlines or backslashes inject text into combined exports and odd member names into archives | Sanitise section comments and member names; reject control characters in collection names |
| 10 | Low | views | Object lookup before the permission check reveals which ids exist; creating a collection from the rule form skips `add_ruleset` | Check permission first; require `add_ruleset` |

Also from the review, for the containers package: the scan timeout (60 s)
exceeds gunicorn's default worker timeout (30 s), so set gunicorn's timeout
above scan timeout plus compile time; cap request bodies in Caddy; a
directory scan started from the UI runs inside the request. Smaller items:
`ensure_roles` ignores the `using` argument of `post_migrate`,
`ensure_superuser` skips the password validators, leftover scaffold
docstrings in `config/`, and no test yet for `check --deploy`.
