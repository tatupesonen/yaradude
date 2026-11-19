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
  "modified locally". `imported_name` (the rule's name in the file as last
  imported; kept when the rule is renamed locally, used to match it on the
  next import; blank for manual rules). Sources and hashes use LF line
  endings (section 5.1).
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
The tokenizer is a lazy generator of small tuples; whitespace tokens are
never materialised, only a rule's `meta:` section is kept as tokens, and the
names a rule references are collected in the same pass over its body
(finding 1 of section 13: a 10 MiB file now takes 2.9 s and 88 MiB RSS
instead of 10.4 s and 836 MiB). Line endings: `parse` converts CRLF to LF
first (`normalize_newlines`, the one place this happens), so rule sources
and their hashes are the same whether the rule came from disk or from a
browser textarea (which submits CRLF). A lone CR is kept (it may sit inside
a string literal). `Ruleset.original_content` stays verbatim.

Top-level grammar: `import "mod"`, `include "file"`, and
`[global] [private] rule NAME [: tag…] { … }` where the closing brace is found
by depth counting over tokens (strings, regexes and comments are opaque).

Per rule it returns: name, tags, `is_private`, `is_global`, source slice
(first modifier through closing brace), meta pairs (parsed from the `meta:`
section: string with escapes, integer, float, negative integer or float,
`true`/`false`; YARA-X accepts floats such as `score = 7.5` but no size
suffix on them),
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
- `import_directory(root, user=None, origin=...)` imports the files
  `rule_files(root)` selects: `*.yar` / `*.yara` (any case), not hidden, not
  in a hidden directory; directory symlinks are not descended into and a
  file symlink is used only if its target resolves inside `root` (checked
  again when the file is read). Files over `YARADUDE_MAX_RULE_FILE_BYTES`
  are recorded as failed; reading stops at the limit, so a file that grew
  after listing also fails. `import_uploads(files, user)` handles uploads;
  both return an `ImportRun`.
- Per file. Before any write lock is taken (finding 1):
  1. Read, decode (UTF-8, fall back to Latin-1), hash. Same hash as the
     stored ruleset → count as unchanged, touch `last_imported_at`, stop.
  2. Parse and run the safety-net compile. Failure → `ImportFile(status=
     failed)` with the message; nothing else changes.
  3. Plan the sync against the ruleset's current rules (below) and compile
     the resulting active rules.
  Then, in one short transaction: read the ruleset and its rules again,
  re-plan (pure Python), write, and store the precompiled diagnostics if the
  re-planned active rules are exactly what was compiled (otherwise compile
  again inside; only when another writer got in between).
- Sync rules. The file's rules are matched to the ruleset's rules (removed
  ones included) first by `Rule.imported_name`, the name the rule had in the
  file when last imported, so a rule renamed in the editor stays the same
  rule (finding 3); then by `imported_sha256` (rules renamed before
  `imported_name` was recorded); then by current name for rules that never
  came from a file. For each match: hash equals `imported_sha256` → disk
  unchanged, the local content (including a local rename) is kept; hash
  equals the current content → disk caught up, no version; otherwise disk
  wins: update (name included), bump version, record a `RuleVersion`; the
  local edit stays in the history. No match → create with version 1. A
  previously removed rule that reappears is restored. Rules of the ruleset
  missing from the file that came from a file → `removed_at`; locally
  created rules stay. If the result would give two rules one name (a local
  rename onto a name the file also uses), the file fails with a message
  saying so and nothing changes.
- Store `original_content`, hashes, timestamps; sync tags; store the compile
  diagnostics; move the rules revision if anything the compiled rule set
  depends on changed.
- Any error in one file (unreadable, database locked, a bug) is caught: the
  file is recorded as failed with a message naming only the error type
  (never file content), the traceback goes to the log, and the run goes on.
  Counters are saved after every file and the run is always finished, so
  an interrupted run shows how far it got. After a run, `PRAGMA optimize`.
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
- **Deleted rows (PLAN.md 12.11).** `Rule.objects` and `Ruleset.objects`
  (the default managers, hence also `ruleset.rules`, `get_object_or_404`,
  the admin) leave deleted rows out by construction. Deleted rows are
  reached deliberately through `Rule.all_objects` / `Ruleset.all_objects`
  (`.deleted()` on either). Joins do not apply managers: an aggregate over
  `rules__…` (e.g. per-ruleset counts) must add
  `rules__deleted_at__isnull=True` itself.
- `Ruleset`: `Origin` choices (`DIRECTORY`, `UPLOAD`, `MANUAL`),
  `get_origin_display()`, `get_absolute_url()` → `rules:ruleset_detail`,
  related `rules` (all not deleted, including removed) and `import_files`;
  `deleted_at`, `deleted_by`, `is_deleted`.
- `Rule.objects` / `Rule` querysets: `.active()` (neither removed nor
  deleted), `.removed()` (removed, not deleted), `.deleted()` (use on
  `all_objects`),
  `.failing()` (non-blank `compile_error`), `.modified()` (changed locally).
  `deleted_at`, `deleted_by`, `deleted_with_ruleset`, `is_deleted`.
  Permissions `rules.purge_rule` / `rules.purge_ruleset` (no role group
  has them; superusers do).
  `Tag.objects.unused()` (tags no rule uses; the services delete them).
  Instance: `text` (imports + blank line + source: editor and download
  text), `is_modified`, `is_removed`, `compiles`, `compile_warnings` (list of
  diagnostic texts), `tags` (M2M to `Tag`), `versions` (newest first),
  `get_absolute_url()` → `rules:rule_detail`. `meta` is a list of
  `[key, value]` pairs; values are `str`, `int`, `float` or `bool`.
  `imported_name`: the rule's name in its file as last imported (differs
  from `name` after a local rename; blank for manual rules).
- `RulesRevision`: single row, read through `revision.current()` (below).
- `RuleVersion`: `Origin` choices (`IMPORT`, `UPLOAD`, `CREATE`, `EDIT`,
  `RESTORE`), `text`, `get_absolute_url()` → `rules:rule_version`.
- `ImportRun`: `Origin` choices (`SCAN`, `UPLOAD`, `CLI`), counters
  (including `files_skipped` / `rules_skipped`: deleted in yaradude, left
  alone), `summary` (one-line text; mentions skips when there are any),
  `files` (only changed/failed/skipped files), `get_absolute_url()` →
  `rules:import_run`.
- `ImportFile`: `Status` choices (`CREATED`, `UPDATED`, `FAILED`,
  `SKIPPED`), `path`, `ruleset`, per-file counters (incl. `rules_skipped`),
  `message`. A `SKIPPED` row is written when a changed file belongs to a
  deleted ruleset.
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
- `normalize_newlines(text: str) -> str` — CRLF → LF; `parse` applies it.
- `ParsedRule`: `name`, `tags: list[str]`, `is_private`, `is_global`,
  `source` (LF line endings), `meta: list[tuple[str, str | int | float |
  bool]]`, `imports: list[str]`
  (modules of the file's imports this rule references), `import_lines`,
  `line` (line of the `rule` keyword or first modifier), `source_line`;
  properties `description`, `author`, `text`, `sha256`;
  `meta_value(key) -> str`; `parsed_line(text_line) -> int | None`.

**`compiler.py`** (only this module and `scanner.py` import `yara_x`)
- `new_compiler() -> yara_x.Compiler` — includes disabled, configured regex
  strictness, default globals.
- `check_ruleset(ruleset: Ruleset, *, changed: bool = False) ->
  RulesetCheck` — stores per-rule `compile_error` / `compile_warnings` and
  `Ruleset.compile_error`; moves the rules revision when a rule starts or
  stops compiling, or when the caller passes `changed=True`.
- `RuleEntry(name, imports, source)`, `RuleEntry.of(rule)`,
  `compile_entries(entries: list[RuleEntry]) -> list[RuleDiagnostics]` (pure,
  no database), `store_check(ruleset, rules, results, *, changed=False) ->
  RulesetCheck`, `ruleset_entries(ruleset) -> (all rules, active rules)`,
  `plan_edit(ruleset, rule, parsed) -> EditPlan` (`validation`, `entries`,
  `results`): the building blocks that let writers compile before taking
  the write lock. Views do not need them.
- `RulesetCheck`: `ruleset`, `diagnostics: dict[Rule, RuleDiagnostics]`;
  properties `failing: list[Rule]`, `ok: bool`, `summary: str`.
- `RuleDiagnostics`: `name`, `error: str`, `line: int | None` (relative to
  `Rule.text`), `warnings: list[str]`; property `ok`.
- `validate_edit(ruleset, rule: Rule | None, parsed: ParsedRule) ->
  EditValidation` — no writes; views normally use `editing` instead. An
  unsaved `ruleset` has no sibling rules.
- `EditValidation`: `error: str`, `line: int | None` (in the editor text),
  `warnings: list[str]`, `broken: list[BrokenRule]`; property `ok`.
- `BrokenRule`: `rule: Rule`, `error: str`.
- `build_source(ruleset) -> str`, `combine_rules(rules: list[Rule]) -> str`,
  `compiled_identifiers(text) -> list[str] | None`.

**`editing.py`** — the editor flow (new module, not in the original plan)
- `validate_rule_text(ruleset, text, rule=None) -> EditResult` — "Validate"
  button; no writes. `ruleset` may be unsaved (a collection that does not
  exist yet, from `manual_ruleset(name, save=False)`); it then has no
  sibling rules.
- `create_rule(ruleset, text, user=None) -> EditResult` — appends a new rule
  (version 1, origin `create`) when valid. An unsaved `ruleset` is created in
  the same transaction as the rule, so a refused save leaves nothing behind
  (the view no longer needs its own transaction and rollback). A name taken
  meanwhile is a `conflict` result.
- `update_rule(rule, text, user=None, origin=EDIT, *, expected_version: int |
  None = None) -> EditResult` — new version (origin `edit`) when valid;
  identical text saves nothing (line endings do not count: CRLF from the
  textarea equals the stored LF text). `expected_version` is the version the
  editor was rendered with (the edit form's hidden `version` field); when
  omitted, the version of the `rule` instance passed is expected. The rule
  is read again inside the transaction: if it moved on (another save, an
  import) or was deleted, or its new name was taken meanwhile, nothing is
  saved and the result has `error` set and `conflict=True`. Never raises
  `IntegrityError`.
- `restore_version(version: RuleVersion, user=None, *, expected_version:
  int | None = None) -> EditResult` — the old text becomes a new version
  (origin `restore`), with the same checks as an edit; pass the rule's
  version as shown on the page as `expected_version`.
- `delete_rule(rule, user=None) -> None` — **now recoverable** (12.11): flags
  the rule deleted (`deleted_at`, `deleted_by`), keeps its history and tags,
  re-checks the ruleset. No-op for a deleted rule.
- `delete_ruleset(ruleset, user=None) -> None` — **now recoverable**: flags
  the ruleset and its rules (those marked `deleted_with_ruleset`). No-op for
  a deleted ruleset.
- `restore_rule(rule, user=None) -> EditResult` — brings a deleted rule back
  with the content it had; `error` if its ruleset is deleted (restore that
  instead) or it is not deleted (`conflict`). The ruleset's file hash is
  cleared, so the next import re-reads the file and, if the file moved on
  meanwhile, updates the rule under the normal import rules.
- `restore_ruleset(ruleset, user=None) -> None` — brings back the ruleset
  and the rules deleted with it (rules deleted on their own stay deleted);
  the next import re-reads its file.
- `purge_rule(rule) -> None`, `purge_ruleset(ruleset) -> None` — the old
  hard deletes, with history; views must require `rules.purge_rule` /
  `rules.purge_ruleset`. Import runs keep their `ImportFile` rows, with
  `ruleset` set to null.
- A deleted rule keeps its name: creating or renaming onto it is refused
  with "A deleted rule named … still holds this name … Restore it, or purge
  it". `create_rule` into a deleted ruleset is refused (`conflict`).
- `manual_ruleset(name, save: bool = True) -> Ruleset` — get or create a
  manual ruleset; with `save=False` a missing one is returned unsaved; a
  deleted one is returned as it is (`is_deleted`).
- `EditResult`: `error: str`, `line: int | None` (line in the submitted
  text), `warnings: list[str]`, `broken: list[BrokenRule]` (siblings this
  change breaks; saving is still allowed), `parsed: ParsedRule | None`,
  `rule: Rule | None` (set when saved), `conflict: bool` (refused because
  of a concurrent change; show "reload and apply again"); property `ok`. A save is refused,
  with `error` set and `rule` None, when the text does not parse, the name
  is taken by another rule of the ruleset (removed rules included), or the
  rule itself does not compile.

**`importer.py`**
- `import_directory(root: Path | str, user=None, origin=ImportRun.Origin.SCAN)
  -> ImportRun` — the UI passes `settings.YARADUDE_RULES_DIR`, never a path
  from the request.
- `import_uploads(files: Iterable[File], user=None) -> ImportRun` — e.g.
  `request.FILES.getlist("files")`.
- `rule_files(root: Path | str) -> list[RuleFile]` — exactly the files
  `import_directory(root)` processes, in order (use it for counts on the
  Import page). `RuleFile`: `path: Path`, `identity: str` (the ruleset
  path), `size: int`, `mtime_ns: int`, `error: str` (non-blank: will be
  recorded as failed: too large, or a symbolic link leading outside the
  rules directory or nowhere — such links are listed, never followed, and
  the message does not name their target). Hidden files and other suffixes
  are not listed.
- `decode(content: bytes) -> str`; `max_file_bytes() -> int` (the
  `YARADUDE_MAX_RULE_FILE_BYTES` setting, default 4 MiB); constants
  `RULE_SUFFIXES` and `MAX_FILE_BYTES` (the setting's value at start-up, for
  form limits and help texts).
- `import_file(run, origin, path, read: Callable[[], bytes]) -> ImportFile |
  None` — one file into an existing run (used by the archive import and the
  watcher); never raises.

**`revision.py`**
- `current() -> Revision` — one primary-key query. `Revision`: `number: int`
  (0 before the first change), `changed_at: datetime | None`. The number
  moves, inside the same transaction, on every write that changes what the
  compiled rule set should hold or its order: rule created, updated,
  restored, removed, un-removed or deleted, positions changed by an import,
  ruleset deleted, a rule starting or stopping to compile. No-ops (identical
  re-import, a re-check that changes nothing, a refused or identical edit)
  leave it. Writers call `bump()` only through `store_check(...,
  changed=True)` / `check_ruleset(..., changed=True)` or
  `editing.delete_ruleset`.

**`scanner.py`** — scans use one compiled set of all rules (section 12.4)
- `scan_sample(sample: File, rulesets: Iterable[Ruleset] | None = None) ->
  ScanResult` — scans in the calling process with the compiled set (never
  compiles); raises `ScanError` (message suitable for the user) when the
  sample exceeds `YARADUDE_SCAN_MAX_BYTES`, the scan times out or YARA-X
  fails. Kept for the existing form; new code submits jobs
  (`scans.services`).
- `scan_bytes(data, name="", limit: ScanLimit | None = None, *, timeout=None,
  previews=True) -> ScanResult` — the same on bytes; `previews=False` leaves
  `hex`/`ascii` empty (for stored results). Raises `ScanTimeout(ScanError)` /
  `ScanError`.
- `limit_for(path="", tag="", rulesets=None) -> ScanLimit` — `path` as on
  the rule list (ending in `/` = prefix, else substring), `tag` (rules
  carrying that YARA tag), `rulesets` (objects or ids); combined with AND.
  The scan always uses the full set and filters the matches; rulesets are
  separate namespaces, so this equals compiling only the selection.
  `ruleset_ids_for_path(path) -> frozenset[int]`.
- `ScanResult`: `sample_name`, `sample_size`, `sample_sha256`,
  `matches: list[RuleMatch]`, `rulesets: Sequence[Ruleset]` (a lazy
  `RulesetList`: `len()` costs no query, iterating loads the rulesets in
  name order without `original_content`), `rules_scanned` (non-private
  rules within the limit), `left_out: list[Rule]` (active rules not in the
  set because they do not compile; within the limit), `elapsed: float`
  (server time of the call), and, added for the compiled set: `revision`
  (rules revision the set reflects), `built_at`, `pending: bool` (rules
  changed since; the newer set is still being built, the answer uses the
  previous one), `unmapped: list[str]` (matches skipped because they map to
  no stored rule, e.g. `"12:rule_name"`; never a crash), `scan_seconds`
  (time inside the engine).
- `RuleMatch`: `rule: Rule` (with `ruleset` loaded; `source` and
  `ruleset.original_content` deferred), `tags: list[str]`,
  `patterns: list[PatternMatch]`; property `ruleset`.
- `PatternMatch`: `identifier`, `count` (capped at 1000),
  `instances: list[PatternInstance]` (first 5).
- `PatternInstance`: `offset`, `length`, `hex` (`"4d 5a 90"`), `ascii`
  (non-printables as `.`), `truncated` (match longer than the 32-byte
  preview).
- `compiled_status() -> CompiledSetStatus` — cheap (one primary-key query
  and a small file header): `available`, `set: CompiledSetInfo | None`,
  `current_revision`, `current_changed_at`, `pending` (database revision
  differs from the set's, or no set), `building` (a build holds the lock
  now); properties `revision`, `built_at`. `CompiledSetInfo`: `revision`,
  `revision_changed_at`, `built_at`, `build_seconds`, `engine` (yara-x
  version), `rules`, `rulesets`, `left_out`, `slow`.
- `slow_rules() -> list[SlowRule]` — rules YARA-X warned about at build time
  with a slow-pattern or slow-loop warning (`code` contains `slow`, e.g.
  `slow_pattern`, `potentially_slow_loop`): `rule_id`, `ruleset_id`,
  `name`, `code`, `message`. Fetch `Rule` rows by id if more is needed.
- `build_compiled_set(*, force=False, wait=False) -> BuildOutcome | None`
  (`built`, `info`) — normally only the builder worker calls it; `None`
  when another build holds the lock. Management command
  `compile_rules [--force]`.
- Uploads are memory-only (`FILE_UPLOAD_HANDLERS`); a request body larger
  than `FILE_UPLOAD_MAX_MEMORY_SIZE` (scan limit + 1 MiB) arrives without
  its files, so the form should report "file missing or too large". This
  also caps the total of a multi-sample upload.

**`exporter.py`**
- `export_rule(rule) -> ExportFile`, `export_ruleset(ruleset) -> ExportFile`
  (rebuilt), `export_ruleset_original(ruleset) -> ExportFile`,
  `export_combined(rules: Iterable[Rule]) -> ExportFile` (`.yar`),
  `export_zip(rules: Iterable[Rule]) -> ExportFile` — removed rules are
  skipped; pass querysets with `select_related("ruleset")`.
- `ExportFile`: `filename`, `content: bytes`, `content_type`. Serve with
  `HttpResponse(f.content, content_type=f.content_type,
  headers={"Content-Disposition": content_disposition_header(True, f.filename)})`.
- `ruleset_filename(ruleset, keep_directories=False) -> str` — safe as an
  archive member name: no control characters, backslashes, drive letters,
  empty, `.` or `..` components. Section comments of combined exports put
  ruleset names and paths on one line (control characters become `?`).

**`search.py`** — full-text search (12.5)
- `search_rules(queryset: QuerySet[Rule], text: str, *, rank: bool = False)
  -> QuerySet[Rule]` — the rules of `queryset` whose name, description,
  author or source contains `text`, case-insensitively; the result can
  still be filtered, ordered and paginated. Replace the list's four
  `icontains` conditions with it. Semantics are those of the old filter:
  the whole trimmed input is one literal substring (several words are a
  phrase, not AND-ed); quotes, `AND`/`OR`/`NOT`/`NEAR`, `name:`, `*`, `^`,
  `-` and parentheses are plain text, never FTS syntax. Input under three
  characters (or containing NUL) uses the old `icontains` filter. The one
  difference: non-ASCII letters are case-folded too. With `rank=True` the
  queryset is annotated `search_rank` (bm25, lower is better; None for short
  input) and ordered by it, then pk. Empty text returns `queryset`.
  Removed and deleted rules are in the index; the base queryset decides.
- `rebuild_index() -> int`, `index_is_consistent() -> bool`,
  `fts_support() -> str` ('' when available). Command
  `manage.py rebuild_search_index`. System check `rules.E001` fails at
  startup if SQLite lacks FTS5 trigram (3.34+; this machine 3.51, the
  `python:3.13-slim-bookworm` base 3.40.1, both verified).

**`database.py`** — SQLite housekeeping (8.1)
- `optimize(connection=None)`, `checkpoint(connection=None) -> Checkpoint |
  None` (`busy`, `wal_pages`, `checkpointed`; truncating), `maintain()`
  (both), `pragmas(connection=None) -> dict` (read-back of the tuning
  PRAGMAs). Recurring task `rules.tasks.database_maintenance` (maintenance
  queue, `YARADUDE_DB_MAINTENANCE_INTERVAL`). `importer.optimize_database()`
  delegates to `optimize()`.

**`names.py`**
- `has_control_characters(text) -> bool` (line breaks, controls, invisible
  format characters such as bidi overrides) — forms reject collection and
  ruleset names for which it is true. `single_line(text) -> str`,
  `safe_member_path(path, fallback) -> str`.

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

**`scans` app** — scan jobs, task queues, recurring tasks, live updates
(sections 12.4, 12.7, 12.9). Views and the API call `scans.services`.

*Jobs* (`scans.models.ScanJob`, shared with the team: every user with
`rules.scan_rules` may list and open every job and sees who submitted it;
users without it see none)
- Fields: `id` (UUID, use it in URLs), `user` (submitter, null once that
  user is deleted; property `submitted_by` → username or "deleted user"),
  `batch` (UUID shared by the jobs of one multi-sample submission, else
  null), `sample_name`, `sample_size`, `sample_sha256`, `options`
  (`{"path", "tag", "rulesets"}`), `state` (`State`: `QUEUED`, `RUNNING`,
  `FINISHED`, `FAILED`), `phase` (`Phase`: `QUEUED` "waiting for a worker",
  `LOADING` "loading the compiled rules", `SCANNING`, `DONE`), `inline`
  (scanned at once, without the queue), `created_at`, `started_at`,
  `finished_at`, `updated_at` (last change), `error` (user-facing message
  when failed), `result` (JSON below, finished jobs only), `match_count`,
  `revision` (rules revision of the set used), `rules_pending` (rules had
  changed and the newer set was not ready); property `done`.
- `submit_samples(samples: Sequence[File], user: User, *, path="", tag="",
  rulesets=None) -> list[ScanJob]` — one job per sample, in order. A
  single sample of at most `YARADUDE_SCAN_INLINE_MAX_BYTES` is scanned
  right away in the calling process and comes back `FINISHED` (or
  `FAILED`); everything else comes back `QUEUED`. A sample over
  `YARADUDE_SCAN_MAX_BYTES` becomes a `FAILED` job without being read.
  Raises `ScanError` for no samples or more than `YARADUDE_SCAN_MAX_SAMPLES`.
  E.g. `request.FILES.getlist("samples")`.
- `visible_jobs(user) -> QuerySet[ScanJob]` — all jobs newest first, `user`
  loaded, `result` deferred (paginate it); empty without the permission.
- `get_job(user, job_id) -> ScanJob` — with its result; raises
  `ScanJob.DoesNotExist` for an unknown id, a malformed id or a user without
  the permission (answer 404 in all three cases).
- `job_json(job, *, with_result=True) -> dict` — the job object of the
  socket protocol below (also suitable for the API).
- `system_status() -> SystemStatus`: `compiled` (`CompiledSetStatus`),
  `workers` (live processes per role: `"scan"`, `"maintenance"`,
  `"builder"`), `queued`, `running` (scan jobs), `recurring`
  (`list[RecurringStatus]`).
- `can_scan(user) -> bool`.
- Stored result (`job.result`; no sample bytes, so no hex/ASCII previews):
  `{"matches": [{"rule_id", "rule", "ruleset_id", "ruleset",
  "ruleset_path", "tags": [str], "patterns": [{"identifier", "count",
  "instances": [{"offset", "length"}]}]}], "rules_scanned", "rulesets"
  (count), "left_out": [{"rule_id", "rule", "ruleset_id", "ruleset"}],
  "unmapped": [str], "compiled": {"revision", "built_at", "pending"},
  "scan_seconds"}`.
- Jobs and finished task records are deleted after
  `YARADUDE_SCAN_RETENTION_DAYS` (recurring task `cleanup_scan_jobs`, or
  `manage.py scans_cleanup`).

*Queues and workers* (`django-tasks-db` backend, queue in SQLite)
- Queues (`scans.queues`): `SCAN_QUEUE = "scans"` (scan jobs only) and
  `MAINTENANCE_QUEUE = "maintenance"` (directory passes, cleanup, other
  housekeeping). Each worker process serves exactly one queue, so a long
  directory import never delays a scan and scans never starve maintenance.
- Enqueue maintenance work with an ordinary task:
  `@task(queue_name=MAINTENANCE_QUEUE)` in an app's `tasks.py`, then
  `my_task.enqueue(...)` (JSON-able arguments only). Deferred:
  `my_task.using(run_after=datetime).enqueue()` (supported natively).
- Processes: `manage.py run_workers` starts `YARADUDE_SCAN_WORKERS` scan
  workers, `YARADUDE_MAINTENANCE_WORKERS` maintenance workers and one
  compiled-set builder, restarts any that exit, and fails the jobs of a
  worker that died. `manage.py run_worker scan|maintenance|builder` runs one.
  Workers must be started this way (heartbeats), not with `db_worker`.

*Recurring tasks* (`scans.recurring`)
- Declare in an app's `tasks.py` (imported in every process at start):
  ```python
  from django.tasks import task
  from scans.queues import MAINTENANCE_QUEUE
  from scans.recurring import recurring

  @recurring("YARADUDE_RULES_WATCH_INTERVAL")  # name of a setting, seconds
  @task(queue_name=MAINTENANCE_QUEUE)
  def watch_rules_directory() -> None: ...
  ```
  The task takes no arguments. Interval 0 (or less) means off: nothing is
  scheduled and a waiting occurrence is removed.
- Guarantees: at most one pending (waiting or running) occurrence at any
  time, also when several processes start at once; the next occurrence is
  scheduled when one finishes, successful or raising, at the later of now
  and "this run's start + interval" (a run longer than the interval is
  followed once, at once; no pile-up); the next occurrence is a queued task
  with `run_after`, no sleeping process.
- Repair: `ensure_all_scheduled()` restores a lost schedule (fresh
  database, queue emptied, worker killed mid-run — detected by its missing
  heartbeat, or a follow-up that was never written). It runs when any
  worker process starts and every 30 s in each idle maintenance worker.
- `status(task_or_path) -> RecurringStatus`: `name`, `interval`, `enabled`,
  `scheduled_for` (when the waiting occurrence is due; None if none or due
  now), `waiting`, `running`, `last_started_at`, `last_finished_at`,
  `last_succeeded`, `last_error` (exception class path or "worker lost"),
  `runs`. `run_now(task)` makes the waiting occurrence due now.
  `ensure_scheduled(task)` schedules one explicitly (idempotent).
  `registered() -> list[Recurring]`.

*Live updates: WebSocket protocol, version 1* (`/ws/scans/`)

Uploading stays an ordinary multipart POST that calls `submit_samples`; the
socket only delivers updates. The page opens
`new WebSocket((location.protocol === "https:" ? "wss://" : "ws://") +
location.host + "/ws/scans/")` with the session cookie (same origin).
Without JavaScript the jobs page refreshes itself instead.

- Admission: the handshake is refused (HTTP 403; the browser reports close
  code 1006) unless the user is signed in, active and has
  `rules.scan_rules`, and the `Origin` header equals the page's own origin
  (scheme and host as Django's CSRF origin check, or an entry of
  `DJANGO_CSRF_TRUSTED_ORIGINS`). At most 10 open sockets per user per
  server process (the 11th is closed with 4429 right after opening).
- Frames: text only, each one JSON object of at most 4096 bytes (UTF-8)
  with `"v": 1` and a `"type"`; at most 20 client messages per 10 seconds.
  A binary frame, a frame that is not a JSON object, a wrong `v`, an
  unknown `type` or a malformed field gets an `error` message and the
  socket is closed (codes below). The server re-checks the user's account
  and permission every 30 s and closes a socket after one hour (the client
  reconnects and subscribes again).
- Client → server:
  - `{"v":1,"type":"subscribe","jobs":["<job id>", …]}` — follow these jobs
    (at most 200 followed jobs per socket that are not finished yet). For
    each id the server replies at once with `job` (current state) or
    `job_unknown`.
  - `{"v":1,"type":"unsubscribe","jobs":["<job id>", …]}`.
  - `{"v":1,"type":"follow","scope":"mine"}` — also deliver jobs created
    from now on: `"mine"` (submitted by this user), `"all"` (anyone's),
    `"none"` (stop).
  - `{"v":1,"type":"ping","id":"<string up to 64 chars>"}`.
- Server → client:
  - `{"v":1,"type":"hello","user":"<username>","limits":{"max_message_bytes":4096,"max_jobs":200,"messages_per_10s":20},"compiled":<compiled>}`
    once after the socket opens.
  - `{"v":1,"type":"job","job":<job>}` — on subscribe, for each followed
    new job, and on every change of `state` or `phase`. `<job>` is
    `job_json(job)`: `id`, `batch`, `state`, `phase`, `inline`,
    `sample_name`, `sample_size`, `sample_sha256`, `submitted_by`,
    `options`, `created_at`, `started_at`, `finished_at`, `updated_at`
    (ISO 8601 or null), `error`, `match_count`, `revision`,
    `rules_pending`, `result` (the stored result above when `state` is
    `finished`, else null). After a `finished` or `failed` event the job is
    no longer followed.
  - `{"v":1,"type":"job_unknown","id":"<job id>"}` — no such job (never
    existed, malformed id, or removed by retention).
  - `{"v":1,"type":"compiled","compiled":<compiled>}` — when the compiled
    set changes (new revision available, build starts or ends). `<compiled>`:
    `{"available": bool, "revision": int|null, "built_at": str|null,
    "current_revision": int, "pending": bool, "building": bool,
    "rules": int, "rulesets": int}`.
  - `{"v":1,"type":"pong","id":"…"}`.
  - `{"v":1,"type":"error","code":"…","message":"…"}` with `code` one of
    `bad_message`, `unsupported_version`, `unknown_type`, `too_large`,
    `binary_not_accepted`, `rate_limited` (all followed by a close) or
    `too_many_jobs` (not fatal; the extra ids are ignored).
- Close codes: 4400 protocol error, 4403 account disabled or permission
  removed, 4408 one-hour limit reached (reconnect), 4413 message too large,
  4429 rate limit or too many sockets.
- Latency: the server looks for changes of followed jobs every 0.25 s.

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
the CDN script); the design tokens live in the Tailwind theme (section 7.2).
Hard constraints: no external requests of any kind (air gap), no inline
`<script>`, inline event handlers or `style=""` attributes (strict CSP
`default-src 'self'`), system font stack, light and dark themes via
`prefers-color-scheme`, usable at laptop and phone widths, accessible
(labels, focus states, sufficient contrast).

Design direction: calm, dense-but-readable tool for analysts. Persistent
navigation, monospace for identifiers and code, clear status badges
(compiles / error / warnings / modified locally / removed), timestamps shown
as absolute local time (`DJANGO_TIME_ZONE`) with relative time as a
secondary hint.

### 7.1 Pages, URLs and permissions

Every view declares its permission (`rules.views.base.PermissionMixin`, a
`PermissionRequiredMixin` with `raise_exception=True` that checks the
permission *before* any object lookup, so a user without it gets 403 whether
or not the id exists). Anonymous users are redirected to the sign-in page by
`LoginRequiredMiddleware`. Templates hide controls the user cannot use.

| Page | URL name | URL | Permission | Notes |
|---|---|---|---|---|
| Sign in / out | `login`, `logout` | `/accounts/login/`, `/accounts/logout/` | public / POST | Django auth views, styled (`accounts/templates/registration/`) |
| Change password | `password_change`, `password_change_done` | `/accounts/password_change/`, `…/done/` | signed in | styled; linked from the account menu. No password reset (no email in the air gap) |
| Dashboard | `rules:dashboard` | `/` | `view_rule` | counts (rules, rulesets, tags, compile errors, warnings, modified locally, removed), recent import runs, recently updated rules; empty state points to Import |
| Rules | `rules:rule_list` | `/rules/` | `view_rule` | search `q` (name, description, author, source); filters `path` (ruleset path: ends with `/` = directory prefix, e.g. `signature-base/`, otherwise substring), `ruleset` (id, set by links from a ruleset page), `tag`, `status` (active (default) / error / warnings / modified / removed / all); `sort` (name, ruleset, updated, created, each ± ; every key ends with the rule id); 100 per page with first/prev/next/last and a page-number field; active filters as removable chips; row selection; export of selection or of the current filter. Layout: below 640 px the filters fold into a `<details>` "Filters" and the ruleset name is shown under the rule name; the ruleset column appears from 640 px, updated from 768 px, description (two lines) and tags from 1024 px; the name column keeps at least 10rem |
| Export | `rules:rule_export` | `/rules/export/` | `view_rule` | GET or POST: `scope=selected` with `ids`, or `scope=filter` with the list filters; `format=yar` (default) or `zip`; removed rules are skipped; nothing to export → back to the list with a message |
| Rule detail | `rules:rule_detail` | `/rules/<id>/` | `view_rule` | highlighted source with line numbers and copy button, compile error / warnings in `<pre>`, meta (booleans as `true`/`false`, floats in plain decimal notation, never an exponent: `meta_value` filter), tags, imports, ruleset, timestamps, hashes (one line, truncated with the full value in `title` and a copy button; a full row of the details card at ≥ 1280 px), version list; actions edit, download, delete |
| Download rule | `rules:rule_download` | `/rules/<id>/download/` | `view_rule` | `<name>.yar` |
| New rule | `rules:rule_create` | `/rules/new/` | `add_rule` (+ `add_ruleset` when it creates a new manual collection) | target: the manual collections, the ruleset given by `?ruleset=<id>`, or a new collection name (trimmed, ≤ 100 chars, refused when `names.has_control_characters` is true); "Validate" (no writes) and "Save". A new name goes to the services as `editing.manual_ruleset(name, save=False)`: `validate_rule_text` checks against it and `create_rule` creates it in the rule's transaction, so a refused save leaves no collection; `add_ruleset` is required only when that name does not exist yet |
| Edit rule | `rules:rule_edit` | `/rules/<id>/edit/` | `change_rule` | same editor; the hidden `version` field is passed to `editing.update_rule` as `expected_version` (the service is the only check). On a `conflict` result the text stays in the editor, the page says someone else changed the rule and lists the versions saved meanwhile (links to their pages and diffs), and the form now carries the current version: the button reads "Save over version N", so the next save overwrites deliberately after merging by hand. A rule deleted meanwhile is reported without Save. A name taken meanwhile is an ordinary "Not saved" error |
| Version | `rules:rule_version` | `/rules/<id>/versions/<n>/` | `view_rule` + `view_ruleversion` | diff against the previous version, source, previous/next links, link to the current version, "Restore this version" form carrying the rule's version as shown (`version`) |
| Restore | `rules:rule_restore` | `/rules/<id>/versions/<n>/restore/` | `change_rule`, POST only | posted `version` → `editing.restore_version(..., expected_version=)`; missing → refused ("page out of date"); conflict → back to the version page with a message linking the current version; rule deleted meanwhile → its ruleset; other refusals (e.g. no longer compiles) shown as an error message |
| Delete rule | `rules:rule_delete` | `/rules/<id>/delete/` | `delete_rule` | GET confirmation page, POST deletes rule and history |
| Rulesets | `rules:ruleset_list` | `/rulesets/` | `view_ruleset` | search name/path, origin filter, sort (name, changed, imported, rule count), counts and compile status per ruleset |
| Ruleset detail | `rules:ruleset_detail` | `/rulesets/<id>/` | `view_ruleset` | rules in file order (removed last), details, add rule, downloads, delete |
| Download ruleset | `rules:ruleset_download`, `rules:ruleset_original` | `/rulesets/<id>/download/`, `/rulesets/<id>/original/` | `view_ruleset` | rebuilt from current rules / verbatim file as last imported |
| Delete ruleset | `rules:ruleset_delete` | `/rulesets/<id>/delete/` | `delete_ruleset` | GET confirmation, POST deletes ruleset, rules and history (`editing.delete_ruleset`) |
| Import | `rules:import` | `/import/` | `view_importrun` | history for everyone; for Editors the directory card (configured path; counts from `importer.rule_files`, i.e. exactly what the import processes: files to import, plus files that will be skipped and recorded as failed, grouped by their `error` with the paths; last directory scan; button disabled, and the POST refused, when the directory is missing or nothing is importable) and the multi-file upload with drag and drop (help text shows `importer.max_file_bytes()`, read per request) |
| Directory import | `rules:import_scan` | `/import/scan/` | `import_rules`, POST only | always `settings.YARADUDE_RULES_DIR`, never a path from the request |
| Upload import | `rules:import_upload` | `/import/upload/` | `import_rules`, POST only | form field `rule_files` (multiple) |
| Import run | `rules:import_run` | `/import/runs/<id>/` | `view_importrun` | counters and changed/failed files; rows whose ruleset was deleted still render |
| Test scan | `rules:scan` | `/scan/` | `scan_rules` | upload a sample (memory only, never stored or logged); optional `path` limit (same semantics as the rules list) with a GET "Check limit" that shows how many rules it covers; results with matched rules, string instances (offset, length, hex/ASCII preview), rules left out because they do not compile; scan errors shown on the form |
| Admin | `admin:index` | `/admin/` | staff | users, groups, raw data; rule and version content is read-only there, rules are edited in the UI (no UI text points to the admin for that) |
| Health | `healthz` | `/healthz/` | public | checks the database |

Error pages `400.html`, `403.html` (explains roles; a user in no group is
told to ask for Viewers or Editors), `403_csrf.html`, `404.html` and
`500.html` live in `rules/templates/` and extend the base layout (they work
without a request context). `TEMPLATES["DIRS"]` lists `accounts/templates`
so the styled `registration/` templates win over the admin's.

Code layout: `rules/views/` (package: `base`, `dashboard`, `rules`,
`rulesets`, `imports`, `scan`), `rules/forms.py`, `rules/urls.py`,
`rules/templatetags/yaradude.py` (`ts` timestamp filter, `rule_status`,
`highlight`, `query`/`sort_header` querystring helpers, `basename`),
`rules/templates/`, `rules/static/rules/js/app.js` (select-all and selection
count, copy buttons, Tab/Shift+Tab indent in the editor with Esc to leave,
drag and drop into the file input, busy state on long forms, closing the
account menu), `rules/static/rules/img/` (SVG mark and favicon).

List pages keep a constant number of queries (asserted in tests) and never
select large text columns (`Rule.source`, `Ruleset.original_content`) for a
page of rows; sorting a page of 100 out of 10,000 rules costs the same at
page 1 and page 100.

### 7.2 Design tokens

Defined once in `rules/tailwind/yaradude.css`: colours as CSS custom
properties (`--yd-*`) switched by `prefers-color-scheme`, exposed to
Tailwind through `@theme inline` as `bg`, `surface`, `subtle`, `line`,
`line-strong`, `fg`, `muted`, `faint`, `accent` (teal), `accent-strong`,
`accent-soft`, `on-accent`, status colours `ok`, `error`, `warn`,
`modified`, `removed` (each with a `-soft` background) and `code`; type
scale 12/13/14/16/20/24 px (`text-xs` … `text-2xl`, base 14 px); spacing is
Tailwind's 4 px scale; system sans and mono font stacks only. Small
component classes (`btn`, `card`, `badge-*`, `data-table`, `meta-list`,
`diagnostic`, `diff`, `dropzone`, `chip`, `pager`, …) and the Pygments
token colours for `.highlight` are in the same file. Templates use no
`dark:` variants.

### 7.3 Building the CSS (Tailwind standalone CLI)

- Tool: `django-tailwind-cli==4.9.0` (uv **dev** group only) providing the
  `manage.py tailwind …` commands; `config/settings.py` adds
  `django_tailwind_cli` to `INSTALLED_APPS` only when it is importable, so
  the production image (no dev group) contains nothing that can download.
- Tailwind version pinned: `TAILWIND_CLI_VERSION = "4.3.5"` (never
  `latest`, which would query github.com). `TAILWIND_CLI_AUTOMATIC_DOWNLOAD
  = False` (hard-coded): `build` and `watch` never download; with the binary
  missing they fail at once, without any network access, with "Automatic
  download of Tailwind CSS CLI is deactivated. Please download the Tailwind
  CSS CLI manually."
- Binary location: directory `TAILWIND_CLI_PATH` = env
  `YARADUDE_TAILWIND_CLI_PATH`, default `<repo>/.tailwind/` (must be
  git-ignored). In a directory the package expects the file
  `tailwindcss-<os>-<arch>-4.3.5` (e.g. `tailwindcss-linux-x64-4.3.5`,
  `tailwindcss-linux-arm64-4.3.5`, `tailwindcss-macos-arm64-4.3.5`), mode
  0755. `YARADUDE_TAILWIND_CLI_PATH` may instead name the executable itself.
- Fetching the binary (explicit, connected machine only):
  `uv run python manage.py tailwind download_cli` (downloads exactly the
  pinned version for the current platform). Images download the release
  asset directly instead: from
  `https://github.com/tailwindlabs/tailwindcss/releases/download/v4.3.5/<asset>`
  with assets `tailwindcss-linux-x64` (amd64) and `tailwindcss-linux-arm64`
  (arm64), the glibc builds for Debian (not the `-musl` ones), saved as
  `tailwindcss-linux-<x64|arm64>-4.3.5`. Checksums are published in the
  release as `sha256sums.txt` (same URL prefix); the GitHub API digests for
  v4.3.5 are `linux-x64`
  `e47695cee3f0d90623a91f3939b08bdee610eb5ad99340adff9d4145b284d6cc`,
  `linux-arm64`
  `ffcd0d21dbd7c605dc12743ff0c0b47debc963c86b399674084c1c8f2c96ecad`,
  `macos-arm64`
  `f3f4f5d1727e2b693b8f1c9a1492b5dd87008c86ea286bee1589cb458e6235fc`.
- Input: `rules/tailwind/yaradude.css` (outside every static directory, so
  it is never collected). It scans `rules/templates`, `accounts/templates`,
  `rules/static/rules/js`, `rules/templatetags`, `rules/forms.py` and
  `rules/views` for class names (`@import "tailwindcss" source(none)` plus
  explicit `@source` lines).
- Output: `rules/static/rules/css/yaradude.css`, linked with plain
  `{% static 'rules/css/yaradude.css' %}`. `STATICFILES_DIRS =
  [("rules/css", BASE_DIR / "rules/static/rules/css")]` exists only because
  the package writes below `STATICFILES_DIRS[0]`; it is the same directory
  the app finder serves, so collectstatic sees that one file twice (harmless).
- Not minified (`TAILWIND_CLI_AUTOMATIC_MINIFY = False`): `watch` cannot
  minify, so `build` and `watch` produce byte-identical output; WhiteNoise
  serves it compressed.
- **The output is committed.** Tests, `collectstatic` and the production
  image need neither the binary nor the network. After changing templates,
  JS or the input CSS run `uv run python manage.py tailwind build` (or keep
  the watcher running) and commit the result. A test rebuilds the CSS to a
  temporary file when the binary is present and fails if the committed file
  is stale (skipped when the binary is absent).
- Commands: build `uv run python manage.py tailwind build`; watch
  `uv run python manage.py tailwind watch`; dev server plus watcher
  `uv run python manage.py tailwind runserver [addr:port]`.
- The production build stage does not need the binary (the CSS is
  committed); the offline dev image needs it at `YARADUDE_TAILWIND_CLI_PATH`
  for `watch`.

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
| `YARADUDE_MAX_RULE_FILE_BYTES` | 4 MiB | per-file limit for imported rule files (directory, upload, archive members); was a fixed 10 MiB. Parse plus compile costs about 1 s per MiB; the largest real file seen is about 1 MiB |
| `YARADUDE_DB_CACHE_MIB` | 16 | SQLite private page cache per connection (`PRAGMA cache_size`) |
| `YARADUDE_DB_MMAP_MIB` | 256 | SQLite memory map of the database file (`PRAGMA mmap_size`); shared OS page cache |
| `YARADUDE_DB_CONN_MAX_AGE` | 0 (3600 in task workers) | Django `CONN_MAX_AGE` in seconds |
| `YARADUDE_DB_MAINTENANCE_INTERVAL` | 600 | seconds between `PRAGMA optimize` + truncating WAL checkpoint on the maintenance queue (0 = off) |
| `DJANGO_SUPERUSER_USERNAME` / `_PASSWORD` / `_EMAIL` | unset | first-admin bootstrap |
| `YARADUDE_SITE_ADDRESS` | `localhost` | Caddy site address |
| `YARADUDE_TLS` | `internal` | Caddy `tls` directive arguments: `internal` (Caddy's own CA) or `/certs/cert.pem /certs/key.pem` |

SQLite is configured for a web workload: WAL journal, `IMMEDIATE`
transactions, a busy timeout. Every connection of every process (web, task
workers, management commands) also runs `cache_size` (16 MiB),
`mmap_size` (256 MiB), `temp_store=MEMORY` and `journal_size_limit`
(64 MiB) from `init_command`; `rules/tests/test_database.py` reads them
back from a real connection. Sizing: the memory map is file-backed and
shared by all processes, so it does not multiply; the page cache is private
per connection and fills only with pages not served by the map, worst case
(web processes × DB threads + workers + commands) × 16 MiB, e.g. 12 × 16 =
192 MiB. With the map, 16 MiB measured the same as 32 and 64 MiB.
Persistent connections: off for the web server, because under the ASGI
server (uvicorn) Django runs every request in a fresh thread, so a kept
connection is never reused — measured: 5 requests opened 5 connections with
`CONN_MAX_AGE` 0 and with 600; the memory map keeps fresh connections warm
instead. Task workers (`run_worker`, `db_worker`) are single-threaded, poll
every 50 ms and call `close_old_connections()` each time, so they keep one
connection for an hour (otherwise 20 reconnects a second). Health checks are
on (a no-op for SQLite). After restoring a database file, restart all
processes (a kept connection would still see the old file).
`PRAGMA optimize` runs after every import run and, with a truncating WAL
checkpoint, in `rules.tasks.database_maintenance` every 10 minutes on the
maintenance queue; SQLite's own passive checkpoints never shrink the WAL,
and `journal_size_limit` caps it after each reset. Measured on the
10,231-rule copy through Django, median per request, fresh connection per
request as the web server does (before → after): rules list page 50
4.6 → 3.5 ms, failing-rules count 0.8 → 0.8 ms (partial index), substring
over source 15.0 → 12.6 ms, FTS search 1.1 → 1.2 ms; with a kept
connection (task workers) 2.2, 0.19, 10.0 and 0.41 ms. Static files are served by WhiteNoise with
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
- **Scan speed is a top priority.** Scanning one small file against all rules
  took 12.8 s in the app, all of it loading sources and compiling. Engine
  measurements with the same rules: compile 4.3 s; serialised size 11.4 MB,
  written in 0.01 s and loaded in 1.1 s; one pass over all rules 2–3 ms for a
  151 KB sample and 0.58 s for 67 MB of real binaries (about 110 MB/s);
  reusing a scanner or `fast_scan` changes nothing; and `yara_x` holds the
  GIL while scanning, so four scans in four threads take four times as long
  as one and block the process meanwhile. The design that follows:
  - A scan request never compiles. One compiled set of all active, compiling
    rules is rebuilt when rules change (after imports and edits, and by the
    watcher process), stored as a file beside the database with a fingerprint
    and engine version, and loaded by each server process.
  - Scans answer at once from the newest complete set. If a rebuild is still
    running, the previous set is used and the result says which revision it
    reflects.
  - A scan limited by ruleset, path or tag uses the full set and filters the
    matches; nothing is compiled for a subset.
  - One pass, never one pass per ruleset (20–60 times slower).
  - Scans run where a large one cannot stall other requests or queue behind
    another scan (worker processes, because of the GIL).
  - Targets with a warm set: under 20 ms server time for a sample under 1 MB
    against about 10,000 rules; within 20% of raw engine time at 64 MB.
  - Rules with slow-pattern warnings are listed so they can be dealt with.
  - **Compile caching, as built (2026-11-19).** The compiled rule set is
    cached as one file (about 12 MB for 10,286 rules) and reused by every
    scan; nothing is recompiled per scan. Measured through the real scan page
    on the development preview: 16 ms for a 151 KB sample (was 12.8 s), 31 ms
    for 1.3 MB, 0.24 s for 28 MB. What is not cached is the rebuild itself:
    any rule change triggers a full recompile of all rules (about 7 s) in the
    background, during which scans keep answering from the previous set.
    Ideas to cut that, not yet investigated: batch changes that arrive close
    together into one rebuild; cache per-ruleset compile results so that only
    changed rulesets are recompiled — which needs checking whether YARA-X can
    combine separately compiled units into one set at all, since scanning
    ruleset by ruleset was measured 20–60 times slower than one pass.
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
  **Done (migrations 0004, 0005):** partial indexes on `name` for failing,
  removed, warnings and modified rules, each with exactly the condition the
  list filter generates (deleted-aware since 0005), and one on `deleted_at`
  for the Deleted view. No stored "has warnings" boolean was needed: SQLite
  matches a partial index whose condition is `NOT (compile_warnings = '[]')`
  also with bound parameters (checked on 3.51 and on the base image's
  3.40.1). `EXPLAIN QUERY PLAN` of the list query for each status shows
  `SCAN rules_rule USING INDEX rule_<status>_name_idx`; page plus count fell
  from 6–96 ms to 0.4–8 ms. The dashboard's single `aggregate()` with five
  filtered counts cannot use partial indexes (one pass over the table);
  separate `.count()` queries per status would.
- Add `(ruleset, position)` for rules in file order. **Done**; used by
  compile checks and edit validation (`SEARCH … USING INDEX
  rule_ruleset_position_idx (ruleset_id=?)`, no sort). The ruleset page
  orders by `removed_at` first and still sorts its few rows.
- **Full-text search — done (migration 0004, `search.py` in 5.7).** An
  external-content FTS5 table (`detail=full`, about 18 MiB for 13.5 MB of
  rule text), triggers on insert/update/delete of `rules_rule`, recreated by
  a post_migrate handler because Django's table rebuilds drop triggers.
  Search for a page of 50 plus count on the 10,231-rule copy: 34–46 ms with
  LIKE, 0.8–2 ms with FTS (12.7 ms for a 4,193-row result). Original text:
  Substring search over rule
  name, description, author and source cannot use an ordinary index (20 ms
  now, linear in total rule text). It moves to SQLite FTS5 with the trigram
  tokenizer: the index is created and populated in a migration, kept in sync
  with the rule table on every write path, rebuildable by a management
  command, and exposed as a search service that returns a queryset with
  optional relevance ordering. User input is treated as literal text, never
  as FTS query syntax; terms shorter than three characters fall back to the
  plain substring match. A check fails clearly at startup if the SQLite build
  lacks FTS5 or the trigram tokenizer (needs SQLite 3.34 or newer).
- The collection filter by path prefix scans; if collections become a main
  navigation axis, store the collection name in its own indexed column
  instead (revisit the "path prefix, not a model" choice in 12.2).
- No planner statistics exist; run `PRAGMA optimize` after import runs.
  **Done** (`importer.optimize_database()` after every run).
- Three single-column foreign-key indexes duplicate the leading column of a
  unique constraint (`rule.ruleset`, `ruleversion.rule`, the tag join table's
  `rule`). Harmless; leave unless write speed becomes a concern.

### 12.6 Watching the rules directory
The rules directory is watched, and rule files that are not in the database
yet are imported without anyone pressing "Scan and import".
- Each pass over the directory is a **task on Django Tasks**, run by the same
  worker infrastructure as scan jobs (12.9), not a separate daemon. It runs
  **periodically** on an interval: the directory is a bind mount or network
  share in containers, where file-change events are unreliable. Django Tasks
  has no scheduler of its own, so recurrence comes from one shared mechanism
  owned by the task infrastructure: exactly one pending pass exists at any
  time, a finished or failed pass schedules the next, and a missing schedule
  (after a crash or a restart) is detected and restored. A management command
  runs a single pass on demand.
- Directory passes and other maintenance work (rebuilding the compiled rule
  set) use their own queue, separate from scan jobs, so a long first import
  cannot delay scans and scans cannot starve the watcher.
- An idle pass is cheap: candidates are found by path, size and modification
  time, and only new or changed files are read, hashed and imported. An idle
  pass creates no import run; a pass that imports something creates one run
  with origin `watch`, attributed to "directory watcher".
- A file is picked up only after it has been stable for a settle time, so a
  file still being copied in is not imported half-written. A file that fails
  is recorded once and not retried until it changes on disk.
- New and changed files follow the same rules as the manual scan (changed
  rules get a new version, local edits survive as specified); a file that
  disappears from disk changes nothing.
- It tolerates a locked database, a temporarily missing directory and
  shutdown signals, and never runs two passes at once.
- The Import page shows the watcher's state: last pass, what it found, last
  error, or that it is not running.
- Settings: the polling interval (0 turns the watcher off) and the settle
  time.

### 12.7 Live test-scan results over a WebSocket
The test scan reports progress and matches as they are found instead of
after the whole scan.
- **What "live" can mean with YARA-X.** The Python API returns the results of
  one `scan()` call all at once; it has no per-match callback, and one pass
  over all rules is by far the fastest way to scan (section 12.4). So the
  live scan uses the single pass and streams the phases as they happen —
  upload received, waiting for or loading the compiled set, scanning,
  finished — and the matches the moment the pass returns. With a warm
  compiled set that is milliseconds for small samples and under a second for
  64 MB.
- **Transport.** Django Channels on ASGI, with the consumer running the scan
  in a worker thread and writing to its own connection. No channel layer and
  no Redis: nothing crosses processes, which keeps the air-gapped stack to
  the same two containers.
- **Flow.** The browser opens `/ws/scan/`, sends the scan options and then the
  sample as binary frames; the server holds it in memory only (same size
  limit as today, enforced on bytes received), runs the batches and sends
  typed JSON events: started, progress, match, rules left out, finished,
  error. Closing the page cancels the scan between batches.
- **Security.** A WebSocket bypasses the HTTP middleware, so the consumer
  itself requires a signed-in user with `scan_rules`, validates the `Origin`
  header against the allowed hosts (the WebSocket equivalent of CSRF
  protection), allows one scan at a time per connection, and applies message
  size, total size and time limits. `connect-src 'self'` in the CSP.
- **Fallback.** The existing form POST stays and works without JavaScript;
  the page upgrades to the live view when JavaScript and the socket are
  available.
- **Consequences for deployment.** The app server changes from gunicorn
  (WSGI) to an ASGI server; Caddy proxies WebSockets without extra
  configuration. New dependencies must have wheels for linux amd64 and arm64
  and go into the offline wheel cache. Sections 8.2 and 8.5 follow this.
- **Showing what is being scanned right now.** YARA-X does not go through
  rules one by one: one pass matches the sample against all compiled rules at
  once, so inside a pass there is no "current rule". Measured on 2026-11-19
  with the three real rule sets (10,219 rules, 2,121 files): compiling
  everything takes 4.4 s in one piece or 6.8 s file by file; once compiled,
  one pass over all rules takes 0.01 s for a 151 KB sample and 0.09 s for
  20 MB, and one pass per rule file takes 0.2 s and 5.5 s in total. The time
  a user waits is therefore almost all compilation, and after caching a scan
  is near-instant. **Speed and a step-by-step display pull in opposite
  directions**: showing the ruleset currently being scanned means one pass
  per rule file, 20–60 times slower than the single pass, and a per-rule
  indicator one pass per rule, slower again. Speed has priority, so neither
  is built; the event format leaves room for an optional "step through
  rulesets" mode if it is wanted later for demonstration.

### 12.9 Scan jobs on Django Tasks
Several users can scan several samples at the same time. Scans run as tasks
on Django's Tasks framework (`django.tasks`, new in Django 6.0), executed by
worker processes separate from the web server.
- **Why it fits.** The engine holds the GIL during a scan (12.4), so scans in
  the web process block it and queue behind each other. Worker processes,
  each holding the compiled rule set, give real parallelism and keep the web
  process responsive. Django itself ships only an immediate and a dummy
  backend; a backend with real workers and a queue stored in SQLite has to be
  chosen and verified against the installed versions (no Redis, no broker:
  the deployment stays self-contained).
- **Scan jobs.** A scan is a job row: who submitted it, sample name, size and
  SHA-256, options (limit by path or tag), state (queued, running, finished,
  failed), timings and the result. One upload of several samples creates one
  job per sample. Jobs and results are **shared with the team**: everyone
  with the scan permission sees all jobs, who submitted each, and the
  results, so analysts can read each other's findings. Results are kept for a
  configurable time (default 30 days), then deleted.
- **The sample has to reach a worker process**, so it can no longer live only
  in the memory of one request. It is written to a private spool directory
  (unpredictable name, owner-only permissions, on the data volume), read by
  the worker, and deleted as soon as the scan ends, whatever the outcome; a
  sweep removes leftovers from crashed workers. Sample bytes never go into
  the database, the task arguments, the results or the logs. This replaces
  the earlier "never written to disk" rule for scans that go through jobs.
- **Speed.** A queue adds latency that a 3 ms scan does not need. So a single
  small sample (size threshold in settings; 0 sends everything through the
  queue) is scanned at once in a dedicated in-process path and still recorded
  as a finished job; larger samples and multi-sample uploads are queued.
  Queue latency (submit to start) is measured and kept low by how workers
  wait for work.
- **Live updates.** The WebSocket of 12.7 reports job state changes and
  results for the jobs a user has open; without JavaScript the jobs page
  refreshes itself.
- **Deployment.** One more Compose service on the same image for the scan
  workers (count is a setting), beside web, the directory watcher and Caddy.

### 12.11 Recoverable deletes
Deleting a rule or a ruleset in the UI or API no longer destroys it
(decided; replaces the hard delete with history loss).
- A deleted rule is flagged (when, by whom), hidden from the normal lists,
  and left out of scans, exports and the compiled rule set. It keeps its
  version history and can be restored. Deleting a ruleset does the same for
  the ruleset and all its rules, and restoring it brings them back.
- "Deleted" is distinct from "removed" (a rule that a newer version of its
  source file no longer contains), and both are shown as such.
- Deletion is sticky across imports: a rule or ruleset deleted here is not
  brought back because its file is imported again or changes on disk. The
  import run counts it as skipped (deleted locally). Restoring it makes it
  follow its file again.
- A deleted rule still occupies its name within its ruleset; creating a rule
  with that name is refused with a pointer to restore or purge.
- **Purging** — permanent deletion with history — is a separate action behind
  its own permission, held by administrators and by neither role group.
- A "Deleted" view lists deleted rules and rulesets with who deleted them and
  when, with restore and (for those allowed) purge.
- **As built (service layer, migration 0005).** `deleted_at` / `deleted_by`
  on `Rule` and `Ruleset`, plus `Rule.deleted_with_ruleset` so restoring a
  ruleset brings back exactly the rules deleted with it. The default
  managers hide deleted rows everywhere; `all_objects` reaches them.
  Imports match deleted rules like others but never write them (counted in
  `rules_skipped`); a file of a deleted ruleset is skipped whole
  (`files_skipped`, an `ImportFile` with status `skipped` when its content
  changed). Restore brings back the stored content and clears the
  ruleset's file hash, so the next import re-reads the file and, if it moved
  on, updates the rule under the normal rules (local edits survive while
  the disk version of that rule is unchanged). Delete, restore and purge
  move the rules revision. The admin follows the same rules: delete is
  recoverable, "restore" and "purge" are list actions, purge only with the
  permission.

### 12.10 `yarad`, the command-line scan client for workstations
One small Python script, named **`yarad`**, that people run on their own
machines to scan files against yaradude's rules, using the API and a personal
API key. It is a command-line program driven by subcommands and flags
(`yarad configure`, `yarad scan [--local | --server] [--recursive] [--json]
FILE...`, `--help`, `--version`), not a library: it exposes nothing for other
code to import. "yarad" is the only name a user sees, including for its
per-user configuration and cache folders.
- **One file, standard library only**, for a stock Python 3 on Windows, macOS
  and Linux; no installation step. Configured once (server address, API key,
  optional CA certificate for the internal TLS certificate) through a
  `configure` command or environment variables; the key is stored in a file
  only its owner can read. TLS verification is never switched off silently.
- **Server mode (default).** The files are uploaded to the API and scanned on
  the server; the script prints the matches. Works for single files, several
  files and directories, with human-readable or JSON output and exit codes a
  script can test (no match / match / error).
- **Local mode.** The script downloads the server's compiled rule set and
  scans on the workstation, so files never leave it and repeated scans are
  fast. The download is cached and only fetched again when the rules change.
  Scanning locally needs a YARA-X engine on the workstation, which the script
  cannot contain. **The engine is served by yaradude** (decided): an
  administrator places the official `yr` binaries for Windows, macOS and
  Linux, in the server's engine version, in a folder on the server; the API
  lists them with platform, version and SHA-256, and the script downloads the
  one matching the workstation, verifies the checksum, caches it in the
  user's own directory and runs it. That works inside the air gap and
  guarantees the compiled rule set loads, since a compiled set only loads in
  the engine version that produced it. If no binary for the platform is on
  the server, the script says so and offers server mode; a `yr` or `yara-x`
  already installed is used only if its version matches.
- **Server side.** An API endpoint serves the compiled rule set with its
  revision, engine version and checksum, plus the mapping from compiled
  namespaces back to rulesets, to anyone allowed to export rules. The script
  itself is downloadable from the API documentation page.

### 12.8 HTTP API with personal API keys
Everything that can be done in the UI can be done by a script.
- **Keys.** Each user creates, names and revokes their own API keys on an
  account page. A key is shown once at creation and stored only as a hash,
  with a short visible prefix to recognise it, creation time, last-used time
  and optional expiry. A key acts as its user: the same Viewer/Editor
  permissions apply, and changes made with it are attributed to that user.
- **Authentication.** `Authorization: Bearer <key>` only. No cookies on the
  API, so no CSRF surface; an invalid, expired or revoked key gets a JSON
  `401`, a missing permission a JSON `403`, never a redirect to the sign-in
  page. Keys are never logged. Per-key rate limiting.
- **Surface (versioned under `/api/v1/`, JSON).** Rules: list with the same
  search, filters, sorting and pagination as the UI, detail, create, edit
  (with the version check), delete, validate without saving, versions, diff
  and restore, download. Rulesets and collections: list, detail, download
  (rebuilt and original), delete, archive export. Tags. Import: upload rule
  files and archives, start a directory scan, list and read import runs.
  Test scan: upload a sample and get the matches. Account: who am I.
- **Same code paths.** API views call the same services as the UI; no
  business logic is written twice.
- **Documentation.** An OpenAPI description served by the app, and an API
  page in the UI with a copyable `curl` and Python example for every
  endpoint, using the address the user is browsing from. Everything is
  served locally; no external documentation assets.
- Endpoints for features that are still being built (full-text search,
  archives, attribution, the directory watcher's state, live scan) are added
  as each lands.
- **As built (app `api/`, migration `api/0001`).** Status and open items:
  `docs/status/api.md`.
  - *No API framework* (plain Django views). Checked on 2026-11-19 from
    installed wheels: DRF 3.18.3 (Django 6.1 / Py 3.13 OK, pure Python, but
    its browsable API uses inline scripts and its OpenAPI generator needs
    drf-spectacular + 4 more packages), django-ninja 1.8.0 (Django 6.1 OK,
    needs pydantic-core, a compiled wheel present for linux amd64/arm64; its
    docs pages fall back to a CDN when `ninja` is not an installed app, and
    redoc.html has an inline script). Both would duplicate the UI's form
    validation in their own schemas. Plain Django reuses the UI's forms and
    query functions unchanged, adds no dependency to the air-gapped bundle,
    and has no bundled HTML to police under the CSP.
  - One declaration per endpoint (`api.registry.endpoint`) generates the URL
    patterns, the dispatch (Bearer auth → rate limit → method → permission,
    before any lookup), the OpenAPI 3.1 document (`/api/v1/openapi.json`),
    the documentation pages (`/api-docs/`, one page per UI group) and their
    curl / Python examples. Tests run every Python example and parse every
    curl example against the routes, and check every API answer in the test
    suite against the documented status codes and JSON schemas.
  - Keys `yd_<12 hex public id>_<43-char secret>`, 256-bit secret, only
    SHA-256 stored, `hmac.compare_digest`; last use written at most once per
    `YARADUDE_API_KEY_TOUCH_SECONDS` (300) with a conditional UPDATE.
  - Rate limit: per-key token bucket in `flock`ed files
    (`YARADUDE_API_RATE_DIR`, local filesystem), exact across all worker
    processes of one host; not shared across hosts/containers.
  - Deviation: the Python examples use a small standard-library helper
    module (`yaradude_client.py`, served from the docs page) rather than
    `requests`, because analyst machines in the air gap may lack `requests`.
  - Shared query logic: rules list/export reuse `filtered_rules` and
    `RuleFilterForm`; the dashboard reuses `DashboardView`'s context. The
    rulesets list/detail could not reuse `rules.views.rulesets` because its
    `with_counts` counts deleted rules over a join; the API has its own
    corrected copy until that is fixed and a `filtered_rulesets(values)`
    function is extracted.

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

**Status (service layer, 2026-11-19).** Findings 1–9 and the smaller items
are fixed, each with a test that fails on the old code: 1 parser rewrite and
import phases (sections 5.1, 5.3), 2 `expected_version` and conflict results
(5.7), 3 `imported_name` matching (5.3), 4 per-file error handling (5.3),
5 CRLF normalisation (5.1; migration 0002 converted the existing CRLF rows
and remapped their hashes, so nothing turned "modified"), 6 admin content
read-only, versions/tags/import history read-only, admin deletes through the
editing service (the scanner part moved to the scan-pipeline package),
7 symlinks (5.3), 8 float meta (5.1), 9 export comments and member names
(5.7 `exporter.py`, `names.py`; forms reject control characters with
`names.has_control_characters`). `ensure_roles` honours `using`;
`ensure_superuser` refuses a password the validators reject (an error, not a
warning: the account has every permission, the command runs unattended
where a warning goes unread, and refusing changes nothing that exists);
`check --deploy` runs as a test in a subprocess with production variables.
