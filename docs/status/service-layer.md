# Service layer — status (2026-11-19)

Owner of: `config/` (except `asgi.py`, now the scan agent's), `accounts/*.py`,
`rules/models.py`, `rules/migrations/`, `rules/admin.py`, `rules/apps.py`,
`rules/tasks.py`, `rules/services/` (except `scanner.py`), `rules/management/`,
and the tests `rules/tests/test_{parser,compiler,importer,exporter,editing,models,commands,revision,search,database}.py`,
`rules/tests/helpers.py`, `accounts/tests/`, `config/tests.py`.
PLAN.md section 5.7 matches the code as it stands.

## Verified at hand-over
- `manage.py check`: no issues. `makemigrations --check --dry-run`: no changes.
- My test modules (`rules.tests.test_parser … test_database`, `accounts`,
  `config`): 227 tests, OK. `ruff check`, `ruff format --check`, `ty check`
  on my paths: clean.
- `check --deploy --fail-level WARNING` with production variables: no issues
  (also run as a test in `rules/tests/test_commands.py`, subprocess).
- Full suite: 535 tests, 4 failures, all in UI-agent test files (see "Failing
  tests").

## Finished
### Stage 1 — review findings (PLAN.md 13)
Each fix has a test that was confirmed to fail on the original code (old
service files restored into a scratch copy: 43 failures/errors).
1. Large files — `parser.py` rewritten as a lazy tuple tokenizer (no
   whitespace tokens, meta tokens only, referenced names in one pass);
   importer reads/hashes/parses/compiles before the write transaction and
   re-plans inside it. 10 MiB synthetic file (17,088 rules): parse 10.35 s /
   836 MiB RSS / 752 MiB traced → 2.94 s / 88 MiB RSS / 43 MiB traced.
   Setting `YARADUDE_MAX_RULE_FILE_BYTES` (default 4 MiB, was fixed 10 MiB).
   Tests: `test_parser.LargeInputTests`, `test_importer.TransactionScopeTests`.
2. Concurrent edits — `update_rule`/`restore_version(..., *, expected_version=None)`,
   re-read inside the transaction, `EditResult.conflict`; never IntegrityError.
   Tests: `test_editing.ConcurrentEditTests`.
3. Rename then re-import — `Rule.imported_name` (match by imported name,
   then imported hash, then name for manual rules). `test_importer.RenameThenReimportTests`.
4. One bad file — per-file catch, failed `ImportFile` without content, logged
   traceback, counters saved per file, run always finished. `RobustRunTests`.
5. Line endings — `parser.normalize_newlines` (CRLF→LF) in `parse`; migration
   0002 converted the 129 CRLF rules/versions of the preview and remapped
   hashes (none turned "modified"). `LineEndingTests`, `ParseTests.test_crlf_line_endings`.
6. Admin — content read-only, no add; versions/tags/import history
   read-only; deletes go through services. `test_models.AdminContentIsReadOnlyTests`.
   (Scanner crash part handed to the scan agent: one `by_key.get` +
   `continue` edit in `scanner.py`, reported.)
7. Symlinks — `importer.rule_files`: directory links not descended; file
   links followed only inside root, re-checked at read; links outside or
   dangling are listed with `error` and recorded as failed. `SymlinkTests`.
8. Float meta — accepted. `ParseErrorTests.test_float_meta_values`, `FloatMetaImportTests`.
9. Export — `names.py` (`single_line`, `safe_member_path`,
   `has_control_characters`); section comments and member names safe.
   `test_exporter.ExportInjectionTests`.
Small items: `ensure_roles(using=…)`; `ensure_superuser` runs the password
validators and refuses a weak password (error, not warning: unattended,
all-powerful account, refusing changes nothing existing); scaffold
docstrings replaced; `check --deploy` test. UI gaps: validation/creation
with an unsaved ruleset (`manual_ruleset(name, save=False)`),
`importer.rule_files(root)`.

### Rules revision (coordinator request)
`RulesRevision` single row (migration 0003), `revision.current()` (one PK
query), bumped only via `compiler.store_check(..., changed=True)` /
compile-status flips and `editing.delete_ruleset`/`purge_*`.
`test_revision.py` covers every write path and the no-ops.

### Stage 2 — indexes and full-text search
- Partial indexes on `name` for failing/removed/warnings/modified (deleted-aware),
  `(ruleset, position)`, partial `deleted_at` index. EXPLAIN on the 10,231-rule
  copy: each status list query uses `rule_<status>_name_idx`; page+count
  6–96 ms → 0.4–8 ms; compile-order query uses `rule_ruleset_position_idx`
  without a sort. No "has warnings" column needed (partial index matches).
- FTS5 trigram (`search.py`, migration 0004): triggers + post_migrate repair
  (Django table rebuilds drop triggers — happened with 0005 on the preview;
  repaired there by `migrate`). Search page+count 34–46 ms → 0.8–2 ms;
  ranked 10.9 ms (join via `.extra`). System check `rules.E001`; command
  `rebuild_search_index`. Verified FTS5 trigram and partial indexes in
  `python:3.13-slim-bookworm` (SQLite 3.40.1). `test_search.py`.
- `PRAGMA optimize` after every import run.

### Recoverable deletes (PLAN.md 12.11, migration 0005)
Soft delete/restore/purge services, default managers hide deleted rows,
`all_objects` reaches them, sticky across imports (`files_skipped`,
`rules_skipped`, `ImportFile.Status.SKIPPED`), purge permissions held by no
group, admin restore/purge actions. Tests in `test_editing.RecoverableDeleteTests`,
`test_importer.DeletedIsStickyTests`, `test_models`, `test_revision`.

### SQLite tuning (coordinator request)
`cache_size` 16 MiB, `mmap_size` 256 MiB, `temp_store=MEMORY`,
`journal_size_limit` 64 MiB on every connection; `CONN_MAX_AGE` 0 for web
(uvicorn opens a new connection per request regardless — measured 5/5),
3600 for `run_worker`/`db_worker`; recurring `rules.tasks.database_maintenance`
(optimize + truncating checkpoint, every 600 s). Numbers in PLAN.md 8.1.
`test_database.py` reads the PRAGMAs back from a real file connection.

## Migrations added (all apply with plain `migrate`; tested on preview copies)
- 0002 `imported_name_and_lf_line_endings` — field + data conversion of CRLF rows.
- 0003 `rules_revision` — new table (row created lazily on first change).
- 0004 `status_indexes_and_search` — indexes, FTS5 table, triggers, index fill (~2 s).
- 0005 `recoverable_deletes` — soft-delete fields, counters, permissions,
  index conditions. It rebuilds `rules_rule`, which drops the FTS triggers;
  the post_migrate handler in `rules/apps.py` restores them and rebuilds
  the index, so `migrate` must run (not only the migration executor).

## Assigned but not started
- 12.1 Attribution (`Rule.created_by/updated_by`, show/filter). Partial
  groundwork only: imports already pass `run.user` to
  `record_version(user=…)`, so import versions now carry `created_by`.
  Next step: add the two FKs (+migration), set them in `record_version`,
  `restore_rule` (its `user` argument is currently unused), and document
  `select_related` for lists.
- 12.2/12.3 Archives (upload and export). `importer.import_file(run,
  origin, path, read)` and `names.safe_member_path` are the intended
  building blocks. Open decision (12.5): store the collection as an indexed
  `Ruleset` column rather than only a path prefix — not decided yet.
- 12.6 Directory watcher as a recurring task. The scans recurring mechanism
  exists (PLAN.md 5.7 "Recurring tasks"); `rule_files()` returns size and
  `mtime_ns` for the cheap idle pass. Next step: store size/mtime/settle and
  failure state per path (model + migration), write the pure pass function,
  the `@recurring("YARADUDE_RULES_WATCH_INTERVAL")` task in `rules/tasks.py`,
  the single-pass command, origin `watch`, and status for the Import page.

## Failing tests (not in my files)
- `rules.tests.test_views_import.ImportPageTests.test_counts_agree_with_what_the_import_does`:
  expects `status.skipped == ["big.yar"]`; `rule_files()` now also lists
  `link.yar` (outside symlink), as the coordinator requested. Test needs
  updating by the UI agent.
- `rules.tests.test_views_rules.ExportTests.test_nothing_selected_redirects_back_with_filters`:
  redirect now carries `&sort=relevance` (UI agent's search wiring).
- `rules.tests.test_views_rules.RuleEditorTests.test_delete_confirmation_and_delete`
  and `rules.tests.test_views_rulesets.RulesetDetailTests.test_delete`:
  expect "cannot be undone"; deletes are recoverable now (UI rewiring in progress).
- Earlier in the session `test_views_tailwind` and the `api` tests failed
  intermittently while their owners were editing; not caused by service changes.

## Known issues / notes for other owners
- UI: `rules/views/rulesets.py` counts via `Q(rules__removed_at__isnull=True)`
  include individually deleted rules (joins bypass managers) — add
  `rules__deleted_at__isnull=True`. The version page still shows versions of
  a deleted rule. Tag lists include tags used only by deleted rules.
- The dashboard's single `aggregate()` cannot use the partial indexes;
  separate `.count()` queries would.
- Any future migration that rebuilds `rules_rule` drops the FTS triggers;
  they come back on `migrate` via post_migrate (do not apply migrations
  without it).
- `ty` reports errors in `rules/services/scanner.py` (scan agent's file).

## Decisions not yet seen by the owner
- Rename matching via `imported_name` (+hash fallback), no backfill; a local
  rename onto a name the file also uses fails that file with a message.
- Search keeps phrase semantics (words not AND-ed); non-ASCII case folded.
- All rules (removed and deleted too) are in the search index.
- Restore clears `Ruleset.sha256` so the next import re-reads the file.
- `update_rule` without `expected_version` expects the passed instance's version.
- Weak bootstrap superuser password is an error.
