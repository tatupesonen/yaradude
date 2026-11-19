# Web UI status (2026-11-19)

Owner: UI agent. Scope: `rules/views/`, `rules/forms.py`, `rules/urls.py`,
`rules/templatetags/`, `rules/templates/`, `rules/static/`, `rules/tailwind/`,
`accounts/templates/`, `rules/tests/test_views_*.py`, `rules/tests/test_permissions.py`.
The pages and URLs are listed in PLAN.md section 7.1.

## Finished and verified (tests pass unless listed under "Failing")

- **Edit conflicts (review finding 2).** The edit view passes the hidden
  `version` field to `editing.update_rule(expected_version=)`; the service is
  the only check.
  - On `conflict` the editor keeps the user's text, lists the versions saved
    meanwhile with links to their diffs, and the form then carries the current
    version ("Save over version N").
  - A rule deleted meanwhile is reported, with no Save button.
  - The version page's Restore form posts `version`, and the restore view
    passes it as `expected_version`.
  - Tests: `test_views_rules.EditConflictTests`, `RestoreConflictTests`.
- **New rule in a new collection.** Uses `editing.manual_ruleset(name, save=False)`.
  `add_ruleset` is needed only when the name does not exist yet. Names are
  refused when `names.has_control_characters` is true. Tests:
  `NewCollectionTests`, `test_permissions.NewCollectionPermissionTests`.
- **Import page.** Counts come from `importer.rule_files()`: files to import,
  plus files that will be skipped grouped by their error. The upload help shows
  `importer.max_file_bytes()`. Tests: `test_views_import.ImportPageTests`.
- **Float meta** is shown in plain decimal notation (`meta_value` filter).
  Test: `MetaRenderingTests`.
- **Rules table layout** fixed at 375–1440 px. This was checked in a real
  browser against a scratch copy of the preview DB on port 8799.
  - Name column at least 10rem; ruleset column from 640 px; updated from
    768 px; description and tags from 1024 px; on phones the ruleset is shown
    under the name.
  - Hashes take a full row of the details card at 1280 px and up.
- **Deletes are now described truthfully** (recoverable, PLAN 12.11).
  - Rule and ruleset delete pages and success messages say the item is hidden,
    kept with its history and can be restored, and that restoring is not yet
    available in the UI.
  - The views pass the user to `delete_rule` / `delete_ruleset`.
  - Tests: `test_views_rules.RuleEditorTests.test_delete_confirmation_and_delete`,
    `test_views_rulesets.RulesetDetailTests.test_delete`.
- **Full-text search.** The list's `q` filter uses
  `search.search_rules(rules, q, rank=sort == "relevance")`.
  - "Relevance" is offered, and is the default, only while `q` is set; the
    default option submits an empty value, so a new search starts by relevance.
  - `RuleFilterForm.values()` / `forms.default_sort(q)` hold that rule; the
    export "nothing to export" redirect drops the default sort.
  - Tests (`SearchTests`, written but **not run** after the last edits;
    coordinator asked not to rerun): hostile input (`"`, `AND`, `name:`, `-x`,
    `*`, `(OR`), service called with rank, relevance default and fallback,
    short input, query count and deferred columns with `q`.
- **Join leaks fixed** (code done):
  - `rules/views/rulesets.py` counts now exclude deleted rules
    (`NOT_DELETED`, `ACTIVE`, `REMOVED`).
  - Rules-list tag dropdown and dashboard tag count use
    `Tag.objects.filter(rules__deleted_at__isnull=True).distinct()`.
  - The version page and version restore look up `RuleVersion` with
    `rule__deleted_at__isnull=True`, so a deleted rule's versions now give 404.
  - Tests written: `test_views_rulesets.DeletedRuleCountTests`,
    `test_views_rules.DeletedRuleLeakTests`, plus 404 checks in the
    rule-delete test. Only the rule-delete test was run after the change;
    the other two were not.
- **Import run skipped counters** (code done, test written, not run):
  - `import_run.html` shows `files_skipped` / `rules_skipped` tiles, a
    "Skipped: deleted locally" explanation, the `SKIPPED` badge and a per-file
    skipped column.
  - The import history has a Skipped column (from 1024 px).
  - A file whose ruleset is deleted is shown unlinked as "(ruleset deleted)".
  - Test: `test_views_import.SkippedCounterTests`.

## Failing / not run, with cause

1. `test_views_import.ImportPageTests.test_counts_agree_with_what_the_import_does`
   fails: `status.skipped` is `['big.yar', 'link.yar']`.
   - Cause: `importer.rule_files` now returns a symlink pointing outside the
     directory, with `error` set (it used to drop it).
   - Next step: expect both files in `skipped`; check that the run records
     both as failed (`files_failed == 2`) or adjust to what `import_directory`
     does with them; check the page shows the symlink reason.
2. Not run after the last edits: `SearchTests`, `DeletedRuleLeakTests`,
   `DeletedRuleCountTests`, `SkippedCounterTests`, and the permission and
   security modules.
   - Next step: `uv run python manage.py test rules.tests.test_views_rules
     rules.tests.test_views_rulesets rules.tests.test_views_import
     rules.tests.test_permissions rules.tests.test_views_security
     rules.tests.test_views_tailwind`.
3. Other agents' tests, as of the last full run (`Ran 461 tests`,
   `failures=28, errors=1` before the delete fixes): `api.tests.*` (API
   agent) and `rules.tests.test_scanner.ScannerTests.test_sample_is_never_persisted`
   (scan pipeline agent). Not UI code.

## Remaining from the coordinator's search-and-deletes message

- **Relevance sort:** done, see above (tests not run).
- **Deleted page with restore and purge:** not built. A first draft was built
  and backed out untested.
  - Next step: new `rules/views/deleted.py` with:
    - `DeletedView` at `deleted/`, permission view_rule + view_ruleset: tabs
      "rules" (`Rule.all_objects.deleted().filter(deleted_with_ruleset=False)`)
      and "rulesets" (`Ruleset.all_objects.deleted()`), with who and when.
    - `RuleUndeleteView` / `RulesetUndeleteView`: POST, `change_rule` /
      `change_ruleset`; call `editing.restore_rule` / `restore_ruleset`.
    - `RulePurgeView` / `RulesetPurgeView`: GET confirmation + POST,
      `purge_rule` / `purge_ruleset`; look up via `all_objects.deleted()`; call
      `editing.purge_*`.
  - Wire the URLs in `rules/urls.py` and `rules/views/__init__.py`.
  - Link with a count from the rules and rulesets list headers (and optionally
    a dashboard tile).
  - Then make the delete pages and messages link to it.
  - Add the URLs to the PLAN 7.1 table and to `test_permissions` for
    anonymous / Viewer / Editor / a user holding the purge permissions.
- **Deleted state on direct URLs:** not built. Today a deleted rule or ruleset
  URL gives 404.
  - Next step: in `RuleDetailView` and `RulesetDetailView`, look up via
    `all_objects`; if `is_deleted`, render a `deleted_item.html` with Restore
    (and Purge for holders of the purge permissions).
  - The version page could do the same instead of returning 404.
- **Name held by a deleted rule on create/edit:** not built. The service's
  error text is shown, without a link.
  - Next step: in `_EditorView.render_result` (`rules/views/rules.py`), on
    failure look up
    `Rule.all_objects.deleted().filter(ruleset=target, name=result.parsed.name)`
    (and `target.is_deleted` for a deleted collection); pass it to
    `rule_form.html` with links to it and to the Deleted page.
- **Skipped counters on import runs:** done, see above (test not run).
- **Leaks through joins:** ruleset counts, version page and tag lists are
  done (tests not all run).
  - Also reviewed and found fine: dashboard aggregates (base queryset is the
    default manager), scan limit summary, rules list filters and sort, export.
  - The `api/` views were not reviewed (API agent's code).

## UI work other agents' features will need

- Scan pipeline: a scan jobs page (queue/status/history) and a WebSocket
  client in `rules/static/rules/js/app.js` for live results (PLAN 12.7, 12.9),
  with a plain-HTTP fallback.
- Directory watcher: watcher status on the Import page (PLAN 12.6).
- Attribution: "imported by / last changed by" columns and a filter on the
  rules list and detail (PLAN 12.1).
- Archives: `.zip` / `.tar.gz` upload on the Import page and collection
  download controls (PLAN 12.2, 12.3).
- A slow-rule listing, once the scanner exposes timings.
- An API link is already in `base.html` (added by the API agent).

## Design checks not done

- Light theme: all renders were checked in dark mode only.
- Browsers other than the Browser pane's Chromium (Safari, Firefox). This
  includes the fallback for browsers without `::details-content` (the filters
  should stay a working disclosure at every width).
- Very long usernames in the header at 768–800 px.
- None of the latest template changes (delete pages, import run skipped
  tiles, relevance option) were looked at in a browser; they were checked only
  for HTTP 200 on the preview.
