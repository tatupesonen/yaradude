# API (PLAN.md 12.8) — status, 2026-11-19

Owner: API agent. Everything lives in `api/` except the edits listed under
"Edits outside `api/`". PLAN.md 12.8 has an "As built" summary.

## State at hand-off

- `uv run python manage.py test api`: **91 tests, all pass**. No `api.tests`
  test fails or is skipped. (The earlier "26 failures and 1 error / undocumented
  422" came from tests run while the service layer changed underneath; fixed
  by adopting the 5.7 changes below.)
- Full suite at hand-off: 535 tests, 5 failures + 1 error, **all in
  `rules.tests`** (soft-delete semantics, `sort=relevance` in the export
  redirect, a symlink skipped in the import-page count, `test_editor_can_delete`).
  None touch `api/`; owners: UI / service-layer agents. The Tailwind
  stale-CSS failure was mine and is fixed (CSS rebuilt).
- `manage.py check`, `makemigrations --check --dry-run`, `ruff check api`,
  `ruff format --check api`, `ty check api`, and `check --deploy` with
  production variables: all clean.
- Every docs page (`/api-docs/` and each group page), the key page and both
  downloads render 200 for Viewer, Editor, no-role user and superuser
  (`api/tests/test_pages.py`, generated from `registry.GROUPS`). A sweep of
  every non-destructive endpoint as superuser gave no 5xx.

## Framework decision

Plain Django views, no API framework. Checked from installed wheels
(scratch venv): DRF 3.18.3 supports Django 6.1/Py 3.13, but the browsable API
uses inline scripts and OpenAPI needs drf-spectacular (+uritemplate, PyYAML,
jsonschema, inflection); django-ninja 1.8.0 supports Django 6.1, needs
pydantic-core (wheels exist for manylinux_2_28 x86_64 and aarch64), its docs
templates fall back to a CDN when `ninja` is not installed as an app and
`redoc.html` has an inline script. Either would re-declare the validation the
UI forms already do. Plain Django reuses `RuleFilterForm`, `RuleCreateForm`,
`RuleUpdateForm`, `ExportForm`, `UploadForm`, `ScanForm` and the query
functions unchanged and adds no dependency (no `uv add`, `uv.lock` untouched).

## How it is built

- `api/registry.py`: `@endpoint(method, route, operation=…, group=…,
  permissions=…, params=…, body=…, replies=…)`. From these declarations:
  URL patterns (`api/urls.py`), dispatch (Bearer auth → rate limit → method →
  permission → handler; permission is checked before any object lookup),
  OpenAPI (`api/openapi.py` + response schemas in `api/schemas.py`), docs
  pages (`api/pages.py`, `api/templates/api/`) and examples
  (`api/examples.py`).
- Views are `login_not_required` + `csrf_exempt`; only the `Authorization:
  Bearer` header authenticates, `request.user` is replaced by the key's user;
  session cookies are ignored (tested: logged-in session without key → 401,
  cross-site POST with session → 401, no cookies set on answers).
- Errors: always JSON `{"error": {"code", "message", "fields"?, …}}`:
  401 (+`WWW-Authenticate: Bearer`), 403, 404 (also any unknown `/api/…`
  path via a catch-all), 405 (+`Allow`), 400/413/415, 409, 422, 429
  (+`Retry-After`), 500 (logged without body, headers or key).
  `Cache-Control: no-store` on all answers. HEAD = GET without body.
- Not under the API's control: `DisallowedHost` (400) and the HTTPS redirect
  happen in middleware before URL resolution and stay Django's defaults.

## Endpoints (all under `/api/v1/`)

| Method | Path | Permission | Service / shared code called |
|---|---|---|---|
| GET | `me/` | any valid key | — |
| GET | `openapi.json` | any valid key | `api.openapi` |
| GET | `dashboard/` | view_rule | `DashboardView` context (reused) |
| GET | `rules/` | view_rule | `RuleFilterForm` + `filtered_rules` (incl. `search_rules`, `sort=relevance`) |
| POST | `rules/` | add_rule (+add_ruleset for a new collection) | `RuleCreateForm`, `editing.manual_ruleset(save=False)`, `create_rule` |
| POST | `rules/validate/` | add_rule | `validate_rule_text` |
| GET | `rules/{pk}/` | view_rule | ORM |
| PUT | `rules/{pk}/` | change_rule | `RuleUpdateForm`, `update_rule(expected_version=)`; 409 `version_conflict` |
| DELETE | `rules/{pk}/` | delete_rule | `editing.delete_rule(user=)` (recoverable) |
| POST | `rules/{pk}/validate/` | change_rule | `validate_rule_text` |
| GET | `rules/{pk}/download/` | view_rule | `exporter.export_rule` |
| GET | `rules/export/` | view_rule | `ExportForm`, `filtered_rules`, `export_combined` / `export_zip` |
| POST | `rules/export/` | view_rule | same, ids in JSON |
| GET | `rules/{pk}/versions/` | view_rule + view_ruleversion | ORM |
| GET | `rules/{pk}/versions/{number}/` | view_rule + view_ruleversion | `previous_version`, `diff_versions` |
| POST | `rules/{pk}/versions/{number}/restore/` | change_rule | `restore_version(expected_version=)` |
| GET | `rules/deleted/` | view_rule | `Rule.all_objects.deleted()` |
| POST | `rules/deleted/{pk}/restore/` | delete_rule | `editing.restore_rule` |
| DELETE | `rules/deleted/{pk}/` | purge_rule | `editing.purge_rule` |
| GET | `tags/` | view_tag | ORM (deleted/removed rules not counted) |
| GET | `rulesets/` | view_ruleset | `RulesetFilterForm`, `SORTS`, own `with_counts` (see bugs) |
| GET | `rulesets/{pk}/` | view_ruleset | ORM + own `with_counts` |
| DELETE | `rulesets/{pk}/` | delete_ruleset | `editing.delete_ruleset(user=)` (recoverable) |
| GET | `rulesets/{pk}/download/` | view_ruleset | `exporter.export_ruleset` |
| GET | `rulesets/{pk}/original/` | view_ruleset | `exporter.export_ruleset_original` |
| GET | `rulesets/deleted/` | view_ruleset | `Ruleset.all_objects.deleted()` |
| POST | `rulesets/deleted/{pk}/restore/` | delete_ruleset | `editing.restore_ruleset` |
| DELETE | `rulesets/deleted/{pk}/` | purge_ruleset | `editing.purge_ruleset` |
| GET | `imports/` | view_importrun | ORM (25/page as the UI) |
| GET | `imports/{pk}/` | view_importrun | ORM (incl. `files_skipped`, `rules_skipped`, status `skipped`) |
| POST | `imports/upload/` | import_rules | `UploadForm`, `importer.import_uploads` |
| GET | `imports/directory/` | import_rules | `rules.views.imports.directory_status` |
| POST | `imports/scan/` | import_rules | `directory_status`, `importer.import_directory(settings.YARADUDE_RULES_DIR)` |
| POST | `scan/` | scan_rules | `ScanForm`, `rulesets_by_path`, `scanner.scan_sample` |
| GET | `scan/limit/` | scan_rules | `rules.views.scan.limit_summary` |
| POST | `scans/` | scan_rules | `scans.services.submit_samples` (field `samples`, repeatable; `path`, `tag`) |
| GET | `scans/` | scan_rules | `visible_jobs` (+ `batch` filter), `job_json` |
| GET | `scans/{job_id}/` | scan_rules | `get_job`, `job_json` |
| GET | `scans/status/` | scan_rules | `system_status` |

Choices made: restore of a deleted item needs the matching *delete*
permission; purge works only on items already deleted (404 otherwise).

## Missing endpoints and what each waits on

| Missing | Waiting on | Next step |
|---|---|---|
| Compiled rule set download (revision, engine version, checksum, namespace → ruleset map, ETag/If-None-Match), for `yarad --local` | a documented 5.7 function that exports the set in a form `yr`/`yara_x` can load (the stored file is yaradude's own block format; `compiled_path()` is undocumented) | when documented: `GET /api/v1/compiled/` (metadata) + `GET /api/v1/compiled/rules` (file, ETag = revision+engine), permission view_rule |
| `yr` engine binaries list/download (decision 12.10) | a setting for the binaries folder (none exists yet) and verification of how `yr` loads a serialized set / reports its version | add `YARADUDE_ENGINE_DIR` in the API settings block; `GET engine/` lists files (platform, arch, version, size, server-computed SHA-256), `GET engine/<id>/` serves by validated identifier only |
| Archive upload / collection export (12.2, 12.3) | services not in 5.7 | add multipart `archive` to `imports/upload/` and `GET rulesets/export/` once documented |
| Attribution (12.1: `created_by` / `updated_by`, filter by user) | services/fields not in 5.7 | add fields to `RuleSummary` and a `user` filter |
| Directory watcher state (12.6) | not in 5.7 | add to `imports/directory/` |
| Live scan (WebSocket) | browser-only protocol | none planned in HTTP API; jobs endpoints cover scripts |

## Keys

`api.models.ApiKey`: `user`, `name`, `public_id` (12 hex, unique), `secret_sha256`,
`created_at`, `last_used_at`, `expires_at`, `revoked_at`. Key format
`yd_<public_id>_<secret>`, secret = `secrets.token_urlsafe(32)` (256 bits);
only SHA-256 stored (fast hash is enough for a full-entropy secret);
`hmac.compare_digest`; unknown ids cost one comparison too. Shown once in the
POST response of the key page (rendered, not stored/redirected, `no-store`).
Revocation keeps the row. Max 20 usable keys per user. Inactive users' keys
→ 401 `inactive_user`. `last_used_at` is written at most once per
`YARADUDE_API_KEY_TOUCH_SECONDS` (300 s) by a conditional UPDATE; a locked
database never fails the request (tested with captured queries). The admin
lists keys (no secrets), cannot add, can revoke. Keys are never logged
(tested with `assertLogs`).

## Rate limit

`api/ratelimit.py`: token bucket per key in a file under
`YARADUDE_API_RATE_DIR` (default `$TMPDIR/yaradude-api-ratelimit`), guarded by
`fcntl.flock`. Guarantee: per key, across all processes on one host sharing
that directory, at most `capacity + rate·t` requests in any t seconds
(capacity = `YARADUDE_API_RATE_LIMIT`, default 120 per
`YARADUDE_API_RATE_WINDOW` = 60 s; 0 = off). Tested with 4 spawned processes
(exactly 50 of 120 admitted). Limits: local filesystem only; separate hosts or
web containers each have their own buckets; buckets refill if the directory
is emptied. Works the same under ASGI. Answers carry `RateLimit-Limit`,
`RateLimit-Remaining`; 429 has `Retry-After`.

## Documentation pages

`/api-docs/` (overview: base URL from the request, key creation, header,
errors, pagination, filters, edits/deletes, uploads/downloads, rate limit,
Python helper, TLS with a private CA) and `/api-docs/<group>/` for
Dashboard, Rules, Rulesets, Import, Scan, Account: every endpoint with
method/path, permission (and whether the reader's role has it), parameters,
body fields with types, responses, curl and Python examples with copy
buttons (existing `data-copy` JS), example response built from the schema
examples. Linked from the main navigation ("API") and the account menu ("API
keys"). Raw OpenAPI for signed-in users at `/api-docs/openapi.json`. Examples
use `$YARADUDE_API_KEY`, never a key; ids are placeholders (42, 2). Python
examples use `yaradude_client.py` (stdlib only, Python 3.9+), served from
`/api-docs/yaradude_client.py` with the reader's host as default.

## `yarad` (12.10)

**Not started**: no file exists. The name change to "yarad" is moot so far;
the only downloadable Python file is `yaradude_client.py`, the helper for the
Python examples — not the scan client. Decide whether to keep that helper
under its name or fold the examples into self-contained snippets so "yarad"
is the only client a user sees. Server mode can be built now on
`POST /api/v1/scan/` and `POST/GET /api/v1/scans/`; local mode waits on the
compiled-set and engine endpoints above.

Next step: `tools/yarad` (single stdlib file, argparse subcommands
`configure`, `scan [--local|--server] [--recursive] [--json]`, `status`,
`--version`; exit 0/1/2), server mode first, subprocess tests against
`LiveServerTestCase`, a test that it imports only stdlib (+ guarded
`yara_x`), and a download link on `/api-docs/`.

## Known bugs / awkward spots (outside `api/`)

- `rules/views/rulesets.py` `with_counts` counts deleted rules (join bypasses
  the manager): the UI's Rulesets list/detail show wrong counts and
  `rules`/`removed` sort. The API has a corrected copy in
  `api/endpoints/rulesets.py`; fix the view and extract
  `filtered_rulesets(values)` so the API can reuse it, then delete the copy.
- `DashboardView` is reused by instantiating it (`api/endpoints/common.py
  ui_context`); extract `dashboard_counts()` and drop that bridge.
- Rule creation needed `manual_ruleset(save=False)` to stop duplicating the
  view's transaction; done now that 5.7 documents it.

## Edits outside `api/`

- `config/settings.py`: `"api"` in `INSTALLED_APPS`; block
  `# ---- API … # ---- end API` (rate limit, rate dir, touch interval, max keys).
- `config/urls.py`: `path("", include("api.urls"))`.
- `rules/templates/base.html`: "API" nav link, "API keys" account-menu link.
- `rules/tailwind/yaradude.css`: `@source "../../api/templates";`
- `rules/static/rules/css/yaradude.css`: rebuilt (`tailwind build`).
- `PLAN.md`: 12.8 "As built".
- No dependency changes.

## Migration

`api/migrations/0001_initial.py` (ApiKey). Applied to the preview by main.

## Evidence

`curl` transcript against a scratch server (scratch DB, port 8791): /me,
search, download (`-OJ`), upload, edit (200 then 409 `version_conflict` with
the stale version), scan with matches, bad key → 401 with
`WWW-Authenticate`. Saved at
`/private/tmp/claude-501/-Users-tatu-py/08d308fb-f27d-40e5-a709-fc1774719f75/scratchpad/e2e-transcript.txt`
(key redacted).
