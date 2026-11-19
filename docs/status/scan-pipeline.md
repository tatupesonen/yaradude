# Scan pipeline status (sections 12.4, 12.7, 12.9) — 2026-11-19

## Verified
- `manage.py check`: no issues. `makemigrations --check --dry-run`: no changes.
- My tests: `rules.tests.test_scanner` (28), `scans.tests` (test_jobs, test_recurring,
  test_consumer, 55 together) and `rules.tests.test_views_scan` → 90 tests, OK.
- `ruff check`, `ruff format --check`, `ty check` clean on `scans/`,
  `rules/services/scanner.py`, `rules/tests/test_scanner.py`, `config/`.
- Full suite at the last run (535 tests): 4 failures + 1 error, all outside my
  paths (other agents' work in progress): `test_views_import...test_counts_agree...`
  (symlink counted as skipped), `test_views_rules...test_nothing_selected...`
  (`sort=relevance` in redirect), `test_views_rules...test_delete_confirmation...`
  and `test_views_rulesets...test_delete` (tests expect "cannot be undone"; deletes
  are now recoverable), `test_permissions...test_editor_can_delete` (error).
- `ScannerTests.test_sample_is_never_persisted` passes now: it asserted exactly one
  query; the scan now issues only SELECTs (revision, matched rules, left-out rules)
  and the test asserts "only SELECTs, nothing written". Queued jobs do write the
  sample to the spool by design (12.9).

## Measurements (copy of the preview DB, 10,286 rules / 2,125 rulesets, macOS arm64)
How: scripts in the session scratchpad; `time.perf_counter` around the call,
median of 20 runs (3 for 64 MB); raw engine = `yara_x.Scanner(rules).scan(data)`.
| What | Before | After |
|---|---|---|
| Server time, 151 KB sample | 12.8 s (brief) | 3.5 ms (engine 2.1 ms) |
| Server time, 1 MiB sample | — | 13.0 ms (engine 11.1 ms) — target < 20 ms met |
| 64 MiB sample | — | 645 ms vs raw engine 595 ms = +8.3% (incl. SHA-256) — target 20% met |
| Compile all rules (full build) | 4.3 s (brief) | 6.8–7.1 s measured (PLAN said 4.3) |
| Serialize / file size | 0.01 s / 11.4 MB | 0.015 s / 11.6 MB (+index JSON) |
| Load (`deserialize_from`) = cold start of a scanning process | 1.1 s | 1.05–1.08 s; holds the GIL (a 1 ms ticker thread ran 5 times in 1.05 s) |
| RSS of a process holding the set | — | 127 MiB (bare python+yara_x 17 MiB → ~110 MiB for the set) |
| Queries per warm scan | — | 2–3, none selects `source`/`original_content` |
Not measured (no time): rebuild time after editing one rule (expected = full
build, ~7 s, plus ≤ 0.5 s builder poll), queue latency and throughput with N
workers, cold start of the whole stack, fast path including the job INSERT.

## Design as built
- Compiled set (`rules/services/scanner.py`): one file
  `<YARADUDE_SCAN_DIR>/compiled/rules.ydset` (magic, info JSON, index JSON,
  serialized rules). Key = format version | yara-x version | compile-settings
  digest | `revision.current()` (number@changed_at). Built from `Rule.objects.active()`
  in one SELECT outside any transaction (no write lock), temp file + fsync + rename +
  dir fsync; crashed build leaves the old file; `flock` on `build.lock` excludes
  concurrent builds. Processes load the file when its inode/mtime/size changes;
  no file → build and wait (first start only); stale → answer with old set,
  `pending=True`. `YARADUDE_SCAN_COMPILED_CACHE` is False under tests (compile per
  call; avoids sets leaking between tests at revision 0).
- Filtering: full set, matches filtered by ruleset ids (path/rulesets) and tag;
  tested equal to compiling the subset. Unmappable match → skipped, listed in
  `ScanResult.unmapped`, logged (finding 13.6 test included).
- Jobs (`scans/`): `ScanJob` (shared with the team), spool (`scans/spool.py`, 0700
  dir, 0600 files, 256-bit names only in `ScanJob.spool_token`, deleted in
  `finally`, sweep after 300 s grace), stored results without previews.
- Fast path: single sample ≤ `YARADUDE_SCAN_INLINE_MAX_BYTES` (1 MiB) scanned in
  the web process, one at a time per process (busy → queue), inline timeout 1 s
  then handed to a worker. Bound on blocking the web process: ~11 ms per MiB of
  threshold normally, ≤ 1 s worst case; plus a ~1.05 s GIL pause per web process
  each time it loads a new compiled set (once per rules revision, at its first
  inline scan after the change), and ~110 MiB RSS per web process.
- Backend: django-tasks-db 0.13.0 (Jake Howard's ORM backend for django.tasks;
  Django 6.1.3 ships only immediate/dummy — verified; pure-Python wheel; deps
  django-stubs-ext, typing-extensions, both pure Python). Its `db_worker` polls
  with `time.sleep(interval)` (default 1 s) and takes SQLite's write lock
  (EXCLUSIVE) on every poll; my `QueueWorker` subclass polls every
  `YARADUDE_WORKER_POLL_MS` (50 ms) with a read-only `exists()` and only then
  claims. Pinned exactly because it subclasses internals.
- Queues: `scans` and `maintenance`; one queue per worker process. Builder is its
  own process (not a task). Heartbeats (`WorkerProcess`, 5 s, lost after scan
  timeout + 60 s) detect dead workers; the supervisor repairs at once when a child exits.
- Recurring tasks: `scans/recurring.py`, documented in PLAN.md 5.7, tests in
  `scans/tests/test_recurring.py`; `cleanup_scan_jobs` (retention 30 days) uses it.
- ASGI: uvicorn 0.54 + wsproto 1.3.2 (+h11, click): all pure-Python wheels, so
  amd64/arm64 are covered; smallest footprint (daphne needs Twisted, cryptography…).
  Channels 4.3.2 (pure Python) with `AuthMiddlewareStack`, no channel layer.
  `channels.testing` imports daphne, so the socket tests use asgiref's
  `ApplicationCommunicator` (same base class) — deviation from the brief.
- Socket: upload stays a multipart POST; socket only reports (simpler: tiny
  frames, CSRF covered by the form, no 64 MB buffers per connection). Protocol v1
  in PLAN.md 5.7; security tests cover anonymous, no permission, inactive, Origin
  (missing/foreign/wrong scheme/foreign Host, trusted origins, proxied https),
  sockets per user, garbage, binary, size, rate, permission removed, lifetime.
- CSP: `connect-src 'self'` added.

## Commands
- Preview (dev): `uv run python manage.py migrate` once (new migrations), then
  `uv run python manage.py dev 127.0.0.1:8765` — uvicorn with Django's autoreloader
  + `tailwind watch` + `run_workers --reload` in one terminal. Verified on a scratch
  port: healthz/login/static 200, `/ws/scans/` refuses anonymous with 403, CSP header.
  The old `manage.py tailwind runserver 127.0.0.1:8765` still works for HTTP
  (WSGI runserver; the scan page and `scan_sample` work), but has no WebSocket and
  no workers: queued jobs stay queued unless `uv run python manage.py run_workers`
  runs beside it.
- Deployment (container agent to wire): web
  `uvicorn config.asgi:application --host 0.0.0.0 --port 8000 --ws wsproto --ws-max-size 65536 --proxy-headers --forwarded-allow-ips '*'`
  (replaces gunicorn; `config.wsgi` still works for HTTP-only); workers (second
  service, same image, data volume shared)
  `python manage.py run_workers` (counts from `YARADUDE_SCAN_WORKERS`=2,
  `YARADUDE_MAINTENANCE_WORKERS`=1). Not tested in containers.

## Partly done / not started (next steps)
- Measurements listed above as not measured: write a script that submits N 64 MB
  samples against `run_workers` on the scratch DB and records submit→`started_at`.
- `check --deploy` under production env: not run for this change.
- PLAN.md 8.1 (new settings table rows), 8.2/8.3 (uvicorn, workers service) and
  corrections in 12.4 (compile 6.8–7.1 s, not 4.3 s), 12.7 (no binary upload over
  the socket; jobs + POST instead) and 12.9 (no previews in stored results, because
  previews are sample bytes) are NOT yet written into PLAN.md — only 5.7 is updated.
- Worker/supervisor/builder have no automated tests of their own (only exercised
  through `QueueWorker.run_once` in tests and manually with `dev`); add tests for
  `Builder.check`, supervisor restart and orphan exit.
- Admin registration for `ScanJob`, `WorkerProcess`, `RecurringSchedule`: not done.
- `.gitignore` entry for `/scan/` (default dir beside `db.sqlite3`): not done.
- Duplicate log lines from django-tasks-db/django.tasks loggers in workers: cosmetic.
- UI agent: scan page → `scans.services.submit_samples`, jobs list/detail pages
  (`visible_jobs`, `get_job`, `job_json`), socket client per PLAN.md 5.7,
  self-refresh without JS, slow-rule list (`scanner.slow_rules()`), compiled-set
  status (`scanner.compiled_status()` / `services.system_status()`).
- API agent: same functions; submit returns jobs (finished or queued); result JSON has
  no previews.

## Migrations and dependencies added
- Migrations: `scans/migrations/0001_initial.py`; django_tasks_db's own 0001–0021.
- Dependencies (`uv add`): `django-tasks-db==0.13.0`, `channels>=4.3.2`,
  `uvicorn>=0.54.0`, `wsproto>=1.3.2` (pulls django-stubs-ext, typing-extensions, h11;
  click already present). `uv lock --check` passed after adding.

## Edits outside my paths
- `config/settings.py`: `django_tasks_db`, `scans` in INSTALLED_APPS; `import tempfile`;
  delimited scans block (ASGI_APPLICATION, TASKS, YARADUDE_SCAN_* settings);
  `connect-src` in SECURE_CSP.
- `pyproject.toml` / `uv.lock` (deps above). `PLAN.md` 5.7 (scanner contract, scans app,
  recurring tasks, socket protocol).
