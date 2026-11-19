# Running yaradude locally

How to get a development server running on your own machine. Containers are
not needed for this (and are not built yet).

## Requirements

- [uv](https://docs.astral.sh/uv/) — it installs the right Python (3.13) and
  all dependencies.
- Network access for the first setup (packages, and the Tailwind binary if
  you want to change styles). After that everything runs offline.

## First-time setup

Run these from the repository root.

```bash
uv sync
```

```bash
export DJANGO_DEBUG=true
```

`DJANGO_DEBUG=true` is required for local work: without it the app expects
production settings (a secret key, HTTPS, allowed hosts). Set it in every
terminal you use, or put it in your shell profile.

```bash
uv run python manage.py migrate
```

Always use `manage.py migrate` to apply migrations: it also repairs the
full-text search index and creates the Viewers and Editors groups.

```bash
uv run python manage.py createsuperuser
```

A superuser can do everything. Other users need to be put in the **Viewers**
or **Editors** group in the admin (`/admin/`) before they can see anything.

Optional, to have some rules to look at:

```bash
uv run python manage.py import_rules
```

That imports the example rules in `yara-rules/`. Pass a path to import a
different directory, for example a clone of a public rule repository.

## Start the server

```bash
uv run python manage.py dev 127.0.0.1:8000
```

Then open http://127.0.0.1:8000/ and sign in.

`dev` runs three things together and reloads them when code changes:

| Part | What it does |
|---|---|
| Web server (uvicorn, ASGI) | Pages, the API under `/api/v1/`, WebSockets |
| Task workers | Scan jobs, and the background builder that keeps the compiled rule set up to date |
| Tailwind watcher | Rebuilds the stylesheet when templates change |

Flags: `--no-workers` and `--no-tailwind` leave those parts out.

### The Tailwind binary

The compiled stylesheet is committed, so the app looks right without any
extra step. The watcher only matters if you change templates or styles, and
it needs the Tailwind standalone binary, which is never downloaded
automatically. Fetch it once, on a machine with network access:

```bash
uv run python manage.py tailwind download_cli
```

It is stored in `.tailwind/` (git-ignored). If you have not fetched it, start
the server with `--no-tailwind`.

## Where things are stored

| What | Default location | Override |
|---|---|---|
| Database (all rules, versions, users, jobs) | `db.sqlite3` in the repository root | `YARADUDE_DB_PATH` |
| Compiled rule set and scan spool | `scan/` beside the database | `YARADUDE_SCAN_DIR` |
| Directory the UI imports from | `yara-rules/` | `YARADUDE_RULES_DIR` |

All of these are git-ignored except the example rules. Every setting and its
default is listed in `PLAN.md`, section 8.1.

## Checks

```bash
uv run python manage.py test
```

```bash
uv run ruff check .
```

```bash
uv run ruff format --check .
```

```bash
uv run ty check
```

## Useful commands

| Command | Use |
|---|---|
| `uv run python manage.py import_rules [path]` | Import rule files from a directory |
| `uv run python manage.py run_workers` | Run only the workers (when the web server is started some other way) |
| `uv run python manage.py compile_rules` | Build the compiled rule set now if it is out of date (`--force` to rebuild regardless) |
| `uv run python manage.py rebuild_search_index` | Rebuild the full-text search index |
| `uv run python manage.py ensure_superuser` | Create the first admin from `DJANGO_SUPERUSER_USERNAME` / `_PASSWORD` / `_EMAIL` (refuses weak passwords) |

## Troubleshooting

- **Scans of larger files stay "queued"**: the workers are not running. Use
  `manage.py dev` (without `--no-workers`) or start `run_workers` beside the
  server.
- **"no such column" or "no such table" errors**: run
  `uv run python manage.py migrate`.
- **A signed-in user sees "no access"**: add them to the Viewers or Editors
  group in the admin.
- **Styles look wrong after editing a template**: the watcher is not running
  or the binary is missing; see "The Tailwind binary" above.

For where each part of the project stands, see `docs/status/`.
