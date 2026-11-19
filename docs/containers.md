# Containers: how they will work

**Status: design only. None of this is built yet.** It records what was
agreed so the containers work package can start from it. The detailed
requirements are in `PLAN.md` sections 8.2–8.6; where this note and the older
parts of section 8 disagree (gunicorn, a single app process), this note is
the newer one.

## What we want

1. A **development image** that is built on a machine with internet, moved
   into the air-gapped network, and used there to keep developing.
2. A **production stack** (Docker Compose, Caddy in front) that runs with no
   network access at all.
3. The ability to **build the production image inside the air gap** after
   changing code there.
4. Both `linux/amd64` and `linux/arm64`.

## The three images

| Image | Built from | Contains | Used for |
|---|---|---|---|
| `yaradude-dev` | `python:3.13-slim-bookworm` | `uv`, the complete virtualenv including dev tools (ruff, ty, the Tailwind package), the Tailwind standalone binary for the image's architecture, and a `uv` wheel cache holding every package in `uv.lock` | Developing in the air gap, and as the build stage for production |
| `yaradude` | `python:3.13-slim-bookworm` | Only the runtime virtualenv (no dev tools, no `uv`, no Tailwind), the application code, the compiled stylesheet and collected static files; runs as a non-root user | Production: web server and workers |
| `yaradude-caddy` | the official Caddy image | Caddy with our `Caddyfile` baked in | Production: TLS and reverse proxy |

All base images are pinned to exact versions. Nothing in any image downloads
anything at run time: the Tailwind package's automatic download is disabled
in settings, `uv` runs in offline mode inside the dev image, and Caddy uses
its own internal certificate authority (or certificates you mount) instead of
Let's Encrypt.

## Development in the air gap

On the machine with internet:

1. Build `yaradude-dev` for the target architecture.
2. `docker save` it to a tarball.
3. Carry across: the tarball, and the source code (a `git bundle` or a copy
   of the repository).

Inside the air gap:

1. `docker load` the tarball.
2. Start it with `compose.dev.yaml`: the repository is mounted into the
   container, a volume holds the database and scan directory, and the
   container runs `python manage.py dev 0.0.0.0:8000` — the web server, the
   task workers and the Tailwind watcher together, reloading on code changes.
3. Edit code on the host with any editor; run tests, ruff and ty inside the
   container.

The virtualenv lives outside the mounted source directory, so mounting the
repository does not hide it.

What works offline: changing code, templates and styles, running the tests
and checks, creating migrations.

What does not: **adding or upgrading a dependency** (that changes `uv.lock`,
and the new packages are not in the image). For that, rebuild the dev image
on the internet machine and carry it across again. The same goes for a new
Python, Tailwind or base-image version.

VS Code note: the Dev Containers extension normally downloads its server
component into the container the first time it attaches, which fails without
network. Either pre-install that component by a documented procedure, or do
not use the extension and work with plain `docker compose` plus an editor on
the mounted source. A `.devcontainer/devcontainer.json` pointing at
`compose.dev.yaml` will be provided for those who can use it.

## The production stack

One Compose file, three services on one host, all sharing one data volume:

| Service | Image | Runs | Notes |
|---|---|---|---|
| `caddy` | `yaradude-caddy` | Caddy | The only service with published ports (80, 443). Terminates TLS, proxies HTTP and WebSockets to `web`, caps upload size. |
| `web` | `yaradude` | `uvicorn config.asgi:application` (ASGI) | Pages, the API, WebSockets. Its entrypoint runs `migrate` and `ensure_superuser` first. Has a health check on `/healthz/`. |
| `workers` | `yaradude` | `python manage.py run_workers` | Scan workers, maintenance workers (later: the periodic scan of the rules directory) and the compiled-rule-set builder. Starts after `web` is healthy, so only one container ever runs migrations. |

Storage:

- **Data volume** (`/data`): the SQLite database, the compiled rule set and
  the sample spool. Shared by `web` and `workers`. This is the only thing to
  back up.
- **Rules directory** (`/rules`): mounted read-only from the host; the
  directory the UI and the watcher import from.
- **Caddy volumes**: its internal CA and certificates, so they survive
  restarts.

Configuration comes from a `.env` file next to the Compose file (secret key,
allowed hosts, site address, first-admin credentials, worker counts). The
first-admin command refuses weak passwords.

Because the database is SQLite and the API rate limiter and scan spool are
files on the shared volume, **everything runs on one host**. Scaling is by
worker count (`YARADUDE_SCAN_WORKERS`), not by adding hosts. Each process
that scans holds the compiled rule set in memory (measured at about 127 MiB
for 10,000 rules).

## Delivering to the air gap

A script on the internet machine builds everything for each architecture and
writes one bundle per architecture containing:

- the three images as `docker save` archives (plus the pinned Python and
  Caddy base images, which the offline production build needs),
- `compose.yaml`, `compose.dev.yaml`, `.env.example`,
- a short install note: `docker load`, edit `.env`, `docker compose up -d`.

The Compose file refers to images by tag with pulling disabled, so the
air-gapped host never tries to reach a registry.

For the `yarad` workstation client's local mode, the official `yr` engine
binaries are placed by an administrator in a folder on the data volume; the
server only redistributes what is put there.

## Building production inside the air gap

After code changes made in the air gap, production images are rebuilt there:

1. The production Dockerfile's build stage is `FROM yaradude-dev`. It runs
   `uv sync --frozen --no-dev` in offline mode against the wheel cache baked
   into the dev image, compiles the stylesheet with the baked-in Tailwind
   binary, and runs `collectstatic`.
2. The final stage is `FROM` the pinned Python runtime base, already loaded
   from the bundle, and copies in the virtualenv, code and static files.
3. No step uses `apt-get`, `curl`, `pip`, a registry, PyPI or GitHub. The
   build is run with networking disabled (`docker build --network=none`) to
   prove it.

So a source change can go from edit to a new production image entirely
inside the air gap. A dependency change cannot; see above.

## What has been checked, and what has not

Checked (2026-11-19):

- Every package in `uv.lock` installs on Linux without a compiler: 20 of 24
  are pure Python, and `yara-x`, `ruff` and `ty` publish wheels for both
  amd64 and arm64.
- The Tailwind binary is published for Linux on both architectures, with
  checksums.
- Docker on the development Mac can build both architectures.
- SQLite full-text search (FTS5 trigram) works with the SQLite in
  `python:3.13-slim-bookworm`.

Still to prove by building and running with networking disabled:

- `docker build` resolves `FROM` images from the local image store when no
  registry is reachable.
- `uv sync --offline` installs from the baked wheel cache.
- The Tailwind binary makes no network calls.
- The whole stack starts on a network without outbound access, serves the
  sign-in page over HTTPS through Caddy, runs a scan job through the workers,
  delivers a WebSocket update, and keeps its data across a restart.

## Open points for whoever builds this

- uvicorn worker count for `web`, and its timeouts relative to the scan
  timeout.
- The upload size cap in Caddy (the app accepts samples up to 64 MiB).
- Whether `web` and `workers` should be one image with two commands (assumed
  here) or two images.
- Running the dev image as the host user so files created in the mounted
  repository are not owned by root.
- An offline procedure for the VS Code server component, if the extension is
  wanted.
