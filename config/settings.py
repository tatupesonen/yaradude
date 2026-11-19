"""
yaradude settings. Every deployment-specific value comes from the
environment; PLAN.md section 8.1 lists the variables.
"""

import importlib.util
import os
import sys
import tempfile
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured
from django.utils.csp import CSP  # ty: ignore[import-not-found]  # Django 6.0 module absent from django-types 0.24


def env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name, "").strip().lower()
    if not value:
        return default
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    raise ImproperlyConfigured(f"{name} must be true or false, got {value!r}.")


def env_int(name: str, default: int) -> int:
    value = os.environ.get(name, "").strip()
    if not value:
        return default
    try:
        return int(value)
    except ValueError:
        raise ImproperlyConfigured(f"{name} must be an integer, got {value!r}.") from None


def env_list(name: str, default: list[str]) -> list[str]:
    value = os.environ.get(name)
    if value is None:
        return default
    return [item.strip() for item in value.split(",") if item.strip()]


# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = env_bool("DJANGO_DEBUG", False)

# The test runner gets the same relaxed defaults as debug mode (no secret key
# required, plain HTTP, unhashed static files) so `manage.py test` works
# without any environment.
TESTING = sys.argv[1:2] == ["test"]

# SECURITY WARNING: keep the secret key used in production secret!
# Without debug there is no fallback: Django then raises ImproperlyConfigured
# as soon as anything (sessions, CSRF, signing) uses the key, while commands
# that do not need it, such as makemigrations or collectstatic, still work.
SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY") or (
    "django-insecure-development-only" if DEBUG or TESTING else ""
)

ALLOWED_HOSTS = env_list(
    "DJANGO_ALLOWED_HOSTS", ["localhost", "127.0.0.1", "[::1]"] if DEBUG else []
)
CSRF_TRUSTED_ORIGINS = env_list("DJANGO_CSRF_TRUSTED_ORIGINS", [])


# Application definition

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "accounts",
    "rules",
    "api",
    "django_tasks_db",
    "scans",
]
# django-tailwind-cli is a dev-group dependency that only provides the
# `tailwind` build/watch commands; production serves the committed CSS and
# does not install it.
if importlib.util.find_spec("django_tailwind_cli"):
    INSTALLED_APPS.append("django_tailwind_cli")

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.middleware.csp.ContentSecurityPolicyMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.auth.middleware.LoginRequiredMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        # Searched before the app directories, so the styled registration/
        # templates win over django.contrib.admin's (admin comes first in
        # INSTALLED_APPS and ships its own password-change templates).
        "DIRS": [BASE_DIR / "accounts" / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.template.context_processors.csp",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"


# Database
# https://docs.djangoproject.com/en/6.1/ref/settings/#databases

# SQLite tuning (PLAN.md 8.1). Every connection of every process (web,
# task workers, management commands) runs init_command:
# - mmap_size: reads go through a shared memory map of the file, i.e. the
#   OS page cache shared by all processes, so a fresh connection starts warm.
#   Virtual address space, not private memory; it does not multiply.
# - cache_size: SQLite's private page cache per connection, filled only by
#   pages the connection reads and does not get from the map (mostly writes
#   and temp b-trees). Worst case it multiplies by the number of open
#   connections: about (web processes x threads using the database) + task
#   workers + running commands, e.g. (2 x 4) + 3 + 1 = 12 x 16 MiB = 192 MiB;
#   in practice far less, since a connection only caches what it touches.
# - temp_store=MEMORY: sorts and temporary b-trees in memory, not temp files.
# - journal_size_limit: the WAL file is truncated back to this size after a
#   checkpoint resets it, so it cannot stay large after a burst of writes.
YARADUDE_DB_CACHE_MIB = env_int("YARADUDE_DB_CACHE_MIB", 16)
YARADUDE_DB_MMAP_MIB = env_int("YARADUDE_DB_MMAP_MIB", 256)
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": os.environ.get("YARADUDE_DB_PATH") or BASE_DIR / "db.sqlite3",
        # Persistent connections (PLAN.md 8.1): useless under the ASGI server,
        # which runs each request in a fresh thread and so opens a new
        # connection per request whatever this says (measured with uvicorn);
        # the memory map keeps those warm instead. Task workers are single
        # threaded and poll every YARADUDE_WORKER_POLL_MS, calling
        # close_old_connections() each time, so they keep one connection.
        "CONN_MAX_AGE": env_int(
            "YARADUDE_DB_CONN_MAX_AGE",
            3600 if sys.argv[1:2] in (["run_worker"], ["db_worker"]) else 0,
        ),
        "CONN_HEALTH_CHECKS": True,
        "OPTIONS": {
            # IMMEDIATE takes the write lock at BEGIN, so concurrent writers
            # wait up to `timeout` seconds instead of failing with "database
            # is locked" when a read transaction tries to upgrade.
            "transaction_mode": "IMMEDIATE",
            "timeout": 20,
            "init_command": (
                "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; "
                f"PRAGMA cache_size=-{YARADUDE_DB_CACHE_MIB * 1024}; "
                f"PRAGMA mmap_size={YARADUDE_DB_MMAP_MIB * 1024 * 1024}; "
                "PRAGMA temp_store=MEMORY; "
                f"PRAGMA journal_size_limit={64 * 1024 * 1024};"
            ),
        },
    }
}


# Authentication

AUTH_USER_MODEL = "accounts.User"
LOGIN_URL = "login"
LOGIN_REDIRECT_URL = "rules:dashboard"
LOGOUT_REDIRECT_URL = "login"


# Password validation
# https://docs.djangoproject.com/en/6.1/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]


# Internationalization
# https://docs.djangoproject.com/en/6.1/topics/i18n/

LANGUAGE_CODE = "en-us"

TIME_ZONE = os.environ.get("DJANGO_TIME_ZONE") or "UTC"

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/6.1/howto/static-files/

STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
# Only the compiled Tailwind stylesheet lives here (django-tailwind-cli writes
# its output below STATICFILES_DIRS[0]); it is the same directory the rules app
# serves as static/rules/css/, so the URL is static/rules/css/yaradude.css.
STATICFILES_DIRS = [("rules/css", BASE_DIR / "rules" / "static" / "rules" / "css")]
STORAGES = {
    "default": {
        "BACKEND": "django.core.files.storage.FileSystemStorage",
    },
    "staticfiles": {
        "BACKEND": (
            "django.contrib.staticfiles.storage.StaticFilesStorage"
            if TESTING
            else "whitenoise.storage.CompressedManifestStaticFilesStorage"
        ),
    },
}


# Email
# https://docs.djangoproject.com/en/6.1/topics/email/#topic-email-configuration

# yaradude sends no email (it runs air-gapped; users are managed in the
# admin), so production keeps Django's SMTP default.
MAILERS = {
    "default": {
        "BACKEND": (
            "django.core.mail.backends.console.EmailBackend"
            if DEBUG
            else "django.core.mail.backends.smtp.EmailBackend"
        ),
    },
}


# Uploads: rule files and scan samples are kept in memory only, because
# samples may be malware and must never touch the disk. A request whose body
# exceeds FILE_UPLOAD_MAX_MEMORY_SIZE arrives without its files.

YARADUDE_SCAN_MAX_BYTES = env_int("YARADUDE_SCAN_MAX_BYTES", 64 * 1024 * 1024)
YARADUDE_SCAN_TIMEOUT = env_int("YARADUDE_SCAN_TIMEOUT", 60)
FILE_UPLOAD_HANDLERS = ["django.core.files.uploadhandler.MemoryFileUploadHandler"]
FILE_UPLOAD_MAX_MEMORY_SIZE = YARADUDE_SCAN_MAX_BYTES + 1024 * 1024  # multipart overhead


# Tailwind CSS (django-tailwind-cli, standalone CLI, no Node). PLAN.md
# section 7 describes the build. The version is pinned (never "latest", which
# would query github.com) and automatic downloads are off: `tailwind build`
# and `tailwind watch` use the binary already present at TAILWIND_CLI_PATH
# (a directory holding tailwindcss-<os>-<arch>-<version>, or the path of an
# executable) and fail without touching the network when it is missing. The
# only step that downloads is the explicit `tailwind download_cli`.
TAILWIND_CLI_VERSION = "4.3.5"
TAILWIND_CLI_PATH = os.environ.get("YARADUDE_TAILWIND_CLI_PATH") or BASE_DIR / ".tailwind"
TAILWIND_CLI_AUTOMATIC_DOWNLOAD = False
TAILWIND_CLI_SRC_CSS = BASE_DIR / "rules" / "tailwind" / "yaradude.css"
TAILWIND_CLI_DIST_CSS = "yaradude.css"
# `tailwind watch` cannot minify, so `build` does not either: both then write
# byte-identical output, and the committed file does not flip between forms
# while the watcher runs. WhiteNoise serves it compressed.
TAILWIND_CLI_AUTOMATIC_MINIFY = False


# YARA

YARADUDE_RULES_DIR = Path(os.environ.get("YARADUDE_RULES_DIR") or BASE_DIR / "yara-rules")
YARADUDE_RELAXED_RE_SYNTAX = env_bool("YARADUDE_RELAXED_RE_SYNTAX", False)
# Per-file limit for rule files read by imports. Parsing and compiling a file
# takes about 1 s per MiB; the largest file in the public rule sets checked
# (PLAN.md 12.4) is about 1 MiB.
YARADUDE_MAX_RULE_FILE_BYTES = env_int("YARADUDE_MAX_RULE_FILE_BYTES", 4 * 1024 * 1024)
# Seconds between `PRAGMA optimize` + truncating WAL checkpoint runs on the
# maintenance queue (rules.tasks.database_maintenance; 0 = off).
YARADUDE_DB_MAINTENANCE_INTERVAL = env_int("YARADUDE_DB_MAINTENANCE_INTERVAL", 600)
# Globals defined for every compile and scan, so that public rule sets written
# for tools such as LOKI or THOR compile. The scanner fills in the sample's
# file name and extension.
YARADUDE_GLOBALS = {
    "filename": "",
    "filepath": "",
    "extension": "",
    "filetype": "",
    "owner": "",
}


# --- Scan jobs, compiled rule set, task workers and WebSocket (scans app) ---
# PLAN.md 12.4, 12.7, 12.9; the variables are listed in section 8.1.

ASGI_APPLICATION = "config.asgi.application"
# django.tasks itself ships only immediate and dummy backends; django-tasks-db
# keeps the queue in the SQLite database and runs real worker processes
# (`manage.py run_workers`). One queue per kind of work, one queue per worker.
TASKS = {
    "default": {
        "BACKEND": "django_tasks_db.DatabaseBackend",
        "QUEUES": ["scans", "maintenance"],
    },
}
# Compiled rule set, its build lock and the sample spool live here, on the
# data volume beside the database. Tests get a private temporary directory.
YARADUDE_SCAN_DIR = Path(
    os.environ.get("YARADUDE_SCAN_DIR")
    or (
        Path(tempfile.gettempdir()) / f"yaradude-tests-{os.getpid()}"
        if TESTING
        else Path(DATABASES["default"]["NAME"]).parent / "scan"
    )
)
# Off under tests: every scan then compiles the current rules in memory, so a
# test never sees a set compiled from another test's data (the scans tests
# switch it on with their own directory).
YARADUDE_SCAN_COMPILED_CACHE = not TESTING
# A single sample up to this size is scanned at once in the web process
# (0 = always use the queue); bounded by YARADUDE_SCAN_INLINE_TIMEOUT seconds,
# after which it is handed to a worker.
YARADUDE_SCAN_INLINE_MAX_BYTES = env_int("YARADUDE_SCAN_INLINE_MAX_BYTES", 1024 * 1024)
YARADUDE_SCAN_INLINE_TIMEOUT = 1
YARADUDE_SCAN_MAX_SAMPLES = env_int("YARADUDE_SCAN_MAX_SAMPLES", 20)
YARADUDE_SCAN_RETENTION_DAYS = env_int("YARADUDE_SCAN_RETENTION_DAYS", 30)
YARADUDE_SCAN_CLEANUP_INTERVAL = env_int("YARADUDE_SCAN_CLEANUP_INTERVAL", 3600)
YARADUDE_SCAN_WORKERS = env_int("YARADUDE_SCAN_WORKERS", 2)
YARADUDE_MAINTENANCE_WORKERS = env_int("YARADUDE_MAINTENANCE_WORKERS", 1)
# How often an idle worker looks for work (a read-only indexed query).
YARADUDE_WORKER_POLL_MS = env_int("YARADUDE_WORKER_POLL_MS", 50)
# --- end of scans block ---


# ---- API (api app, PLAN.md section 12.8) ---------------------------------
# Per-key token bucket: YARADUDE_API_RATE_LIMIT requests per
# YARADUDE_API_RATE_WINDOW seconds (0 switches it off), shared by all worker
# processes through flock'ed files in YARADUDE_API_RATE_DIR, which must be on
# a local filesystem. Last use of a key is written at most once per
# YARADUDE_API_KEY_TOUCH_SECONDS.
YARADUDE_API_RATE_LIMIT = env_int("YARADUDE_API_RATE_LIMIT", 120)
YARADUDE_API_RATE_WINDOW = env_int("YARADUDE_API_RATE_WINDOW", 60)
YARADUDE_API_RATE_DIR = Path(
    os.environ.get("YARADUDE_API_RATE_DIR")
    or Path(os.environ.get("TMPDIR") or "/tmp") / "yaradude-api-ratelimit"
)
YARADUDE_API_KEY_TOUCH_SECONDS = env_int("YARADUDE_API_KEY_TOUCH_SECONDS", 300)
YARADUDE_API_MAX_KEYS_PER_USER = 20
# ---- end API --------------------------------------------------------------


# Security
# https://docs.djangoproject.com/en/6.1/howto/deployment/checklist/

HTTPS = env_bool("DJANGO_HTTPS", not (DEBUG or TESTING))
if HTTPS:
    # Caddy terminates TLS and sets X-Forwarded-Proto.
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
    SECURE_SSL_REDIRECT = True
    # The container health check talks to gunicorn directly over HTTP.
    SECURE_REDIRECT_EXEMPT = [r"^healthz/$"]
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SECURE_HSTS_SECONDS = 60 * 60 * 24 * 365
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
# HSTS preloading means submitting a public domain to the browsers' preload
# list, which does not apply to an air-gapped deployment.
SILENCED_SYSTEM_CHECKS = ["security.W021"]

# The application has no inline scripts or styles. The nonce in style-src is
# for the one <style> block the Django admin emits on some change lists.
SECURE_CSP = {
    "default-src": [CSP.SELF],
    "style-src": [CSP.SELF, CSP.NONCE],
    "object-src": [CSP.NONE],
    "base-uri": [CSP.NONE],
    "form-action": [CSP.SELF],
    "frame-ancestors": [CSP.NONE],
    # The live scan view's WebSocket (/ws/scans/, PLAN.md 12.7).
    "connect-src": [CSP.SELF],
}


# Logging: everything to stdout for the container runtime to collect.

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "plain": {"format": "{asctime} {levelname} {name}: {message}", "style": "{"},
    },
    "handlers": {
        "stdout": {
            "class": "logging.StreamHandler",
            "stream": "ext://sys.stdout",
            "formatter": "plain",
        },
    },
    "root": {"handlers": ["stdout"], "level": "INFO"},
}
