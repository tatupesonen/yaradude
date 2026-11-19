"""
Development server: uvicorn (ASGI: HTTP and the live scan socket) with
Django's autoreloader, plus the Tailwind watcher and the task workers, in
one terminal. Ctrl+C stops everything.
"""

import importlib.util
import os
import subprocess
import sys
from argparse import ArgumentParser
from typing import Any

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.utils import autoreload

# django.utils.autoreload.DJANGO_AUTORELOAD_ENV (absent from the django-types stubs)
RELOADER_CHILD = "RUN_MAIN"

DEFAULT_ADDRESS = "127.0.0.1:8000"
WS_MAX_SIZE = 64 * 1024  # incoming WebSocket messages; the consumer allows 4 KiB


def serve(host: str, port: int) -> None:
    import uvicorn

    uvicorn.run(
        "config.asgi:application",
        host=host,
        port=port,
        ws="wsproto",
        ws_max_size=WS_MAX_SIZE,
        lifespan="off",
        log_level="info",
    )


class Command(BaseCommand):
    help = (
        "Run the development server (uvicorn, ASGI, auto-reload) together with "
        "`tailwind watch` and `run_workers --reload`."
    )

    def add_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument("address", nargs="?", default=DEFAULT_ADDRESS, help="[host:]port")
        parser.add_argument("--no-workers", action="store_true", help="Do not start workers.")
        parser.add_argument("--no-tailwind", action="store_true", help="Do not start the watcher.")

    def handle(
        self, *args: Any, address: str, no_workers: bool, no_tailwind: bool, **options: Any
    ) -> None:
        host, _, port = address.rpartition(":")
        host = host or "127.0.0.1"
        if not port.isdigit():
            raise CommandError(f"Invalid address {address!r}; use host:port.")

        if os.environ.get(RELOADER_CHILD) == "true":
            # The reloader's child: only the server.
            autoreload.run_with_reloader(serve, host=host, port=int(port))
            return

        manage = str(settings.BASE_DIR / "manage.py")
        children: list[subprocess.Popen[bytes]] = []
        if not no_tailwind and importlib.util.find_spec("django_tailwind_cli"):
            children.append(subprocess.Popen([sys.executable, manage, "tailwind", "watch"]))
        if not no_workers:
            children.append(subprocess.Popen([sys.executable, manage, "run_workers", "--reload"]))
        try:
            autoreload.run_with_reloader(serve, host=host, port=int(port))
        finally:
            for child in children:
                child.terminate()
            for child in children:
                try:
                    child.wait(10)
                except subprocess.TimeoutExpired:
                    child.kill()
