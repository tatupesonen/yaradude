"""
The live scan socket, `/ws/scans/` (protocol version 1, PLAN.md 5.7).

A WebSocket bypasses Django's HTTP middleware, so this consumer does its own
admission: a signed-in, active user with `rules.scan_rules` and an `Origin`
equal to the page's own origin (the WebSocket equivalent of the CSRF origin
check). Samples are not uploaded here; the socket only reports job changes,
read from the database every POLL_SECONDS (no channel layer, nothing crosses
processes).
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from collections import deque
from datetime import timedelta
from typing import Any
from urllib.parse import urlsplit

from channels.db import database_sync_to_async
from channels.generic.websocket import AsyncWebsocketConsumer
from django.conf import settings
from django.contrib.auth import get_user_model
from django.db.models import Q
from django.http.request import split_domain_port, validate_host
from django.utils import timezone

from rules.services import scanner
from scans import services
from scans.models import ScanJob

VERSION = 1
MAX_MESSAGE_BYTES = 4096
MAX_JOBS = 200  # followed jobs that are not finished yet, per socket
MAX_IDS_PER_MESSAGE = 200
RATE_MESSAGES = 20
RATE_WINDOW = 10.0  # seconds
MAX_SOCKETS_PER_USER = 10  # per server process
POLL_SECONDS = 0.25
COMPILED_SECONDS = 2.0
RECHECK_SECONDS = 30.0
LIFETIME_SECONDS = 3600.0
MAX_PING_ID = 64

CLOSE_PROTOCOL = 4400
CLOSE_FORBIDDEN = 4403
CLOSE_LIFETIME = 4408
CLOSE_TOO_LARGE = 4413
CLOSE_RATE = 4429

FOLLOW_SCOPES = ("none", "mine", "all")

_open_sockets: dict[int, int] = {}


def _header(scope: dict[str, Any], name: bytes) -> str | None:
    for key, value in scope.get("headers", []):
        if key.lower() == name:
            return value.decode("latin-1")
    return None


def _allowed_hosts() -> list[str]:
    hosts: list[str] = list(settings.ALLOWED_HOSTS)
    if settings.DEBUG and not hosts:
        hosts = [".localhost", "127.0.0.1", "[::1]"]
    return hosts


def origin_allowed(scope: dict[str, Any]) -> bool:
    """
    The `Origin` header must name this site, as Django's CSRF origin check
    requires for unsafe requests: `<scheme>://<Host>` with a host from
    ALLOWED_HOSTS, or an entry of CSRF_TRUSTED_ORIGINS. A missing header is
    refused.
    """
    origin = _header(scope, b"origin")
    host = _header(scope, b"host")
    if not origin or not host:
        return False
    trusted: list[str] = settings.CSRF_TRUSTED_ORIGINS
    if origin in trusted:
        return True
    domain, _port = split_domain_port(host)
    if not domain or not validate_host(domain, _allowed_hosts()):
        return False
    secure = scope.get("scheme") in ("wss", "https")
    proxy_header = getattr(settings, "SECURE_PROXY_SSL_HEADER", None)
    if proxy_header:
        name, value = proxy_header
        header = name.removeprefix("HTTP_").replace("_", "-").lower().encode()
        if (_header(scope, header) or "").split(",")[0].strip() == value:
            secure = True
    expected = f"{'https' if secure else 'http'}://{host}"
    parsed = urlsplit(origin)
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}" == expected.lower()


def compiled_json(status: scanner.CompiledSetStatus) -> dict[str, Any]:
    info = status.set
    return {
        "available": status.available,
        "revision": info.revision if info else None,
        "built_at": info.built_at.isoformat() if info else None,
        "current_revision": status.current_revision,
        "pending": status.pending,
        "building": status.building,
        "rules": info.rules if info else 0,
        "rulesets": info.rulesets if info else 0,
    }


class ProtocolError(Exception):
    def __init__(self, code: str, message: str, close: int | None = CLOSE_PROTOCOL) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.close_code = close


class ScanJobsConsumer(AsyncWebsocketConsumer):
    user_id: int | None = None

    async def connect(self) -> None:
        user = self.scope.get("user")
        allowed = origin_allowed(self.scope) and await database_sync_to_async(services.can_scan)(
            user
        )
        if not allowed or user is None:
            await self.close(code=CLOSE_FORBIDDEN)  # before accept: HTTP 403
            return
        await self.accept()
        user_id: int = user.pk
        if _open_sockets.get(user_id, 0) >= MAX_SOCKETS_PER_USER:
            await self.close(code=CLOSE_RATE)
            return
        _open_sockets[user_id] = _open_sockets.get(user_id, 0) + 1
        self.user_id = user_id
        self.username: str = user.get_username()
        self.opened = time.monotonic()
        self.last_recheck = self.opened
        self.last_compiled_check = 0.0
        self.compiled: dict[str, Any] | None = None
        self.recent: deque[float] = deque()
        self.tracked: set[uuid.UUID] = set()
        self.sent: dict[uuid.UUID, tuple[str, str]] = {}
        self.follow = "none"
        self.follow_since = timezone.now()
        self.since = timezone.now()
        self.closing = False
        compiled = await database_sync_to_async(scanner.compiled_status)()
        self.compiled = compiled_json(compiled)
        await self.send_message(
            "hello",
            user=self.username,
            limits={
                "max_message_bytes": MAX_MESSAGE_BYTES,
                "max_jobs": MAX_JOBS,
                "messages_per_10s": RATE_MESSAGES,
            },
            compiled=self.compiled,
        )
        self.poller = asyncio.create_task(self.poll())

    async def disconnect(self, code: int) -> None:
        poller = getattr(self, "poller", None)
        if poller is not None and poller is not asyncio.current_task():
            poller.cancel()
        if self.user_id is not None:
            remaining = _open_sockets.get(self.user_id, 1) - 1
            if remaining > 0:
                _open_sockets[self.user_id] = remaining
            else:
                _open_sockets.pop(self.user_id, None)
            self.user_id = None

    async def send_message(self, type_: str, **fields: Any) -> None:
        await self.send(text_data=json.dumps({"v": VERSION, "type": type_, **fields}))

    async def fail(self, error: ProtocolError) -> None:
        await self.send_message("error", code=error.code, message=error.message)
        if error.close_code is not None and not self.closing:
            self.closing = True
            await self.close(code=error.close_code)

    # -- client messages ---------------------------------------------------

    async def receive(self, text_data: str | None = None, bytes_data: bytes | None = None) -> None:
        if self.closing or self.user_id is None:
            return
        try:
            await self.handle(text_data, bytes_data)
        except ProtocolError as error:
            await self.fail(error)

    def parse(self, text_data: str | None, bytes_data: bytes | None) -> dict[str, Any]:
        if bytes_data is not None or text_data is None:
            raise ProtocolError("binary_not_accepted", "Only JSON text frames are accepted.")
        if len(text_data.encode()) > MAX_MESSAGE_BYTES:
            raise ProtocolError(
                "too_large", f"Messages are limited to {MAX_MESSAGE_BYTES} bytes.", CLOSE_TOO_LARGE
            )
        now = time.monotonic()
        self.recent.append(now)
        while self.recent and self.recent[0] < now - RATE_WINDOW:
            self.recent.popleft()
        if len(self.recent) > RATE_MESSAGES:
            raise ProtocolError("rate_limited", "Too many messages.", CLOSE_RATE)
        try:
            message = json.loads(text_data)
        except ValueError:
            raise ProtocolError("bad_message", "Not JSON.") from None
        if not isinstance(message, dict):
            raise ProtocolError("bad_message", "Expected a JSON object.")
        if message.get("v") != VERSION:
            raise ProtocolError("unsupported_version", f"Protocol version {VERSION} only.")
        return message

    async def handle(self, text_data: str | None, bytes_data: bytes | None) -> None:
        message = self.parse(text_data, bytes_data)
        kind = message.get("type")
        if kind == "subscribe":
            await self.subscribe(self.job_ids(message))
        elif kind == "unsubscribe":
            for _raw, key in self.job_ids(message):
                if key is not None:
                    self.tracked.discard(key)
        elif kind == "follow":
            scope = message.get("scope")
            if scope not in FOLLOW_SCOPES:
                raise ProtocolError("bad_message", 'scope must be "mine", "all" or "none".')
            self.follow = str(scope)
            self.follow_since = await database_sync_to_async(timezone.now)()
        elif kind == "ping":
            ping_id = message.get("id", "")
            if not isinstance(ping_id, str | int) or len(str(ping_id)) > MAX_PING_ID:
                raise ProtocolError("bad_message", "id must be a short string.")
            await self.send_message("pong", id=ping_id)
        else:
            raise ProtocolError("unknown_type", "Unknown message type.")

    def job_ids(self, message: dict[str, Any]) -> list[tuple[str, uuid.UUID | None]]:
        jobs = message.get("jobs")
        if not isinstance(jobs, list) or not all(isinstance(j, str) for j in jobs):
            raise ProtocolError("bad_message", "jobs must be a list of job ids.")
        if len(jobs) > MAX_IDS_PER_MESSAGE:
            raise ProtocolError(
                "bad_message", f"At most {MAX_IDS_PER_MESSAGE} job ids per message."
            )
        parsed: list[tuple[str, uuid.UUID | None]] = []
        for raw in jobs:
            try:
                parsed.append((raw[:64], uuid.UUID(raw)))
            except ValueError:
                parsed.append((raw[:64], None))
        return parsed

    async def subscribe(self, ids: list[tuple[str, uuid.UUID | None]]) -> None:
        keys = [key for _raw, key in ids if key is not None]
        jobs = await database_sync_to_async(self.load_jobs)(keys)
        overflow = False
        for raw, key in ids:
            job = jobs.get(key) if key is not None else None
            if job is None or key is None:
                await self.send_message("job_unknown", id=raw)
                continue
            if not job["done"] and key not in self.tracked:
                if len(self.tracked) >= MAX_JOBS:
                    overflow = True
                    continue
                self.tracked.add(key)
            self.sent[key] = (job["data"]["state"], job["data"]["phase"])
            await self.send_message("job", job=job["data"])
        if overflow:
            await self.fail(
                ProtocolError(
                    "too_many_jobs", f"At most {MAX_JOBS} unfinished jobs per socket.", None
                )
            )

    def load_jobs(self, keys: list[uuid.UUID]) -> dict[uuid.UUID, dict[str, Any]]:
        jobs = ScanJob.objects.select_related("user").filter(pk__in=keys)
        return {job.pk: {"done": job.done, "data": services.job_json(job)} for job in jobs}

    # -- server push ---------------------------------------------------------

    def changes(self) -> tuple[list[tuple[uuid.UUID, bool, dict[str, Any]]], Any]:
        """Followed jobs changed since the last look, and the time of this look."""
        now = timezone.now()
        condition = Q(pk__in=list(self.tracked))
        if self.follow == "mine":
            condition |= Q(user_id=self.user_id, created_at__gte=self.follow_since)
        elif self.follow == "all":
            condition |= Q(created_at__gte=self.follow_since)
        # Look back a second and de-duplicate, so a change committed while the
        # previous look ran is not missed.
        since = self.since - timedelta(seconds=1)
        jobs = ScanJob.objects.select_related("user").filter(condition, updated_at__gte=since)
        return [(job.pk, job.done, services.job_json(job)) for job in jobs], now

    def user_still_allowed(self) -> bool:
        user = get_user_model().objects.filter(pk=self.user_id).first()
        return services.can_scan(user)

    async def poll(self) -> None:
        try:
            while not self.closing:
                await asyncio.sleep(POLL_SECONDS)
                now = time.monotonic()
                if now - self.opened > LIFETIME_SECONDS:
                    self.closing = True
                    await self.close(code=CLOSE_LIFETIME)
                    return
                if now - self.last_recheck > RECHECK_SECONDS:
                    self.last_recheck = now
                    if not await database_sync_to_async(self.user_still_allowed)():
                        self.closing = True
                        await self.close(code=CLOSE_FORBIDDEN)
                        return
                if self.tracked or self.follow != "none":
                    await self.push_changes()
                if now - self.last_compiled_check > COMPILED_SECONDS:
                    self.last_compiled_check = now
                    status = await database_sync_to_async(scanner.compiled_status)()
                    compiled = compiled_json(status)
                    if compiled != self.compiled:
                        self.compiled = compiled
                        await self.send_message("compiled", compiled=compiled)
        except asyncio.CancelledError:
            raise

    async def push_changes(self) -> None:
        changed, looked_at = await database_sync_to_async(self.changes)()
        self.since = looked_at
        for key, done, data in changed:
            followed_new = key not in self.tracked and key not in self.sent
            if key not in self.tracked and not followed_new:
                continue  # unsubscribed, or already reported finished
            if followed_new and not done:
                if len(self.tracked) >= MAX_JOBS:
                    continue
                self.tracked.add(key)
            state = (data["state"], data["phase"])
            if self.sent.get(key) == state:
                continue
            self.sent[key] = state
            if done:
                self.tracked.discard(key)
            await self.send_message("job", job=data)
