"""
Personal API keys: creation, revocation and authentication.

A key looks like `yd_<public id>_<secret>`: 12 hex characters of public id
(48 random bits, unique, used to find the row and shown as the key's prefix)
and a 43-character URL-safe secret (256 random bits from `secrets`). Only the
SHA-256 of the whole key is stored. A fast hash is enough because the secret
has full entropy, so there is nothing to brute-force or look up in a
dictionary; a slow password hash would only add latency to every request.
The stored and presented hashes are compared with `hmac.compare_digest`.

Keys are never logged: nothing in this module or in the API passes the
presented key, or the Authorization header, to a logger or an error message.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import TYPE_CHECKING

from django.conf import settings
from django.db import DatabaseError, transaction
from django.utils import timezone

from api.models import KEY_PREFIX, ApiKey

if TYPE_CHECKING:
    from accounts.models import User

logger = logging.getLogger(__name__)

PUBLIC_ID_HEX = 12
SECRET_BYTES = 32
KEY_RE = re.compile(
    rf"^{KEY_PREFIX}(?P<public_id>[0-9a-f]{{{PUBLIC_ID_HEX}}})_(?P<secret>[A-Za-z0-9_-]{{43}})$"
)


class TooManyKeys(Exception):
    """The user already has the maximum number of usable keys."""


class Failure(StrEnum):
    """Why a presented key was refused (the API turns each into a JSON 401)."""

    MALFORMED = "malformed"
    UNKNOWN = "unknown"
    REVOKED = "revoked"
    EXPIRED = "expired"
    INACTIVE_USER = "inactive_user"


@dataclass(frozen=True)
class Authenticated:
    key: ApiKey
    user: User


def digest(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode()).hexdigest()


def max_keys() -> int:
    limit: int = settings.YARADUDE_API_MAX_KEYS_PER_USER
    return limit


def usable_keys(user: User):
    now = timezone.now()
    return ApiKey.objects.filter(user=user, revoked_at__isnull=True).exclude(expires_at__lte=now)


def create_key(user: User, name: str, expires_in: timedelta | None = None) -> tuple[ApiKey, str]:
    """
    Create a key for `user` and return it with the full secret key, which
    exists only in this return value: show it once and drop it.
    """
    with transaction.atomic():
        if usable_keys(user).count() >= max_keys():
            raise TooManyKeys(f"You can have at most {max_keys()} active API keys.")
        while True:
            public_id = secrets.token_hex(PUBLIC_ID_HEX // 2)
            if not ApiKey.objects.filter(public_id=public_id).exists():
                break
        raw_key = f"{KEY_PREFIX}{public_id}_{secrets.token_urlsafe(SECRET_BYTES)}"
        now = timezone.now()
        key = ApiKey.objects.create(
            user=user,
            name=name,
            public_id=public_id,
            secret_sha256=digest(raw_key),
            created_at=now,
            expires_at=now + expires_in if expires_in else None,
        )
    return key, raw_key


def revoke_key(key: ApiKey) -> None:
    if key.revoked_at is None:
        key.revoked_at = timezone.now()
        key.save(update_fields=["revoked_at"])


def authenticate(raw_key: str) -> Authenticated | Failure:
    """The key and its user, or why the key is refused."""
    match = KEY_RE.match(raw_key)
    if match is None:
        return Failure.MALFORMED
    key = (
        ApiKey.objects.select_related("user")
        .filter(public_id=match.group("public_id"))
        .only(
            "pk",
            "name",
            "public_id",
            "secret_sha256",
            "created_at",
            "last_used_at",
            "expires_at",
            "revoked_at",
            "user__id",
            "user__username",
            "user__first_name",
            "user__last_name",
            "user__email",
            "user__is_active",
            "user__is_staff",
            "user__is_superuser",
        )
        .first()
    )
    if key is None:
        # Compare anyway so that an unknown id costs the same as a wrong secret.
        hmac.compare_digest(digest(raw_key), "0" * 64)
        return Failure.UNKNOWN
    if not hmac.compare_digest(digest(raw_key), key.secret_sha256):
        return Failure.UNKNOWN
    now = timezone.now()
    if key.revoked_at is not None:
        return Failure.REVOKED
    if key.is_expired(now):
        return Failure.EXPIRED
    if not key.user.is_active:
        return Failure.INACTIVE_USER
    touch(key, now)
    return Authenticated(key=key, user=key.user)


def touch(key: ApiKey, now: datetime) -> bool:
    """
    Record that the key was used, but write at most once per
    YARADUDE_API_KEY_TOUCH_SECONDS: SQLite has a single writer, and a write
    on every API request would serialise all of them behind each other and
    behind imports. The update is conditional on the value read, so workers
    racing over the same key write it once. A locked database never fails
    the request; the next request after the interval tries again.
    Returns whether a write happened.
    """
    interval: int = settings.YARADUDE_API_KEY_TOUCH_SECONDS
    previous = key.last_used_at
    if previous is not None and now - previous < timedelta(seconds=interval):
        return False
    try:
        written = ApiKey.objects.filter(pk=key.pk, last_used_at=previous).update(last_used_at=now)
    except DatabaseError:
        logger.warning("Could not record the last use of API key %s", key.prefix)
        return False
    key.last_used_at = now
    return bool(written)
