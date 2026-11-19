from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from django.conf import settings
from django.db import models
from django.utils import timezone

if TYPE_CHECKING:
    from accounts.models import User

KEY_PREFIX = "yd_"


class ApiKey(models.Model):
    """
    A personal API key. The secret itself is never stored: only its SHA-256
    and a public identifier (`public_id`) that is part of the key and is
    shown as its recognisable prefix (`yd_<public_id>`). `api.keys` creates
    and checks keys.
    """

    user: models.ForeignKey[User] = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="api_keys"
    )
    name = models.CharField(max_length=100)
    public_id = models.CharField(max_length=16, unique=True, editable=False)
    secret_sha256 = models.CharField(max_length=64, editable=False)
    created_at = models.DateTimeField(default=timezone.now, editable=False)
    # Updated at most once per YARADUDE_API_KEY_TOUCH_SECONDS, not per request.
    last_used_at = models.DateTimeField(null=True, blank=True, editable=False)
    expires_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at", "-pk"]
        verbose_name = "API key"

    def __str__(self) -> str:
        return f"{self.prefix} ({self.name})"

    @property
    def prefix(self) -> str:
        """The visible start of the key, e.g. `yd_3f9a0c1b7d2e`."""
        return f"{KEY_PREFIX}{self.public_id}"

    @property
    def is_revoked(self) -> bool:
        return self.revoked_at is not None

    def is_expired(self, now: datetime | None = None) -> bool:
        return self.expires_at is not None and self.expires_at <= (now or timezone.now())

    @property
    def is_usable(self) -> bool:
        return not self.is_revoked and not self.is_expired()
