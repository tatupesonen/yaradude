from __future__ import annotations

from typing import TYPE_CHECKING

from django.contrib.auth.models import AbstractUser

if TYPE_CHECKING:
    from django.db.models.manager import RelatedManager

    from rules.models import ImportRun


class User(AbstractUser):
    # Reverse relation, declared for the type checker only.
    import_runs: RelatedManager[ImportRun]
