"""
The rules revision: a counter that moves whenever the compiled rule set
would change (PLAN.md section 5.7). Writers call `bump()` inside their
transaction; everything else reads `current()`.
"""

from dataclasses import dataclass
from datetime import datetime

from django.db import transaction
from django.db.models import F
from django.utils import timezone

from rules.models import RulesRevision


@dataclass(frozen=True)
class Revision:
    number: int  # 0 before the first change
    changed_at: datetime | None  # None before the first change


def current() -> Revision:
    """The current revision: one primary-key lookup."""
    row = RulesRevision.objects.filter(pk=1).values_list("number", "changed_at").first()
    if row is None:
        return Revision(0, None)
    return Revision(*row)


def bump() -> None:
    """
    Increment the revision. Call it inside the transaction of the write that
    changes the rules, so the counter and the change commit together.
    """
    now = timezone.now()
    with transaction.atomic():
        if not RulesRevision.objects.filter(pk=1).update(number=F("number") + 1, changed_at=now):
            RulesRevision.objects.create(pk=1, number=1, changed_at=now)
