"""
Django Tasks, re-exported for type checking: `django.tasks` (new in Django
6.0) is missing from the django-types stubs, so its imports carry the only
suppressions here. Import task APIs from this module.
"""

from django.tasks import (  # ty: ignore[import-not-found]  # Django 6.0 module absent from django-types 0.24
    Task,
    TaskContext,
    TaskResult,
    TaskResultStatus,
    task,
)
from django.tasks.signals import (  # ty: ignore[import-not-found]  # Django 6.0 module absent from django-types 0.24
    task_finished,
    task_started,
)

__all__ = [
    "Task",
    "TaskContext",
    "TaskResult",
    "TaskResultStatus",
    "task",
    "task_finished",
    "task_started",
]
