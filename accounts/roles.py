"""The Viewers and Editors groups and their exact permission sets."""

from typing import Any

from django.contrib.auth.models import Group, Permission
from django.db import DEFAULT_DB_ALIAS

VIEWERS = "Viewers"
EDITORS = "Editors"

VIEWER_PERMISSIONS: list[str] = [
    "view_importfile",
    "view_importrun",
    "view_rule",
    "view_ruleset",
    "view_ruleversion",
    "view_tag",
    "scan_rules",
]
EDITOR_PERMISSIONS: list[str] = [
    *VIEWER_PERMISSIONS,
    "add_rule",
    "change_rule",
    "delete_rule",
    "add_ruleset",
    "change_ruleset",
    "delete_ruleset",
    "import_rules",
]


def ensure_roles(using: str = DEFAULT_DB_ALIAS, **kwargs: Any) -> None:
    """
    Create the role groups and set their permissions to exactly the defined
    sets in database `using` (post_migrate passes the database it migrated).
    Connected to post_migrate for the rules app, after Django has created
    that app's permissions; safe to run any number of times.
    """
    for name, codenames in ((VIEWERS, VIEWER_PERMISSIONS), (EDITORS, EDITOR_PERMISSIONS)):
        permissions = Permission.objects.using(using).filter(
            content_type__app_label="rules", codename__in=codenames
        )
        group, _ = Group.objects.using(using).get_or_create(name=name)
        group.permissions.set(permissions)
