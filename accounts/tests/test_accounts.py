from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.core.management import call_command
from django.test import TestCase

from accounts.models import User
from accounts.roles import EDITORS, VIEWERS, ensure_roles


def codenames(group_name: str) -> list[tuple[str, str]]:
    group = Group.objects.get(name=group_name)
    return sorted(group.permissions.values_list("content_type__app_label", "codename"))


class UserModelTests(TestCase):
    def test_custom_user_model(self) -> None:
        self.assertIs(get_user_model(), User)
        self.assertEqual(User._meta.db_table, "accounts_user")


class RoleTests(TestCase):
    VIEWER = [
        ("rules", "scan_rules"),
        ("rules", "view_importfile"),
        ("rules", "view_importrun"),
        ("rules", "view_rule"),
        ("rules", "view_ruleset"),
        ("rules", "view_ruleversion"),
        ("rules", "view_tag"),
    ]
    EDITOR = sorted(
        VIEWER
        + [
            ("rules", "add_rule"),
            ("rules", "add_ruleset"),
            ("rules", "change_rule"),
            ("rules", "change_ruleset"),
            ("rules", "delete_rule"),
            ("rules", "delete_ruleset"),
            ("rules", "import_rules"),
        ]
    )

    def test_groups_created_by_migrate(self) -> None:
        self.assertEqual(codenames(VIEWERS), self.VIEWER)
        self.assertEqual(codenames(EDITORS), self.EDITOR)

    def test_bootstrap_is_idempotent_and_restores_exact_sets(self) -> None:
        viewers = Group.objects.get(name=VIEWERS)
        viewers.permissions.add(Permission.objects.get(codename="delete_rule"))
        viewers.permissions.remove(Permission.objects.get(codename="scan_rules"))
        ensure_roles()
        ensure_roles()
        call_command("migrate", verbosity=0)
        self.assertEqual(Group.objects.filter(name__in=[VIEWERS, EDITORS]).count(), 2)
        self.assertEqual(codenames(VIEWERS), self.VIEWER)
        self.assertEqual(codenames(EDITORS), self.EDITOR)

    def test_permissions_through_groups(self) -> None:
        viewer = User.objects.create_user("viewer")
        viewer.groups.add(Group.objects.get(name=VIEWERS))
        editor = User.objects.create_user("editor")
        editor.groups.add(Group.objects.get(name=EDITORS))
        nobody = User.objects.create_user("nobody")

        self.assertTrue(viewer.has_perms(["rules.view_rule", "rules.scan_rules"]))
        self.assertFalse(viewer.has_perm("rules.change_rule"))
        self.assertFalse(viewer.has_perm("rules.import_rules"))
        self.assertTrue(
            editor.has_perms(["rules.change_rule", "rules.delete_ruleset", "rules.import_rules"])
        )
        self.assertFalse(editor.has_perm("auth.change_user"))
        self.assertFalse(nobody.has_perm("rules.view_rule"))
