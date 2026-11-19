"""
Admin for raw data. Rule content is only changed through the services
(rules.services.editing / importer), which hash, version and compile-check
it, so content fields are read-only here, versions and import history are
fully read-only, and deletions go through the editing service (PLAN.md
section 13, finding 6): deleting is recoverable, restoring and purging are
actions, and purging needs the purge permission (PLAN.md 12.11).
"""

from collections.abc import Sequence
from typing import Any

from django.contrib import admin
from django.db.models import Model, QuerySet
from django.http import HttpRequest

from accounts.models import User
from rules.models import ImportFile, ImportRun, Rule, Ruleset, RuleVersion, Tag
from rules.services import editing


class RecoverableDeleteAdmin(admin.ModelAdmin):
    """
    Lists deleted rows too (filter "deleted at"); deleting flags rows through
    the editing service and keeps everything, so the confirmation page lists
    only the objects themselves; "restore" and "purge" are actions, purge
    only for users with the model's purge permission.
    """

    purge_permission = ""
    actions = ["restore_selected", "purge_selected"]

    def get_queryset(self, request: HttpRequest) -> QuerySet:
        return self.model.all_objects.all()

    def get_deleted_objects(
        self, objs: Sequence[Model] | QuerySet, request: HttpRequest
    ) -> tuple[list[str], dict[str, int], set[str], list[str]]:
        names = [str(obj) for obj in objs]
        return names, {str(self.model._meta.verbose_name_plural): len(names)}, set(), []

    def has_purge_permission(self, request: HttpRequest) -> bool:
        return request.user.has_perm(self.purge_permission)

    def restore(self, obj: Any, request: HttpRequest) -> None:
        raise NotImplementedError

    def purge(self, obj: Any) -> None:
        raise NotImplementedError

    @admin.action(description="Restore selected deleted %(verbose_name_plural)s")
    def restore_selected(self, request: HttpRequest, queryset: QuerySet) -> None:
        for obj in queryset.filter(deleted_at__isnull=False):
            self.restore(obj, request)

    @admin.action(
        description="Purge selected %(verbose_name_plural)s permanently, with history",
        permissions=["purge"],
    )
    def purge_selected(self, request: HttpRequest, queryset: QuerySet) -> None:
        for obj in queryset:
            self.purge(obj)


class ReadOnlyAdmin(admin.ModelAdmin):
    """Viewable in the admin, never added or changed there."""

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False

    def has_change_permission(self, request: HttpRequest, obj: Model | None = None) -> bool:
        return False


class RuleInline(admin.TabularInline):
    model = Rule
    fields = ["position", "name", "version", "updated_at", "removed_at"]
    readonly_fields = fields
    show_change_link = True
    can_delete = False
    extra = 0

    def has_add_permission(self, request: HttpRequest, obj: Model | None = None) -> bool:
        return False


@admin.register(Ruleset)
class RulesetAdmin(RecoverableDeleteAdmin):
    purge_permission = "rules.purge_ruleset"
    list_display = [
        "name",
        "origin",
        "path",
        "updated_at",
        "last_imported_at",
        "compiles",
        "deleted_at",
    ]
    list_filter = ["origin", "last_imported_at", ("deleted_at", admin.EmptyFieldListFilter)]
    search_fields = ["name", "path"]
    # Only the display name is editable; identity, content and status come
    # from imports and compile checks.
    readonly_fields = [
        "origin",
        "path",
        "original_content",
        "sha256",
        "compile_error",
        "created_at",
        "updated_at",
        "last_imported_at",
        "deleted_at",
        "deleted_by",
    ]
    date_hierarchy = "updated_at"
    inlines = [RuleInline]

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False

    def delete_model(self, request: HttpRequest, obj: Ruleset) -> None:
        editing.delete_ruleset(obj, user=_user(request))

    def delete_queryset(self, request: HttpRequest, queryset: QuerySet[Ruleset]) -> None:
        for ruleset in queryset:
            editing.delete_ruleset(ruleset, user=_user(request))

    def restore(self, obj: Ruleset, request: HttpRequest) -> None:
        editing.restore_ruleset(obj, user=_user(request))

    def purge(self, obj: Ruleset) -> None:
        editing.purge_ruleset(obj)

    @admin.display(boolean=True)
    def compiles(self, obj: Ruleset) -> bool:
        return not obj.compile_error


@admin.register(Tag)
class TagAdmin(ReadOnlyAdmin):
    """Tags are parsed from rule sources; renaming or deleting one here would desync them."""

    search_fields = ["name"]

    def has_delete_permission(self, request: HttpRequest, obj: Model | None = None) -> bool:
        return False


class RuleVersionInline(admin.TabularInline):
    model = RuleVersion
    fields = ["number", "origin", "created_at", "created_by", "import_run"]
    readonly_fields = fields
    can_delete = False
    extra = 0

    def has_add_permission(self, request: HttpRequest, obj: Model | None = None) -> bool:
        return False


@admin.register(Rule)
class RuleAdmin(RecoverableDeleteAdmin):
    purge_permission = "rules.purge_rule"
    list_display = [
        "name",
        "ruleset",
        "author",
        "version",
        "updated_at",
        "compiles",
        "is_modified",
        "removed_at",
        "deleted_at",
    ]
    list_filter = [
        "is_private",
        "is_global",
        "removed_at",
        ("deleted_at", admin.EmptyFieldListFilter),
        "tags",
        "ruleset__origin",
    ]
    list_select_related = ["ruleset"]
    search_fields = ["name", "description", "author", "ruleset__name"]
    date_hierarchy = "updated_at"
    inlines = [RuleVersionInline]

    def get_queryset(self, request: HttpRequest) -> QuerySet[Rule]:
        return super().get_queryset(request).defer("ruleset__original_content")

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False

    def has_change_permission(self, request: HttpRequest, obj: Model | None = None) -> bool:
        # Content changes go through the editor, which versions and compiles them.
        return False

    def delete_model(self, request: HttpRequest, obj: Rule) -> None:
        editing.delete_rule(obj, user=_user(request))

    def delete_queryset(self, request: HttpRequest, queryset: QuerySet[Rule]) -> None:
        for rule in queryset:
            editing.delete_rule(rule, user=_user(request))

    def restore(self, obj: Rule, request: HttpRequest) -> None:
        editing.restore_rule(obj, user=_user(request))

    def purge(self, obj: Rule) -> None:
        editing.purge_rule(obj)

    @admin.display(boolean=True)
    def compiles(self, obj: Rule) -> bool:
        return obj.compiles

    @admin.display(boolean=True, description="modified locally")
    def is_modified(self, obj: Rule) -> bool:
        return obj.is_modified


@admin.register(RuleVersion)
class RuleVersionAdmin(ReadOnlyAdmin):
    list_display = ["rule", "number", "origin", "created_at", "created_by"]
    list_filter = ["origin", "created_at"]
    list_select_related = ["rule", "created_by"]
    search_fields = ["rule__name"]

    def has_delete_permission(self, request: HttpRequest, obj: Model | None = None) -> bool:
        return False


class ImportFileInline(admin.TabularInline):
    model = ImportFile
    fields = [
        "path",
        "status",
        "ruleset",
        "rules_created",
        "rules_updated",
        "rules_removed",
        "rules_unchanged",
        "message",
    ]
    readonly_fields = fields
    can_delete = False
    extra = 0

    def has_add_permission(self, request: HttpRequest, obj: Model | None = None) -> bool:
        return False


@admin.register(ImportRun)
class ImportRunAdmin(ReadOnlyAdmin):
    list_display = [
        "started_at",
        "origin",
        "source",
        "user",
        "files_seen",
        "files_changed",
        "files_failed",
        "rules_created",
        "rules_updated",
        "rules_removed",
    ]
    list_filter = ["origin", "started_at"]
    list_select_related = ["user"]
    search_fields = ["source"]
    date_hierarchy = "started_at"
    inlines = [ImportFileInline]


@admin.register(ImportFile)
class ImportFileAdmin(ReadOnlyAdmin):
    list_display = ["path", "status", "run", "ruleset", "rules_created", "rules_updated"]
    list_filter = ["status"]
    list_select_related = ["run", "ruleset"]
    search_fields = ["path", "message"]


def _user(request: HttpRequest) -> User | None:
    user = request.user
    return user if isinstance(user, User) else None
