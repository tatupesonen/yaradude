from django.contrib import admin
from django.db.models import Model
from django.http import HttpRequest

from rules.models import ImportFile, ImportRun, Rule, Ruleset, RuleVersion, Tag


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
class RulesetAdmin(admin.ModelAdmin):
    list_display = ["name", "origin", "path", "updated_at", "last_imported_at", "compiles"]
    list_filter = ["origin", "last_imported_at"]
    search_fields = ["name", "path"]
    readonly_fields = ["created_at", "sha256"]
    date_hierarchy = "updated_at"
    inlines = [RuleInline]

    @admin.display(boolean=True)
    def compiles(self, obj: Ruleset) -> bool:
        return not obj.compile_error


@admin.register(Tag)
class TagAdmin(admin.ModelAdmin):
    search_fields = ["name"]


class RuleVersionInline(admin.TabularInline):
    model = RuleVersion
    fields = ["number", "origin", "created_at", "created_by", "import_run"]
    readonly_fields = fields
    can_delete = False
    extra = 0

    def has_add_permission(self, request: HttpRequest, obj: Model | None = None) -> bool:
        return False


@admin.register(Rule)
class RuleAdmin(admin.ModelAdmin):
    list_display = [
        "name",
        "ruleset",
        "author",
        "version",
        "updated_at",
        "compiles",
        "is_modified",
        "removed_at",
    ]
    list_filter = ["is_private", "is_global", "removed_at", "tags", "ruleset__origin"]
    list_select_related = ["ruleset"]
    search_fields = ["name", "description", "author", "ruleset__name"]
    autocomplete_fields = ["tags"]
    raw_id_fields = ["ruleset"]
    readonly_fields = ["sha256", "imported_sha256", "created_at"]
    date_hierarchy = "updated_at"
    inlines = [RuleVersionInline]

    @admin.display(boolean=True)
    def compiles(self, obj: Rule) -> bool:
        return obj.compiles

    @admin.display(boolean=True, description="modified locally")
    def is_modified(self, obj: Rule) -> bool:
        return obj.is_modified


@admin.register(RuleVersion)
class RuleVersionAdmin(admin.ModelAdmin):
    list_display = ["rule", "number", "origin", "created_at", "created_by"]
    list_filter = ["origin", "created_at"]
    list_select_related = ["rule", "created_by"]
    search_fields = ["rule__name"]
    raw_id_fields = ["rule", "created_by", "import_run"]


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
class ImportRunAdmin(admin.ModelAdmin):
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
class ImportFileAdmin(admin.ModelAdmin):
    list_display = ["path", "status", "run", "ruleset", "rules_created", "rules_updated"]
    list_filter = ["status"]
    list_select_related = ["run", "ruleset"]
    search_fields = ["path", "message"]
    raw_id_fields = ["run", "ruleset"]
