from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar, Self, cast

from django.conf import settings
from django.db import models
from django.urls import reverse
from django.utils import timezone

from rules.services.parser import MetaValue, ParsedRule, rule_text

if TYPE_CHECKING:
    from django.db.models.manager import ManyToManyRelatedManager, RelatedManager

    from accounts.models import User


class Ruleset(models.Model):
    """The rules of one source file, or a named manual collection."""

    class Origin(models.TextChoices):
        DIRECTORY = "directory", "Rules directory"
        UPLOAD = "upload", "Upload"
        MANUAL = "manual", "Manual"

    name = models.CharField(max_length=255)
    origin = models.CharField(max_length=16, choices=Origin.choices)
    # Identity within the origin: POSIX path relative to the rules directory
    # (absolute when imported by the CLI from elsewhere), the upload file
    # name, or the manual collection's name.
    path = models.CharField(max_length=1024)
    original_content = models.TextField(blank=True, help_text="File as last imported, verbatim.")
    sha256 = models.CharField(max_length=64, blank=True)
    compile_error = models.TextField(blank=True, help_text="Blank when every active rule compiles.")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(default=timezone.now, help_text="Content last changed.")
    last_imported_at = models.DateTimeField(null=True, blank=True)

    # Reverse relations, declared for the type checker only.
    rules: RuleRelatedManager
    import_files: RelatedManager[ImportFile]

    class Meta:
        ordering = ["name", "pk"]
        constraints = [
            models.UniqueConstraint(fields=["origin", "path"], name="unique_ruleset_origin_path"),
        ]

    def __str__(self) -> str:
        return self.name

    def get_absolute_url(self) -> str:
        return reverse("rules:ruleset_detail", kwargs={"pk": self.pk})


class TagQuerySet(models.QuerySet["Tag"]):
    def unused(self) -> Self:
        return self.filter(rules=None)


class RuleQuerySet(models.QuerySet["Rule"]):
    def active(self) -> Self:
        return self.filter(removed_at__isnull=True)

    def removed(self) -> Self:
        return self.filter(removed_at__isnull=False)

    def failing(self) -> Self:
        return self.exclude(compile_error="")

    def modified(self) -> Self:
        """Imported rules whose current content differs from the disk version."""
        return self.exclude(imported_sha256="").exclude(sha256=models.F("imported_sha256"))


if TYPE_CHECKING:
    # `QuerySet.as_manager()` builds a Manager subclass at runtime that copies
    # the queryset's methods, and related managers subclass the model's
    # default manager. The stubs cannot express that, so these classes
    # describe the result for the type checker; they do not exist at runtime.

    class TagManager(models.Manager["Tag"], TagQuerySet): ...

    class RuleManager(models.Manager["Rule"], RuleQuerySet): ...

    class RuleRelatedManager(RelatedManager["Rule"], RuleQuerySet): ...


class Tag(models.Model):
    name = models.CharField(max_length=128, unique=True)

    objects: ClassVar[TagManager] = cast("TagManager", TagQuerySet.as_manager())

    rules: ManyToManyRelatedManager[Rule, models.Model]

    class Meta:
        ordering = ["name"]

    def __str__(self) -> str:
        return self.name


class Rule(models.Model):
    ruleset = models.ForeignKey(Ruleset, on_delete=models.CASCADE, related_name="rules")
    name = models.CharField(max_length=128)
    position = models.PositiveIntegerField(default=0)
    source = models.TextField(help_text="The rule text, including attached leading comments.")
    imports: models.JSONField[list[str]] = models.JSONField(default=list, blank=True)
    meta: models.JSONField[list[list[MetaValue]]] = models.JSONField(
        default=list, blank=True, help_text="List of [key, value] pairs."
    )
    description = models.TextField(blank=True)
    author = models.CharField(max_length=255, blank=True)
    is_private = models.BooleanField(default=False)
    is_global = models.BooleanField(default=False)
    tags = models.ManyToManyField(Tag, blank=True, related_name="rules")
    sha256 = models.CharField(max_length=64)
    imported_sha256 = models.CharField(
        max_length=64, blank=True, help_text="Content as last imported; blank for manual rules."
    )
    version = models.PositiveIntegerField(default=1)
    compile_error = models.TextField(blank=True)
    compile_warnings: models.JSONField[list[str]] = models.JSONField(default=list, blank=True)
    removed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now, help_text="Content last changed.")

    objects: ClassVar[RuleManager] = cast("RuleManager", RuleQuerySet.as_manager())

    versions: RelatedManager[RuleVersion]

    class Meta:
        ordering = ["ruleset_id", "position", "pk"]
        constraints = [
            models.UniqueConstraint(fields=["ruleset", "name"], name="unique_rule_name_in_ruleset"),
        ]
        indexes = [
            models.Index(fields=["name"]),
            models.Index(fields=["updated_at"]),
        ]
        permissions = [
            ("import_rules", "Can import rules"),
            ("scan_rules", "Can test-scan samples"),
        ]

    def __str__(self) -> str:
        return self.name

    def get_absolute_url(self) -> str:
        return reverse("rules:rule_detail", kwargs={"pk": self.pk})

    @property
    def text(self) -> str:
        """Standalone rule text (imports and rule), as edited and downloaded."""
        return rule_text(self.imports, self.source)

    @property
    def is_modified(self) -> bool:
        """Changed locally since the last import."""
        return bool(self.imported_sha256) and self.sha256 != self.imported_sha256

    @property
    def is_removed(self) -> bool:
        return self.removed_at is not None

    @property
    def compiles(self) -> bool:
        return not self.compile_error

    def apply_parsed(self, parsed: ParsedRule) -> None:
        """Copy the content fields of a parsed rule onto this (unsaved) instance."""
        self.name = parsed.name
        self.source = parsed.source
        self.imports = parsed.imports
        self.meta = [list(pair) for pair in parsed.meta]
        self.description = parsed.description
        self.author = parsed.author[:255]
        self.is_private = parsed.is_private
        self.is_global = parsed.is_global
        self.sha256 = parsed.sha256

    def set_tags(self, names: list[str]) -> None:
        """Replace this rule's tags; callers delete `Tag.objects.unused()` afterwards."""
        tags = [Tag.objects.get_or_create(name=name)[0] for name in dict.fromkeys(names)]
        self.tags.set(tags)

    def record_version(
        self,
        origin: RuleVersion.Origin,
        user: User | None = None,
        import_run: ImportRun | None = None,
    ) -> RuleVersion:
        """Snapshot the current content as version `self.version`."""
        return RuleVersion.objects.create(
            rule=self,
            number=self.version,
            source=self.source,
            imports=self.imports,
            sha256=self.sha256,
            origin=origin,
            created_by=user,
            import_run=import_run,
        )


class RuleVersion(models.Model):
    """Immutable snapshot of a rule's content, one per content change."""

    class Origin(models.TextChoices):
        IMPORT = "import", "Import"
        UPLOAD = "upload", "Upload"
        CREATE = "create", "Created"
        EDIT = "edit", "Edited"
        RESTORE = "restore", "Restored"

    rule = models.ForeignKey(Rule, on_delete=models.CASCADE, related_name="versions")
    number = models.PositiveIntegerField()
    source = models.TextField()
    imports: models.JSONField[list[str]] = models.JSONField(default=list, blank=True)
    sha256 = models.CharField(max_length=64)
    origin = models.CharField(max_length=16, choices=Origin.choices)
    created_at = models.DateTimeField(default=timezone.now)
    created_by: models.ForeignKey[User | None] = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
    )
    import_run = models.ForeignKey(
        "ImportRun", on_delete=models.SET_NULL, null=True, blank=True, related_name="versions"
    )

    class Meta:
        ordering = ["rule_id", "-number"]
        constraints = [
            models.UniqueConstraint(fields=["rule", "number"], name="unique_rule_version_number"),
        ]

    def __str__(self) -> str:
        return f"{self.rule} v{self.number}"

    def get_absolute_url(self) -> str:
        return reverse("rules:rule_version", kwargs={"pk": self.rule_id, "number": self.number})

    @property
    def text(self) -> str:
        return rule_text(self.imports, self.source)


class ImportRun(models.Model):
    class Origin(models.TextChoices):
        SCAN = "scan", "Directory scan"
        UPLOAD = "upload", "Upload"
        CLI = "cli", "Command line"

    origin = models.CharField(max_length=16, choices=Origin.choices)
    source = models.CharField(max_length=1024, help_text="What was imported.")
    user: models.ForeignKey[User | None] = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="import_runs",
    )
    started_at = models.DateTimeField(default=timezone.now)
    finished_at = models.DateTimeField(null=True, blank=True)
    files_seen = models.PositiveIntegerField(default=0)
    files_changed = models.PositiveIntegerField(default=0)
    files_unchanged = models.PositiveIntegerField(default=0)
    files_failed = models.PositiveIntegerField(default=0)
    rules_created = models.PositiveIntegerField(default=0)
    rules_updated = models.PositiveIntegerField(default=0)
    rules_removed = models.PositiveIntegerField(default=0)
    rules_unchanged = models.PositiveIntegerField(default=0)

    files: RelatedManager[ImportFile]
    versions: RelatedManager[RuleVersion]

    class Meta:
        ordering = ["-started_at", "-pk"]

    def __str__(self) -> str:
        return f"{self.get_origin_display()} {self.source} ({self.started_at:%Y-%m-%d %H:%M})"

    def get_absolute_url(self) -> str:
        return reverse("rules:import_run", kwargs={"pk": self.pk})

    @property
    def summary(self) -> str:
        return (
            f"files: {self.files_seen} seen, {self.files_changed} changed, "
            f"{self.files_unchanged} unchanged, {self.files_failed} failed; "
            f"rules: {self.rules_created} created, {self.rules_updated} updated, "
            f"{self.rules_removed} removed, {self.rules_unchanged} unchanged"
        )


class ImportFile(models.Model):
    """Result for one file of an import run; only changed or failed files are stored."""

    class Status(models.TextChoices):
        CREATED = "created", "Created"
        UPDATED = "updated", "Updated"
        FAILED = "failed", "Failed"

    run = models.ForeignKey(ImportRun, on_delete=models.CASCADE, related_name="files")
    path = models.CharField(max_length=1024)
    status = models.CharField(max_length=16, choices=Status.choices)
    ruleset = models.ForeignKey(
        Ruleset, on_delete=models.SET_NULL, null=True, blank=True, related_name="import_files"
    )
    rules_created = models.PositiveIntegerField(default=0)
    rules_updated = models.PositiveIntegerField(default=0)
    rules_removed = models.PositiveIntegerField(default=0)
    rules_unchanged = models.PositiveIntegerField(default=0)
    message = models.TextField(blank=True)

    class Meta:
        ordering = ["run_id", "pk"]

    def __str__(self) -> str:
        return f"{self.path} ({self.get_status_display()})"
