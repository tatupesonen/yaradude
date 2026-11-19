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


class RulesetQuerySet(models.QuerySet["Ruleset"]):
    def deleted(self) -> Self:
        """Deleted rulesets (only reachable through `Ruleset.all_objects`)."""
        return self.filter(deleted_at__isnull=False)


class _NotDeletedManager(models.Manager):
    """
    Default manager of Rule and Ruleset: leaves deleted rows out, so every
    list, count, related manager (`ruleset.rules`), detail lookup and the
    admin exclude them by construction (PLAN.md 12.11). Deleted rows are
    reached deliberately through `all_objects`.
    """

    def get_queryset(self) -> models.QuerySet:
        return super().get_queryset().filter(deleted_at__isnull=True)


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
    # Recoverable delete (PLAN.md 12.11); the ruleset still holds its
    # (origin, path) identity, so imports of its file are skipped.
    deleted_at = models.DateTimeField(null=True, blank=True)
    deleted_by: models.ForeignKey[User | None] = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
    )

    objects: ClassVar[RulesetManager] = cast(
        "RulesetManager", _NotDeletedManager.from_queryset(RulesetQuerySet)()
    )
    all_objects: ClassVar[RulesetManager] = cast("RulesetManager", RulesetQuerySet.as_manager())

    # Reverse relations, declared for the type checker only.
    rules: RuleRelatedManager
    import_files: RelatedManager[ImportFile]

    class Meta:
        ordering = ["name", "pk"]
        constraints = [
            models.UniqueConstraint(fields=["origin", "path"], name="unique_ruleset_origin_path"),
        ]
        permissions = [
            ("purge_ruleset", "Can permanently delete rulesets with their history"),
        ]

    def __str__(self) -> str:
        return self.name

    def get_absolute_url(self) -> str:
        return reverse("rules:ruleset_detail", kwargs={"pk": self.pk})

    @property
    def is_deleted(self) -> bool:
        return self.deleted_at is not None


class TagQuerySet(models.QuerySet["Tag"]):
    def unused(self) -> Self:
        return self.filter(rules=None)


class RuleQuerySet(models.QuerySet["Rule"]):
    def active(self) -> Self:
        """Rules that take part in compiles, scans and exports: neither removed nor deleted."""
        return self.filter(removed_at__isnull=True, deleted_at__isnull=True)

    def removed(self) -> Self:
        """Rules dropped from their file (and not deleted)."""
        return self.filter(removed_at__isnull=False, deleted_at__isnull=True)

    def deleted(self) -> Self:
        """Deleted rules (only reachable through `Rule.all_objects`)."""
        return self.filter(deleted_at__isnull=False)

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

    class RulesetManager(models.Manager["Ruleset"], RulesetQuerySet): ...

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
    imported_name = models.CharField(
        max_length=128,
        blank=True,
        help_text="Name in the file as last imported (kept when the rule is renamed locally); "
        "blank for manual rules and for rules last imported before this was recorded.",
    )
    version = models.PositiveIntegerField(default=1)
    compile_error = models.TextField(blank=True)
    compile_warnings: models.JSONField[list[str]] = models.JSONField(default=list, blank=True)
    removed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now, help_text="Content last changed.")
    # Recoverable delete (PLAN.md 12.11), distinct from removed_at. A rule
    # deleted together with its ruleset is marked so that restoring the
    # ruleset brings back exactly those rules.
    deleted_at = models.DateTimeField(null=True, blank=True)
    deleted_by: models.ForeignKey[User | None] = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
    )
    deleted_with_ruleset = models.BooleanField(default=False)

    objects: ClassVar[RuleManager] = cast(
        "RuleManager", _NotDeletedManager.from_queryset(RuleQuerySet)()
    )
    all_objects: ClassVar[RuleManager] = cast("RuleManager", RuleQuerySet.as_manager())

    versions: RelatedManager[RuleVersion]

    class Meta:
        ordering = ["ruleset_id", "position", "pk"]
        constraints = [
            models.UniqueConstraint(fields=["ruleset", "name"], name="unique_rule_name_in_ruleset"),
        ]
        indexes = [
            models.Index(fields=["name"]),
            models.Index(fields=["updated_at"]),
            # Rules in file order (compile checks, ruleset pages).
            models.Index(fields=["ruleset", "position"], name="rule_ruleset_position_idx"),
            # Partial indexes for the status filters of the rule list (sorted
            # by name); each condition is written exactly as the queryset
            # methods / list filters spell it, so SQLite can match it.
            models.Index(
                fields=["name"],
                condition=models.Q(removed_at__isnull=True, deleted_at__isnull=True)
                & ~models.Q(compile_error=""),
                name="rule_failing_name_idx",
            ),
            models.Index(
                fields=["name"],
                condition=models.Q(removed_at__isnull=False, deleted_at__isnull=True),
                name="rule_removed_name_idx",
            ),
            models.Index(
                fields=["name"],
                condition=models.Q(
                    removed_at__isnull=True, deleted_at__isnull=True, compile_error=""
                )
                & ~models.Q(compile_warnings=[]),
                name="rule_warnings_name_idx",
            ),
            models.Index(
                fields=["name"],
                condition=models.Q(removed_at__isnull=True, deleted_at__isnull=True)
                & ~models.Q(imported_sha256="")
                & ~models.Q(sha256=models.F("imported_sha256")),
                name="rule_modified_name_idx",
            ),
            # The "Deleted" view, newest first.
            models.Index(
                fields=["deleted_at"],
                condition=models.Q(deleted_at__isnull=False),
                name="rule_deleted_idx",
            ),
        ]
        permissions = [
            ("import_rules", "Can import rules"),
            ("scan_rules", "Can test-scan samples"),
            ("purge_rule", "Can permanently delete rules with their history"),
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
    def is_deleted(self) -> bool:
        return self.deleted_at is not None

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
    # Deleted in yaradude, so the import leaves them alone (PLAN.md 12.11).
    files_skipped = models.PositiveIntegerField(default=0)
    rules_skipped = models.PositiveIntegerField(default=0)

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
        files = (
            f"files: {self.files_seen} seen, {self.files_changed} changed, "
            f"{self.files_unchanged} unchanged, {self.files_failed} failed"
        )
        rules = (
            f"rules: {self.rules_created} created, {self.rules_updated} updated, "
            f"{self.rules_removed} removed, {self.rules_unchanged} unchanged"
        )
        if self.files_skipped:
            files += f", {self.files_skipped} skipped (deleted)"
        if self.rules_skipped:
            rules += f", {self.rules_skipped} skipped (deleted)"
        return f"{files}; {rules}"


class ImportFile(models.Model):
    """Result for one file of an import run; only changed, failed or skipped files are stored."""

    class Status(models.TextChoices):
        CREATED = "created", "Created"
        UPDATED = "updated", "Updated"
        FAILED = "failed", "Failed"
        SKIPPED = "skipped", "Skipped (deleted)"

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
    rules_skipped = models.PositiveIntegerField(default=0)
    message = models.TextField(blank=True)

    class Meta:
        ordering = ["run_id", "pk"]

    def __str__(self) -> str:
        return f"{self.path} ({self.get_status_display()})"


class RulesRevision(models.Model):
    """
    A single row counting changes to what the compiled rule set should hold:
    which rules are active and compile, their content and their order. It is
    incremented by rules.services.revision.bump() inside the transaction of
    every such write, so readers (the scan cache) can tell cheaply whether
    anything changed. Read it with rules.services.revision.current().
    """

    number = models.PositiveBigIntegerField(default=0)
    changed_at = models.DateTimeField(default=timezone.now)

    class Meta:
        constraints = [
            models.CheckConstraint(condition=models.Q(pk=1), name="rules_revision_single_row"),
        ]

    def __str__(self) -> str:
        return f"revision {self.number}"
