from dataclasses import dataclass, field
from pathlib import Path

from django.conf import settings
from django.contrib import messages
from django.shortcuts import get_object_or_404, redirect
from django.views.generic import TemplateView, View

from rules.forms import UploadForm
from rules.models import ImportRun
from rules.services import importer
from rules.services.importer import RuleFile
from rules.views.base import PermissionMixin, current_user, paginate


@dataclass(frozen=True)
class DirectoryStatus:
    """What a directory import would do, from importer.rule_files (display only)."""

    exists: bool
    importable: int = 0
    skipped: list[RuleFile] = field(default_factory=list)

    @property
    def reasons(self) -> list[tuple[str, list[str]]]:
        """Why files will be skipped: each reason with the paths it applies to."""
        grouped: dict[str, list[str]] = {}
        for file in self.skipped:
            grouped.setdefault(file.error, []).append(file.identity)
        return list(grouped.items())


def directory_status(root: Path) -> DirectoryStatus:
    """
    The rule files a directory import of `root` would process: the same
    selection as importer.import_directory, so the counts agree with the run.
    Files with an error (e.g. over the size limit) are recorded as failed.
    """
    if not root.is_dir():
        return DirectoryStatus(exists=False)
    files = importer.rule_files(root)
    skipped = [file for file in files if file.error]
    return DirectoryStatus(exists=True, importable=len(files) - len(skipped), skipped=skipped)


def _report(request, run: ImportRun) -> None:
    if run.files_failed:
        messages.warning(request, f"Import finished with {run.files_failed} failed file(s).")
    else:
        messages.success(request, "Import finished.")


class ImportView(PermissionMixin, TemplateView):
    """Directory scan, upload (Editors) and the history of import runs (everyone)."""

    permission_required = "rules.view_importrun"
    template_name = "rules/import.html"

    def get_context_data(self, **kwargs):
        kwargs.setdefault("upload_form", UploadForm())
        return super().get_context_data(
            page=paginate(self.request, ImportRun.objects.select_related("user"), per_page=25),
            rules_dir=settings.YARADUDE_RULES_DIR,
            # Only Editors see the directory card; listing the files costs a stat per file.
            rules_dir_status=(
                directory_status(Path(settings.YARADUDE_RULES_DIR))
                if self.request.user.has_perm("rules.import_rules")
                else None
            ),
            max_file_bytes=importer.max_file_bytes(),
            last_scan=ImportRun.objects.filter(origin=ImportRun.Origin.SCAN).first(),
            **kwargs,
        )


class ImportScanView(PermissionMixin, View):
    """Import the configured rules directory (never a path from the request)."""

    permission_required = "rules.import_rules"
    http_method_names = ["post"]

    def post(self, request):
        status = directory_status(Path(settings.YARADUDE_RULES_DIR))
        if not status.importable:
            if not status.exists:
                message = "The configured rules directory does not exist."
            elif status.skipped:
                message = "No rule file in the configured rules directory can be imported."
            else:
                message = "The configured rules directory contains no .yar or .yara files."
            messages.error(request, message)
            return redirect("rules:import")
        run = importer.import_directory(settings.YARADUDE_RULES_DIR, user=current_user(request))
        _report(request, run)
        return redirect(run.get_absolute_url())


class ImportUploadView(PermissionMixin, TemplateView):
    permission_required = "rules.import_rules"
    http_method_names = ["post"]
    template_name = "rules/import.html"

    def post(self, request):
        form = UploadForm(request.POST, request.FILES)
        if not form.is_valid():
            view = ImportView(request=request, kwargs={})
            context = view.get_context_data(upload_form=form)
            return self.render_to_response(context, status=400)
        run = importer.import_uploads(form.cleaned_data["rule_files"], user=current_user(request))
        _report(request, run)
        return redirect(run.get_absolute_url())


class ImportRunView(PermissionMixin, TemplateView):
    permission_required = "rules.view_importrun"
    template_name = "rules/import_run.html"

    def get_context_data(self, **kwargs):
        run = get_object_or_404(ImportRun.objects.select_related("user"), pk=self.kwargs["pk"])
        return super().get_context_data(
            run=run,
            files=run.files.select_related("ruleset").order_by("status", "path"),
            **kwargs,
        )
