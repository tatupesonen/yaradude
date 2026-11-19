from pathlib import Path

from django.conf import settings
from django.contrib import messages
from django.shortcuts import get_object_or_404, redirect
from django.views.generic import TemplateView, View

from rules.forms import UploadForm
from rules.models import ImportRun
from rules.services import importer
from rules.views.base import PermissionMixin, paginate


MAX_COUNTED_FILES = 10_000


def count_rule_files(root: Path) -> int | None:
    """
    How many files a directory import would read (same selection as
    importer.import_directory: *.yar / *.yara, hidden paths skipped), for
    display only; None if the directory does not exist. Stops counting at
    MAX_COUNTED_FILES.
    """
    if not root.is_dir():
        return None
    count = 0
    for path in root.rglob("*"):
        if (
            path.suffix.lower() in importer.RULE_SUFFIXES
            and not any(part.startswith(".") for part in path.relative_to(root).parts)
            and path.is_file()
        ):
            count += 1
            if count >= MAX_COUNTED_FILES:
                break
    return count


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
            rules_dir_files=count_rule_files(Path(settings.YARADUDE_RULES_DIR)),
            max_counted_files=MAX_COUNTED_FILES,
            last_scan=ImportRun.objects.filter(origin=ImportRun.Origin.SCAN).first(),
            **kwargs,
        )


class ImportScanView(PermissionMixin, View):
    """Import the configured rules directory (never a path from the request)."""

    permission_required = "rules.import_rules"
    http_method_names = ["post"]

    def post(self, request):
        files = count_rule_files(Path(settings.YARADUDE_RULES_DIR))
        if not files:
            messages.error(
                request,
                "The configured rules directory does not exist."
                if files is None
                else "The configured rules directory contains no .yar or .yara files.",
            )
            return redirect("rules:import")
        run = importer.import_directory(settings.YARADUDE_RULES_DIR, user=request.user)
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
        run = importer.import_uploads(form.cleaned_data["files"], user=request.user)
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
