from django.db.models import Count
from django.utils.decorators import method_decorator
from django.views.decorators.debug import sensitive_post_parameters
from django.views.generic import FormView

from rules.forms import ScanForm
from rules.models import Rule
from rules.services.scanner import ScanError, scan_sample
from rules.views.base import PermissionMixin
from rules.views.rules import rulesets_by_path


def limit_summary(path: str) -> dict:
    """How many active rules and rulesets a scan limited to `path` would use."""
    rules = Rule.objects.active()
    if path:
        rules = rules.filter(ruleset__in=rulesets_by_path(path))
    return rules.aggregate(rules=Count("pk"), rulesets=Count("ruleset", distinct=True))


@method_decorator(sensitive_post_parameters(), name="dispatch")
class ScanView(PermissionMixin, FormView):
    """
    Test-scan an uploaded sample. The result is rendered directly; the
    sample stays in memory (FILE_UPLOAD_HANDLERS) and is never stored.
    "Check limit" submits the same form with GET to preview the rule count.
    """

    permission_required = "rules.scan_rules"
    template_name = "rules/scan.html"
    form_class = ScanForm

    def get_initial(self):
        return {"path": self.request.GET.get("path", "").strip()[:1024]}

    def get_context_data(self, **kwargs):
        form = kwargs.get("form") or self.get_form()
        path = form["path"].value() or ""
        return super().get_context_data(limit=limit_summary(str(path).strip()), **kwargs)

    def form_valid(self, form):
        path = form.cleaned_data["path"].strip()
        rulesets = rulesets_by_path(path) if path else None
        try:
            result = scan_sample(form.cleaned_data["sample"], rulesets)
        except ScanError as error:
            form.add_error("sample", str(error))
            return self.form_invalid(form)
        return self.render_to_response(self.get_context_data(form=form, result=result))
