from django.contrib import messages
from django.db.models import Count, Q
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse
from django.views.generic import TemplateView, View

from rules.forms import RulesetFilterForm
from rules.models import Rule, Ruleset
from rules.services import editing, exporter
from rules.views.base import PermissionMixin, file_response, paginate

SORTS = {
    "name": ["name", "pk"],
    "updated": ["updated_at", "pk"],
    "imported": ["last_imported_at", "pk"],
    "rules": ["active_count", "name", "pk"],
}

ACTIVE = Q(rules__removed_at__isnull=True)


def with_counts(queryset):
    return queryset.annotate(
        active_count=Count("rules", filter=ACTIVE),
        failing_count=Count("rules", filter=ACTIVE & ~Q(rules__compile_error="")),
        removed_count=Count("rules", filter=~ACTIVE),
    )


class RulesetListView(PermissionMixin, TemplateView):
    permission_required = "rules.view_ruleset"
    template_name = "rules/ruleset_list.html"

    def get_context_data(self, **kwargs):
        form = RulesetFilterForm(self.request.GET)
        values = form.values()
        rulesets = Ruleset.objects.defer("original_content")
        if values["q"]:
            rulesets = rulesets.filter(
                Q(name__icontains=values["q"]) | Q(path__icontains=values["q"])
            )
        if values["origin"]:
            rulesets = rulesets.filter(origin=values["origin"])
        fields = SORTS[values["sort"].lstrip("-")]
        if values["sort"].startswith("-"):
            fields = [f"-{field}" for field in fields]
        page = paginate(self.request, with_counts(rulesets).order_by(*fields))
        filtered = bool(values["q"] or values["origin"])
        return super().get_context_data(
            form=form,
            values=values,
            page=page,
            filtered=filtered,
            **kwargs,
        )


class RulesetDetailView(PermissionMixin, TemplateView):
    permission_required = "rules.view_ruleset"
    template_name = "rules/ruleset_detail.html"

    def get_context_data(self, **kwargs):
        ruleset = get_object_or_404(
            with_counts(Ruleset.objects.defer("original_content")), pk=self.kwargs["pk"]
        )
        rules = (
            Rule.objects.filter(ruleset=ruleset)
            .defer("source", "meta")
            .prefetch_related("tags")
            .order_by("removed_at", "position", "pk")
        )
        return super().get_context_data(
            ruleset=ruleset,
            rules=rules,
            has_original=Ruleset.objects.filter(pk=ruleset.pk)
            .exclude(original_content="")
            .exists(),
            **kwargs,
        )


class RulesetDownloadView(PermissionMixin, View):
    permission_required = "rules.view_ruleset"

    def get(self, request, pk):
        return file_response(exporter.export_ruleset(get_object_or_404(Ruleset, pk=pk)))


class RulesetOriginalView(PermissionMixin, View):
    permission_required = "rules.view_ruleset"

    def get(self, request, pk):
        ruleset = get_object_or_404(Ruleset, pk=pk)
        if not ruleset.original_content:
            messages.info(request, "This ruleset was not imported from a file.")
            return redirect(ruleset.get_absolute_url())
        return file_response(exporter.export_ruleset_original(ruleset))


class RulesetDeleteView(PermissionMixin, TemplateView):
    permission_required = "rules.delete_ruleset"
    template_name = "rules/ruleset_confirm_delete.html"

    def load(self, pk, **kwargs):
        self.ruleset = get_object_or_404(
            with_counts(Ruleset.objects.defer("original_content")), pk=pk
        )

    def get_context_data(self, **kwargs):
        return super().get_context_data(ruleset=self.ruleset, **kwargs)

    def post(self, request, pk):
        name = self.ruleset.name
        editing.delete_ruleset(self.ruleset)
        messages.success(request, f"Deleted ruleset {name} with its rules and their history.")
        return redirect(reverse("rules:ruleset_list"))
