from django.contrib import messages
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.db.models import Prefetch, Q
from django.http import Http404
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse
from django.views.generic import FormView, TemplateView, View

from rules.forms import NEW_RULESET, ExportForm, RuleCreateForm, RuleFilterForm, RuleUpdateForm
from rules.models import Rule, RuleVersion, Ruleset, Tag
from rules.services import editing, exporter
from rules.services.diffing import diff_versions, previous_version
from rules.views.base import PermissionMixin, file_response, paginate

SORTS = {
    # Base-table columns with the primary key as the only tiebreaker, so
    # SQLite can walk an index instead of sorting the joined rows; sorting
    # by ruleset is the one option that pays for a sort.
    "name": ["name", "pk"],
    "ruleset": ["ruleset__name", "ruleset_id", "position", "pk"],
    "updated": ["updated_at", "pk"],
    "created": ["created_at", "pk"],
}


def rulesets_by_path(path: str):
    """
    Rulesets selected by a path filter: a value ending in "/" is a directory
    prefix (e.g. "signature-base/"), anything else matches anywhere in the path.
    """
    if path.endswith("/"):
        return Ruleset.objects.filter(path__startswith=path)
    return Ruleset.objects.filter(path__icontains=path)


def filtered_rules(values: dict):
    """Rules matching the list filters, in the requested order."""
    rules = Rule.objects.all()
    status = values["status"]
    if status == "removed":
        rules = rules.removed()
    elif status != "all":
        rules = rules.active()
        if status == "error":
            rules = rules.failing()
        elif status == "warnings":
            rules = rules.filter(compile_error="").exclude(compile_warnings=[])
        elif status == "modified":
            rules = rules.modified()
    if values["q"]:
        q = values["q"]
        rules = rules.filter(
            Q(name__icontains=q)
            | Q(description__icontains=q)
            | Q(author__icontains=q)
            | Q(source__icontains=q)
        )
    if values["ruleset"]:
        rules = rules.filter(ruleset_id=values["ruleset"])
    if values["path"]:
        rules = rules.filter(ruleset__in=rulesets_by_path(values["path"]))
    if values["tag"]:
        rules = rules.filter(tags__name=values["tag"])
    sort = values["sort"]
    fields = SORTS[sort.lstrip("-")]
    if sort.startswith("-"):
        fields = [f"-{field}" for field in fields]
    return rules.order_by(*fields)


class RuleListView(PermissionMixin, TemplateView):
    permission_required = "rules.view_rule"
    template_name = "rules/rule_list.html"

    def get_context_data(self, **kwargs):
        form = RuleFilterForm(self.request.GET)
        values = form.values()
        rules = (
            filtered_rules(values)
            .select_related("ruleset")
            .prefetch_related(Prefetch("tags", queryset=Tag.objects.order_by("name")))
            # Large text columns would be carried through the sort of every
            # row before OFFSET applies, which makes deep pages slow.
            .defer("source", "meta", "ruleset__original_content")
        )
        page = paginate(self.request, rules)
        filtered = any(values[key] for key in ("q", "ruleset", "path", "tag", "status"))
        return super().get_context_data(
            form=form,
            values=values,
            page=page,
            filtered=filtered,
            has_rules=filtered or page.paginator.count > 0 or Rule.objects.exists(),
            selected_ruleset=(
                Ruleset.objects.filter(pk=values["ruleset"]).only("pk", "name").first()
                if values["ruleset"]
                else None
            ),
            tags=Tag.objects.order_by("name").values_list("name", flat=True),
            export_form=ExportForm(initial={"format": "yar"}),
            **kwargs,
        )


class RuleDetailView(PermissionMixin, TemplateView):
    permission_required = "rules.view_rule"
    template_name = "rules/rule_detail.html"

    def get_context_data(self, **kwargs):
        rule = get_object_or_404(
            Rule.objects.select_related("ruleset").prefetch_related("tags"), pk=self.kwargs["pk"]
        )
        versions = rule.versions.select_related("created_by", "import_run").order_by("-number")
        return super().get_context_data(rule=rule, versions=versions, **kwargs)


class RuleDownloadView(PermissionMixin, View):
    permission_required = "rules.view_rule"

    def get(self, request, pk):
        return file_response(exporter.export_rule(get_object_or_404(Rule, pk=pk)))


class RuleVersionView(PermissionMixin, TemplateView):
    permission_required = ("rules.view_rule", "rules.view_ruleversion")
    template_name = "rules/rule_version.html"

    def get_context_data(self, **kwargs):
        version = get_object_or_404(
            RuleVersion.objects.select_related("rule__ruleset", "created_by", "import_run"),
            rule_id=self.kwargs["pk"],
            number=self.kwargs["number"],
        )
        previous = previous_version(version)
        rule = version.rule
        return super().get_context_data(
            rule=rule,
            version=version,
            previous=previous,
            next_version=rule.versions.filter(number__gt=version.number).order_by("number").first(),
            diff=diff_versions(previous, version),
            is_current=version.sha256 == rule.sha256,
            **kwargs,
        )


def _report_broken(request, result) -> None:
    if result.broken:
        names = ", ".join(broken.rule.name for broken in result.broken)
        messages.warning(
            request,
            f"Saved, but {len(result.broken)} other rule(s) in this ruleset no longer compile: "
            f"{names}.",
        )


class RuleRestoreView(PermissionMixin, View):
    permission_required = "rules.change_rule"
    http_method_names = ["post"]

    def post(self, request, pk, number):
        version = get_object_or_404(
            RuleVersion.objects.select_related("rule__ruleset"), rule_id=pk, number=number
        )
        old_number = version.rule.version
        result = editing.restore_version(version, user=request.user)
        if not result.ok:
            messages.error(request, f"Version {number} cannot be restored: {result.error}")
            return redirect(version.get_absolute_url())
        if result.rule.version == old_number:
            messages.info(request, f"Version {number} is the same as the current content.")
        else:
            messages.success(
                request, f"Restored version {number} as version {result.rule.version}."
            )
        _report_broken(request, result)
        return redirect(result.rule.get_absolute_url())


class _EditorMixin:
    """Validate / Save handling shared by the create and edit pages."""

    template_name = "rules/rule_form.html"

    def form_valid(self, form):
        text = form.cleaned_data["text"]
        if self.request.POST.get("action") == "validate":
            result = self.validate(form, text)
            return self.render_to_response(
                self.get_context_data(form=form, result=result, validated=True)
            )
        return self.save(form, text)

    def render_result(self, form, result):
        return self.render_to_response(self.get_context_data(form=form, result=result))


class RuleCreateView(PermissionMixin, _EditorMixin, FormView):
    permission_required = "rules.add_rule"
    form_class = RuleCreateForm
    rule = None

    def get_initial(self):
        initial = {"text": 'rule new_rule\n{\n    meta:\n        description = ""\n\n'
                   '    strings:\n        $a = "example"\n\n    condition:\n        $a\n}\n'}
        ruleset = self.request.GET.get("ruleset", "")
        if ruleset.isdigit():
            initial["ruleset"] = ruleset
        return initial

    def validate(self, form, text):
        if form.cleaned_data["ruleset"] != NEW_RULESET:
            return editing.validate_rule_text(form.cleaned_data["ruleset_obj"], text)
        # Validate inside the collection it would go into; a collection that
        # does not exist yet is created for the check and rolled back.
        with transaction.atomic():
            ruleset = editing.manual_ruleset(form.cleaned_data["new_ruleset"])
            result = editing.validate_rule_text(ruleset, text)
            transaction.set_rollback(True)
        return result

    def save(self, form, text):
        if form.cleaned_data["ruleset"] != NEW_RULESET:
            result = editing.create_rule(
                form.cleaned_data["ruleset_obj"], text, user=self.request.user
            )
        else:
            if not self.request.user.has_perm("rules.add_ruleset"):
                raise PermissionDenied("Creating a collection needs the add_ruleset permission.")
            # The collection is only kept if the rule is saved into it.
            with transaction.atomic():
                ruleset = editing.manual_ruleset(form.cleaned_data["new_ruleset"])
                result = editing.create_rule(ruleset, text, user=self.request.user)
                if not result.ok:
                    transaction.set_rollback(True)
        if not result.ok:
            return self.render_result(form, result)
        messages.success(self.request, f"Created rule {result.rule.name}.")
        _report_broken(self.request, result)
        return redirect(result.rule.get_absolute_url())

    def get_context_data(self, **kwargs):
        return super().get_context_data(creating=True, **kwargs)


class RuleEditView(PermissionMixin, _EditorMixin, FormView):
    permission_required = "rules.change_rule"
    form_class = RuleUpdateForm

    def load(self, pk, **kwargs):
        self.rule = get_object_or_404(
            Rule.objects.select_related("ruleset").defer("ruleset__original_content"), pk=pk
        )

    def get_initial(self):
        return {"text": self.rule.text, "version": self.rule.version}

    def validate(self, form, text):
        return editing.validate_rule_text(self.rule.ruleset, text, self.rule)

    def save(self, form, text):
        if form.cleaned_data["version"] != self.rule.version:
            form.add_error(
                None,
                f"This rule was changed (now version {self.rule.version}) after you opened "
                "the editor. Copy your text, reload the page and apply your change again.",
            )
            return self.form_invalid(form)
        old_version = self.rule.version
        result = editing.update_rule(self.rule, text, user=self.request.user)
        if not result.ok:
            return self.render_result(form, result)
        if result.rule.version == old_version:
            messages.info(self.request, "No changes to save.")
        else:
            messages.success(
                self.request, f"Saved {result.rule.name} as version {result.rule.version}."
            )
        _report_broken(self.request, result)
        return redirect(result.rule.get_absolute_url())

    def get_context_data(self, **kwargs):
        return super().get_context_data(rule=self.rule, **kwargs)


class RuleDeleteView(PermissionMixin, TemplateView):
    permission_required = "rules.delete_rule"
    template_name = "rules/rule_confirm_delete.html"

    def load(self, pk, **kwargs):
        self.rule = get_object_or_404(
            Rule.objects.select_related("ruleset").defer("ruleset__original_content"), pk=pk
        )

    def get_context_data(self, **kwargs):
        return super().get_context_data(
            rule=self.rule, version_count=self.rule.versions.count(), **kwargs
        )

    def post(self, request, pk):
        ruleset = self.rule.ruleset
        name = self.rule.name
        editing.delete_rule(self.rule)
        messages.success(request, f"Deleted rule {name} and its version history.")
        return redirect(ruleset.get_absolute_url())


class RuleExportView(PermissionMixin, View):
    """
    Export as .yar or .zip: the selected rules (POST from the rules list)
    or every rule matching the list filters (GET or POST with scope=filter).
    """

    permission_required = "rules.view_rule"

    def get(self, request):
        return self.export(request.GET)

    def post(self, request):
        return self.export(request.POST)

    def export(self, data):
        form = ExportForm(data)
        if not form.is_valid():
            raise Http404("Invalid export request.")
        if form.cleaned_data["scope"] == "selected":
            rules = Rule.objects.filter(pk__in=form.cleaned_data["ids"])
        else:
            rules = filtered_rules(RuleFilterForm(data).values())
        rules = list(rules.active().select_related("ruleset"))
        if not rules:
            messages.warning(self.request, "Nothing to export: no active rules were selected.")
            filters = RuleFilterForm(data).values()
            params = {k: v for k, v in filters.items() if v and not (k == "sort" and v == "name")}
            url = reverse("rules:rule_list")
            if params:
                from urllib.parse import urlencode

                url += "?" + urlencode(params)
            return redirect(url)
        if form.cleaned_data.get("format") == "zip":
            return file_response(exporter.export_zip(rules))
        return file_response(exporter.export_combined(rules))
