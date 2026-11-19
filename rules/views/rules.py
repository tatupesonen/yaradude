from typing import Any

from django.contrib import messages
from django.core.exceptions import PermissionDenied
from django.db.models import Prefetch
from django.http import Http404, HttpResponse
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse
from django.utils.html import format_html
from django.views.generic import FormView, TemplateView, View

from rules.forms import (
    NEW_RULESET,
    RELEVANCE,
    ExportForm,
    RuleCreateForm,
    RuleFilterForm,
    RuleUpdateForm,
    default_sort,
)
from rules.models import Rule, Ruleset, RuleVersion, Tag
from rules.services import editing, exporter
from rules.services.diffing import diff_versions, previous_version
from rules.services.editing import EditResult
from rules.services.search import search_rules
from rules.views.base import (
    PermissionMixin,
    current_user,
    file_response,
    paginate,
    saved_rule,
)

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
    if values["ruleset"]:
        rules = rules.filter(ruleset_id=values["ruleset"])
    if values["path"]:
        rules = rules.filter(ruleset__in=rulesets_by_path(values["path"]))
    if values["tag"]:
        rules = rules.filter(tags__name=values["tag"])
    sort = values["sort"]
    if values["q"]:
        # Full-text search (literal phrase); relevance orders by its rank.
        rules = search_rules(rules, values["q"], rank=sort == RELEVANCE)
        if sort == RELEVANCE:
            return rules
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
            default_sort=default_sort(values["q"]),
            page=page,
            filtered=filtered,
            has_rules=filtered or page.paginator.count > 0 or Rule.objects.exists(),
            selected_ruleset=(
                Ruleset.objects.filter(pk=values["ruleset"]).only("pk", "name").first()
                if values["ruleset"]
                else None
            ),
            # Tags of rules that are not deleted (the join bypasses the default manager).
            tags=Tag.objects.filter(rules__deleted_at__isnull=True)
            .distinct()
            .order_by("name")
            .values_list("name", flat=True),
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
        # The join to the rule bypasses Rule's default manager: exclude
        # deleted rules explicitly, so their history is not shown as live.
        version = get_object_or_404(
            RuleVersion.objects.select_related("rule__ruleset", "created_by", "import_run"),
            rule__deleted_at__isnull=True,
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
            RuleVersion.objects.select_related("rule__ruleset"),
            rule__deleted_at__isnull=True,
            rule_id=pk,
            number=number,
        )
        # The rule's version as shown on the version page: the service refuses
        # the restore if the rule moved on after the page was rendered.
        shown = request.POST.get("version", "")
        if not shown.isdigit():
            messages.error(request, "The page was out of date. Check the versions and try again.")
            return redirect(version.get_absolute_url())
        result = editing.restore_version(
            version, user=current_user(request), expected_version=int(shown)
        )
        if result.conflict:
            return self.conflict(version, int(shown), result)
        if not result.ok:
            messages.error(request, f"Version {number} cannot be restored: {result.error}")
            return redirect(version.get_absolute_url())
        rule = saved_rule(result)
        if rule.version == int(shown):
            messages.info(request, f"Version {number} is the same as the current content.")
        else:
            messages.success(request, f"Restored version {number} as version {rule.version}.")
        _report_broken(request, result)
        return redirect(rule.get_absolute_url())

    def conflict(self, version: RuleVersion, shown: int, result: EditResult) -> HttpResponse:
        rule = version.rule
        current = Rule.objects.filter(pk=rule.pk).values_list("version", flat=True).first()
        if current is None:
            messages.error(
                self.request,
                f"Not restored: someone else deleted the rule {rule.name} meanwhile.",
            )
            return redirect(rule.ruleset.get_absolute_url())
        if current == shown:  # e.g. the name was taken by another rule meanwhile
            messages.error(
                self.request, f"Version {version.number} cannot be restored: {result.error}"
            )
            return redirect(version.get_absolute_url())
        messages.error(
            self.request,
            format_html(
                "Not restored: someone else changed this rule while you were looking at it; "
                'it is now <a href="{}">version {}</a> (the link shows what changed). '
                "Check that change, then restore version {} again if you still want it.",
                reverse("rules:rule_version", args=[rule.pk, current]),
                current,
                version.number,
            ),
        )
        return redirect(version.get_absolute_url())


class _EditorView(PermissionMixin, FormView):
    """Validate / Save handling shared by the create and edit pages."""

    template_name = "rules/rule_form.html"

    def validate(self, form: Any, text: str) -> EditResult:
        raise NotImplementedError

    def save(self, form: Any, text: str) -> HttpResponse:
        raise NotImplementedError

    def form_valid(self, form):
        text = form.cleaned_data["text"]
        if self.request.POST.get("action") == "validate":
            result = self.validate(form, text)
            return self.render_to_response(
                self.get_context_data(form=form, result=result, validated=True)
            )
        return self.save(form, text)

    def render_result(self, form: Any, result: EditResult) -> HttpResponse:
        return self.render_to_response(self.get_context_data(form=form, result=result))

    def saved(self, result: EditResult, message: str) -> HttpResponse:
        rule = saved_rule(result)
        messages.success(self.request, message.format(rule=rule))
        _report_broken(self.request, result)
        return redirect(rule.get_absolute_url())


class RuleCreateView(_EditorView):
    permission_required = "rules.add_rule"
    form_class = RuleCreateForm

    def get_initial(self):
        initial = {
            "text": 'rule new_rule\n{\n    meta:\n        description = ""\n\n'
            '    strings:\n        $a = "example"\n\n    condition:\n        $a\n}\n'
        }
        ruleset = self.request.GET.get("ruleset", "")
        if ruleset.isdigit():
            initial["ruleset"] = ruleset
        return initial

    def target(self, form: Any) -> Ruleset:
        """The chosen ruleset, or the new collection (unsaved if it does not exist yet)."""
        if form.cleaned_data["ruleset"] != NEW_RULESET:
            return form.cleaned_data["ruleset_obj"]
        return editing.manual_ruleset(form.cleaned_data["new_ruleset"], save=False)

    def validate(self, form, text):
        return editing.validate_rule_text(self.target(form), text)

    def save(self, form, text):
        user = current_user(self.request)
        ruleset = self.target(form)
        if ruleset.pk is None and not user.has_perm("rules.add_ruleset"):
            raise PermissionDenied("Creating a collection needs the add_ruleset permission.")
        # An unsaved collection is created together with the rule, in one
        # transaction, so a refused save leaves nothing behind.
        result = editing.create_rule(ruleset, text, user=user)
        if not result.ok:
            return self.render_result(form, result)
        return self.saved(result, "Created rule {rule.name}.")

    def get_context_data(self, **kwargs):
        return super().get_context_data(creating=True, **kwargs)


class RuleEditView(_EditorView):
    permission_required = "rules.change_rule"
    form_class = RuleUpdateForm

    def load(self, **kwargs: Any) -> None:
        self.rule = get_object_or_404(
            Rule.objects.select_related("ruleset").defer("ruleset__original_content"),
            pk=kwargs["pk"],
        )

    def get_initial(self):
        return {"text": self.rule.text, "version": self.rule.version}

    def validate(self, form, text):
        return editing.validate_rule_text(self.rule.ruleset, text, self.rule)

    def save(self, form, text):
        expected = form.cleaned_data["version"]
        result = editing.update_rule(
            self.rule, text, user=current_user(self.request), expected_version=expected
        )
        if result.conflict:
            return self.conflict(form, expected, result)
        if not result.ok:
            return self.render_result(form, result)
        if saved_rule(result).version == expected:
            messages.info(self.request, "No changes to save.")
            return redirect(self.rule.get_absolute_url())
        return self.saved(result, "Saved {rule.name} as version {rule.version}.")

    def conflict(self, form: Any, expected: int, result: EditResult) -> HttpResponse:
        """
        Someone else saved (or an import changed) the rule after this editor
        was opened, or deleted it. The submitted text stays in the editor;
        the page lists the versions saved meanwhile so the user can merge
        by hand. The form now carries the current version, so the next Save
        replaces it on purpose.
        """
        current = Rule.objects.filter(pk=self.rule.pk).values_list("version", flat=True).first()
        if current == expected:
            # Not a newer version: e.g. the new name was taken meanwhile.
            return self.render_result(form, result)
        if current is not None:
            self.rule.refresh_from_db()
            data = self.request.POST.copy()
            data["version"] = str(current)
            form = RuleUpdateForm(data)
            form.is_valid()
        meanwhile = (
            self.rule.versions.filter(number__gt=expected)
            .select_related("created_by", "import_run")
            .order_by("number")
            if current is not None
            else RuleVersion.objects.none()
        )
        return self.render_to_response(
            self.get_context_data(
                form=form,
                conflict={"expected": expected, "current": current, "versions": meanwhile},
            )
        )

    def get_context_data(self, **kwargs):
        return super().get_context_data(rule=self.rule, **kwargs)


class RuleDeleteView(PermissionMixin, TemplateView):
    permission_required = "rules.delete_rule"
    template_name = "rules/rule_confirm_delete.html"

    def load(self, **kwargs: Any) -> None:
        self.rule = get_object_or_404(
            Rule.objects.select_related("ruleset").defer("ruleset__original_content"),
            pk=kwargs["pk"],
        )

    def get_context_data(self, **kwargs):
        return super().get_context_data(
            rule=self.rule, version_count=self.rule.versions.count(), **kwargs
        )

    def post(self, request, pk):
        ruleset = self.rule.ruleset
        name = self.rule.name
        editing.delete_rule(self.rule, user=current_user(request))
        messages.success(
            request,
            f"Deleted rule {name}. It is hidden, not destroyed: it is kept with its history "
            "and can be restored.",
        )
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
            default = default_sort(filters["q"])
            params = {k: v for k, v in filters.items() if v and not (k == "sort" and v == default)}
            url = reverse("rules:rule_list")
            if params:
                from urllib.parse import urlencode

                url += "?" + urlencode(params)
            return redirect(url)
        if form.cleaned_data.get("format") == "zip":
            return file_response(exporter.export_zip(rules))
        return file_response(exporter.export_combined(rules))
