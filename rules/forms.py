"""Forms of the web UI. They validate input only; business logic is in rules.services."""

import unicodedata

from django import forms
from django.conf import settings
from django.db import models
from django.template.defaultfilters import filesizeformat

from rules.models import Ruleset
from rules.services.importer import MAX_FILE_BYTES, RULE_SUFFIXES

# ------------------------------------------------------------------ rules list

STATUS_CHOICES = [
    ("", "Active"),
    ("error", "Does not compile"),
    ("warnings", "With warnings"),
    ("modified", "Modified locally"),
    ("removed", "Removed"),
    ("all", "All, including removed"),
]

SORT_CHOICES = [
    ("name", "Name"),
    ("-name", "Name, descending"),
    ("ruleset", "Ruleset"),
    ("-ruleset", "Ruleset, descending"),
    ("updated", "Updated, oldest first"),
    ("-updated", "Updated, newest first"),
    ("created", "First imported, oldest first"),
    ("-created", "First imported, newest first"),
]


class RuleFilterForm(forms.Form):
    """Search, filters and sort of the rules list (a GET form; invalid values are ignored)."""

    q = forms.CharField(required=False, max_length=200, label="Search")
    ruleset = forms.IntegerField(required=False, min_value=1)
    path = forms.CharField(required=False, max_length=1024, label="Ruleset path")
    tag = forms.CharField(required=False, max_length=128)
    status = forms.ChoiceField(required=False, choices=STATUS_CHOICES)
    sort = forms.ChoiceField(required=False, choices=SORT_CHOICES)

    def values(self) -> dict:
        """The valid filter values; anything invalid falls back to its default."""
        self.is_valid()
        data = getattr(self, "cleaned_data", {})
        return {
            "q": (data.get("q") or "").strip(),
            "ruleset": data.get("ruleset"),
            "path": (data.get("path") or "").strip(),
            "tag": (data.get("tag") or "").strip(),
            "status": data.get("status") or "",
            "sort": data.get("sort") or "name",
        }


FORMAT_CHOICES = [("yar", "Single .yar file"), ("zip", ".zip, one file per ruleset")]


class ExportForm(forms.Form):
    """Export of selected rules or of everything matching the current filter."""

    format = forms.ChoiceField(choices=FORMAT_CHOICES, required=False)
    scope = forms.ChoiceField(choices=[("selected", "Selected"), ("filter", "Filter")])
    ids = forms.TypedMultipleChoiceField(coerce=int, required=False)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Any integer is acceptable here; the view only exports rules that exist.
        self.fields["ids"].valid_value = lambda value: str(value).isdigit()


# ------------------------------------------------------------------ rulesets list


class RulesetFilterForm(forms.Form):
    q = forms.CharField(required=False, max_length=200, label="Search")
    origin = forms.ChoiceField(required=False, choices=[("", "Any origin"), *Ruleset.Origin.choices])
    sort = forms.ChoiceField(
        required=False,
        choices=[
            ("name", "Name"),
            ("-name", "Name, descending"),
            ("updated", "Changed, oldest first"),
            ("-updated", "Changed, newest first"),
            ("imported", "Imported, oldest first"),
            ("-imported", "Imported, newest first"),
            ("rules", "Rules, fewest first"),
            ("-rules", "Rules, most first"),
        ],
    )

    def values(self) -> dict:
        self.is_valid()
        data = getattr(self, "cleaned_data", {})
        return {
            "q": (data.get("q") or "").strip(),
            "origin": data.get("origin") or "",
            "sort": data.get("sort") or "name",
        }


# ------------------------------------------------------------------ editor

NEW_RULESET = "new"
MAX_COLLECTION_NAME = 100


class RuleEditForm(forms.Form):
    """Editor text plus, for a new rule, the ruleset it goes into."""

    text = forms.CharField(
        label="Rule source",
        strip=False,
        max_length=MAX_FILE_BYTES,
        widget=forms.Textarea(
            attrs={
                "class": "editor",
                "rows": 24,
                "spellcheck": "false",
                "autocapitalize": "off",
                "autocomplete": "off",
                "data-editor": "",
            }
        ),
        help_text='Optional import lines (e.g. import "pe") followed by exactly one rule.',
    )

    def clean_text(self):
        text = self.cleaned_data["text"].replace("\r\n", "\n")
        if not text.strip():
            raise forms.ValidationError("Enter a rule.")
        return text


class RuleCreateForm(RuleEditForm):
    ruleset = forms.ChoiceField(label="Ruleset")
    new_ruleset = forms.CharField(
        label="New collection name",
        required=False,
        max_length=MAX_COLLECTION_NAME,
        help_text="Used when “New manual collection” is chosen.",
    )

    field_order = ["ruleset", "new_ruleset", "text"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Offer the manual collections plus the ruleset chosen on the way in
        # (e.g. "Add rule" on a ruleset page), not every imported file:
        # there can be thousands.
        selected = str(self.data.get("ruleset") or self.initial.get("ruleset") or "")
        query = models.Q(origin=Ruleset.Origin.MANUAL)
        if selected.isdigit():
            query |= models.Q(pk=int(selected))
        rulesets = (
            Ruleset.objects.filter(query).order_by("name", "pk").only("pk", "name", "origin", "path")
        )
        self.fields["ruleset"].choices = [
            (NEW_RULESET, "New manual collection…"),
            *((str(r.pk), f"{r.name} ({r.get_origin_display()})") for r in rulesets),
        ]
        self._rulesets = {str(r.pk): r for r in rulesets}

    def clean(self):
        cleaned = super().clean()
        if cleaned.get("ruleset") == NEW_RULESET:
            name = (cleaned.get("new_ruleset") or "").strip()
            if not name:
                self.add_error("new_ruleset", "Name the new collection.")
            elif any(unicodedata.category(char) in ("Cc", "Cf", "Zl", "Zp") for char in name):
                self.add_error(
                    "new_ruleset", "The name must not contain line breaks or control characters."
                )
            cleaned["new_ruleset"] = name
            cleaned["ruleset_obj"] = None
        elif cleaned.get("ruleset"):
            cleaned["ruleset_obj"] = self._rulesets.get(cleaned["ruleset"])
        return cleaned


class RuleUpdateForm(RuleEditForm):
    version = forms.IntegerField(widget=forms.HiddenInput, min_value=1)


# ------------------------------------------------------------------ import


class MultipleFileInput(forms.ClearableFileInput):
    allow_multiple_selected = True


class MultipleFileField(forms.FileField):
    widget = MultipleFileInput

    def clean(self, data, initial=None):
        single = super().clean
        if isinstance(data, list | tuple):
            return [single(item, initial) for item in data]
        return [single(data, initial)] if data else single(data, initial)


class UploadForm(forms.Form):
    files = MultipleFileField(
        label="Rule files",
        widget=MultipleFileInput(attrs={"accept": ",".join(RULE_SUFFIXES), "class": "peer sr-only"}),
        help_text=(
            f"{' or '.join(RULE_SUFFIXES)} files, up to {filesizeformat(MAX_FILE_BYTES)} each. "
            "Each file becomes one ruleset, identified by its file name."
        ),
        error_messages={"required": "Choose at least one file (or the upload was too large)."},
    )

    def clean_files(self):
        files = self.cleaned_data["files"]
        if not files:
            raise forms.ValidationError("Choose at least one file.")
        return files


# ------------------------------------------------------------------ test scan


class ScanForm(forms.Form):
    sample = forms.FileField(
        label="Sample",
        help_text=(
            f"Up to {filesizeformat(settings.YARADUDE_SCAN_MAX_BYTES)}. Scanned in memory; "
            "the file is never stored."
        ),
        error_messages={"required": "Choose a file to scan (or the file was too large)."},
    )
    path = forms.CharField(
        label="Limit to ruleset path",
        required=False,
        max_length=1024,
        help_text=(
            "Optional. Only rulesets whose path contains this text; end it with “/” to "
            "select a directory, e.g. signature-base/. Leave empty to scan with every rule."
        ),
    )

    def clean_sample(self):
        sample = self.cleaned_data["sample"]
        if sample.size > settings.YARADUDE_SCAN_MAX_BYTES:
            raise forms.ValidationError(
                f"The sample is larger than the limit of "
                f"{filesizeformat(settings.YARADUDE_SCAN_MAX_BYTES)}."
            )
        return sample
