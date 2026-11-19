import unicodedata
from datetime import timedelta

from django import forms

EXPIRY_CHOICES = [
    ("", "Never"),
    ("7", "In 7 days"),
    ("30", "In 30 days"),
    ("90", "In 90 days"),
    ("365", "In one year"),
]


class ApiKeyForm(forms.Form):
    name = forms.CharField(
        max_length=100,
        label="Name",
        help_text="What the key is for, e.g. “nightly export” or the host it runs on.",
        widget=forms.TextInput(attrs={"class": "input", "autocomplete": "off"}),
    )
    expires = forms.ChoiceField(
        choices=EXPIRY_CHOICES,
        required=False,
        label="Expires",
        widget=forms.Select(attrs={"class": "select"}),
    )

    def clean_name(self) -> str:
        name = self.cleaned_data["name"].strip()
        if any(unicodedata.category(char) in ("Cc", "Cf", "Zl", "Zp") for char in name):
            raise forms.ValidationError("The name must not contain control characters.")
        if not name:
            raise forms.ValidationError("Name the key.")
        return name

    def expires_in(self) -> timedelta | None:
        days = self.cleaned_data.get("expires")
        return timedelta(days=int(days)) if days else None
