"""Template helpers for the yaradude UI: timestamps, status badges, navigation, querystrings."""

import math
from decimal import Decimal

from django import template
from django.utils import timezone
from django.utils.html import format_html
from django.utils.safestring import mark_safe
from django.utils.timesince import timesince

from rules.services.highlight import highlight_yara

register = template.Library()

# URL names (within the "rules" namespace) grouped by navigation section.
_SECTIONS = {
    "dashboard": "dashboard",
    "rule_": "rules",
    "ruleset_": "rulesets",
    "import": "import",
    "scan": "scan",
}


@register.simple_tag(takes_context=True)
def nav_section(context) -> str:
    """The navigation section of the current page ("rules", "import", …) or ""."""
    request = context.get("request")
    match = getattr(request, "resolver_match", None)
    if match is None or match.namespace != "rules":
        return ""
    for prefix, section in _SECTIONS.items():
        if match.url_name.startswith(prefix):
            return section
    return ""


@register.filter
def ts(value, style: str = ""):
    """
    A timestamp as absolute local time with a relative hint:
    `<time datetime="…">2026-11-19 20:41</time> · 3 hours ago`. With
    style "short" only the absolute time is shown (the relative hint goes
    into the title).
    """
    if not value:
        return mark_safe('<span class="text-faint">—</span>')
    local = timezone.localtime(value)
    absolute = local.strftime("%Y-%m-%d %H:%M")
    full = local.strftime("%Y-%m-%d %H:%M:%S %Z")
    now = timezone.now()
    if value > now:
        relative = "just now"
    else:
        relative = timesince(value, now, depth=1)  # ty: ignore[unknown-argument]  # `depth` (Django 4.1) is absent from django-types 0.24
        relative = "just now" if relative.startswith("0\xa0") else f"{relative} ago"
    if style == "short":
        return format_html(
            '<time datetime="{}" title="{} ({})" class="tabular-nums whitespace-nowrap">{}</time>',
            value.isoformat(),
            full,
            relative,
            absolute,
        )
    return format_html(
        '<time datetime="{}" title="{}" class="tabular-nums whitespace-nowrap">{}</time>'
        ' <span class="whitespace-nowrap text-faint">· {}</span>',
        value.isoformat(),
        full,
        absolute,
        relative,
    )


@register.inclusion_tag("rules/includes/rule_status.html")
def rule_status(rule, compact=False):
    """Status badges of a rule: removed / does not compile / warnings / compiles, modified."""
    return {"rule": rule, "compact": compact}


@register.filter
def highlight(source: str, linenos: str = ""):
    """YARA source highlighted server-side (Pygments, no inline styles)."""
    return highlight_yara(source or "", linenos=bool(linenos))


@register.simple_tag(takes_context=True)
def query(context, **changes) -> str:
    """
    The current querystring with `changes` applied ("" or None removes a
    key), starting with "?". `page` is dropped whenever anything else
    changes, so a new filter or sort starts at page one.
    """
    params = context["request"].GET.copy()
    if set(changes) - {"page"}:
        params.pop("page", None)
    for key, value in changes.items():
        if value in ("", None):
            params.pop(key, None)
        else:
            params[key] = value
    encoded = params.urlencode()
    return f"?{encoded}" if encoded else "?"


@register.inclusion_tag("rules/includes/sort_header.html", takes_context=True)
def sort_header(context, label, key, current, numeric=False):
    """A sortable column header; clicking toggles between ascending and descending."""
    descending = current == f"-{key}"
    active = current in (key, f"-{key}")
    target = key if descending or not active else f"-{key}"
    return {
        "label": label,
        "href": query(context, sort=target),
        "active": active,
        "descending": descending,
        "numeric": numeric,
    }


@register.filter
def meta_value(value) -> str:
    """
    A rule meta value as YARA would write it: booleans as true/false and
    floats in plain decimal notation (shortest form that reads back as the
    same number, never an exponent: 1e+20 becomes 100000000000000000000.0).
    """
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float):
        if not math.isfinite(value):
            return str(value)
        text = format(Decimal(repr(value)), "f")
        return text if "." in text else f"{text}.0"
    return str(value)


@register.filter
def basename(path: str) -> str:
    """The last component of a ruleset path ("a/b/c.yar" -> "c.yar")."""
    return str(path).rstrip("/").rsplit("/", 1)[-1]
