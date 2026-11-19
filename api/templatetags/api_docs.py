"""Template filters of the API documentation pages."""

import re

from django import template
from django.utils.html import escape
from django.utils.safestring import SafeString, mark_safe

register = template.Library()

_TICKS = re.compile(r"`([^`]+)`")


@register.filter
def ticks(text: str) -> SafeString:
    """Escape `text` and show `quoted` parts as inline code."""
    return mark_safe(_TICKS.sub(r"<code>\1</code>", escape(text)))  # escaped first
