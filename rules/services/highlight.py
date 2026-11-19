"""Server-side YARA syntax highlighting with Pygments."""

from django.utils.safestring import SafeString, mark_safe
from pygments import highlight
from pygments.formatters.html import HtmlFormatter
from pygments.lexers.yara import YaraLexer

# HtmlFormatter and YaraLexer are imported from their defining modules
# because the lazy re-exports in pygments.formatters and pygments.lexers are
# invisible to the type checker.
_LEXER = YaraLexer()


def highlight_yara(source: str, linenos: bool = False) -> SafeString:
    """
    YARA source as HTML: `<div class="highlight"><pre><code>` with standard
    Pygments token classes (`.k`, `.s`, `.c1`, …) and no inline styles, so it
    is compatible with the CSP. With `linenos`, each line starts with a
    `<span class="linenos">`. Style it with CSS generated once by e.g.
    `pygmentize -S default -f html -a .highlight`.
    """
    formatter = HtmlFormatter(wrapcode=True, linenos="inline" if linenos else False)
    # Pygments escapes the source text.
    return mark_safe(highlight(source, _LEXER, formatter))
