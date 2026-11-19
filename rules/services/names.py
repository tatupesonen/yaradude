"""
Making names that come from users or files safe where they are written out:
in comments of exported rule files and as member names of archives.
"""

import re
import unicodedata

# Unicode categories of control characters (C0/C1 controls and DEL), line
# and paragraph separators, and invisible format characters such as
# bidirectional overrides.
_CONTROL = frozenset({"Cc", "Cf", "Zl", "Zp"})
# Characters that act as separators or are invalid in file names on some
# system that may extract an archive.
_UNSAFE_IN_MEMBER = re.compile(r'[\\:*?"<>|]')


def has_control_characters(text: str) -> bool:
    """True if `text` holds a line break, a control or an invisible format character."""
    return any(unicodedata.category(char) in _CONTROL for char in text)


def single_line(text: str) -> str:
    """`text` with control and format characters (line breaks included) replaced by "?"."""
    return "".join("?" if unicodedata.category(char) in _CONTROL else char for char in text)


def safe_member_path(path: str, fallback: str) -> str:
    """
    A relative POSIX path that is safe as an archive member name on any
    system: "/" is the only separator (a backslash becomes "_"), no empty,
    "." or ".." component, no drive letters, no control characters. Returns
    `fallback` when nothing usable is left.
    """
    parts: list[str] = []
    for raw in path.split("/"):
        part = _UNSAFE_IN_MEMBER.sub("_", single_line(raw)).strip()
        if not part.strip("."):
            continue  # empty, ".", ".." or only dots
        parts.append(part)
    return "/".join(parts) or fallback
