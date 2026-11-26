"""Arabic text reshaping and BiDi display helpers for legacy LTR terminals."""

from __future__ import annotations

import re

import arabic_reshaper

try:
    from bidi import get_display
except ImportError:  # pragma: no cover - fallback for python-bidi < 0.5
    from bidi.algorithm import get_display  # type: ignore[no-redef]

_ARABIC_RE = re.compile(
    r"[\u0600-\u06FF\u0750-\u077F\u08A0-\u08FF\uFB50-\uFDFF\uFE70-\uFEFF]"
)


def contains_arabic(text: str) -> bool:
    """Return True if *text* contains any Arabic script code points."""
    return bool(_ARABIC_RE.search(text))


def fix_ar(text: str, enabled: bool = True) -> str:
    """Reshape connected Arabic glyphs and apply the Unicode BiDi algorithm.

    Set *enabled* to False on modern terminals that natively shape and reorder
    right-to-left Arabic text to avoid double-reversing characters.
    """
    if not enabled or not text or not contains_arabic(text):
        return text

    lines = text.splitlines(keepends=True)
    processed: list[str] = []
    for line in lines:
        stripped = line.rstrip("\r\n")
        ending = line[len(stripped) :]
        if contains_arabic(stripped):
            reshaped = arabic_reshaper.reshape(stripped)
            visual = get_display(reshaped)
            processed.append(f"{visual}{ending}")
        else:
            processed.append(line)
    return "".join(processed)
