"""Shared Unicode matching and display helpers; source text stays untouched."""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterator

# Post-NFKC supplement: common Cyrillic/Greek and accented Latin lookalikes.
_CONFUSABLE_MAP: dict[str, str] = {
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "х": "x",
    "і": "i",
    "у": "y",
    "ο": "o",
    "α": "a",
    "ε": "e",
    "ρ": "p",
    "ν": "v",
    "à": "a",
    "á": "a",
    "è": "e",
    "é": "e",
    "ó": "o",
    "ö": "o",
    "ü": "u",
    "í": "i",
}
_WORDS = re.compile(r"\w+")


def invisible_class(char: str) -> str | None:
    """Classify explicit invisible codepoints, independently of NFKC changes."""
    code = ord(char)
    if 0xE0000 <= code <= 0xE007F:
        return "tag block"
    if 0xFE00 <= code <= 0xFE0F or 0xE0100 <= code <= 0xE01EF:
        return "variation selector"
    if unicodedata.category(char) == "Cf":
        return "Cf (format)"
    return None


def normalize_text(text: str) -> str:
    """NFKC, remove invisibles, then fold the curated confusable supplement."""
    return "".join(
        _CONFUSABLE_MAP.get(char.lower(), char).upper()
        if char.isupper() and char.lower() in _CONFUSABLE_MAP
        else _CONFUSABLE_MAP.get(char, char)
        for char in unicodedata.normalize("NFKC", text)
        if invisible_class(char) is None
    )


def _mixed_script_positions(text: str) -> Iterator[int]:
    visible = "".join(char for char in unicodedata.normalize("NFKC", text) if invisible_class(char) is None)
    for match in _WORDS.finditer(visible):
        word = match.group()
        if any("LATIN" in unicodedata.name(char, "") for char in word):
            for index, char in enumerate(word):
                if char.lower() in _CONFUSABLE_MAP and unicodedata.name(char, "").startswith(
                    ("CYRILLIC", "GREEK")
                ):
                    yield match.start() + index
                    break


def obfuscation_classes(text: str) -> list[str]:
    """Flag invisibles and confusables mixed into Latin-shaped words.

    Pure non-Latin words and accented Latin letters are ordinary text. NFKC
    compatibility changes alone (fullwidth, ligatures, etc.) are not anomalies.
    """
    classes = {kind for char in text if (kind := invisible_class(char)) is not None}
    if next(_mixed_script_positions(text), None) is not None:
        classes.add("confusable (mixed-script)")
    return sorted(classes)


def render_invisibles(text: str) -> str:
    """Make invisible codepoints explicit in human-facing report strings."""
    return "".join(f"‹U+{ord(char):04X}›" if invisible_class(char) else char for char in text)


def first_obfuscation(text: str) -> int:
    """Locate the first invisible or gated mixed-script confusable in raw text."""
    invisible = next((index for index, char in enumerate(text) if invisible_class(char)), len(text))
    mixed = next(_mixed_script_positions(text), None)
    index = min(invisible, _raw_offset(text, mixed, start=True) if mixed is not None else len(text))
    return index if index < len(text) else 0


def _raw_offset(raw: str, position: int, *, start: bool = False) -> int:
    """Map a normalized boundary, excluding stripped text before a match start."""
    low, high = 0, len(raw)
    while low < high:
        middle = (low + high) // 2
        length = len(normalize_text(raw[:middle]))
        if length < position or (start and length == position):
            low = middle + 1
        else:
            high = middle
    return max(0, low - 1) if start else low


def raw_excerpt(raw: str, normalized: str, excerpt: str, match_span: tuple[int, int]) -> str:
    """Map context and the actual match to raw text, prioritizing the match."""
    position = normalized.find(excerpt)
    context_start = _raw_offset(raw, position) if position >= 0 else 0
    match_start = _raw_offset(raw, match_span[0], start=True)
    match_end = _raw_offset(raw, match_span[1])
    start = max(context_start, match_start - 20, min(match_start, match_end - 200))
    return raw[start : start + 200]
