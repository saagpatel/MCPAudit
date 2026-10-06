"""Shared Unicode matching and display helpers; source text stays untouched."""

from __future__ import annotations

import re
import unicodedata

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


def obfuscation_classes(text: str) -> list[str]:
    """Flag invisibles and confusables mixed into Latin-shaped words.

    Pure non-Latin words and accented Latin letters are ordinary text. NFKC
    compatibility changes alone (fullwidth, ligatures, etc.) are not anomalies.
    """
    classes = {kind for char in text if (kind := invisible_class(char)) is not None}
    visible = "".join(char for char in unicodedata.normalize("NFKC", text) if invisible_class(char) is None)
    for word in _WORDS.findall(visible):
        if any("LATIN" in unicodedata.name(char, "") for char in word) and any(
            char.lower() in _CONFUSABLE_MAP and unicodedata.name(char, "").startswith(("CYRILLIC", "GREEK"))
            for char in word
        ):
            classes.add("confusable (mixed-script)")
    return sorted(classes)


def render_invisibles(text: str) -> str:
    """Make invisible codepoints explicit in human-facing report strings."""
    return "".join(f"‹U+{ord(char):04X}›" if invisible_class(char) else char for char in text)


def first_obfuscation(text: str) -> int:
    """Locate raw evidence after the class gate has established an anomaly."""
    return next(
        (
            index
            for index, char in enumerate(text)
            if invisible_class(char)
            or (
                char.lower() in _CONFUSABLE_MAP
                and unicodedata.name(char, "").startswith(("CYRILLIC", "GREEK"))
            )
        ),
        0,
    )


def raw_excerpt(raw: str, normalized: str, excerpt: str) -> str:
    """Project a normalized excerpt start back to the unchanged source prefix."""
    position = normalized.find(excerpt)
    if position < 0:
        return raw[:200]
    low, high = 0, len(raw)
    while low < high:
        middle = (low + high) // 2
        if len(normalize_text(raw[:middle])) < position:
            low = middle + 1
        else:
            high = middle
    return raw[low : low + 200]
