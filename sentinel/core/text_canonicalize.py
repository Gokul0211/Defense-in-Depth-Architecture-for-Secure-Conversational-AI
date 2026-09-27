"""
Shared text canonicalization — defends the embedding-based checks (L1
Tier 2, L2's instruction density, L3's harm alignment) against Unicode
confusable/invisible-character evasion, the same defense class real-world
anti-phishing/anti-spoofing systems use against homoglyph attacks.

WHY THIS EXISTS
------------------
`layer1.py`'s `normalize()` (NFKC + zero-width-char stripping + leetspeak
collapse + lowercasing) already existed, but only ever reached Tier 1's
regex check — Tier 2 (the semantic/embedding check) scored raw, un-
normalized text. Confirmed live: a red-team run using
`RuleBasedParaphraser`'s case-randomization, zero-width-space injection,
and Cyrillic-homoglyph substitution techniques (`sentinel/eval/redteam.py`)
evaded detection in 43/50 originally-detected `sentinel_bench` samples
(86%). L2's `calculate_instruction_density` and L3's `layer3_check` had no
normalization at all.

NFKC does NOT fold homoglyphs — Cyrillic 'а' (U+0430) and Latin 'a'
(U+0061) are canonically distinct with no NFKC decomposition relationship;
NFKC only handles compatibility variants (ligatures, full-width forms).
The `_CONFUSABLES` table below closes that gap directly.

SCOPE, DELIBERATELY BROADER THAN THE RED-TEAM'S OWN 5-CHARACTER MAP
------------------------------------------------------------------------
`redteam.py`'s `RuleBasedParaphraser` only substitutes 5 characters
(a/e/o/p/c). The table below covers a wider, principled set of common
Cyrillic/Greek Latin-lookalikes (the same characters Unicode's own
"confusables" mechanism, TR39, flags as high-risk for spoofing) — a real
defense against the general technique class, not a fit to this specific
eval's paraphraser.
"""

import re
import unicodedata

# Zero-width space, zero-width non-joiner, zero-width joiner, BOM/zero-width
# no-break space — same set layer1.py's original normalize() stripped,
# expressed as explicit escapes rather than literal invisible characters
# in the source for readability/safety.
_ZERO_WIDTH_RE = re.compile(r"[\u200b\u200c\u200d\ufeff]")

# Cyrillic and Greek characters commonly used to visually spoof Latin
# letters, mapped to their Latin equivalent. Covers the letters most
# frequently targeted in real homoglyph-based evasion (a/e/o/p/c/x/y/i/s/
# h/k/m/t/b), not just the red-team's own 5-character substitution set.
_CONFUSABLES: dict[str, str] = {
    # Cyrillic -> Latin
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "х": "x", "у": "y", "і": "i", "ѕ": "s", "һ": "h",
    "к": "k", "м": "m", "т": "t", "в": "b",
    "А": "A", "Е": "E", "О": "O", "Р": "P", "С": "C",
    "Х": "X", "У": "Y", "І": "I", "Ѕ": "S", "Н": "H",
    "К": "K", "М": "M", "Т": "T", "В": "B",
    # Greek -> Latin
    "α": "a", "ο": "o", "ρ": "p", "χ": "x", "υ": "y",
    "ι": "i",
    "Α": "A", "Ο": "O", "Ρ": "P", "Χ": "X", "Υ": "Y",
    "Ι": "I",
}

_LEET_MAP = {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "@": "a"}


def canonicalize(text: str) -> str:
    """
    Normalize unicode, strip invisible characters, fold homoglyphs,
    collapse leetspeak, lowercase. Same transform `layer1.py`'s Tier 1
    regex check already applies (moved here so L1 Tier 2, L2, and L3 can
    all use it too — see module docstring).
    """
    text = unicodedata.normalize("NFKC", text)
    text = _ZERO_WIDTH_RE.sub("", text)
    text = "".join(_CONFUSABLES.get(c, c) for c in text)
    text = text.lower()
    return "".join(_LEET_MAP.get(c, c) for c in text)
