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


_UNICODE_SPACES_RE = re.compile("[\u00a0\u1680\u2000-\u200a\u202f\u205f\u3000]")
_TRAILING_WS_RE = re.compile(r"[ \t]+(?=\n)")
_BLANK_RUN_RE = re.compile(r"\n{3,}")


def canonical_whitespace(text: str) -> str:
    """Whitespace-only normal form (L2 C1, results.md §22): CRLF / CR -> LF, Unicode spaces -> ' ', trailing spaces
    and tabs per line removed, runs of 3+ line breaks -> 2, outer whitespace stripped. Changes nothing but whitespace,
    so a document and the same document with different outer / trailing whitespace read identically (real-runner t9:
    leading / trailing whitespace alone flipped 10 / 458 middle-position decisions)."""
    t = (text or "").replace("\r\n", "\n").replace("\r", "\n")
    t = _UNICODE_SPACES_RE.sub(" ", t)
    t = _TRAILING_WS_RE.sub("", t)
    t = _BLANK_RUN_RE.sub("\n\n", t)
    return t.strip()


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


# =====================================================================================================================
# L1 REVIEW B2 (2026-10-27; scratch/rca/l1/L1_REVIEW.md): the "unhide" view.
# =====================================================================================================================
# `canonicalize` strips only four zero-width code points. The hiding techniques below pass through it untouched, and
# Tier 3 (Prompt Guard / PIGuard) never read even the canonical form:
#   * Unicode TAG characters U+E0000-E007F ("ASCII smuggling"): an invisible shadow copy of ASCII that people do not
#     see and LLMs read (Goodside 2024; Robust Intelligence; Microsoft 2026-09-03);
#   * VARIATION-SELECTOR smuggling: bytes encoded as runs of U+FE00-FE0F / U+E0100-E01EF after one visible character;
#   * bidi controls (U+202A-202E, U+2066-2069, "Trojan Source") and other invisible format characters;
#   * homoglyphs mixed into Latin words (Cyrillic / Greek look-alikes);
#   * LETTER SPACING ("i g n o r e ..."), the published Prompt-Guard-86M bypass (99.8 % evasion;
#     meta-llama/llama-models issue #50).
# `unhide` reverses all of them WITHOUT lowercasing or leetspeak folding, so it is a fair input for the Tier-3
# classifiers too; `canonicalize_v2` = canonicalize(unhide(text)) for Tiers 1 / 2. Text with none of these is returned
# unchanged, so the views cost nothing on ordinary input.

_TAG_BASE = 0xE0000
_BLACK_FLAG = "\U0001F3F4"
_CANCEL_TAG = "\U000E007F"
# invisible format characters stripped by `unhide` (bidi controls, word joiner / invisible operators, soft hyphen,
# Mongolian vowel separator, BOM, LRM / RLM / ALM, the four zero-width characters)
_INVISIBLE_RE = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\u00ad\u180e\ufeff\u061c]")
_BIDI_OVERRIDE_RE = re.compile("[\u202a-\u202e\u2066-\u2069]")
_VS_RE = re.compile("[\ufe00-\ufe0f\U000e0100-\U000e01ef]+")
# runs of >= 8 single letters / digits, each followed by ONE separator (or a 2-3-space word gap)
_SPACED_RUN_RE = re.compile(r"(?<![A-Za-z0-9])(?:[A-Za-z0-9](?:[ ._*|/-]| {2,3})){7,}[A-Za-z0-9](?![A-Za-z0-9])")
_WORD_RE = re.compile(r"\w+", re.UNICODE)
_LATIN_RE = re.compile(r"[A-Za-z]")
_CONFUSABLE_CHARS = frozenset(_CONFUSABLES)


def _vs_byte(c: str) -> int:
    cp = ord(c)
    return cp - 0xFE00 if cp <= 0xFE0F else cp - 0xE0100 + 16


def decode_tag_chars(text: str) -> tuple[str, int]:
    """(text with TAG characters decoded to ASCII, number of tag characters decoded).

    Emoji subdivision flags (U+1F3F4 + tag letters + U+E007F, e.g. the flags of England / Scotland / Wales) are the one
    legitimate use; they are kept as the bare black flag and not counted."""
    if not any(_TAG_BASE <= ord(c) <= _TAG_BASE + 0x7F for c in text):
        return text, 0
    out, n, i = [], 0, 0
    while i < len(text):
        c = text[i]
        if c == _BLACK_FLAG:
            j = i + 1
            while j < len(text) and _TAG_BASE + 0x20 <= ord(text[j]) <= _TAG_BASE + 0x7E:
                j += 1
            if j > i + 1 and j < len(text) and text[j] == _CANCEL_TAG:
                out.append(c)
                i = j + 1
                continue
        cp = ord(c)
        if _TAG_BASE + 0x20 <= cp <= _TAG_BASE + 0x7E:
            out.append(chr(cp - _TAG_BASE))
            n += 1
        elif _TAG_BASE <= cp <= _TAG_BASE + 0x7F:
            pass                                            # language tag / cancel tag outside a flag: drop
        else:
            out.append(c)
        i += 1
    return "".join(out), n


def decode_variation_selectors(text: str, min_run: int = 4) -> tuple[str, str]:
    """(text with VS runs replaced, the hidden text they carried). A run of >= `min_run` variation selectors is read
    as bytes (U+FE00-FE0F = 0-15, U+E0100-E01EF = 16-255) and decoded as UTF-8; shorter runs (emoji presentation
    selectors, CJK ideographic variation sequences) are simply removed."""
    hidden = []

    def _sub(m):
        run = m.group(0)
        if len(run) < min_run:
            return ""
        s = bytes(_vs_byte(c) for c in run).decode("utf-8", errors="ignore")
        s = "".join(ch for ch in s if ch.isprintable() or ch in "\n\t")
        if s.strip():
            hidden.append(s)
            return f" {s} "
        return ""

    return _VS_RE.sub(_sub, text), " ".join(hidden)


def _fold_mixed_script_word(m) -> str:
    w = m.group(0)
    if _LATIN_RE.search(w) and any(c in _CONFUSABLE_CHARS for c in w):
        return "".join(_CONFUSABLES.get(c, c) for c in w)
    return w


def collapse_spaced_letters(text: str) -> tuple[str, list[str]]:
    """(text with spaced-letter runs collapsed, the collapsed runs). Single separators inside a run are removed and
    a 2-3-space gap becomes one space, so "i g n o r e   a l l" reads "ignore all"."""
    runs = []

    def _sub(m):
        s = re.sub(r" {2,3}", "\x00", m.group(0))
        s = re.sub(r"[ ._*|/-]", "", s).replace("\x00", " ")
        runs.append(s)
        return s

    return _SPACED_RUN_RE.sub(_sub, text), runs


def unhide(text: str) -> str:
    """The text with every hiding technique above reversed; NOT lowercased or leet-folded (a fair Tier-3 input)."""
    if not text:
        return text or ""
    t, _ = decode_tag_chars(text)
    t, _ = decode_variation_selectors(t)
    t = _INVISIBLE_RE.sub("", t)
    t = unicodedata.normalize("NFKC", t)
    t = _WORD_RE.sub(_fold_mixed_script_word, t)
    t, _ = collapse_spaced_letters(t)
    return t


def canonicalize_v2(text: str) -> str:
    """canonicalize(unhide(text)): the Tier-1 / Tier-2 view with the B2 hiding techniques reversed."""
    return canonicalize(unhide(text))


def hiding_report(text: str) -> dict:
    """Counts of each hiding technique in `text` (the T0 anomaly signal, config.L1_ANOMALY_TIER).

    `hidden_text` is what INVISIBLE carriers (tag characters, variation-selector runs) decoded to. `strong` is set
    when they carried >= 4 characters: readable text that a person cannot see has no benign use in a prompt, a
    document or a tool output. Visible obfuscation (spacing, mixed scripts, bidi overrides) is counted but is not
    `strong` on its own -- it only makes the unhide view worth scanning."""
    text = text or ""
    tag_text, n_tags = decode_tag_chars(text)
    tag_hidden = "".join(chr(ord(c) - _TAG_BASE) for c in text if _TAG_BASE + 0x20 <= ord(c) <= _TAG_BASE + 0x7E)
    if n_tags == 0:
        tag_hidden = ""
    _, vs_hidden = decode_variation_selectors(tag_text)
    _, runs = collapse_spaced_letters(text)
    mixed = sum(1 for m in _WORD_RE.finditer(text)
                if _LATIN_RE.search(m.group(0)) and any(c in _CONFUSABLE_CHARS for c in m.group(0)))
    hidden = " ".join(s for s in (tag_hidden.strip(), vs_hidden.strip()) if s)
    return {
        "tag_chars": n_tags,
        "variation_selector_text": len(vs_hidden.strip()),
        "bidi_overrides": len(_BIDI_OVERRIDE_RE.findall(text)),
        "invisible_chars": len(_INVISIBLE_RE.findall(text)),
        "spaced_runs": len(runs),
        "mixed_script_words": mixed,
        "hidden_text": hidden,
        "strong": len(hidden.replace(" ", "")) >= 4,
    }
