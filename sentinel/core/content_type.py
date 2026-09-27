"""
Lightweight content-type detection for L2's instruction-density scoring.

WHY THIS EXISTS (Phase 5 plan item 3B.6)
-------------------------------------------
`INSTRUCTIONAL_TEMPLATES` is a single global list scoring five structurally
different BIPIA content types — email, table, code, qa (news articles) and
abstract (BBC summaries). Phase 2.4 mined four genuinely better templates
for the qa/abstract scenarios by disciplined train-only calibration, and
confirmed a real held-out gain (AUROC 0.7008 -> 0.7120). It then correctly
REJECTED them, because the same global list also scores code, where a
cross-scenario regression check measured -0.0417 — a bigger loss on
BIPIA's strongest scenario than the gain being bought.

That rejection was right given one global list. The list is the problem:
a template set tuned for long-form journalism should not be scoring
source code. Conditioning the template set on content type captures the
qa/abstract gain without paying the code cost, because the two sets never
score the same content.

A second, independent reason from plan item 3B.2: L2's calibrated
operating point turned out to be corpus-dependent, not universal — its
BIPIA-derived review boundary (threat score 0.287) produces FPR 0.9245 on
sentinel_bench. A detector whose right threshold depends on what kind of
content it is reading is a detector that should be conditioning on
content type rather than picking one number.

SCOPE AND HONESTY
--------------------
This is deliberately a cheap structural classifier, not a semantic one.
It looks at markup, punctuation and layout — the properties that actually
distinguish a table from an article — and never at meaning. It is meant
to be obviously-right on clear cases and to fall back to PROSE when
unsure, because PROSE keeps the existing production template set and
therefore the existing behaviour.

The classifier is NOT validated against labelled content-type ground
truth (no such corpus exists here). Its job is routing, and the routing
is gated behind a config flag that is OFF by default, so an incorrect
classification cannot change any production or already-published number
until the routing itself has been validated on held-out data.
"""

from __future__ import annotations

import re

PROSE = "prose"
CODE = "code"
TABULAR = "tabular"
LONG_FORM = "long_form"

# Strong code signals: language keywords in declaration position, fenced
# blocks, and the punctuation density real source has and prose does not.
_CODE_MARKERS = (
    re.compile(r"```"),
    re.compile(r"^\s*(?:def|class|import|from|function|var|let|const|public|private)\s+", re.M),
    re.compile(r"^\s*(?:#include|package|using)\s+", re.M),
    re.compile(r"\bif\s*\([^)]*\)\s*\{"),
    re.compile(r"=>|::|->|\+=|!==|===")
)

# A markdown/ASCII table needs several pipe-delimited rows, not one
# sentence that happens to contain a pipe.
_TABLE_ROW = re.compile(r"^\s*\|.*\|\s*$", re.M)
_TSV_ROW = re.compile(r"^[^\t\n]+\t[^\t\n]+", re.M)

# Long-form prose threshold. BIPIA's qa/abstract contexts are full news
# and BBC articles; email/table content is far shorter. 1200 chars sits
# well above typical email bodies and well below article length — chosen
# as a structural separator, and deliberately not tuned against any
# held-out score.
_LONG_FORM_MIN_CHARS = 1200
_SENTENCE_END = re.compile(r"[.!?][\s\"')\]]")


def _code_score(text: str) -> int:
    """
    Total code-marker OCCURRENCES, not the number of distinct patterns
    that matched.

    Counting distinct patterns was wrong and measurably so: ordinary
    Python trips only the declaration-keyword pattern, however many
    `def`/`import` lines it contains, so a whole source file scored 1 and
    was classified as prose. Occurrences scale with how code-like the text
    actually is, which is the property being tested.
    """
    return sum(len(pattern.findall(text)) for pattern in _CODE_MARKERS)


def _symbol_ratio(text: str) -> float:
    """
    Density of code-ish punctuation.

    `|` is deliberately EXCLUDED. It is the markdown table delimiter, and
    including it meant a well-formed table exceeded the code ratio and was
    classified as CODE before the table check ever ran.
    """
    if not text:
        return 0.0
    symbols = sum(1 for c in text if c in "{}[]();<>=/\\*&^%$#@~`")
    return symbols / len(text)


def _is_tabular(text: str) -> bool:
    return len(_TABLE_ROW.findall(text)) >= 3 or len(_TSV_ROW.findall(text)) >= 3


def detect_content_type(text: str) -> str:
    """
    Classify `text` into one of PROSE / CODE / TABULAR / LONG_FORM.

    Order is load-bearing:
      1. Explicit code markers win outright — a long source file is still
         code, not an article.
      2. Tables are checked BEFORE the symbol-density fallback, because
         delimiter-heavy tables would otherwise read as code.
      3. The symbol-density fallback then catches code that uses no
         recognised keywords (minified JS, config blobs).
      4. Length + sentence structure identifies long-form articles.
    PROSE is the fallback for anything unclear, which is the safe default:
    PROSE routes to the unchanged production template set.
    """
    if not text or not text.strip():
        return PROSE

    if _code_score(text) >= 2:
        return CODE

    if _is_tabular(text):
        return TABULAR

    if _symbol_ratio(text) > 0.08:
        return CODE

    if len(text) >= _LONG_FORM_MIN_CHARS and len(_SENTENCE_END.findall(text)) >= 5:
        return LONG_FORM

    return PROSE
