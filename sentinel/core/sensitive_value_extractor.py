"""
Candidate sensitive-value extractor for L5's provenance leak check —
name-shaped strings AND identifier-shaped values. NOT full NER.

WHY THIS EXISTS
------------------
RCA (2026-09-11, see layer5_output/pii_scanner.py's own RCA comment):
L5's PII_PATTERNS is pure regex, structurally blind to free-text name
disclosure — SSNs/cards/phones have fixed formats regex can exploit,
names don't. Measured against real AgentLeak data: 48% of real leaks are
free-text names, invisible to L5 as a result.

Rather than add a heavy NER dependency, this reuses the same idea L4
already proved out for a different problem (matching a value back to
where it came from — see layer4_agentic/provenance_tracker.py's
fuzzy_contains): extract candidate sensitive values from content the
system ingests (RAG documents, tool responses), track them per-session,
and at output time check whether the response mentions one of them (see
layer5_output/layer5.py). If a value that appeared in retrieved/tool
content shows up in the output, that's a real, checkable leak signal —
no NER model needed, and it's a provenance question ("did this come from
somewhere sensitive"), not a semantic one.

WHY IT EXTRACTS MORE THAN NAMES (2026-09-18, Phase 5 Stage 0a / 3B.4)
-----------------------------------------------------------------------
The original version matched exactly one pattern: "First Last" pairs.
That was correct for the RCA that created it — but it was a limitation of
the *extractor*, not of the approach. The provenance check is value
matching, not pattern matching; it is format-agnostic by construction,
and there is no reason a case number is harder to trace than a surname.

The cost of the restriction was measured directly against real AgentLeak
per-sample scores: the legal-vertical leak categories (case_number,
case_id, confidential_strategy, risk_notes) scored mean L5 score = 0.000
*exactly* — never flagged at all, regardless of ground truth — and B.8's
own hand spot-check documented a phone_real false negative. Every one of
those values sat verbatim in the tracked context and was thrown away by
the name-only regex. Real vault content from a prepared AgentLeak trace,
showing what was being discarded:

    "Devin Schaefer Colleen Nguyen CANARY_SSN_C0E3534A 787-08-3753
     1995-01-25 CANARY_DIAGNOSIS_BF3C0DAB Generalized Anxiety ..."

Held-out result of lifting the restriction (train/test split by MD5 of
sample_id, specificity bar swept on train only — see
config.L5_PROVENANCE_MIN_IDENTIFIER_LEN for the full numbers):
recall 0.8223 -> 0.8870 at FPR 0.0748 -> 0.0923.

WHY THIS IS NOT CORPUS OVERFITTING
-------------------------------------
A fair objection, and the same one that correctly killed a proposed
`LLLL########`-shaped account-number regex in Phase 2.2: don't learn this
corpus's value *shapes*. Nothing here does. No pattern is derived from
AgentLeak's values; the rule is "a sufficiently specific value that
entered this session from a sensitive source must not appear in the
output," which is the identical provenance question L4 already answers
with fuzzy_contains. AgentLeak's `input.vault` is just that corpus's
instantiation of a set the production system already tracks at every
ingestion point (app.py's RAG-retrieval and tool-response handlers).

The one genuinely tunable piece is the specificity bar, and it is named,
documented, env-overridable, and explicitly scoped as corpus-derived in
config.py rather than buried as a literal here.

KNOWN, STATED LIMITATIONS — not a claim of solving leak detection
--------------------------------------------------------------------
- Names: only "First Last"-shaped consecutive-capitalized-word pairs.
  Misses single-word names and non-Western name formats, and will have
  some false-positive rate on genuine proper nouns unrelated to any leak
  (place names, brand names).
- Names, segmentation (found 2026-09-18, NOT fixed here): finditer
  matches non-overlapping pairs, so a capitalized word immediately
  preceding a name absorbs the name's first token — "Patient Allison
  Hill" yields "Patient Allison", and "Allison Hill" is never extracted.
  Left unchanged deliberately: D.3 measured name-type recall at 99.9%
  with this exact regex against real vault text (whose values are
  space-joined, so pairs align), and changing the name path would
  invalidate that verified result without a re-measurement. Locked in by
  tests/test_sensitive_value_extractor.py so it stays visible; fixing it
  is its own change with its own held-out run.
- Identifiers: only values carrying a digit or an explicit sensitivity
  marker. A purely alphabetic secret (a codename, a password phrase) is
  not extracted, because tracking every long word would flood the store
  and the output check with ordinary vocabulary.
- The specificity bar is a blunt instrument. A genuinely short secret
  (a 4-digit PIN) is deliberately out of scope: it cannot be told apart
  from ordinary numeric content by length alone, and the false-positive
  cost of trying dominates.
"""

from __future__ import annotations

import re

from sentinel.config import (
    L5_PROVENANCE_MIN_IDENTIFIER_LEN,
    MAX_TRACKED_SENSITIVE_VALUES,
)

# "First Last" pattern — two consecutive capitalized words. Filters common
# sentence-initial false positives (a capitalized word starting a new
# sentence, immediately followed by another capitalized word, e.g. "The
# Report") by requiring the match not be preceded by sentence-ending
# punctuation + whitespace, handled by the caller filtering short common
# words rather than a lookbehind (variable-width lookbehind isn't
# supported by Python's re module for this pattern).
_NAME_CANDIDATE_RE = re.compile(r"\b[A-Z][a-z]+ [A-Z][a-z]+\b")

# Identifier-shaped run: alphanumerics plus the separators real-world
# identifiers actually use (hyphen, underscore, slash, dot). Deliberately
# excludes whitespace — an identifier is one token; multi-token sensitive
# phrases are the name path's job, not this one.
_IDENTIFIER_CANDIDATE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9\-_/\.]{2,}")

# Separators that are part of an identifier internally but are punctuation
# when they end one ("CASE-3728-112231." at the end of a sentence). Left
# attached, the candidate would never match the same value in the output.
_TRAILING_PUNCT = "-_/."

# Explicit sensitivity markers — a value carrying one qualifies on the
# marker alone, without needing a digit. CANARY_ is SENTINEL's own planted
# -token convention (see config.CANARY_TOKEN) and is also how AgentLeak's
# traces mark their planted vault values.
_SENSITIVITY_MARKERS = ("CANARY_",)

# Common capitalized word pairs that aren't names — title-case phrases,
# common sentence-starting words followed by another capitalized word.
# Not exhaustive; a real, bounded filter for the most common false-positive
# shapes, not a claim of eliminating them all.
_STOPWORD_FIRST = {
    "The", "This", "That", "These", "Those", "A", "An", "In", "On", "At",
    "For", "With", "From", "To", "Of", "And", "Or", "But", "If", "When",
    "While", "As", "Please", "Note", "Warning", "Important", "According",
}

MIN_NAME_LEN = 4  # matches provenance_tracker.py's MIN_TRACEABLE_LEN reasoning


def is_name_shaped(value: str) -> bool:
    """
    True if `value` is one of the name-shaped candidates this module
    extracts. Exposed so layer5.py can pick a match policy without
    duplicating the regex — see match_policy_for below.
    """
    return bool(value) and _NAME_CANDIDATE_RE.fullmatch(value) is not None


def match_policy_for(value: str) -> str:
    """
    Which matching rule L5 should use for this tracked value:
    "fuzzy" or "exact".

    Names get fuzzy matching (the behaviour D.3 verified): an LLM
    routinely re-cases, reorders, or lightly reformats a person's name
    while still disclosing it, and difflib's ratio is the right tool for
    that.

    Identifiers get EXACT matching, deliberately. A near-miss identifier
    is a *different* identifier, not a disclosure of this one —
    "CASE-3728-112232" is not a leak of "CASE-3728-112231", but the two
    sit far above fuzzy_contains' 0.85 ratio. Digit strings in particular
    are pathologically prone to high fuzzy similarity with unrelated digit
    strings of the same shape, so applying the name policy here would
    trade the recall this module gained for false positives on exactly
    the categories it was added to catch.
    """
    return "fuzzy" if is_name_shaped(value) else "exact"


def _extract_names(text: str) -> list[str]:
    """Name-shaped candidates. Behaviour unchanged since D.3."""
    found = []
    for match in _NAME_CANDIDATE_RE.finditer(text):
        candidate = match.group(0)
        if candidate.split()[0] in _STOPWORD_FIRST:
            continue
        if len(candidate) < MIN_NAME_LEN:
            continue
        found.append(candidate)
    return found


def _extract_identifiers(text: str) -> list[str]:
    """
    Identifier-shaped candidates passing the specificity bar.

    A candidate qualifies if it is long enough (see
    L5_PROVENANCE_MIN_IDENTIFIER_LEN's calibration note) AND either
    contains a digit or carries an explicit sensitivity marker. The digit
    requirement is what keeps ordinary long words — "confidentiality",
    "recommendations" — out of the store; without it, the output check
    would fire on any response reusing a word from a retrieved document.
    """
    found = []
    for match in _IDENTIFIER_CANDIDATE_RE.finditer(text):
        candidate = match.group(0).rstrip(_TRAILING_PUNCT)
        if len(candidate) < L5_PROVENANCE_MIN_IDENTIFIER_LEN:
            continue
        has_marker = any(m in candidate for m in _SENSITIVITY_MARKERS)
        if not has_marker and not any(c.isdigit() for c in candidate):
            continue
        found.append(candidate)
    return found


def extract_sensitive_value_candidates(text: str) -> list[str]:
    """
    Extract candidate sensitive values from `text`. Called at ingestion
    points (RAG documents, tool responses) to populate
    session.tracked_sensitive_values — see that field's docstring in
    core/models.py, and prefer track_sensitive_values() below over
    calling this and extending the list by hand.

    Returns names first, then identifiers, de-duplicated with first-seen
    order preserved. Order matters only for readability of the resulting
    findings; correctness does not depend on it.
    """
    if not text:
        return []

    out: list[str] = []
    seen: set[str] = set()
    for candidate in _extract_names(text) + _extract_identifiers(text):
        if candidate in seen:
            continue
        seen.add(candidate)
        out.append(candidate)
    return out


def track_sensitive_values(session, text: str) -> int:
    """
    Extract candidates from `text` and add them to `session`'s tracked
    set, de-duplicating against what is already there and enforcing
    MAX_TRACKED_SENSITIVE_VALUES. Returns the number newly added.

    WHY THIS EXISTS rather than callers doing `.extend(extract(...))`:
    generalizing the extractor beyond names (3B.4) materially raises how
    many values one document can contribute, and L5 walks the entire list
    on every output scan. Three separate call sites were each doing an
    unbounded extend, so the bound and the de-duplication live here once
    instead of being re-implemented (or forgotten) at each.

    Retention on overflow is oldest-first: a later output is most likely
    to be leaking context ingested earlier in the session, so dropping the
    newest arrivals preserves the values most likely to matter. This is a
    stated design choice, not a measured one — no data currently exists to
    prefer it over the opposite, and the cap is set high enough (512) that
    real sessions should not reach it.
    """
    if not text:
        return 0

    existing = set(session.tracked_sensitive_values)
    added = 0
    for candidate in extract_sensitive_value_candidates(text):
        if len(session.tracked_sensitive_values) >= MAX_TRACKED_SENSITIVE_VALUES:
            break
        if candidate in existing:
            continue
        existing.add(candidate)
        session.tracked_sensitive_values.append(candidate)
        added += 1
    return added
