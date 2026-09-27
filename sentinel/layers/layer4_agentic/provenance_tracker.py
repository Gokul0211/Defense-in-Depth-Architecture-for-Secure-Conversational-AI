import difflib
import re
from sentinel.layers.layer2_rag import layer2_provenance_chunks

# Below this length, substring/fuzzy matching against free-form text is
# unreliable in both directions: short values (e.g. "1", "yes", "USD") will
# spuriously substring-match almost any text, while being too short for a
# fuzzy ratio to mean anything either. Rather than report a false
# EXPLICIT_USER_REQUEST/CONTEXT_DERIVED with high confidence for these, we
# report them as UNTRACEABLE with a note explaining why — that's the honest
# answer, not a confident-looking wrong one.
MIN_TRACEABLE_LEN = 4

# Provenance source labels. UNTRACEABLE is separate from UNCERTAIN and the
# distinction is load-bearing — see determine_authorization.
#
#   EXPLICIT_USER_REQUEST  traced to a specific conversation turn
#   CONTEXT_DERIVED        traced to a specific retrieved chunk
#   UNCERTAIN              WAS traceable, and traced to nothing
#   UNTRACEABLE            could not be traced either way (empty, or below
#                          MIN_TRACEABLE_LEN), so it carries NO evidence
SOURCE_EXPLICIT = "EXPLICIT_USER_REQUEST"
SOURCE_CONTEXT = "CONTEXT_DERIVED"
SOURCE_UNCERTAIN = "UNCERTAIN"
SOURCE_UNTRACEABLE = "UNTRACEABLE"

# Minimum token length for the token-containment fallback below. Two-character
# tokens ("of", "to", "id") appear in almost any English sentence, so including
# them would let a value be "contained" by coincidence.
_MIN_TOKEN_LEN = 3

# Fraction of a value's token characters that must be accounted for before
# token containment is accepted. 1.0 would require every token including
# throwaway ones ("https", "com"); requiring ALL tokens to be present but
# scoring confidence by coverage keeps the rule conservative while letting the
# confidence reflect how much of the value was actually explained.
_TOKEN_SPLIT_RE = re.compile(r"[^0-9a-z]+")

# Fuzzy-match ratio (difflib.SequenceMatcher) above which a window of text is
# considered a match to a parameter value even without an exact substring hit.
# This is a placeholder pending calibration against a labeled corpus (see the
# evaluation plan doc) — 0.85 is a conservative starting point chosen to
# avoid the ratio drifting into token-level false positives.
FUZZY_MATCH_THRESHOLD = 0.85


def fuzzy_contains(needle: str, haystack: str, threshold: float = FUZZY_MATCH_THRESHOLD) -> tuple[bool, float]:
    """
    Check whether `haystack` contains a span that fuzzy-matches `needle`,
    using a sliding window + difflib.SequenceMatcher ratio. This is what
    actually implements the "fuzzy / edit-distance-aware" matching the
    project's docs describe — the previous implementation only ever did an
    exact `in` substring check, which misses near-matches (reformatted
    numbers, minor paraphrasing, whitespace/punctuation differences) that an
    LLM commonly introduces even when a value legitimately did come from the
    user or a retrieved chunk.

    Returns (matched, best_ratio).
    """
    if not needle or not haystack:
        return False, 0.0

    # Fast path: exact substring match.
    if needle in haystack:
        return True, 1.0

    window_size = max(len(needle), 4)
    step = max(1, window_size // 4)

    best_ratio = 0.0
    for start in range(0, max(1, len(haystack) - window_size + 1), step):
        window = haystack[start:start + window_size]
        ratio = difflib.SequenceMatcher(None, needle, window).ratio()
        if ratio > best_ratio:
            best_ratio = ratio
            if best_ratio >= threshold:
                return True, best_ratio

    return False, best_ratio


def token_containment(needle: str, haystack: str) -> tuple[bool, float]:
    """
    Whether every alphanumeric token of `needle` appears somewhere in
    `haystack`, with confidence scaled by how much of `needle` that explains.

    WHY THIS EXISTS — measured, 2026-09-20. `fuzzy_contains` compares the value
    as one string against sliding windows, so a value whose components are all
    present but reassembled into a different shape is reported UNCERTAIN. Three
    real instances from InjecAgent's benign user cases
    (scratch/rca_l4_provenance.py):

        url   "https://www.codedculinary.com/recipe/blueberry-scones/"
        turn  "navigate to the Blueberry Scones recipe on `www.codedculinary.com`"

        email "amy.watson@gmail.com"
        turn  "Check Amy Watson's shared calendar ..."

        id    "ElizabethGreen_Dentist"
        turn  "good reviews about Dr. Elizabeth Green, the dentist"

    In each case an agent legitimately SYNTHESIZED an identifier from values the
    user supplied. Reporting those as untraced provenance is wrong in the
    direction that matters: it manufactures suspicion about the most ordinary
    thing a tool-using agent does.

    Requiring ALL tokens (not a fraction) is what keeps this conservative — an
    injected value that shares a few tokens with the conversation does not pass.
    `coverage` is reported as the confidence input so a value explained by one
    long token ranks below one explained by several.

    DELIBERATELY STILL STRICT. Of the three cases above only the third is
    resolved by this rule. `amy.watson@gmail.com` keeps the tokens `gmail` and
    `com`, which appear nowhere in the user's turn, and
    `https://.../recipe/...` keeps `https` and `recipe`; in both the agent
    genuinely added information the user never supplied, and reporting that as
    not-fully-traced is the correct security answer. The all-tokens rule was NOT
    relaxed to a coverage fraction to capture them, because any such fraction
    would have been chosen while looking at this corpus's benign arm. What was
    wrong about those samples is what their UNCERTAIN verdict then COST them
    downstream, which is a separate defect (see determine_authorization).

    Each token is tested against the raw haystack and against a
    separator-collapsed copy of it, so an identifier that concatenates words the
    user did supply ("ElizabethGreen" from "Elizabeth Green") matches. That is a
    normalization refinement in the same spirit as core/text_canonicalize.py —
    fold a representational difference before comparing — not a loosening of the
    matching bar.
    """
    if not needle or not haystack:
        return False, 0.0
    tokens = [t for t in _TOKEN_SPLIT_RE.split(needle) if len(t) >= _MIN_TOKEN_LEN]
    if not tokens:
        return False, 0.0
    collapsed = _TOKEN_SPLIT_RE.sub("", haystack)
    matched = [t for t in tokens if t in haystack or t in collapsed]
    if len(matched) != len(tokens):
        return False, 0.0
    total_chars = sum(len(t) for t in tokens)
    covered = sum(len(t) for t in matched)
    return True, (covered / total_chars) if total_chars else 0.0


def _leaf_values(name: str, value, out: list | None = None) -> list[tuple[str, object]]:
    """
    Flatten a parameter into its scalar leaves, as (path, scalar) pairs.

    WHY THIS EXISTS — a real bug, measured 2026-09-20. `trace_parameters` used
    `str(param_value)` on whatever it was handed, so a container parameter was
    matched against prose by its PYTHON REPR:

        {'keywords': ['Budget']}   ->  traced the string "['budget']"
        {'event_ids': ['DocAppointment1']} -> traced "['docappointment1']"
        {'date_range': {'start_date': '2022-01-22', ...}} -> traced the dict repr

    No natural-language turn contains a Python list literal, so EVERY
    container-valued parameter was untraceable by construction, reported
    UNCERTAIN, and escalated the whole call to SUSPICIOUS at score 0.9. On
    InjecAgent's 17 benign user cases this alone accounted for samples 1, 6, 8
    and 12; sample 8's `['DocAppointment1']` becomes an EXACT match in turn 0
    once flattened.

    Leaves are traced individually and the parameter's provenance is the worst
    TRACEABLE leaf (see trace_parameters), which matches L4's existing
    worst-parameter semantics one level down.
    """
    if out is None:
        out = []
    if isinstance(value, dict):
        for k, v in value.items():
            _leaf_values(f"{name}.{k}", v, out)
    elif isinstance(value, (list, tuple, set)):
        for i, v in enumerate(value):
            _leaf_values(f"{name}[{i}]", v, out)
    else:
        out.append((name, value))
    return out


def _trace_one_value(val_str: str, user_turns: list, active_chunks: list) -> dict:
    """
    Provenance for a single scalar value. Order of evidence: exact/fuzzy match
    against a user turn, then token containment against a user turn, then the
    same two against retrieved chunks, then UNCERTAIN.

    Token containment is tried only AFTER whole-string matching on every turn,
    so a value that genuinely appears verbatim keeps its higher confidence and
    its exact-match wording.
    """
    best_turn_idx, best_turn_ratio = None, 0.0
    for turn_idx, turn_text in user_turns:
        matched, ratio = fuzzy_contains(val_str, turn_text)
        if matched and ratio > best_turn_ratio:
            best_turn_idx, best_turn_ratio = turn_idx, ratio

    if best_turn_idx is not None:
        return {
            "source": SOURCE_EXPLICIT,
            "confidence": 0.95 if best_turn_ratio >= 0.999 else round(0.6 + 0.35 * best_turn_ratio, 2),
            "details": (
                f"Found exact match in turn {best_turn_idx}" if best_turn_ratio >= 0.999
                else f"Found fuzzy match in turn {best_turn_idx} (ratio={best_turn_ratio:.2f})"
            ),
            "matched_turn_index": best_turn_idx,
            "matched_chunk_id": None,
        }

    best_tok_idx, best_tok_cov = None, 0.0
    for turn_idx, turn_text in user_turns:
        contained, coverage = token_containment(val_str, turn_text)
        if contained and coverage > best_tok_cov:
            best_tok_idx, best_tok_cov = turn_idx, coverage

    if best_tok_idx is not None:
        # Capped below the whole-string fuzzy band: a value reassembled from the
        # user's own tokens is real provenance, but weaker evidence than the
        # value appearing as written, and the confidence must say so.
        return {
            "source": SOURCE_EXPLICIT,
            "confidence": round(0.6 + 0.25 * best_tok_cov, 2),
            "details": (
                f"All value tokens present in turn {best_tok_idx} "
                f"(coverage={best_tok_cov:.2f}); value appears synthesized from user-supplied terms"
            ),
            "matched_turn_index": best_tok_idx,
            "matched_chunk_id": None,
        }

    # L4_PROVENANCE_POLICY="source_trust" (fixing.md G, R-010): chunks L2 held for
    # review or quarantined are UNTRUSTED third-party content, and a parameter copied
    # from one is the indirect-injection signature. The legacy tracer SKIPPED
    # quarantined chunks, so a value copied from a known-malicious chunk came out as
    # "untraceable" rather than as "from untrusted content". Checked first, so a value
    # present in both a trusted and an untrusted chunk is attributed conservatively.
    import sentinel.config as _cfg
    if getattr(_cfg, "L4_PROVENANCE_POLICY", "legacy") == "source_trust":
        for chunk in active_chunks:
            if not (chunk.get("quarantined") or chunk.get("review_flagged")):
                continue
            chunk_text = (chunk.get("text") or "").lower()
            matched, ratio = fuzzy_contains(val_str, chunk_text)
            if not matched:
                matched, ratio = token_containment(val_str, chunk_text)
            if matched:
                trust = chunk["metadata"].get("trust_score", 0.0)
                return {
                    "source": SOURCE_CONTEXT,
                    "untrusted_source": True,
                    "confidence": trust,
                    "details": (f"Traced to UNTRUSTED chunk {chunk['chunk_id']} "
                                f"(trust={trust:.2f}, match_ratio={ratio:.2f})"),
                    "matched_turn_index": None,
                    "matched_chunk_id": chunk["chunk_id"],
                }
    for chunk in active_chunks:
        if chunk.get("quarantined", False):
            continue
        chunk_text = (chunk.get("text") or "").lower()
        matched, ratio = fuzzy_contains(val_str, chunk_text)
        if not matched:
            matched, ratio = token_containment(val_str, chunk_text)
        if matched:
            trust = chunk["metadata"].get("trust_score", 0.5)
            return {
                "source": SOURCE_CONTEXT,
                "confidence": trust,
                "details": (
                    f"Traced to RAG chunk {chunk['chunk_id']} (trust={trust:.2f}, "
                    f"match_ratio={ratio:.2f})"
                ),
                "matched_turn_index": None,
                "matched_chunk_id": chunk["chunk_id"],
            }

    return {
        "source": SOURCE_UNCERTAIN,
        "confidence": 0.1,
        "details": "Could not trace value to user input or RAG context",
        "matched_turn_index": None,
        "matched_chunk_id": None,
    }


# Rank used to pick a container parameter's representative leaf: the least
# trusted TRACEABLE leaf wins, mirroring determine_authorization's own ordering
# one level down.
_SOURCE_SEVERITY = {
    SOURCE_UNCERTAIN: 3,
    SOURCE_CONTEXT: 2,
    SOURCE_EXPLICIT: 1,
    SOURCE_UNTRACEABLE: 0,
}


def trace_parameters(parameters: dict, conversation_history: list[dict],
                     session_id: str | None = None, chunks: list[dict] | None = None) -> dict:
    """
    Trace where each parameter value came from.
    Returns a dict mapping param_name -> {
        "source": source_type,
        "confidence": float,
        "details": str,
        "matched_turn_index": int | None,   # which turn in conversation_history matched, if source is EXPLICIT_USER_REQUEST
        "matched_chunk_id": str | None,     # which chunk matched, if source is CONTEXT_DERIVED
    }

    Turn-level granularity: previously all user turns were joined into one
    blob (`" ".join(user_texts)`) before matching, so a match only told you
    "some turn in this conversation" rather than which one. This matters for
    building a taint graph with real per-turn edges (see taint_graph.py) —
    without it, every EXPLICIT_USER_REQUEST provenance result would have to
    collapse to one coarse "whole conversation" node instead of the specific
    turn that actually produced the value.

    CONTAINER PARAMETERS ARE FLATTENED (2026-09-20). A dict/list parameter is
    traced by its scalar LEAVES, not by its Python repr — see `_leaf_values`
    for the bug that motivated this and the measured effect. The parameter's
    reported provenance is its worst TRACEABLE leaf; `leaf_provenance` in
    `details` keeps the per-leaf detail for auditing.

    A parameter whose leaves are all untraceable (empty, or below
    MIN_TRACEABLE_LEN) is reported as UNTRACEABLE rather than UNCERTAIN, which
    is what stops "we cannot tell" from being consumed downstream as "evidence
    of attack" — see determine_authorization.
    """
    provenance = {}

    # Keep turns individually addressable (index -> lowercased text) instead
    # of joining them into one string.
    user_turns = [
        (i, turn.get("content", "").lower())
        for i, turn in enumerate(conversation_history)
        if turn.get("role") == "user"
    ]

    # Chunks this call may legitimately have read: the shared knowledge base plus THIS
    # session's own tool outputs. It used to read every chunk of every session (B-1), so
    # a value could "trace" to another user's tool output.
    active_chunks = chunks if chunks is not None else layer2_provenance_chunks(session_id)

    for param_name, param_value in parameters.items():
        leaves = _leaf_values(param_name, param_value)

        leaf_results: dict[str, dict] = {}
        for leaf_path, leaf_value in leaves:
            val_str = str(leaf_value).lower() if leaf_value is not None else ""

            if not val_str:
                leaf_results[leaf_path] = {
                    "source": SOURCE_UNTRACEABLE,
                    "confidence": 1.0,
                    "details": "Empty parameter value — carries no provenance evidence",
                    "matched_turn_index": None,
                    "matched_chunk_id": None,
                }
                continue

            if len(val_str) < MIN_TRACEABLE_LEN:
                # Short values are unreliable to trace either way (see
                # MIN_TRACEABLE_LEN above). Reported as UNTRACEABLE, with
                # confidence 1.0 meaning "no reason for suspicion from this
                # leaf" rather than the old 0.3, which downstream consumers
                # (determine_authorization, _min_provenance_confidence,
                # taint_graph) all read as positive evidence of attack.
                leaf_results[leaf_path] = {
                    "source": SOURCE_UNTRACEABLE,
                    "confidence": 1.0,
                    "details": f"Value too short ({len(val_str)} chars) to trace reliably",
                    "matched_turn_index": None,
                    "matched_chunk_id": None,
                }
                continue

            leaf_results[leaf_path] = _trace_one_value(val_str, user_turns, active_chunks)

        # The parameter's verdict is its worst traceable leaf; if every leaf was
        # untraceable the parameter itself is untraceable.
        worst_path = max(
            leaf_results,
            key=lambda p: (
                _SOURCE_SEVERITY.get(leaf_results[p]["source"], 0),
                -leaf_results[p]["confidence"],
            ),
        )
        chosen = dict(leaf_results[worst_path])
        if len(leaf_results) > 1:
            chosen["details"] = f"[{worst_path}] {chosen['details']}"
            chosen["leaf_provenance"] = {
                p: {"source": r["source"], "confidence": r["confidence"]}
                for p, r in leaf_results.items()
            }
        provenance[param_name] = chosen

    return provenance


def determine_authorization(provenance: dict) -> str:
    """
    Overall authorization source for a call, from its per-parameter provenance.

    UNTRACEABLE IS NOT SUSPICIOUS, and that is the point of the label
    (2026-09-20). Previously any `UNCERTAIN` escalated the call to SUSPICIOUS,
    and `MIN_TRACEABLE_LEN`'s honest "too short to trace reliably" result used
    that same label — so `tool_auditor` did `final_score = max(base, 0.9)`
    because a parameter was a pagination integer.

    Measured on InjecAgent's 17 benign user cases
    (scratch/rca_l4_provenance.py): samples 1, 6 and 15 were SUSPICIOUS solely
    because of `max_results: 1`, `limit: 1` and `max_results: 5`. Those
    samples then scored 0.9, ABOVE 419 of 510 genuinely malicious samples,
    which is the direct cause of FPR 1.0000 on that row.

    Turning "no evidence" into "evidence of absence" is the exact error
    `L1Result.tier_scores`' field comment in core/models.py forbids for L1's
    tiers; this is the same error one layer over. A value that could not be
    traced BECAUSE IT IS TOO SHORT TO TRACE must contribute nothing, in either
    direction.

    A call whose every parameter is untraceable therefore reads the same as a
    call with no parameters at all — IMPLICIT_USER_INTENT — because that is
    genuinely how much provenance evidence exists.
    """
    sources = [p["source"] for p in provenance.values()]

    if not sources:
        return "IMPLICIT_USER_INTENT"  # No params

    import sentinel.config as _cfg
    if getattr(_cfg, "L4_PROVENANCE_POLICY", "legacy") == "source_trust":
        # Graded by the TRUST of the source, not by traceability (fixing.md G):
        # copied from untrusted content > copied from trusted content > synthesised by
        # the agent (untraceable is not evidence of attack) > from the user.
        if any(p.get("untrusted_source") for p in provenance.values()):
            return "UNTRUSTED_SOURCE"
        if SOURCE_CONTEXT in sources:
            return SOURCE_CONTEXT
        if SOURCE_UNCERTAIN in sources:
            return "AGENT_SYNTHESIZED"
        if SOURCE_EXPLICIT in sources:
            return SOURCE_EXPLICIT
        return "IMPLICIT_USER_INTENT"

    if SOURCE_UNCERTAIN in sources:
        return "SUSPICIOUS"

    if SOURCE_CONTEXT in sources:
        return SOURCE_CONTEXT

    if SOURCE_EXPLICIT in sources:
        return SOURCE_EXPLICIT

    # Every parameter was UNTRACEABLE: no provenance evidence either way.
    return "IMPLICIT_USER_INTENT"
