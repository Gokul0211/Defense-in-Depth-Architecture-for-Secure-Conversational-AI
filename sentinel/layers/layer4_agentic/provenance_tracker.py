import difflib
from sentinel.layers.layer2_rag import layer2_get_chunks

# Below this length, substring/fuzzy matching against free-form text is
# unreliable in both directions: short values (e.g. "1", "yes", "USD") will
# spuriously substring-match almost any text, while being too short for a
# fuzzy ratio to mean anything either. Rather than report a false
# EXPLICIT_USER_REQUEST/CONTEXT_DERIVED with high confidence for these, we
# report them as UNCERTAIN with a note explaining why — that's the honest
# answer, not a confident-looking wrong one.
MIN_TRACEABLE_LEN = 4

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


def trace_parameters(parameters: dict, conversation_history: list[dict]) -> dict:
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
    """
    provenance = {}

    # Keep turns individually addressable (index -> lowercased text) instead
    # of joining them into one string.
    user_turns = [
        (i, turn.get("content", "").lower())
        for i, turn in enumerate(conversation_history)
        if turn.get("role") == "user"
    ]

    # Get all active chunks from L2 to check if params came from RAG
    active_chunks = layer2_get_chunks()

    for param_name, param_value in parameters.items():
        val_str = str(param_value).lower()

        if not val_str:
            provenance[param_name] = {
                "source": "UNCERTAIN",
                "confidence": 0.1,
                "details": "Empty parameter value",
                "matched_turn_index": None,
                "matched_chunk_id": None,
            }
            continue

        if len(val_str) < MIN_TRACEABLE_LEN:
            # Short values are unreliable to trace either way (see
            # MIN_TRACEABLE_LEN docstring above) — report honestly rather
            # than let a coincidental substring hit produce false confidence.
            provenance[param_name] = {
                "source": "UNCERTAIN",
                "confidence": 0.3,
                "details": f"Value too short ({len(val_str)} chars) to trace reliably",
                "matched_turn_index": None,
                "matched_chunk_id": None,
            }
            continue

        # 1. Check if it came from user input (exact or fuzzy), turn by turn,
        # keeping the best (highest-ratio) match so we can name a specific
        # source turn rather than "somewhere in the conversation".
        best_turn_idx, best_turn_ratio = None, 0.0
        for turn_idx, turn_text in user_turns:
            matched, ratio = fuzzy_contains(val_str, turn_text)
            if matched and ratio > best_turn_ratio:
                best_turn_idx, best_turn_ratio = turn_idx, ratio

        if best_turn_idx is not None:
            provenance[param_name] = {
                "source": "EXPLICIT_USER_REQUEST",
                "confidence": 0.95 if best_turn_ratio >= 0.999 else round(0.6 + 0.35 * best_turn_ratio, 2),
                "details": (
                    f"Found exact match in turn {best_turn_idx}" if best_turn_ratio >= 0.999
                    else f"Found fuzzy match in turn {best_turn_idx} (ratio={best_turn_ratio:.2f})"
                ),
                "matched_turn_index": best_turn_idx,
                "matched_chunk_id": None,
            }
            continue

        # 2. Check if it came from a RAG chunk (exact or fuzzy)
        found_in_rag = False
        for chunk in active_chunks:
            if chunk.get("quarantined", False):
                continue
            chunk_text = (chunk.get("text") or "").lower()
            matched, ratio = fuzzy_contains(val_str, chunk_text)
            if matched:
                trust = chunk["metadata"].get("trust_score", 0.5)
                provenance[param_name] = {
                    "source": "CONTEXT_DERIVED",
                    "confidence": trust,
                    "details": (
                        f"Traced to RAG chunk {chunk['chunk_id']} (trust={trust:.2f}, "
                        f"match_ratio={ratio:.2f})"
                    ),
                    "matched_turn_index": None,
                    "matched_chunk_id": chunk["chunk_id"],
                }
                found_in_rag = True
                break

        if found_in_rag:
            continue

        # 3. Uncertain / LLM Hallucinated
        provenance[param_name] = {
            "source": "UNCERTAIN",
            "confidence": 0.1,
            "details": "Could not trace value to user input or RAG context",
            "matched_turn_index": None,
            "matched_chunk_id": None,
        }

    return provenance


def determine_authorization(provenance: dict) -> str:
    """Determine overall authorization source based on parameter provenances."""
    sources = [p["source"] for p in provenance.values()]

    if not sources:
        return "IMPLICIT_USER_INTENT"  # No params

    if "UNCERTAIN" in sources:
        return "SUSPICIOUS"

    if "CONTEXT_DERIVED" in sources:
        return "CONTEXT_DERIVED"

    return "EXPLICIT_USER_REQUEST"
