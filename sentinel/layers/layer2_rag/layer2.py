from sentinel.core.models import L2Result
from .chunk_store import ingest_chunk, get_all_chunks, quarantine_chunk, retrieve_and_validate, reset_store

async def layer2_ingest(text: str, source: str) -> dict:
    """
    Public interface to ingest a document chunk.
    """
    return await ingest_chunk(text, source)

async def layer2_validate_context(query: str) -> tuple[L2Result, list]:
    """
    Retrieve chunks for a query and validate them.
    Returns (L2Result summarizing the worst finding, the full list of validated chunk dicts).

    NOTE: this previously declared a return type of `L2Result` while actually
    returning a `(L2Result, list)` tuple. Callers were already unpacking it
    correctly (via an isinstance(..., tuple) check), so this was a type-hint
    lie rather than a runtime bug — fixed here for correctness.
    """
    validated_chunks = retrieve_and_validate(query)

    max_score = 0.0
    threat_class = "CLEAN"
    reason = "Context validated successfully."
    all_findings = []
    any_blocked = False

    for chunk in validated_chunks:
        if chunk.get("blocked"):
            any_blocked = True

        chunk_score = 0.0

        if not chunk["is_valid"]:
            chunk_score = 1.0
            candidate_class = "KNOWLEDGE_POISONING"
            candidate_reason = f"HMAC validation failed for chunk {chunk['chunk_id']}"
            all_findings.append(candidate_reason)
        elif chunk["current_density"] > 0.6:
            chunk_score = chunk["current_density"]
            candidate_class = "INSTRUCTIONAL_CHUNK"
            candidate_reason = f"High instruction density ({chunk_score:.2f}) in chunk {chunk['chunk_id']}"
            all_findings.append(f"Chunk {chunk['chunk_id']} density: {chunk_score:.2f}")
        else:
            candidate_class = None
            candidate_reason = None

        # Only let this chunk's finding become the summary reason/threat_class
        # if it's the most severe one seen so far. Previously `reason` and
        # `threat_class` were overwritten unconditionally on every invalid
        # chunk regardless of score, so a later lower-severity finding could
        # silently clobber an earlier tampering detection in the summary.
        if chunk_score > max_score:
            threat_class = candidate_class
            reason = candidate_reason

        max_score = max(max_score, chunk_score)

    return L2Result(
        score=max_score,
        threat_class=threat_class,
        confidence=0.85 if max_score > 0 else 0.0,
        reason=reason,
        # Previously hardcoded False regardless of outcome — now reflects
        # whether any chunk in this retrieval was actually quarantined.
        quarantined=any_blocked,
    ), validated_chunks

def layer2_get_chunks() -> list:
    """Get all active, review-flagged, and quarantined chunks."""
    return get_all_chunks()

def layer2_quarantine(chunk_id: str) -> bool:
    """Manually quarantine a chunk."""
    return quarantine_chunk(chunk_id)

def layer2_reset() -> None:
    """Clear all RAG chunk stores. Called on /sentinel/reset."""
    reset_store()
