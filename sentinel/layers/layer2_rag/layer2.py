from sentinel.core.models import L2Result
from .chunk_store import (ingest_chunk, get_all_chunks, quarantine_chunk, retrieve_and_validate,
                          reset_store, get_chunks_for_provenance, retrieval_flagged, review_chunk)

async def layer2_ingest(text: str, source: str, session_id: str | None = None,
                        scope: str | None = None, principal: str | None = None) -> dict:
    """
    Public interface to ingest a document chunk. Tool outputs (source "tool_response*")
    are stored per session and never enter the shared, retrievable knowledge base (B-1);
    pass the session_id so that session's L4 can trace against them.
    """
    return await ingest_chunk(text, source, session_id=session_id, scope=scope, principal=principal)

async def layer2_validate_context(query: str) -> tuple[L2Result, list]:
    """
    Retrieve chunks for a query and validate them.
    Returns (L2Result summarizing the worst finding, the full list of validated chunk dicts).

    NOTE: this previously declared a return type of `L2Result` while actually
    returning a `(L2Result, list)` tuple. Callers were already unpacking it
    correctly (via an isinstance(..., tuple) check), so this was a type-hint
    lie rather than a runtime bug — fixed here for correctness.
    """
    # L2 review C8: retrieval embeds the query and re-scores candidates -- model work, kept off the event loop.
    import sentinel.config as _cfg
    if getattr(_cfg, "L2_SCORE_IN_THREAD", True):
        from sentinel.core.model_executor import run_model     # reused pool: no leaked OpenMP teams (§21.5)
        validated_chunks = await run_model(retrieve_and_validate, query)
    else:
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
        elif chunk.get("doc_axis") and chunk.get("blocked"):
            # L2 review C12: a doc-axis chunk re-validated at/above its anchor (re-scored under a newer configuration,
            # or an anchor that moved) used to score 0 here, so a blocked retrieval was invisible to the pipeline. It
            # now publishes its own score on the shared axis (>= WARN by construction).
            from sentinel.config import l2_shared_score
            chunk_score = l2_shared_score(chunk.get("metadata") or {})
            candidate_class = "INSTRUCTIONAL_CHUNK"
            candidate_reason = f"Retrieved chunk {chunk['chunk_id']} re-validated at/above its anchor"
            all_findings.append(candidate_reason)
        elif chunk.get("doc_axis"):
            # Doc-axis chunks are judged on their own axis (R-014); an admitted chunk
            # with a valid signature is below its anchor by construction.
            candidate_class = None
            candidate_reason = None
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
    """Get all active, review-flagged, and quarantined knowledge-base chunks."""
    return get_all_chunks()


def layer2_provenance_chunks(session_id: str | None) -> list:
    """Chunks L4 may trace against for this session: shared KB + its own tool outputs."""
    return get_chunks_for_provenance(session_id)


def layer2_retrieval_flagged(chunk: dict) -> bool:
    """Whether a retrieved chunk is flagged for L4 (one rule for app and simulator)."""
    return retrieval_flagged(chunk)

def layer2_quarantine(chunk_id: str) -> bool:
    """Manually quarantine a chunk."""
    return quarantine_chunk(chunk_id)

def layer2_review(chunk_id: str, decision: str, note: str = "") -> dict | None:
    """Release (retrievable) or reject (quarantine) a chunk held for review (L2 review C5)."""
    return review_chunk(chunk_id, decision, note)


def layer2_reset() -> None:
    """Clear all RAG chunk stores. Called on /sentinel/reset."""
    reset_store()
