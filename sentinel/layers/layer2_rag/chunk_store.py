import uuid
import numpy as np
from sklearn.metrics.pairwise import cosine_similarity
from .provenance import sign_chunk, verify_chunk
from .instruction_density import calculate_instruction_density
from sentinel.layers.layer1 import layer1_check
from sentinel.core.embedding import get_model

# In-memory store. NOTE: this is a development/eval fallback, not a production
# vector store — swap for a real ChromaDB/FAISS/pgvector-backed store before
# reporting any latency or scale numbers (see roadmap doc, Section 6.2).
collection = {}          # trust_score >= REVIEW_THRESHOLD  -> eligible for retrieval
review_store = {}        # QUARANTINE_THRESHOLD <= trust_score < REVIEW_THRESHOLD -> held for human review, NOT retrievable
quarantine_store = {}    # trust_score < QUARANTINE_THRESHOLD, or failed post-ingestion re-validation

# Two-tier trust bands, matching the documented (not the previously-implemented)
# behavior: hard block below 0.4, human review between 0.4 and 0.6, trusted above.
QUARANTINE_THRESHOLD = 0.4
REVIEW_THRESHOLD = 0.6

# Weighted trust formula weights. These are placeholders pending the ROC-based
# calibration described in the evaluation plan (Section 6.3 of the roadmap doc) —
# there is no labeled corpus yet to fit these against, so they are a documented,
# principled starting point (density weighted higher: instructional content in
# a *retrieved document* is inherently more suspicious than a document that merely
# resembles a known injection phrase) rather than an empirically tuned value.
TRUST_DENSITY_WEIGHT = 0.6
TRUST_L1_WEIGHT = 0.4


def _compute_trust_score(l1_score: float, density_score: float) -> float:
    """
    Weighted-sum trust score. Continuous in both inputs (no hard cutoff before
    this point) — a hard cutoff creates a discontinuity where e.g. density=0.39
    contributes nothing and density=0.41 contributes its full value, which makes
    the score impossible to calibrate sensibly. Previously the implementation
    used max(l1_penalty, density_penalty) with density zeroed below 0.4, which
    does not match this weighted formula.
    """
    trust = 1.0 - (TRUST_DENSITY_WEIGHT * density_score + TRUST_L1_WEIGHT * l1_score)
    return max(0.0, min(1.0, trust))


async def ingest_chunk(text: str, source: str) -> dict:
    """
    Ingest a chunk into the RAG vector store.
    Runs L1 scan, calculates instruction density, assigns trust score, signs it,
    and routes it into one of three tiers: quarantine / review / trusted.
    """
    chunk_id = f"chk_{uuid.uuid4().hex[:8]}"

    # 1. Run L1 Scan
    l1_result = await layer1_check(text)

    # 2. Calculate instruction density
    density_score = calculate_instruction_density(text)

    # 3. Calculate Trust Score (weighted, continuous — see _compute_trust_score)
    trust_score = _compute_trust_score(l1_result.score, density_score)

    # 4. Sign chunk for provenance
    signature = sign_chunk(chunk_id, text)

    # 5. Compute embedding for semantic retrieval
    embedding = get_model().encode([text])[0].tolist()

    metadata = {
        "source": source,
        "trust_score": trust_score,
        "instruction_density": density_score,
        "l1_score": l1_result.score,
        "signature": signature,
    }

    result = {
        "chunk_id": chunk_id,
        "text": text,
        "metadata": metadata,
        "embedding": embedding,
        "quarantined": False,
        "review_flagged": False,
        "reason": "Ingested successfully",
    }

    if trust_score < QUARANTINE_THRESHOLD:
        result["quarantined"] = True
        result["reason"] = (
            f"Quarantined: trust_score={trust_score:.2f} < {QUARANTINE_THRESHOLD} "
            f"(L1={l1_result.score:.2f}, density={density_score:.2f})"
        )
        quarantine_store[chunk_id] = result
        return result

    if trust_score < REVIEW_THRESHOLD:
        result["review_flagged"] = True
        result["reason"] = (
            f"Flagged for manual review: trust_score={trust_score:.2f} "
            f"is between {QUARANTINE_THRESHOLD} and {REVIEW_THRESHOLD} "
            f"(L1={l1_result.score:.2f}, density={density_score:.2f}). "
            f"Not eligible for retrieval until reviewed."
        )
        review_store[chunk_id] = result
        return result

    # trust_score >= REVIEW_THRESHOLD: eligible for retrieval
    collection[chunk_id] = result
    return result


def get_all_chunks() -> list:
    """Return all active, review-flagged, and quarantined chunks for the dashboard."""
    def _strip(chunk):
        return {k: v for k, v in chunk.items() if k != "embedding"}
    active_chunks = [_strip(c) for c in collection.values()]
    review_chunks = [_strip(c) for c in review_store.values()]
    q_chunks = [_strip(c) for c in quarantine_store.values()]
    return active_chunks + review_chunks + q_chunks


def quarantine_chunk(chunk_id: str) -> bool:
    """Manually move a chunk to quarantine, from either the active collection or review store."""
    for store in (collection, review_store):
        if chunk_id in store:
            chunk = store.pop(chunk_id)
            chunk["quarantined"] = True
            chunk["review_flagged"] = False
            chunk["reason"] = "Manually quarantined"
            quarantine_store[chunk_id] = chunk
            return True
    return False


def _quarantine_after_failed_revalidation(chunk_id: str, chunk_data: dict, reason: str):
    """
    Move a chunk from the active collection into quarantine because it failed
    re-validation at retrieval time (signature mismatch = tampering, or a
    re-scored instruction density above the review threshold).

    This is the fix for the previous behavior, where a failed HMAC check was
    recorded as a "finding" in the response but the chunk's text was still
    returned to the caller — i.e. a *detected* tampering event had no actual
    enforcement effect. Detection without action is not a security control.
    """
    collection.pop(chunk_id, None)
    chunk_data["quarantined"] = True
    chunk_data["reason"] = reason
    quarantine_store[chunk_id] = chunk_data


def retrieve_and_validate(query: str, top_k: int = 3) -> list:
    """
    Retrieve chunks ranked by cosine similarity to the query and re-validate
    their integrity at retrieval time. Chunks that fail re-validation are
    quarantined (moved out of `collection`, so they cannot be retrieved again
    on subsequent calls).

    IMPORTANT for callers: each returned dict carries a `blocked` flag. `text`
    is always populated (including for blocked chunks) because Layer 4's
    parameter-provenance tracer needs the real content to trace tool-call
    parameters back to a tampered chunk — that is a legitimate internal
    security use, not exposure. Any code path that assembles LLM-facing
    context from these results MUST check `blocked` first and exclude that
    chunk's text — do not thread `text` from a `blocked=True` entry into a
    prompt.
    """
    if not collection:
        return []

    query_embedding = get_model().encode([query])[0].reshape(1, -1)

    scored = []
    for chunk_data in collection.values():
        chunk_emb = np.array(chunk_data["embedding"]).reshape(1, -1)
        sim = float(cosine_similarity(query_embedding, chunk_emb)[0][0])
        scored.append((sim, chunk_data))

    scored.sort(key=lambda x: x[0], reverse=True)
    results = [item for _, item in scored[:top_k]]

    validated_chunks = []

    for chunk_data in results:
        chunk_id = chunk_data["chunk_id"]
        text = chunk_data["text"]
        metadata = chunk_data["metadata"]

        is_valid = verify_chunk(chunk_id, text, metadata.get("signature", ""))
        density = calculate_instruction_density(text)

        findings = []
        if not is_valid:
            findings.append("HMAC signature mismatch - possible tampering")
        if density > REVIEW_THRESHOLD:
            findings.append(f"High instruction density detected: {density:.2f}")

        blocked = (not is_valid) or (density > REVIEW_THRESHOLD)

        if blocked:
            reason = (
                "Quarantined at retrieval: "
                + "; ".join(findings)
            )
            _quarantine_after_failed_revalidation(chunk_id, chunk_data, reason)
            validated_chunks.append({
                "chunk_id": chunk_id,
                "text": text,
                "metadata": metadata,
                "is_valid": is_valid,
                "current_density": density,
                "findings": findings,
                "blocked": True,
            })
            continue

        validated_chunks.append({
            "chunk_id": chunk_id,
            "text": text,
            "metadata": metadata,
            "is_valid": is_valid,
            "current_density": density,
            "findings": findings,
            "blocked": False,
        })

    return validated_chunks


def reset_store():
    """Clear all in-memory RAG chunk stores. Called on /sentinel/reset."""
    collection.clear()
    review_store.clear()
    quarantine_store.clear()
