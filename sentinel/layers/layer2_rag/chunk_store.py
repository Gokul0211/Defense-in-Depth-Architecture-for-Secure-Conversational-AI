import uuid
import numpy as np
from sklearn.metrics.pairwise import cosine_similarity
from .provenance import sign_chunk, verify_chunk
from .instruction_density import calculate_instruction_density
from sentinel.layers.layer1 import layer1_check
from sentinel.core.embedding import get_model
from sentinel.core.bounded_cache import BoundedLRUDict
from sentinel.config import MAX_TRACKED_SESSIONS

# In-memory store. NOTE: this is a development/eval fallback, not a production
# vector store — swap for a real ChromaDB/FAISS/pgvector-backed store before
# reporting any latency or scale numbers (see roadmap doc, Section 6.2).
#
# Bounded via the same LRU utility used for the other session-keyed stores
# (see core/bounded_cache.py) — this was previously missed when that fix was
# applied elsewhere. It matters concretely for evaluation runs: the eval
# runner's L2 evaluator calls layer2_ingest() once per sample, and a
# multi-thousand-sample benchmark run would otherwise grow these dicts
# without bound for the lifetime of the process, same as the leak that was
# already fixed in layer3/threat_bus/correlation_engine.
collection = BoundedLRUDict(MAX_TRACKED_SESSIONS)          # trust_score >= REVIEW_THRESHOLD  -> eligible for retrieval
review_store = BoundedLRUDict(MAX_TRACKED_SESSIONS)        # QUARANTINE_THRESHOLD <= trust_score < REVIEW_THRESHOLD -> held for human review, NOT retrievable
quarantine_store = BoundedLRUDict(MAX_TRACKED_SESSIONS)    # trust_score < QUARANTINE_THRESHOLD, or failed post-ingestion re-validation

# SESSION-SCOPED third-party content (B-1, 2026-09-25). The three stores above are the
# SHARED knowledge base. Tool outputs used to be ingested into them too, which made one
# session's tool output (a) retrievable as RAG context by every other session, (b)
# traceable by every other session's L4 provenance check and (c) able to evict KB
# documents from the bounded LRU -- a cross-tenant leak and a one-request poisoning
# vector. Tool outputs now live here, keyed by session, are never retrievable by
# `retrieve_and_validate`, and are visible to L4 only for their own session.
# {session_id: {chunk_id: chunk}}; each session capped at MAX_SESSION_CHUNKS.
session_chunks = BoundedLRUDict(MAX_TRACKED_SESSIONS)
MAX_SESSION_CHUNKS = 256
_UNSCOPED = "_unscoped"

# Two-tier trust bands, matching the documented (not the previously-implemented)
# behavior: hard block below 0.4, human review between 0.4 and 0.6, trusted above.
QUARANTINE_THRESHOLD = 0.4
REVIEW_THRESHOLD = 0.713  # Youden's J-optimal on BIPIA test.jsonl (n=20000, recall=0.6116, FPR=0.2560) — see calibrate_l2_weights2.py

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


def _is_session_scoped(source: str, scope: str | None) -> bool:
    """Tool outputs are per-session third-party content, not knowledge-base documents."""
    if scope is not None:
        return scope == "session"
    return str(source or "").startswith("tool_response")


async def ingest_chunk(text: str, source: str, session_id: str | None = None,
                       scope: str | None = None) -> dict:
    """
    Ingest a chunk into the RAG vector store.
    Runs L1 scan, calculates instruction density, assigns trust score, signs it,
    and routes it into one of three tiers: quarantine / review / trusted.

    `scope`: "kb" (shared knowledge base, retrievable) or "session" (third-party content
    of one session, never retrievable, visible to that session's L4 only). Default:
    "session" for sources starting with "tool_response", else "kb" (B-1).
    """
    chunk_id = f"chk_{uuid.uuid4().hex[:8]}"

    # 1. L1 is scored LAZILY (2026-09-23, scratch/rca/LEDGER.md R-006): it only enters
    # the trust score on the legacy path. When the document-threat scorer handles the
    # text, running L1 anyway cost a full four-tier scan per document -- including a
    # hosted-judge call whenever the score landed in the judge band -- whose result was
    # stored in metadata and never used.
    l1_score: float | None = None

    # 2. Calculate instruction density
    density_score = calculate_instruction_density(text)

    # 3. Calculate Trust Score.
    #
    # The legacy composition is `1 - (0.6*density + 0.4*l1)`, whose two terms
    # measure the same property (both are instruction-shapedness — see
    # document_threat.py's module docstring). The rebuilt scorer replaces it with
    # Prompt Guard's non-benign mass, a document-local instruction-contrast term,
    # and a dangerous-code indicator. Measured on BIPIA: AUROC 0.7186 -> 0.9502.
    #
    # Falls back to the legacy composition when the new scorer is off OR when
    # Prompt Guard is unavailable, so a model-load failure degrades to previous
    # behaviour rather than scoring every document 0.
    import sentinel.config as _cfg

    threat_detail = None
    if getattr(_cfg, "L2_DOCUMENT_THREAT_SCORER", False):
        from .document_threat import document_threat_score

        threat_detail = document_threat_score(text)
    if (threat_detail is not None and threat_detail["available"]
            and threat_detail.get("bin") == "short"
            and getattr(_cfg, "L2_SHORT_DOC_JUDGE", False)
            and getattr(_cfg, "L1_LLM_JUDGE_ENABLED", False)):
        lo, hi = _cfg.L2_SHORT_DOC_JUDGE_BAND
        if lo < threat_detail["threat"] < hi:
            from sentinel.layers.layer1_llm_judge import llm_judge_check
            j = await llm_judge_check(text)
            threat_detail = {**threat_detail, "judge": j}
            if j is not None and j > threat_detail["threat"]:
                threat_detail["threat"] = float(j)
    if threat_detail is not None and threat_detail["available"]:
        trust_score = 1.0 - threat_detail["threat"]
    else:
        l1_score = (await layer1_check(text, harm_head=False)).score
        trust_score = _compute_trust_score(l1_score, density_score)
    _why = (f"L1={l1_score:.2f}, density={density_score:.2f}" if l1_score is not None
            else f"document_threat={threat_detail['threat']:.2f}")

    # 4. Sign chunk for provenance
    signature = sign_chunk(chunk_id, text)

    # 5. Compute embedding for semantic retrieval
    embedding = get_model().encode([text])[0].tolist()

    metadata = {
        "source": source,
        "trust_score": trust_score,
        "instruction_density": density_score,
        # Components of the rebuilt scorer, when it ran. Recorded so an artifact
        # says WHICH signal drove a decision instead of only the fused number.
        **({"document_threat": threat_detail} if threat_detail else {}),
        "l1_score": l1_score,
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

    # ROUTING BY THE AXIS'S OWN ANCHORS on the doc axis (R-013, 2026-09-23). The store's
    # REVIEW_THRESHOLD (trust 0.713 = threat 0.287) is a Youden point on the LEGACY axis
    # with FPR 0.2560 on BIPIA benign; measured, it held 31.7 % of benign BIPIA documents
    # out of retrieval while the reported L2 row sits at 4 %. On the doc axis a benign
    # code answer scores ~0.3-0.7, so that constant would have hidden ~46 % of them.
    # Doc-axis chunks therefore route exactly where L2 is measured: review at the bin's
    # WARN anchor, quarantine at its BLOCK anchor. The legacy axis keeps the old
    # constants -- sentinel_bench / SPLIT-Bench numbers depend on them -- and its
    # re-derivation is owed together with the legacy anchor (it reads judge-on L1).
    if threat_detail is not None and threat_detail["available"]:
        q_trust = 1.0 - _cfg.l2_block_threshold_for(metadata)
        r_trust = 1.0 - _cfg.l2_warn_threshold_for(metadata)
    else:
        q_trust, r_trust = QUARANTINE_THRESHOLD, REVIEW_THRESHOLD

    session_scoped = _is_session_scoped(source, scope)
    result["scope"] = "session" if session_scoped else "kb"
    if session_scoped:
        result["session_id"] = session_id

    if trust_score < q_trust:
        result["quarantined"] = True
        result["reason"] = (
            f"Quarantined: trust_score={trust_score:.2f} < {q_trust:.3f} "
            f"({_why})"
        )
        if session_scoped:
            _store_session_chunk(session_id, result)
        else:
            quarantine_store[chunk_id] = result
        return result

    if trust_score < r_trust:
        result["review_flagged"] = True
        result["reason"] = (
            f"Flagged for manual review: trust_score={trust_score:.2f} "
            f"is between {q_trust:.3f} and {r_trust:.3f} "
            f"({_why}). "
            f"Not eligible for retrieval until reviewed."
        )
        if session_scoped:
            _store_session_chunk(session_id, result)
        else:
            review_store[chunk_id] = result
        return result

    if session_scoped:
        result["reason"] = "Ingested as session-scoped third-party content (not retrievable)"
        _store_session_chunk(session_id, result)
        return result

    # trust_score >= REVIEW_THRESHOLD: eligible for retrieval
    collection[chunk_id] = result
    return result


def _store_session_chunk(session_id: str | None, result: dict) -> None:
    sid = session_id or _UNSCOPED
    bucket = session_chunks.get(sid)
    if bucket is None:
        bucket = {}
        session_chunks[sid] = bucket
    bucket[result["chunk_id"]] = result
    while len(bucket) > MAX_SESSION_CHUNKS:           # oldest first (dicts keep insertion order)
        bucket.pop(next(iter(bucket)))


def _strip(chunk):
    return {k: v for k, v in chunk.items() if k != "embedding"}


def get_all_chunks() -> list:
    """Return all active, review-flagged, and quarantined KNOWLEDGE-BASE chunks for the
    dashboard. Session-scoped tool outputs are deliberately excluded (B-1)."""
    active_chunks = [_strip(c) for c in collection.values()]
    review_chunks = [_strip(c) for c in review_store.values()]
    q_chunks = [_strip(c) for c in quarantine_store.values()]
    return active_chunks + review_chunks + q_chunks


def get_session_chunks(session_id: str | None) -> list:
    """This session's third-party content (tool outputs), all tiers."""
    bucket = session_chunks.get(session_id or _UNSCOPED) or {}
    return [_strip(c) for c in bucket.values()]


def get_chunks_for_provenance(session_id: str | None) -> list:
    """What L4 may trace a parameter against: the shared KB plus THIS session's own
    third-party content -- never another session's (B-1)."""
    return get_all_chunks() + get_session_chunks(session_id)


def retrieval_flagged(chunk: dict) -> bool:
    """ONE rule, shared by app.py and pipeline_sim, for whether a RETRIEVED chunk is
    flagged for L4 (B-2). Doc-axis chunks: failed HMAC, or re-validated at/above their
    own anchor (`blocked`). Legacy-axis chunks keep the published density > 0.6 rule
    (sentinel_bench / SPLIT-Bench numbers depend on it). The old code applied the legacy
    density rule to doc-axis chunks too -- the RCA-#3 axis error."""
    if not chunk.get("is_valid", True):
        return True
    if chunk.get("doc_axis"):
        return bool(chunk.get("blocked"))
    return chunk.get("current_density", 0) > 0.6


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


def retrieve_and_validate(query: str, top_k: int = 3, min_similarity: float | None = None) -> list:
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
    # RELEVANCE FLOOR (B-3). Top-k used to be returned whatever the similarity, so
    # unrelated KB chunks reached L4/L5 session state on every request. Default 0.0
    # (off) until the floor is derived on real query/document pairs -- turning it on
    # can drop a document a benchmark expects to be retrieved.
    if min_similarity is None:
        import sentinel.config as _c
        min_similarity = float(getattr(_c, "L2_RETRIEVAL_MIN_SIMILARITY", 0.0))
    results = [item for sim, item in scored[:top_k] if sim >= min_similarity]

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

        # RE-VALIDATION ON THE AXIS THE CHUNK WAS ADMITTED ON (R-014, 2026-09-24). This
        # compared instruction DENSITY against REVIEW_THRESHOLD, a TRUST cutoff on the
        # legacy axis -- two different quantities -- so a document the doc-axis scorer
        # admitted could be quarantined at retrieval by a number that never admitted it.
        # A valid signature means the text is byte-identical to what was scored at
        # ingest, so a doc-axis chunk is re-checked against its OWN stored threat and
        # anchor. Legacy chunks keep the old rule (published numbers depend on it).
        import sentinel.config as _cfg
        dt = metadata.get("document_threat") or {}
        doc_axis = bool(getattr(_cfg, "L2_DOCUMENT_THREAT_SCORER", False) and dt.get("available"))
        if doc_axis:
            over = dt["threat"] >= _cfg.l2_warn_threshold_for(metadata)
            if over:
                findings.append(f"Document threat {dt['threat']:.2f} at/above its anchor")
        else:
            over = density > REVIEW_THRESHOLD
            if over:
                findings.append(f"High instruction density detected: {density:.2f}")

        blocked = (not is_valid) or over

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
                "doc_axis": doc_axis,
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
            "doc_axis": doc_axis,
            "findings": findings,
            "blocked": False,
        })

    return validated_chunks


def reset_store():
    """Clear all in-memory RAG chunk stores. Called on /sentinel/reset."""
    collection.clear()
    review_store.clear()
    quarantine_store.clear()
    session_chunks.clear()
