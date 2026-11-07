import uuid
import numpy as np
from sklearn.metrics.pairwise import cosine_similarity
from .provenance import sign_chunk, verify_chunk, sign_record, verify_record
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
import sentinel.config as _cfg_store

# L2 review C9 (2026-10-28): the knowledge base had the SESSION cap (MAX_TRACKED_SESSIONS) and LRU eviction, so a client
# ingesting that many documents evicted the operator's real knowledge base (poisoning by displacement) and quarantined
# evidence aged out the same way. The stores keep their LRU type (the eval runner ingests one document per sample and
# relies on bounded memory), but sized by L2_KB_MAX_CHUNKS / L2_QUARANTINE_MAX_CHUNKS, and an EXTERNAL ingest
# (an operator or a public client, see ingest_chunk's `principal`) is refused when the knowledge base is full instead
# of evicting what is there. Internal callers (evaluations, demo scenarios) keep the bounded-LRU behaviour.
collection = BoundedLRUDict(_cfg_store.L2_KB_MAX_CHUNKS)          # eligible for retrieval
review_store = BoundedLRUDict(_cfg_store.L2_KB_MAX_CHUNKS)        # held for human review, NOT retrievable
quarantine_store = BoundedLRUDict(_cfg_store.L2_QUARANTINE_MAX_CHUNKS)    # quarantined, or failed re-validation

# Knowledge-base chunks ingested per external principal (C9 quota). Public principals are keyed by client address in
# the app; the address is never stored in a chunk's metadata.
_principal_counts: dict[str, int] = {}
# Exact-duplicate registry for the shared KB (L2 review C15): normalized-text digest -> chunk_id.
_kb_digests: dict[str, str] = {}


def _norm_digest(text: str) -> str:
    import hashlib
    import re as _re
    return hashlib.sha256(_re.sub(r"\s+", " ", (text or "").strip().lower()).encode("utf-8", "surrogatepass")).hexdigest()


def scorer_version() -> str:
    """Identifier of the L2 scoring configuration a verdict was produced under (L2 review C10). A chunk whose stored
    version differs is re-scored at retrieval instead of keeping a verdict from older detectors or anchors."""
    import hashlib
    import sentinel.config as cfg
    keys = ("L2_DOCUMENT_THREAT_SCORER", "L2_SHORT_DOC_SCORER", "L2_DANGER_CREDENTIAL_STRICT", "L2_STRICT_CODE_DETECTION",
            "L2_CODE_PROSE_SPLIT", "L2_CODE_PROSE_WARN", "L2_CODE_PROSE_BLOCK", "L2_DOCUMENT_THREAT_WARN_THRESHOLD",
            "L2_DOCUMENT_THREAT_WARN_THRESHOLD_CODE", "L2_DOCUMENT_THREAT_BLOCK_THRESHOLD_CODE",
            "L2_DOCUMENT_THREAT_WARN_THRESHOLD_SHORT", "L2_DOCUMENT_THREAT_BLOCK_THRESHOLD_SHORT", "L2_BLOCK_THRESHOLD",
            "L2_SPOOF_MARKERS", "L2_ADR", "L2_CODE_INCOHERENCE", "L2_CODE_INCOHERENCE_TAU", "L2_SHORT_BIN_BY_SOURCE",
            "L2_SHORT_DOC_WARN", "L2_UNHIDE", "L2_HIDDEN_CHARS_ACTION", "L2_KAD", "L2_DOC_PROSE_BLOCK_DERIVED")
    raw = "|".join(f"{k}={getattr(cfg, k, None)!r}" for k in keys) + "|code=2026-10-28"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _find_kb_chunk(chunk_id: str):
    for store in (collection, review_store, quarantine_store):
        if chunk_id in store:
            return store[chunk_id]
    return None


class IngestRefused(Exception):
    """An external ingest that must not proceed: `status` is the HTTP status the API should return."""

    def __init__(self, status: int, reason: str):
        super().__init__(reason)
        self.status, self.reason = status, reason


def _principal_tier(principal: str | None) -> str:
    if principal is None:
        return "internal"
    return "operator" if principal == "operator" else "public"


def _admit_external(text: str, principal: str | None, session_scoped: bool) -> None:
    """C8 / C9 gates for one ingest; raises IngestRefused. Internal callers (principal None) only meet the size cap."""
    import sentinel.config as cfg
    cap = int(getattr(cfg, "L2_MAX_DOC_CHARS", 0) or 0)
    if cap and len(text or "") > cap:
        raise IngestRefused(413, f"document too large ({len(text)} chars > {cap})")
    if principal is None or session_scoped:
        return
    if len(collection) + len(review_store) >= int(cfg.L2_KB_MAX_CHUNKS):
        raise IngestRefused(507, "knowledge base is full; an operator must remove documents first")
    if principal != "operator":
        quota = int(getattr(cfg, "L2_KB_QUOTA_PER_PRINCIPAL", 0) or 0)
        if quota and _principal_counts.get(principal, 0) >= quota:
            raise IngestRefused(429, f"ingest quota reached ({quota} documents for this client)")

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
                       scope: str | None = None, principal: str | None = None) -> dict:
    """
    Ingest a chunk into the RAG vector store.
    Runs L1 scan, calculates instruction density, assigns trust score, signs it,
    and routes it into one of three tiers: quarantine / review / trusted.

    `scope`: "kb" (shared knowledge base, retrievable) or "session" (third-party content
    of one session, never retrievable, visible to that session's L4 only). Default:
    "session" for sources starting with "tool_response", else "kb" (B-1).

    `principal` (L2 review C8 / C9): None for internal callers (evaluations, the proxy's tool outputs, demo
    scenarios); "operator" or a public-client key for the RAG API. External ingests meet the size cap, the
    knowledge-base capacity check and (public only) the per-client quota; refusals raise IngestRefused.
    """
    _admit_external(text, principal, _is_session_scoped(source, scope))
    import sentinel.config as _cfgd
    if getattr(_cfgd, "L2_DEDUPE", True) and not _is_session_scoped(source, scope):
        # L2 review C15: the same document ingested again returns the stored verdict instead of a second copy (copies
        # could fill the whole top-k, the PoisonedRAG pattern). The first ingest's source is kept.
        prev_id = _kb_digests.get(_norm_digest(text))
        prev = _find_kb_chunk(prev_id) if prev_id else None
        if prev is not None and (prev.get("metadata") or {}).get("scorer_version") == scorer_version():
            return {**_strip(prev), "duplicate_of": prev_id, "reason": f"Duplicate of {prev_id}: {prev['reason']}"}
        if prev is not None:
            # A verdict made under another scoring configuration is not reused (the C10 rule): the stale copy is
            # removed and the document is scored again below.
            for store in (collection, review_store, quarantine_store):
                store.pop(prev_id, None)
    chunk_id = f"chk_{uuid.uuid4().hex[:8]}"

    # L2 review N8 (L2_DETECT_REMOVE, off): an LLM detector quotes the injection and it is removed by fuzzy match;
    # "remove" ingests the sanitized text and keeps the original as quarantined evidence, "report" only records it.
    llm_meta = {}
    _dr_mode = getattr(_cfgd, "L2_DETECT_REMOVE", "off")
    _dr_hold = False
    if _dr_mode in ("report", "review", "remove") and not _is_session_scoped(source, scope):
        from .llm_checks import detect_and_remove
        dr = await detect_and_remove(text)
        if dr is not None:
            llm_meta["detect_remove"] = {"injected": dr["injected"],
                                         "removed_chars": len(text) - len(dr["sanitized"])}
            if dr["injected"] and _dr_mode == "remove" and dr["sanitized"] != text and dr["sanitized"].strip():
                ev = quarantine_text(text, source, "Original of a document an LLM detector sanitized (injection "
                                                   "removed before ingest)")
                llm_meta["detect_remove"]["original_quarantined"] = ev["chunk_id"]
                text = dr["sanitized"]
            elif dr["injected"] and _dr_mode in ("review", "remove"):
                # "review": a detected injection holds the document for an operator (measured, r08: 37 / 37 DIDA
                # poisoned documents, 0 / 278 benign incl. corporate notices and instructional text). "remove" falls
                # back to the same hold when the quoted injection could not be removed.
                _dr_hold = True

    # L2 redesign (L2_LOCAL_DETECTOR, off | report | review | authoritative; scratch/rca/l2/L2_REDESIGN.md): the LOCAL
    # model reads the document under a document policy and a residual-stream probe (BIPIA TRAIN only, threshold from
    # held-out benign documents) decides -- the N8 reading without a hosted call. "review" holds a detected document for
    # an operator exactly like the N8 hold, ON TOP of the shipped scorers; "report" only records the score.
    # "authoritative": when the detector answers, ITS decision replaces the soft document-threat verdict (applied below,
    # once the bin's anchors are known); the high-precision checks after it (control-channel spoofing, hidden text,
    # known-answer) still apply. Why: the shipped soft scorer's WARN anchors are its alpha-0.05 bin anchors, so a union
    # with the alpha-0.01 detector cannot meet a ~1 % budget -- measured end to end on BIPIA t5, "review" 0.983 recall
    # at 12.2 % false positives on pasted passages, 11.5 % of them the shipped scorer's own (results.md §20.8).
    _ld_mode = getattr(_cfgd, "L2_LOCAL_DETECTOR", "off")
    _ld_tool = _is_session_scoped(source, scope)
    ld = None
    if (_ld_mode in ("report", "review", "authoritative")
            and (not _ld_tool or getattr(_cfgd, "L2_LOCAL_DETECTOR_TOOLS", False))):
        import asyncio
        from sentinel.core.model_executor import run_model     # reused pool: no leaked OpenMP teams (§21.5)
        from .local_detector import local_doc_read
        ld = await run_model(local_doc_read, text, _ld_tool)
        if ld is not None:
            llm_meta["local_detector"] = {"bin": ld["bin"], "score": round(ld["score"], 4), "tau": round(ld["tau"], 4),
                                          "fired": ld["fired"]}
            if ld["fired"] and _ld_mode == "review":
                _dr_hold = True

    # 1. L1 is scored LAZILY (2026-09-23, scratch/rca/LEDGER.md R-006): it only enters
    # the trust score on the legacy path. When the document-threat scorer handles the
    # text, running L1 anyway cost a full four-tier scan per document -- including a
    # hosted-judge call whenever the score landed in the judge band -- whose result was
    # stored in metadata and never used.
    l1_score: float | None = None

    # L2 D3 (config.L2_SKIP_SOFT_WHEN_AUTHORITATIVE; scratch/rca/l2/l2p60 profile: Prompt Guard's document-threat scorer
    # was 65 % and instruction density 13 % of the ingest time). In "authoritative" mode the detector's decision REPLACES
    # the soft verdict and the anchors depend only on the bin (content type), so for a full-length document the
    # detector answered, the soft scorers are skipped: same bin, same anchors, same trust score and routing.
    # Short documents keep their own path (cheap, and their bin depends on it).
    from .document_threat import _MIN_DOC_CHARS
    _skip_soft = (_ld_mode == "authoritative" and ld is not None and len(text) >= _MIN_DOC_CHARS
                  and getattr(_cfgd, "L2_SKIP_SOFT_WHEN_AUTHORITATIVE", False))

    # 2. Calculate instruction density
    # L2 review C8: model work runs in a worker thread (L2_SCORE_IN_THREAD), so a long document no longer blocks the
    # event loop -- and with it every other request -- while it is scored.
    density_score = None if _skip_soft else await _run_scoring(calculate_instruction_density, text)

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
    if _skip_soft and getattr(_cfg, "L2_DOCUMENT_THREAT_SCORER", False):
        from sentinel.core.content_type import detect_content_type as _dct
        threat_detail = {"threat": 0.0, "available": True, "content_type": str(_dct(text)),
                         "soft_scorer": "skipped: the authoritative local detector answered (L2 D3)"}
    elif getattr(_cfg, "L2_DOCUMENT_THREAT_SCORER", False):
        from .document_threat import document_threat_score

        if getattr(_cfg, "L2_SHORT_BIN_BY_SOURCE", False):
            # L2 review I12: the short bin is chosen by source (tool output vs KB document).
            _kind = "tool" if _is_session_scoped(source, scope) else "doc"
            threat_detail = await _run_scoring(lambda t: document_threat_score(t, source_kind=_kind), text)
        else:
            threat_detail = await _run_scoring(document_threat_score, text)
    # L2 review C14 / N5 (L2_UNHIDE, off): the classifiers read raw text, so Unicode tag characters, variation-selector
    # payloads, bidi / invisible characters and spaced-out letters reached them unchanged. When the unhide view
    # (text_canonicalize.unhide, the same view L1 uses) differs, it is scored too and the higher threat stands.
    if (threat_detail is not None and threat_detail["available"] and getattr(_cfg, "L2_UNHIDE", False) and not _skip_soft):
        from sentinel.core.text_canonicalize import unhide
        from .document_threat import document_threat_score as _dts
        _u = unhide(text)
        if _u != text:
            _kind2 = "tool" if _is_session_scoped(source, scope) else "doc"
            _alt = await _run_scoring(
                (lambda t: _dts(t, source_kind=_kind2)) if getattr(_cfg, "L2_SHORT_BIN_BY_SOURCE", False) else _dts,
                _u)
            if _alt.get("available") and _alt["threat"] > threat_detail["threat"]:
                threat_detail = {**_alt, "raw_view_threat": threat_detail["threat"], "view": "unhide"}
    if (threat_detail is not None and threat_detail["available"]
            and str(threat_detail.get("bin", "")).startswith("short")
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
    embedding = (await _run_scoring(lambda t: get_model().encode([t])[0], text)).tolist()

    metadata = {
        "source": source,
        "ingested_by": _principal_tier(principal),
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

    # L2_LOCAL_DETECTOR="authoritative" (see the detector block above): the detector's decision, mapped monotonically
    # onto this bin's axis, replaces the soft verdict. Fired -> between the bin's review and quarantine cuts (held for
    # an operator, never quarantined by this signal alone); clear -> below the review cut. The soft score is kept as
    # base_threat for audit. No answer from the detector (no GPU / weights / artifact) -> the soft verdict stands.
    if _ld_mode == "authoritative" and ld is not None:
        import math
        r_thr, q_thr = 1.0 - r_trust, 1.0 - q_trust
        _m = ld["score"] - ld["tau"]
        if ld["fired"]:                              # _m > 0: strictly above the review cut, below the quarantine cut
            a_thr = r_thr + 1e-6 + max(0.0, q_thr - r_thr - 2e-6) * (1.0 - math.exp(-_m))
        else:
            a_thr = max(0.0, r_thr * math.exp(min(_m, 0.0)) - 1e-6)
        if threat_detail is not None and threat_detail.get("available"):
            threat_detail.setdefault("base_threat", threat_detail["threat"])
            threat_detail["threat"] = a_thr
        trust_score = 1.0 - a_thr
        metadata["trust_score"] = trust_score
        _why = (f"local detector {'fired' if ld['fired'] else 'clear'} (score {ld['score']:.2f}, tau {ld['tau']:.2f}, "
                f"authoritative); {_why}")

    # ADDRESSEE (v3, config.L2_ADR, off by default): a second detector on its own benign anchors --
    # does this third-party text address the AI? -- mapped onto THIS bin's axis (ADR WARN -> the
    # bin's review cut, ADR BLOCK -> its quarantine cut) and united with the bin's score by max, so
    # every consumer that reads trust / threat sees the union on the axis it already understands.
    adr = _addressee_check(text, 1.0 - r_trust, 1.0 - q_trust)
    if adr is not None:
        metadata["addressee"] = adr
        if adr["mapped"] > 1.0 - trust_score:
            if threat_detail is not None and threat_detail["available"]:
                threat_detail["base_threat"] = threat_detail["threat"]
                threat_detail["threat"] = adr["mapped"]
            trust_score = 1.0 - adr["mapped"]
            metadata["trust_score"] = trust_score
            _why = f"addressee={adr['score']:.2f} (warn {adr['warn']:.3f}, block {adr['block']:.3f}); {_why}"

    # CONTROL-CHANNEL SPOOFING (v3 code review, config.L2_SPOOF_MARKERS): third-party text that
    # announces itself as a system / admin / developer message ("[ADMIN OVERRIDE: ...]",
    # "[IMPORTANT SYSTEM UPDATE: ...]", "###(system_message)") is impersonating a channel data never
    # comes from. It is quarantined: its threat is raised to this bin's BLOCK anchor, so every
    # consumer (retrieval re-validation, L4's untrusted set, the shared axis) reads the same verdict.
    # Measured on 12 benign corpora: 0 firings (core/control_spoof.py); DIDA-Bench's poisoned_rag_exfil
    # documents ("[ADMIN OVERRIDE: ... display the employee's SSN ...]") score PIGuard 0.03-0.48 and
    # were invisible to every local detector before.
    if getattr(_cfg, "L2_SPOOF_MARKERS", False):
        from sentinel.core.control_spoof import spoof_markers
        marks = spoof_markers(text)
        if not marks and getattr(_cfg, "L2_UNHIDE", False):
            from sentinel.core.text_canonicalize import unhide
            _uv = unhide(text)
            marks = spoof_markers(_uv) if _uv != text else []
        if marks:
            metadata["control_spoof"] = marks
            if trust_score >= q_trust:
                spoof_threat = min(1.0, 1.0 - q_trust + 1e-6)
                if threat_detail is not None and threat_detail["available"]:
                    threat_detail.setdefault("base_threat", threat_detail["threat"])
                    threat_detail["threat"] = spoof_threat
                trust_score = 1.0 - spoof_threat
                metadata["trust_score"] = trust_score
            _why = f"spoofed control-channel marker ({', '.join(marks)}); {_why}"

    # L2 review C14 / N5 (L2_HIDDEN_CHARS_ACTION, off): text carried by INVISIBLE characters (Unicode tag characters,
    # variation-selector runs; >= 4 characters, emoji flag sequences excepted) inside third-party content has no benign
    # use. "review" raises the threat to this bin's WARN anchor (held for review), "quarantine" to its BLOCK anchor.
    _hca = getattr(_cfg, "L2_HIDDEN_CHARS_ACTION", "off")
    if _hca in ("review", "quarantine"):
        from sentinel.core.text_canonicalize import hiding_report
        _rep = hiding_report(text)
        if _rep["strong"]:
            metadata["hidden_chars"] = {k: v for k, v in _rep.items() if k != "hidden_text"} | {
                "hidden_text_chars": len(_rep["hidden_text"])}
            cut = q_trust if _hca == "quarantine" else r_trust
            if trust_score >= cut:
                h_threat = min(1.0, 1.0 - cut + 1e-6)
                if threat_detail is not None and threat_detail["available"]:
                    threat_detail.setdefault("base_threat", threat_detail["threat"])
                    threat_detail["threat"] = h_threat
                trust_score = 1.0 - h_threat
                metadata["trust_score"] = trust_score
            _why = f"text hidden in invisible characters ({len(_rep['hidden_text'])} chars); {_why}"

    # L2 review N2 (L2_KAD: off | kb | all): known-answer detection -- does the document stop a model from repeating a
    # fresh key? A contaminated result lifts the threat to this bin's WARN anchor (held for review): behavioural
    # evidence of a hijack, but not proof (adaptive attacks and refusals exist), so never a quarantine on its own.
    _kad = getattr(_cfg, "L2_KAD", "off")
    if _kad == "all" or (_kad == "kb" and not _is_session_scoped(source, scope)):
        from .llm_checks import known_answer_check
        k = await known_answer_check(text)
        if k is not None:
            llm_meta["kad"] = k
            if k["contaminated"] and trust_score >= r_trust:
                k_threat = min(1.0, 1.0 - r_trust + 1e-6)
                if threat_detail is not None and threat_detail["available"]:
                    threat_detail.setdefault("base_threat", threat_detail["threat"])
                    threat_detail["threat"] = k_threat
                trust_score = 1.0 - k_threat
                metadata["trust_score"] = trust_score
                _why = f"known-answer check: the document overrode a repeat instruction; {_why}"
    if _dr_hold and trust_score >= r_trust:
        h_threat = min(1.0, 1.0 - r_trust + 1e-6)
        if threat_detail is not None and threat_detail["available"]:
            threat_detail.setdefault("base_threat", threat_detail["threat"])
            threat_detail["threat"] = h_threat
        trust_score = 1.0 - h_threat
        metadata["trust_score"] = trust_score
        _why = f"LLM detector: the document contains an instruction aimed at an AI; {_why}"
    if llm_meta:
        metadata.update(llm_meta)

    # L2 review N6 (L2_PUBLIC_KB_POLICY): "review" holds every PUBLIC (non-operator) knowledge-base document for an
    # operator's release, whatever its score -- source trust as an enforced attribute, not a free-text label.
    if (getattr(_cfg, "L2_PUBLIC_KB_POLICY", "shared") == "review" and _principal_tier(principal) == "public"
            and not _is_session_scoped(source, scope) and trust_score >= q_trust):
        metadata["held_by_policy"] = "public_kb_review"
        _why = f"public knowledge-base documents need operator release; {_why}"

    # L2 review C10 / C11: the verdict is final here -- record the scorer version and sign the whole record.
    metadata["scorer_version"] = scorer_version()
    if getattr(_cfg, "L2_SIGN_RECORD", True):
        metadata["record_signature"] = sign_record(chunk_id, text, metadata, embedding)

    session_scoped = _is_session_scoped(source, scope)
    result["scope"] = "session" if session_scoped else "kb"
    if not session_scoped:
        _kb_digests[_norm_digest(text)] = chunk_id
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
            _count_principal(principal)
        return result

    if trust_score < r_trust or metadata.get("held_by_policy"):
        result["review_flagged"] = True
        result["reason"] = (
            f"Flagged for manual review: trust_score={trust_score:.2f} "
            + (f"is between {q_trust:.3f} and {r_trust:.3f} " if trust_score < r_trust else "(held by policy) ")
            + f"({_why}). "
            f"Not eligible for retrieval until reviewed."
        )
        if session_scoped:
            _store_session_chunk(session_id, result)
        else:
            review_store[chunk_id] = result
            _count_principal(principal)
        return result

    if session_scoped:
        result["reason"] = "Ingested as session-scoped third-party content (not retrievable)"
        _store_session_chunk(session_id, result)
        return result

    # trust_score >= REVIEW_THRESHOLD: eligible for retrieval
    collection[chunk_id] = result
    _count_principal(principal)
    return result


def _count_principal(principal: str | None) -> None:
    if principal is not None and principal != "operator":
        _principal_counts[principal] = _principal_counts.get(principal, 0) + 1


async def _run_scoring(fn, text):
    import sentinel.config as cfg
    if getattr(cfg, "L2_SCORE_IN_THREAD", True):
        from sentinel.core.model_executor import run_model     # reused pool: no leaked OpenMP teams (§21.5)
        return await run_model(fn, text)
    return fn(text)


def _map_onto_bin(a: float, a_warn: float, a_block: float, b_warn: float, b_block: float) -> float:
    """Strictly monotone piecewise-linear map of an ADR score onto a bin's threat axis:
    0 -> 0, a_warn -> b_warn, a_block -> b_block, 1 -> 1 (AUROC-invariant, moves only the
    operating point -- the same discipline as core.models.rescale_layer_score)."""
    a = max(0.0, min(1.0, float(a)))
    if a <= a_warn:
        return 0.0 if a_warn <= 0 else a / a_warn * b_warn
    if a <= a_block:
        return b_warn + (a - a_warn) / max(1e-9, a_block - a_warn) * (b_block - b_warn)
    return b_block + (a - a_block) / max(1e-9, 1.0 - a_block) * (1.0 - b_block)


def _addressee_check(text: str, bin_warn: float, bin_block: float) -> dict | None:
    """ADR on this chunk (config.L2_ADR), or None when off, unanchored or unavailable."""
    import sentinel.config as cfg

    mode = getattr(cfg, "L2_ADR", "off")
    warn, block = getattr(cfg, "L2_ADR_WARN_THRESHOLD", None), getattr(cfg, "L2_ADR_BLOCK_THRESHOLD", None)
    if mode == "off" or warn is None or block is None:
        return None
    if mode == "short" and len(text or "") >= 600:
        return None
    from sentinel.core import addressee_model
    r = addressee_model.score_text(text)
    if r is None:
        return None
    block = max(block, warn + 1e-6)
    return {"score": r["score"], "window": (r.get("window") or "")[:240], "warn": warn, "block": block,
            "mapped": _map_onto_bin(r["score"], warn, block, bin_warn, max(bin_block, bin_warn + 1e-6))}


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


def review_chunk(chunk_id: str, decision: str, note: str = "") -> dict | None:
    """
    L2 review C5: the human-review step that "review_flagged" always promised and nothing implemented. A held chunk
    used to stay in `review_store` forever -- never retrievable, i.e. review was quarantine under another name, and the
    prose bin's alpha-0.05 anchor holds ~5 % of benign prose documents there by design.

    decision "release": the chunk becomes retrievable (moved to `collection`); its verdict, signature and text are
    unchanged, and the release is recorded in metadata["review"] (who decided is the caller's audit concern).
    decision "reject": the chunk is quarantined. Returns the chunk (stripped of its embedding) or None if it is not
    held for review.
    """
    if decision not in ("release", "reject"):
        raise ValueError("decision must be 'release' or 'reject'")
    if chunk_id not in review_store:
        return None
    chunk = review_store.pop(chunk_id)
    import time as _t
    chunk["metadata"]["review"] = {"decision": decision, "note": str(note)[:500],
                                   "at": _t.strftime("%Y-%m-%dT%H:%M:%S")}
    chunk["review_flagged"] = False
    if decision == "release":
        chunk["quarantined"] = False
        chunk["reason"] = "Released by an operator after review"
        collection[chunk_id] = chunk
    else:
        chunk["quarantined"] = True
        chunk["reason"] = "Rejected by an operator after review"
        quarantine_store[chunk_id] = chunk
    return _strip(chunk)


def quarantine_text(text: str, source: str, reason: str) -> dict:
    """Store `text` directly in quarantine, unscored (evidence, never retrievable) -- e.g. text a PDF hides from its
    reader (L2 review N1). Signed like any chunk so the evidence itself is tamper-evident."""
    chunk_id = f"chk_{uuid.uuid4().hex[:8]}"
    metadata = {"source": source, "ingested_by": "internal", "trust_score": 0.0,
                "signature": sign_chunk(chunk_id, text), "scorer_version": scorer_version()}
    result = {"chunk_id": chunk_id, "text": text, "metadata": metadata, "embedding": None, "quarantined": True,
              "review_flagged": False, "reason": reason, "scope": "kb"}
    quarantine_store[chunk_id] = result
    return _strip(result)


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


def _diverse_top_k(ranked: list, top_k: int) -> tuple[list, dict]:
    """
    L2 review N3 (config.L2_RETRIEVAL_DIVERSITY, off until measured): knowledge-corruption attacks (PoisonedRAG) inject
    several near-identical passages crafted to win retrieval for a target question, so that they fill the whole
    context and outvote the true passage. Two cheap, model-free rules over the ranked candidates:

      * near-duplicate cluster: candidates whose embeddings are within cosine L2_DUP_COSINE of an already-picked one
        are skipped (one representative per cluster), and a cluster of >= L2_DUP_CLUSTER_MIN members is reported on the
        representative -- the clustering idea of TrustRAG's first stage (arXiv 2501.00879), in its simplest form;
      * source diversity: at most L2_MAX_PER_SOURCE picks per declared source.

    Returns (picked [(sim, chunk)], {chunk_id: note}). Deliberately not a verdict: a flagged cluster is evidence for
    the operator and the pipeline, the documents themselves are not quarantined by this rule.
    """
    import sentinel.config as cfg
    dup_cos = float(getattr(cfg, "L2_DUP_COSINE", 0.95))
    min_cluster = int(getattr(cfg, "L2_DUP_CLUSTER_MIN", 3))
    per_source = int(getattr(cfg, "L2_MAX_PER_SOURCE", 1))
    pool = ranked[:max(top_k * 5, top_k)]
    picked, members, by_source = [], {}, {}
    for sim, item in pool:
        emb = np.asarray(item.get("embedding") or [], dtype=float)
        dup_of = None
        for _, p in picked:
            pe = np.asarray(p.get("embedding") or [], dtype=float)
            if emb.size and pe.size == emb.size:
                c = float(emb @ pe / ((np.linalg.norm(emb) * np.linalg.norm(pe)) or 1.0))
                if c >= dup_cos:
                    dup_of = p["chunk_id"]
                    break
        if dup_of is not None:
            members[dup_of] = members.get(dup_of, 1) + 1
            continue
        src = str((item.get("metadata") or {}).get("source", ""))
        if per_source > 0 and by_source.get(src, 0) >= per_source:
            continue
        if len(picked) < top_k:
            picked.append((sim, item))
            by_source[src] = by_source.get(src, 0) + 1
            members.setdefault(item["chunk_id"], 1)
    notes = {cid: f"near-duplicate cluster of {n} candidate passages (possible knowledge-corruption flood)"
             for cid, n in members.items() if n >= min_cluster}
    return picked, notes


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
    cluster_notes: dict[str, str] = {}
    import sentinel.config as _cd
    if getattr(_cd, "L2_RETRIEVAL_DIVERSITY", False):
        picked, cluster_notes = _diverse_top_k([(s, i) for s, i in scored if s >= min_similarity], top_k)
        results = picked
    else:
        results = [(sim, item) for sim, item in scored[:top_k] if sim >= min_similarity]

    validated_chunks = []

    for similarity, chunk_data in results:
        chunk_id = chunk_data["chunk_id"]
        text = chunk_data["text"]
        metadata = chunk_data["metadata"]

        is_valid = verify_chunk(chunk_id, text, metadata.get("signature", ""))
        findings = [cluster_notes[chunk_id]] if chunk_id in cluster_notes else []
        if not is_valid:
            findings.append("HMAC signature mismatch - possible tampering")
        elif metadata.get("record_signature") and not verify_record(
                chunk_id, text, metadata, chunk_data.get("embedding"), metadata["record_signature"]):
            # L2 review C11: the verdict, source or embedding was edited after ingest.
            is_valid = False
            findings.append("Record signature mismatch - stored verdict, source or embedding changed")

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
        if (doc_axis and is_valid and getattr(_cfg, "L2_RESCAN_ON_VERSION", True)
                and metadata.get("scorer_version") != scorer_version()):
            # L2 review C10: admitted under another scoring configuration -> re-score once with the current one.
            from .document_threat import document_threat_score
            fresh = document_threat_score(text)
            if fresh.get("available"):
                metadata["document_threat"] = fresh
                metadata["trust_score"] = 1.0 - fresh["threat"]
                metadata["scorer_version"] = scorer_version()
                if metadata.get("record_signature"):
                    metadata["record_signature"] = sign_record(chunk_id, text, metadata, chunk_data.get("embedding"))
                dt = fresh
                findings.append("Re-scored under the current L2 configuration")
        # L2 review C10: instruction density is only the legacy axis's rule; the doc axis never used it here.
        density = calculate_instruction_density(text) if not doc_axis else None
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
                "similarity": similarity,
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
            "similarity": similarity,
        })

    return validated_chunks


def reset_store():
    """Clear all in-memory RAG chunk stores. Called on /sentinel/reset."""
    collection.clear()
    review_store.clear()
    quarantine_store.clear()
    session_chunks.clear()
    _principal_counts.clear()
    _kb_digests.clear()
