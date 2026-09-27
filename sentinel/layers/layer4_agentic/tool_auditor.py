from sentinel.core.models import L4Result
from sentinel.config import L4_DECISION_THRESHOLD
from .risk_matrix import evaluate_tool_risk, risk_to_score
from .provenance_tracker import trace_parameters, determine_authorization, fuzzy_contains, MIN_TRACEABLE_LEN
from .reasoning_parser import parse_reasoning

async def audit_tool_call(
    tool_name: str,
    parameters: dict,
    reasoning_trace: str | None,
    session_id: str,
    conversation_history: list[dict],
    flagged_chunks: list[dict] = None
) -> L4Result:
    """
    Main entry point for Layer 4. Audits a tool call before execution.
    """
    import sentinel.config as _cfg
    if getattr(_cfg, "L4_PROVENANCE_POLICY", "legacy") == "action":
        # Action authorisation (deep_rca.md §9): capability + requested-action + sink
        # provenance; replaces the ladder below entirely under this policy.
        from .action_policy import audit_action
        return await audit_action(tool_name, parameters, reasoning_trace, session_id,
                                  conversation_history, flagged_chunks=flagged_chunks)
    # Direct Parameter-to-Flagged-Chunk Tracing.
    #
    # This previously did an unguarded exact substring check
    # (`param_str in chunk_text`) with no minimum length — a short parameter
    # value like "1" or "usd" would spuriously substring-match almost any
    # chunk of text and trigger an immediate CRITICAL block with no real
    # basis. That's a bigger deal here than in the general provenance tracer
    # below: this path short-circuits straight to should_execute=False, and
    # (after the correlation engine fix) is the specific signal
    # RAG_PLUS_AGENT_ATTACK keys off. Reusing the same guarded fuzzy-match
    # helper as the general tracer keeps both paths' precision consistent.
    # `max_flagged_chunk_ratio` is tracked across the WHOLE scan, not only
    # on the branch that matches. That is the point: the gate at
    # FUZZY_MATCH_THRESHOLD (0.85) is a measured cliff — ratio 0.8630 is
    # CRITICAL and blocked, 0.8493 is LOW and executed, and everything from
    # 0.8493 down to 0.6575 behaves identically (scratch/probe_l4_cliff.py).
    # An attacker who paraphrases a payload one character past the gate
    # escapes, and the near-miss evidence used to vanish with them. It is
    # now reported so a consumer can weigh it, while the gate itself — and
    # therefore every calibrated L4 number — is left exactly as it was.
    max_flagged_chunk_ratio = 0.0
    if flagged_chunks:
        for param_name, param_val in parameters.items():
            param_str = str(param_val).lower()
            if len(param_str) < MIN_TRACEABLE_LEN:
                continue
            for chunk in flagged_chunks:
                chunk_text = (chunk.get('text') or '').lower()
                matched, ratio = fuzzy_contains(param_str, chunk_text)
                max_flagged_chunk_ratio = max(max_flagged_chunk_ratio, ratio)
                if matched:
                    return L4Result(
                        score=0.97,
                        threat_class="RAG_INJECTION",
                        authorization_source="SUSPICIOUS",
                        risk_level="CRITICAL",
                        should_execute=False,
                        reason=(
                            f"Parameter trace matched suspicious/flagged RAG chunk: "
                            f"'{chunk.get('chunk_id')}' (match_ratio={ratio:.2f})"
                        ),
                        provenance={
                            param_name: {
                                "source": "CONTEXT_DERIVED",
                                "confidence": ratio,
                                "details": f"Matched flagged chunk {chunk.get('chunk_id')} directly (ratio={ratio:.2f})",
                                "matched_turn_index": None,
                                "matched_chunk_id": chunk.get("chunk_id"),
                            }
                        },
                        max_flagged_chunk_ratio=max_flagged_chunk_ratio,
                        min_provenance_confidence=ratio,
                        # Computed, not hardcoded to 1.0. Pinning it would
                        # tie every blocked sample at the top of the scale
                        # — the same evidence-destroying quantisation this
                        # field was added to remove, just moved one branch
                        # over. A 0.999 match and a 0.851 match are not
                        # equally strong evidence even though both block.
                        confidence=_continuous_confidence(
                            risk_level="CRITICAL",
                            provenance={param_name: {"confidence": ratio}},
                            reasoning_flags=[],
                            max_flagged_chunk_ratio=max_flagged_chunk_ratio,
                        ),
                    )

    # 1. Base Risk Evaluation
    risk_level = evaluate_tool_risk(tool_name, parameters)
    base_score = risk_to_score(risk_level)
    
    # 2. Parameter Provenance
    provenance = trace_parameters(parameters, conversation_history, session_id=session_id)
    auth_source = determine_authorization(provenance)
    
    # 3. Reasoning Analysis
    reasoning_flags = parse_reasoning(reasoning_trace)
    
    # Calculate final score and decision
    final_score = base_score
    should_execute = True
    reasons = []
    
    if auth_source == "UNTRUSTED_SOURCE":
        # source_trust policy (fixing.md G): the parameter was copied from content L2
        # held for review or quarantined -- the same severity and gating the legacy
        # ladder gave to "untraceable", now given to the actual attack signature.
        final_score = max(final_score, 0.9)
        reasons.append("Parameter copied from untrusted (flagged) third-party content")
        if risk_level in ["HIGH", "CRITICAL"]:
            should_execute = False

    if auth_source == "AGENT_SYNTHESIZED":
        # source_trust policy: an id / date / URL the agent built from the request is
        # the most ordinary thing a tool-using agent does; it keeps the tool's base risk.
        reasons.append("Parameter synthesised by the agent (not traceable verbatim)")

    if auth_source == "SUSPICIOUS":
        final_score = max(final_score, 0.9)
        reasons.append("Unverified parameter provenance (possible hallucination/injection)")
        if risk_level in ["HIGH", "CRITICAL"]:
            should_execute = False
            
    if auth_source == "CONTEXT_DERIVED":
        final_score = max(final_score, 0.7)
        # We don't auto-block context derived, but we flag it for correlation engine
        reasons.append("Parameters derived from retrieved context")
        
    if reasoning_flags:
        final_score = max(final_score, 0.8)
        reasons.extend(reasoning_flags)
        should_execute = False

    # Additive ceiling (InjecAgent-calibrated) — on top of, not in place of,
    # the branch-specific should_execute rules above. Anything already
    # blocked above stays blocked; this only extends coverage to cases that
    # push final_score this high without tripping an existing branch.
    if final_score >= L4_DECISION_THRESHOLD:
        should_execute = False

    threat_class = "CLEAN"
    if not should_execute:
        threat_class = "AGENTIC_HIJACK"
    elif final_score >= 0.7:
        threat_class = "SUSPICIOUS_TOOL_CALL"
        
    reason_str = " | ".join(reasons) if reasons else f"Authorized via {auth_source}"

    return L4Result(
        score=final_score,
        threat_class=threat_class,
        authorization_source=auth_source,
        risk_level=risk_level,
        should_execute=should_execute,
        reason=reason_str,
        provenance=provenance,
        max_flagged_chunk_ratio=max_flagged_chunk_ratio,
        min_provenance_confidence=_min_provenance_confidence(provenance),
        confidence=_continuous_confidence(
            risk_level=risk_level,
            provenance=provenance,
            reasoning_flags=reasoning_flags,
            max_flagged_chunk_ratio=max_flagged_chunk_ratio,
        ),
    )


def _min_provenance_confidence(provenance: dict) -> float:
    """
    The least-trusted parameter's provenance confidence, or 1.0 when the
    call takes no parameters.

    `determine_authorization` collapses the same information into three
    strings, so a parameter matched at fuzzy ratio 0.86 and one matched
    exactly both read as EXPLICIT_USER_REQUEST downstream. The minimum is
    the right summary because L4's own escalation logic is already a
    worst-parameter rule: one UNCERTAIN parameter makes the whole call
    SUSPICIOUS.

    UNTRACEABLE parameters are SKIPPED (2026-09-20). A value that could not be
    traced because it is too short to trace carries no evidence, so letting its
    confidence enter this minimum would re-introduce through the
    continuous-confidence path exactly the defect `determine_authorization`'s
    docstring describes — a pagination integer driving the layer's evidence
    term. Skipping is correct rather than merely convenient: the quantity this
    function summarises is "how untrustworthy is the weakest thing we actually
    managed to trace".
    """
    from .provenance_tracker import SOURCE_UNTRACEABLE

    values = [
        p.get("confidence", 0.0)
        for p in provenance.values()
        if p.get("source") != SOURCE_UNTRACEABLE
    ]
    return min(values) if values else 1.0


def _evidence_terms(
    risk_level: str,
    provenance: dict,
    reasoning_flags: list,
    max_flagged_chunk_ratio: float,
) -> dict[str, float]:
    """L4's four evidence sources, each as a probability-like value in [0, 1)."""
    from sentinel.core.evidence import saturating_count

    return {
        "risk": risk_to_score(risk_level),
        # How untrustworthy the weakest parameter's provenance is.
        # Continuous via the fuzzy-match ratio (0.6 + 0.35*r) and the
        # matched chunk's trust score.
        "provenance": 1.0 - _min_provenance_confidence(provenance),
        # Saturating in the flag count: the first flag is most of the
        # evidence, later ones add less. Needs no fitted constants.
        "reasoning": saturating_count(len(reasoning_flags)),
        "flagged_chunk": max_flagged_chunk_ratio,
    }


def _continuous_confidence(
    risk_level: str,
    provenance: dict,
    reasoning_flags: list,
    max_flagged_chunk_ratio: float,
) -> float:
    """
    Noisy-OR over L4's four evidence sources, in [0, 1).

    Each source is independently sufficient to raise suspicion, which is
    exactly what noisy-OR encodes: 1 - prod(1 - e_i). It is monotone in
    every component, bounded, and — deliberately — carries NO fitted
    weights. Inventing per-source weights with no labelled corpus to fit
    them against would be the speculative tuning this project avoids; an
    unweighted noisy-OR is defensible on its structure alone, and because
    the components are also reported individually it can be replaced by a
    fitted combiner later without an interface change.

    ACCUMULATED IN LOG SPACE, WHICH IS NOT A DETAIL. Summing
    -log(1 - e_i) and squashing once at the end is algebraically identical
    to multiplying, but it keeps full floating-point resolution in the
    regime that matters here. Several components sit near 1.0 at once (a
    CRITICAL call with untraceable parameters), where the direct product
    collapses toward 0.0 and the returned confidence toward 1.0, ties
    included. The clamp at `_MAX_COMPONENT_EVIDENCE` bounds each term so
    no single saturated component can swallow the others.

    This is an ORDERING, not a calibrated probability of attack — claiming
    the latter would need a base rate the system cannot know. Because
    AUROC and every fusion rule downstream are rank-based, the remaining
    compression near 1.0 costs nothing: the ranking is exact.

    The aggregation itself now lives in `core.evidence.noisy_or`, shared
    with L5: both layers have the identical quantisation defect and the
    identical fix, so writing it twice would let the two drift.
    """
    from sentinel.core.evidence import noisy_or

    return noisy_or(
        _evidence_terms(risk_level, provenance, reasoning_flags, max_flagged_chunk_ratio)
    )
