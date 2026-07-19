from sentinel.core.models import L4Result
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
    if flagged_chunks:
        for param_name, param_val in parameters.items():
            param_str = str(param_val).lower()
            if len(param_str) < MIN_TRACEABLE_LEN:
                continue
            for chunk in flagged_chunks:
                chunk_text = (chunk.get('text') or '').lower()
                matched, ratio = fuzzy_contains(param_str, chunk_text)
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
                    )

    # 1. Base Risk Evaluation
    risk_level = evaluate_tool_risk(tool_name, parameters)
    base_score = risk_to_score(risk_level)
    
    # 2. Parameter Provenance
    provenance = trace_parameters(parameters, conversation_history)
    auth_source = determine_authorization(provenance)
    
    # 3. Reasoning Analysis
    reasoning_flags = parse_reasoning(reasoning_trace)
    
    # Calculate final score and decision
    final_score = base_score
    should_execute = True
    reasons = []
    
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
    )
