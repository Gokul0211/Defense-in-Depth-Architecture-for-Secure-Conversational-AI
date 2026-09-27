import uuid
from datetime import datetime
from sentinel.core.threat_bus import threat_bus, SessionState
from sentinel.core.models import ThreatEvent
from sentinel.core.bounded_cache import BoundedLRUDict
from sentinel.core.taint_graph import build_session_taint_graph
from sentinel.config import MAX_TRACKED_SESSIONS

# Track which correlation rules have already fired per session to prevent
# double-fire. Key: session_id, Value: set of threat_types that already fired.
# Previously an unbounded plain dict — now LRU-bounded like the other
# session-keyed stores (see sentinel/core/bounded_cache.py).
_fired_rules: BoundedLRUDict[str, set[str]] = BoundedLRUDict(MAX_TRACKED_SESSIONS)

# The verdict each rule carries. ENFORCED since 2026-09-23 (scratch/rca/LEDGER.md R-002):
# before that, every call site ran `check_correlations` after the request's action was
# already fixed and ignored the outcome, so a "BLOCKED" rule changed nothing in the live
# app while `pipeline_sim` counted it as a BLOCK. `check_correlations` now RETURNS the
# rules newly fired by this call, a BLOCKED rule marks the session terminated, and the
# call sites escalate the pending request/response/tool call.
RULE_ACTIONS: dict[str, str] = {
    "SLOW_BURN_INJECTION": "BLOCKED",
    "RAG_PLUS_AGENT_ATTACK": "BLOCKED",
    "EXFIL_AFTER_PROBE": "BLOCKED",
    "TAINT_PATH_DETECTED": "WARNED",
}


def blocking_rules(fired: list[str] | None) -> list[str]:
    """The subset of `fired` whose verdict is BLOCKED."""
    return [r for r in (fired or []) if RULE_ACTIONS.get(r) == "BLOCKED"]


async def check_correlations(session_id: str, disabled_rules: frozenset[str] = frozenset()):
    """
    Evaluates cross-layer correlation rules against the current session state.
    Emits a CORRELATION ThreatEvent if any rules fire.
    Each rule fires at most once per session to prevent duplicate events.

    `disabled_rules`: rule names (e.g. "SLOW_BURN_INJECTION", "TAINT_PATH_DETECTED")
    to skip evaluating entirely, as if that rule didn't exist. This exists
    specifically to support leave-one-rule-out ablation studies (see
    sentinel/eval/ablation.py) — it runs the exact same production logic as
    a normal call, just with one rule's condition short-circuited to never
    fire, rather than a separate reimplementation that could drift from the
    real rule logic over time. Empty by default, so normal (non-ablation)
    callers are completely unaffected.
    """
    state = await threat_bus.get_session(session_id)
    if not state:
        return []

    # Initialise the fired set for this session if needed
    if session_id not in _fired_rules:
        _fired_rules[session_id] = set()
    fired = _fired_rules[session_id]
    already = set(fired)

    # RULE 1: SLOW_BURN_INJECTION
    # Condition: sustained L3 drift/escalation alongside elevated L1 injection
    # scores earlier in the same session.
    #
    # `state.l3_current` must be L3's RESCALED score (see
    # core/models.py's rescale_layer_score docstring, RCA #3) — on that
    # shared 0-1 WARN/BLOCK scale, 0.7 sits meaningfully between
    # WARN_THRESHOLD(0.50) and BLOCK_THRESHOLD(0.85). Every caller that
    # sets state.l3_current MUST rescale L3's raw score first (app.py
    # already does; pipeline_sim.py was fixed to do the same after this
    # was found to be the reason this rule never fired on real data —
    # comparing L3's raw, compressed score directly against 0.7 made the
    # condition structurally unreachable).
    # `state.l1_max` carries the SAME requirement as `l3_current`: it must be
    # L1's score RESCALED onto the shared WARN/BLOCK axis.
    #
    # BUG FIX (2026-09-19). This was previously unspecified, and the two
    # callers disagreed — which made these constants uninterpretable and the
    # eval harness's firing rates unrepresentative of production:
    #
    #   * `pipeline_sim` set `l1_max` to L1's RAW score every turn. On the raw
    #     axis 0.3 means shared 0.3416 and 0.5 means shared 0.5519, so both
    #     rules were stricter than the constants suggest.
    #   * production never set it directly at all. `threat_bus` updated it
    #     only when `event.layer == "L1"`, from `event.threat_score` — which
    #     app.py populates with `combined_score`, the max over ALL rescaled
    #     layers. So production's `l1_max` was "the combined score, on turns
    #     where L1 happened to dominate": neither L1-specific nor consistent.
    #
    # On the shared axis the constants read as intended: 0.3 is "L1 elevated
    # but below WARN(0.50)", and Rule 3's 0.5 is exactly "L1 crossed WARN".
    if "SLOW_BURN_INJECTION" not in fired and "SLOW_BURN_INJECTION" not in disabled_rules:
        if state.l3_current > 0.7 and getattr(state, 'l1_max', 0.0) > 0.3:
            fired.add("SLOW_BURN_INJECTION")
            await _emit_correlation(
                session_id=session_id,
                threat_type="SLOW_BURN_INJECTION",
                severity="CRITICAL",
                score=min(1.0, max(state.l3_current, state.l1_max) + 0.1),
                evidence="L3 semantic drift detected alongside elevated L1 injection scores.",
                action="BLOCKED"
            )
            # NOTE: deliberately no `return` here (bug fixed below — see
            # the note above Rule 2). Firing this rule must not prevent
            # Rules 2-4 from also being independently evaluated in the
            # same call.

    # RULE 2: RAG_PLUS_AGENT_ATTACK
    #
    # BUG FIX (deep RCA, found after the trust_threshold fix in
    # taint_graph.py's find_low_trust_high_impact_paths — verified
    # directly against synthetic data shaped like a real fired session —
    # STILL didn't make TAINT_PATH_DETECTED fire on real pipeline runs):
    # every rule below through Rule 4 used to `return` immediately after
    # firing. Since check_correlations is called exactly ONCE per session
    # in the eval harness (pipeline_sim.py, not per-turn), any session
    # where an earlier rule fired would never even reach Rule 4's code —
    # not a threshold problem, a control-flow bug. All four `return`
    # statements were removed so each rule is evaluated independently;
    # `fired.add(...)` (unchanged) still prevents any single rule from
    # firing twice. pipeline_sim.py's readback was updated to collect
    # every fired rule for a session instead of just the first.
    #
    # Condition: an L4 tool call whose parameters were actually traced back to
    # one of this session's flagged L2 chunks.
    #
    # Bug this fixes: the previous version fired whenever `l2_findings` was
    # non-empty AND *any* L4 call in the session had HIGH/CRITICAL risk with
    # SUSPICIOUS/CONTEXT_DERIVED authorization — with no check that the two
    # were actually related. Two unrelated events in the same session (an
    # unrelated poisoned chunk earlier, and an unrelated risky-but-legitimate
    # tool call later) would trip this rule and get reported as a single
    # correlated "RAG + agent" attack chain, which is a false correlation,
    # not a detection of the thing the rule is named after.
    #
    # This version requires the L4 result to specifically carry the
    # RAG_INJECTION threat class, which tool_auditor.py only assigns when it
    # has directly traced a tool-call parameter's text to a specific flagged
    # chunk (see layer4_agentic/tool_auditor.py's "Direct
    # Parameter-to-Flagged-Chunk Tracing" block) — i.e. an actual traced
    # link, not co-occurrence. A fuller graph-based version of this (tracing
    # arbitrary chains, not just this one hand-coded pattern) is the taint
    # propagation graph described in the research roadmap document.
    if "RAG_PLUS_AGENT_ATTACK" not in fired and "RAG_PLUS_AGENT_ATTACK" not in disabled_rules:
        l2_findings = getattr(state, 'l2_findings', [])
        l4_calls = getattr(state, 'l4_calls', [])

        if l2_findings and l4_calls:
            for call in l4_calls:
                # RAG_INJECTION: a parameter traced to a flagged chunk (both L4 paths).
                # AGENTIC_HIJACK with `named_in_untrusted`: the action policy's control-flow
                # injection (an unrequested action named in flagged content), 2026-09-25.
                if call.get('threat_class') == 'RAG_INJECTION' or (
                        call.get('threat_class') == 'AGENTIC_HIJACK'
                        and (call.get('action') or {}).get('named_in_untrusted')):
                    fired.add("RAG_PLUS_AGENT_ATTACK")
                    await _emit_correlation(
                        session_id=session_id,
                        threat_type="RAG_PLUS_AGENT_ATTACK",
                        severity="CRITICAL",
                        score=0.97,
                        evidence=f"Tool call '{call.get('tool_name')}' parameter directly traced to a flagged RAG chunk.",
                        action="BLOCKED"
                    )
                    break
            # NOTE: deliberately no `return` here — see the bug-fix note
            # above this rule. `break` above only stops iterating l4_calls
            # once one match is found (this rule itself still only fires
            # once, via fired.add); it does not skip Rules 3-4.

    # RULE 3: EXFIL_AFTER_PROBE
    # Condition: L1 EXTRACTION_PROBE (or L3 drift) AND L5 exfil > 0.5
    # (l3_current > 0.7 here has the same rescaled-scale requirement as
    # Rule 1 above — see that rule's comment.)
    if "EXFIL_AFTER_PROBE" not in fired and "EXFIL_AFTER_PROBE" not in disabled_rules:
        l5_scores = getattr(state, 'l5_scores', [])
        has_high_l5 = any(score > 0.5 for score in l5_scores)
        if (getattr(state, 'l1_max', 0.0) > 0.5 or getattr(state, 'l3_current', 0.0) > 0.7) and has_high_l5:
            fired.add("EXFIL_AFTER_PROBE")
            await _emit_correlation(
                session_id=session_id,
                threat_type="EXFIL_AFTER_PROBE",
                severity="CRITICAL",
                score=0.98,
                evidence="System prompt extraction attempt followed by high exfiltration score in response.",
                action="BLOCKED"
            )
            # NOTE: deliberately no `return` here — see the bug-fix note
            # above Rule 2.


    # RULE 4: TAINT_PATH_DETECTED (general cross-layer taint propagation)
    #
    # Rules 1-3 above are each a single hand-coded pattern — they can only
    # ever catch the specific attack chains someone thought to write an
    # IF-statement for. This rule instead builds the session's taint
    # propagation graph (see core/taint_graph.py) and asks a general
    # question: is there ANY path connecting a low-trust source (a turn with
    # an elevated L1 score, or a flagged RAG chunk) to a high-impact action
    # (a HIGH/CRITICAL-risk tool-call parameter), using the *continuous*
    # trust signal rather than a binary flagged/not-flagged gate?
    #
    # Concretely, this catches cases Rule 2 cannot represent: e.g. a turn
    # with an elevated-but-not-independently-blocked L1 score (say 0.65 —
    # under L1's own block threshold) whose text is later used, via a
    # confident fuzzy match, as a parameter to a CRITICAL-risk tool call.
    # L4's own scoring treats EXPLICIT_USER_REQUEST-sourced parameters as
    # clean regardless of how suspicious that source turn itself was, and
    # none of rules 1-3 represent "a moderately-suspicious turn directly
    # authorized a high-impact action" as a pattern at all. The taint graph
    # does, because it propagates the turn's own continuous trust score
    # rather than checking whether any single layer's binary threshold fired.
    #
    # Only session.l2_flagged_chunks (not every chunk the session has ever
    # touched) needs to feed the graph here: a chunk that was never flagged
    # is by construction high-trust, so it cannot be the upstream cause of a
    # low-trust finding — omitting it doesn't change what this query can
    # find, it just avoids passing in nodes that can never be interesting.
    if "TAINT_PATH_DETECTED" not in fired and "TAINT_PATH_DETECTED" not in disabled_rules:
        turn_provenance = getattr(state, 'turn_provenance', [])
        l4_calls = getattr(state, 'l4_calls', [])
        l2_flagged_chunks = getattr(state, 'l2_flagged_chunks', [])

        if turn_provenance and l4_calls:
            turns = [
                (t.get("turn_index", i), t.get("text", ""), t.get("l1_score", 0.0))
                for i, t in enumerate(turn_provenance)
            ]
            graph = build_session_taint_graph(
                turns=turns,
                l2_chunks=l2_flagged_chunks,
                l4_calls=l4_calls,
            )
            findings = graph.find_low_trust_high_impact_paths()
            if findings:
                fired.add("TAINT_PATH_DETECTED")
                worst = min(findings, key=lambda f: f.effective_trust)
                await _emit_correlation(
                    session_id=session_id,
                    threat_type="TAINT_PATH_DETECTED",
                    severity="HIGH",
                    score=min(1.0, 1.0 - worst.effective_trust + 0.1),
                    evidence=(
                        f"Taint path detected: {' -> '.join(worst.path)} "
                        f"(effective_trust={worst.effective_trust:.2f}, impact={worst.impact})"
                    ),
                    action="WARNED"
                )
                # No `return` needed — this is the last rule, but omitted
                # for consistency with Rules 1-3 above (see bug-fix note
                # at Rule 2).

    newly = sorted(set(fired) - already)
    blocking = blocking_rules(newly)
    if blocking and not getattr(state, "terminated", False):
        state.terminated = True
        state.termination_reason = "+".join(blocking)
    return newly


def reset_correlation_state():
    """Clear all fired-rule tracking — called on demo reset."""
    _fired_rules.clear()


async def _emit_correlation(session_id: str, threat_type: str, severity: str, score: float, evidence: str, action: str):
    """Helper to emit a correlation event."""
    event = ThreatEvent(
        event_id=f"evt_{uuid.uuid4().hex[:8]}",
        timestamp=datetime.now().strftime("%H:%M:%S"),
        session_id=session_id,
        layer="TIB",
        threat_type=threat_type,
        severity=severity,
        threat_score=min(1.0, score),
        action=action,
        evidence={"correlation_rule": threat_type, "details": evidence},
        explanation={
            "summary": evidence,
            "chain": [{
                "layer": "TIB",
                "finding": f"Correlation Rule {threat_type} triggered",
                "evidence": evidence,
                "action": action
            }]
        },
        note=evidence[:60]
    )
    await threat_bus.emit(event)
