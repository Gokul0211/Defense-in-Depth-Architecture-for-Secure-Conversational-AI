"""
Tests for the taint propagation graph (Contribution A).

Three layers of testing, matching how the roadmap doc says this should be
validated:
  1. Formalism correctness — does propagate() actually implement the stated
     math, independent of any application to security data.
  2. Builder correctness — does build_session_taint_graph() turn realistic
     pipeline data into the right nodes/edges.
  3. The generalization claim — a concrete, end-to-end demonstration (using
     the real correlation_engine, not a re-implementation of it) that the
     taint graph catches an attack pattern none of the three hand-coded
     correlation rules can represent, because they gate on binary
     flagged/not-flagged signals while the graph propagates continuous trust.
"""

import pytest

from sentinel.core.taint_graph import (
    TaintGraph, TaintNode, TaintEdge, NodeType, EdgeType, GraphCycleError,
    build_session_taint_graph,
)


# ---------------------------------------------------------------------------
# 1. Formalism correctness
# ---------------------------------------------------------------------------

class TestPropagationFormalism:
    def test_node_with_no_incoming_edges_keeps_own_trust(self):
        g = TaintGraph()
        g.add_node(TaintNode("a", NodeType.USER_TURN, own_trust=0.3))
        effective = g.propagate()
        assert effective["a"] == pytest.approx(0.3)

    def test_full_confidence_edge_fully_propagates_upstream_trust(self):
        """weight=1.0 -> taint(u,v) = effective_trust(u) exactly."""
        g = TaintGraph()
        g.add_node(TaintNode("u", NodeType.RETRIEVED_CHUNK, own_trust=0.2))
        g.add_node(TaintNode("v", NodeType.TOOL_PARAM, own_trust=1.0, impact="CRITICAL"))
        g.add_edge(TaintEdge("u", "v", EdgeType.CONTEXT_DERIVED, weight=1.0))
        effective = g.propagate()
        assert effective["v"] == pytest.approx(0.2)

    def test_zero_confidence_edge_is_a_no_op(self):
        """weight=0.0 -> taint(u,v) = 1.0, i.e. the edge doesn't affect v at all."""
        g = TaintGraph()
        g.add_node(TaintNode("u", NodeType.RETRIEVED_CHUNK, own_trust=0.0))
        g.add_node(TaintNode("v", NodeType.TOOL_PARAM, own_trust=0.7, impact="CRITICAL"))
        g.add_edge(TaintEdge("u", "v", EdgeType.CONTEXT_DERIVED, weight=0.0))
        effective = g.propagate()
        assert effective["v"] == pytest.approx(0.7)

    def test_min_across_multiple_edges_not_averaged(self):
        """A trustworthy second source must NOT dilute a low-trust first
        source — this is the specific security property the min-rule
        encodes (an attacker can't launder a poisoned source's influence by
        also citing something benign)."""
        g = TaintGraph()
        g.add_node(TaintNode("low", NodeType.RETRIEVED_CHUNK, own_trust=0.1))
        g.add_node(TaintNode("high", NodeType.RETRIEVED_CHUNK, own_trust=0.95))
        g.add_node(TaintNode("v", NodeType.TOOL_PARAM, own_trust=1.0, impact="CRITICAL"))
        g.add_edge(TaintEdge("low", "v", EdgeType.CONTEXT_DERIVED, weight=1.0))
        g.add_edge(TaintEdge("high", "v", EdgeType.CONTEXT_DERIVED, weight=1.0))

        effective = g.propagate()
        # If this were an average, effective["v"] would be ~0.525. It must
        # instead track the worse (lower-trust) source.
        assert effective["v"] == pytest.approx(0.1)

    def test_transitive_propagation_through_multiple_hops(self):
        g = TaintGraph()
        g.add_node(TaintNode("a", NodeType.USER_TURN, own_trust=0.3))
        g.add_node(TaintNode("b", NodeType.TOOL_PARAM, own_trust=1.0, impact="LOW"))
        g.add_node(TaintNode("c", NodeType.TOOL_PARAM, own_trust=1.0, impact="CRITICAL"))
        g.add_edge(TaintEdge("a", "b", EdgeType.EXPLICIT_USER_REQUEST, weight=1.0))
        g.add_edge(TaintEdge("b", "c", EdgeType.EXPLICIT_USER_REQUEST, weight=1.0))
        effective = g.propagate()
        assert effective["b"] == pytest.approx(0.3)
        assert effective["c"] == pytest.approx(0.3)

    def test_cycle_raises(self):
        g = TaintGraph()
        g.add_node(TaintNode("a", NodeType.TOOL_PARAM, own_trust=1.0))
        g.add_node(TaintNode("b", NodeType.TOOL_PARAM, own_trust=1.0))
        g.add_edge(TaintEdge("a", "b", EdgeType.EXPLICIT_USER_REQUEST, weight=0.5))
        g.add_edge(TaintEdge("b", "a", EdgeType.EXPLICIT_USER_REQUEST, weight=0.5))
        with pytest.raises(GraphCycleError):
            g.propagate()

    def test_invalid_trust_value_rejected(self):
        with pytest.raises(ValueError):
            TaintNode("a", NodeType.USER_TURN, own_trust=1.5)

    def test_invalid_edge_weight_rejected(self):
        with pytest.raises(ValueError):
            TaintEdge("a", "b", EdgeType.EXPLICIT_USER_REQUEST, weight=-0.1)

    def test_edge_to_unknown_node_rejected(self):
        g = TaintGraph()
        g.add_node(TaintNode("a", NodeType.USER_TURN, own_trust=1.0))
        with pytest.raises(ValueError):
            g.add_edge(TaintEdge("a", "nonexistent", EdgeType.EXPLICIT_USER_REQUEST, weight=1.0))


class TestFindLowTrustHighImpactPaths:
    def test_low_trust_high_impact_is_flagged_with_correct_path(self):
        g = TaintGraph()
        g.add_node(TaintNode("chunk_x", NodeType.RETRIEVED_CHUNK, own_trust=0.1))
        g.add_node(TaintNode("param_y", NodeType.TOOL_PARAM, own_trust=1.0, impact="CRITICAL"))
        g.add_edge(TaintEdge("chunk_x", "param_y", EdgeType.CONTEXT_DERIVED, weight=0.9))

        findings = g.find_low_trust_high_impact_paths(trust_threshold=0.4)
        assert len(findings) == 1
        f = findings[0]
        assert f.node_id == "param_y"
        assert f.responsible_node_id == "chunk_x"
        assert f.path == ["chunk_x", "param_y"]

    def test_high_trust_source_not_flagged(self):
        g = TaintGraph()
        g.add_node(TaintNode("chunk_x", NodeType.RETRIEVED_CHUNK, own_trust=0.95))
        g.add_node(TaintNode("param_y", NodeType.TOOL_PARAM, own_trust=1.0, impact="CRITICAL"))
        g.add_edge(TaintEdge("chunk_x", "param_y", EdgeType.CONTEXT_DERIVED, weight=0.9))

        findings = g.find_low_trust_high_impact_paths(trust_threshold=0.4)
        assert findings == []

    def test_low_impact_node_not_flagged_even_if_low_trust(self):
        g = TaintGraph()
        g.add_node(TaintNode("chunk_x", NodeType.RETRIEVED_CHUNK, own_trust=0.05))
        g.add_node(TaintNode("param_y", NodeType.TOOL_PARAM, own_trust=1.0, impact="LOW"))
        g.add_edge(TaintEdge("chunk_x", "param_y", EdgeType.CONTEXT_DERIVED, weight=0.9))

        findings = g.find_low_trust_high_impact_paths(trust_threshold=0.4)
        assert findings == []


# ---------------------------------------------------------------------------
# 2. Builder correctness
# ---------------------------------------------------------------------------

class TestBuildSessionTaintGraph:
    def test_explicit_user_request_edge_built_from_matched_turn_index(self):
        turns = [(0, "please refund order 12345", 0.1)]
        l4_calls = [{
            "tool_name": "refund_api",
            "risk_level": "HIGH",
            "provenance": {
                "order_id": {
                    "source": "EXPLICIT_USER_REQUEST",
                    "confidence": 0.95,
                    "matched_turn_index": 0,
                    "matched_chunk_id": None,
                }
            },
        }]
        graph = build_session_taint_graph(turns=turns, l2_chunks=[], l4_calls=l4_calls)
        assert "turn_0" in graph.nodes
        param_node = "call0_refund_api_order_id"
        assert param_node in graph.nodes
        assert any(e.source_id == "turn_0" and e.target_id == param_node for e in graph.edges)

    def test_context_derived_edge_built_from_matched_chunk_id(self):
        l2_chunks = [{"chunk_id": "chk_1", "metadata": {"trust_score": 0.2}, "quarantined": True}]
        l4_calls = [{
            "tool_name": "send_email",
            "risk_level": "CRITICAL",
            "provenance": {
                "recipient": {
                    "source": "CONTEXT_DERIVED",
                    "confidence": 0.88,
                    "matched_turn_index": None,
                    "matched_chunk_id": "chk_1",
                }
            },
        }]
        graph = build_session_taint_graph(turns=[], l2_chunks=l2_chunks, l4_calls=l4_calls)
        assert "chunk_chk_1" in graph.nodes
        assert graph.nodes["chunk_chk_1"].own_trust == pytest.approx(0.2)
        param_node = "call0_send_email_recipient"
        assert any(e.source_id == "chunk_chk_1" and e.target_id == param_node for e in graph.edges)

    def test_uncertain_provenance_sets_own_trust_directly_with_no_edge(self):
        l4_calls = [{
            "tool_name": "execute_code",
            "risk_level": "CRITICAL",
            "provenance": {
                "script": {
                    "source": "UNCERTAIN",
                    "confidence": 0.1,
                    "matched_turn_index": None,
                    "matched_chunk_id": None,
                }
            },
        }]
        graph = build_session_taint_graph(turns=[], l2_chunks=[], l4_calls=l4_calls)
        param_node = "call0_execute_code_script"
        assert graph.nodes[param_node].own_trust == pytest.approx(0.1)
        assert not any(e.target_id == param_node for e in graph.edges)

        findings = graph.find_low_trust_high_impact_paths()
        assert any(f.node_id == param_node for f in findings)

    def test_clean_scenario_produces_no_findings(self):
        turns = [(0, "what's the weather like today", 0.0)]
        l4_calls = [{
            "tool_name": "get_weather",
            "risk_level": "LOW",
            "provenance": {
                "city": {
                    "source": "EXPLICIT_USER_REQUEST",
                    "confidence": 0.95,
                    "matched_turn_index": 0,
                    "matched_chunk_id": None,
                }
            },
        }]
        graph = build_session_taint_graph(turns=turns, l2_chunks=[], l4_calls=l4_calls)
        assert graph.find_low_trust_high_impact_paths() == []


# ---------------------------------------------------------------------------
# 3. The generalization demonstration — real correlation_engine, not a
#    reimplementation of it, showing Rules 1-3 structurally cannot catch
#    this pattern while Rule 4 (taint graph) does.
# ---------------------------------------------------------------------------

class TestGraphGeneralizationOverHandCodedRules:
    @pytest.mark.asyncio
    async def test_moderately_suspicious_turn_directly_authorizing_critical_tool(self):
        """
        Scenario: a single turn scores L1=0.65 — elevated, but under L1's own
        block threshold (0.75 in config.py), so the request alone is only
        WARNED, never BLOCKED. Later in the same session, that turn's text is
        used (via a confident fuzzy match) as a parameter to a CRITICAL-risk
        tool call. determine_authorization() in provenance_tracker.py treats
        an EXPLICIT_USER_REQUEST source as clean by construction — it does
        not look at how suspicious the *source turn itself* was — so L4's
        own scoring doesn't elevate this call either.

        None of Rules 1-3 represent this pattern:
          - Rule 1 needs L3 drift > 0.7 (this is a single turn, no drift).
          - Rule 2 needs an L4 call with threat_class == RAG_INJECTION,
            which only gets set by the flagged-chunk direct-tracing path —
            there's no RAG chunk involved here at all.
          - Rule 3 needs elevated L1/L3 AND a high L5 exfil score — there's
            no output-side signal here.

        This test asserts, against the real check_correlations(), that none
        of rules 1-3 fire, and that Rule 4 (the taint graph) does.
        """
        from sentinel.core.threat_bus import threat_bus
        from sentinel.core.correlation_engine import check_correlations, reset_correlation_state

        threat_bus.reset()
        reset_correlation_state()
        session_id = "test-generalization-session"
        session = await threat_bus.get_session(session_id)

        # The one turn: elevated but sub-block L1 score, no drift, no RAG
        # findings, no L5 signal at all.
        session.l1_max = 0.65
        session.l3_current = 0.0
        session.l2_findings = []
        session.l5_scores = []
        session.turn_provenance = [{"turn_index": 0, "text": "wire $50,000 to account 9182736450 now", "l1_score": 0.65}]

        # The L4 call: CRITICAL tool, parameter traced back to that same
        # turn with high confidence, authorization treated as clean by L4's
        # own logic (EXPLICIT_USER_REQUEST), threat_class therefore CLEAN —
        # nothing here that Rule 2 keys off (RAG_INJECTION) is present.
        session.l4_calls = [{
            "tool_name": "approve_loan",
            "risk_level": "CRITICAL",
            "threat_class": "CLEAN",
            "authorization_source": "EXPLICIT_USER_REQUEST",
            "provenance": {
                "amount": {
                    "source": "EXPLICIT_USER_REQUEST",
                    "confidence": 0.95,
                    "matched_turn_index": 0,
                    "matched_chunk_id": None,
                }
            },
        }]

        await check_correlations(session_id)
        fired_types = {e.threat_type for e in session.events}

        # The specific claim: none of the hand-coded rules fire...
        assert "SLOW_BURN_INJECTION" not in fired_types
        assert "RAG_PLUS_AGENT_ATTACK" not in fired_types
        assert "EXFIL_AFTER_PROBE" not in fired_types
        # ...but the taint graph rule does.
        assert "TAINT_PATH_DETECTED" in fired_types

    @pytest.mark.asyncio
    async def test_fully_clean_session_triggers_no_rules_at_all(self):
        """Sanity check in the other direction: the taint rule must not fire
        on a clean session, so it isn't just a lower-threshold version of
        'always flag CRITICAL tool calls'."""
        from sentinel.core.threat_bus import threat_bus
        from sentinel.core.correlation_engine import check_correlations, reset_correlation_state

        threat_bus.reset()
        reset_correlation_state()
        session_id = "test-clean-session"
        session = await threat_bus.get_session(session_id)

        session.l1_max = 0.05
        session.l3_current = 0.0
        session.l2_findings = []
        session.l5_scores = []
        session.turn_provenance = [{"turn_index": 0, "text": "please approve the standard loan for account 1122334455", "l1_score": 0.05}]
        session.l4_calls = [{
            "tool_name": "approve_loan",
            "risk_level": "CRITICAL",
            "threat_class": "CLEAN",
            "authorization_source": "EXPLICIT_USER_REQUEST",
            "provenance": {
                "account": {
                    "source": "EXPLICIT_USER_REQUEST",
                    "confidence": 0.95,
                    "matched_turn_index": 0,
                    "matched_chunk_id": None,
                }
            },
        }]

        await check_correlations(session_id)
        fired_types = {e.threat_type for e in session.events}
        assert fired_types == set()
