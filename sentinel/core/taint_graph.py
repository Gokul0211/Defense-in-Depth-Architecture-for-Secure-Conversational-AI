"""
Cross-Layer Taint Propagation Graph — Contribution A (research roadmap doc,
Section 2).

THE GAP THIS CLOSES
--------------------
Every layer in this pipeline (L1-L5) independently scores its own artifact —
a turn, a chunk, a tool call, an output span. Nothing in the system
represents *which chunk influenced which tool call* as an explicit,
first-class object. The correlation engine's `RAG_PLUS_AGENT_ATTACK` rule
approximates this by requiring the L4 auditor to have already traced a
specific parameter to a specific flagged chunk (see tool_auditor.py's direct
chunk-tracing block) — but that's still a single hand-coded pattern, not a
general representation of information flow through the pipeline.

This module is the general representation: a directed graph over turns,
retrieved chunks, and tool-call parameters, with an explicit trust
propagation function. It is a direct, deliberate transplant of dynamic taint
analysis from software security (where a value derived from untrusted input
stays "tainted" as it flows through a program regardless of whether any
single operation on it looks suspicious) into the LLM-pipeline setting.

SCOPE (v1)
----------
Node types implemented: USER_TURN, RETRIEVED_CHUNK, TOOL_PARAM. OUTPUT_SPAN
is defined for forward compatibility but not yet populated by the builder
below — L5 output spans aren't currently associated back to specific
upstream tool-call results anywhere in the pipeline's instrumentation, so
building real OUTPUT_SPAN edges would require adding that association first
rather than fabricating one. Extending to L5 is a natural next step, not a
redesign: the graph and propagation function are already general.

FORMALISM
---------
Every node has an `own_trust` in [0, 1] (1.0 = fully trusted). Every edge
(u -> v) has a `weight` in [0, 1]: how confident we are that this edge
represents genuine information flow (e.g. a fuzzy-match ratio between a
parameter value and a chunk's text).

    taint(u, v) = 1 - weight(u, v) * (1 - effective_trust(u))

    effective_trust(v) = own_trust(v)                                if v has no incoming edges
                        = own_trust(v) * min_{(u,v) in E} taint(u, v)  otherwise

Reading `taint(u, v)`: if the edge confidence is low, v's trust stays close
to its own trust regardless of how untrustworthy u is (weight -> 0 implies
taint -> 1, a no-op multiplier). If the edge is fully confident (weight=1),
v inherits u's untrustworthiness in full (taint -> effective_trust(u)).
Taking the `min` across multiple incoming edges — rather than, say, an
average — encodes the actual security property we want: a single low-trust,
high-confidence source is enough to taint v, and that can't be diluted by v
also having trustworthy sources. (An averaging rule would let an attacker
launder a poisoned chunk's influence by also citing something benign.)

This is a *deterministic* propagation rule chosen for interpretability and
auditability (every flagged node comes with an exact, explainable upstream
path — see `_backtrack_path`). A probabilistic alternative (e.g. treating
each edge as an independent noisy channel and propagating via a noisy-OR
rather than min) is a reasonable extension once there's a labeled corpus to
decide between them empirically; it is not implemented here because there's
currently no data to justify choosing it over the simpler, more auditable
rule.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class NodeType(str, Enum):
    USER_TURN = "USER_TURN"
    RETRIEVED_CHUNK = "RETRIEVED_CHUNK"
    TOOL_PARAM = "TOOL_PARAM"
    OUTPUT_SPAN = "OUTPUT_SPAN"  # defined for forward compatibility, not yet populated — see module docstring


class EdgeType(str, Enum):
    EXPLICIT_USER_REQUEST = "EXPLICIT_USER_REQUEST"  # turn -> param
    CONTEXT_DERIVED = "CONTEXT_DERIVED"              # chunk -> param
    OUTPUT_OVERLAP = "OUTPUT_OVERLAP"                # param/chunk -> output span (not yet built, see above)


IMPACT_LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


@dataclass
class TaintNode:
    node_id: str
    node_type: NodeType
    own_trust: float  # 1.0 = fully trusted, 0.0 = fully untrusted
    impact: str = "LOW"  # only meaningful for TOOL_PARAM / OUTPUT_SPAN nodes
    metadata: dict = field(default_factory=dict)

    def __post_init__(self):
        if not (0.0 <= self.own_trust <= 1.0):
            raise ValueError(f"own_trust must be in [0,1], got {self.own_trust}")
        if self.impact not in IMPACT_LEVELS:
            raise ValueError(f"impact must be one of {IMPACT_LEVELS}, got {self.impact}")


@dataclass
class TaintEdge:
    source_id: str
    target_id: str
    edge_type: EdgeType
    weight: float  # confidence this edge represents genuine information flow
    metadata: dict = field(default_factory=dict)

    def __post_init__(self):
        if not (0.0 <= self.weight <= 1.0):
            raise ValueError(f"weight must be in [0,1], got {self.weight}")


@dataclass
class TaintPathFinding:
    """A high-impact node whose effective trust fell below threshold, with
    the specific upstream path responsible — this is what makes a taint-graph
    detection explainable rather than a black-box score."""
    node_id: str
    effective_trust: float
    impact: str
    responsible_node_id: str
    responsible_edge: Optional[TaintEdge]
    path: list[str]  # root cause -> ... -> flagged node


class GraphCycleError(ValueError):
    """Raised when the graph contains a cycle. The graph is constructed from
    causally/temporally ordered events (a turn or chunk must exist before a
    tool call can reference it), so a cycle indicates a bug in how the graph
    was built, not a valid input to reason about."""


class TaintGraph:
    def __init__(self):
        self.nodes: dict[str, TaintNode] = {}
        self.edges: list[TaintEdge] = []
        self._incoming: dict[str, list[TaintEdge]] = {}
        self._effective_trust_cache: Optional[dict[str, float]] = None

    def add_node(self, node: TaintNode) -> None:
        self.nodes[node.node_id] = node
        self._incoming.setdefault(node.node_id, [])
        self._effective_trust_cache = None

    def add_edge(self, edge: TaintEdge) -> None:
        if edge.source_id not in self.nodes or edge.target_id not in self.nodes:
            raise ValueError(
                f"Edge references unknown node(s): {edge.source_id!r} -> {edge.target_id!r}"
            )
        self.edges.append(edge)
        self._incoming.setdefault(edge.target_id, []).append(edge)
        self._effective_trust_cache = None

    def _topological_order(self) -> list[str]:
        """Kahn's algorithm. O(V + E)."""
        in_degree = {nid: 0 for nid in self.nodes}
        outgoing: dict[str, list[str]] = {nid: [] for nid in self.nodes}
        for e in self.edges:
            in_degree[e.target_id] += 1
            outgoing[e.source_id].append(e.target_id)

        queue = [nid for nid, d in in_degree.items() if d == 0]
        order = []
        while queue:
            n = queue.pop(0)
            order.append(n)
            for m in outgoing[n]:
                in_degree[m] -= 1
                if in_degree[m] == 0:
                    queue.append(m)

        if len(order) != len(self.nodes):
            raise GraphCycleError(
                "TaintGraph contains a cycle. The graph is expected to be a "
                "DAG given its causal/temporal construction (turns/chunks "
                "precede the tool-call parameters they influence). This "
                "means graph construction produced an edge pointing "
                "backwards in time — a bug in the builder, not a valid input."
            )
        return order

    def propagate(self) -> dict[str, float]:
        """Compute effective_trust for every node. See module docstring for
        the formalism. O(V + E); cached until the next add_node/add_edge."""
        if self._effective_trust_cache is not None:
            return self._effective_trust_cache

        order = self._topological_order()
        effective: dict[str, float] = {}

        for node_id in order:
            node = self.nodes[node_id]
            incoming = self._incoming.get(node_id, [])
            if not incoming:
                effective[node_id] = node.own_trust
                continue

            taints = [
                1.0 - e.weight * (1.0 - effective[e.source_id])
                for e in incoming
            ]
            effective[node_id] = node.own_trust * min(taints)

        self._effective_trust_cache = effective
        return effective

    def find_low_trust_high_impact_paths(
        self,
        trust_threshold: float = 0.4,
        impact_levels: tuple[str, ...] = ("HIGH", "CRITICAL"),
    ) -> list[TaintPathFinding]:
        """
        The core detection query: any node whose effective trust fell below
        `trust_threshold` AND whose impact is in `impact_levels`, even if
        neither the node's own layer nor any single upstream layer crossed
        its own independent threshold. This is what subsumes and generalizes
        the correlation engine's hand-coded RAG_PLUS_AGENT_ATTACK rule (see
        core/correlation_engine.py) — any path through the graph that
        connects untrusted provenance to high-impact action gets caught,
        not just the one specific pattern that rule was written for.
        """
        effective = self.propagate()
        findings = []

        for node_id, node in self.nodes.items():
            if node.impact not in impact_levels:
                continue
            trust = effective[node_id]
            if trust >= trust_threshold:
                continue

            incoming = self._incoming.get(node_id, [])
            if not incoming:
                # Below threshold purely from its own trust, no upstream edge to blame.
                findings.append(TaintPathFinding(
                    node_id=node_id, effective_trust=trust, impact=node.impact,
                    responsible_node_id=node_id, responsible_edge=None, path=[node_id],
                ))
                continue

            worst_edge = min(
                incoming,
                key=lambda e: 1.0 - e.weight * (1.0 - effective[e.source_id]),
            )
            findings.append(TaintPathFinding(
                node_id=node_id, effective_trust=trust, impact=node.impact,
                responsible_node_id=worst_edge.source_id, responsible_edge=worst_edge,
                path=self._backtrack_path(node_id, effective),
            ))

        return findings

    def _backtrack_path(self, node_id: str, effective: dict[str, float]) -> list[str]:
        """Walk backwards from `node_id`, at each step following the single
        incoming edge that contributed the most taint, until reaching a root
        (a node with no incoming edges) — i.e. the specific chain of custody
        responsible for this node's low trust. Returns root-first order."""
        path = [node_id]
        current = node_id
        visited = {node_id}
        while True:
            incoming = self._incoming.get(current, [])
            if not incoming:
                break
            worst_edge = min(
                incoming,
                key=lambda e: 1.0 - e.weight * (1.0 - effective[e.source_id]),
            )
            if worst_edge.source_id in visited:
                break  # defensive; shouldn't trigger in a validated DAG
            path.append(worst_edge.source_id)
            visited.add(worst_edge.source_id)
            current = worst_edge.source_id
        return list(reversed(path))

    def to_dict(self) -> dict:
        """JSON-serializable snapshot, for logging/eval (see the evaluation
        plan doc's requirement to log taint graphs per session for edge-level
        precision/recall, separate from final-decision accuracy)."""
        effective = self.propagate()
        return {
            "nodes": [
                {
                    "node_id": n.node_id,
                    "node_type": n.node_type.value,
                    "own_trust": n.own_trust,
                    "effective_trust": effective[n.node_id],
                    "impact": n.impact,
                    "metadata": n.metadata,
                }
                for n in self.nodes.values()
            ],
            "edges": [
                {
                    "source_id": e.source_id,
                    "target_id": e.target_id,
                    "edge_type": e.edge_type.value,
                    "weight": e.weight,
                    "metadata": e.metadata,
                }
                for e in self.edges
            ],
        }


def build_session_taint_graph(
    turns: list[tuple[int, str, float]],
    l2_chunks: list[dict],
    l4_calls: list[dict],
) -> TaintGraph:
    """
    Build a TaintGraph from the data already flowing through the pipeline for
    one session — no new instrumentation required beyond the L4Result.provenance
    field added alongside this module (see core/models.py and
    layer4_agentic/tool_auditor.py).

    Args:
        turns: (turn_index, lowercased_text, l1_score) for each user turn.
        l2_chunks: dicts with at least `chunk_id`, and metadata.trust_score
            (matching the shape returned by layer2_get_chunks()).
        l4_calls: dicts matching session.l4_calls' shape: `tool_name`,
            `risk_level`, `provenance` (the structured per-parameter dict
            produced by provenance_tracker.trace_parameters and threaded
            through L4Result — see core/models.py's L4Result.provenance).

    A TOOL_PARAM node's own trust is set directly from its provenance
    confidence only when there's no traceable source to attach an edge to
    (source == "UNCERTAIN") — an untraceable value feeding a high-impact tool
    call is inherently suspicious on its own terms. When a source *was*
    traced (EXPLICIT_USER_REQUEST or CONTEXT_DERIVED), the param node starts
    neutral (own_trust=1.0) and its effective trust is governed entirely by
    the propagation edge from that source — avoiding double-counting the
    same risk once as "own trust" and again as "propagated trust".

    IMPORTANT ASSUMPTION — turn-index alignment: each L4 call's provenance
    dict carries `matched_turn_index`, which is an index into whatever
    `conversation_history` list was passed to that specific
    audit_tool_call() invocation (see layer4_agentic/tool_auditor.py). This
    function assumes that index refers to the same turn sequence as the
    `turns` argument passed in here (in production, `session.turn_provenance`
    — see core/models.py's SessionState). That holds as long as callers of
    the /sentinel/tool_call endpoint pass a `history` payload that actually
    matches the session's real turn order, which is the expected contract
    but isn't enforced by a shared identity between the two lists. If the
    indices don't line up, this fails safe rather than fails dangerous: the
    `if turn_node_id in graph.nodes` check below simply skips the edge, so a
    misaligned index produces a missed edge (a param that looks untraceable),
    never a false edge to the wrong turn.
    """
    graph = TaintGraph()

    for turn_idx, text, l1_score in turns:
        graph.add_node(TaintNode(
            node_id=f"turn_{turn_idx}",
            node_type=NodeType.USER_TURN,
            own_trust=max(0.0, min(1.0, 1.0 - l1_score)),
            metadata={"text_preview": text[:80]},
        ))

    for chunk in l2_chunks:
        chunk_id = chunk.get("chunk_id")
        if chunk_id is None:
            continue
        trust = chunk.get("metadata", {}).get("trust_score", chunk.get("trust_score", 0.5))
        graph.add_node(TaintNode(
            node_id=f"chunk_{chunk_id}",
            node_type=NodeType.RETRIEVED_CHUNK,
            own_trust=max(0.0, min(1.0, trust)),
            metadata={"quarantined": chunk.get("quarantined", False)},
        ))

    for call_idx, call in enumerate(l4_calls):
        provenance = call.get("provenance") or {}
        risk_level = call.get("risk_level", "MEDIUM")
        impact = risk_level if risk_level in IMPACT_LEVELS else "MEDIUM"
        tool_name = call.get("tool_name", "unknown_tool")

        for param_name, prov in provenance.items():
            param_node_id = f"call{call_idx}_{tool_name}_{param_name}"
            source = prov.get("source")
            confidence = float(prov.get("confidence", 0.0))

            if source == "UNCERTAIN":
                # No edge to attach — the param's own trust directly encodes
                # "how suspicious is it that this value has no known origin".
                own_trust = confidence
            else:
                own_trust = 1.0  # neutral; propagation edge governs effective trust

            graph.add_node(TaintNode(
                node_id=param_node_id,
                node_type=NodeType.TOOL_PARAM,
                own_trust=own_trust,
                impact=impact,
                metadata={"tool_name": tool_name, "param_name": param_name, "source": source},
            ))

            if source == "EXPLICIT_USER_REQUEST" and prov.get("matched_turn_index") is not None:
                turn_node_id = f"turn_{prov['matched_turn_index']}"
                if turn_node_id in graph.nodes:
                    graph.add_edge(TaintEdge(
                        source_id=turn_node_id, target_id=param_node_id,
                        edge_type=EdgeType.EXPLICIT_USER_REQUEST, weight=confidence,
                    ))
            elif source == "CONTEXT_DERIVED" and prov.get("matched_chunk_id") is not None:
                chunk_node_id = f"chunk_{prov['matched_chunk_id']}"
                if chunk_node_id in graph.nodes:
                    graph.add_edge(TaintEdge(
                        source_id=chunk_node_id, target_id=param_node_id,
                        edge_type=EdgeType.CONTEXT_DERIVED, weight=confidence,
                    ))

    return graph
