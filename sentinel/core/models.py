"""
SENTINEL Core Models — All dataclasses for threat events, sessions, and layer results.
"""

from dataclasses import dataclass, field
from typing import Optional, Any


def score_to_severity(score: float) -> str:
    """Map a 0.0-1.0 threat score to a severity label."""
    if score >= 0.85:
        return "CRITICAL"
    if score >= 0.65:
        return "HIGH"
    if score >= 0.40:
        return "MEDIUM"
    if score >= 0.20:
        return "LOW"
    return "CLEAN"


def score_to_action(score: float, block_threshold: float = 0.85, warn_threshold: float = 0.50) -> str:
    """Map a threat score to an action."""
    if score >= block_threshold:
        return "BLOCKED"
    if score >= warn_threshold:
        return "WARNED"
    return "ALLOWED"


@dataclass
class ThreatEvent:
    """A single threat detection event emitted by any layer."""
    event_id: str
    timestamp: str
    session_id: str
    layer: str                  # L1, L2, L3, L4, L5, TIB
    threat_type: str            # e.g. INJECTION, SEMANTIC_SHIFT, PROVENANCE_FAIL
    severity: str               # CLEAN, LOW, MEDIUM, HIGH, CRITICAL
    threat_score: float         # 0.0 - 1.0
    action: str                 # ALLOWED, WARNED, BLOCKED
    evidence: dict = field(default_factory=dict)
    explanation: dict = field(default_factory=dict)
    turn: Optional[int] = None  # Turn number for L3 events
    note: Optional[str] = None  # Human-readable note

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "session_id": self.session_id,
            "layer": self.layer,
            "threat_type": self.threat_type,
            "severity": self.severity,
            "threat_score": self.threat_score,
            "action": self.action,
            "evidence": self.evidence,
            "explanation": self.explanation,
            "turn": self.turn,
            "note": self.note,
        }


@dataclass
class Turn:
    """A single turn within a session's timeline."""
    turn_number: int
    score: float
    severity: str
    note: str = ""
    layer: str = "L3"

    def to_dict(self) -> dict:
        return {
            "turn_number": self.turn_number,
            "score": self.score,
            "severity": self.severity,
            "note": self.note,
            "layer": self.layer,
        }


@dataclass
class SessionState:
    """Full state for a single monitored session."""
    session_id: str
    turns: list = field(default_factory=list)
    events: list = field(default_factory=list)
    l1_max: float = 0.0
    l2_findings: list = field(default_factory=list)
    l2_flagged_chunks: list = field(default_factory=list)
    l3_current: float = 0.0
    l4_calls: list = field(default_factory=list)
    l5_scores: list = field(default_factory=list)
    overall: float = 0.0
    risk: str = "CLEAN"
    chat_history: list = field(default_factory=list)
    # (turn_index, lowercased user text, l1_score) per user turn — feeds the
    # taint propagation graph's USER_TURN nodes (see core/taint_graph.py).
    # Kept separate from chat_history (which also holds assistant turns and
    # doesn't carry L1 scores) rather than overloading that field.
    turn_provenance: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "turn_count": len(self.turns),
            "turns": [t.to_dict() if hasattr(t, 'to_dict') else t for t in self.turns],
            "events": [e.to_dict() if hasattr(e, 'to_dict') else e for e in self.events],
            "l1_max": self.l1_max,
            "l2_findings": self.l2_findings,
            "l2_flagged_chunks": self.l2_flagged_chunks,
            "l3_current": self.l3_current,
            "l4_calls": self.l4_calls,
            "l5_scores": self.l5_scores,
            "overall": self.overall,
            "risk": self.risk,
            "chat_history": self.chat_history,
            "turn_provenance": self.turn_provenance,
        }


@dataclass
class L1Result:
    """Result from Layer 1 injection classification."""
    score: float
    threat_class: str           # INJECTION, EXTRACTION_PROBE, JAILBREAK, SUSPICIOUS, CLEAN
    confidence: float
    reason: str
    tier_used: int              # 1 (regex) or 2 (semantic)

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "threat_class": self.threat_class,
            "confidence": self.confidence,
            "reason": self.reason,
            "tier_used": self.tier_used,
        }


@dataclass
class L3Result:
    """Result from Layer 3 conversational drift tracking."""
    score: float
    semantic_velocity: float
    cumulative_drift: float
    escalation_found: bool
    turn_count: int
    reason: str

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "semantic_velocity": self.semantic_velocity,
            "cumulative_drift": self.cumulative_drift,
            "escalation_found": self.escalation_found,
            "turn_count": self.turn_count,
            "reason": self.reason,
        }

@dataclass
class L2Result:
    """Result from Layer 2 RAG Integrity Monitor."""
    score: float
    threat_class: str
    confidence: float
    reason: str
    quarantined: bool

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "threat_class": self.threat_class,
            "confidence": self.confidence,
            "reason": self.reason,
            "quarantined": self.quarantined,
        }

@dataclass
class L4Result:
    """Result from Layer 4 Agentic Reasoning Auditor."""
    score: float
    threat_class: str
    authorization_source: str
    risk_level: str
    should_execute: bool
    reason: str
    # Structured per-parameter provenance (see provenance_tracker.trace_parameters).
    # Previously this was computed internally by audit_tool_call() and then
    # discarded after being collapsed into the single `authorization_source`
    # string — meaning nothing downstream could tell *which* parameter came
    # from *which* turn or chunk, only "at least one parameter was uncertain".
    # The taint propagation graph (sentinel/core/taint_graph.py) needs the
    # per-parameter, per-turn/chunk detail to build real edges, so it's
    # carried through here instead of being thrown away.
    provenance: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "threat_class": self.threat_class,
            "authorization_source": self.authorization_source,
            "risk_level": self.risk_level,
            "should_execute": self.should_execute,
            "reason": self.reason,
            "provenance": self.provenance,
        }

@dataclass
class L5Result:
    """Result from Layer 5 Output Semantic Firewall."""
    score: float
    threat_class: str
    pii_findings: list[dict]
    exfil_score: float
    policy_violations: list[str]
    reason: str

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "threat_class": self.threat_class,
            "pii_findings": self.pii_findings,
            "exfil_score": self.exfil_score,
            "policy_violations": self.policy_violations,
            "reason": self.reason,
        }

