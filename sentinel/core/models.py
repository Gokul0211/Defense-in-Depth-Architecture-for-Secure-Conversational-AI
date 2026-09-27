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


def rescale_layer_score(
    raw_score: float,
    layer_warn_threshold: float,
    layer_block_threshold: float,
    global_warn_threshold: float,
    global_block_threshold: float,
) -> float:
    """
    Rescale a single layer's raw score onto the pipeline's shared
    WARN/BLOCK scale, for the sole purpose of combining several layers'
    scores (of potentially very different practical ranges) via one
    shared `max()` + one shared threshold pair.

    --------------------------------------------------------------------
    RCA #3 (2026-07-25, session 3): why this exists
    --------------------------------------------------------------------
    `sentinel/app.py` computes `combined_score = max(l1_score, l3_score,
    l2_score, l2_retrieval_score)` and then classifies THAT single number
    against the pipeline-wide `WARN_THRESHOLD`/`BLOCK_THRESHOLD`. That's
    only a valid comparison if every layer's raw score means roughly the
    same thing at the same number — which broke for L3 specifically once
    its score formula changed (see layer3.py's RCA #2): a real live run
    scored **AUROC=0.9795 on L3 alone (excellent ranking)** but
    **Precision=Recall=FPR=0.0000 at the shared WARN_THRESHOLD=0.50** —
    every single L3 score in the whole test set, malicious or benign, fell
    below 0.50. This isn't a detector failure; it's a well-known property
    of real sentence-embedding cosine similarities (they're compressed
    into a narrower range than [-1, 1] even between clearly related
    concepts — an anisotropy effect, not a bug in this codebase) combined
    with L3's harm_alignment-weighted formula, which just doesn't produce
    raw values anywhere near 0.85, or reliably near 0.50 either, even for
    genuinely malicious conversations. Comparing that raw number against a
    threshold calibrated for a different layer's scale silently means a
    real slow-burn attack that L1's per-message classifier can't see
    (that's the whole reason L3 exists) would never trigger WARN or BLOCK
    in the live pipeline either — this is a real detection miss, not just
    an eval-script artifact.

    This function maps `layer_warn_threshold -> global_warn_threshold` and
    `layer_block_threshold -> global_block_threshold` (piecewise-linear,
    clamped at 0 below the layer's warn point), so a layer-specific
    calibrated operating point becomes comparable to every other layer's
    on the shared 0.50/0.85 scale — without touching L1/L2's already-
    working raw scores (their thresholds equal the global ones, so this
    function is a no-op for them: pass their own thresholds in and the
    piecewise map is the identity function).

    IMPORTANT: `layer_warn_threshold`/`layer_block_threshold` must
    themselves be calibrated on real data (see
    `sentinel/eval/calibrate_l3_weights.py`'s threshold-suggestion
    section for L3) — this function only does the remapping arithmetic,
    it does not calibrate anything itself. Passing in a wrong layer
    threshold just moves the miscalibration to a different number.
    """
    if raw_score <= 0:
        return 0.0
    if raw_score <= layer_warn_threshold:
        # 0 -> 0, layer_warn_threshold -> global_warn_threshold
        if layer_warn_threshold <= 0:
            return 0.0
        return (raw_score / layer_warn_threshold) * global_warn_threshold
    if raw_score <= layer_block_threshold:
        # layer_warn_threshold -> global_warn_threshold,
        # layer_block_threshold -> global_block_threshold
        span = layer_block_threshold - layer_warn_threshold
        if span <= 0:
            return global_block_threshold
        frac = (raw_score - layer_warn_threshold) / span
        return global_warn_threshold + frac * (global_block_threshold - global_warn_threshold)
    # Above the layer's own BLOCK point — extrapolate past global BLOCK
    # proportionally to how far raw_score is past layer_block_threshold,
    # rather than hard-clamping to exactly global_block_threshold (so
    # severity ordering among several BLOCK-worthy signals is preserved).
    overshoot = raw_score - layer_block_threshold
    return global_block_threshold + overshoot


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
    # Candidate sensitive values (proper-noun-shaped strings) seen in RAG
    # documents / tool responses this session — see
    # core/sensitive_value_extractor.py and layer5_output/layer5.py's
    # provenance-based leak check (added 2026-09-11). Closes L5's free-text
    # name-disclosure blind spot (regex PII_PATTERNS can't catch names —
    # no fixed format) by reusing L4's provenance-tracing idea
    # (fuzzy_contains) pointed at output instead of input.
    tracked_sensitive_values: list = field(default_factory=list)
    # Set when a correlation rule whose verdict is BLOCKED fires (correlation_engine.
    # RULE_ACTIONS). A correlation verdict is about the SESSION, not one request, so
    # every later request/tool call on a terminated session is refused.
    terminated: bool = False
    termination_reason: str = ""

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
            "tracked_sensitive_values": self.tracked_sensitive_values,
            "terminated": self.terminated,
            "termination_reason": self.termination_reason,
        }


@dataclass
class L1Result:
    """Result from Layer 1 injection classification."""
    score: float
    threat_class: str           # INJECTION, EXTRACTION_PROBE, JAILBREAK, SUSPICIOUS, CLEAN
    confidence: float
    reason: str
    tier_used: int              # 1 (regex), 2 (semantic), 3 (Prompt Guard), 4 (LLM judge)
    # Phase 5 Stage -1 (2026-09-18): every tier's own score, not just the
    # fused result. L1 combines its four tiers with `max()`
    # (layer1.py: `combined_sim = max(max_sim, pg_score)`, then the judge
    # overrides only if strictly higher), which discards the other tiers'
    # values entirely — so nothing downstream could measure what any
    # individual tier contributed. Confirmed by direct search before adding
    # this: no per-tier score was persisted anywhere in the codebase, which
    # made per-tier contribution analysis impossible rather than merely
    # inconvenient.
    #
    # Needed by three separate pieces of downstream work: the calibrated
    # tier-fusion experiment (plan item 3B.3 — max is not the
    # Neyman-Pearson-optimal combination rule), per-layer informativeness
    # accounting (plan item S3), and per-tier e-value calibration.
    #
    # KEY SEMANTIC, do not "simplify" this to 0.0: a tier that did not RUN
    # records None, not 0.0. Prompt Guard may be unavailable (model load
    # failed) and the LLM judge is only invoked inside the ambiguous band;
    # layer1.py's own comment is explicit that a missing judge result means
    # "skip", never "scored zero". Collapsing the two would silently turn
    # "no evidence" into "evidence of absence" in any fusion fitted on
    # these values.
    tier_scores: dict = field(default_factory=dict)
    # The intent-level safety tier's RAW score (fixing.md A), None when it did not run
    # (flag off, gated out because L1 was already at WARN, or guard unavailable). Kept
    # out of `tier_scores` because the frozen tier-fusion artifact is keyed on exactly
    # the four cascade tiers.
    safety_score: float | None = None
    # The HARM-INTENT head (L1_HARM_HEAD="separate", 2026-09-25, R-020): P(harmful) from the
    # guard, or the policy judge's verdict when the guard was in its uncertain band.
    # Deliberately NOT fused into `score`: `score` answers "is this an injection", this
    # answers "is the request harmful" -- orthogonal questions (94 % of TensorTrust
    # injections have P(unsafe) < 0.1), so neither may veto or inflate the other.
    harm_score: float | None = None
    harm_source: str | None = None       # "guard" | "judge" | None

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "threat_class": self.threat_class,
            "confidence": self.confidence,
            "reason": self.reason,
            "tier_used": self.tier_used,
            "tier_scores": self.tier_scores,
            "safety_score": self.safety_score,
            "harm_score": self.harm_score,
            "harm_source": self.harm_source,
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
    # Added in the 2026-07-25 (session 2) RCA — see sentinel/layers/layer3.py
    # module docstring. Max cosine similarity of the current turn to a small
    # set of generic harm-topic anchor embeddings. Defaults to 0.0 so the
    # dataclass stays backward compatible with any positional construction.
    harm_alignment: float = 0.0
    # The safety guard's content score when L3_CONTENT_SIGNAL="guard" (fixing.md B/C),
    # None otherwise or when the guard was unavailable.
    guard_score: float | None = None
    # The guard's P(Unsafe) on this turn's decoded cipher goal when L3_DECODED_GUARD is on
    # and the turn decoded (fixing.md C), None otherwise.
    decoded_guard_score: float | None = None

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "semantic_velocity": self.semantic_velocity,
            "cumulative_drift": self.cumulative_drift,
            "escalation_found": self.escalation_found,
            "turn_count": self.turn_count,
            "reason": self.reason,
            "harm_alignment": self.harm_alignment,
            "guard_score": self.guard_score,
            "decoded_guard_score": self.decoded_guard_score,
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
    # Phase 5 (2026-09-19): CONTINUOUS evidence, emitted alongside the
    # discrete decision. Purely additive — nothing below is read by
    # `score`, `should_execute`, `risk_level` or `threat_class`, so every
    # already-calibrated L4 number is unchanged.
    #
    # WHY THIS EXISTS. `score` is quantised onto {0.2, 0.5, 0.7, 0.8, 0.9,
    # 0.97, 1.0} by risk_matrix.risk_to_score plus a handful of constant
    # escalations. Measured consequences, both 2026-09-19:
    #
    #   * WARN_THRESHOLD is 0.5, so the ONLY sub-threshold value L4 can
    #     emit is LOW = 0.2 — exactly what an innocuous tool call emits.
    #     Malicious and benign low-risk calls are therefore numerically
    #     identical and L4's sub-threshold AUROC is 0.5 BY CONSTRUCTION,
    #     which is why SPLIT-Bench excludes it as a vector carrier.
    #   * The flagged-chunk trace is gated at fuzzy ratio 0.85, and the
    #     gate is a cliff: at ratio 0.8630 a call is CRITICAL / blocked, at
    #     0.8493 it is LOW / executed, and from 0.8493 down to 0.6575 the
    #     behaviour is completely flat (scratch/probe_l4_cliff.py). One
    #     extra character substitution in a parameter converts a block into
    #     an execution, and the similarity evidence below the gate is
    #     discarded entirely.
    #
    # Both are the same defect as L5's quantised output: evidence destroyed
    # at a layer interface before any consumer can weigh it. These fields
    # carry it across instead. Same shape as L5.provenance_best_ratio.

    # Best fuzzy-match ratio between ANY parameter value and ANY flagged
    # RAG chunk, recorded whether or not it cleared FUZZY_MATCH_THRESHOLD.
    # This is the quantity the cliff throws away.
    max_flagged_chunk_ratio: float = 0.0
    # Lowest per-parameter provenance confidence (1.0 when there are no
    # parameters). `authorization_source` collapses this to three strings;
    # the underlying value is continuous via the fuzzy-match ratio and the
    # matched chunk's trust score.
    min_provenance_confidence: float = 1.0
    # Noisy-OR aggregate of the continuous evidence above with the risk
    # ordinal and the reasoning-flag count, in [0, 1]. Monotone in each
    # component and free of fitted constants, so it is a defensible
    # ordering — NOT a calibrated probability of attack, which would need
    # a base rate this system cannot know.
    confidence: float = 0.0
    # L4_PROVENANCE_POLICY="action" (2026-09-25): the action-authorisation evidence --
    # capability, whether the user requested the action, sink parameters and where each
    # came from. Empty under the legacy / source_trust ladders.
    action: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "action": self.action,
            "score": self.score,
            "threat_class": self.threat_class,
            "authorization_source": self.authorization_source,
            "risk_level": self.risk_level,
            "should_execute": self.should_execute,
            "reason": self.reason,
            "provenance": self.provenance,
            "max_flagged_chunk_ratio": self.max_flagged_chunk_ratio,
            "min_provenance_confidence": self.min_provenance_confidence,
            "confidence": self.confidence,
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
    # Phase 2.3 (2026-09-14): provenance-based leak findings (layer5.py's
    # _provenance_leak_findings) were previously only visible folded into
    # `reason`'s human-readable string, with no way to tell "a leak was
    # found via provenance" apart from "a policy violation was found" from
    # outside layer5.py — needed to report leak-detection precision
    # separately from policy-compliance precision (see
    # SENTINEL_COMPLETE_RESULTS_RECORD.md B.8). Purely additive: doesn't
    # change threat_score/threat_class composition.
    provenance_findings: list[str] = field(default_factory=list)
    # Phase 5 Stage 0a / 3B.5 (2026-09-18): `score` blends two mechanisms
    # that answer different questions — "did this output disclose
    # something it shouldn't have" (exfil + PII regex + provenance) and
    # "does this output comply with the configured output policy"
    # (policy_verifier). Measured on AgentLeak, the policy signal fires on
    # 3.31% of benign and 3.62% of malicious samples — near-identical
    # rates, i.e. it carries almost no information about leakage, because
    # that corpus has no compliance labels at all. Blended into one scalar,
    # neither question can be thresholded or reported independently.
    #
    # These two fields expose the components. `score` is UNCHANGED and
    # remains exactly max(leak_score, policy_score), so no already-cited
    # aggregate number moves — this is an architectural split, not a
    # recomposition. See SENTINEL_COMPLETE_RESULTS_RECORD.md B.8.
    leak_score: float = 0.0
    policy_score: float = 0.0
    # Continuous strength of the best provenance match seen, INCLUDING
    # near-misses that did not clear the match bar. Purely diagnostic: it
    # feeds no decision and changes no score.
    #
    # Added 2026-09-18 after Contribution E's E-2 measurement found L5's
    # sub-threshold AUROC to be exactly 0.5000 on AgentLeak — not because
    # L5 lacks information below its threshold, but because its emitted
    # score is quantised (0.0, or a 0.55/0.6 floor), so every
    # below-threshold sample ties at 0.0 and no ranking survives. A
    # score-fusion rule therefore cannot use L5 at all in its current
    # form. This exposes the underlying continuous evidence so it can.
    provenance_best_ratio: float = 0.0
    # Phase 5 (2026-09-19): CONTINUOUS confidence, the same addition made
    # to L4Result the same day and for the same measured reason. Purely
    # additive — `score`, `threat_class` and every threshold decision are
    # unchanged, so no already-cited L5 number moves.
    #
    # `score` is quantised to {0.0, 0.55, 0.6, ...}, and WARN_THRESHOLD is
    # 0.5, so the only sub-threshold value L5 can emit is 0.0. Every
    # sub-threshold sample ties and L5's sub-threshold AUROC is 0.5 BY
    # CONSTRUCTION — measured at exactly 0.5000 on AgentLeak (Contribution
    # E, E-2). This field carries the evidence across that interface
    # instead: a noisy-OR over exfiltration score, PII count, policy
    # violation count and provenance match ratio, all of which layer5.py
    # already computes and then collapses into a constant floor.
    confidence: float = 0.0

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "leak_score": self.leak_score,
            "policy_score": self.policy_score,
            "provenance_best_ratio": self.provenance_best_ratio,
            "confidence": self.confidence,
            "threat_class": self.threat_class,
            "pii_findings": self.pii_findings,
            "exfil_score": self.exfil_score,
            "policy_violations": self.policy_violations,
            "reason": self.reason,
            "provenance_findings": self.provenance_findings,
        }

