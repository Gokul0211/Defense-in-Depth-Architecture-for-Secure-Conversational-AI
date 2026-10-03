"""
Shared, computed verdicts for events that are NOT produced by app.py's request
paths: demo scenarios, the image-steganography scan, RAG ingest/upload events and
the raw L1 scan endpoint.

Every severity, action and explanation-chain entry built here is derived from a
layer's actual result and the configured thresholds -- never a hardcoded label.
The input-side rule is the same one `/sentinel/chat` applies: per-layer scores
rescaled onto the shared WARN/BLOCK axis, then `pipeline_decision`.
"""
from __future__ import annotations

from sentinel.core.models import score_to_severity, rescale_layer_score
import sentinel.config as cfg

ACTION_BY_DECISION = {"BLOCK": "BLOCKED", "WARN": "WARNED", "ALLOW": "ALLOWED"}
CHAIN_ACTION = {"BLOCKED": "BLOCK", "WARNED": "WARN", "ALLOWED": "ALLOW"}

L1_TIER_LABELS = {
    1: "Tier 1 regex",
    2: "Tier 2 semantic",
    3: "Tier 3 classifier (Prompt Guard x PIGuard)",
    4: "Tier 4 policy judge",
}


def l1_tier_label(tier_used: int | None) -> str:
    """Human label for the L1 tier that produced the final score."""
    return L1_TIER_LABELS.get(tier_used or 0, f"Tier {tier_used}")


def shared_action(shared_score: float) -> str:
    """BLOCKED / WARNED / ALLOWED for a score already on the shared axis."""
    return ACTION_BY_DECISION[cfg.pipeline_decision({"score": shared_score})]


def l1_shared(l1_result) -> float:
    """L1's injection score on the shared axis (same rescale as app.py)."""
    return rescale_layer_score(l1_result.score, cfg.l1_warn_threshold(), cfg.L1_BLOCK_THRESHOLD,
                               cfg.WARN_THRESHOLD, cfg.BLOCK_THRESHOLD)


def l3_shared(l3_result) -> float:
    """L3's score on the shared axis (same rescale as app.py)."""
    return rescale_layer_score(l3_result.score, cfg.l3_warn_threshold(), cfg.l3_block_threshold(),
                               cfg.WARN_THRESHOLD, cfg.BLOCK_THRESHOLD)


def l1_chain_item(l1_result, shared: float | None = None) -> dict:
    shared = l1_shared(l1_result) if shared is None else shared
    return {
        "layer": "L1",
        "severity": score_to_severity(l1_result.score),
        "finding": f"Input Scanner ({l1_tier_label(l1_result.tier_used)}): {l1_result.threat_class}",
        "evidence": l1_result.reason,
        "action": CHAIN_ACTION[shared_action(shared)],
    }


def l3_chain_item(l3_result, shared: float | None = None) -> dict:
    shared = l3_shared(l3_result) if shared is None else shared
    return {
        "layer": "L3",
        "severity": score_to_severity(shared),
        "finding": (f"Drift Tracker: velocity={l3_result.semantic_velocity:.3f}, "
                    f"drift={l3_result.cumulative_drift:.3f}, harm_alignment={l3_result.harm_alignment:.3f}, "
                    f"turn={l3_result.turn_count}"),
        "evidence": l3_result.reason,
        "action": CHAIN_ACTION[shared_action(shared)],
    }


def input_verdict(l1_result=None, l3_result=None) -> dict:
    """The /sentinel/chat input rule for a user turn: L1 (+ harm head) and L3 on the
    shared axis, combined by `pipeline_decision`. Returns score, severity, action,
    dominant layer, reason and the explanation chain."""
    scores: dict[str, float] = {}
    chain: list[dict] = []
    reasons: dict[str, str] = {}
    if l1_result is not None:
        s1 = l1_shared(l1_result)
        scores["L1"] = s1
        harm = cfg.l1_harm_shared(getattr(l1_result, "harm_score", None))
        if harm:
            scores["L1H"] = harm
        reasons["L1"] = l1_result.reason
        if l1_result.score > 0.1:
            chain.append(l1_chain_item(l1_result, s1))
    if l3_result is not None:
        s3 = l3_shared(l3_result)
        scores["L3"] = s3
        reasons["L3"] = l3_result.reason
        if l3_result.score > 0.1:
            chain.append(l3_chain_item(l3_result, s3))
    combined = max(scores.values()) if scores else 0.0
    dominant_key = max(scores, key=scores.get) if scores else "L1"
    dominant = "L1" if dominant_key == "L1H" else dominant_key
    action = ACTION_BY_DECISION[cfg.pipeline_decision(scores)]
    return {
        "score": combined,
        "severity": score_to_severity(combined),
        "action": action,
        "dominant": dominant,
        "reason": reasons.get(dominant, ""),
        "chain": chain,
    }


def l2_ingest_verdict(result: dict, source: str) -> dict:
    """Score, severity, action and chain for a `layer2_ingest` result, on the
    shared axis of the Mondrian bin that scored it (`l2_shared_score`)."""
    meta = result.get("metadata", {}) or {}
    shared = cfg.l2_shared_score(meta)
    if result.get("quarantined"):
        action, chain_action = "QUARANTINED", "QUARANTINE"
    elif result.get("review_flagged"):
        action, chain_action = "FLAGGED", "FLAG_FOR_REVIEW"
    else:
        action, chain_action = "ALLOWED", "ALLOW"
    trust = float(meta.get("trust_score", 1.0))
    density = meta.get("instruction_density")
    density_txt = f", instruction_density={density:.2f}" if isinstance(density, (int, float)) else ""
    return {
        "score": shared,
        "severity": score_to_severity(shared),
        "action": action,
        "chain": [{
            "layer": "L2",
            "severity": score_to_severity(shared),
            "finding": f"Chunk from '{source}': trust_score={trust:.2f}{density_txt}",
            "evidence": result.get("reason", ""),
            "action": chain_action,
        }],
    }


def l4_verdict(l4_result) -> dict:
    """Severity/action for an L4 audit, matching /sentinel/agent/tool_call."""
    if not l4_result.should_execute:
        action = "BLOCKED"
    elif l4_result.score >= cfg.L4_WARN_THRESHOLD:
        action = "WARNED"
    else:
        action = "ALLOWED"
    item = {
        "layer": "L4",
        "severity": score_to_severity(l4_result.score),
        "finding": f"Agentic Auditor: {l4_result.threat_class} (authorization: {l4_result.authorization_source})",
        "evidence": l4_result.reason,
        "action": CHAIN_ACTION.get(action, action),
    }
    return {"score": l4_result.score, "severity": score_to_severity(l4_result.score),
            "action": action, "chain": [item]}


def l5_verdict(l5_result) -> dict:
    """Severity/action for an L5 scan, matching /sentinel/chat (BLOCK at the shared
    BLOCK threshold), with one chain entry per finding the layer actually made."""
    action = shared_action(l5_result.score)
    chain: list[dict] = []
    if l5_result.exfil_score > 0:
        chain.append({"layer": "L5", "severity": score_to_severity(l5_result.exfil_score),
                      "finding": f"Exfiltration evidence (exfil_score={l5_result.exfil_score:.2f})",
                      "evidence": l5_result.reason, "action": CHAIN_ACTION[action]})
    if l5_result.pii_findings:
        types = sorted({str(f.get("type", "pii")) for f in l5_result.pii_findings if isinstance(f, dict)})
        chain.append({"layer": "L5", "severity": score_to_severity(l5_result.leak_score),
                      "finding": f"PII redacted: {len(l5_result.pii_findings)} ({', '.join(types) or 'unknown type'})",
                      "action": "REDACT"})
    for finding in l5_result.provenance_findings:
        chain.append({"layer": "L5", "severity": score_to_severity(l5_result.leak_score),
                      "finding": finding, "action": "REDACT"})
    for violation in l5_result.policy_violations:
        chain.append({"layer": "L5", "severity": score_to_severity(l5_result.policy_score),
                      "finding": f"Policy: {violation}", "action": CHAIN_ACTION[action]})
    return {"score": l5_result.score, "severity": score_to_severity(l5_result.score),
            "action": action, "chain": chain}


def steg_verdict(steg_result: dict, filename: str | None = None) -> dict:
    """Severity/action/chain for `layer1_steg_scan`, matching /sentinel/l1/scan-image."""
    score = max(float(steg_result.get("chi_score", 0.0)), float(steg_result.get("l1_score", 0.0)))
    action = "BLOCKED" if steg_result.get("is_malicious") else "ALLOWED"
    chi = float(steg_result.get("chi_score", 0.0))
    decoded = steg_result.get("decoded_text") or ""
    chain = [{
        "layer": "L1",
        "severity": score_to_severity(chi),
        "finding": f"LSB chi-square suspicion: {chi:.2f}" + (f" ({filename})" if filename else ""),
        "action": "ANALYZE",
    }, {
        "layer": "L1",
        "severity": score_to_severity(score),
        "finding": steg_result.get("reason", ""),
        "evidence": f"Decoded: '{decoded[:80]}'" if decoded else "No payload decoded",
        "action": CHAIN_ACTION[action],
    }]
    return {"score": score, "severity": score_to_severity(score), "action": action, "chain": chain}


def thresholds() -> dict:
    """Live warn/block thresholds per layer, read from the running configuration."""
    return {
        "shared_axis": {"warn": cfg.WARN_THRESHOLD, "block": cfg.BLOCK_THRESHOLD},
        "L1": {"warn": cfg.l1_warn_threshold(), "block": cfg.L1_BLOCK_THRESHOLD,
               "conformal_alpha": cfg.L1_CONFORMAL_ALPHA, "judge_enabled": cfg.L1_LLM_JUDGE_ENABLED},
        "L1H": {"warn": cfg.L1_HARM_TAU, "may_block": cfg.L1_HARM_MAY_BLOCK,
                "block": cfg.L1_HARM_BLOCK_TAU},
        "L2": {
            "legacy": {"warn": cfg.L2_WARN_THRESHOLD, "block": cfg.L2_BLOCK_THRESHOLD},
            "document": {"warn": cfg.L2_DOCUMENT_THREAT_WARN_THRESHOLD, "block": cfg.L2_BLOCK_THRESHOLD},
            "code": {"warn": cfg.L2_DOCUMENT_THREAT_WARN_THRESHOLD_CODE,
                     "block": max(cfg.L2_BLOCK_THRESHOLD, cfg.L2_DOCUMENT_THREAT_BLOCK_THRESHOLD_CODE)},
            "short": {"warn": cfg.L2_DOCUMENT_THREAT_WARN_THRESHOLD_SHORT,
                      "block": cfg.L2_DOCUMENT_THREAT_BLOCK_THRESHOLD_SHORT},
        },
        "L3": {"warn": cfg.l3_warn_threshold(), "block": cfg.l3_block_threshold()},
        "L4": {"warn": cfg.L4_WARN_THRESHOLD, "block": cfg.L4_BLOCK_THRESHOLD},
        "L5": {"warn": cfg.WARN_THRESHOLD, "block": cfg.BLOCK_THRESHOLD},
    }
