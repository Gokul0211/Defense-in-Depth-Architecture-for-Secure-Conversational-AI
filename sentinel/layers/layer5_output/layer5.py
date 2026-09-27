from sentinel.core.models import L5Result
from .pii_scanner import scan_for_pii, BASE64_CANDIDATE_PATTERN, try_decode_base64
from .exfil_detector import detect_exfiltration
from .policy_verifier import verify_policy
from sentinel.config import CANARY_TOKEN
from sentinel.layers.layer4_agentic.provenance_tracker import fuzzy_contains, MIN_TRACEABLE_LEN
from sentinel.core.sensitive_value_extractor import match_policy_for

# Score floors, named rather than left as literals scattered through
# _compose_scores below (Phase 5 Stage 0a / 3B.5).
#
# LEAK_EVIDENCE_SCORE: the floor a concrete leak finding (a PII regex
# match or a provenance match) puts under the leak score. Previously 0.4,
# which sat BELOW WARN_THRESHOLD (0.50) — meaning a correctly-detected
# leak could never register as even a WARN-level event, regardless of how
# confident the match was. Exposed empirically: an evaluation run against
# a real PII corpus showed the scanner correctly identifying PII while
# recall at any sane threshold stayed near zero, because 0.4 was
# mathematically unreachable-to-WARN by construction. Redaction happens
# regardless of this score (see sanitized_text below), but the score
# should still reflect that something worth surfacing was found. 0.55 is
# still a placeholder pending the ROC-based calibration described in the
# evaluation plan doc, chosen only to sit just above WARN_THRESHOLD.
LEAK_EVIDENCE_SCORE = 0.55

# POLICY_VIOLATION_SCORE: the floor an output-policy violation puts under
# the policy score. Higher than LEAK_EVIDENCE_SCORE for historical
# reasons, NOT because policy findings are more reliable — measured on
# AgentLeak they are considerably less so (precision 0.2882 vs. 0.8805).
# Left unchanged here deliberately: re-tuning it against AgentLeak would
# be fitting a compliance checker to a corpus with no compliance labels,
# the same overfitting error Phase 2.2 and Phase 2.4 correctly rejected.
# It needs its own labelled corpus, which does not currently exist.
POLICY_VIOLATION_SCORE = 0.6

# Exfil score at or above which the finding is classified as outright
# output exfiltration rather than a leak. Was an inline 0.8.
OUTPUT_EXFILTRATION_THRESHOLD = 0.8


def _provenance_leak_findings(
    response_text: str, tracked_values: list[str]
) -> tuple[list[str], float]:
    """
    Check whether `response_text` discloses any candidate sensitive value
    seen earlier this session (RAG documents / tool responses) — closes
    L5's blind spots that regex PII_PATTERNS structurally can't cover
    (see sensitive_value_extractor.py's module docstring: free-text names
    have no fixed format; the legal/finance identifier categories have no
    shared one either). Reuses L4's fuzzy_contains (provenance_tracker.py)
    — the same "does this value trace back to something we saw" idea,
    pointed at output instead of input.

    The match rule is chosen PER VALUE, not globally (2026-09-18, 3B.4):
    names fuzzy-match, identifiers must match exactly. See
    sensitive_value_extractor.match_policy_for for why — in short, an
    identifier one character off is a different identifier, and digit
    strings of the same shape sit far above fuzzy_contains' 0.85 ratio,
    so a single global fuzzy policy would spend the recall this check
    gained on false positives in exactly the categories it was extended
    to catch.
    """
    findings = []
    # Best match strength seen, kept as a CONTINUOUS value (Phase 5,
    # Contribution E's E-2 measurement). L5's thresholded score is
    # quantised — 0.0, or a floor of 0.55/0.6 — so its sub-threshold AUROC
    # on AgentLeak is exactly 0.5000: every below-threshold sample ties at
    # 0.0 and no ranking is possible. That is not missing information, it
    # is information destroyed at the interface, so nothing downstream
    # (least of all a score-fusion rule) can recover it. Exposing the
    # underlying ratio costs nothing and does not touch any decision.
    best_ratio = 0.0
    seen = set()
    haystack_lower = response_text.lower()
    for value in tracked_values:
        if len(value) < MIN_TRACEABLE_LEN or value in seen:
            continue
        seen.add(value)

        if match_policy_for(value) == "exact":
            # Case-insensitive exact containment. An identifier is only a
            # disclosure if it appears as written; no sliding window, which
            # also keeps this cheap now that a session can track many more
            # values than it used to.
            if value.lower() in haystack_lower:
                findings.append(
                    f"Output contains '{value}', seen earlier in retrieved/tool content (exact match)"
                )
                best_ratio = 1.0
            continue

        matched, ratio = fuzzy_contains(value.lower(), haystack_lower)
        # Track the best ratio whether or not it cleared the match bar —
        # a near-miss is exactly the sub-threshold evidence fusion needs,
        # and discarding it is the defect this field exists to fix.
        best_ratio = max(best_ratio, ratio)
        if matched:
            findings.append(f"Output mentions '{value}', seen earlier in retrieved/tool content (match_ratio={ratio:.2f})")
    return findings, best_ratio


def _canary_leaked(text: str) -> bool:
    """Check for the canary token both in plaintext and hidden inside a
    base64-encoded span — a model (or attacker) forced to redact/obfuscate
    the token still leaks it if it emits it encoded rather than verbatim."""
    if CANARY_TOKEN in text:
        return True
    for match in BASE64_CANDIDATE_PATTERN.finditer(text):
        decoded = try_decode_base64(match.group(0))
        if decoded and CANARY_TOKEN in decoded:
            return True
    return False

async def layer5_scan_output(
    response_text: str,
    system_prompt: str | None,
    session_id: str,
) -> tuple[L5Result, str]:
    """
    Scan an LLM response before sending it to the user.
    Returns: (L5Result, sanitized_response_text)
    """
    if not response_text:
        return L5Result(0.0, "CLEAN", [], 0.0, [], "Empty response", []), response_text
        
    reasons = []
    
    # 1. PII Scan
    pii_findings, sanitized_text = scan_for_pii(response_text)
    if pii_findings:
        reasons.append(f"Redacted {len(pii_findings)} PII instances")
        
    # 2. Exfiltration Scan
    exfil_score, exfil_evidence = detect_exfiltration(sanitized_text, system_prompt)
    if exfil_evidence:
        reasons.extend(exfil_evidence)

    # Canary check — plaintext or base64-obfuscated (see _canary_leaked)
    if _canary_leaked(sanitized_text):
        exfil_score = 1.0
        reasons.append("CRITICAL: System prompt canary token leaked in output (possibly obfuscated)!")
        sanitized_text = sanitized_text.replace(CANARY_TOKEN, "[CANARY_REDACTED]")
        # Also strip any base64 span that decodes to the canary token
        for match in list(BASE64_CANDIDATE_PATTERN.finditer(sanitized_text)):
            decoded = try_decode_base64(match.group(0))
            if decoded and CANARY_TOKEN in decoded:
                sanitized_text = sanitized_text.replace(match.group(0), "[CANARY_REDACTED_B64]")
        
    # 3. Policy Verification
    policy_violations = verify_policy(sanitized_text)
    if policy_violations:
        reasons.extend(policy_violations)

    # 4. Provenance-based leak check — closes the free-text name-disclosure
    # gap regex PII_PATTERNS structurally can't cover (see
    # _provenance_leak_findings's docstring). Session lookup is local to
    # avoid a module-level circular import (threat_bus -> core.models,
    # nothing pulls in layer5_output, but importing at call time keeps
    # this file's import graph simple and matches how session lookups are
    # already done at the app.py call sites, not inside layer functions).
    from sentinel.core.threat_bus import threat_bus
    session = await threat_bus.get_session(session_id)
    provenance_findings, provenance_best_ratio = _provenance_leak_findings(
        sanitized_text, session.tracked_sensitive_values
    )
    if provenance_findings:
        reasons.extend(provenance_findings)

    # Compose the two component scores separately, then blend.
    #
    # LEAK score — "did this output disclose something it shouldn't have."
    # Exfiltration, PII regex matches, and provenance matches are all
    # evidence for the same proposition, so they share one score. A
    # provenance match sits at the same severity tier as a PII regex match
    # deliberately: it is the same kind of evidence (a real value that
    # shouldn't be here), just matched via provenance instead of format.
    leak_score = exfil_score
    if pii_findings or provenance_findings:
        leak_score = max(leak_score, LEAK_EVIDENCE_SCORE)

    # POLICY score — "does this output comply with the configured output
    # policy." A different question with a different ground truth, kept on
    # its own axis so a deployment can give it its own budget instead of
    # spending the leak detector's (see L5Result's field comment for the
    # measured reason this matters).
    policy_score = POLICY_VIOLATION_SCORE if policy_violations else 0.0

    # Blended score, for the single-number consumers (app.py's
    # BLOCK/WARN decision, the eval harness's aggregate metrics). This is
    # EXACTLY the previous composition — max over every mechanism — so
    # splitting the components moves no already-published number.
    threat_score = max(leak_score, policy_score)

    # Threat-class attribution, most severe first.
    #
    # BUG FIX (2026-09-18, Phase 5 Stage 0a / 3B.5): `policy_violations`
    # used to be checked BEFORE `pii_findings or provenance_findings`, so
    # any output carrying both a genuine leak AND a policy violation was
    # labelled POLICY_VIOLATION and the leak was masked entirely. Measured
    # on AgentLeak: 60 samples have both signals, 47 of them malicious.
    # This is not cosmetic — app.py emits threat_class as the ThreatEvent's
    # threat_type (app.py:344) and returns it in the blocked-response body
    # (app.py:355), so 47 real leaks were being surfaced to an operator
    # under the label of the least precise mechanism in the layer
    # (policy precision 0.2882 vs. leak precision 0.8805 on that corpus).
    # Leak evidence now outranks policy; exfiltration's position at the top
    # of the ladder is unchanged.
    threat_class = "CLEAN"
    if exfil_score >= OUTPUT_EXFILTRATION_THRESHOLD:
        threat_class = "OUTPUT_EXFILTRATION"
    elif pii_findings or provenance_findings:
        threat_class = "PII_LEAK"
    elif policy_violations:
        threat_class = "POLICY_VIOLATION"

    reason_str = " | ".join(reasons) if reasons else "Response clean."

    result = L5Result(
        score=threat_score,
        threat_class=threat_class,
        pii_findings=pii_findings,
        exfil_score=exfil_score,
        policy_violations=policy_violations,
        reason=reason_str,
        provenance_findings=provenance_findings,
        leak_score=leak_score,
        policy_score=policy_score,
        provenance_best_ratio=provenance_best_ratio,
        confidence=_continuous_confidence(
            exfil_score=exfil_score,
            n_pii=len(pii_findings),
            n_policy=len(policy_violations),
            provenance_best_ratio=provenance_best_ratio,
        ),
    )
    
    return result, sanitized_text


def _evidence_terms(
    exfil_score: float,
    n_pii: int,
    n_policy: int,
    provenance_best_ratio: float,
) -> dict[str, float]:
    """
    L5's four evidence sources, each as a probability-like value in [0, 1).

    Every one of these is ALREADY computed above and then discarded into a
    floor: `leak_score` collapses exfiltration, PII count and provenance
    into the constant 0.55 the moment any of them fires, and `policy_score`
    collapses the whole policy verifier into 0.6. So a single PII match and
    an output leaking six tracked values are numerically identical
    downstream, and a provenance match at ratio 0.62 is identical to one at
    0.99.
    """
    from sentinel.core.evidence import saturating_count

    return {
        # Already continuous; the only component that survived the floor.
        "exfiltration": exfil_score,
        "pii": saturating_count(n_pii),
        "policy": saturating_count(n_policy),
        "provenance": provenance_best_ratio,
    }


def _continuous_confidence(
    exfil_score: float,
    n_pii: int,
    n_policy: int,
    provenance_best_ratio: float,
) -> float:
    """
    L5's continuous confidence, in [0, 1). PURELY ADDITIVE — `score`,
    `threat_class` and every threshold decision are untouched.

    WHY. `layer5.py` emits a quantised score: 0.0 when nothing fires, else
    a floor of 0.55 (leak) or 0.6 (policy). `WARN_THRESHOLD` is 0.5, so the
    ONLY sub-threshold value L5 can emit is 0.0 — every sub-threshold
    sample ties and L5's sub-threshold AUROC is 0.5 by construction.
    Measured at exactly **0.5000** on AgentLeak (Contribution E, E-2,
    n_sub = 167 malicious / 3382 benign). That is why SPLIT-Bench excludes
    L5 as a vector carrier, and it is the `[ACTIONABLE]` item E-2 raised.

    Aggregation is `core.evidence.noisy_or`, the same function L4 uses —
    both layers have the same defect and the same fix, so the machinery is
    shared rather than duplicated.
    """
    from sentinel.core.evidence import noisy_or

    return noisy_or(
        _evidence_terms(exfil_score, n_pii, n_policy, provenance_best_ratio)
    )

