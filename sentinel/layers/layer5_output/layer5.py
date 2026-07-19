from sentinel.core.models import L5Result
from .pii_scanner import scan_for_pii
from .exfil_detector import detect_exfiltration
from .policy_verifier import verify_policy
from sentinel.config import CANARY_TOKEN

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
        return L5Result(0.0, "CLEAN", [], 0.0, [], "Empty response"), response_text
        
    reasons = []
    
    # 1. PII Scan
    pii_findings, sanitized_text = scan_for_pii(response_text)
    if pii_findings:
        reasons.append(f"Redacted {len(pii_findings)} PII instances")
        
    # 2. Exfiltration Scan
    exfil_score, exfil_evidence = detect_exfiltration(sanitized_text, system_prompt)
    if exfil_evidence:
        reasons.extend(exfil_evidence)
        
    # Redact canary token if present
    if CANARY_TOKEN in sanitized_text:
        sanitized_text = sanitized_text.replace(CANARY_TOKEN, "[CANARY_REDACTED]")
        
    # 3. Policy Verification
    policy_violations = verify_policy(sanitized_text)
    if policy_violations:
        reasons.extend(policy_violations)
        
    # Calculate overall threat score
    threat_score = exfil_score
    if pii_findings:
        threat_score = max(threat_score, 0.4) # Medium risk for finding PII
    if policy_violations:
        threat_score = max(threat_score, 0.6) # High risk for policy violations
        
    threat_class = "CLEAN"
    if exfil_score >= 0.8:
        threat_class = "OUTPUT_EXFILTRATION"
    elif policy_violations:
        threat_class = "POLICY_VIOLATION"
    elif pii_findings:
        threat_class = "PII_LEAK"
        
    reason_str = " | ".join(reasons) if reasons else "Response clean."
    
    result = L5Result(
        score=threat_score,
        threat_class=threat_class,
        pii_findings=pii_findings,
        exfil_score=exfil_score,
        policy_violations=policy_violations,
        reason=reason_str
    )
    
    return result, sanitized_text

