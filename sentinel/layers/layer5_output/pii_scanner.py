import re

PII_PATTERNS = {
    "credit_card":    r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b",
    "ssn":            r"\b\d{3}-\d{2}-\d{4}\b",
    "email":          r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    "phone_in":       r"\b[6-9]\d{9}\b",
    "aadhaar":        r"\b[2-9]{1}[0-9]{11}\b",
    "pan":            r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b",
    "api_key":        r"\b(sk-|pk_|rk_|AIza|ghp_)[A-Za-z0-9_\-]{12,}\b",
    "jwt_token":      r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b",
}


def scan_for_pii(text: str) -> tuple[list[dict], str]:
    """
    Scan text for PII.
    Returns: (list of findings, sanitized_text)

    Fixed from the previous implementation: matches for each PII type used to
    be found by re-scanning the text *after* earlier types had already
    redacted their matches — meaning each finding's recorded `position` was
    an offset into a different intermediate string each time, not into
    either the original text or the final sanitized text. Any caller trying
    to map a finding's `position` back to a span of the original text would
    get the wrong span for every type after the first. This version finds
    all matches against the original text in a single pass, resolves
    overlaps once, and only then builds the sanitized text — so every
    reported `position` is consistently an offset into the original input.
    """
    if not text:
        return [], text

    candidates = []
    for pii_type, pattern in PII_PATTERNS.items():
        for match in re.finditer(pattern, text):
            candidates.append((match.start(), match.end(), pii_type))

    # Resolve overlaps: sort by start (then by longest span first for ties),
    # and greedily keep non-overlapping matches. This prevents two pattern
    # types that happen to overlap on the same span (e.g. a digit run that
    # partially matches two different numeric PII types) from both trying to
    # redact the same characters.
    candidates.sort(key=lambda c: (c[0], -(c[1] - c[0])))

    accepted = []
    last_end = -1
    for start, end, pii_type in candidates:
        if start >= last_end:
            accepted.append((start, end, pii_type))
            last_end = end

    findings = []
    for start, end, pii_type in accepted:
        findings.append({
            "type": pii_type,
            "position": (start, end),
            "redacted_value": f"[{pii_type.upper()}_REDACTED]",
        })

    # Build sanitized text by replacing accepted spans from end to start, so
    # earlier positions stay valid as we go.
    sanitized_text = text
    for start, end, pii_type in sorted(accepted, key=lambda c: c[0], reverse=True):
        sanitized_text = sanitized_text[:start] + f"[{pii_type.upper()}_REDACTED]" + sanitized_text[end:]

    return findings, sanitized_text
