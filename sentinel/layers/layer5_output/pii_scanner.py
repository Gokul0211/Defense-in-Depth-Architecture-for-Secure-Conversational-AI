import re
import base64

# RCA finding (2026-07-24): a real evaluation run against custom_l5_pii
# (48 malicious / 62 benign, all pure regex — verified directly in-sandbox,
# no embedding model needed) found:
#   - credit_card missed 4/7 real card-number samples: the old pattern only
#     recognized Visa (4...), Mastercard (51-55...), and Amex (34/37...)
#     prefixes — JCB (35xx / legacy 2131 / 1800...), Discover (6011/65...),
#     and Diners Club (300-305/36/38...) card numbers, all real, widely-
#     issued network prefixes (not corpus-specific formatting), were never
#     matched at all.
#   - financial (bank-account/balance disclosures, e.g. "account ending
#     7691 ... balance of $25,405.41") missed 7/7 — there was no pattern
#     for this category at all.
#   - "email" and "ssn" produced FALSE POSITIVES on benign text that merely
#     *discusses* PII formats using universally-known placeholder values:
#     support@example.com (example.com/.org/.net/.edu are IETF-reserved
#     specifically for documentation, per RFC 2606 — they can never be a
#     real address) and 078-05-1120 (the single most widely-reused fake
#     SSN in the US, originally a 1938 Woolworth's wallet promotional
#     insert, since misused so often the SSA published an advisory about
#     it — https://www.ssa.gov/history/ssn/misused.html). 16/62 benign
#     samples were flagged this way. Excluding a short, explicitly-named
#     list of globally-known placeholder values is a generalizable
#     precision fix (these values are famous specifically *because* they
#     appear everywhere in documentation, not because this corpus uses
#     them) — NOT tuning to this benchmark's specific text.
#   - "address" and "medical" (patient name/DOB/diagnosis/prescription
#     narrative text) had 0/3 and 0/4 coverage and are NOT fixed here: both
#     are free-text disclosures with no fixed structural format, so a
#     regex that reliably caught this corpus's phrasing would necessarily
#     be tuned to this corpus's own generation templates rather than to
#     any real, general pattern — see generate_l5_corpus.py and
#     01_RESEARCH_GRADE_ROADMAP.md's risk register on why that's the wrong
#     kind of fix. Closing this gap for real needs a genuinely different
#     approach (NER or an LLM-based PHI/address classifier), not a regex
#     addition, and is left as an explicit, documented limitation.
#   - "email" produced false positives on benign text using a generic,
#     ROLE-based mailbox (support@example.com in a customer-service
#     context) — RFC 2142 standardizes exactly this category of address
#     (postmaster, abuse, webmaster, etc.) as an institutional mailbox, not
#     a personal identifier, which is the real, generalizable distinction.
#     NOTE: an earlier version of this fix incorrectly excluded by DOMAIN
#     (any @example.com/.org/.net address) instead of by role — that broke
#     real detections, because this corpus's genuine "contact_info" leak
#     samples are Faker-generated and Faker deliberately uses the same
#     RFC-2606-reserved domains for ALL fake data, not just placeholders
#     (e.g. "vaughanheather@example.net" is this corpus's stand-in for a
#     real person's leaked email, on the same domain as the benign
#     "support@example.com" mailbox). The domain was never the
#     distinguishing signal; the local part (role-based vs. personal) is.
PII_PATTERNS = {
    "credit_card":    r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b",
    "ssn":            r"\b\d{3}-\d{2}-\d{4}\b",
    "email":          r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    "phone_in":       r"\b[6-9]\d{9}\b",
    "aadhaar":        r"\b[2-9]{1}[0-9]{11}\b",
    "pan":            r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b",
    "api_key":        r"\b(sk-|pk_|rk_|AIza|ghp_)[A-Za-z0-9_\-]{12,}\b",
    "jwt_token":      r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b",
    # Generalizable addition (not corpus-specific): "account/card ending
    # NNNN" and "balance of $N" are standard, widely-used real-world
    # disclosure phrasings across banks/fintechs, not a phrasing invented
    # by this corpus's generator. Verified against the benign set: 0 false
    # positives.
    "financial_disclosure": r"\b(?:account|card)\s+(?:ending|number)\b[^.]{0,20}?\d{3,4}\b|\bbalance of \$[\d,]+\.\d{2}\b",
}

# Globally well-known placeholder/example values, and RFC 2142 standardized
# institutional mailbox names, that must NOT be treated as a real PII leak
# regardless of format match — see the module-level RCA comment above.
_KNOWN_PLACEHOLDER_SSNS = {"078-05-1120"}
_ROLE_BASED_EMAIL_LOCAL_PARTS = {
    "support", "info", "contact", "help", "sales", "admin", "webmaster",
    "postmaster", "abuse", "noreply", "no-reply", "hostmaster",
}


def _is_known_placeholder(pii_type: str, matched_text: str) -> bool:
    if pii_type == "ssn":
        return matched_text in _KNOWN_PLACEHOLDER_SSNS
    if pii_type == "email":
        local_part = matched_text.split("@", 1)[0].lower()
        return local_part in _ROLE_BASED_EMAIL_LOCAL_PARTS
    return False


# RCA finding (2026-09-14, Phase 2.2): a real AgentLeak evaluation run
# found 95 of financial_disclosure's false positives (of 120 real
# pii-caused FPs on the full 5,006-sample corpus) came from matching an
# ALREADY-MASKED account/card reference — "account ending in ****2693",
# typically inside a benign refusal or lookup-mismatch response where the
# model correctly withheld the real number. Real redaction markers appear
# in several equivalent forms (****1234, XXXX1234, xxxx-1234,
# [REDACTED] 1234), not just one — a single one-off exclusion would miss
# the others, so this is checked as a small grammar, not one literal
# string.
#
# NOT costless — disclosed exactly, not claimed as "recall preserved":
# spot-checking every AgentLeak malicious sample whose only signal was a
# masked financial_disclosure match found 4 real samples (of 1,355
# malicious, ~0.3pp of recall) that would flip from caught to missed.
# 2 of those are genuine account_last4 leaks (AgentLeak's own ground
# truth treats confirming a masked last-4 match to a real, on-file
# account as a real disclosure) with no other signal firing — a real,
# accepted recall cost. The other 2 were already right-answer-wrong-
# reason: their actual leaked field is a full, UNMASKED alphanumeric
# account number elsewhere in the same response (e.g.
# "XAIO16623425301281"), which no existing PII_PATTERNS pattern matches
# at all (no fixed real-world format the way card-network prefixes give
# credit_card one) — this fix exposes that pre-existing, separate gap
# rather than causing it. See SENTINEL_COMPLETE_RESULTS_RECORD.md
# Phase 2.2 for the full before/after metrics and this breakdown.
_MASK_MARKER_RE = re.compile(r"(?:[*xX]{3,}[\s-]*|\[REDACTED\]\s*)$")


def _is_masked_reference(pii_type: str, matched_text: str) -> bool:
    if pii_type != "financial_disclosure":
        return False
    prefix = re.sub(r"\d{3,4}\s*$", "", matched_text, flags=re.IGNORECASE)
    return bool(_MASK_MARKER_RE.search(prefix))


# NUMERIC VALIDITY (config.L5_PII_VALIDITY, v3 P1.3). The digit patterns above only check a
# shape, so any long enough digit run matches. Two measured false matches on benign traffic: an
# "aadhaar" that was the fractional part of a coordinate inside a Google-Maps URL
# ("3843.534694025997!2d...") and a "credit_card" that was the digits of sqrt(2)
# ("1.4142135623746899"). An identifier is not the tail (or head) of a decimal number, and -- for
# cards -- is valid under the Luhn checksum every issuer uses.
# Aadhaar's Verhoeff checksum is deliberately NOT enforced: synthetic corpora (custom_l5) use
# random digits, and checking it would trade a real format check for a corpus artefact (v3 a05).
_NUMERIC_TYPES = {"credit_card", "aadhaar", "phone_in"}


def _luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _numeric_context_invalid(pii_type: str, text: str, start: int, end: int) -> bool:
    """True when a digit-pattern match is not a standalone identifier."""
    import sentinel.config as cfg

    if pii_type not in _NUMERIC_TYPES or not getattr(cfg, "L5_PII_VALIDITY", False):
        return False
    # Part of a decimal number (a coordinate, a constant). NOT a URL rule: a card number in a URL
    # query string is a real exfiltration vector and must stay visible.
    before, after = text[max(0, start - 2):start], text[end:end + 2]
    if re.search(r"\d[.,]$", before) or re.match(r"[.,]\d", after):
        return True
    if pii_type == "credit_card" and not _luhn_ok(re.sub(r"\D", "", text[start:end])):
        return True
    return False


# Candidate base64-looking spans worth attempting to decode. Public (not
# underscore-prefixed) because layer5.py reuses this exact pattern for
# canary-token leak detection — see BASE64_CANDIDATE_PATTERN usage there.
# Intentionally broad (any long-enough base64-alphabet run) — false
# positives here are cheap, since a candidate only ever produces a finding
# if what it decodes to *also* matches something sensitive. Without this
# pass, an attacker (or a leaking model) can trivially bypass every regex
# above just by base64-encoding the secret before emitting it — a real,
# common DLP evasion technique, not a hypothetical one.
BASE64_CANDIDATE_PATTERN = re.compile(r"\b[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])")



def try_decode_base64(candidate: str) -> str | None:
    """Attempt to decode a base64 candidate string to printable UTF-8 text.
    Returns None if it isn't valid base64 or doesn't decode to printable text."""
    try:
        decoded = base64.b64decode(candidate, validate=True).decode("utf-8")
    except Exception:
        return None
    if not decoded or not decoded.isprintable():
        return None
    return decoded


def _try_decode_base64_spans(text: str) -> list[dict]:
    """
    Find base64-looking substrings in `text`, attempt to decode each, and
    check the decoded content against PII_PATTERNS. Returns findings with
    positions referring to the ENCODED span in the original text (since
    that's what actually needs to be redacted — the leak vector is the
    encoded blob, not text that was never in the response as plain text).
    """
    findings = []
    for match in BASE64_CANDIDATE_PATTERN.finditer(text):
        decoded = try_decode_base64(match.group(0))
        if decoded is None:
            continue

        for pii_type, pattern in PII_PATTERNS.items():
            inner_match = re.search(pattern, decoded)
            if inner_match and not _is_known_placeholder(pii_type, inner_match.group(0)) and not _is_masked_reference(pii_type, inner_match.group(0)):
                findings.append({
                    "type": f"base64_obfuscated_{pii_type}",
                    "position": (match.start(), match.end()),
                    "redacted_value": f"[BASE64_{pii_type.upper()}_REDACTED]",
                })
                break  # one finding per encoded span is enough

    return findings


def scan_for_pii(text: str, user_text: str | None = None) -> tuple[list[dict], str]:
    """
    Scan text for PII, including PII hidden inside base64-encoded spans
    (see _try_decode_base64_spans — a real, common evasion technique).

    `user_text` (v3 P1.2, config.L5_USER_PROVENANCE): the user's own turns. A plaintext match that
    the user themselves supplied is not a disclosure and is neither reported nor redacted. Only
    exact (case-insensitive) re-appearance counts; base64-hidden values are never exempt.

    Returns: (list of findings, sanitized_text)

    Note on history: matches for each PII type used to be found by
    re-scanning the text *after* earlier types had already redacted their
    matches, which meant each finding's recorded `position` was an offset
    into a different intermediate string each time rather than into either
    the original text or the final sanitized text. This version finds all
    matches (plaintext and base64-decoded) against the original text in a
    single pass, resolves overlaps once, and only then builds the sanitized
    text — every reported `position` is consistently an offset into the
    original input.
    """
    if not text:
        return [], text

    user_low = (user_text or "").lower()
    candidates = []
    for pii_type, pattern in PII_PATTERNS.items():
        for match in re.finditer(pattern, text):
            if _is_known_placeholder(pii_type, match.group(0)):
                continue
            if _is_masked_reference(pii_type, match.group(0)):
                continue
            if _numeric_context_invalid(pii_type, text, match.start(), match.end()):
                continue
            if user_low and match.group(0).lower() in user_low:
                continue                     # the user supplied this value (control channel)
            candidates.append((match.start(), match.end(), pii_type))

    for finding in _try_decode_base64_spans(text):
        start, end = finding["position"]
        candidates.append((start, end, finding["type"]))

    # Resolve overlaps: sort by start (then by longest span first for ties),
    # and greedily keep non-overlapping matches. This prevents two pattern
    # types that happen to overlap on the same span (e.g. a digit run that
    # partially matches two different numeric PII types, or a base64 span
    # that overlaps a plaintext match) from both trying to redact the same
    # characters.
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
