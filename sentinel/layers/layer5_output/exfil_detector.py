import re
from sentence_transformers import util
from sentinel.core.embedding import get_model
from sentinel.config import CANARY_TOKEN

EXFILTRATION_PATTERNS = [
    r"my instructions say",
    r"i was told to",
    r"my system prompt",
    r"i have been instructed",
    r"here are my instructions",
]

SEMANTIC_OVERLAP_THRESHOLD = 0.65
TOKEN_OVERLAP_THRESHOLD = 0.40


def jaccard_similarity(str1: str, str2: str) -> float:
    """Compute token-level overlap."""
    a = set(str1.lower().split())
    b = set(str2.lower().split())
    if not a or not b:
        return 0.0
    c = a.intersection(b)
    return float(len(c)) / (len(a) + len(b) - len(c))


def detect_exfiltration(response: str, system_prompt: str | None) -> tuple[float, list[str]]:
    """
    Detect if the response leaks the system prompt.
    Returns: (exfil_score, list of evidence)

    Fixed from the previous implementation: the score used to be computed as
    `semantic_overlap * 0.4` and `token_overlap * 0.8` unconditionally, while
    the "evidence" strings were only appended once overlap crossed 0.65 /
    0.40 respectively. That meant a response could accumulate a meaningfully
    elevated score purely from sub-threshold overlap (e.g.
    semantic_overlap=0.60, below the 0.65 evidence threshold, still
    contributed 0.24 to the score) with no evidence text explaining why —
    score and explanation could silently disagree. This version only lets a
    signal contribute to the score once it has actually crossed its own
    documented threshold, so the reported evidence always accounts for the
    reported score.
    """
    if not response:
        return 0.0, []

    evidence = []

    # 0. Canary Token Check
    if CANARY_TOKEN in response:
        evidence.append("CRITICAL: System prompt canary token leaked in output!")
        return 1.0, evidence

    # 1. Structural pattern check
    structural_matches = []
    for pattern in EXFILTRATION_PATTERNS:
        if re.search(pattern, response, re.IGNORECASE):
            structural_matches.append(pattern)

    if structural_matches:
        evidence.append("Found structural markers indicating rule disclosure")

    semantic_score_contribution = 0.0
    token_score_contribution = 0.0

    if system_prompt:
        # 2. Semantic overlap
        resp_emb = get_model().encode(response)
        sys_emb = get_model().encode(system_prompt)
        semantic_overlap = float(util.cos_sim(resp_emb, sys_emb)[0][0])

        if semantic_overlap > SEMANTIC_OVERLAP_THRESHOLD:
            evidence.append(f"High semantic overlap with system prompt ({semantic_overlap:.2f})")
            semantic_score_contribution = semantic_overlap * 0.4

        # 3. Token overlap
        token_overlap = jaccard_similarity(response, system_prompt)
        if token_overlap > TOKEN_OVERLAP_THRESHOLD:
            evidence.append(f"High token overlap with system prompt ({token_overlap:.2f})")
            token_score_contribution = token_overlap * 0.8

    score = max(
        semantic_score_contribution,
        token_score_contribution,
        0.9 if structural_matches else 0.0,
    )

    return min(1.0, score), evidence
