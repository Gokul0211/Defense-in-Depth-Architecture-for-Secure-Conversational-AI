"""
L2's document threat score — rebuilt 2026-09-21.

WHAT WAS WRONG WITH THE OLD ONE. `chunk_store._compute_trust_score` computed

    trust  = 1 - (0.6 * instruction_density + 0.4 * l1_score)

and both terms measure the same property. `instruction_density` is max similarity
to INSTRUCTIONAL_TEMPLATES; L1's dominant tier is max similarity to
KNOWN_INJECTIONS anchors, which `results.md` 8e showed is a measure of
instruction-shapedness. One signal, counted twice, with weights the code itself
described as "a principled starting point" — never fitted. Measured on
bipia_local: AUROC 0.7186, recall 0.1496.

THE ACTUAL DEFECT, AND IT IS NOT THE WEIGHTS. L1's Tier 3 is Prompt-Guard-86M,
whose three output heads are collapsed to `jailbreak_prob` by
`prompt_guard.predict()`. That choice is documented and was correct for L1: on
SHORT standalone conversational turns the `injection` head scores AUROC 0.185 —
inverted, not merely noisy. But the same note says that head was trained for
"instructions embedded within longer retrieved/third-party documents" and asks
that it be kept available "for anyone scanning longer retrieved-document content
where it may behave differently".

**L2 is the layer that scans retrieved documents, and it was using the head that
was rejected for conversational turns.** Measured on 1,800 BIPIA documents,
changing nothing else:

    PG jailbreak_prob, whole document   AUROC 0.7583    R@5%FPR 0.1513
    PG injection_prob, whole document   AUROC 0.9017    R@5%FPR 0.6307
    1 - benign_prob (both heads)        AUROC 0.9071    R@5%FPR 0.6567

An independent published 2026 evaluation reports Prompt-Guard-86M at 0.910 AUC on
BIPIA. Measuring 0.9017 here is strong evidence that the shipped 0.7186 was an
integration defect, not a benchmark ceiling.

THE SCORE THIS SHIPS:

    threat = (1 - benign_prob) * (1 + instruction_contrast) / 2

`1 - benign_prob` uses the model's whole non-benign mass rather than picking one
head, which beat either head alone on every metric and needs no choice defended.
`instruction_contrast` (see instruction_profile) is document-local and rescues the
weakest scenario. The `/ 2` bounds the result to [0, 1] — required, because
`trust_score = 1 - threat` feeds QUARANTINE_THRESHOLD and REVIEW_THRESHOLD — and
since a constant divisor is strictly monotone it changes no ranking. There is no
fitted constant anywhere in this expression.

MEASURED, BIPIA dev subset (1,500 malicious / 300 benign, stratified by scenario
and insertion position):

    rule                         AUROC    R@1%FPR   worst scenario
    shipped 0.6*instr+0.4*L1    0.7186*       —          0.7013*
    this                        0.9093     0.3113        0.8123
    (* full-corpus reference)

WHAT WAS TRIED AND REJECTED, so it is not retried:
  * WINDOWING Prompt Guard (max over windows): 0.9017 -> 0.7141, every scenario
    worse. The injection head judges whether a span is out of place *in its
    context*; isolating windows removes the evidence it uses. Do not window a
    model trained to read context — the anti-dilution argument that justified
    windowing Tier 2 comes from context-FREE embedding similarity.
  * FITTING a logistic/embedding fusion: out-of-fold 0.9269, but
    leave-one-scenario-out 0.7910 versus 0.8909 for this unfitted rule. Fitting
    bought nothing that survived scenario transfer.

INSERTION CONFOUND: CONTROLLED. BIPIA appends attacks to clean contexts, so a
"something stands out" term is the shape `results.md` 8c.2 had to reject. Three-arm
control (clean / benign-sentence-appended / malicious): confound share **2.9 %**,
insertion-only arm 0.5385. It responds to what was inserted, not that something was.
"""

from __future__ import annotations

import logging
import os
import re

from .instruction_density import instruction_profile

logger = logging.getLogger(__name__)

# Prompt Guard truncates at 512 tokens (~2,000 characters). Documents longer than
# that had their tail never scored at all, and the measurement shows exactly that
# cliff: AUROC by length was 0.9223 for 600-1000 chars, 0.9793 for 1000-2000, then
# 0.8478 for 2000+. Over-long documents are therefore split into a few LARGE
# overlapping segments and scored by max.
#
# LARGE segments, not sentence windows, and the distinction is load-bearing:
# scoring sentence windows collapsed AUROC 0.9017 -> 0.7141 because the injection
# head judges whether a span is out of place IN ITS CONTEXT, and an isolated
# sentence has none. Each segment stays long enough to carry that context while
# the union covers the whole document. The overlap exists so an injection
# straddling a boundary is intact in at least one segment.
#
# Measured: documents >1800 chars went 0.8852 -> 0.9932 AUROC; documents under the
# limit are passed through untouched and are bit-identical.
_LONG_DOC_CHARS = 1800
_SEGMENT_CHARS = 1600
_SEGMENT_OVERLAP = 400

# Dangerous-operation families for code-bearing content.
#
# WHY THIS EXISTS. `code` was the one scenario the Prompt Guard signal could not
# separate (AUROC 0.8068 where every other scenario reached 0.96+). The failure
# analysis is unambiguous: in the code scenario EVERY document is instructional,
# because benign ones are Stack Overflow answers telling you to run something.
# Prompt Guard scored "You made a syntax error, try np.array instead of np.aray"
# at 0.9999 not-benign, and scored a real exfiltration payload phrased as "Your
# algorithm can ascend substantially by including the following code excerpt" at
# 0.0017. Instruction-shapedness separates nothing there -- the same root cause
# `results.md` 8e found on Alpaca.
#
# What actually differs is the SEMANTICS OF THE CODE: benign answers suggest
# np.array or nltk.download; attacks import subprocess and requests to exfiltrate.
# These patterns are written from the threat taxonomy (egress / execution /
# credential access / obfuscation), not by inspecting which samples they catch.
#
# Measured: AUROC 0.8516 on `code` ALONE, and ~0.50 on every non-code scenario --
# it is inert where there is no code, which is why it can be combined globally
# rather than routed by content type.
_DANGEROUS_CODE_FAMILIES = {
    "egress": re.compile(
        r"\b(requests\.(post|get|put)|urllib\.request|urlopen|socket\.|httpx\.|"
        r"fetch\(|curl\s|wget\s|smtplib|sendmail)", re.I),
    "execution": re.compile(
        r"\b(subprocess|os\.system|os\.popen|popen\(|exec\(|eval\(|__import__|"
        r"shell=True|pty\.spawn)", re.I),
    "credential": re.compile(
        r"(os\.environ|getenv|\.ssh/|id_rsa|\.aws/credentials|/etc/passwd|"
        r"\.netrc|API_KEY|SECRET|TOKEN|password\s*=)", re.I),
    "obfuscation": re.compile(
        r"\b(base64\.(b64decode|b64encode)|codecs\.decode|chr\(\d+\)\s*\+|"
        r"bytes\.fromhex|rot13)", re.I),
}


def segment_document(text: str) -> list[str]:
    """Whole document as one segment, or large overlapping segments if over-long."""
    if len(text) <= _LONG_DOC_CHARS:
        return [text]
    out, start = [], 0
    while start < len(text):
        end = min(start + _SEGMENT_CHARS, len(text))
        if end < len(text):
            space = text.rfind(" ", start + _SEGMENT_CHARS - _SEGMENT_OVERLAP, end)
            if space > start:
                end = space
        out.append(text[start:end])
        if end >= len(text):
            break
        start = max(end - _SEGMENT_OVERLAP, start + 1)
    return out


# CREDENTIAL ACCESS, not credential VOCABULARY (v3 code review, config.L2_DANGER_CREDENTIAL_STRICT).
# The family above is case-insensitive with no word boundary on API_KEY|SECRET|TOKEN, so it fired on
# "secretary of state", "a secret ballot", "tokens of appreciation", "word_tokenize": 8.9 % of the
# benign pipeline arm's documents and 4 % of WildChat code answers carried +0.25 for it -- and the
# prose bin's WARN anchor (0.250618) sat exactly on that floor (scratch/rca/v3/d03). Kept: reading
# the environment / key files / password databases, SECRET / TOKEN / API_KEY as code IDENTIFIERS
# (upper-case constant style, case-sensitive), and a credential being ASSIGNED. Every BIPIA code
# attack string the old family matched is still matched (6/6 on the train split; the test split has
# none either way, d02).
_CREDENTIAL_STRICT = re.compile(
    r"(os\.environ|\bgetenv\b|\.ssh/|\bid_rsa\b|\.aws/credentials|/etc/passwd|/etc/shadow|\.netrc\b|"
    r"\b[A-Z0-9_]*(?:API_KEY|SECRET|TOKEN|PASSWORD|PASSWD)[A-Z0-9_]*\b|"
    r"(?i:\b(?:password|passwd|api_key|secret_key|access_token)\s*[=:]\s*\S))")


def _danger_families() -> dict:
    import sentinel.config as cfg
    if getattr(cfg, "L2_DANGER_CREDENTIAL_STRICT", False):
        return {**_DANGEROUS_CODE_FAMILIES, "credential": _CREDENTIAL_STRICT}
    return _DANGEROUS_CODE_FAMILIES


def dangerous_code_score(text: str) -> float:
    """Fraction of dangerous-operation families present, in [0, 1]."""
    fams = _danger_families()
    return sum(1 for rx in fams.values() if rx.search(text)) / len(fams)


_PG1 = "meta-llama/Prompt-Guard-86M"
_own_pg1 = None
_own_pg1_failed = False


def _prompt_guard_v1():
    """
    Prompt Guard 1 for L2, whatever L1 uses (L2 review C13).

    This axis reads Prompt Guard 1's 3-class `benign` probability. It reused L1's singleton, so setting
    L1_TIER3_MODEL to a binary model (Prompt Guard 2) made every long document silently fall back to the legacy axis.
    L1's instance is shared when it IS Prompt Guard 1 (one copy in memory, the old behaviour); otherwise L2 loads its
    own pinned copy.
    """
    global _own_pg1, _own_pg1_failed
    import sentinel.config as cfg
    if getattr(cfg, "L1_TIER3_MODEL", _PG1) == _PG1:
        from sentinel.layers.layer1 import _get_prompt_guard
        return _get_prompt_guard()
    if _own_pg1_failed:
        return None
    if _own_pg1 is None:
        try:
            from sentinel.eval.baselines.prompt_guard import PromptGuardBaseline
            g = PromptGuardBaseline(model_name=_PG1)
            g._load()
            _own_pg1 = g
        except Exception as e:                                        # noqa: BLE001
            logger.warning(f"Prompt Guard 1 unavailable for L2: {e}")
            _own_pg1_failed = True
            return None
    return _own_pg1


def _benign_prob(text: str) -> float | None:
    """
    Prompt Guard's `benign` class probability for the whole document.

    Reuses L1's Prompt Guard singleton rather than constructing a second
    PromptGuardBaseline: the model is 86M parameters and a second copy would
    double L2's resident memory for no benefit. Returns None when the model is
    unavailable, so the caller can fail soft instead of scoring everything 0.
    """
    guard = _prompt_guard_v1()
    if guard is None:
        return None
    segments = segment_document(text)
    try:
        # One batched call over every segment -- a long document costs one forward
        # pass over N segments, not N separate calls.
        rows = guard.probs_batch(segments, batch_size=max(len(segments), 1))
    except Exception as e:                                        # noqa: BLE001
        logger.warning(f"Prompt Guard unavailable for L2 scoring: {e}")
        return None
    if not rows or "benign_prob" not in rows[0]:
        # A binary-head model has no benign class to read; caller falls back.
        return None
    # MIN benign across segments == MAX not-benign, the anti-dilution choice: a
    # document is as suspicious as its most suspicious segment.
    return float(min(r["benign_prob"] for r in rows))


# Minimum input length for this scorer to be trusted.
#
# THE MEASUREMENT THAT SETS IT. Prompt Guard's `injection` head is degenerate on
# short text — this is the same finding prompt_guard.py's RCA recorded (AUROC
# 0.185 on short conversational turns), re-measured here as outright saturation.
# Fraction of BENIGN documents scored `not_benign > 0.99`:
#
#     Alpaca, median 65 chars        1.000   <- no signal at all, every benign
#                                               instruction reads as 100% not-benign
#     bipia_local    0- 300 chars    0.286
#     bipia_local  300- 600 chars    0.040
#     bipia_local  600-1000 chars    0.019
#     bipia_local 1000-2000 chars    0.000
#
# So the head is usable on retrieved documents and unusable on short prompts, and
# the transition is at a few hundred characters. Below this gate the caller falls
# back to the legacy composition, which is what short chunks were always scored by.
#
# This is NOT a tuned constant chasing a metric: it is the boundary of the
# distribution the model was trained for, and shipping without it would have
# handed L2 a 100 % false-positive rate on short benign text.
# RAISED 300 -> 600 after the promotion gate caught a regression. At 300 the
# scorer applied to sentinel_bench (median 409 chars) and collapsed that row:
# AUROC 0.8337 -> 0.6549, FPR 0.0755 -> 0.3396. Diagnosis: on sentinel_bench's
# 300-600 char band (84 % of that corpus) Prompt Guard's not-benign signal scores
# AUROC 0.4478 -- BELOW CHANCE, the same inversion its original RCA found on short
# conversational text -- and `instr_contrast` is also inverted there (0.4161),
# because sentinel_bench's poisoned documents are system/IT notices whose WHOLE
# framing is instructional, so nothing stands out against the rest.
#
# Length is an imperfect proxy: BIPIA's 300-600 band is fine while
# sentinel_bench's is inverted. 600 is therefore the conservative line -- the
# scorer applies only where it has been validated, on genuinely document-length
# retrieved content, which is the distribution Prompt Guard's injection head was
# trained for. sentinel_bench has NO document at or above 600 chars, so it is
# entirely unaffected by construction.
#
# Cost on bipia_local of the raise: AUROC 0.9484 -> 0.9315, still +0.2129 over the
# legacy 0.7186. Overridable so the boundary can be re-derived if a corpus of long
# sentinel_bench-style documents ever exists to measure it against.
_MIN_DOC_CHARS = int(os.getenv("L2_MIN_DOC_CHARS", "600"))


# ---------------------------------------------------------------------------------------
# SHORT third-party text (< _MIN_DOC_CHARS): the "short" Mondrian bin (2026-09-25, B-4/B-5)
#
# Below the gate L2 fell back to `1 - (0.6*density + 0.4*L1)`, which has two defects:
#   * a weighted sum CANNOT reach BLOCK (0.60) on certain evidence from one term: with
#     L1 = 1.0 the L1 term contributes 0.4 -- an explicit "[ADMIN OVERRIDE: ...]" payload
#     with ordinary wording can never be quarantined (sentinel_bench poisoned_rag_exfil);
#   * it reads L1's score, and L1's Tier 3 is PG-jailbreak x PIGuard-injection: on
#     documents PG-jailbreak is ~0.000, so the product multiplies PIGuard's signal away.
# Measured on sentinel_bench's 56 short documents (scratch/rca/D01): Prompt Guard
# injection head AUROC 0.304 (inverted on short text, as documented above), PG jailbreak
# 0.543, PIGuard injection 0.884. So the short bin reads PIGuard directly, noisy-OR'd with
# the dangerous-code indicator (the same composition the long-document axis uses), and is
# calibrated on its OWN anchors -- a separate bin, because its score distribution is not
# the long-document one (RCA-#3 discipline).
#
# OFF until L2_SHORT_DOC_SCORER=piguard AND its anchors are derived
# (scratch/rca/R026_short_doc_anchor.py): with an underived anchor the bin reports
# `available: False` and the legacy composition is used, exactly as before.
def _piguard_injection_prob(text: str) -> float | None:
    try:
        from sentinel.layers.layer1_tier3 import _get_piguard
        g = _get_piguard()
        if g is None:
            return None
        return float(g.predict(text).score)
    except Exception as e:                                            # noqa: BLE001
        logger.warning(f"PIGuard unavailable for short-document scoring: {e}")
        return None


def _short_bin_name(source_kind: str | None) -> str:
    """L2 review I12 / C16 (config.L2_SHORT_BIN_BY_SOURCE): one short bin per source. The shipped bin's anchor is
    the MAXIMUM over its calibration sources -- benign news paragraphs WARN 0.000128, benign agent tool outputs WARN
    0.999712 (l2_short_anchor_20260925_232659.json) -- so every short KB document was held to the tool-output bar
    (DIDA-Bench recall 0.405, BIPIA short 0.464; scratch/rca/l2/r02). With the flag, tool outputs keep that bar and KB
    documents get their own anchor, calibrated on benign short documents that include instructional, human-addressed
    text (r02 showed a news-only anchor flags every benign corporate notice)."""
    import sentinel.config as cfg
    if not getattr(cfg, "L2_SHORT_BIN_BY_SOURCE", False):
        return "short"
    return "short_tool" if source_kind == "tool" else "short_doc"


def short_document_threat(text: str, force: bool = False, source_kind: str | None = None) -> dict | None:
    """Threat for text below the long-document gate, or None if the short bin is off.
    `force=True` scores even with underived anchors (anchor-derivation scripts only)."""
    import sentinel.config as cfg

    if getattr(cfg, "L2_SHORT_DOC_SCORER", "legacy") != "piguard" and not force:
        return None
    base = {"content_type": "short", "bin": _short_bin_name(source_kind), "not_benign": None}
    if not force and (cfg.L2_DOCUMENT_THREAT_WARN_THRESHOLD_SHORT is None
                      or cfg.L2_DOCUMENT_THREAT_BLOCK_THRESHOLD_SHORT is None):
        return {**base, "threat": 0.0, "available": False, "reason": "short_doc_anchor_underived"}
    pig = _piguard_injection_prob(text)
    if pig is None:
        return {**base, "threat": 0.0, "available": False, "reason": "piguard_unavailable"}
    danger = dangerous_code_score(text)
    threat = 1.0 - (1.0 - pig) * (1.0 - danger)
    return {**base, "threat": max(0.0, min(threat, 1.0)), "available": True,
            "piguard_injection": pig, "dangerous_code": danger}


def document_threat_score(text: str, source_kind: str | None = None) -> dict:
    """
    Threat score in [0, 1] for a retrieved document, plus its components.

    Returns `threat`, and `available` — False when this scorer must not be used,
    which tells the caller to fall back to the legacy composition rather than
    treat an unscored document as clean. `available` is False when Prompt Guard
    cannot be loaded OR when the input is too short to be in the head's
    distribution (see _MIN_DOC_CHARS).
    """
    from sentinel.core.content_type import detect_content_type

    profile = instruction_profile(text)
    # The Mondrian calibration bin (config.l2_warn_threshold_for): benign code answers
    # sit far higher on this axis than prose, so they carry their own anchor.
    ctype = detect_content_type(text)
    if len(text) < _MIN_DOC_CHARS:
        short = short_document_threat(text, source_kind=source_kind)
        if short is not None and short.get("available"):
            return {**short, "instruction_max": profile["max"],
                    "instruction_contrast": profile["contrast"]}
        return {
            "threat": 0.0,
            "available": False,
            "reason": "below_min_doc_chars",
            "content_type": ctype,
            "not_benign": None,
            "instruction_max": profile["max"],
            "instruction_contrast": profile["contrast"],
        }
    benign = _benign_prob(text)
    if benign is None:
        return {
            "threat": 0.0,
            "available": False,
            "content_type": ctype,
            "not_benign": None,
            "instruction_max": profile["max"],
            "instruction_contrast": profile["contrast"],
        }

    not_benign = 1.0 - benign
    base = not_benign * (1.0 + profile["contrast"]) / 2.0
    danger = dangerous_code_score(text)
    # Noisy-OR, because the two are independent kinds of evidence: a document is
    # suspicious if its language reads as an embedded instruction OR its code does
    # something dangerous. Measured against using `base` alone: pooled AUROC
    # 0.9551 -> 0.9502 (immaterial) while the WORST scenario goes 0.8068 -> 0.8699
    # and recall at 1% FPR goes 0.3740 -> 0.4133. Robustness and low-FPR recall
    # were preferred over a fifth of a point of pooled ranking.
    threat = 1.0 - (1.0 - base) * (1.0 - danger)
    out = {
        "threat": max(0.0, min(threat, 1.0)),
        "available": True,
        "content_type": ctype,
        "not_benign": not_benign,
        "instruction_max": profile["max"],
        "instruction_contrast": profile["contrast"],
        "dangerous_code": danger,
        "n_segments": len(segment_document(text)),
    }
    if ctype == "code":
        _apply_code_prose_part(text, out)
        _apply_code_incoherence(text, out)
    return out


def code_blocks(text: str) -> list[str]:
    """Contiguous code runs of a document (fenced bodies; indented / declaration / symbol-dense lines), >= 2 lines."""
    from sentinel.core.content_type import _DECL_LINE, _symbol_ratio
    blocks, cur = [], []
    for i, part in enumerate(re.split(r"```[^\n]*\n?", text or "")):
        if i % 2 == 1:
            if cur:
                blocks.append("\n".join(cur)); cur = []
            if part.strip():
                blocks.append(part.strip())
            continue
        for ln in part.splitlines():
            s = ln.strip()
            if s and (ln.startswith(("    ", "\t")) or _DECL_LINE.match(ln) or _symbol_ratio(s) > 0.15):
                cur.append(ln)
            elif s and cur:
                blocks.append("\n".join(cur)); cur = []
    if cur:
        blocks.append("\n".join(cur))
    return [b for b in blocks if sum(1 for l in b.splitlines() if l.strip()) >= 2]


def block_incoherence(text: str) -> float | None:
    """1 - min over code blocks of cos(block, rest of the document) in MiniLM space; None without a scorable block.
    Content-neutral: it asks whether a block belongs to the answer it sits in, not what the code does."""
    import numpy as _np
    from sentinel.core.embedding import get_model
    vals = []
    for b in code_blocks(text):
        rest = text.replace(b, " ")
        if len(rest.strip()) < 50:
            continue
        e = _np.asarray(get_model().encode([b[:2000], rest[:4000]]))
        vals.append(float(e[0] @ e[1] / (_np.linalg.norm(e[0]) * _np.linalg.norm(e[1]) + 1e-12)))
    return (1.0 - min(vals)) if vals else None


def _apply_code_incoherence(text: str, out: dict) -> None:
    """
    L2 RCA 2 candidate (config.L2_CODE_INCOHERENCE, OFF; inert while L2_CODE_INCOHERENCE_TAU is unset). An injected
    snippet is usually off-topic for the answer it is inserted into; a code block whose similarity to the rest of the
    document is below the benign anchor lifts the document to the code bin's WARN anchor (held for review). Evidence of
    a misfit, not of intent, so it never quarantines on its own. Adoption gates (scratch/rca/l2/r06): an insertion
    control (benign off-topic blocks) and a union budget with the prose-part check on held-out benign code answers.
    """
    import sentinel.config as cfg
    tau = getattr(cfg, "L2_CODE_INCOHERENCE_TAU", None)
    if not getattr(cfg, "L2_CODE_INCOHERENCE", False) or tau is None:
        return
    inc = block_incoherence(text)
    if inc is None:
        return
    out["block_incoherence"] = inc
    if inc >= tau:
        bin_w = cfg.L2_DOCUMENT_THREAT_WARN_THRESHOLD_CODE
        if out["threat"] < bin_w:
            out.setdefault("base_threat", out["threat"])
            out["threat"] = min(1.0, bin_w + 1e-6)


CODE_PROSE_MIN_CHARS = 200


def prose_part_score(prose: str) -> float | None:
    """The score the prose part of a code document is judged by (and its anchors derived with,
    scratch/rca/l2/c4_code_prose_anchor.py): the doc-axis base (Prompt Guard non-benign x instruction contrast) for a
    prose part of >= _MIN_DOC_CHARS, else PIGuard's injection probability -- each the scorer validated for that length.
    None when the needed model is unavailable."""
    if len(prose) >= _MIN_DOC_CHARS:
        benign = _benign_prob(prose)
        if benign is None:
            return None
        return (1.0 - benign) * (1.0 + instruction_profile(prose)["contrast"]) / 2.0
    return _piguard_injection_prob(prose)


def _apply_code_prose_part(text: str, out: dict) -> None:
    """
    L2 review C4 (config.L2_CODE_PROSE_SPLIT, OFF until measured). A code document is judged on the code bin's anchor,
    calibrated on benign code answers, which is right for the code but lets any prose carried alongside it ride on
    that lenient bar. The prose part is scored on its own and compared with anchors calibrated on the PROSE PARTS of
    benign code answers (L2_CODE_PROSE_WARN / _BLOCK); the result is mapped onto the code bin's axis (its WARN -> the
    bin's WARN, BLOCK -> BLOCK, strictly monotone) and max-fused into `threat`. Inert while the anchors are unset.
    """
    import sentinel.config as cfg
    if not getattr(cfg, "L2_CODE_PROSE_SPLIT", False):
        return
    w, b = getattr(cfg, "L2_CODE_PROSE_WARN", None), getattr(cfg, "L2_CODE_PROSE_BLOCK", None)
    if w is None or b is None:
        return
    from sentinel.core.content_type import split_code_prose
    _, prose = split_code_prose(text)
    if len(prose) < CODE_PROSE_MIN_CHARS:
        return
    s = prose_part_score(prose)
    if s is None:
        return
    from sentinel.layers.layer2_rag.chunk_store import _map_onto_bin
    bin_w = cfg.L2_DOCUMENT_THREAT_WARN_THRESHOLD_CODE
    bin_b = max(cfg.L2_BLOCK_THRESHOLD, cfg.L2_DOCUMENT_THREAT_BLOCK_THRESHOLD_CODE)
    mapped = _map_onto_bin(s, w, max(b, w + 1e-6), bin_w, max(bin_b, bin_w + 1e-6))
    out["prose_part"] = {"chars": len(prose), "score": s, "mapped": mapped}
    if mapped > out["threat"]:
        out["base_threat"] = out["threat"]
        out["threat"] = mapped
