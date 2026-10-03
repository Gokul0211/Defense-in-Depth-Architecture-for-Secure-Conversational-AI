"""
SENTINEL Configuration — All thresholds, environment variables, and tunable parameters.
"""

import os
from dotenv import load_dotenv

import uuid

load_dotenv()

# System Canary Token (Generated per server run)
CANARY_TOKEN = f"SENTINEL-CANARY-{uuid.uuid4().hex}"

# Server
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8080"))
# Browser origins allowed to call the API (comma-separated). Defaults to the local
# Next.js frontend; set to "*" to allow any origin (credentials are then disabled).
CORS_ORIGINS = [o.strip() for o in os.getenv(
    "DIDA_CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000").split(",") if o.strip()]

# LLM Backend
LLM_BACKEND = os.getenv("LLM_BACKEND", "https://api.groq.com/openai/v1/chat/completions")
LLM_API_KEY = os.getenv("GROQ_API_KEY", os.getenv("OPENAI_API_KEY", ""))

# Judge key pool, added 2026-09-20. Same provider, same model, separate
# accounts — rotated ONLY when one is quota-exhausted (HTTP 429).
#
# WHY. L1's judge tier fires on ~48% of samples at the adopted band
# (0.30, 0.75], so WildJailbreak alone needs ~1,068 calls against a
# 1,000/day per-account cap. An exhausted judge returns None, which is
# CORRECTLY treated as "skip this signal" — and therefore degrades the
# layer silently: recall 0.9492 -> 0.5254 with no error surfaced anywhere.
# That is precisely how this project published an L1 number ~49 recall
# points low. Rotation keeps a run complete; the judge counters record
# what actually happened either way.
#
# Falls back to the single LLM_API_KEY when unset, so nothing changes for
# a deployment that does not configure a pool.
LLM_API_KEY_POOL = [
    k.strip() for k in os.getenv("GROQ_API_KEYS", "").split(",") if k.strip()
] or ([LLM_API_KEY] if LLM_API_KEY else [])
# Groq retired the llama3-*/llama-3.1-*-instant lineup this model was
# previously pinned to (confirmed 2026-09-11 via a live 404 from the chat
# completions endpoint, then cross-checked against /v1/models — the only
# chat-capable models left on the account are the openai/gpt-oss-* and
# qwen/qwen3.*-* families). Defaulting to the smallest currently-served
# model in the same "fast/cheap" tier the old default targeted.
LLM_MODEL_OVERRIDE = os.getenv("LLM_MODEL_OVERRIDE", "openai/gpt-oss-20b")

# Decision Thresholds
BLOCK_THRESHOLD = float(os.getenv("BLOCK_THRESHOLD", "0.85"))
WARN_THRESHOLD = float(os.getenv("WARN_THRESHOLD", "0.50"))

# Layer 1 — Input Injection Classifier
L1_TIER1_THRESHOLD = 0.45
L1_BLOCK_THRESHOLD = 0.85
L1_SEMANTIC_HIGH = 0.75       # Cosine sim above this → definite injection
# Widened from 0.55 to 0.30, 2026-09-14 (Phase 3.1 judge-band sweep): real
# 6-point sweep on 300 WildJailbreak malicious / 200 Alpaca benign samples
# showed recall 0.2810->0.7299 and AUROC 0.5473->0.7060 moving from 0.55 to
# 0.30, while Alpaca's FPR (genuine benign traffic) stayed flat at 0.0250 at
# every single point on the curve -- the real cost is judge-invocation-rate
# and latency (2.67%->48.33%, p95 1561ms->3396ms), scoped only to the
# already-narrow ambiguous band, not a false-positive cost to real users.
# See SENTINEL_COMPLETE_RESULTS_RECORD.md's Phase 3.1 correction and
# sentinel/eval/results/LEDGER.jsonl for the full real numbers.
L1_SEMANTIC_MEDIUM = 0.30     # Cosine sim above this → suspicious

# L1's own WARN anchor, for rescale_layer_score — CALIBRATED 2026-09-18
# (Phase 5 Stage 0a / plan item 3B.2).
#
# WHY THIS EXISTS. app.py computes `combined_score = max(l1_score,
# l3_effective_score, l2_score, l2_retrieval_score)` and classifies it
# against the global WARN/BLOCK pair. Only L3 was rescaled first (RCA #3).
# L1 was compared raw, on the assumption stated in rescale_layer_score's
# own docstring that "their thresholds equal the global ones, so this
# function is a no-op for them". That assumption was never tested. It is
# false: L1's real alpha=0.05 operating point is 0.4391, not 0.50 — so L1
# ran MORE conservative than a 5% false-positive budget, paying recall for
# an FPR nobody chose.
#
# HOW IT WAS DERIVED. Split-conformal risk control (Vovk; Angelopoulos et
# al. 2022) over 500 real Alpaca benign samples scored through the real,
# unmodified layer1_check(), at alpha=0.05 —
# sentinel/eval/conformal_l1_eval.py, result
# eval_conformal_l1_20260918_191436.json. Alpaca is the right calibration
# corpus precisely because it is generic benign traffic, which is what a
# global anchor should represent.
#
# The guarantee, stated precisely: for a new benign sample drawn
# exchangeably with the calibration set, P(score > 0.4391) <= 0.05. That
# is distribution-free and finite-sample; it is NOT a claim about
# adversarially-styled benign text (see the honest caveat below).
#
# MEASURED, this re-derivation (all three arms, current config):
#   alpaca same-source validation  n=500  empirical FPR 0.0380  HELD
#   sentinel_bench benign          n=53   empirical FPR 0.0000  HELD
#   wildjailbreak benign           n=210  empirical FPR 0.2667  VIOLATED
#
# The WildJailbreak violation is real, expected, and already this
# project's Contribution D finding (Part E of the results record): the
# exchangeability assumption fails on adversarially-styled benign text.
# Re-deriving at the current config REPLICATES it (0.2619 -> 0.2667),
# confirming that finding is not an artifact of the pre-Phase-3.1 config.
# Adopting this threshold does not paper over that — alpha is the knob,
# and the guarantee is scoped to traffic resembling the calibration set.
#
# STABILITY NOTE worth keeping: tau came back bit-identical (0.4391) to
# the 2026-09-13 derivation, despite L1_SEMANTIC_MEDIUM having moved
# 0.55 -> 0.30 in between. The re-run was done because that change was
# assumed to invalidate the old tau; it did not, because the judge band
# only ever raises a score and rarely fires on benign Alpaca text, so the
# benign upper tail tau is computed from is dominated by Tier 2/3. Worth
# knowing rather than assuming in either direction.
#
# EFFECT ON sentinel_bench (n=112): recall 0.4576 -> 0.5254 at measured
# FPR 0.0000, i.e. the recall gain is real and costs nothing on that
# corpus; the alpha=0.05 budget is an upper bound being bought, not spent.
# DEFAULT CHANGED 2026-09-23 (#10 / #5): 0.4391 (alpha 0.05) -> 0.5494 (alpha 0.01).
# alpha 0.01 was the operating budget declared in scratch/l1x/LEDGER.md EXP-012 but
# never written here, so every "Alpaca 0.0055" / "NotInject 0.0383" number described a
# non-default config. Re-derived on the FINAL axis (Tier-1 regex fixes, Tier 3 =
# agreement, judge = gpt-oss-safeguard-20b/low/v4) by scratch/t10/calibrate_tau.py:
# split-conformal on Alpaca rows 0-499, judge ON -> tau 0.5494 (the judge fired on 140
# of them and raised none past tau). Held-out real hard-benign check (482 OASST2
# prompts containing injection vocabulary, disjoint from every dev set): FPR 0.0788.
L1_WARN_THRESHOLD = float(os.getenv("L1_WARN_THRESHOLD", "0.5494"))
# The alpha this was calibrated at. Recorded so the guarantee can be
# restated (and re-derived) without archaeology.
L1_CONFORMAL_ALPHA = float(os.getenv("L1_CONFORMAL_ALPHA", "0.01"))

# Tier 4 (LLM judge) kill switch. Default ON — production behaviour is
# unchanged, and the judge still skips itself when no API key is set.
#
# Exists so a harness can pin L1 to a DETERMINISTIC axis and say so. Tier 4
# is L1's only non-deterministic input, and any artifact whose ground truth
# depends on it — SPLIT-Bench's certificates above all — is reproducible
# only as long as the third-party API behaves identically. See the comment
# in layer1_llm_judge.llm_judge_check for the concrete failure this caught.
L1_LLM_JUDGE_ENABLED = os.getenv("L1_LLM_JUDGE_ENABLED", "true").lower() == "true"

# Judge system-prompt version (2026-09-23, #10). "v1" = the original prompt; "v4" =
# trigger-word-aware prompt, see _JUDGE_SYSTEM_PROMPT_V4 in layer1_llm_judge.py.
# Every judge-on number depends on this, so it is captured in the run config.
# DEFAULT CHANGED 2026-09-23 (#10): "v1" -> "v6" (v4 was adopted first and
# superseded the same day after it regressed extraction recall; see the v6 comment in
# layer1_llm_judge.py). See the three settings below.
# DEFAULT CHANGED 2026-09-25: "v6" -> "v7", by the gate pre-declared in fixing.md E1
# (ship v7 only if exfil recall >= v6 AND synthetic FPR <= 0.0312). Measured
# (scratch/rca/v2/G1_report.log, G2v7_*): exfil recall 0.9375 vs 0.667; synthetic FPR
# 0.026; judge-on NotInject FPR 0.0354 (v6 0.0383); sentinel_bench L1 recall 0.9661 /
# AUROC 0.9731 / FPR 0 (v6 same day 0.8983); TensorTrust 0.8754; L2/SB 0.9661 / 0.9706;
# pipeline SB BLOCK-only 0.6949 (v6 0.678). Fixes v6's spoofed-system/exfil blind spot.
L1_JUDGE_PROMPT_VERSION = os.getenv("L1_JUDGE_PROMPT_VERSION", "v7").strip().lower()
# B-9 (2026-09-25): let a benign judge verdict hold an in-band L1 score below WARN.
# Off by default; gate on NotInject FPR vs TensorTrust / sentinel_bench recall.
L1_JUDGE_MAY_LOWER = os.getenv("L1_JUDGE_MAY_LOWER", "false").lower() == "true"
# Hosted judge calls made with a POLICY prompt (core/policy_prompts: harm head, L4 alignment,
# benign-arm audit) are switched by this, not by L1_LLM_JUDGE_ENABLED (2026-09-25).
POLICY_JUDGE_ENABLED = os.getenv("POLICY_JUDGE_ENABLED", "true").lower() == "true"

# The L1 judge's OWN model, separate from LLM_MODEL_OVERRIDE (which is the upstream
# chat model app.py proxies to). "" falls back to LLM_MODEL_OVERRIDE, the historical
# behaviour. Harnesses that swap LLM_BACKEND to a non-Groq provider must blank this.
#
# DEFAULT 2026-09-23 (#10): openai/gpt-oss-safeguard-20b, reasoning_effort "low",
# prompt v4 -- OpenAI's open-weight POLICY classifier (it classifies against a written
# policy, which is exactly what the judge prompt is). Chosen on dev sets that exclude
# every reported corpus (scratch/t10/LEDGER.md, E10-3):
#
#   judge                     trigger-benign FPR     SB held-out   deepset    coverage
#                             synthetic   OASST2     recall        recall
#   gpt-oss-20b + v1 (old)      0.1813    0.0278      1.0000       0.3600      0.944
#   safeguard-low + v1          0.0469    0.0333      1.0000       0.1333      1.000
#   safeguard-low + v4          0.0104    0.0200      1.0000       0.3000      1.000
#
# ~600 tokens and ~0.4 s per call against gpt-oss-20b's ~1,000-2,000 (it routinely
# spent its budget on hidden reasoning), so the same daily quota covers ~2-3x the calls.
L1_JUDGE_MODEL = os.getenv("L1_JUDGE_MODEL", "openai/gpt-oss-safeguard-20b").strip()

# Reasoning effort sent to the judge model ("" = parameter not sent, the historical
# request). A different effort is a different judge, so it is captured in the run
# config alongside the model and the prompt version.
LLM_JUDGE_REASONING_EFFORT = os.getenv("LLM_JUDGE_REASONING_EFFORT", "low").strip().lower()

# Layer 1 — Calibrated tier fusion (Phase 5 / 3B.3)
#
# OFF BY DEFAULT pending the confirming WildJailbreak run against the
# ensemble judge. L1 currently combines its four tiers with max(), which
# is not the Neyman-Pearson-optimal rule and measurably discards ranking
# information. Cross-corpus (the pre-registered bar — fit on one corpus,
# evaluate on another, both directions):
#
#   fit sentinel_bench -> eval wildjailbreak:  0.6457 -> 0.7426  (+0.0969)
#   fit wildjailbreak  -> eval sentinel_bench: 0.9719 -> 1.0000  (+0.0281)
#
# Confirmed 2026-09-19 with paired bootstrap CIs (2,000 stratified
# replicates, both rules scored on the same resample):
#
#   fit sentinel_bench -> eval wildjailbreak (n=2210):
#       CI95 [+0.0668, +0.1278], p_worse=0.000, min delta +0.0435
#   fit wildjailbreak  -> eval sentinel_bench (n=112):
#       CI95 [+0.0000, +0.0720], p_worse=0.000, min delta +0.0000
#
# The fusion never ranked WORSE than max() in any replicate in either
# direction; the 0.0000 lower bound on sentinel_bench is ties, not losses
# (max() is already at 0.9719 there, so many replicates contain no pair it
# gets wrong). The pre-registered bar in tier_fusion_eval.py is met.
#
# Enabling this changes L1's score for every request and therefore every
# L1 number in the paper, so it requires: (a) the confirming run, (b) a
# frozen model artifact fitted on a NAMED corpus, and (c) a re-derived
# conformal L1_WARN_THRESHOLD, because the fused score lives on a
# different axis (see tier_fusion.fused_score_to_unit). Flipping it
# without (c) would leave L1 on a threshold calibrated for a scale it no
# longer uses — the exact RCA-#3 error this project already fixed once
# for L3 and once for L1 itself.
#
# KNOWN, MEASURED, AND DELIBERATELY NOT YET FIXED: L1_SEMANTIC_MEDIUM
# (0.30) and L1_SEMANTIC_HIGH (0.75) serve two roles, and enabling fusion
# splits them apart.
#
#   1. Judge-invocation gate. Evaluated BEFORE _apply_tier_fusion, still on
#      the max() axis they were calibrated on. CORRECT and unaffected —
#      this ordering is why the frozen model's cascade availability
#      patterns stay valid.
#   2. threat_class assignment. Evaluated AFTER fusion, so with the flag on
#      it compares a fused logistic score against cosine-similarity bands.
#      That is the wrong axis.
#
# Measured effect on WildJailbreak (n=2210), max() -> fused:
#      all samples   INJECTION 1049 -> 828, SUSPICIOUS 653 -> 981,
#                    CLEAN      508 -> 401
#      benign only   CLEAN       64 -> 109, SUSPICIOUS 110 -> 70,
#                    INJECTION   36 -> 31
#
# The fused labels are in fact BETTER on benign, but "happens to look
# better" is not a calibration and is not claimed as one. Severity is
# bounded: `threat_class` is consumed only for REPORTING — app.py's
# dominant_type and finding strings, the demo replays' labels — while every
# block/allow decision reads `score` against WARN/BLOCK. So this changes
# what a report says, never what the system does.
#
# FIXED 2026-09-19 — see L1_FUSED_SEMANTIC_* below.
L1_TIER_FUSION = os.getenv("L1_TIER_FUSION", "false").lower() == "true"

# threat_class bands for the FUSED axis. Used INSTEAD of
# L1_SEMANTIC_MEDIUM/HIGH only when L1_TIER_FUSION is on, and only for
# threat_class — the judge-invocation gate keeps using the max()-axis
# constants, because it runs BEFORE fusion and that ordering is what keeps
# the frozen model's cascade availability patterns valid.
#
# Derived by `python -m sentinel.eval.derive_fused_bands` on n=1000 Alpaca
# benign (the designated calibration corpus, never fitted on by the fusion
# model), and frozen to core/artifacts/l1_fused_bands.json. Benign data
# only, exactly like the conformal tau derivation — no labels involved.
#
#   MEDIUM  0.3000 -> 0.3883   benign-quantile match at q=0.7520,
#                              bootstrap sd 0.0014
#   HIGH    0.7500 -> 0.5073   conformal upper anchor, bootstrap sd 0.0139
#
# HIGH needed a different anchor, and the reason is a finding rather than a
# workaround: 0.75 sits above EVERY one of the 1000 benign samples on the
# max() axis too (benign max there is 0.6797), so q = 1.0 and it is not a
# benign quantile at all. It never was — it is a cosine-similarity
# heuristic that no amount of benign data can identify, on either axis. So
# HIGH is transported by preserving the statement benign data CAN support,
# "above essentially all benign traffic", as the conformal threshold at the
# smallest alpha n supports (1/(n+1)).
#
# Shipped because the bands are well IDENTIFIED, not merely because they
# exist: the gap between them is 0.1190 and the worst bootstrap sd is
# 0.0139, i.e. 12% of the gap. Had sampling noise been comparable to the
# gap, which of the three classes a score falls into would have been
# decided by which 1000 benign samples were drawn, and the labels would
# have carried no information.
L1_FUSED_SEMANTIC_MEDIUM = float(os.getenv("L1_FUSED_SEMANTIC_MEDIUM", "0.3883"))
L1_FUSED_SEMANTIC_HIGH = float(os.getenv("L1_FUSED_SEMANTIC_HIGH", "0.5073"))
# Points at the FROZEN artifact under core/artifacts/, not at eval/results/.
# Deliberate: eval/results/ is a timestamped scratch area that evals
# overwrite, so a production decision rule living there could silently
# change identity between runs. core/artifacts/ holds exactly one model
# plus a provenance sidecar recording the corpus, source file and SHA-256
# it was fitted from. Written by `python -m sentinel.eval.fit_production_fusion`.
L1_TIER_FUSION_MODEL = os.getenv(
    "L1_TIER_FUSION_MODEL",
    str(__import__("pathlib").Path(__file__).parent / "core" / "artifacts" / "l1_tier_fusion.json"),
)

# Layer 1 — harm-content tier (added 2026-09-20)
#
# OFF BY DEFAULT, on the same terms as L1_TIER_FUSION below: enabling it changes
# L1's score for every request and therefore every L1 number already published,
# so adoption must be a declared configuration change, not a silent one.
#
# THE GAP IT CLOSES. All four of L1's tiers ask ONE question — "does this look
# like an injection or jailbreak ATTEMPT". Measured per-tier AUROC on
# WildJailbreak (n=2210, from the stored tier_scores of
# eval_L1_wildjailbreak_20260920_143328):
#
#     tier1 regex 0.5077 | tier2 semantic 0.5588 | tier3 Prompt Guard 0.5458
#     max() as reported 0.5694 | mean(t2,t3) 0.5573 | max(t1,mean(t2,t3)) 0.5728
#
# So the row is NOT a fusion problem: max() already beats every single tier and
# no unfitted recombination gains more than +0.0034. WildJailbreak's benign arm
# is purpose-built to use the same roleplay/scenario wrapper as its malicious
# arm, so the classes differ in the HARMFULNESS OF THE REQUEST, not in
# injection-ness — and L1 has no signal that reads harmfulness at all.
#
# WHAT IT ADDS. Max cosine similarity of the input against layer3's
# HARM_ANCHOR_PHRASES — five generic harm-domain sentences, reused VERBATIM, not
# authored or edited for this experiment — scored on raw and canonicalized text,
# then averaged with L1's existing combined tier score. Mean, not max: max is
# measurably worse (see the table below), consistent with this project's repeated
# finding that max() is a poor combiner across quantities.
#
# MEASURED (scratch/rca_l1_harm_signal.py -> scratch/rca_l1_harm_signal.json).
# Each rule evaluated at its OWN split-conformal threshold derived on 500 Alpaca
# benign at alpha=0.05, so all rules are compared at an identical benign budget:
#
#   corpus           metric     max() (current)   mean(L1,harm)      delta
#   wildjailbreak    AUROC             0.5694          0.6733      +0.1039
#                    recall            0.4520          0.6545      +0.2025
#                    FPR               0.3429          0.3476      +0.0047
#                    precision         0.9262          0.9472      +0.0210
#   sentinel_bench   AUROC             0.8094          0.8561      +0.0467
#                    recall            0.6441          0.7627      +0.1186
#                    FPR               0.0755          0.0000      -0.0755
#                    precision         0.9048          1.0000      +0.0952
#   tensortrust      recall            0.9211          0.9526      +0.0315
#   alpaca           FPR               0.0480          0.0480       0.0000
#
# It dominates on every measurable metric on three corpora and is neutral on the
# fourth (Alpaca's FPR is equal by construction — that is what calibrating both
# rules at alpha=0.05 means). This clears the cross-corpus, both-directions bar
# tier_fusion_eval.py established.
#
# The harm signal ALONE reaches WildJailbreak AUROC 0.7369 — the best of any rule
# there — but is much worse on sentinel_bench (0.8507 recall 0.5424) and
# TensorTrust (recall 0.6544). So the COMBINATION is what earns adoption, not a
# replacement of L1's existing tiers.
#
# HONEST CAVEAT, inherited and restated rather than dropped: layer3.py's own
# docstring discloses that HARM_ANCHOR_PHRASES covers five broad harm domains
# drawn from a standard threat taxonomy, and asks for validation "against a
# held-out benchmark with DIFFERENT harm categories before being trusted as
# general-purpose". A corpus whose malicious class concentrates in those five
# domains will flatter this signal. Neither WildJailbreak nor sentinel_bench was
# used to author the anchors — if anything they are LESS fitted to these corpora
# than L1's own templates, which were calibrated on sentinel_bench train — but
# that is not the same as a clean held-out claim about novel harm categories.
#
# WHY IT IS STILL OFF. Enabling it moves L1 onto a different axis, so
# L1_WARN_THRESHOLD must be re-derived there. Unlike L1_TIER_FUSION, that
# blocker is already closed: L1_HARM_FUSED_WARN_THRESHOLD below is the
# split-conformal threshold for this exact axis, derived by the same method, on
# the same corpus, at the same alpha. What remains before flipping the default is
# a decision to move every published L1 number, which is not a decision to take
# silently.
L1_HARM_CONTENT_TIER = os.getenv("L1_HARM_CONTENT_TIER", "false").lower() == "true"
# Split-conformal one-sided threshold for the mean(L1, harm) axis: 500 Alpaca
# benign, alpha=0.05, k = ceil(501*0.95) = 476. Measured Alpaca FPR at it: 0.0480.
# Used INSTEAD of L1_WARN_THRESHOLD when L1_HARM_CONTENT_TIER is on.
L1_HARM_FUSED_WARN_THRESHOLD = float(os.getenv("L1_HARM_FUSED_WARN_THRESHOLD", "0.3177"))

# ---------------------------------------------------------------------------
# L1 harm-PROBE tier (2026-09-21) — a learned readout of harmful INTENT.
#
# WHAT PROBLEM IT SOLVES, and why L1's existing tiers cannot. All four cascade
# tiers ask "does this look like an injection attempt". WildJailbreak's benign
# class is `adversarial_benign` — jailbreak-PHRASED prompts with harmless intent,
# included by its authors precisely to catch detectors that key on phrasing. No
# amount of tuning a style detector separates a style-matched pair; the question
# is unanswerable as posed. L1 reaches AUROC 0.5694 there, near chance.
#
# This tier asks a different question — is the underlying request harmful — using
# a linear probe on the sentence embedding, frozen at
# core/artifacts/l1_harm_probe.json.
#
# MEASURED ZERO-SHOT, on corpora the probe was never fitted on:
#
#                          probe alone    L1 alone    mean(L1, probe)
#   wildjailbreak  AUROC      0.8105       0.5694        0.7835
#   sentinel_bench AUROC      0.8670       0.8094        0.8561
#   tensortrust    recall     0.7105       0.8947        0.9228
#   alpaca         FPR        0.0020       0.0300        0.0080
#
# Every AUROC improves, TensorTrust recall improves, and Alpaca FPR FALLS. Unlike
# the harm-content tier this needs no new threshold: the probe publishes on the
# shared 0.50/0.85 axis via rescale_layer_score with frozen benign-quantile
# anchors, so mean(L1, probe) stays on L1's existing axis and L1_WARN_THRESHOLD
# still reads it correctly.
#
# THE CONTROLS THAT HAD TO PASS. This project has had two apparent breakthroughs
# turn out to be artifacts of corpus construction (results.md §8c.2 and §8c.3),
# so the probe was screened before adoption: a shape-only probe (length,
# punctuation, case — no semantics) transfers at 0.4137, BELOW chance; 50 refits
# on permuted labels average 0.5076; 200 fit-set bootstrap refits give
# [0.7723, 0.8275].
#
# THE COST, stated rather than buried. JailbreakBench and Alpaca are both
# reported L1 rows. Fitting on them retires JailbreakBench as a zero-shot row for
# this component, and Alpaca must be reported on rows 0-500, which are never
# fitted on. WildJailbreak, TensorTrust and sentinel_bench remain fully held out.
#
# THE ONE THING THAT GETS WORSE, and it is inherent rather than incidental: false
# positives on WildJailbreak's `adversarial_benign` over-refusal set rise from
# 0.2619 to 0.4095. A detector that genuinely recognises harmful intent will also
# refuse more prompts that merely sound like attacks. That is a deployer's policy
# call, which is the reason this defaults to OFF.
#
# Independent of L1_HARM_CONTENT_TIER. Enabling both averages twice and is not a
# configuration either tier was measured in.
L1_HARM_PROBE_TIER = os.getenv("L1_HARM_PROBE_TIER", "false").lower() == "true"


def l1_warn_threshold() -> float:
    """
    L1's warn anchor for whichever axis L1 is currently scoring on.

    WHY THIS IS A FUNCTION. A flag that changes a layer's score axis without
    moving the threshold that reads it is the RCA-#3 error, and this project has
    now hit that class of defect five times (L3's raw score vs the shared WARN,
    L1's own 0.4391, L2's 0.3729, L4's MEDIUM floor, and the threat_class bands
    on the fused axis). `L1_TIER_FUSION`'s comment still names it as that
    feature's open blocker (c).

    Reading the flag live here means enabling L1_HARM_CONTENT_TIER cannot leave
    the operating point behind on the max() axis — the two move together or not
    at all. Read this instead of the L1_WARN_THRESHOLD constant in any consumer
    that compares an L1 score against a threshold.

    NOTE the deliberate gap: L1_TIER_FUSION is NOT handled here, because no
    conformal threshold has been derived for the fused-logistic axis. Inventing
    one would be exactly the silent miscalibration this function exists to
    prevent, so that flag keeps its documented blocker.
    """
    if L1_HARM_CONTENT_TIER:
        return L1_HARM_FUSED_WARN_THRESHOLD
    return L1_WARN_THRESHOLD

# Layer 2 — Tool-Response Content (InjecAgent-calibrated)
# See l4_find_threshold.py / l4_ds_eval.py: Youden's J on real ingest_chunk()
# trust_score for tool-response-shaped text (510-row direct-harm set,
# confirmed on an independent 544-row data-stealing subset).
#
# LEGACY AXIS ONLY (R-017, 2026-09-25). It is a TRUST cutoff derived when every
# tool response was scored `1 - (0.6*density + 0.4*L1)`. Since the document-threat
# scorer became the default (2026-09-24), a tool response >= 600 chars is scored on
# the doc axis instead, where `trust < 0.813` means threat > 0.187 -- below even the
# doc axis's lowest WARN anchor (0.250618). On AgentDojo's benign traces 73 of L4's 189
# false alarms are parameters copied from FLAGGED benign outputs; 82 of the 305 outputs
# are long enough for the doc axis, so this defect is part of those 73, not all of them
# (the 2026-09-24 artifacts did not record the axis; the re-run does).
# Read `l2_tool_response_flagged(metadata)`, never this constant, in a consumer.
L2_TOOL_RESPONSE_FLAG_THRESHOLD = float(os.getenv("L2_TOOL_RESPONSE_FLAG_THRESHOLD", "0.813"))

# L2 SHORT third-party text (B-4/B-5, 2026-09-25). "legacy" (shipped) = the
# 0.6*density + 0.4*L1 composition below the 600-char gate; "piguard" = the short Mondrian
# bin of the doc axis (document_threat.short_document_threat): PIGuard injection
# probability noisy-OR'd with dangerous code, on its OWN split-conformal anchors, derived
# by scratch/rca/R026_short_doc_anchor.py on benign news paragraphs (150-599 chars,
# disjoint from every other calibration set). Unset anchors -> the bin stays unavailable.
L2_SHORT_DOC_SCORER = os.getenv("L2_SHORT_DOC_SCORER", "piguard").strip().lower()        # adopted 2026-09-26 (R-026 v2 gate)
L2_DOCUMENT_THREAT_WARN_THRESHOLD_SHORT = float(os.getenv("L2_DOCUMENT_THREAT_WARN_THRESHOLD_SHORT", "0.999712"))   # R-026 v2
L2_DOCUMENT_THREAT_BLOCK_THRESHOLD_SHORT = float(os.getenv("L2_DOCUMENT_THREAT_BLOCK_THRESHOLD_SHORT", "0.999933"))   # R-026 v2
# Judge cascade on the short bin: only when the judge is enabled and the short-bin threat
# is inside this band does the (hosted) judge read the text; its verdict is max-fused.
# The band is on the short bin's own axis; the anchors must be derived with the same
# setting (R026 records it).
L2_SHORT_DOC_JUDGE = os.getenv("L2_SHORT_DOC_JUDGE", "false").lower() == "true"
L2_SHORT_DOC_JUDGE_BAND = (float(os.getenv("L2_SHORT_DOC_JUDGE_LO", "0.10")),
                           float(os.getenv("L2_SHORT_DOC_JUDGE_HI", "0.90")))

# app.py compares tool-output L2 RAW against WARN 0.50 (owed since 2026-09-20). True =
# publish it on the shared axis via l2_shared_score. Off until measured on live traffic:
# it moves live blocking (legacy anchor 0.3729 -> more WARNs; doc prose anchor 0.25 ->
# more BLOCKs), and pipeline_sim's half stays blocked on SPLIT-Bench regeneration.
L2_SHARED_AXIS_IN_APP = os.getenv("L2_SHARED_AXIS_IN_APP", "false").lower() == "true"
# ONE switch for app AND simulator (SPLIT-Bench v2 plan): L2 published on the shared axis via
# l2_shared_score everywhere. Must be ON when SPLIT-Bench v2 is generated -- the owed fix
# that broke 349/680 v1 certificates is resolved by regenerating, not by leaving L2 raw.
L2_SHARED_AXIS = (os.getenv("L2_SHARED_AXIS", "").lower() == "true") or L2_SHARED_AXIS_IN_APP

# Deployable cross-layer SCORE fusion (core/pipeline_fusion.py): "off" (shipped) | "warn" |
# "warn_block". Frozen logistic fitted on sentinel_bench mining_set, alarm anchors
# split-conformal on the benign multi-layer arm (sentinel/eval/fit_pipeline_fusion.py).
PIPELINE_FUSION = os.getenv("PIPELINE_FUSION", "off").strip().lower()

# Retrieval relevance floor (B-3). 0.0 = off (shipped behaviour).
L2_RETRIEVAL_MIN_SIMILARITY = float(os.getenv("L2_RETRIEVAL_MIN_SIMILARITY", "0.0"))

# Doc-axis counterpart, a THREAT cutoff. Unset (default) -> the Mondrian WARN anchor
# of the output's content-type bin, i.e. flagged exactly when the store routes the
# output to review. `calibrate_tool_response_flag.py` derives a tool-output-specific
# value on benign AgentDojo outputs (task-level held-out split) and prints it.
L2_TOOL_RESPONSE_DOC_FLAG_THRESHOLD = (
    float(os.environ["L2_TOOL_RESPONSE_DOC_FLAG_THRESHOLD"])
    if os.getenv("L2_TOOL_RESPONSE_DOC_FLAG_THRESHOLD") else None)

# Layer 2 — the (warn, block) pair L2's score is mapped onto the shared
# WARN/BLOCK axis with, via core.models.rescale_layer_score. Added 2026-09-20.
#
# WHY THIS EXISTS. L1 and L3 publish their scores on the shared axis through
# their own calibrated anchors; L2 never did. Its score is
# `1 - trust = 0.6*density + 0.4*l1_score`, and it was compared directly against
# WARN_THRESHOLD = 0.50. Measured on the real ingest path
# (scratch/rca_l2_axis.py, scratch/rca_l2_axis.json):
#
#   arm                      n     mean chars   p50      p95      max
#   alpaca benign          500            84  0.2317   0.3729   0.5844
#   bipia_local benign     300          1609  0.2514   0.3683   0.4967
#   sentinel_bench benign   53           398  0.3634   0.4272   0.4272
#   sentinel_bench mal      59           383  0.4270   0.7148   0.7548
#
# and from the stored BIPIA run (eval_L2_bipia_local_20260920_131845), malicious
# p50 0.3138 / p95 0.478 with only 4.11% of samples at or above 0.50. The
# reported recall of 0.0411 on that row is therefore not a detection result: the
# shared threshold sits at L2's malicious 95.9th percentile. This is the same
# defect class as L3's multi-turn term being capped below its own threshold — a
# threshold outside its quantity's usable range — and the paper's interface
# site 2 already recorded L2's half of it as unmeasured. It is now measured.
#
# HOW L2_WARN_THRESHOLD WAS DERIVED. Split-conformal one-sided threshold
# selection at alpha = 0.05 over 500 real Alpaca benign samples scored through
# the real, unmodified `layer2_ingest()` — the identical method, corpus and
# alpha used for L1_WARN_THRESHOLD, so this introduces no new methodology.
# n=500, alpha=0.05 => k = ceil(501*0.95) = 476 => tau = 0.372876.
#
# Benign data only. No labels, and no malicious corpus, so there is nothing that
# has to transfer and nothing fitted to a test split.
#
# CROSS-CORPUS STRESS TEST, Clopper-Pearson 95% CI, `HELD` by the
# `ci_low > alpha` criterion in conformal_risk_control:
#
#   alpaca benign (same source)  n=500  FPR 0.0480  (0.0310, 0.0706)  HELD
#   bipia_local benign (heldout) n=300  FPR 0.0400  (0.0208, 0.0688)  HELD
#   sentinel_bench benign (heldout) n=53 FPR 0.0755 (0.0209, 0.1821)  HELD
#
# Worth stating plainly because it is the opposite of L1's result: L1's
# conformal anchor is VIOLATED on WildJailbreak benign (0.2667 against
# alpha=0.05, Contribution D). L2's transfers to two further benign
# distributions that differ by 19x in document length. The anchor is a property
# of the layer, not of Alpaca.
#
# MEASURED EFFECT ON DETECTION. sentinel_bench malicious recall at this anchor
# is 0.8305, against 0.4407 at the shared 0.50 on the same samples and the same
# code. AUROC is UNCHANGED by construction — rescale_layer_score is strictly
# monotone, so this moves the operating point and not the ranking. The gain is
# real but it is a calibration gain, and this comment says so rather than
# letting it read as a capability gain.
#
# L2_BLOCK_THRESHOLD is not new either: it is `1 - QUARANTINE_THRESHOLD`
# (chunk_store.py), L2's own hard-block point, at which measured FPR is 0.0000
# on all three benign arms and sentinel_bench malicious recall is 0.3390.
#
# HONEST SCOPE. Derived from one benign corpus and confirmed on two more. The
# METHOD is general; re-derive against a deployment's own benign traffic before
# trusting the number there, exactly as L1's comment says of its own anchor.
L2_WARN_THRESHOLD = float(os.getenv("L2_WARN_THRESHOLD", "0.372876"))
L2_BLOCK_THRESHOLD = float(os.getenv("L2_BLOCK_THRESHOLD", "0.600"))

# The WARN anchor for the REBUILT document-threat axis (L2_DOCUMENT_THREAT_SCORER).
#
# WHY A SECOND ANCHOR EXISTS, and why a single one was refuted by measurement.
# `document_threat_score` applies only to documents >= L2_MIN_DOC_CHARS (600);
# shorter input falls back to the legacy `0.6*density + 0.4*L1` composition. Those
# are two DIFFERENT axes, and results.md 8j.7 recorded "a single conformal tau
# serving both" as a limitation to revisit. Revisited 2026-09-22, and it is not a
# limitation but a defect:
#
#   sentinel_bench (every document under the gate, so entirely on the LEGACY axis)
#     tau = 0.372876  recall 0.8305  FPR 0.0755   <- current
#     tau = 0.357431  recall 0.8305  FPR 0.7170   <- adopting the new tau globally
#
#   34 benign sentinel_bench documents sit in the band [0.357431, 0.372876) and
#   ZERO malicious ones. A single tau would have raised that corpus's L2 false
#   positives 9.5x for no recall whatever.
#
# So the anchor is selected by which scorer produced the score, via
# `l2_warn_threshold_for()`. This is the same principle the project applies
# everywhere else: a threshold belongs to an axis, and comparing a score against
# another axis's threshold is the RCA-#3 error (L3 2026-07-25, L1 2026-09-18, and
# once by hand during the L2 rebuild itself).
#
# HOW IT WAS DERIVED. Split-conformal at alpha = 0.05 over 150 bipia_local benign
# documents, disjoint from the 150 used to report FPR (scratch/l2x/validate.py).
# n=150 => k = ceil(151*0.95) = 144 => tau = 0.357431. Benign only; no labels.
# Held-out result at this anchor: AUROC 0.9342, recall 0.7225, FPR 0.0400.
#
# BLOCK is deliberately NOT duplicated: L2_BLOCK_THRESHOLD is the structural point
# `1 - QUARANTINE_THRESHOLD`, and both scorers publish `threat` on [0,1] feeding
# `trust_score = 1 - threat`, so it means the same thing on either axis.
#
# RE-DERIVED 2026-09-23 (#1, scratch/rca/LEDGER.md R-006) -- MONDRIAN (content-type-
# conditional) split-conformal, because the single anchor above hid a failure:
#
#   benign CODE documents on the doc axis: Prompt Guard's non-benign mass is 0.93-0.99
#   on ordinary Stack-Overflow-style answers ("you need to instantiate ... ```code```").
#   At the old single anchor 0.357431 BIPIA's benign code arm was flagged 20 % (the
#   pooled 3-4 % hid it), and real benign code answers from WildChat ~46-52 %.
#
# So the anchor is conditioned on sentinel.core.content_type (a structural router that
# already existed) and each bin is calibrated on BENIGN documents of its own kind,
# DISJOINT from BIPIA, so all 300 BIPIA benign become a held-out arm:
#   non-code  XSum-train + NewsQA-train articles >= 600 chars (BIPIA's abstract/qa
#             contexts come from these sources; zero textual overlap found), cal half
#             n=301 by md5 -> alpha 0.05: tau 0.250618 (k=287); alpha 0.01: 0.553796
#   code      ChatGPT code-bearing ANSWERS from WildChat-1M (English, non-toxic, not in
#             any Track-B split), cal half n=220 -> alpha 0.05: tau 0.644572 (k=210);
#             alpha 0.01: 0.776558 (k=219)
# WARN = the alpha 0.05 bin anchor (L2's channel budget, see R-007). BLOCK = max(the
# structural 0.60, the bin's alpha 0.01 anchor): for code the structural point would sit
# BELOW its own WARN, which is not an operating point at all.
# Held out (never calibrated on): news FPR 0.0234 (n=299), WildChat code 0.0522 (n=230),
# BIPIA benign 0.0133 overall (code 0.06, 3/50), BIPIA malicious recall 0.636 (500,
# disjoint from the scorer's dev set) -- vs the legacy L2 on the SAME samples at its own
# anchor: recall 0.148 at FPR 0.040. Judge off; the doc axis never reads L1.
L2_DOCUMENT_THREAT_WARN_THRESHOLD = float(
    os.getenv("L2_DOCUMENT_THREAT_WARN_THRESHOLD", "0.250618"))
L2_DOCUMENT_THREAT_WARN_THRESHOLD_CODE = float(
    os.getenv("L2_DOCUMENT_THREAT_WARN_THRESHOLD_CODE", "0.644572"))
L2_DOCUMENT_THREAT_BLOCK_THRESHOLD_CODE = float(
    os.getenv("L2_DOCUMENT_THREAT_BLOCK_THRESHOLD_CODE", "0.776558"))


def _doc_axis(metadata: dict | None):
    """The document_threat detail dict when the rebuilt scorer produced the score."""
    if not L2_DOCUMENT_THREAT_SCORER or not metadata:
        return None
    dt = metadata.get("document_threat")
    return dt if isinstance(dt, dict) and dt.get("available") is True else None


def _short_bin(dt: dict) -> bool:
    return dt.get("content_type") == "short" or dt.get("bin") == "short"


def l2_warn_threshold_for(metadata: dict | None = None) -> float:
    """L2's WARN anchor for the axis -- and, on the doc axis, the content type -- that
    actually produced this score.

    Pass the `metadata` dict from `layer2_ingest`/`ingest_chunk`. Legacy axis: the
    legacy anchor. Doc axis: the Mondrian bin anchor (code vs everything else).

    Read this instead of the `L2_WARN_THRESHOLD` constant in any consumer that
    compares an L2 score against a threshold or rescales it onto the shared axis.
    Calling with no metadata returns the legacy anchor, which is correct for every
    caller that predates the rebuilt scorer.
    """
    dt = _doc_axis(metadata)
    if dt is None:
        return L2_WARN_THRESHOLD
    if _short_bin(dt):
        if L2_DOCUMENT_THREAT_WARN_THRESHOLD_SHORT is None:
            raise RuntimeError("short-document bin scored without a derived anchor "
                               "(scratch/rca/R026_short_doc_anchor.py)")
        return L2_DOCUMENT_THREAT_WARN_THRESHOLD_SHORT
    if dt.get("content_type") == "code":
        return L2_DOCUMENT_THREAT_WARN_THRESHOLD_CODE
    return L2_DOCUMENT_THREAT_WARN_THRESHOLD


def l2_block_threshold_for(metadata: dict | None = None) -> float:
    """L2's BLOCK anchor for the axis/bin that produced this score (see above)."""
    dt = _doc_axis(metadata)
    if dt is not None and _short_bin(dt):
        if L2_DOCUMENT_THREAT_BLOCK_THRESHOLD_SHORT is None:
            raise RuntimeError("short-document bin scored without a derived BLOCK anchor")
        return max(L2_DOCUMENT_THREAT_BLOCK_THRESHOLD_SHORT, l2_warn_threshold_for(metadata) + 1e-6)
    if dt is not None and dt.get("content_type") == "code":
        return max(L2_BLOCK_THRESHOLD, L2_DOCUMENT_THREAT_BLOCK_THRESHOLD_CODE)
    return L2_BLOCK_THRESHOLD


def l1_harm_shared(harm_score: float | None) -> float:
    """The harm head on the SHARED axis: tau -> WARN, capped below BLOCK unless
    L1_HARM_MAY_BLOCK with a derived L1_HARM_BLOCK_TAU. Strictly monotone. 0.0 if absent."""
    if harm_score is None:
        return 0.0
    from sentinel.core.safety_guard import map_to_layer_axis
    if L1_HARM_MAY_BLOCK and L1_HARM_BLOCK_TAU is not None:
        s = float(harm_score)
        if s >= L1_HARM_BLOCK_TAU:
            return BLOCK_THRESHOLD + (s - L1_HARM_BLOCK_TAU) / max(1e-9, 1 - L1_HARM_BLOCK_TAU) * (1 - BLOCK_THRESHOLD)
        return map_to_layer_axis(s, L1_HARM_TAU, WARN_THRESHOLD, BLOCK_THRESHOLD - 1e-6) if s <= L1_HARM_BLOCK_TAU else BLOCK_THRESHOLD
    return map_to_layer_axis(float(harm_score), L1_HARM_TAU, WARN_THRESHOLD, BLOCK_THRESHOLD - 1e-6)


def l2_shared_score(metadata: dict | None) -> float:
    """L2's `1 - trust` on the SHARED WARN/BLOCK axis, rescaled with the (warn, block)
    pair of the axis and Mondrian bin that produced it (R-027). Read this instead of
    rescaling with constants: the runner used the constant L2_BLOCK_THRESHOLD (0.60)
    with the code bin's WARN 0.6446, i.e. an inverted interval."""
    from sentinel.core.models import rescale_layer_score
    meta = metadata or {}
    raw = 1.0 - float(meta.get("trust_score", 1.0))
    return rescale_layer_score(raw, l2_warn_threshold_for(meta), l2_block_threshold_for(meta),
                               WARN_THRESHOLD, BLOCK_THRESHOLD)


def l2_tool_response_flagged(metadata: dict | None) -> bool:
    """Whether an ingested tool response is untrusted third-party content, judged on
    the axis that scored it (R-017). Flagged outputs feed `session.l2_flagged_chunks`,
    and L4 hard-blocks (0.97) any parameter copied from one.

    Legacy axis: trust < L2_TOOL_RESPONSE_FLAG_THRESHOLD (unchanged).
    Doc axis:    threat >= L2_TOOL_RESPONSE_DOC_FLAG_THRESHOLD when set, else the
                 content-type bin's WARN anchor (the store's own review cut).
    """
    meta = metadata or {}
    dt = _doc_axis(meta)
    if dt is None:
        return float(meta.get("trust_score", 1.0)) < L2_TOOL_RESPONSE_FLAG_THRESHOLD
    cut = (L2_TOOL_RESPONSE_DOC_FLAG_THRESHOLD if L2_TOOL_RESPONSE_DOC_FLAG_THRESHOLD is not None
           else l2_warn_threshold_for(meta))
    return float(dt["threat"]) >= cut
# The alpha L2_WARN_THRESHOLD was calibrated at, recorded so the guarantee can
# be restated and re-derived without archaeology (same as L1_CONFORMAL_ALPHA).
L2_CONFORMAL_ALPHA = float(os.getenv("L2_CONFORMAL_ALPHA", "0.05"))

# Layer 2 — Content-type-conditional template routing (Phase 5 / 3B.6)
#
# OFF BY DEFAULT, deliberately. Phase 2.4 mined four genuinely better
# templates for BIPIA's qa/abstract scenarios (held-out AUROC 0.7008 ->
# 0.7120) and correctly rejected them, because INSTRUCTIONAL_TEMPLATES is
# one global list and the same change cost BIPIA's code scenario -0.0417.
# Routing the template set by content type captures the gain without the
# cost, since the two sets then never score the same content.
#
# ADOPTED 2026-09-18 after the cross-scenario regression check this comment
# originally demanded — the same check that correctly killed Phase 2.4's
# global-list attempt. All five BIPIA scenarios, identical samples, only the
# flag differing (120 malicious / 50-60 benign per scenario, seed 42, drawn
# from the held-out bipia_local test cache):
#
#   scenario     routing OFF   routing ON     delta
#   qa              0.6942       0.7206      +0.0264
#   abstract        0.6778       0.6885      +0.0107
#   code            0.6646       0.6646      +0.0000
#   email           0.6987       0.6987      +0.0000
#   table           0.8005       0.8005      +0.0000
#
# STRICTLY DOMINANT: both long-form scenarios improve, and the three
# non-long-form scenarios are BIT-IDENTICAL. Phase 2.4's blocker (code
# -0.0417) is eliminated entirely, because the mined templates now only
# ever reach content classified as long-form and never touch code or
# tables. That is enforced structurally, not by tuning — see
# `_TEMPLATES_BY_CONTENT_TYPE`: any content type not explicitly listed
# resolves to exactly INSTRUCTIONAL_TEMPLATES.
#
# Absolute AUROCs here are NOT directly comparable to B.5's published
# figures (different subsample sizes, and scored through
# calculate_instruction_density directly rather than the runner's
# trust-score path). The DELTAS are the valid quantity: same samples, same
# code path, one flag changed.
L2_CONTENT_TYPE_ROUTING = os.getenv("L2_CONTENT_TYPE_ROUTING", "true").lower() == "true"

# Layer 5 — Provenance-based leak detection (AgentLeak-calibrated)
#
# Minimum character length for an identifier-shaped value (one containing a
# digit, or carrying an explicit sensitivity marker) to be tracked as a
# candidate leak value. This is a SPECIFICITY bar, not a formatting rule:
# below it, ordinary content — years ("2024"), order numbers ("4521"),
# prices ("25405.41") — starts matching by coincidence and every retrieved
# document turns into a leak alert. Above it, a value echoed verbatim in
# the output is very unlikely to be there by chance.
#
# Calibrated 2026-09-18 (Phase 5 Stage 0a / plan item 3B.4) on a
# train/test split of AgentLeak's 5,006 real traces, split by MD5 of
# sample_id (train n=2,456 / test n=2,550), swept on TRAIN ONLY. The
# sweep was run against the real implementation via an offline model of
# the provenance rule that was first verified to reproduce a real
# end-to-end run's per-sample decisions at 5,006/5,006 = 100% agreement,
# so the numbers below are the real ones, not an approximation.
#
#   TRAIN    recall     FPR    prec      F1   Youden J
#   (none)   0.8408  0.0725  0.8195  0.8300   0.7683   <- name-only baseline
#        9   0.8900  0.0827  0.8081  0.8471   0.8073
#       11   0.8857  0.0827  0.8074  0.8447   0.8030
#       12   0.8857  0.0725  0.8270  0.8553   0.8132   <- train argmax (J and F1)
#       16   0.8857  0.0725  0.8270  0.8553   0.8132
#
# 12 is the SMALLEST bar achieving the train argmax on both Youden's J
# and F1 — the tie-break is deliberate: least restrictive choice
# consistent with the optimum, so a deployment whose identifier formats
# differ from this corpus keeps the most candidates.
#
# WHY THE BAND BELOW 12 HURTS, mechanistically (checked, not assumed):
# the values of length 9-11 that actually matched output text are
# dominated by DISP-###### (97) and EMP-##### (29) — short scenario
# reference IDs AgentLeak's own ground truth does not treat as protected
# disclosures — plus bare four-digit years (2026, 2022, 2021 ...), which
# carry no identifying information at all. Excluding that band removes
# every added false positive while keeping the case/account/phone-shaped
# values the extension was added for.
#
# HELD-OUT CONFIRMATION at 12 (test split, never used for selection):
#   recall 0.8223 -> 0.8675, FPR 0.0748 -> 0.0748 (unchanged),
#   precision 0.7948 -> 0.8033, F1 0.8083 -> 0.8342.
# Full-corpus effect vs. the 2026-09-14 baseline: recall 0.8317 ->
# 0.8768, precision 0.8073 -> 0.8154, F1 0.8193 -> 0.8450, FPR 0.0737 ->
# 0.0737. Strictly dominant — every metric improves or holds.
#
# NOTE, stated rather than buried: bar=9 reaches a higher held-out recall
# (0.8870) than 12 (0.8675), and a marginally higher held-out Youden J
# (0.7948 vs 0.7912). It was NOT selected, because selection happens on
# train and held-out only reports — picking 9 on the strength of its test
# numbers would be selecting on the test split, the exact discipline
# failure this project's calibrations exist to avoid. 12 also wins
# held-out F1 and precision.
#
# HONEST SCOPE: derived from one corpus. The mechanism (track specific
# values from sensitive sources, flag verbatim reappearance) is general;
# this particular number is not claimed to be. Re-derive it against a
# deployment's own benign traffic before trusting it there — the cost of
# setting it too low is false positives on ordinary numeric content.
# One consequence worth knowing: an SSN-shaped value ("787-08-3753", 11
# chars) falls below this bar. That is fine here and not a coverage gap —
# SSNs have a fixed format and are already caught by pii_scanner.py's
# `ssn` pattern. The provenance path exists for values that have NO fixed
# format, which is exactly why it must not be tuned to catch ones that do.
L5_PROVENANCE_MIN_IDENTIFIER_LEN = int(os.getenv("L5_PROVENANCE_MIN_IDENTIFIER_LEN", "12"))

# Upper bound on how many candidate sensitive values a single session may
# accumulate. Generalizing the extractor beyond name-shaped strings (3B.4)
# materially increases how many values one ingested document can
# contribute — a document dense with identifiers could otherwise grow this
# list without limit for the session's lifetime, and L5 walks the whole
# list on every output scan. Same bounded-state posture as
# MAX_TRACKED_SESSIONS / MAX_STORED_EVENTS below (see core/bounded_cache.py);
# oldest-first retention, since earlier-ingested context is what a later
# output is most likely to be leaking.
MAX_TRACKED_SENSITIVE_VALUES = int(os.getenv("MAX_TRACKED_SENSITIVE_VALUES", "512"))

# Layer 4 — Decision Threshold (InjecAgent-calibrated, additive ceiling)
# Youden's J-optimal on audit_tool_call()'s final_score once tool-response
# text is actually routed through L2 (see L2_TOOL_RESPONSE_FLAG_THRESHOLD
# above). Applied as an EXTRA should_execute=False condition on top of
# tool_auditor.py's existing ad hoc branches, not a replacement for them.
L4_DECISION_THRESHOLD = 0.970

# Layer 4 — the (warn, block) pair L4's score is mapped onto the shared
# WARN/BLOCK axis with, via core.models.rescale_layer_score. Added 2026-09-20.
#
# WHY THIS EXISTS. L1 and L3 publish their scores on the shared axis through
# their own calibrated anchors; L4 never did, and its raw score was compared
# directly against WARN_THRESHOLD = 0.50. `risk_matrix.risk_to_score` maps
# MEDIUM to EXACTLY 0.5, and `core.models.score_to_action` compares with `>=`,
# so **every tool call whose name is not in TOOL_RISK_MATRIX is a WARN by
# arithmetic**, regardless of content. Unknown tool names are the norm outside
# this project's own corpora: InjecAgent's tools are real product API names
# (`AugustSmartLockGrantGuestAccess`, `GmailSearchEmails`, ...), all of which
# fall through `evaluate_tool_risk`'s MEDIUM default.
#
# MEASURED CONSEQUENCE, the reason this is a defect and not a preference: on
# both InjecAgent subsets every one of the 17 benign user cases is flagged and
# the reported FPR is exactly 1.0000
# (eval_L4_injecagent_dedicated_20260920_103027). The benign floor of a
# quantised layer sat on the global decision boundary.
#
# NEITHER ANCHOR IS A NEW NUMBER, which is what keeps this from being a tuning
# step. Both already existed and are already calibrated:
#
#   warn  = 0.70  tool_auditor.py's CONTEXT_DERIVED escalation — L4's own
#                 "this is worth surfacing" level, and the lowest score any
#                 escalation branch in that file can produce.
#   block = 0.97  L4_DECISION_THRESHOLD above, unchanged: L4's own
#                 Youden's-J-calibrated "do not execute" point.
#
# Effect of the mapping, which is strictly monotone and therefore changes no
# AUROC/AUPRC anywhere — only the operating point:
#   raw 0.20 (LOW)      -> 0.143  ALLOW
#   raw 0.50 (MEDIUM)   -> 0.357  ALLOW   <- was WARN
#   raw 0.70            -> 0.500  WARN
#   raw 0.90            -> 0.759  WARN
#   raw 0.97            -> 0.850  BLOCK
L4_WARN_THRESHOLD = float(os.getenv("L4_WARN_THRESHOLD", "0.70"))
L4_BLOCK_THRESHOLD = float(os.getenv("L4_BLOCK_THRESHOLD", str(L4_DECISION_THRESHOLD)))

# Layer 3 — Conversational Drift Tracker
L3_VELOCITY_THRESHOLD = 0.45
L3_DRIFT_THRESHOLD = 0.60
L3_MAX_HISTORY = 10           # Max turns to keep in embedding history

# Layer 3 — Score Weights
#
# NOTE (2026-07-25 RCA #1, see sentinel/layers/layer3.py module docstring for
# the full writeup): velocity and drift are combined MULTIPLICATIVELY, not
# additively — `drift * (1 - velocity) * (L3_DRIFT_WEIGHT + L3_VELOCITY_WEIGHT)`.
# This fixed a below-chance AUROC (0.26) but a subsequent real run against
# the live embedding model still only reached AUROC=0.6145 — below the
# "something's wrong, not just hard" line the testing guide itself sets
# (0.70). See RCA #2 below and layer3.py's module docstring for the deeper
# root cause and the fix (a harm-topic-anchor content signal).
#
# NOTE (2026-07-25 RCA #2): `L3_HARM_ALIGNMENT_WEIGHT` now carries the
# majority of the score budget because the drift/velocity geometry alone
# was shown NOT to discriminate this benchmark's classes (see layer3.py's
# docstring) — cumulative_drift * smoothness is kept only as a secondary/
# backstop signal for gradual-drift patterns the harm anchors don't cover.
# All four numbers below are still hand-set placeholders pending real
# ROC-based calibration (roadmap doc Section 6.3) — run
# `sentinel/eval/calibrate_l3_weights.py` against a real embedding model to
# get data-driven values, then confirm on custom_l3/test.jsonl.
L3_VELOCITY_WEIGHT = 0.10
L3_DRIFT_WEIGHT = 0.15
L3_HARM_ALIGNMENT_WEIGHT = 0.50
L3_ESCALATION_WEIGHT = 0.25
L3_HARM_ALIGNMENT_THRESHOLD = 0.45  # cosine similarity above this → reason string flags it
# ESCALATION_PHRASES converted from literal substring matching to cosine
# similarity 2026-09-11 (measured hit rate on real MHJ text: 0-0.8%,
# essentially dead — same brittleness L1/L2's original template lists had
# before their own semantic-similarity fixes). Placeholder pending the
# same kind of real held-out calibration L1/L2 got — see layer3.py's
# ESCALATION_ANCHOR_PHRASES comment.
L3_ESCALATION_THRESHOLD = 0.45

# CALIBRATED 2026-09-18 (Phase 5 Stage 0a / plan item 3B.1): L3_WARN_THRESHOLD
# 0.30 -> 0.27. The note below correctly flagged 0.30 as a PLACEHOLDER GUESS
# and asked for a real Youden's-J calibration before trusting it; this is
# that calibration, run against a real external corpus instead of the
# internal one. `calibrate_l3_weights.py:324` documents Youden's J as the
# intended procedure for this exact constant, so the method here is the
# project's own, not a new one.
#
# Method: tom-gibbs (n=5,336: 4,136 malicious / 1,200 benign, the
# post-Phase-2.1b cipher-decode run eval_L3_tomgibbs_mt_20260914_175643),
# carved into train/test by MD5 of sample_id (train n=2,723 / test
# n=2,613) because tom-gibbs ships no split — same discipline B.7 already
# applied to MHJ. Threshold swept on TRAIN ONLY; train Youden argmax
# 0.2686 (J=0.4032), rounded to 0.27. Rounding is deliberate: a
# sensitivity check showed held-out J moves 0.3805 -> 0.3773 between the
# two, i.e. the 4th decimal is noise, and quoting it would be exactly the
# false precision B.10 of the results record warns against.
#
#   HELD-OUT TEST (never used for selection)
#   th       recall     FPR    precision   Youden J
#   0.235    0.7279   0.3697     0.8697     0.3582   <- what the paper reported
#   0.27     0.4832   0.1059     0.9393     0.3773   <- adopted
#   0.30     0.3266   0.0303     0.9734     0.2963   <- previous placeholder
#
# CROSS-CORPUS REGRESSION CHECK, required before adopting (the same check
# that correctly killed Phase 2.4's qa/abstract templates): on MHJ — never
# used for this calibration — recall improves 0.0455 -> 0.0818 at 0.30 ->
# 0.27 with FPR staying at exactly 0.0000 and precision at 1.0000. No
# regression; a strict improvement on the second corpus too. The only
# other L3 corpus, custom_l3, has no usable current result — its available
# run (2026-07-19) predates L3's scoring rewrite and is degenerate
# (FPR=1.0 at every threshold), so it was NOT used as evidence in either
# direction rather than being quoted misleadingly.
#
# WHAT THIS INVALIDATES, stated rather than discovered later: this constant
# is also the anchor `core.models.rescale_layer_score` maps to the shared
# WARN scale, so it feeds app.py (2 sites), pipeline_sim.py, and through
# them the internal ablation, SPRT, pattern-mining and Phase 4 benchmark
# verification numbers. Any of those computed before this date were
# computed at 0.30. The correlation engine's SLOW_BURN_INJECTION rule
# (l3_current > 0.7) now fires at raw >= ~0.4008 rather than ~0.4143 —
# slightly more sensitive, structurally unchanged.
#
# NOTE (2026-07-25 RCA #3, see sentinel/core/models.py's rescale_layer_score
# docstring for the full writeup): a confirmed real run scored L3 alone at
# AUROC=0.9795 (excellent ranking) but Precision=Recall=FPR=0.0000 at the
# shared WARN_THRESHOLD=0.50 — L3's raw score, under real sentence-embedding
# cosine similarities, never actually reaches anywhere near 0.50 even for
# genuinely malicious conversations (a well-documented compression property
# of real sentence embeddings, not a bug). These two numbers are PLACEHOLDER
# GUESSES, not measured values — run calibrate_l3_weights.py's threshold-
# suggestion section (against the real embedding model, on train) and
# replace these with its output before trusting them. Everything that
# checks l3_result.score against WARN_THRESHOLD/BLOCK_THRESHOLD in
# app.py/runner.py should instead rescale through
# core.models.rescale_layer_score(raw, L3_WARN_THRESHOLD, L3_BLOCK_THRESHOLD,
# WARN_THRESHOLD, BLOCK_THRESHOLD) first.
L3_WARN_THRESHOLD = float(os.getenv("L3_WARN_THRESHOLD", "0.27"))
L3_BLOCK_THRESHOLD = float(os.getenv("L3_BLOCK_THRESHOLD", "0.50"))

# Embedding Model — pinned to a specific revision for reproducibility
# (Section 6.4 of the roadmap, Section 8 of the evaluation plan).
# To find the current revision: check HuggingFace commits page for
# sentence-transformers/all-MiniLM-L6-v2 and update this hash.
EMBEDDING_MODEL = "all-MiniLM-L6-v2"
EMBEDDING_MODEL_REVISION = "8b3219a92973c328a8e22fadcfa821b5dc75636a"

# Bounded in-memory state — every session-keyed store in this codebase
# (Layer 3's drift tracker, the Threat Bus's session table, the correlation
# engine's fired-rule tracker) previously grew without eviction for the
# lifetime of the process. These caps bound that memory growth via LRU
# eviction (see sentinel/core/bounded_cache.py). Tune upward for higher
# expected concurrent-session volume in production.
MAX_TRACKED_SESSIONS = int(os.getenv("MAX_TRACKED_SESSIONS", "10000"))
MAX_STORED_EVENTS = int(os.getenv("MAX_STORED_EVENTS", "5000"))


# ---------------------------------------------------------------------------
# L2 rebuilt document threat scorer (2026-09-21).
#
# WHAT IT REPLACES. `chunk_store._compute_trust_score` computes
# `1 - (0.6*instruction_density + 0.4*l1_score)`. Both terms measure the same
# property — instruction-shapedness (results.md §8e) — so L2 was one signal
# counted twice, with weights the code called "a principled starting point".
#
# THE DEFECT THAT ACTUALLY MATTERED. L1's Tier 3 is Prompt-Guard-86M, whose three
# heads are collapsed to `jailbreak_prob`. That is correct for L1 (on short
# conversational turns the `injection` head scores AUROC 0.185, inverted), but
# prompt_guard.py's own note says that head was trained for "instructions embedded
# within longer retrieved/third-party documents". L2 scans exactly those, and was
# using the head rejected for the other distribution.
#
# MEASURED on 1,800 BIPIA documents (1,500 malicious / 300 benign, stratified by
# scenario and insertion position):
#
#                                         AUROC   worst scenario   R@1%FPR
#   shipped 0.6*density + 0.4*L1         0.7186*      0.7013*         --
#   + correct Prompt Guard head          0.9071       0.7462        0.2507
#   + instruction-contrast term          0.9093       0.8123        0.3113
#   + overlapping segments for long docs 0.9551       0.8068        0.3740
#   + dangerous-code indicator           0.9502       0.8699        0.4133
#   (* full-corpus reference, n=42,800)
#
# The last step trades 0.005 of pooled AUROC for +0.063 on the worst scenario and
# +0.04 recall at 1% FPR — robustness and the low-FPR operating region were
# preferred over pooled ranking.
#
# NOT FITTED. Every term is either a pretrained model output or a document-local
# statistic. A fitted embedding fusion was tried and rejected on evidence:
# out-of-fold 0.9269 but leave-one-scenario-out 0.7910, versus 0.8909 for the
# unfitted rule.
#
# WHY IT IS OFF BY DEFAULT. Enabling it changes L2's score for every document and
# therefore every published L2 number, and `L2_WARN_THRESHOLD` is calibrated for
# the OLD axis. Turn it on together with a threshold re-derived on the new axis.
#
# ON BY DEFAULT since 2026-09-23 (#1), together with the Mondrian anchors above and
# axis-aware store routing (chunk_store). No sentinel_bench / Phase-4 / SPLIT-Bench
# number moves: none of those corpora has a document >= the 600-char gate (checked).
L2_DOCUMENT_THREAT_SCORER = os.getenv(
    "L2_DOCUMENT_THREAT_SCORER", "true").lower() == "true"

# Layer 1 — Tier 3 classifier selection (2026-09-22)
#
# DEFAULT "prompt_guard" = the shipped tier, byte-identical. The alternatives are
# measured but not adopted, because adopting one moves every L1 number and the
# promotion gate has to be re-run first.
#
# WHY THIS EXISTS. Tier 3 is the weakest component in L1 on two independent
# measurements (scratch/l1x/guard_bench.py, threshold-free so no operating point
# can flatter anyone):
#
#   corpus           prompt_guard (shipped)   piguard     ensemble
#   sentinel_bench          0.6975            0.9316       0.9506
#   wildjailbreak           0.5493            0.6619       0.6071
#   bipia_local             0.8200            0.9448       0.9595
#
# and it is the IRREDUCIBLE source of L1's over-defense: the benign samples that no
# threshold can suppress are 8/339 on NotInject and 14/210 on WildJailbreak benign,
# every one of them Tier 3 saturating at ~1.000.
#
# THE THREE MODES, and the honest trade-off between the last two:
#
#   "prompt_guard"  shipped.
#   "piguard"       best over-defense at every budget (NotInject FPR 0.0973 at a
#                   0.5 % Alpaca budget vs shipped 0.2566) but NOT a Pareto
#                   improvement -- WildJailbreak recall 0.4065 vs shipped 0.5620.
#   "ensemble"      unweighted mean on a shared benign-quantile axis. The only
#                   candidate no worse than shipped on any corpus at any budget:
#                   at 1 % -> NotInject 0.2124, SB 1.0000, WJB 0.8705, bipia 0.9606
#                   against shipped   0.3540,    0.8814,     0.6910,       0.9596.
#
# LEAVE-ONE-CORPUS-OUT selection picks a DIFFERENT winner for each held-out corpus,
# so no design dominates and "ensemble" is adopted on a declared criterion (never
# worse than shipped) rather than because it topped a table. That criterion, and the
# fact that PIGuard alone wins over-defense, are both recorded here so the choice
# can be revisited if over-defense becomes the binding constraint.
# DEFAULT CHANGED 2026-09-23 (#10): "prompt_guard" -> "agreement"
# (tier3 = pg_jailbreak x piguard_injection, an AND; layer1_tier3.py). Real runs at
# tau 0.5494, judge off (results.md §8o.4): NotInject FPR 0.0590 -> 0.0383,
# sentinel_bench bit-identical, WildJailbreak AUROC 0.5694 -> 0.5729, TensorTrust
# recall 0.8439 -> 0.8298. The product is <= jailbreak_prob, so Tier 3 can only move
# DOWN and no threshold is invalidated by the switch itself. Costs one PIGuard
# (DeBERTa-base) forward per request. Revert with L1_TIER3_MODE=prompt_guard.
L1_TIER3_MODE = os.getenv("L1_TIER3_MODE", "agreement").strip().lower()

# Layer 1 — which harm-probe artifact the harm tier uses (2026-09-22)
#
# DEFAULT "shipped" = byte-identical behaviour. The alternative is measurably a
# better component, but adopting it moves every harm-tier number and belongs with
# the #3 frontier decision recorded in results.md §8p.
#
# WHY A SECOND ARTIFACT EXISTS. The shipped probe (fit_harm_probe.py) contrasts
# JailbreakBench harmful against ALPACA benign, so it learned "harmful TOPIC vs
# ordinary topic" and is a topic detector, not an intent detector. Measured against
# OR-Bench-Hard (1,319 benign prompts that are harm-ADJACENT):
#
#   AUROC, attacks vs harm-adjacent benign      shipped   wrapped
#     wildjailbreak                              0.5032    0.7222
#     sentinel_bench                             0.2767    0.8900   <- was INVERTED
#     tensortrust                                0.2477    0.8565   <- was INVERTED
#
# OR-Bench benign scores 0.7623 mean on the shipped probe against WildJailbreak
# harmful's 0.7697 -- indistinguishable. Its apparent 0.9837 power exists only
# against ordinary benign text, which is why enabling it moved NotInject
# over-defense 0.1150 -> 0.1947.
#
# "wrapped" (fit_harm_probe_wrapped.py) fixes this with two changes: hard negatives
# (OR-Bench as the benign class) and wrapper augmentation (positives AND negatives
# wrapped in the same generic persona templates, so the wrapper carries no label
# information -- verified: empty wrappers alone score 0.0222). Benign means fall
# NotInject 0.2106 -> 0.0601, Alpaca 0.0501 -> 0.0208.
#
# Its WildJailbreak AUROC is LOWER (0.8080 -> 0.7361) and that is the point: the
# shipped 0.8080 was a topic artifact. Both survive a length control (the external
# confound on this split), 0.8080 -> 0.8329 and 0.7361 -> 0.7469 length-matched.
L1_HARM_PROBE_VARIANT = os.getenv("L1_HARM_PROBE_VARIANT", "shipped").strip().lower()

# Layer 3 — scoring mode (2026-09-22). DEFAULT "production" = unchanged.
#
# "rank_fusion" replaces L3's fixed-weight aggregate with the mean of three session
# statistics read against a frozen benign CDF (see layers/layer3_rank_fusion.py):
#
#              MHJ      tom-gibbs
#   production 0.6139   0.5949
#   rank_fusion 0.6632  0.6350     <- frozen custom_l3 reference, shipped form
#   (rank against the OTHER corpus: 0.7012 / 0.7121 -- the ceiling a larger
#    reference corpus would approach)
#
# This is the first rule measured to beat L3's production score on BOTH corpora,
# which §8b.3 concluded was impossible. That conclusion was correct for the
# production TERMS and does not cover these features -- §8b.3 searched
# `harm x 0.50` and `drift x smooth x 0.25`, whereas per-feature the useful
# families are complementary rather than inverted.
L3_SCORE_MODE = os.getenv("L3_SCORE_MODE", "production").strip().lower()


# =============================================================================
# fixing.md implementation block (2026-09-24). EVERYTHING below defaults to the
# shipped behaviour; each flag is flipped only by its promotion gate in fixing.md.
# =============================================================================

# --- Intent-level safety signal (core/safety_guard.py) -----------------------
# Third-party guard model read as P(Unsafe) (or a frozen hidden-state head over it).
# Root cause it addresses: R-011 (no component reads harmful intent over a full
# hazard taxonomy; #2, #3, #6 all label exactly that).
SAFETY_GUARD_MODEL = os.getenv("SAFETY_GUARD_MODEL", "Qwen/Qwen3Guard-Gen-0.6B")
# Name of a head artifact in core/artifacts/ (written by scratch/trackA/A007_head.py
# --export). Empty = zero-shot P(Unsafe).
SAFETY_GUARD_HEAD = os.getenv("SAFETY_GUARD_HEAD", "")

# L1 safety tier (fixing.md A). OFF until the gate. When on, the guard runs only on
# inputs L1 has NOT already put at or above its own WARN anchor (it cannot change
# those decisions -- see L1_SAFETY_MAY_BLOCK), and its score is mapped onto L1's axis
# with the channel's own conformal anchor and fused by max.
L1_SAFETY_TIER = os.getenv("L1_SAFETY_TIER", "false").lower() == "true"
# The channel anchor: split-conformal on HARM-ADJACENT benign prompts (OR-Bench-80K
# minus Hard-1K, 1,500 rows), alpha 0.05, zero-shot readout -> 0.6737 (A-005). A head
# readout needs its own anchor; set L1_SAFETY_TAU with it (A-007 prints it).
L1_SAFETY_TAU = float(os.getenv("L1_SAFETY_TAU", "0.6737"))
# POLICY: harmful content alone WARNS (the request is forwarded and flagged); it does
# not BLOCK. Over-refusal is a BLOCK, so OR-Bench's cost is alerting, not refusal --
# and it is reported separately as such. Set true only with its own measurement.
L1_SAFETY_MAY_BLOCK = os.getenv("L1_SAFETY_MAY_BLOCK", "false").lower() == "true"

# L1 HARM-INTENT HEAD (2026-09-25, deep_rca.md R-020). "off" (shipped) | "separate".
# WHY SEPARATE, measured on the WildJailbreak hold-out (n=1,519): the guard alone scores
# AUROC 0.942 (recall 0.72 at 5.6 % benign flagged); max-fused into L1 (the L1_SAFETY_TIER
# design) it drops to 0.855 because L1's FORM false alarms (14.8 % of the jailbreak-styled
# benign arm) ride along. A veto the other way is equally wrong: 94 % of TensorTrust and
# 71 % of sentinel_bench injections have P(unsafe) < 0.1. So the head is its own output
# (L1Result.harm_score), decided at its own anchor, reported on harm benchmarks (WJB, OR-
# Bench) as layer "L1H", and joined to the pipeline as its own signal "L1H".
# Supersedes L1_SAFETY_TIER (that max-fusion is skipped when this is "separate").
L1_HARM_HEAD = os.getenv("L1_HARM_HEAD", "separate").strip().lower()        # adopted 2026-09-26 (#3; over-refusal documented)
# The head's WARN anchor on the guard's P(unsafe) axis: the L1 safety channel's split-
# conformal anchor on harm-ADJACENT benign prompts (OR-Bench-80K \ Hard, alpha .05).
L1_HARM_TAU = float(os.getenv("L1_HARM_TAU", os.getenv("L1_SAFETY_TAU", "0.6737")))
# WARN-only unless explicitly allowed (over-refusal is a BLOCK); a BLOCK anchor must be
# derived separately before this is turned on.
L1_HARM_MAY_BLOCK = os.getenv("L1_HARM_MAY_BLOCK", "false").lower() == "true"
L1_HARM_BLOCK_TAU = float(os.environ["L1_HARM_BLOCK_TAU"]) if os.getenv("L1_HARM_BLOCK_TAU") else None
# Cascade: the hosted policy judge (core/policy_prompts.HARM_POLICY_V1) reads the prompt
# only when the guard's P(unsafe) is inside this band; its number replaces the guard's.
L1_HARM_JUDGE = os.getenv("L1_HARM_JUDGE", "false").lower() == "true"
L1_HARM_JUDGE_BAND = (float(os.getenv("L1_HARM_JUDGE_LO", "0.10")),
                      float(os.getenv("L1_HARM_JUDGE_HI", "0.90")))
HARM_POLICY_VERSION = "harm_v1"

# L3 content signal (fixing.md B/C). "anchors" = the 5 HARM_ANCHOR_PHRASES (shipped).
# "guard" = the guard in its native multi-turn mode on the conversation so far, plus
# the guard on L3's own DECODED plaintext when a word-mapping cipher was declared
# (tom-gibbs), max of the two; it REPLACES harm_alignment in the score and keeps the
# other terms and weights.
L3_CONTENT_SIGNAL = os.getenv("L3_CONTENT_SIGNAL", "anchors").strip().lower()
# The guard-mode L3 score lives on a different axis from the anchors score, so it has
# its own anchors (RCA-#3 discipline). DERIVED BY scratch/trackB/B009_analyse.py on the
# WildChat REFERENCE split at the L3 channel budget; placeholders until that runs --
# l3_warn_threshold() refuses to use guard mode with an underived anchor.
L3_GUARD_WARN_THRESHOLD = float(os.environ["L3_GUARD_WARN_THRESHOLD"]) if os.getenv("L3_GUARD_WARN_THRESHOLD") else None
L3_GUARD_BLOCK_THRESHOLD = float(os.environ["L3_GUARD_BLOCK_THRESHOLD"]) if os.getenv("L3_GUARD_BLOCK_THRESHOLD") else None

# L3 DECODED-GOAL guard (fixing.md C, 2026-09-25). B-009 split the "guard" mode above
# into a failing half and a passing half: the per-turn conversation guard fails its gate
# (MHJ vs sensitive-benign WildChat AUROC 0.495, needs >= 0.80), while the guard on L3's
# DECODED cipher goal separates tom-gibbs 0.9999 (195/196 sessions, every benign session
# also declares a cipher, so this is not "has a cipher"). This flag runs ONLY the second:
# L3's score and anchors are untouched, and on a turn whose word-mapping decode changes
# the text, the guard's P(Unsafe) on the decoded text is mapped onto L3's own axis
# (tau -> L3 WARN, capped below L3 BLOCK: WARN-only, the same policy as the L1 safety
# tier) and fused by max. It cannot fire on a conversation that declares no cipher, so
# every non-cipher false-alarm number is unchanged by construction.
L3_DECODED_GUARD = os.getenv("L3_DECODED_GUARD", "true").lower() == "true"        # adopted 2026-09-26 (#6, C2 gate)
# The decoded goal is a single prompt read with the same single-prompt readout as the L1
# safety tier, so it takes that channel's anchor (OR-Bench-80K \ Hard, alpha .05, never
# fitted on tom-gibbs) unless one is derived for it.
L3_DECODED_GUARD_TAU = float(os.getenv("L3_DECODED_GUARD_TAU", str(L1_SAFETY_TAU)))
# R-035: "max" (fuse with the production score) | "replace" (the decoded goal IS the content of a
# cipher session; the mapping preamble scores 0). See layer3.py.
L3_DECODED_GUARD_MODE = os.getenv("L3_DECODED_GUARD_MODE", "replace").strip().lower()        # adopted 2026-09-26 (R-035)

# --- Calibration consistency (fixing.md D, R-007) -----------------------------
# Per-CHANNEL false-alarm budgets, union-bounded: a WARN on benign traffic is a union
# of per-layer false alarms, so the rate on a channel is <= the sum of the alphas of
# the layers reading it. Equal alphas were never the right invariant.
CHANNEL_BUDGETS = {
    # user channel: L1 per turn + L3 per conversation (+ the L1 safety tier when on)
    "user": {"budget": 0.05, "layers": {"L1": 0.01, "L3": 0.04}},
    # third-party content channel: retrieved documents and tool results
    "third_party": {"budget": 0.05, "layers": {"L2": 0.05}},
}
# L3 anchor calibration. "youden" = 0.27, Youden's J on tom-gibbs TRAIN labels
# (shipped; ~4 % on real benign conversations). "conformal" = label-free split-
# conformal on WildChat REFERENCE conversations at the channel's L3 budget (0.04):
# 0.2806 (scratch/rca/R007_l3_conformal.py). Flipping it moves every artifact that
# rescales L3, so it waits for the Groq window that re-runs them.
L3_CALIBRATION = os.getenv("L3_CALIBRATION", "youden").strip().lower()
L3_CONFORMAL_WARN_THRESHOLD = float(os.getenv("L3_CONFORMAL_WARN_THRESHOLD", "0.2806"))


def l3_warn_threshold() -> float:
    """L3's WARN anchor for the axis L3 is scoring on right now. Read this, never the
    constant, in any consumer that rescales or thresholds an L3 score."""
    import math
    import sentinel.config as c
    if c.L3_CONTENT_SIGNAL == "guard":
        if c.L3_GUARD_WARN_THRESHOLD is None:
            raise RuntimeError("L3_CONTENT_SIGNAL=guard needs L3_GUARD_WARN_THRESHOLD "
                               "(derive it with scratch/trackB/B009_analyse.py)")
        return c.L3_GUARD_WARN_THRESHOLD
    if c.L3_CALIBRATION == "conformal":
        return c.L3_CONFORMAL_WARN_THRESHOLD
    return c.L3_WARN_THRESHOLD


def l3_block_threshold() -> float:
    import math
    import sentinel.config as c
    if c.L3_CONTENT_SIGNAL == "guard":
        if c.L3_GUARD_BLOCK_THRESHOLD is None:
            raise RuntimeError("L3_CONTENT_SIGNAL=guard needs L3_GUARD_BLOCK_THRESHOLD")
        return c.L3_GUARD_BLOCK_THRESHOLD
    return c.L3_BLOCK_THRESHOLD


# --- L4 provenance policy (fixing.md G, R-010) --------------------------------
# "legacy" (shipped): a parameter untraceable to the user -> SUSPICIOUS 0.9, one copied
# from any retrieved content -> 0.7. "source_trust": the attack signature of indirect
# injection is "copied from UNTRUSTED third-party content" -- a parameter tracing to a
# review-flagged or quarantined chunk -> 0.9 (those chunks are no longer skipped by the
# tracer), one tracing to trusted content -> 0.7 as before, and an agent-SYNTHESISED
# parameter (ids, dates, URLs; untraceable to anything) -> the tool's base risk, since
# untraceable is not evidence of attack. Needs a real benign agent-trace set to gate.
# "action" (2026-09-25, deep_rca.md §9, layers/layer4_agentic/action_policy.py): L4 as action
# AUTHORISATION -- tool capability (read/write/communicate/transfer/destroy/security/execute),
# reads never blocked, the ACTION checked against the user's request (control flow), and
# only SINK parameters traced (data flow). Gate: AgentDojo per-task utility AND injected-
# call recall (eval/agentdojo_l4.py --attacks), InjecAgent, sentinel_bench pipeline.
L4_PROVENANCE_POLICY = os.getenv("L4_PROVENANCE_POLICY", "action").strip().lower()        # adopted 2026-09-26 (#4)
# R-031 (2026-09-26): score the text AROUND each sink value (recipient / IBAN / hotel / URL)
# for an instruction addressed to the assistant; see action_policy._instruction_context.
# Off by default; the threshold is derived on benign sink-value windows by
# scratch/rca/R031_sink_context_calib.py and has no default (off without it).
L4_SINK_CONTEXT_CHECK = os.getenv("L4_SINK_CONTEXT_CHECK", "true").lower() == "true"        # adopted 2026-09-26 (R-031b)
L4_SINK_CONTEXT_TAU = float(os.environ["L4_SINK_CONTEXT_TAU"]) if os.getenv("L4_SINK_CONTEXT_TAU") else None
L4_SINK_CONTEXT_WINDOW = int(os.getenv("L4_SINK_CONTEXT_WINDOW", "250"))
# R-031b: piguard | cue_strong | cue_gate -- see action_policy._instruction_context
L4_SINK_CONTEXT_MODE = os.getenv("L4_SINK_CONTEXT_MODE", "cue_strong").strip().lower()
# R-031d: where the value must sit (window = +/-W chars; block = INSIDE an addressee-cued span)
# and which arguments are checked (sinks = destinations only; all_args = every argument of a
# side-effect call). Defaults reproduce R-031b / the S3V runs.
L4_SINK_CONTEXT_SPAN = os.getenv("L4_SINK_CONTEXT_SPAN", "block").strip().lower()        # adopted 2026-09-26 (R-031d)
L4_SINK_CONTEXT_SCOPE = os.getenv("L4_SINK_CONTEXT_SCOPE", "all_args").strip().lower()
# 2026-09-26 (off by default; see action_policy / pipeline_sim): hold unrequested sensitive reads
# named by third-party content; and make the simulator BLOCK when L4 refuses execution, as app.py does.
L4_HOLD_SENSITIVE_READS = os.getenv("L4_HOLD_SENSITIVE_READS", "true").lower() == "true"        # adopted 2026-09-26 (#9)
PIPELINE_L4_ENFORCE = os.getenv("PIPELINE_L4_ENFORCE", "true").lower() == "true"        # adopted 2026-09-26 (= app.py)
# the simulator ignores `name(args)` found on a source-code line (see pipeline_sim._in_code_line)
PIPELINE_SIM_CODE_FILTER = os.getenv("PIPELINE_SIM_CODE_FILTER", "true").lower() == "true"        # simulator bug fix 2026-09-26
# Under "action": ask the hosted judge (ACTION_ALIGNMENT_V1) whether a side-effect call the
# lexicon could not match to the user's request is nevertheless authorised. Costs one
# judge call per such call only.
L4_ALIGNMENT_JUDGE = os.getenv("L4_ALIGNMENT_JUDGE", "false").lower() == "true"

# --- Pipeline BLOCK policy (fixing.md F, R-003) --------------------------------
# "single_layer" (shipped): BLOCK = a BLOCKED correlation verdict or one layer >= BLOCK.
# "corroboration": additionally BLOCK when at least PIPELINE_CORROBORATION_K distinct
# layers are each at or above WARN. 0.9153 on SB, but its gain rests on L4/L5 and SB's
# benign arm never exercises them; gate on the benign multi-layer arm
# (sentinel/eval/generate_benign_pipeline_arm.py).
PIPELINE_BLOCK_POLICY = os.getenv("PIPELINE_BLOCK_POLICY", "single_layer").strip().lower()
PIPELINE_CORROBORATION_K = int(os.getenv("PIPELINE_CORROBORATION_K", "2"))


def pipeline_decision(layer_scores: dict, rule_block: bool = False, rule_warn: bool = False,
                      confidences: dict | None = None) -> str:
    """The pipeline's BLOCK/WARN/ALLOW rule over shared-axis layer scores, in ONE place
    so app.py and pipeline_sim cannot drift apart (they did, R-002). `confidences` are the
    continuous L4/L5 channels, read only by the score-fusion alarm (PIPELINE_FUSION)."""
    import sentinel.config as c
    vals = [float(v) for v in layer_scores.values() if v is not None]
    m = max(vals) if vals else 0.0
    fused = None
    if getattr(c, "PIPELINE_FUSION", "off") != "off":
        from sentinel.core.pipeline_fusion import fusion_decision
        fused = fusion_decision(layer_scores, confidences)
    if rule_block or m >= c.BLOCK_THRESHOLD or fused == "BLOCK":
        return "BLOCK"
    if c.PIPELINE_BLOCK_POLICY == "corroboration":
        # Count distinct LAYERS at WARN, not signal keys: app.py passes "L2" and
        # "L2_retrieval" (and "L1" + "L1H") -- two views of one layer's input, which must
        # not corroborate each other (2026-09-25).
        layers_at_warn = {str(k)[:2] for k, v in layer_scores.items()
                          if v is not None and float(v) >= c.WARN_THRESHOLD}
        if len(layers_at_warn) >= c.PIPELINE_CORROBORATION_K:
            return "BLOCK"
    if rule_warn or m >= c.WARN_THRESHOLD or fused == "WARN":
        return "WARN"
    return "ALLOW"
# How the guard enters L3's score in guard mode: "replace" (takes harm_alignment's
# place and weight; geometry and escalation kept) or "guard_only". B-009 decides.
L3_GUARD_COMBINE = os.getenv("L3_GUARD_COMBINE", "replace").strip().lower()
