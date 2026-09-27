"""
Configuration snapshot for evaluation artifacts.

WHY THIS EXISTS. On 2026-09-19 an audit of every headline number in
`paper/sentinel_paper.tex` found that the evaluation result JSONs record
`threshold`, `n`, and `seed` — but not the *layer configuration* the run used.
The consequence, concretely:

    eval_L1_wildjailbreak_20260918_203435.json   threshold 0.4391, n=2210, recall 0.381
    eval_L1_wildjailbreak_20260918_215128.json   threshold 0.4391, n=2210, recall 0.572

Two runs 77 minutes apart, same corpus, same sample count, same threshold,
recall differing by 19 points, and **nothing in either artifact distinguishes
them**. Neither is in the append-only ledger either, so the configuration is
unrecoverable and neither number is citable in a paper.

The same audit found the cause of a second, larger discrepancy: L1's
sentinel_bench recall was reported as 0.458 in the paper, measured on a day when
SENTINEL's judge API was returning HTTP 429 for 63 of ~93 calls. A failed judge
call is correctly treated as "skip", so the layer silently scored 0.5254 instead
of 0.9492 and *no error surfaced in the artifact*. A recorded
`l1_llm_judge_enabled` flag would not have caught that on its own, which is why
`judge_calls_attempted` / `judge_calls_succeeded` are captured too: a
configuration flag says what was *intended*, and those counters say what actually
*happened*.

Captured here rather than inline at each call site so every harness records the
same fields in the same shape, and so adding a field later updates every
artifact at once.
"""

from __future__ import annotations

import os
import platform
import subprocess
import sys


def _git_hash() -> str | None:
    """Short commit hash, or None if this is not a git checkout."""
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=5,
            cwd=os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
        )
        return out.stdout.strip() or None if out.returncode == 0 else None
    except Exception:                                            # noqa: BLE001
        return None


def config_snapshot() -> dict:
    """
    Every setting that can move a reported number, read live from config at call
    time (NOT import time — several are monkeypatched by harnesses and tests, and
    an import-time snapshot would record the default rather than what ran).
    """
    from sentinel import config as cfg

    def g(name, default=None):
        return getattr(cfg, name, default)

    return {
        # --- L1: the layer with the most moving parts, and the one whose
        # headline number was misreported because a tier silently no-op'd.
        "l1_tier_fusion": g("L1_TIER_FUSION"),
        "l1_llm_judge_enabled": g("L1_LLM_JUDGE_ENABLED"),
        # The judge gate is `L1_SEMANTIC_MEDIUM < combined <= L1_SEMANTIC_HIGH`
        # (layer1.py:453) — there is no separate band constant. Recorded
        # explicitly as a band because the low edge was widened 0.55 -> 0.30 on
        # 2026-09-14 and that single change moved WildJailbreak AUROC
        # 0.5473 -> 0.7060, so a number quoted without it is ambiguous.
        "l1_judge_band": [g("L1_SEMANTIC_MEDIUM"), g("L1_SEMANTIC_HIGH")],
        "l1_tier1_threshold": g("L1_TIER1_THRESHOLD"),
        "l1_warn_threshold": g("L1_WARN_THRESHOLD"),
        "l1_block_threshold": g("L1_BLOCK_THRESHOLD"),
        "l1_semantic_medium": g("L1_SEMANTIC_MEDIUM"),
        "l1_semantic_high": g("L1_SEMANTIC_HIGH"),
        "l1_fused_semantic_medium": g("L1_FUSED_SEMANTIC_MEDIUM"),
        "l1_fused_semantic_high": g("L1_FUSED_SEMANTIC_HIGH"),
        "l1_conformal_alpha": g("L1_CONFORMAL_ALPHA"),
        # The harm/intent tiers, ADDED 2026-09-22 after they were found missing.
        #
        # THE DEFECT THIS CLOSES, and it is the exact failure this whole module
        # exists to prevent. `eval_L1_alpaca_20260921_010629.json` reports Alpaca
        # FPR 0.0456 and `..._132721.json` reports 0.0118 — a 3.9x difference on
        # the same corpus, same n, same threshold — and their `meta.config`
        # blocks are BYTE-IDENTICAL, because the flag that differed was not
        # captured here. Neither number was attributable to a configuration from
        # its own artifact, which is precisely the condition the paper's argument
        # says invalidates a result.
        #
        # These change L1's score for every request (the probe fuses as
        # mean(L1, probe) rather than max(), so unlike every other tier it can
        # LOWER a score), so a run that does not record them cannot be reproduced
        # or compared.
        "l1_harm_probe_tier": g("L1_HARM_PROBE_TIER"),
        "l1_harm_content_tier": g("L1_HARM_CONTENT_TIER"),
        # Tier-3 classifier selection. Added 2026-09-22 — and it was missed on the
        # first pass of this very fix, because the invariant test written that
        # morning only swept BOOLEAN flags and this one is a string. Two runs
        # differing only in `L1_TIER3_MODE` would again have been indistinguishable
        # from their artifacts. The test now sweeps string mode flags too.
        "l1_tier3_mode": g("L1_TIER3_MODE"),
        "l1_judge_prompt_version": g("L1_JUDGE_PROMPT_VERSION"),
        "llm_judge_reasoning_effort": g("LLM_JUDGE_REASONING_EFFORT"),
        "l1_judge_model": g("L1_JUDGE_MODEL"),
        # Which harm-probe artifact. A different artifact is a different
        # detector; two runs differing only here must be distinguishable.
        "l1_harm_probe_variant": g("L1_HARM_PROBE_VARIANT"),
        "l1_harm_fused_warn_threshold": g("L1_HARM_FUSED_WARN_THRESHOLD"),
        # --- L2
        "l2_content_type_routing": g("L2_CONTENT_TYPE_ROUTING"),
        "l2_tool_response_flag_threshold": g("L2_TOOL_RESPONSE_FLAG_THRESHOLD"),
        # Doc-axis tool-output cutoff (R-017). Unset means the output's Mondrian WARN
        # anchor -- recorded as that, not as None ("name not found").
        "l2_tool_response_doc_flag_threshold": (
            g("L2_TOOL_RESPONSE_DOC_FLAG_THRESHOLD")
            if g("L2_TOOL_RESPONSE_DOC_FLAG_THRESHOLD") is not None else "mondrian_warn_anchor"),
        "l2_document_threat_scorer": g("L2_DOCUMENT_THREAT_SCORER"),
        "l2_warn_threshold": g("L2_WARN_THRESHOLD"),
        # The rebuilt document-threat axis has its OWN warn anchor; which one a
        # run used depends on l2_document_threat_scorer, so both are recorded.
        "l2_document_threat_warn_threshold": g("L2_DOCUMENT_THREAT_WARN_THRESHOLD"),
        "l2_block_threshold": g("L2_BLOCK_THRESHOLD"),
        # --- L3: the weights are as load-bearing as the threshold, and the
        # 0.30 -> 0.27 change on 2026-09-18 is exactly what made the paper's
        # tom-gibbs recall/FPR pair stale while leaving its AUROC correct.
        # Which scoring rule L3 used. A different rule is a different detector.
        "l3_score_mode": g("L3_SCORE_MODE"),
        "l3_warn_threshold": g("L3_WARN_THRESHOLD"),
        "l3_block_threshold": g("L3_BLOCK_THRESHOLD"),
        "l3_velocity_weight": g("L3_VELOCITY_WEIGHT"),
        "l3_drift_weight": g("L3_DRIFT_WEIGHT"),
        "l3_harm_alignment_weight": g("L3_HARM_ALIGNMENT_WEIGHT"),
        "l3_escalation_weight": g("L3_ESCALATION_WEIGHT"),
        "l3_escalation_threshold": g("L3_ESCALATION_THRESHOLD"),
        "l3_max_history": g("L3_MAX_HISTORY"),
        # --- fixing.md implementation block (2026-09-24): every new flag, because each
        # one changes a detector or a decision rule.
        "safety_guard_model": g("SAFETY_GUARD_MODEL"),
        "safety_guard_head": g("SAFETY_GUARD_HEAD"),
        "l1_safety_tier": g("L1_SAFETY_TIER"),
        "l1_safety_tau": g("L1_SAFETY_TAU"),
        "l1_safety_may_block": g("L1_SAFETY_MAY_BLOCK"),
        "l2_document_threat_warn_threshold_code": g("L2_DOCUMENT_THREAT_WARN_THRESHOLD_CODE"),
        "l2_document_threat_block_threshold_code": g("L2_DOCUMENT_THREAT_BLOCK_THRESHOLD_CODE"),
        "l3_content_signal": g("L3_CONTENT_SIGNAL"),
        "l3_guard_combine": g("L3_GUARD_COMBINE"),
        "l3_guard_warn_threshold": g("L3_GUARD_WARN_THRESHOLD"),
        "l3_guard_block_threshold": g("L3_GUARD_BLOCK_THRESHOLD"),
        "l3_decoded_guard": g("L3_DECODED_GUARD"),
        # --- 2026-09-25 redesign (deep_rca.md §9): every new detector / decision flag
        "l1_harm_head": g("L1_HARM_HEAD"),
        "l1_harm_tau": g("L1_HARM_TAU"),
        "l1_harm_may_block": g("L1_HARM_MAY_BLOCK"),
        "l1_harm_block_tau": g("L1_HARM_BLOCK_TAU"),
        "l1_harm_judge": g("L1_HARM_JUDGE"),
        "l1_harm_judge_band": list(g("L1_HARM_JUDGE_BAND") or ()),
        "harm_policy_version": g("HARM_POLICY_VERSION"),
        "l1_judge_may_lower": g("L1_JUDGE_MAY_LOWER"),
        "l2_short_doc_scorer": g("L2_SHORT_DOC_SCORER"),
        "l2_document_threat_warn_threshold_short": g("L2_DOCUMENT_THREAT_WARN_THRESHOLD_SHORT"),
        "l2_document_threat_block_threshold_short": g("L2_DOCUMENT_THREAT_BLOCK_THRESHOLD_SHORT"),
        "l2_short_doc_judge": g("L2_SHORT_DOC_JUDGE"),
        "l2_short_doc_judge_band": list(g("L2_SHORT_DOC_JUDGE_BAND") or ()),
        "l2_retrieval_min_similarity": g("L2_RETRIEVAL_MIN_SIMILARITY"),
        "l2_shared_axis_in_app": g("L2_SHARED_AXIS_IN_APP"),
        "l4_alignment_judge": g("L4_ALIGNMENT_JUDGE"),
        "policy_judge_enabled": g("POLICY_JUDGE_ENABLED"),
        "l2_shared_axis": g("L2_SHARED_AXIS"),
        "pipeline_fusion": g("PIPELINE_FUSION"),
        "l3_decoded_guard_tau": g("L3_DECODED_GUARD_TAU"),
        "l3_calibration": g("L3_CALIBRATION"),
        "l3_conformal_warn_threshold": g("L3_CONFORMAL_WARN_THRESHOLD"),
        "l4_provenance_policy": g("L4_PROVENANCE_POLICY"),
        # 2026-09-26 flags (results.md §12) -- each can move a reported number
        "l3_decoded_guard_mode": g("L3_DECODED_GUARD_MODE"),
        "l4_sink_context_check": g("L4_SINK_CONTEXT_CHECK"),
        "l4_sink_context_mode": g("L4_SINK_CONTEXT_MODE"),
        "l4_sink_context_span": g("L4_SINK_CONTEXT_SPAN"),
        "l4_sink_context_scope": g("L4_SINK_CONTEXT_SCOPE"),
        "l4_sink_context_tau": g("L4_SINK_CONTEXT_TAU"),
        "l4_sink_context_window": g("L4_SINK_CONTEXT_WINDOW"),
        "l4_hold_sensitive_reads": g("L4_HOLD_SENSITIVE_READS"),
        "pipeline_l4_enforce": g("PIPELINE_L4_ENFORCE"),
        "pipeline_sim_code_filter": g("PIPELINE_SIM_CODE_FILTER"),
        "pipeline_block_policy": g("PIPELINE_BLOCK_POLICY"),
        "pipeline_corroboration_k": g("PIPELINE_CORROBORATION_K"),
        "torch_threads": __import__("os").getenv("SENTINEL_TORCH_THREADS", "1"),
        # --- L4 / L5
        "l4_decision_threshold": g("L4_DECISION_THRESHOLD"),
        "l5_provenance_min_identifier_len": g("L5_PROVENANCE_MIN_IDENTIFIER_LEN"),
        # --- shared axis
        "warn_threshold": g("WARN_THRESHOLD"),
        "block_threshold": g("BLOCK_THRESHOLD"),
        # --- environment
        "embedding_model": g("EMBEDDING_MODEL"),
        "llm_backend": g("LLM_BACKEND"),
        "llm_model_override": g("LLM_MODEL_OVERRIDE"),
        "llm_api_key_present": bool(g("LLM_API_KEY")),
        "git_hash": _git_hash(),
        "python": sys.version.split()[0],
        "platform": platform.platform(),
    }


def judge_call_counters() -> dict:
    """
    What actually happened to the judge tier, as opposed to whether it was
    enabled. A judge that is enabled but rate-limited returns None on every call
    and is silently skipped — which is precisely how L1's sentinel_bench recall
    came to be reported 49 points low. If the layer does not expose counters,
    this returns nulls rather than fabricating zeros.
    """
    try:
        from sentinel.layers.layer1_llm_judge import judge_counters
    except Exception:                                            # noqa: BLE001
        return {"judge_calls_attempted": None, "judge_success_rate": None}
    return judge_counters()


# A judge-dependent row measured below this coverage is not measuring the layer.
# Set from evidence rather than taste: on 2026-09-20 wildjailbreak ran at
# 2.5-4.0% coverage and the judge-on arm reproduced the judge-off arm to four
# decimal places, while the internal corpus at 98.6% showed the judge to be worth
# +42.4 points of recall. Between those lie bipia_local's 29.4%, where recall was
# still monotonically increasing with coverage and so still a lower bound.
_COVERAGE_FLOOR = 0.80


def _judge_coverage_verdict() -> dict:
    """
    One field saying whether the judge tier actually ran, and whether the row is
    therefore reportable.

    Recording raw counters turned out not to be enough: they were present in the
    artifacts for three rows that were still carried into a draft at 1.3-4.0%
    coverage, because reading them required knowing to divide two numbers. This
    computes the fraction and states the verdict.

    `status` is one of:
      "judge_disabled"  the kill switch was set; this is a deliberate arm, and
                        the row IS reportable as an explicitly judge-off result
      "ok"              coverage at or above the floor
      "degraded"        the judge ran but answered too few calls; the row
                        measures the judge's absence more than the layer
      "not_applicable"  no judge calls were reachable at all for this layer
    """
    c = judge_call_counters()
    attempted = c.get("judge_calls_attempted") or 0
    succeeded = c.get("judge_calls_succeeded") or 0
    disabled = c.get("judge_calls_skipped_disabled") or 0
    no_key = c.get("judge_calls_skipped_no_key") or 0

    # PER-SAMPLE DENOMINATOR, corrected 2026-09-21. This used `attempted`, which
    # counts every HTTP attempt INCLUDING 429 retries -- so a throttled run
    # inflated its own denominator and under-reported its coverage. Measured: a
    # TensorTrust run showed 167 "opportunities" for 86 unique band-eligible
    # samples (82 retries double-counted), reporting coverage 0.4371 when the
    # per-sample figure was far higher.
    #
    # Coverage is a per-SAMPLE question -- did this sample get a judge answer --
    # so the denominator is unique samples that entered the judge band, plus the
    # ones that never got that far (disabled, or no usable key). Falls back to the
    # old denominator when the layer does not expose the per-sample counter.
    entered = c.get("judge_samples_entered")
    opportunities = ((entered or 0) + disabled + no_key) if entered is not None \
        else (attempted + disabled + no_key)

    if opportunities == 0:
        return {"status": "not_applicable", "coverage": None,
                "reportable": True, "floor": _COVERAGE_FLOOR}

    coverage = succeeded / opportunities
    if disabled == opportunities:
        status, reportable = "judge_disabled", True
    elif coverage >= _COVERAGE_FLOOR:
        status, reportable = "ok", True
    else:
        status, reportable = "degraded", False

    return {
        "status": status,
        "coverage": round(coverage, 4),
        "judge_opportunities": opportunities,
        "reportable": reportable,
        "floor": _COVERAGE_FLOOR,
        **_coverage_loss_attribution(c, attempted, succeeded),
    }


def _coverage_loss_attribution(c: dict, attempted: int, succeeded: int) -> dict:
    """
    WHY the judge lost coverage, not just how much. Added 2026-09-21.

    `status: "degraded"` was not actionable. Three causes produce it, they need
    opposite responses, and until the counters below existed they were
    indistinguishable in every artifact:

      throttled  the run outran the provider's budget. A pacing bug -- and it WAS
                 one: the per-key interval was set six times faster than the
                 file's own derivation allowed (results.md 8d.2). Fix the client.
      refused    the judge model declined to classify the sample. Not fixable by
                 pacing, retries, or a bigger token budget -- measured, nothing is
                 truncated (finish_reason "stop" on 8 of 8 failing prompts).
                 Needs a judge-prompt or judge-model change.
      other      malformed responses, timeouts, network faults.

    THE FIELD THAT MATTERS MOST IS `loss_is_label_correlated`. Refusals are not
    missing at random: the judge refuses on the hardest MALICIOUS prompts, so a
    refusal-dominated run has lost judge signal preferentially on the samples
    where the tier contributes most, biasing the layer DOWNWARD. A row degraded
    that way is a floor on the true figure, not a noisy estimate of it -- which is
    a materially different thing to report, and an aggregate coverage number
    cannot say it.
    """
    refused = c.get("judge_calls_refused") or 0
    throttled = c.get("judge_calls_rate_limited_429") or 0
    lost = max(attempted - succeeded, 0)
    other = max(lost - refused, 0)

    if lost == 0:
        dominant = None
    elif refused >= other and refused > 0:
        dominant = "refused"
    elif throttled > 0 and other > 0:
        dominant = "throttled"
    elif other > 0:
        dominant = "other"
    else:
        dominant = "refused" if refused else None

    return {
        "coverage_loss": lost,
        "coverage_loss_refused": refused,
        "coverage_loss_other": other,
        "rate_limit_collisions": throttled,
        "calls_deferred_on_budget": c.get("judge_calls_deferred_on_budget") or 0,
        "dominant_loss_cause": dominant,
        # True when the losses are concentrated on hard malicious samples, so the
        # reported metric is a LOWER BOUND rather than an unbiased estimate.
        "loss_is_label_correlated": dominant == "refused",
    }


def reset_run_counters() -> None:
    """Zero every per-run counter. Call before a benchmark run starts."""
    try:
        from sentinel.layers.layer1_llm_judge import reset_judge_counters
        reset_judge_counters()
    except Exception:                                            # noqa: BLE001
        pass
