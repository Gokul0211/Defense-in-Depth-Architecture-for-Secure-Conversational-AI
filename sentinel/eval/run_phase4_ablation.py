"""
Phase 4 — 9-configuration architecture-ablation matrix + unique-detection
metric U. See PHASE4_PROTOCOL.md Sections 2 and 4 for the frozen spec this
implements, and Section 7 for corrections found while implementing it.

Runs `simulate_pipeline` directly (not `ablation.py`'s `run_ablation_study`,
which does leave-one-out deltas against a single baseline — this matrix
needs nine specific, cumulative configurations instead) against Phase 4's
own benchmark (`sentinel/eval/data/phase4_benchmark/all.jsonl`), applying
the eval-only pattern-miner wrapper (`phase4_pattern_miner.py`) for rows
8-9. Per-sample row-5 and row-9 decisions are kept so U can be computed as
an actual set of samples, not inferred from aggregate recall subtraction.

Bucket breakdowns use MEASURED vector count from
`verify_phase4_benchmark.py`'s output (protocol Section 3.1) — construction
intent is not the ground-truth label.

RUNS AGAINST TWO CORPORA, AND BOTH MUST BE REPORTED
------------------------------------------------------
`--corpus phase4` (default) is the NEGATIVE CONTROL. Phase 4's own
benchmark provably cannot support the claim this matrix tests: re-verified
2026-09-19, L2 never crosses WARN on any of its 460 samples,
`sub_threshold_slow_burn` fires zero correlation rules on 100/100, and only
209/460 samples measure the vector count they were built for. Contribution
E's Corollary 1.2 predicts |U| ~ 0 there analytically, so a near-zero
result is uninformative about correlation rather than evidence against it.

`--corpus split_bench` is the positive case, where every sample carries a
machine-checked certificate that it is sub-threshold on every layer and
carries >= k real vectors — i.e. the regime is guaranteed rather than hoped
for.

The nine row definitions are SHARED between the two, because the entire
value of the second run is comparing |U| against the first.

Usage:
    python -m sentinel.eval.run_phase4_ablation
    python -m sentinel.eval.run_phase4_ablation --corpus split_bench
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from pathlib import Path

from sentinel.config import BLOCK_THRESHOLD, WARN_THRESHOLD
from sentinel.eval.pipeline_sim import simulate_pipeline
from sentinel.eval.phase4_pattern_miner import mine_phase4_patterns, pattern_miner_flags

logger = logging.getLogger(__name__)

_DATA_DIR = Path(__file__).parent / "data" / "phase4_benchmark"
_RESULTS_DIR = Path(__file__).parent / "results"

ALL_RULES = frozenset({"SLOW_BURN_INJECTION", "RAG_PLUS_AGENT_ATTACK", "EXFIL_AFTER_PROBE", "TAINT_PATH_DETECTED"})

# name -> (disabled_layers, disabled_rules, pattern_miner_on)
ROWS: dict[str, tuple[frozenset, frozenset, bool]] = {
    "1_L1_only":                       (frozenset({"L2", "L3", "L4", "L5"}), ALL_RULES, False),
    "2_L1_L2":                         (frozenset({"L3", "L4", "L5"}),       ALL_RULES, False),
    "3_L1_L2_L3":                      (frozenset({"L4", "L5"}),             ALL_RULES, False),
    "4_L1_L2_L3_L4":                   (frozenset({"L5"}),                   ALL_RULES, False),
    "5_independent_cascade":           (frozenset(),                        ALL_RULES, False),
    "6_hand_coded_correlation_rules":  (frozenset(),                        frozenset(), False),
    "7_taint_graph_isolated":          (frozenset(),                        frozenset({"SLOW_BURN_INJECTION", "RAG_PLUS_AGENT_ATTACK", "EXFIL_AFTER_PROBE"}), False),
    "8_pattern_miner_isolated":        (frozenset(),                        ALL_RULES, True),
    "9_full_sentinel":                 (frozenset(),                        frozenset(), True),
}

LOCAL_CASCADE_ROW = "5_independent_cascade"
FULL_ROW = "9_full_sentinel"


# Corpora this matrix can be run against. The ROW DEFINITIONS above are
# deliberately shared rather than duplicated per corpus: the whole point of
# running the matrix on a second corpus is to compare |U| between them, and
# that comparison is meaningless if the nine configurations differ by even
# one disabled rule.
#
# WHY A SECOND CORPUS AT ALL. Phase 4's own benchmark cannot support the
# claim the matrix exists to test. Re-verified 2026-09-19: L2 never crosses
# WARN on any of its 460 samples, `sub_threshold_slow_burn` fires zero
# correlation rules on 100/100, and only 209/460 samples measure the vector
# count they were constructed for. Contribution E's Corollary 1.2 predicts
# |U| ~ 0 on that benchmark ANALYTICALLY, which makes the result
# uninformative either way. SPLIT-Bench was built precisely so the regime
# is guaranteed by a machine-checked certificate instead of hoped for.
#
# So the Phase 4 run is the NEGATIVE CONTROL and the SPLIT-Bench run is the
# positive claim. Reporting only one of them would be cherry-picking in
# whichever direction it happened to land.
from sentinel.eval.split_bench import _DATA_DIR as _SPLIT_DIR   # follows SPLIT_BENCH_DIR

CORPORA = {
    "phase4": _DATA_DIR / "all.jsonl",
    "split_bench": _SPLIT_DIR / "all.jsonl",
}


def _load_samples(corpus: str = "phase4") -> list[dict]:
    path = CORPORA.get(corpus)
    if path is None:
        raise SystemExit(f"unknown corpus {corpus!r}; expected one of {sorted(CORPORA)}")
    if not path.exists():
        raise SystemExit(
            f"{path} not found. For split_bench, generate it first:\n"
            f"    python -m sentinel.eval.split_bench --per-bucket 40"
        )
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def _bucket_keys(corpus: str, malicious: list[dict],
                 measured_buckets: dict[str, int]) -> tuple[dict, dict]:
    """
    (sample_id -> measured bucket key, sample_id -> intended bucket name).

    The two corpora define "how many vectors does this sample carry"
    differently, and using the wrong one would silently mislabel every
    bucket row:

      phase4       — measured = how many layers independently CROSS
                     WARN_THRESHOLD, from verify_phase4_benchmark.py.
      split_bench  — every sample is certified sub-threshold on every
                     layer, so the count of layers crossing WARN is 0 for
                     ALL of them and carries no information. The correct
                     analogue is the certificate's `k_measured`: how many
                     ELIGIBLE layers carry score >= theta_lo. That is the
                     measured quantity the bench is built around, and it is
                     verified per sample rather than asserted.
    """
    if corpus == "split_bench":
        measured = {
            s["sample_id"]: s["metadata"]["certificate"]["k_measured"]
            for s in malicious
        }
        intent = {
            s["sample_id"]: f"k={s['metadata']['k_intended']}" for s in malicious
        }
        return measured, intent

    measured = {
        s["sample_id"]: measured_buckets.get(
            s["sample_id"], s["metadata"]["n_vectors_intent"]
        )
        for s in malicious
    }
    intent = {s["sample_id"]: s["metadata"]["bucket"] for s in malicious}
    return measured, intent


def _load_measured_buckets() -> dict[str, int]:
    """sample_id -> measured vector count, from verify_phase4_benchmark.py's
    output. Falls back to construction intent (with a logged warning) if
    verification hasn't been run yet."""
    verif_path = _DATA_DIR / "verification.jsonl"
    if not verif_path.exists():
        logger.warning("verification.jsonl not found — per-bucket breakdown will use "
                        "construction INTENT, not measured vector count. Run "
                        "verify_phase4_benchmark.py first for the protocol-correct breakdown.")
        return {}
    out = {}
    with open(verif_path, encoding="utf-8") as f:
        for line in f:
            row = json.loads(line)
            out[row["sample_id"]] = row["n_vectors_measured"]
    return out


def _detail_record(sample: dict, result, decided: bool, label: str) -> dict:
    """
    Per-sample record for the A/B/C/D novelty partition.

    `max_single_layer_score` is recomputed here from `result.layer_scores`
    rather than read off the result, so the recorded value is the same
    quantity the partition thresholds — `pipeline_sim` does not expose its
    internal `max_single_layer_score` on the returned object.
    """
    scores = dict(result.layer_scores)
    fired = result.correlation_fired
    return {
        "label": label,
        "decided": decided,
        "final_decision": result.final_decision,
        "correlation_fired": fired,
        "fired_rules": fired.split("+") if fired else [],
        "layer_scores": {k: round(v, 6) for k, v in scores.items()},
        "max_single_layer_score": round(max(scores.values()) if scores else 0.0, 6),
    }


def _abcd_partition(detail: dict, decision_threshold: float) -> dict:
    """
    The partition from PHASE_B_C_PARALLEL_ANALYSIS.md §6.1, computed per class.

    `decision_threshold` MUST be the threshold at which a layer score alone
    makes the harness's decision non-ALLOW. That is `WARN_THRESHOLD`, not
    `BLOCK_THRESHOLD`:

        if correlation_fired is not None or max_single >= BLOCK_THRESHOLD: BLOCK
        elif max_single >= WARN_THRESHOLD:                                 WARN/FLAG
        -> `detected = final_decision != "ALLOW"` is true from WARN upward.

    THIS WAS INITIALLY WRONG AND THE ERROR WAS MATERIAL. The first version used
    BLOCK_THRESHOLD, which reported |C| = 1 novel correlation detection on Phase
    4 — apparently contradicting the independent-cascade comparison (rows 5 and 6
    both detect 229/230, implying |C| = 0). At WARN the partition gives A = 229,
    reproducing row 5 exactly, and |C| = 0. The BLOCK-based 1 was an artifact of
    holding correlation to a stricter bar than the layers it was being compared
    against.

    Reported for BOTH classes deliberately. |C| on malicious is the novel-
    detection count; |C| on benign is the novel-FALSE-POSITIVE count, and a rule
    that produces both is not a win. Quoting malicious |C| alone is the same
    error as quoting precision without coverage.
    """
    out = {}
    for label in ("malicious", "benign"):
        rows = [d for d in detail.values() if d["label"] == label]
        n = len(rows)
        if not n:
            continue
        A = [d for d in rows if d["max_single_layer_score"] >= decision_threshold]
        corr = [d for d in rows if d["correlation_fired"]]
        B = [d for d in corr if d["max_single_layer_score"] >= decision_threshold]
        C = [d for d in corr if d["max_single_layer_score"] < decision_threshold]
        D = [d for d in rows
             if not d["correlation_fired"]
             and d["max_single_layer_score"] < decision_threshold]
        out[label] = {
            "n": n,
            "decision_threshold": decision_threshold,
            "A_layer_alone": len(A),
            "B_correlation_redundant": len(B),
            "C_correlation_novel": len(C),
            "D_missed_by_all": len(D),
            "correlation_coverage": len(corr) / n,
            "incremental_over_layers": len(C) / n,
            "novelty_rate_among_firings": (len(C) / len(corr)) if corr else float("nan"),
            "C_sample_ids": sorted(
                sid for sid, d in detail.items()
                if d["label"] == label and d["correlation_fired"]
                and d["max_single_layer_score"] < decision_threshold),
        }
    return out


async def _run_row(
    row_name: str,
    disabled_layers: frozenset,
    disabled_rules: frozenset,
    pm_on: bool,
    malicious: list[dict],
    benign: list[dict],
    mined_patterns,
    l1_cache: dict | None = None,
) -> dict:
    """
    `l1_cache` is shared across ALL rows by the caller. See
    pipeline_sim.simulate_pipeline's docstring for why: without it, L1's
    live LLM-judge call makes the same sample score differently in
    different rows, so between-row differences (which is exactly what the
    |U| metric reads) can be judge noise rather than configuration.
    """
    per_sample_decisions: dict[str, bool] = {}   # malicious sample_id -> detected
    benign_decisions: dict[str, bool] = {}       # benign sample_id -> flagged
    # Richer per-sample record, added 2026-09-19 so the A/B/C/D novelty
    # partition (see PHASE_B_C_PARALLEL_ANALYSIS.md §6.1) is computable
    # WITHOUT diffing two rows against each other.
    #
    # Why that matters: `final_decision != "ALLOW"` is true when
    # `correlation_fired is not None` OR `max_single_layer_score >=
    # BLOCK_THRESHOLD` (pipeline_sim.py:437). So `detected` CONFLATES a
    # correlation firing with an independent layer detection, and no amount of
    # aggregate counting can separate them. Recording both components per
    # sample makes the partition a within-row computation:
    #
    #   layer_alone(x) = max_single_layer_score >= BLOCK_THRESHOLD
    #   corr(x)        = correlation_fired is not None
    #   A = layer_alone            B = corr and layer_alone
    #   C = corr and not layer_alone   <- genuinely novel
    #   D = neither
    #
    # Purely additive: nothing here feeds any decision or metric computed in
    # this function, so it cannot change a measured number.
    per_sample_detail: dict[str, dict] = {}
    n_detected = 0
    layers_active = 5 - len(disabled_layers)
    latencies = []

    for s in malicious:
        result = await simulate_pipeline(
            s["text"], sample_id=s["sample_id"],
            disabled_layers=disabled_layers, disabled_rules=disabled_rules,
            l1_cache=l1_cache,
        )
        detected = result.final_decision != "ALLOW"
        if pm_on and not detected:
            if pattern_miner_flags(result.layer_scores, mined_patterns):
                detected = True
        per_sample_decisions[s["sample_id"]] = detected
        per_sample_detail[s["sample_id"]] = _detail_record(s, result, detected, "malicious")
        if detected:
            n_detected += 1
        latencies.append(result.latency_ms)

    n_fp = 0
    for s in benign:
        result = await simulate_pipeline(
            s["text"], sample_id=s["sample_id"],
            disabled_layers=disabled_layers, disabled_rules=disabled_rules,
            l1_cache=l1_cache,
        )
        fp = result.final_decision != "ALLOW"
        if pm_on and not fp:
            if pattern_miner_flags(result.layer_scores, mined_patterns):
                fp = True
        benign_decisions[s["sample_id"]] = fp
        per_sample_detail[s["sample_id"]] = _detail_record(s, result, fp, "benign")
        if fp:
            n_fp += 1
        latencies.append(result.latency_ms)

    recall = n_detected / len(malicious) if malicious else float("nan")
    fpr = n_fp / len(benign) if benign else float("nan")
    precision = n_detected / (n_detected + n_fp) if (n_detected + n_fp) else float("nan")
    mean_latency = sum(latencies) / len(latencies) if latencies else float("nan")

    return {
        "condition": row_name,
        "per_sample_detail": per_sample_detail,
        "n_malicious": len(malicious), "n_benign": len(benign),
        "n_detected": n_detected, "n_fp": n_fp,
        "recall": recall, "precision": precision, "fpr": fpr,
        # NOT a measurement — it is exactly `5 - len(disabled_layers)` for
        # every sample in the row, i.e. a restatement of the row's own
        # configuration. An earlier version accumulated this per sample and
        # divided, which dressed a constant up as a mean and would have been
        # reported as if it were measured. Renamed so it cannot be mistaken
        # for an empirical cost metric. Real per-sample layer consumption is
        # only meaningful under SPRT early-stopping (Contribution B), which
        # this matrix does not exercise.
        "layers_active_by_config": layers_active,
        "mean_latency_ms": mean_latency,
        "per_sample_decisions": per_sample_decisions,
        "benign_decisions": benign_decisions,
    }


async def run_phase4_ablation(remine: bool = True, corpus: str = "phase4") -> dict:
    import sentinel.config as cfg

    samples = _load_samples(corpus)
    malicious = [s for s in samples if s["label"] == "malicious"]
    benign = [s for s in samples if s["label"] == "benign"]
    # Only phase4 has a separate verification pass; split_bench carries its
    # measured counts inside each sample's own certificate.
    measured_buckets = _load_measured_buckets() if corpus == "phase4" else {}

    # Tier 4 pinned OFF for the whole matrix, and recorded in `meta`.
    #
    # The |U| metric reads DIFFERENCES between rows, so any per-row
    # nondeterminism is indistinguishable from a configuration effect. The
    # shared `l1_cache` below already removes most of that, but the judge is
    # live-configured and rate-limited: a 429 partway through would change
    # L1's behaviour mid-experiment, silently, for the remaining rows. Off
    # is both reproducible and ~1.4s/call faster.
    judge_was = getattr(cfg, "L1_LLM_JUDGE_ENABLED", True)
    cfg.L1_LLM_JUDGE_ENABLED = False

    logger.info(f"Phase 4 ablation matrix: {len(malicious)} malicious, {len(benign)} benign samples, "
                f"{len(ROWS)} configurations (L1 Tier 4 pinned off)")

    # RE-MINE by default, rather than loading the cached set.
    #
    # The cached `phase4_mined_patterns.json` was mined 2026-09-15, which
    # predates L3_WARN_THRESHOLD 0.30 -> 0.27 and the pipeline_sim
    # tool-marker fix that moved L4 off a spurious 0.500 default. The
    # patterns are sequences of BUCKETED LAYER SCORES, so a change in those
    # scores changes which patterns exist and which inputs match them.
    # Loading the stale set would make rows 8-9 under-fire for a reason
    # unrelated to the pattern miner, and |U| is computed from row 9.
    mined_patterns = await mine_phase4_patterns(force=remine)
    logger.info(f"{'Re-mined' if remine else 'Loaded'} {len(mined_patterns)} patterns for rows 8-9")

    row_results = {}
    # ONE L1 cache shared across every row. This is what makes the matrix
    # internally comparable — see simulate_pipeline's `l1_cache` docstring.
    # It also removes ~8/9 of the LLM-judge calls this matrix would
    # otherwise make (9 rows x 460 samples), which is the difference
    # between "runs" and "exhausts the provider quota partway through and
    # silently changes behaviour mid-experiment".
    l1_cache: dict = {}
    t0 = time.perf_counter()
    for row_name, (disabled_layers, disabled_rules, pm_on) in ROWS.items():
        logger.info(f"  Running row: {row_name} (disabled_layers={sorted(disabled_layers)}, "
                    f"disabled_rules={sorted(disabled_rules)}, pattern_miner={pm_on})...")
        r = await _run_row(row_name, disabled_layers, disabled_rules, pm_on, malicious, benign,
                           mined_patterns, l1_cache=l1_cache)
        row_results[row_name] = r
        logger.info(f"    recall={r['recall']:.4f} precision={r['precision']:.4f} "
                    f"fpr={r['fpr']:.4f} layers_active={r['layers_active_by_config']}")
    total_runtime = time.perf_counter() - t0

    # --- Unique-detection metric U: Full(x)=1 AND LocalCascade(x)=0 ---
    full_decisions = row_results[FULL_ROW]["per_sample_decisions"]
    cascade_decisions = row_results[LOCAL_CASCADE_ROW]["per_sample_decisions"]

    U_sample_ids = [
        sid for sid in full_decisions
        if full_decisions[sid] and not cascade_decisions.get(sid, False)
    ]
    N = len(malicious)
    U_overall = {"n_unique": len(U_sample_ids), "n_total": N,
                 "fraction": len(U_sample_ids) / N if N else float("nan")}

    # Unique FALSE POSITIVES: benign samples the full system flags that the
    # independent cascade does not. |U| alone answers "what does correlation
    # catch that layers cannot" but not "at what cost" — and that is the
    # first question a reviewer asks. Added 2026-09-18 (Part 4 review):
    # the benign loop previously recorded no per-sample decisions at all, so
    # this was not computable.
    full_benign = row_results[FULL_ROW]["benign_decisions"]
    cascade_benign = row_results[LOCAL_CASCADE_ROW]["benign_decisions"]
    U_fp_sample_ids = [
        sid for sid in full_benign
        if full_benign[sid] and not cascade_benign.get(sid, False)
    ]
    N_ben = len(benign)
    U_false_positives = {
        "n_unique_fp": len(U_fp_sample_ids), "n_benign_total": N_ben,
        "fraction": len(U_fp_sample_ids) / N_ben if N_ben else float("nan"),
        "unique_fp_sample_ids": U_fp_sample_ids,
    }

    # Per-bucket breakdown, keyed by MEASURED vector count — which means
    # different things per corpus; see `_bucket_keys`.
    id_to_measured, id_to_bucket_intent = _bucket_keys(corpus, malicious, measured_buckets)

    U_by_measured_n: dict[str, dict] = {}
    all_malicious_ids = [s["sample_id"] for s in malicious]
    n_by_measured: dict[int, int] = {}
    u_by_measured: dict[int, int] = {}
    for sid in all_malicious_ids:
        key = id_to_measured[sid]
        n_by_measured[key] = n_by_measured.get(key, 0) + 1
        if sid in U_sample_ids:
            u_by_measured[key] = u_by_measured.get(key, 0) + 1
    for k in sorted(n_by_measured):
        n_k = n_by_measured[k]
        u_k = u_by_measured.get(k, 0)
        U_by_measured_n[str(k)] = {"n_unique": u_k, "n_total": n_k, "fraction": u_k / n_k if n_k else float("nan")}

    U_by_bucket_intent: dict[str, dict] = {}
    n_by_bucket: dict[str, int] = {}
    u_by_bucket: dict[str, int] = {}
    for sid in all_malicious_ids:
        b = id_to_bucket_intent[sid]
        n_by_bucket[b] = n_by_bucket.get(b, 0) + 1
        if sid in U_sample_ids:
            u_by_bucket[b] = u_by_bucket.get(b, 0) + 1
    for b in n_by_bucket:
        n_b = n_by_bucket[b]
        u_b = u_by_bucket.get(b, 0)
        U_by_bucket_intent[b] = {"n_unique": u_b, "n_total": n_b, "fraction": u_b / n_b if n_b else float("nan")}

    # A/B/C/D novelty partition on the FULL row. Computed within the row, so it
    # does not depend on differencing two configurations — see
    # `_abcd_partition` and `_detail_record`.
    # Primary: WARN, the threshold at which a layer alone makes the decision
    # non-ALLOW (see `_abcd_partition`). The BLOCK variant is also reported
    # because "correlation ESCALATED a warn to a block" is a real and different
    # question — it is just not the same as "correlation detected something the
    # layers missed", and conflating the two overstates the engine.
    detail_full = row_results[FULL_ROW]["per_sample_detail"]
    abcd = {
        "primary_at_warn": _abcd_partition(detail_full, WARN_THRESHOLD),
        "escalation_at_block": _abcd_partition(detail_full, BLOCK_THRESHOLD),
    }

    # Strip the bulky per-sample dicts from the row results before saving the
    # summary. They are NOT discarded any more — they go to a sidecar file
    # beside the summary (see `per_sample_path` in meta), because the earlier
    # version dropped them entirely and every new per-sample question then
    # required re-running the whole ~71-minute matrix.
    conditions_summary = {
        name: {k: v for k, v in r.items()
               if k not in ("per_sample_decisions", "benign_decisions",
                            "per_sample_detail")}
        for name, r in row_results.items()
    }

    cfg.L1_LLM_JUDGE_ENABLED = judge_was

    result = {
        "meta": {
            "n_malicious": len(malicious), "n_benign": len(benign),
            "n_mined_patterns": len(mined_patterns),
            "total_runtime_seconds": total_runtime,
            "corpus": corpus,
            "used_measured_buckets": bool(measured_buckets),
            "l1_llm_judge_enabled": False,
            "patterns_remined": remine,
            "l1_tier_fusion": cfg.L1_TIER_FUSION,
        },
        "conditions": conditions_summary,
        "unique_detection": {
            "overall": U_overall,
            "unique_false_positives": U_false_positives,
            "by_measured_vector_count": U_by_measured_n,
            "by_bucket_intent": U_by_bucket_intent,
            "unique_sample_ids": U_sample_ids,
        },
    }

    _RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    out_path = _RESULTS_DIR / f"phase4_ablation_{corpus}_{ts}.json"
    side_path = _RESULTS_DIR / f"phase4_ablation_{corpus}_{ts}_per_sample.json"

    result["abcd_partition"] = abcd
    result["meta"]["per_sample_path"] = side_path.name
    result["meta"]["block_threshold"] = BLOCK_THRESHOLD
    result["meta"]["warn_threshold"] = WARN_THRESHOLD

    with open(side_path, "w", encoding="utf-8") as f:
        json.dump({
            "meta": {"corpus": corpus, "summary": out_path.name,
                     "block_threshold": BLOCK_THRESHOLD,
                     "warn_threshold": WARN_THRESHOLD},
            "conditions": {name: r["per_sample_detail"]
                           for name, r in row_results.items()},
        }, f, indent=2)

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    logger.info(f"\n=== Unique-detection metric U ===")
    logger.info(f"Overall: {U_overall}")
    logger.info(f"Unique FALSE POSITIVES: {U_false_positives['n_unique_fp']}/"
                f"{U_false_positives['n_benign_total']} "
                f"({U_false_positives['fraction']:.4f})")
    logger.info(f"By measured vector count: {U_by_measured_n}")
    logger.info(f"Saved: {out_path}")

    from sentinel.eval.results_ledger import code_files_for, safe_append_entry

    safe_append_entry(
        experiment_id=f"ablation_matrix_{corpus}_{ts}",
        phase="Phase 4 / PHASE4_PROTOCOL 2 and 4",
        code_files=code_files_for(
            "sentinel/eval/run_phase4_ablation.py",
            "sentinel/eval/phase4_pattern_miner.py",
            "sentinel/eval/pipeline_sim.py",
            "sentinel/core/correlation_engine.py",
            "sentinel/core/pattern_mining.py",
        ),
        dataset_cache_file=str(CORPORA[corpus]),
        split=f"all {len(samples)} {corpus} samples, {len(ROWS)} cumulative configurations",
        thresholds_used={"l1_llm_judge_enabled": False, "patterns_remined": remine,
                         "corpus": corpus},
        metrics={"conditions": conditions_summary,
                 "unique_detection": {k: v for k, v in result["unique_detection"].items()
                                      if k != "unique_sample_ids"}},
        result_file=str(out_path),
        runtime_seconds=round(total_runtime, 1),
        notes=(
            "9-configuration cumulative matrix + unique-detection metric |U| "
            "(Full(x)=1 AND IndependentCascade(x)=0). One L1 cache shared across all "
            "rows so between-row differences cannot be L1 nondeterminism. Patterns "
            "for rows 8-9 mined from sentinel_bench's mining_set (a DIFFERENT corpus "
            "from the one evaluated here, so no leakage) and re-mined rather than "
            "loaded, because the cached set predates the L3 threshold change and the "
            "L4 tool-marker fix that moved the bucketed layer scores it keys on."
        ),
    )

    return result


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Run Phase 4's 9-configuration ablation matrix + U metric")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--corpus", default="phase4", choices=sorted(CORPORA),
                        help="phase4 is the negative control; split_bench is the "
                             "certificate-guaranteed positive case")
    parser.add_argument("--no-remine", action="store_true",
                        help="load the cached mined pattern set instead of re-mining "
                             "(only safe if no layer score has changed since it was mined)")
    args = parser.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(message)s")
    asyncio.run(run_phase4_ablation(remine=not args.no_remine, corpus=args.corpus))


if __name__ == "__main__":
    main()
