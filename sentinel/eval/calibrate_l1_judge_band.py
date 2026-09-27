"""
Phase 3.1 — L1 judge-band threshold sweep.

WHY THIS EXISTS
------------------
L1_SEMANTIC_MEDIUM/L1_SEMANTIC_HIGH (config.py, currently 0.55/0.75) gate
when Tier 4's LLM judge is invoked (layer1.py: only for combined_sim in
(MEDIUM, HIGH], the genuinely ambiguous band). A single low/high band
comparison can't reveal where recall/precision/FPR/cost actually trade
off — this sweeps the full band list the plan specifies, holding HIGH
fixed at 0.75 and lowering MEDIUM, reporting the FULL metric set at each
point, not recall alone. Widening the band trivially improves recall by
sending more traffic to an expensive judge; reporting recall alone would
quietly undermine the paper's own runtime/cost argument for gating the
judge narrowly in the first place (see PHASE 1.2's real WildJailbreak
gap this sweep is meant to address).

Run on a BOUNDED development subset (not the full 2,210 WildJailbreak
samples) — real API/latency cost, six full re-runs. Also validates each
candidate band on a genuine BENIGN sample (Alpaca) — the gate requires
this explicitly, not just the malicious-side recall number.

Does NOT auto-adopt a threshold. Prints the full table; a Pareto-optimal
point must be selected and justified in writing afterward (see
SENTINEL_COMPLETE_RESULTS_RECORD.md / the plan's Phase 3.1 gate), then
applied to config.py as an explicit, separate, reviewed change.

Usage:
    python -m sentinel.eval.calibrate_l1_judge_band
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import numpy as np

import sentinel.config as config
import sentinel.layers.layer1 as layer1_module
import sentinel.layers.layer1_llm_judge as judge_module
from sentinel.config import L1_SEMANTIC_MEDIUM as _ORIGINAL_MEDIUM, L1_SEMANTIC_HIGH
from sentinel.eval.runner import run_layer_evaluation
from sentinel.eval.results_ledger import append_entry, hash_file

# [0.55 (current), 0.50, 0.45, 0.40, 0.35, 0.30] — HIGH fixed at 0.75.
BAND_POINTS = [0.55, 0.50, 0.45, 0.40, 0.35, 0.30]

MALICIOUS_DATASET = "wildjailbreak"
MALICIOUS_LIMIT = 300  # bounded dev subset, not the full 2,210
BENIGN_DATASET = "alpaca"
BENIGN_LIMIT = 200

_RESULTS_DIR = Path(__file__).parent / "results"

# --------------------------------------------------------------------------
# Multi-provider judge fallback chain, 2026-09-14
# --------------------------------------------------------------------------
# WHY: SENTINEL's own Groq key hit an account-level rate limit mid-sweep
# (see layer1_llm_judge.py's RATE-LIMIT PACING note) — a real infrastructure
# blocker, not a code bug, that made the first sweep attempt's judge signal
# unavailable for ~93% of calls. OmniRoute (a local multi-provider router,
# 127.0.0.1:20128/v1, REQUIRE_API_KEY=false for this local instance) exposes
# several genuinely separate provider accounts, each already pooling
# multiple keys internally (OmniRoute's own comboStrategy="fallback").
# openai/gpt-oss-120b was verified directly on 25 real WildJailbreak samples
# before trusting it for this sweep: AUROC 0.988, accuracy 0.955, clean
# separation on the indirect/fictionally-framed jailbreaks this corpus is
# dominated by (malicious mean 0.991 vs benign mean 0.138) — a real,
# substantially stronger signal than SENTINEL's own local-Ollama alternative
# (phi3.5, AUROC ~0.5, chance level on the same case). The 3 remaining
# fallback models were each spot-checked live (a single real call) before
# being added to this chain, not assumed from the dated GapSentinel
# reference snapshot alone.
_OMNIROUTE_BACKEND = "http://127.0.0.1:20128/v1/chat/completions"
_OMNIROUTE_KEY = "unused"  # this local instance has REQUIRE_API_KEY=false
_JUDGE_FALLBACK_CHAIN = [
    "openai/gpt-oss-120b",               # Groq via OmniRoute, 4 pooled keys — primary
    "gemini-3.1-flash-lite",              # Gemini via OmniRoute, 4 pooled keys
    "command-a-03-2025",                  # Cohere via OmniRoute, 2 pooled keys
    "nvidia/nemotron-3-super-120b-a12b",  # NVIDIA NIM via OmniRoute, 4 pooled keys
]

_real_llm_judge_check = judge_module.llm_judge_check
judge_fallback_stats: dict[str, int] = {}


async def _fallback_judge_check(text: str, timeout: float = 6.0) -> float | None:
    """Drop-in replacement for llm_judge_check, tried against each model in
    _JUDGE_FALLBACK_CHAIN in order until one returns a real score. Restores
    sentinel.config after every attempt regardless of outcome."""
    for model in _JUDGE_FALLBACK_CHAIN:
        orig = (config.LLM_BACKEND, config.LLM_API_KEY, config.LLM_MODEL_OVERRIDE,
                config.L1_JUDGE_MODEL, config.LLM_JUDGE_REASONING_EFFORT)
        config.LLM_BACKEND, config.LLM_API_KEY, config.LLM_MODEL_OVERRIDE = (
            _OMNIROUTE_BACKEND, _OMNIROUTE_KEY, model,
        )
        config.L1_JUDGE_MODEL, config.LLM_JUDGE_REASONING_EFFORT = model, ""
        try:
            score = await _real_llm_judge_check(text, timeout=30.0)
        finally:
            (config.LLM_BACKEND, config.LLM_API_KEY, config.LLM_MODEL_OVERRIDE,
             config.L1_JUDGE_MODEL, config.LLM_JUDGE_REASONING_EFFORT) = orig
        if score is not None:
            judge_fallback_stats[model] = judge_fallback_stats.get(model, 0) + 1
            return score
    judge_fallback_stats["all_failed"] = judge_fallback_stats.get("all_failed", 0) + 1
    return None


def _judge_invocation_rate(result: dict) -> float:
    per_sample = result.get("per_sample", [])
    scored = [s for s in per_sample if s.get("error") is None]
    if not scored:
        return 0.0
    judged = sum(1 for s in scored if s.get("tier_used") == 4)
    return judged / len(scored)


def _sweep_one(dataset_name: str, limit: int, medium: float) -> dict:
    layer1_module.L1_SEMANTIC_MEDIUM = medium
    start = time.perf_counter()
    result = run_layer_evaluation("L1", dataset_name, limit=limit, run_bootstrap=False)
    elapsed = time.perf_counter() - start
    result["_runtime_seconds"] = elapsed
    result["_judge_invocation_rate"] = _judge_invocation_rate(result)
    return result


def main() -> None:
    print(f"L1 judge-band sweep — HIGH fixed at {L1_SEMANTIC_HIGH}, "
          f"MEDIUM swept across {BAND_POINTS}")
    print(f"Malicious: {MALICIOUS_DATASET} (limit={MALICIOUS_LIMIT}), "
          f"Benign check: {BENIGN_DATASET} (limit={BENIGN_LIMIT})\n")
    print(f"Judge backend: OmniRoute fallback chain {_JUDGE_FALLBACK_CHAIN} "
          f"(SENTINEL's own Groq key skipped — exhausted mid-sweep last attempt)\n")

    judge_module.llm_judge_check = _fallback_judge_check
    rows = []
    try:
        for medium in BAND_POINTS:
            print("=" * 78)
            print(f"MEDIUM={medium} (band=[{medium}, {L1_SEMANTIC_HIGH}])")
            print("=" * 78)

            mal_result = _sweep_one(MALICIOUS_DATASET, MALICIOUS_LIMIT, medium)
            ben_result = _sweep_one(BENIGN_DATASET, BENIGN_LIMIT, medium)

            if "error" in mal_result or "error" in ben_result:
                print(f"  ERROR at MEDIUM={medium}: "
                      f"{mal_result.get('error')} / {ben_result.get('error')}")
                continue

            mc = mal_result["classification"]
            bc = ben_result["classification"]
            row = {
                "medium": medium,
                "malicious_precision": mc["precision"],
                "malicious_recall": mc["recall"],
                "malicious_fpr": mc["fpr"],
                "malicious_auroc": mal_result["threshold_sweep"]["auroc"],
                "malicious_judge_invocation_rate": mal_result["_judge_invocation_rate"],
                "malicious_latency_p50_ms": mal_result["latency"]["p50"],
                "malicious_latency_p95_ms": mal_result["latency"]["p95"],
                "benign_fpr": bc["fpr"],
                "benign_judge_invocation_rate": ben_result["_judge_invocation_rate"],
                "benign_latency_p95_ms": ben_result["latency"]["p95"],
                "runtime_seconds": mal_result["_runtime_seconds"] + ben_result["_runtime_seconds"],
            }
            rows.append(row)

            print(f"  Malicious ({MALICIOUS_DATASET}): recall={mc['recall']:.4f} "
                  f"precision={mc['precision']:.4f} fpr={mc['fpr']:.4f} "
                  f"auroc={row['malicious_auroc']:.4f} "
                  f"judge_rate={row['malicious_judge_invocation_rate']:.4f} "
                  f"p95={row['malicious_latency_p95_ms']:.1f}ms")
            print(f"  Benign ({BENIGN_DATASET}):    fpr={bc['fpr']:.4f} "
                  f"judge_rate={row['benign_judge_invocation_rate']:.4f} "
                  f"p95={row['benign_latency_p95_ms']:.1f}ms")
            print()

            # Ledger entry per sweep point — real run, real thresholds.
            append_entry(
                experiment_id=f"l1_judge_band_sweep_medium_{medium}_{time.strftime('%Y%m%d_%H%M%S')}",
                phase="3.1",
                code_files=["sentinel/layers/layer1.py", "sentinel/layers/layer1_llm_judge.py",
                             "sentinel/eval/calibrate_l1_judge_band.py"],
                dataset_cache_file="sentinel/eval/data/wildjailbreak/test.jsonl",
                split="test",
                thresholds_used={"L1_SEMANTIC_MEDIUM": medium, "L1_SEMANTIC_HIGH": L1_SEMANTIC_HIGH},
                metrics=row,
                result_file="(sweep point — see sentinel/eval/results/l1_judge_band_sweep_summary.json)",
                runtime_seconds=row["runtime_seconds"],
                notes=f"Phase 3.1 judge-band sweep point, MEDIUM={medium}, bounded dev subset "
                      f"(malicious n<={MALICIOUS_LIMIT}, benign n<={BENIGN_LIMIT}). Not yet adopted "
                      f"— see summary table for Pareto comparison across all 6 points.",
            )
    finally:
        # CRITICAL: restore production state regardless of how the sweep exits.
        layer1_module.L1_SEMANTIC_MEDIUM = _ORIGINAL_MEDIUM
        judge_module.llm_judge_check = _real_llm_judge_check
        print(f"Restored L1_SEMANTIC_MEDIUM to {_ORIGINAL_MEDIUM} (production value) "
              f"and llm_judge_check to the real Groq-only implementation.")
        print(f"Judge fallback usage across the whole sweep: {judge_fallback_stats}")

    print("\n" + "=" * 100)
    print("SUMMARY — full metric set per band point (select Pareto-optimal point manually, see gate)")
    print("=" * 100)
    header = f"{'MEDIUM':>7} {'recall':>8} {'prec':>8} {'mal_fpr':>8} {'AUROC':>8} {'judge%':>8} {'ben_fpr':>8} {'p95(ms)':>9}"
    print(header)
    for r in rows:
        print(f"{r['medium']:>7.2f} {r['malicious_recall']:>8.4f} {r['malicious_precision']:>8.4f} "
              f"{r['malicious_fpr']:>8.4f} {r['malicious_auroc']:>8.4f} "
              f"{r['malicious_judge_invocation_rate']:>8.2%} {r['benign_fpr']:>8.4f} "
              f"{r['malicious_latency_p95_ms']:>9.1f}")

    _RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    summary_path = _RESULTS_DIR / f"l1_judge_band_sweep_summary_{time.strftime('%Y%m%d_%H%M%S')}.json"
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump({"band_points": rows, "malicious_dataset": MALICIOUS_DATASET,
                   "malicious_limit": MALICIOUS_LIMIT, "benign_dataset": BENIGN_DATASET,
                   "benign_limit": BENIGN_LIMIT}, f, indent=2)
    print(f"\nFull summary written to {summary_path}")
    print(
        "\nCost note: judge% x (per-call $ rate for openai/gpt-oss-20b, see current "
        "Groq pricing) gives estimated $/sample at each band point — not fabricated "
        "here since pricing changes; judge invocation rate itself is the real, "
        "stable proxy for relative cost across points."
    )


if __name__ == "__main__":
    main()
