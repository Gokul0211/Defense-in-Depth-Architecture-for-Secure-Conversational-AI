"""
Adversarial sensitivity probe for Contribution B's SPRT engine.

WHAT THIS CLOSES
------------------
sequential_triage.py's SPRT accumulation assumes each layer's evidence is
independent of whether a sequential test is running at all — a strategic
attacker who has learned SENTINEL accumulates evidence across layers could,
in principle, "bank benign credit" on early layers (make L1, and possibly
L2, score reassuringly low) so the cumulative log-LLR starts deep in
negative territory, making it harder for later layers' real evidence to
cross the BLOCK boundary within the fixed 5-layer budget — a distinct
attack surface from evading any single layer's own threshold, which is all
the existing red-team chapter (redteam.py) tests. General theory for this
class of problem exists in the statistics literature (adversarially robust
sequential hypothesis testing) but was not found applied to an LLM
security pipeline's layer-consultation problem specifically (see results
record, novelty-check citations).

METHOD — A COUNTERFACTUAL SENSITIVITY ANALYSIS, NOT A TEXT-LEVEL ATTACK
----------------------------------------------------------------------------
This does NOT construct real adversarial text that achieves early-layer
suppression — that is a separate, harder engineering problem (would L1
actually be foolable this way in practice?) this script does not claim to
answer. Instead it tests the narrower, more rigorous structural question
directly: fit the real SPRT engine on the real train split (mirroring
sprt_eval.py exactly), take every real held-out test-split malicious
session the fitted engine currently and correctly decides BLOCK, and ask:
if L1's real score for that exact session were REPLACED with the real
empirical mean benign L1 score from training (a realistic "L1 scored this
like typical benign traffic" substitution, not an arbitrary extreme
value) — holding L2-L5's real scores fixed — does the decision flip? Then
the same for L1+L2 jointly suppressed.

MITIGATION TESTED
--------------------
sequential_triage.py's own TriageResult.exhausted field is already
designed (per its docstring) to let a caller "fall back to the fixed-
cascade decision instead" when SPRT ran out of layers without confidently
crossing a boundary — but sprt_eval.py's real evaluation never actually
exercises that fallback; it scores exhausted sessions on their forced
lean alone. This script tests whether applying that already-documented,
already-designed fallback (only for the exhausted=True counterfactual
cases, falling back to the REAL session's REAL, unsuppressed
simulate_pipeline final_decision as an independent cross-check) recovers
any flips found above. This is a deliberate, narrower framing than "re-run
a full cascade on the counterfactual scores" — it tests whether
independently-computed real pipeline state (correlation rules, taint
graph) already catches what the suppressed SPRT accumulation misses, not
a re-derivation of what a counterfactual cascade would have found.

Usage:
    python -m sentinel.eval.sprt_adversarial_probe
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime
from pathlib import Path

from sentinel.eval.dataset_loaders import load_dataset
from sentinel.eval.pipeline_sim import simulate_pipeline
from sentinel.core.sequential_triage import (
    LikelihoodModel, SPRTBoundaries, SequentialTriageEngine, Decision,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

ALL_LAYERS = ("L1", "L2", "L3", "L4", "L5")


def _mean(xs: list[float]) -> float:
    return sum(xs) / len(xs) if xs else float("nan")


def _is_block(decision: Decision) -> bool:
    return decision == Decision.BLOCK


async def run_sprt_adversarial_probe(alpha: float = 0.05, beta: float = 0.05) -> dict:
    train_dataset = load_dataset("sentinel_bench", split="train")
    test_dataset = load_dataset("sentinel_bench", split="test")

    if not train_dataset.samples or not test_dataset.samples:
        return {"error": "sentinel_bench train/test split not found — generate it first "
                          "with python -m sentinel.eval.generate_sentinel_bench"}

    logger.info(f"Fitting on {len(train_dataset.samples)} train samples, "
                f"probing {len(test_dataset.samples)} test samples")

    # --- 1. Score every train sample, fit LikelihoodModels (mirrors sprt_eval.py) ---
    train_scores_by_layer: dict[str, list[float]] = {L: [] for L in ALL_LAYERS}
    train_labels_by_layer: dict[str, list[int]] = {L: [] for L in ALL_LAYERS}

    for i, sample in enumerate(train_dataset.samples):
        if (i + 1) % 50 == 0:
            logger.info(f"  [train] {i + 1}/{len(train_dataset.samples)}...")
        result = await simulate_pipeline(sample.text, sample_id=sample.sample_id)
        label = 1 if sample.label == "malicious" else 0
        for L in ALL_LAYERS:
            train_scores_by_layer[L].append(result.layer_scores[L])
            train_labels_by_layer[L].append(label)

    boundaries = SPRTBoundaries.from_error_rates(alpha=alpha, beta=beta)
    engine = SequentialTriageEngine(boundaries)
    for L in ALL_LAYERS:
        model = LikelihoodModel(L)
        model.fit(train_scores_by_layer[L], train_labels_by_layer[L])
        engine.register_model(model)

    # Real empirical mean benign score per layer — the realistic
    # "L1 scored like typical benign traffic" substitution.
    mean_benign = {
        L: _mean([s for s, lbl in zip(train_scores_by_layer[L], train_labels_by_layer[L]) if lbl == 0])
        for L in ALL_LAYERS
    }
    logger.info(f"Real empirical mean benign scores (train): {mean_benign}")

    # --- 2. Real scores + real baseline SPRT decision + real full-cascade
    #         decision on every test-split malicious session ---
    n_correctly_blocked = 0
    flips_l1 = 0
    flips_l1_l2 = 0
    flips_l1_recovered_by_fallback = 0
    flips_l1_l2_recovered_by_fallback = 0
    per_sample: list[dict] = []

    for i, sample in enumerate(test_dataset.samples):
        if sample.label != "malicious":
            continue
        if (i + 1) % 20 == 0:
            logger.info(f"  [test] {i + 1}/{len(test_dataset.samples)}...")

        result = await simulate_pipeline(sample.text, sample_id=sample.sample_id)
        real_scores = {L: result.layer_scores[L] for L in ALL_LAYERS}
        real_full_cascade_blocked = result.final_decision != "ALLOW"

        real_seq = [(L, real_scores[L]) for L in ALL_LAYERS]
        baseline_triage = engine.run(real_seq)
        if not _is_block(baseline_triage.decision):
            continue  # only probing sessions the real engine currently gets right
        n_correctly_blocked += 1

        # --- Counterfactual 1: L1 suppressed to mean benign ---
        cf1_seq = [("L1", mean_benign["L1"])] + [(L, real_scores[L]) for L in ALL_LAYERS[1:]]
        cf1_triage = engine.run(cf1_seq)
        cf1_flipped = not _is_block(cf1_triage.decision)
        cf1_recovered = False
        if cf1_flipped:
            flips_l1 += 1
            if cf1_triage.exhausted and real_full_cascade_blocked:
                cf1_recovered = True
                flips_l1_recovered_by_fallback += 1

        # --- Counterfactual 2: L1 + L2 both suppressed to mean benign ---
        cf2_seq = [("L1", mean_benign["L1"]), ("L2", mean_benign["L2"])] + [(L, real_scores[L]) for L in ALL_LAYERS[2:]]
        cf2_triage = engine.run(cf2_seq)
        cf2_flipped = not _is_block(cf2_triage.decision)
        cf2_recovered = False
        if cf2_flipped:
            flips_l1_l2 += 1
            if cf2_triage.exhausted and real_full_cascade_blocked:
                cf2_recovered = True
                flips_l1_l2_recovered_by_fallback += 1

        per_sample.append({
            "sample_id": sample.sample_id,
            "real_scores": real_scores,
            "real_full_cascade_blocked": real_full_cascade_blocked,
            "baseline_decision": baseline_triage.decision.value,
            "cf1_l1_suppressed": {
                "decision": cf1_triage.decision.value, "exhausted": cf1_triage.exhausted,
                "flipped": cf1_flipped, "recovered_by_fallback": cf1_recovered,
            },
            "cf2_l1_l2_suppressed": {
                "decision": cf2_triage.decision.value, "exhausted": cf2_triage.exhausted,
                "flipped": cf2_flipped, "recovered_by_fallback": cf2_recovered,
            },
        })

    n = n_correctly_blocked
    return {
        "meta": {
            "n_train": len(train_dataset.samples),
            "n_test_malicious_correctly_blocked": n,
            "alpha": alpha, "beta": beta,
            "mean_benign_scores": mean_benign,
        },
        "flip_rate_l1_suppressed": (flips_l1 / n) if n else float("nan"),
        "flip_rate_l1_l2_suppressed": (flips_l1_l2 / n) if n else float("nan"),
        "n_flips_l1_suppressed": flips_l1,
        "n_flips_l1_l2_suppressed": flips_l1_l2,
        "fallback_recovery_rate_l1": (flips_l1_recovered_by_fallback / flips_l1) if flips_l1 else float("nan"),
        "fallback_recovery_rate_l1_l2": (flips_l1_l2_recovered_by_fallback / flips_l1_l2) if flips_l1_l2 else float("nan"),
        "per_sample": per_sample,
    }


async def _main_standalone() -> None:
    result = await run_sprt_adversarial_probe()

    out_dir = Path(__file__).parent / "results"
    out_dir.mkdir(exist_ok=True)
    out_path = out_dir / f"eval_sprt_adversarial_probe_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    logger.info(f"Results saved to {out_path}")
    logger.info(
        f"n_correctly_blocked={result['meta']['n_test_malicious_correctly_blocked']}  "
        f"flip_rate_L1={result['flip_rate_l1_suppressed']:.4f}  "
        f"flip_rate_L1+L2={result['flip_rate_l1_l2_suppressed']:.4f}  "
        f"fallback_recovery_L1={result['fallback_recovery_rate_l1']}  "
        f"fallback_recovery_L1+L2={result['fallback_recovery_rate_l1_l2']}"
    )


if __name__ == "__main__":
    asyncio.run(_main_standalone())
