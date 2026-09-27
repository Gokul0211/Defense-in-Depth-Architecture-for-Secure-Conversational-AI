"""
Certified robustness evaluation for L1 (Contribution: complements the
red-team chapter's empirical evasion numbers with a provable guarantee).

WHAT THIS CLOSES
------------------
sentinel/eval/redteam.py measures EMPIRICAL evasion resistance against
specific attackers (rule-based tier: 63.2% evasion final hardened state;
LLM tier: 12.3% — see results record B.9). This script adds a
complementary, PROVABLE guarantee for a narrower, faster-to-certify
surface: L1's own decision alone (not the full 5-layer pipeline max score
redteam.py's harness scores against) — see
sentinel/core/certified_robustness.py's module docstring for the exact
method and its honest scope. Because this certifies a DIFFERENT metric
(L1-alone, not full-pipeline-max), report this as a complementary data
point alongside the red-team numbers, not a literal same-metric
re-measurement of them.

METHODOLOGY
--------------
1. Load sentinel_bench's real malicious samples, same source redteam.py
   uses (`load_dataset("sentinel_bench", ...)`).
2. Filter to "originally detected" by L1 alone (score >= L1_SEMANTIC_MEDIUM,
   the same SUSPICIOUS-or-above threshold L1's own threat_class already
   uses internally) — mirrors redteam.py's require_originally_detected gate.
3. Further filter to samples with >=1 real _SYNONYM_MAP trigger word
   present (certified_robustness.n_eligible_trigger_words) — samples with
   zero eligible words cannot be perturbed at all by this mechanism, and
   including them would inflate the certified-stable fraction with trivial
   no-op cases. Reported explicitly, not silently dropped.
4. For each eligible sample and each budget k in {1,2,3,4}: generate 100
   real noisy copies (sentinel.core.certified_robustness.generate_perturbations),
   score each via the real, unmodified layer1_check(), compare each
   copy's binary decision (score >= L1_SEMANTIC_MEDIUM) against the
   original's, and certify via certify_decision_stability.
5. Report, per budget k: n_eligible, n_certified, certified_fraction.

Usage:
    python -m sentinel.eval.certified_robustness_eval
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
from datetime import datetime
from pathlib import Path

from sentinel.config import L1_SEMANTIC_MEDIUM
from sentinel.core.certified_robustness import (
    certify_decision_stability,
    generate_perturbations,
    n_eligible_trigger_words,
)
from sentinel.eval.dataset_loaders import load_dataset
from sentinel.layers.layer1 import layer1_check

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

BUDGETS = (1, 2, 3, 4)
N_COPIES = 100
SEED = 42


async def _decision(text: str) -> bool:
    result = await layer1_check(text)
    return result.score >= L1_SEMANTIC_MEDIUM


async def run_certified_robustness_evaluation() -> dict:
    dataset = load_dataset("sentinel_bench")
    malicious_samples = [(s.sample_id, s.text) for s in dataset.samples if s.label == "malicious"]
    logger.info(f"Loaded {len(malicious_samples)} real malicious sentinel_bench samples")

    rng = random.Random(SEED)

    eligible: list[tuple[str, str]] = []
    n_not_originally_detected = 0
    n_no_trigger_words = 0

    for sample_id, text in malicious_samples:
        detected = await _decision(text)
        if not detected:
            n_not_originally_detected += 1
            continue
        n_words = n_eligible_trigger_words(text)
        if n_words < 1:
            n_no_trigger_words += 1
            continue
        eligible.append((sample_id, text))

    logger.info(
        f"Eligible for certification: {len(eligible)}/{len(malicious_samples)} "
        f"(excluded {n_not_originally_detected} not originally detected by L1 alone, "
        f"{n_no_trigger_words} with zero eligible trigger words)"
    )

    per_budget: dict[int, dict] = {}
    per_sample_detail: list[dict] = []

    for k in BUDGETS:
        n_certified = 0
        for i, (sample_id, text) in enumerate(eligible):
            if (i + 1) % 5 == 0:
                logger.info(f"  [k={k}] {i + 1}/{len(eligible)} samples...")
            copies = generate_perturbations(text, k=k, n=N_COPIES, rng=rng)
            agreements = 0
            for copy_text in copies:
                copy_detected = await _decision(copy_text)
                if copy_detected:  # original decision is always "detected" (eligibility gate)
                    agreements += 1
            p_hat, p_lo, certified = certify_decision_stability(agreements, N_COPIES)
            if certified:
                n_certified += 1
            per_sample_detail.append({
                "sample_id": sample_id, "k": k, "n": N_COPIES,
                "agreements": agreements, "p_hat": p_hat, "p_lo": p_lo,
                "certified": certified,
            })

        certified_fraction = n_certified / len(eligible) if eligible else float("nan")
        per_budget[k] = {
            "n_eligible": len(eligible),
            "n_certified": n_certified,
            "certified_fraction": certified_fraction,
        }
        logger.info(f"[k={k}] certified_stable = {n_certified}/{len(eligible)} = {certified_fraction:.4f}")

    return {
        "meta": {
            "n_malicious_total": len(malicious_samples),
            "n_not_originally_detected": n_not_originally_detected,
            "n_no_trigger_words": n_no_trigger_words,
            "n_eligible": len(eligible),
            "n_copies_per_sample": N_COPIES,
            "budgets": list(BUDGETS),
            "seed": SEED,
            "detection_threshold": L1_SEMANTIC_MEDIUM,
        },
        "per_budget": {str(k): v for k, v in per_budget.items()},
        "per_sample": per_sample_detail,
    }


async def _main_standalone() -> None:
    result = await run_certified_robustness_evaluation()

    out_dir = Path(__file__).parent / "results"
    out_dir.mkdir(exist_ok=True)
    out_path = out_dir / f"eval_certified_robustness_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    logger.info(f"Results saved to {out_path}")


if __name__ == "__main__":
    asyncio.run(_main_standalone())
