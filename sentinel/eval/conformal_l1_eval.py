"""
Conformal risk control for L1 — cross-corpus false-positive-rate guarantee
stress test.

WHAT THIS CLOSES
------------------
Live literature research (results record, Part E) found that existing
conformal-prediction work for multi-tier LLM systems ("Conformal Cascade",
arXiv:2607.25018; "PASC") targets accuracy/coverage guarantees, not
false-positive-rate control for a security guardrail — and validates its
guarantee on a held-out split of the SAME dataset used for calibration,
never checked against genuine distribution shift. This script does both:
calibrates a formally-guaranteed FPR threshold for L1's real `combined_sim`
score on one real corpus (Alpaca), then checks whether that guarantee
survives being applied, unchanged, to real benign data from two
independently-sourced corpora it never saw.

WHAT THIS DOES NOT TOUCH
---------------------------
This is a read-only analysis script. It calls the real, unmodified
`layer1_check()` production function and reports on its scores — it does
not change L1_SEMANTIC_MEDIUM/HIGH, config.py, or any live decision
threshold. Zero risk to any already-calibrated number in this project.

METHODOLOGY
--------------
1. Calibration: 500 real Alpaca benign samples (alpaca_0..alpaca_499),
   scored fresh via layer1_check() — the exact function
   sentinel/eval/runner.py's _evaluate_l1 calls, reused not reimplemented.
2. Same-source validation (sanity check the math/implementation, not the
   research question): a disjoint 500-sample Alpaca draw (alpaca_500..999).
   The guarantee should hold here close to trivially — if it doesn't, the
   implementation is wrong, not the research finding interesting.
3. Cross-corpus stress test (the real contribution): the SAME threshold,
   calibrated only once on Alpaca, applied to:
   - WildJailbreak's real 210 benign samples — adversarial-style-but-
     harmless text, stylistically closest to the malicious distribution
     L1 is built to catch, so the likeliest place the exchangeability
     assumption actually breaks.
   - sentinel_bench's real 53 benign test-split samples — reusing the
     already-saved, already-cited eval_L1_sentinel_bench_20260913_114753.json
     rather than recomputing (same real production scores, verified
     current this session).

Usage:
    python -m sentinel.eval.conformal_l1_eval
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path

from sentinel.core.conformal_risk_control import (
    calibrate_fpr_threshold, empirical_fpr_with_ci, guarantee_significantly_violated,
)
from sentinel.layers.layer1 import layer1_check

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

_CACHE_DIR = Path(__file__).parent / "data" / "cache"
# sentinel_bench's benign split, scored FRESH like every other arm.
#
# STALENESS BUG FIXED 2026-09-18 (Phase 5 Stage 0a / 3B.2): this used to
# point at a hardcoded `results/eval_L1_sentinel_bench_20260913_114753.json`
# and reuse its saved scores. That file was produced on 2026-09-13 — one
# day BEFORE L1_SEMANTIC_MEDIUM moved 0.55 -> 0.30 (Phase 3.1), which
# changes which inputs reach the LLM-judge tier and therefore changes L1's
# score distribution. So any re-run of this script would have silently
# mixed a freshly-calibrated tau against a stale corpus arm, and the
# hardcoded filename gave no signal that it had gone out of date. Scoring
# it fresh through the same `layer1_check()` path the other two arms use
# removes the whole failure class rather than bumping the filename.
_SENTINEL_BENCH_TEST = Path(__file__).parent / "data" / "sentinel_bench" / "test.jsonl"
# Read from config so the derivation always matches the shipped operating point
# (was a hardcoded 0.05, which would have silently re-derived the OLD tau after
# config moved to alpha 0.01 on 2026-09-23).
from sentinel.config import L1_CONFORMAL_ALPHA as ALPHA
N_CALIBRATION = 500
N_VALIDATION = 500


def _load_jsonl(path: Path) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f]


async def _score_texts(texts: list[str]) -> list[float]:
    scores = []
    for i, text in enumerate(texts):
        if (i + 1) % 50 == 0:
            logger.info(f"  scored {i + 1}/{len(texts)}...")
        result = await layer1_check(text)
        scores.append(result.score)
    return scores


def _report_corpus(name: str, scores: list[float], tau: float, alpha: float) -> dict:
    point, lo, hi = empirical_fpr_with_ci(scores, tau)
    violated = guarantee_significantly_violated(lo, alpha)
    held = not violated
    logger.info(
        f"[{name}] n={len(scores)}  empirical_FPR={point:.4f}  "
        f"95%_CI=({lo:.4f}, {hi:.4f})  target_alpha={alpha}  "
        f"GUARANTEE_HELD={'yes' if held else 'no (statistically significant violation)'}"
    )
    return {
        "corpus": name,
        "n": len(scores),
        "empirical_fpr": point,
        "ci_low": lo,
        "ci_high": hi,
        "alpha": alpha,
        "guarantee_held": held,
    }


async def run_conformal_l1_evaluation() -> dict:
    """Pure computation, no file-saving side effect — mirrors sprt_eval.py's
    run_sprt_evaluation()/pattern_mining_eval.py's run_pattern_mining_evaluation()
    so runner.py's --conformal flag can call this and let its own centralized
    save_results() handle serialization, same as every other eval mode."""
    alpaca_path = _CACHE_DIR / "alpaca" / "test" / "samples.jsonl"
    wildjailbreak_path = _CACHE_DIR / "wildjailbreak" / "test" / "samples.jsonl"

    alpaca_samples = _load_jsonl(alpaca_path)
    if len(alpaca_samples) < N_CALIBRATION + N_VALIDATION:
        raise SystemExit(
            f"Need {N_CALIBRATION + N_VALIDATION} real Alpaca samples, only "
            f"{len(alpaca_samples)} cached at {alpaca_path}."
        )

    calib_texts = [s["text"] for s in alpaca_samples[:N_CALIBRATION]]
    valid_texts = [s["text"] for s in alpaca_samples[N_CALIBRATION:N_CALIBRATION + N_VALIDATION]]

    logger.info(f"Scoring {len(calib_texts)} Alpaca calibration samples via real layer1_check()...")
    calib_scores = await _score_texts(calib_texts)

    tau = calibrate_fpr_threshold(calib_scores, alpha=ALPHA)
    logger.info(f"Calibrated threshold tau={tau:.4f} for alpha={ALPHA} on n={len(calib_scores)} Alpaca samples")

    logger.info(f"Scoring {len(valid_texts)} disjoint Alpaca validation samples (same-source sanity check)...")
    valid_scores = await _score_texts(valid_texts)
    same_source_report = _report_corpus("alpaca_same_source_validation", valid_scores, tau, ALPHA)

    wjb_samples = _load_jsonl(wildjailbreak_path)
    wjb_benign_texts = [s["text"] for s in wjb_samples if s.get("label") == "benign"]
    logger.info(f"Scoring {len(wjb_benign_texts)} real WildJailbreak benign samples (cross-corpus stress test)...")
    wjb_scores = await _score_texts(wjb_benign_texts)
    wjb_report = _report_corpus("wildjailbreak_benign", wjb_scores, tau, ALPHA)

    sb_samples = _load_jsonl(_SENTINEL_BENCH_TEST)
    sb_benign_texts = [s["text"] for s in sb_samples if s.get("label") == "benign"]
    logger.info(f"Scoring {len(sb_benign_texts)} real sentinel_bench benign samples (cross-corpus stress test)...")
    sb_scores = await _score_texts(sb_benign_texts)
    sb_report = _report_corpus("sentinel_bench_benign", sb_scores, tau, ALPHA)

    # Record WHICH L1 score axis produced this calibration. Without it two
    # result files are indistinguishable, and tau is only meaningful
    # relative to its axis: the max() axis and the fused-log-LR axis are
    # different scales, so comparing their taus as numbers is meaningless
    # even though comparing their empirical FPRs is exactly the point.
    from sentinel.config import L1_TIER_FUSION, L1_TIER_FUSION_MODEL

    fusion_provenance = None
    if L1_TIER_FUSION:
        sidecar = Path(L1_TIER_FUSION_MODEL).with_suffix("").with_suffix("")
        sidecar = sidecar.parent / f"{sidecar.name}.provenance.json"
        if sidecar.exists():
            fusion_provenance = json.loads(sidecar.read_text(encoding="utf-8"))

    return {
        "alpha": ALPHA,
        "n_calibration": len(calib_scores),
        "tau": tau,
        "l1_score_axis": "tier_fusion_logistic" if L1_TIER_FUSION else "max_fusion",
        "l1_tier_fusion_enabled": L1_TIER_FUSION,
        "fusion_model_provenance": fusion_provenance,
        "same_source_validation": same_source_report,
        "cross_corpus_stress_tests": [wjb_report, sb_report],
    }


async def _main_standalone() -> None:
    """Standalone entry point (`python -m sentinel.eval.conformal_l1_eval`) —
    saves its own result file since there's no runner.py wrapper to do it."""
    result = await run_conformal_l1_evaluation()

    out_dir = Path(__file__).parent / "results"
    out_dir.mkdir(exist_ok=True)
    from datetime import datetime
    out_path = out_dir / f"eval_conformal_l1_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    logger.info(f"Results saved to {out_path}")


if __name__ == "__main__":
    asyncio.run(_main_standalone())
