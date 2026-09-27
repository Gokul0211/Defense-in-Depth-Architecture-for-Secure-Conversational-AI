"""
Does calibrated tier fusion repair L1's conformal guarantee under
distribution shift? — PAIRED, single-pass comparison.

THE QUESTION
---------------
Contribution D's conformal FPR guarantee is calibrated on Alpaca benign and
holds there (empirical FPR 0.038 against alpha=0.05), holds on
sentinel_bench benign (0.0000), and FAILS on WildJailbreak benign
(0.2667 — a statistically significant violation). Tier fusion raises
cross-corpus AUROC 0.6457 -> 0.7426. The obvious hope is that a better
score axis also repairs the guarantee.

WHY THIS FILE EXISTS RATHER THAN TWO RUNS OF conformal_l1_eval.py
-------------------------------------------------------------------
Running that script twice — once with L1_TIER_FUSION off, once on — gives
an UNPAIRED comparison, and two things differ between the runs besides the
fusion rule:

  * Tier 4 availability. The judge is live-configured but rate-limited;
    which samples got a judge score depends on when each run happened to
    hit HTTP 429. A sample judged in one run and not the other has a
    different score for a reason that has nothing to do with fusion.
  * Ordinary nondeterminism in batching/model load order.

This file scores every sample EXACTLY ONCE, records its `tier_scores`, and
then derives BOTH axes from those same recorded vectors:

    max_fusion_score(tier_scores)                     <- current production
    fused_score_to_unit(model.score(tier_scores))      <- proposed

Both taus are calibrated on the same Alpaca draw, and both FPRs are
measured on the same samples. Any difference is then attributable to the
fusion rule alone.

Tier 4 is additionally PINNED OFF (`L1_LLM_JUDGE_ENABLED=False`) and that
is recorded, so the comparison is reproducible rather than contingent on a
third party's rate limiter.

WHAT A NEGATIVE RESULT WOULD MEAN — WRITTEN BEFORE RUNNING
-------------------------------------------------------------
Discrimination and calibration-transfer are different properties, and
fusion only targets the first. Conformal FPR control needs the benign
score distribution to be EXCHANGEABLE between the calibration corpus and
the deployment corpus. If WildJailbreak's benign scores sit systematically
higher than Alpaca's, an Alpaca-calibrated tau under-covers no matter how
well the score ranks malicious against benign. So:

  * if fusion leaves the violation in place, the honest conclusion is that
    the failure is covariate shift in the BENIGN distribution, which is
    orthogonal to fusion and needs a shift-aware method (weighted or
    Mondrian conformal), not a better detector; and
  * the diagnostic that decides it is not the FPR but the SHIFT ITSELF —
    reported below as the gap between the two corpora's benign score
    distributions on each axis. If fusion improves AUROC while leaving the
    shift unchanged, the mechanism is established rather than guessed.

Usage:
    python -m sentinel.eval.conformal_fusion_paired
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime
from pathlib import Path

from sentinel.core.conformal_risk_control import (
    calibrate_fpr_threshold,
    empirical_fpr_with_ci,
    guarantee_significantly_violated,
)
from sentinel.core.tier_fusion import (
    fused_score_to_unit,
    load_fusion_model,
    max_fusion_score,
)
from sentinel.layers.layer1 import layer1_check

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

_CACHE_DIR = Path(__file__).parent / "data" / "cache"
_SENTINEL_BENCH_TEST = Path(__file__).parent / "data" / "sentinel_bench" / "test.jsonl"
_RESULTS = Path(__file__).parent / "results"

ALPHA = 0.05
N_CALIBRATION = 500
N_VALIDATION = 500


def _load_jsonl(path: Path) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f]


async def _score_tiers(texts: list[str], label: str) -> list[dict]:
    """
    Score once, keep the TIER VECTOR rather than the fused number.

    Keeping the vector is what makes the comparison paired: both fusion
    rules are pure functions of it, so they can be applied afterwards
    without re-running the layer.
    """
    out = []
    for i, text in enumerate(texts):
        if (i + 1) % 100 == 0:
            logger.info(f"  [{label}] scored {i + 1}/{len(texts)}...")
        result = await layer1_check(text)
        out.append(result.tier_scores)
    return out


def _axis_scores(tier_rows: list[dict], model) -> dict[str, list[float]]:
    return {
        "max_fusion": [max_fusion_score(r) for r in tier_rows],
        "tier_fusion": [fused_score_to_unit(model.score(r)) for r in tier_rows],
    }


def _report(name: str, scores: list[float], tau: float) -> dict:
    point, lo, hi = empirical_fpr_with_ci(scores, tau)
    held = not guarantee_significantly_violated(lo, ALPHA)
    return {
        "corpus": name, "n": len(scores), "empirical_fpr": point,
        "ci_low": lo, "ci_high": hi, "alpha": ALPHA, "guarantee_held": held,
    }


def _distribution_summary(scores: list[float]) -> dict:
    import numpy as np

    a = np.asarray(scores, dtype=float)
    return {
        "mean": round(float(a.mean()), 4),
        "sd": round(float(a.std(ddof=1)), 4),
        "p50": round(float(np.percentile(a, 50)), 4),
        "p95": round(float(np.percentile(a, 95)), 4),
    }


def _shift_diagnostics(calib: list[float], deploy: list[float]) -> dict:
    """
    How far apart are two benign score distributions, independent of any
    threshold?

    Reported because it is the quantity that decides whether a conformal
    violation is a fusion problem or a shift problem. All three measures
    are scale-free, which matters here: the max() axis and the fused axis
    are different scales, so raw mean differences between them would not be
    comparable.

      * `ks_statistic` — sup|F_calib - F_deploy|, the standard
        distribution-free shift magnitude.
      * `auroc_calib_vs_deploy` — how well the score alone separates
        "which corpus is this benign sample from". 0.5 means the two benign
        populations are indistinguishable on this axis, i.e. no shift;
        anything higher IS the shift, measured in the units that matter.
      * `deploy_quantile_of_calib_p95` — the fraction of deployment benign
        samples above the calibration set's 95th percentile. Under
        exchangeability this is 0.05 by construction; it is the conformal
        violation restated as a property of the distributions.
    """
    import numpy as np

    from sentinel.eval.tier_fusion_eval import _auroc_fast

    c = np.sort(np.asarray(calib, dtype=float))
    d = np.asarray(deploy, dtype=float)
    grid = np.unique(np.concatenate([c, d]))
    fc = np.searchsorted(c, grid, side="right") / len(c)
    fd = np.searchsorted(np.sort(d), grid, side="right") / len(d)

    return {
        "ks_statistic": round(float(np.abs(fc - fd).max()), 4),
        "auroc_calib_vs_deploy": round(
            _auroc_fast(list(calib) + list(deploy), [0] * len(calib) + [1] * len(deploy)), 4
        ),
        "deploy_quantile_of_calib_p95": round(
            float((d > np.percentile(c, 95)).mean()), 4
        ),
    }


async def run() -> dict:
    import sentinel.config as cfg

    judge_was = getattr(cfg, "L1_LLM_JUDGE_ENABLED", True)
    cfg.L1_LLM_JUDGE_ENABLED = False
    # The fusion model is applied HERE, to recorded tier vectors — so
    # layer1's own flag must stay off or `result.score` would already be
    # fused and `max_fusion_score` would no longer be the baseline.
    fusion_was = cfg.L1_TIER_FUSION
    cfg.L1_TIER_FUSION = False

    try:
        model = load_fusion_model(cfg.L1_TIER_FUSION_MODEL)

        alpaca = _load_jsonl(_CACHE_DIR / "alpaca" / "test" / "samples.jsonl")
        if len(alpaca) < N_CALIBRATION + N_VALIDATION:
            raise SystemExit(
                f"need {N_CALIBRATION + N_VALIDATION} Alpaca samples, have {len(alpaca)}"
            )
        wjb = _load_jsonl(_CACHE_DIR / "wildjailbreak" / "test" / "samples.jsonl")
        sb = _load_jsonl(_SENTINEL_BENCH_TEST)

        corpora = {
            "alpaca_calibration": [s["text"] for s in alpaca[:N_CALIBRATION]],
            "alpaca_validation": [s["text"] for s in alpaca[N_CALIBRATION:N_CALIBRATION + N_VALIDATION]],
            "wildjailbreak_benign": [s["text"] for s in wjb if s.get("label") == "benign"],
            "sentinel_bench_benign": [s["text"] for s in sb if s.get("label") == "benign"],
        }

        tiers = {}
        for name, texts in corpora.items():
            logger.info(f"scoring {len(texts)} samples for {name}...")
            tiers[name] = await _score_tiers(texts, name)

        by_axis = {name: _axis_scores(rows, model) for name, rows in tiers.items()}

        out = {
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "alpha": ALPHA,
            "paired": True,
            "l1_llm_judge_enabled": False,
            "fusion_model": Path(cfg.L1_TIER_FUSION_MODEL).name,
            "n_by_corpus": {k: len(v) for k, v in corpora.items()},
            # PER-SAMPLE TIER VECTORS, persisted deliberately.
            #
            # Scoring these four corpora costs ~8 minutes of real layer
            # inference, and both fusion rules are pure functions of the
            # tier vector. Persisting the vectors means every downstream
            # analysis that needs L1 scores on this data — fused-axis
            # threat_class band derivation, weighted/Mondrian conformal,
            # any future axis — runs offline and instantly, against the
            # EXACT same measurements rather than a fresh run that would
            # differ in Tier-4 availability. The alternative is re-scoring
            # per analysis, which is both slow and unpaired.
            "per_sample_tier_scores": tiers,
            "axes": {},
        }

        for axis in ("max_fusion", "tier_fusion"):
            calib = by_axis["alpaca_calibration"][axis]
            tau = calibrate_fpr_threshold(calib, alpha=ALPHA)
            arms, shifts, dists = [], {}, {}
            for name in ("alpaca_validation", "wildjailbreak_benign", "sentinel_bench_benign"):
                scores = by_axis[name][axis]
                arms.append(_report(name, scores, tau))
                shifts[name] = _shift_diagnostics(calib, scores)
                dists[name] = _distribution_summary(scores)
            out["axes"][axis] = {
                "tau": tau,
                "calibration_distribution": _distribution_summary(calib),
                "arms": arms,
                "benign_distributions": dists,
                "shift_vs_calibration": shifts,
            }

        return out
    finally:
        cfg.L1_LLM_JUDGE_ENABLED = judge_was
        cfg.L1_TIER_FUSION = fusion_was


def _log(out: dict) -> None:
    for axis, a in out["axes"].items():
        logger.info(f"=== {axis} (tau={a['tau']:.4f}) ===")
        for arm in a["arms"]:
            logger.info(
                f"  {arm['corpus']:<24} n={arm['n']:<5} FPR={arm['empirical_fpr']:.4f} "
                f"CI=({arm['ci_low']:.4f},{arm['ci_high']:.4f}) "
                f"held={'yes' if arm['guarantee_held'] else 'NO'}"
            )
        for name, s in a["shift_vs_calibration"].items():
            logger.info(
                f"    shift[{name:<22}] KS={s['ks_statistic']:.4f} "
                f"AUROC_corpus_id={s['auroc_calib_vs_deploy']:.4f} "
                f"frac>calib_p95={s['deploy_quantile_of_calib_p95']:.4f}"
            )

    logger.info("=== paired delta (tier_fusion - max_fusion) ===")
    mx = {a["corpus"]: a for a in out["axes"]["max_fusion"]["arms"]}
    tf = {a["corpus"]: a for a in out["axes"]["tier_fusion"]["arms"]}
    for name in mx:
        logger.info(
            f"  {name:<24} FPR {mx[name]['empirical_fpr']:.4f} -> "
            f"{tf[name]['empirical_fpr']:.4f} "
            f"({tf[name]['empirical_fpr'] - mx[name]['empirical_fpr']:+.4f})"
        )
    for name, s in out["axes"]["max_fusion"]["shift_vs_calibration"].items():
        t = out["axes"]["tier_fusion"]["shift_vs_calibration"][name]
        logger.info(
            f"  {name:<24} shift-AUROC {s['auroc_calib_vs_deploy']:.4f} -> "
            f"{t['auroc_calib_vs_deploy']:.4f} "
            f"({t['auroc_calib_vs_deploy'] - s['auroc_calib_vs_deploy']:+.4f})"
        )


def main() -> None:
    import time

    from sentinel.eval.results_ledger import code_files_for, safe_append_entry

    started = time.monotonic()
    out = asyncio.run(run())
    _log(out)
    _RESULTS.mkdir(exist_ok=True)
    path = _RESULTS / f"eval_conformal_fusion_paired_{datetime.now():%Y%m%d_%H%M%S}.json"
    path.write_text(json.dumps(out, indent=2), encoding="utf-8")
    logger.info(f"Results saved to {path}")

    # `per_sample_tier_scores` is deliberately NOT copied into the ledger:
    # it is thousands of rows, the ledger is one line per run, and the
    # result_file reference already points at it.
    safe_append_entry(
        experiment_id=f"conformal_fusion_paired_{datetime.now():%Y%m%d_%H%M%S}",
        phase="Phase 5 / 3B.3a",
        code_files=code_files_for(
            "sentinel/eval/conformal_fusion_paired.py",
            "sentinel/core/conformal_risk_control.py",
            "sentinel/core/tier_fusion.py",
            "sentinel/layers/layer1.py",
        ),
        dataset_cache_file=str(_CACHE_DIR / "alpaca" / "test" / "samples.jsonl"),
        split=(f"calibrate Alpaca[0:{N_CALIBRATION}]; test Alpaca"
               f"[{N_CALIBRATION}:{N_CALIBRATION + N_VALIDATION}], WJB benign, "
               f"sentinel_bench benign"),
        thresholds_used={"alpha": ALPHA, "l1_llm_judge_enabled": False},
        metrics={
            axis: {
                "tau": a["tau"],
                "arms": a["arms"],
                "shift_vs_calibration": a["shift_vs_calibration"],
            }
            for axis, a in out["axes"].items()
        },
        result_file=str(path),
        runtime_seconds=round(time.monotonic() - started, 1),
        notes=(
            "Paired: every sample scored ONCE, both fusion axes derived from the "
            "same recorded tier vectors, so the comparison is not confounded by "
            "Tier-4 availability drifting between runs. Tier 4 pinned off."
        ),
    )


if __name__ == "__main__":
    main()
