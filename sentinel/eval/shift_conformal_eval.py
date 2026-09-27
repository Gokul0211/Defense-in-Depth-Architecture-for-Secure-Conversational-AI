"""
Does shift-aware conformal repair the guarantee that plain split-conformal
and tier fusion both failed to hold?

THE SETUP
------------
Established 2026-09-19 and not re-litigated here:

  * plain split-conformal calibrated on Alpaca benign holds on Alpaca
    (FPR 0.0380) and on sentinel_bench benign (0.0000), and FAILS on
    WildJailbreak benign (0.2619) against alpha=0.05;
  * calibrated tier fusion does not help — it moved benign shift-AUROC by
    +0.0052 and FPR to 0.3000, because discrimination and
    calibration-transfer are different properties.

So the remaining candidates are methods that model the shift itself.

THE PROTOCOL, AND THE TRAP IN IT
-----------------------------------
Weighted conformal needs the deployment distribution to estimate w(x). The
tempting and WRONG thing is to estimate w on the same WildJailbreak benign
samples the FPR is then measured on: the weights would be fitted to the
very points being scored, and a near-perfect FPR would be guaranteed and
meaningless. That is the same leak the cross-corpus protocol exists to
prevent elsewhere in this project.

So WildJailbreak benign is SPLIT: one half estimates the weights (standing
in for the unlabelled deployment sample a real deployment would have), the
other half is held out and is the only thing FPR is measured on. The split
is repeated over several seeds because n=210 halves to 105, and a single
split of 105 samples is noisy enough to mislead.

Mondrian is evaluated the same way: calibrate the group threshold on one
half, measure on the other. That makes the two methods directly
comparable, and it charges Mondrian honestly for the labelled deployment
data it requires.

WHAT IS AND IS NOT BEING CLAIMED
-----------------------------------
Recovering FPR <= alpha by RAISING the threshold is not, on its own, a
result — a sufficiently high threshold always achieves it, by never firing.
So the cost is reported alongside: `tau` movement and the resulting TPR on
real malicious WildJailbreak samples. A method that holds the guarantee
while destroying recall has traded one failure for another, and the table
shows it.

Usage:
    python -m sentinel.eval.shift_conformal_eval
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path

from sentinel.core.conformal_risk_control import (
    calibrate_fpr_threshold,
    empirical_fpr_with_ci,
    guarantee_significantly_violated,
)
from sentinel.core.shift_conformal import (
    mondrian_thresholds,
    weighted_conformal_threshold,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

_RESULTS = Path(__file__).parent / "results"
ALPHA = 0.05
N_SPLITS = 20


def _latest_paired() -> Path:
    matches = sorted(_RESULTS.glob("eval_conformal_fusion_paired_*.json"))
    if not matches:
        raise SystemExit(
            "no paired conformal result found. Run:\n"
            "    python -m sentinel.eval.conformal_fusion_paired"
        )
    return matches[-1]


def load_scores(path: Path, axis: str = "max_fusion") -> dict[str, list[float]]:
    """
    Rebuild per-sample scores on one axis from the persisted tier vectors.

    Reusing the stored vectors rather than re-scoring is what makes every
    method below comparable: all of them see the EXACT same measurements,
    with the same Tier-4 availability, rather than a fresh run that would
    differ for reasons unrelated to the method.
    """
    from sentinel.core.tier_fusion import (
        fused_score_to_unit,
        load_fusion_model,
        max_fusion_score,
    )

    data = json.loads(path.read_text(encoding="utf-8"))
    tiers = data.get("per_sample_tier_scores")
    if not tiers:
        raise SystemExit(
            f"{path.name} has no `per_sample_tier_scores`. Re-run "
            "`python -m sentinel.eval.conformal_fusion_paired` on current code."
        )

    if axis == "max_fusion":
        score = max_fusion_score
    else:
        from sentinel.config import L1_TIER_FUSION_MODEL

        model = load_fusion_model(L1_TIER_FUSION_MODEL)
        def score(row):  # noqa: E306
            return fused_score_to_unit(model.score(row))

    return {name: [score(r) for r in rows] for name, rows in tiers.items()}


def _report(scores: list[float], tau: float) -> dict:
    point, lo, hi = empirical_fpr_with_ci(scores, tau)
    return {
        "n": len(scores),
        "empirical_fpr": round(point, 4),
        "ci_low": round(lo, 4),
        "ci_high": round(hi, 4),
        "guarantee_held": not guarantee_significantly_violated(lo, ALPHA),
    }


def evaluate(axis: str = "max_fusion") -> dict:
    import numpy as np

    path = _latest_paired()
    scores = load_scores(path, axis)
    calib = scores["alpaca_calibration"]
    deploy = scores["wildjailbreak_benign"]

    baseline_tau = calibrate_fpr_threshold(calib, ALPHA)

    methods = {
        "split_conformal_alpaca": [],
        # Both density-ratio estimators are carried, not just the default.
        # The histogram spends one free parameter per bin on ~500 points
        # and is noisy in the tails where the quantile is read; the
        # logistic spends two and is monotone, matching the measured
        # one-sided shift — but is biased if the true shift is not
        # monotone. Which trade wins is an empirical question, so it is
        # measured rather than argued.
        "weighted_conformal_logistic": [],
        "weighted_conformal_histogram": [],
        "mondrian_wjb": [],
    }
    taus = {k: [] for k in methods}
    diagnostics = []

    rng_master = np.random.default_rng(404)
    for split in range(N_SPLITS):
        idx = rng_master.permutation(len(deploy))
        half = len(idx) // 2
        fit_idx, test_idx = idx[:half], idx[half:]
        fit = [deploy[i] for i in fit_idx]
        test = [deploy[i] for i in test_idx]

        # 1. Baseline: Alpaca-calibrated threshold, ignores the shift.
        methods["split_conformal_alpaca"].append(_report(test, baseline_tau))
        taus["split_conformal_alpaca"].append(baseline_tau)

        # 2. Weighted: Alpaca calibration reweighted toward the deployment
        #    distribution, estimated on the FIT half only.
        for est in ("logistic", "histogram"):
            name = f"weighted_conformal_{est}"
            w_tau, diag = weighted_conformal_threshold(calib, fit, ALPHA, method=est)
            methods[name].append(_report(test, w_tau))
            taus[name].append(w_tau)
            if split == 0:
                diagnostics.append({"split": 0, "estimator": est, **diag})

        # 3. Mondrian: a threshold calibrated on WJB's own benign half.
        m_tau = mondrian_thresholds({"wildjailbreak": fit}, ALPHA)["wildjailbreak"]["tau"]
        methods["mondrian_wjb"].append(_report(test, m_tau))
        taus["mondrian_wjb"].append(m_tau)

    # Recall cost, on real malicious WildJailbreak samples. Without this a
    # method that never fires would look like a total success.
    malicious = _malicious_scores(axis)

    summary = {}
    for name, runs in methods.items():
        fprs = np.array([r["empirical_fpr"] for r in runs])
        tau_arr = np.array([t for t in taus[name] if np.isfinite(t)])
        entry = {
            "n_splits": N_SPLITS,
            "mean_fpr": round(float(fprs.mean()), 4),
            "sd_fpr": round(float(fprs.std(ddof=1)), 4),
            "max_fpr": round(float(fprs.max()), 4),
            "splits_holding_guarantee": sum(r["guarantee_held"] for r in runs),
            "mean_tau": round(float(tau_arr.mean()), 4) if tau_arr.size else None,
            "tau_vs_baseline": (round(float(tau_arr.mean() - baseline_tau), 4)
                                if tau_arr.size else None),
        }
        if malicious and tau_arr.size:
            entry["tpr_on_wjb_malicious_at_mean_tau"] = round(
                float(np.mean([s >= tau_arr.mean() for s in malicious])), 4
            )
        summary[name] = entry

    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "axis": axis,
        "alpha": ALPHA,
        "source_file": path.name,
        "n_calibration": len(calib),
        "n_deployment_benign": len(deploy),
        "n_deployment_malicious": len(malicious),
        "baseline_tau": round(baseline_tau, 4),
        "protocol": (
            "WildJailbreak benign split in half per seed: one half estimates "
            "weights / calibrates the group threshold, the other half is held out "
            "and is the only set FPR is measured on. Repeated over "
            f"{N_SPLITS} seeds."
        ),
        "weight_diagnostics": diagnostics,
        "summary": summary,
    }


def _malicious_scores(axis: str) -> list[float]:
    """
    Real WildJailbreak MALICIOUS scores on the same axis, from the saved L1
    eval's recorded tier vectors.

    Needed to price the guarantee. Returns [] if unavailable, and the
    recall column is then simply omitted rather than guessed.
    """
    from sentinel.core.tier_fusion import (
        fused_score_to_unit,
        load_fusion_model,
        max_fusion_score,
    )

    best, best_cov = None, -1
    for p in sorted(_RESULTS.glob("eval_L1_wildjailbreak_*.json")):
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            continue
        cov = sum(1 for s in d.get("per_sample", [])
                  for v in (s.get("tier_scores") or {}).values() if v is not None)
        if cov > best_cov:
            best, best_cov = d, cov
    if best is None or best_cov <= 0:
        logger.warning("no WildJailbreak eval with tier_scores; recall cost omitted")
        return []

    rows = [s["tier_scores"] for s in best["per_sample"]
            if s.get("tier_scores") and s["label"] == "malicious"]
    if axis == "max_fusion":
        return [max_fusion_score(r) for r in rows]
    from sentinel.config import L1_TIER_FUSION_MODEL

    model = load_fusion_model(L1_TIER_FUSION_MODEL)
    return [fused_score_to_unit(model.score(r)) for r in rows]


def main() -> None:
    import time

    from sentinel.eval.results_ledger import code_files_for, safe_append_entry

    started = time.monotonic()
    out = {axis: evaluate(axis) for axis in ("max_fusion", "tier_fusion")}

    for axis, res in out.items():
        logger.info(f"=== {axis} (alpha={ALPHA}, baseline tau={res['baseline_tau']}) ===")
        logger.info(f"  {'method':<26} {'mean FPR':>9} {'sd':>7} {'max':>7} "
                    f"{'held':>7} {'tau':>8} {'d_tau':>8} {'TPR_mal':>8}")
        for name, s in res["summary"].items():
            logger.info(
                f"  {name:<26} {s['mean_fpr']:>9.4f} {s['sd_fpr']:>7.4f} "
                f"{s['max_fpr']:>7.4f} {s['splits_holding_guarantee']:>4}/{N_SPLITS} "
                f"{s['mean_tau']:>8.4f} {s['tau_vs_baseline']:>+8.4f} "
                f"{s.get('tpr_on_wjb_malicious_at_mean_tau', float('nan')):>8.4f}"
            )
        for d in res["weight_diagnostics"]:
            logger.info(f"    weights[{d.get('estimator')}]: "
                        f"ESS={d.get('effective_sample_size')} "
                        f"({d.get('ess_fraction')} of n), range "
                        f"[{d.get('weight_min')}, {d.get('weight_max')}], "
                        f"at_upper_clip={d.get('n_weights_at_upper_clip')}, "
                        f"at_floor={d.get('n_weights_at_floor')}")

    _RESULTS.mkdir(exist_ok=True)
    path = _RESULTS / f"eval_shift_conformal_{datetime.now():%Y%m%d_%H%M%S}.json"
    path.write_text(json.dumps(out, indent=2), encoding="utf-8")
    logger.info(f"Results saved to {path}")

    safe_append_entry(
        experiment_id=f"shift_conformal_{datetime.now():%Y%m%d_%H%M%S}",
        phase="Phase 5 / 3B.3b",
        code_files=code_files_for(
            "sentinel/core/shift_conformal.py",
            "sentinel/eval/shift_conformal_eval.py",
            "sentinel/core/conformal_risk_control.py",
        ),
        dataset_cache_file=str(_RESULTS / out["max_fusion"]["source_file"]),
        split=out["max_fusion"]["protocol"],
        thresholds_used={"alpha": ALPHA, "n_splits": N_SPLITS},
        metrics={axis: res["summary"] for axis, res in out.items()},
        result_file=str(path),
        runtime_seconds=round(time.monotonic() - started, 1),
        seed=404,
        notes=(
            "Deployment benign SPLIT: weights/group threshold fitted on one half, "
            "FPR measured only on the held-out half, repeated over 20 seeds. "
            "Recall cost on real WJB malicious reported so a method cannot 'win' "
            "by never firing."
        ),
    )


if __name__ == "__main__":
    main()
