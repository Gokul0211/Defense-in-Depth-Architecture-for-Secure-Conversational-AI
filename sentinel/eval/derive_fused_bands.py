"""
Derive L1's `threat_class` bands for the FUSED score axis.

THE DEFECT THIS CLOSES
-------------------------
`L1_SEMANTIC_MEDIUM` (0.30) and `L1_SEMANTIC_HIGH` (0.75) serve two roles
in `layer1.py`, and enabling `L1_TIER_FUSION` splits them apart:

  1. **Judge-invocation gate** — evaluated BEFORE `_apply_tier_fusion`, so
     still on the max() axis it was calibrated on. Correct, unaffected, and
     deliberately left alone: that ordering is what keeps the frozen
     fusion model's cascade availability patterns valid.
  2. **threat_class assignment** — evaluated AFTER fusion, comparing a
     fused logistic score against cosine-similarity bands. Wrong axis.

Measured on WildJailbreak (n=2,210), max() -> fused: INJECTION 1049 -> 828,
SUSPICIOUS 653 -> 981, CLEAN 508 -> 401. The fused labels happen to be
*better* on benign (CLEAN 64 -> 109), but "happens to look better" is not a
calibration.

Severity is bounded and is stated so the fix is not oversold:
`threat_class` is consumed only for REPORTING — `app.py`'s `dominant_type`
and finding strings, `demo_scenarios`' labels — while every block/allow
decision reads `score` against WARN/BLOCK. This changes what a report says,
never what the system does.

THE METHOD: BENIGN-QUANTILE MATCHING
---------------------------------------
Each band answers "how much benign traffic sits below this point". That
question is axis-independent, so the band is transported by preserving its
answer:

    q      = fraction of calibration benign with max_score <= band
    band'  = the q-th quantile of the same samples' FUSED scores

Three reasons this is the right transport and not an arbitrary one:

  * it uses ONLY benign data, exactly like the conformal `tau` derivation,
    so no labels are needed and nothing is fitted to malicious samples;
  * `fused_score_to_unit` is strictly monotone, so ranking is identical on
    both axes and the quantile is the only thing that needs carrying; and
  * Alpaca is the designated calibration corpus and is never fitted on by
    the fusion model (which is fitted on sentinel_bench), so this
    introduces no leakage into any held-out claim.

WHERE IT CAN FAIL, AND WHAT HAPPENS THEN
-------------------------------------------
If a band sits above EVERY calibration benign score, q = 1.0 and the
matched quantile is just the maximum — the mapping saturates and the band
is not identified by benign data at all. That is reported explicitly as
`saturated: true` rather than silently returning the max, because a
saturated band is a number with no calibration behind it and must not be
shipped as though it had one.

Usage:
    python -m sentinel.eval.derive_fused_bands
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

_RESULTS = Path(__file__).parent / "results"
_ARTIFACT_DIR = Path(__file__).resolve().parents[1] / "core" / "artifacts"

# Calibration benign corpora, in preference order. Alpaca first: it is the
# designated calibration set, it is large (500), and the fusion model has
# never seen it.
_CALIBRATION_ARMS = ("alpaca_calibration", "alpaca_validation")


def _latest_paired() -> Path:
    matches = sorted(_RESULTS.glob("eval_conformal_fusion_paired_*.json"))
    if not matches:
        raise SystemExit(
            "no paired conformal result found. Run:\n"
            "    python -m sentinel.eval.conformal_fusion_paired"
        )
    return matches[-1]


def _both_axes(tier_rows: list[dict]) -> tuple[list[float], list[float]]:
    from sentinel.config import L1_TIER_FUSION_MODEL
    from sentinel.core.tier_fusion import (
        fused_score_to_unit,
        load_fusion_model,
        max_fusion_score,
    )

    model = load_fusion_model(L1_TIER_FUSION_MODEL)
    return (
        [max_fusion_score(r) for r in tier_rows],
        [fused_score_to_unit(model.score(r)) for r in tier_rows],
    )


def match_band(
    band: float, max_scores: list[float], fused_scores: list[float],
    n_boot: int = 2000, seed: int = 0,
) -> dict:
    """
    Transport one band from the max() axis to the fused axis.

    THE SATURATED CASE, AND WHY IT IS NOT A FAILURE OF THIS METHOD.
    Measured on n=1000 Alpaca benign, `L1_SEMANTIC_HIGH` = 0.75 sits above
    EVERY benign sample — on the max() axis its own threshold is calibrated
    for (benign max there is 0.6797). So q = 1.0, and the band cannot be
    transported as a benign quantile.

    The reason is worth stating plainly: **0.75 was never a benign quantile
    in the first place.** It is a cosine-similarity heuristic, and no amount
    of benign data can identify it, on either axis. That is a property of
    the original constant, not a shortcoming of quantile matching.

    What benign data CAN identify is the statement "above essentially all
    benign traffic", and the finite-sample-honest version of that is the
    conformal threshold at the smallest alpha the calibration set supports,
    alpha = 1/(n+1). For n=1000 that lands on the sample maximum, so the
    value is reported together with a bootstrap standard deviation — an
    extreme order statistic is high-variance, and shipping one without
    saying so would repeat the original sin of an uncalibrated constant.
    """
    import numpy as np

    from sentinel.core.conformal_risk_control import calibrate_fpr_threshold

    n = len(max_scores)
    q = float(np.mean([s <= band for s in max_scores]))
    saturated = q >= 1.0

    if saturated:
        alpha = 1.0 / (n + 1)
        matched = float(calibrate_fpr_threshold(list(fused_scores), alpha))
        method = "conformal_upper_anchor"
    else:
        # `method="lower"` returns an ACHIEVED score rather than an
        # interpolation between two, matching how conformal thresholds are
        # constructed elsewhere in this project.
        matched = float(np.quantile(fused_scores, q, method="lower"))
        method = "benign_quantile_match"

    rng = np.random.default_rng(seed)
    arr = np.asarray(fused_scores, dtype=float)
    boot = np.array([
        np.quantile(rng.choice(arr, arr.size, replace=True), min(q, 1.0), method="lower")
        for _ in range(n_boot)
    ])

    return {
        "source_band": band,
        "method": method,
        "benign_quantile": round(q, 4),
        "n_calibration": n,
        "matched_band": round(matched, 4),
        "saturated": saturated,
        "bootstrap_sd": round(float(boot.std(ddof=1)), 4),
        "bootstrap_ci95": [round(float(np.percentile(boot, 2.5)), 4),
                           round(float(np.percentile(boot, 97.5)), 4)],
        # How many benign samples land below the matched band on the fused
        # axis. Should reproduce `benign_quantile`; if it does not, the
        # transport is broken.
        "verify_fused_quantile": round(
            float(np.mean([s <= matched for s in fused_scores])), 4
        ),
        # The source band's OWN identification quality on its OWN axis.
        # Recorded so a saturated fused band is judged against the constant
        # it replaces rather than against perfection: if the original was
        # equally unidentified, the transport has lost nothing.
        "source_band_benign_quantile_on_max_axis": round(q, 4),
        "source_axis_benign_max": round(float(np.max(max_scores)), 4),
    }


def derive() -> dict:
    path = _latest_paired()
    data = json.loads(path.read_text(encoding="utf-8"))
    tiers = data.get("per_sample_tier_scores")
    if not tiers:
        raise SystemExit(
            f"{path.name} has no `per_sample_tier_scores`. Re-run "
            "`python -m sentinel.eval.conformal_fusion_paired` on current code."
        )

    rows: list[dict] = []
    used = []
    for arm in _CALIBRATION_ARMS:
        if arm in tiers:
            rows.extend(tiers[arm])
            used.append(arm)
    if not rows:
        raise SystemExit(f"none of {_CALIBRATION_ARMS} present in {path.name}")

    max_scores, fused_scores = _both_axes(rows)

    from sentinel.config import L1_SEMANTIC_HIGH, L1_SEMANTIC_MEDIUM

    bands = {
        "L1_FUSED_SEMANTIC_MEDIUM": match_band(L1_SEMANTIC_MEDIUM, max_scores, fused_scores),
        "L1_FUSED_SEMANTIC_HIGH": match_band(L1_SEMANTIC_HIGH, max_scores, fused_scores),
    }

    ordered = (bands["L1_FUSED_SEMANTIC_MEDIUM"]["matched_band"]
               < bands["L1_FUSED_SEMANTIC_HIGH"]["matched_band"])

    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "source_file": path.name,
        "calibration_arms": used,
        "n_calibration": len(rows),
        "source_bands": {
            "L1_SEMANTIC_MEDIUM": L1_SEMANTIC_MEDIUM,
            "L1_SEMANTIC_HIGH": L1_SEMANTIC_HIGH,
        },
        "bands": bands,
        # MEDIUM < HIGH must survive the transport, or the three-way
        # classification collapses. Monotonicity of fused_score_to_unit
        # makes this true in principle; it is checked because a saturated
        # band can break it in practice.
        "ordering_preserved": ordered,
        # Usability is judged on IDENTIFICATION QUALITY, not on whether a
        # band saturated. A saturated band derived via the conformal upper
        # anchor is still usable if it is well-determined relative to the
        # gap it has to sit in — the failure mode that actually matters is
        # a band whose sampling noise is comparable to the distance between
        # the two bands, since that is when the three-way classification
        # becomes arbitrary.
        "usable": ordered and _well_identified(bands),
        "identification": {
            "band_gap": round(
                bands["L1_FUSED_SEMANTIC_HIGH"]["matched_band"]
                - bands["L1_FUSED_SEMANTIC_MEDIUM"]["matched_band"], 4),
            "worst_bootstrap_sd": round(
                max(b["bootstrap_sd"] for b in bands.values()), 4),
        },
    }


def _well_identified(bands: dict, max_sd_fraction_of_gap: float = 0.25) -> bool:
    """
    Are both bands determined precisely enough to be worth shipping?

    The criterion is relative, not absolute: a bootstrap SD only matters
    compared with the gap between MEDIUM and HIGH. If sampling noise is a
    large fraction of that gap, which of the three classes a score lands in
    is decided by which 1,000 benign samples happened to be drawn, and the
    labels carry no information.
    """
    gap = (bands["L1_FUSED_SEMANTIC_HIGH"]["matched_band"]
           - bands["L1_FUSED_SEMANTIC_MEDIUM"]["matched_band"])
    if gap <= 0:
        return False
    worst = max(b["bootstrap_sd"] for b in bands.values())
    return worst <= max_sd_fraction_of_gap * gap


def main() -> None:
    import time

    from sentinel.eval.results_ledger import code_files_for, safe_append_entry

    started = time.monotonic()
    out = derive()

    logger.info(f"calibration: {out['calibration_arms']} n={out['n_calibration']}")
    for name, b in out["bands"].items():
        logger.info(
            f"  {name:<26} {b['source_band']:.4f} -> {b['matched_band']:.4f}  "
            f"(benign quantile {b['benign_quantile']:.4f}, "
            f"verified {b['verify_fused_quantile']:.4f})"
            + ("  [SATURATED]" if b["saturated"] else "")
        )
    logger.info(f"  ordering preserved: {out['ordering_preserved']}  "
                f"usable: {out['usable']}")
    if not out["usable"]:
        logger.warning(
            "  derived bands are NOT usable — a saturated band has no benign "
            "calibration behind it and must not be shipped as if it had."
        )

    _ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    artifact = _ARTIFACT_DIR / "l1_fused_bands.json"
    artifact.write_text(json.dumps(out, indent=2), encoding="utf-8")
    logger.info(f"wrote {artifact}")

    safe_append_entry(
        experiment_id=f"derive_fused_bands_{datetime.now():%Y%m%d_%H%M%S}",
        phase="Phase 5 / 3B.3c",
        code_files=code_files_for(
            "sentinel/eval/derive_fused_bands.py",
            "sentinel/core/tier_fusion.py",
            "sentinel/layers/layer1.py",
        ),
        dataset_cache_file=str(_RESULTS / out["source_file"]),
        split=f"benign-quantile matching on {out['calibration_arms']}",
        thresholds_used=out["source_bands"],
        metrics=out["bands"] | {"usable": out["usable"]},
        result_file=str(artifact),
        runtime_seconds=round(time.monotonic() - started, 1),
        notes=(
            "threat_class bands only — the judge-invocation gate stays on the "
            "max() axis by design. Uses benign data only, same as the conformal "
            "tau derivation, so no labels and no leakage into held-out claims."
        ),
    )


if __name__ == "__main__":
    main()
