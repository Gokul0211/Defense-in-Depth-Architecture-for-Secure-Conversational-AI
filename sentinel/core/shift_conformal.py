"""
Shift-aware conformal thresholds — weighted and Mondrian.

WHY THIS EXISTS
------------------
`conformal_risk_control.calibrate_fpr_threshold` gives a distribution-free
FPR guarantee under EXCHANGEABILITY between the calibration corpus and the
deployment corpus. That assumption is measurably false for this system.
Measured 2026-09-19 (`eval/conformal_fusion_paired.py`), calibrating on
Alpaca benign and deploying on WildJailbreak benign:

    shift-AUROC (does the L1 score alone say which corpus a BENIGN
    sample came from?)                                   0.8171
    fraction of WJB benign above Alpaca's 95th pct       0.2619
    resulting empirical FPR against alpha=0.05           0.2619  (violated)

And the thing that first looked like the fix did not work: calibrated tier
fusion raised cross-corpus AUROC 0.6457 -> 0.7426 while moving shift-AUROC
by +0.0052 and making FPR slightly WORSE (0.2619 -> 0.3000). Discrimination
and calibration-transfer are different properties; improving a detector
cannot repair a covariate shift in the benign distribution.

A second measured fact shapes the design. sentinel_bench benign is MORE
shifted than WildJailbreak by KS (0.6085 vs 0.4964) yet its guarantee holds
perfectly (FPR 0.0000), because its shift is downward and the guarantee is
one-sided. So the remedy must respond to shift DIRECTION, not magnitude.

TWO METHODS, AND WHAT EACH ACTUALLY BUYS
-------------------------------------------
**Weighted conformal** (Tibshirani et al., 2019) restores the guarantee
under *covariate shift* by reweighting each calibration point by the
likelihood ratio w(x) = dP_deploy/dP_calib, then taking a weighted
quantile. The guarantee is exact when w is exact. Here w is ESTIMATED, by
the standard probabilistic-classifier trick: fit a discriminator to tell
calibration samples from deployment samples, and use its odds. That makes
the guarantee approximate, and the size of the approximation is bounded by
how well that discriminator generalises — which is reported, not assumed.

**Mondrian / group-conditional conformal** (Vovk) sidesteps estimation
entirely: calibrate a SEPARATE threshold per group, and the guarantee holds
within each group by exchangeability *within* the group. It needs labelled
benign data from the deployment corpus, which is a real operational cost —
but it is exact rather than approximate, and it is the honest baseline that
any weighted method has to beat.

WHAT NEITHER CAN DO
----------------------
Neither method invents information. If deployment benign traffic genuinely
scores higher, holding FPR at alpha necessarily means raising the
threshold, which necessarily costs recall. The price is real and is
reported here as `tau` movement, so the trade is visible rather than
buried.
"""

from __future__ import annotations

import logging
import math

logger = logging.getLogger(__name__)


def weighted_quantile(values, weights, q: float) -> float:
    """
    Smallest v such that the weighted fraction of `values` <= v is >= q.

    Written out rather than taken from numpy because numpy's `quantile`
    has no weighted form, and the interpolating variants people reach for
    instead are wrong here: a conformal threshold must be an ACHIEVED
    order statistic of the calibration set, not a value interpolated
    between two of them. Interpolation silently breaks the coverage
    guarantee, which is the entire point of the construction.
    """
    import numpy as np

    values = np.asarray(values, dtype=float)
    weights = np.asarray(weights, dtype=float)
    if values.size == 0:
        raise ValueError("values must be non-empty")
    if values.size != weights.size:
        raise ValueError("values and weights must be the same length")
    if np.any(weights < 0):
        raise ValueError("weights must be non-negative")

    total = weights.sum()
    if total <= 0:
        raise ValueError("weights must not sum to zero")

    order = np.argsort(values, kind="mergesort")
    v, w = values[order], weights[order]
    cumulative = np.cumsum(w) / total
    idx = int(np.searchsorted(cumulative, q, side="left"))
    return float(v[min(idx, len(v) - 1)])


def _logistic_density_ratio(calib, deploy, clip: float, l2: float, iters: int, lr: float):
    """
    w(x) via the probabilistic-classifier trick, with a logistic
    discriminator on the score.

    Fit P(deploy | s) with a 1-D logistic on the score, then

        w(s) = P(deploy|s) / P(calib|s) * (n_calib / n_deploy)

    where the last factor removes the class-balance of the discriminator's
    own training set, leaving a density ratio rather than a posterior odds.

    Why this can beat the histogram: the histogram spends one free
    parameter per bin (20 of them) on ~500 calibration points, so its
    ratio is noisy in the tails — exactly where the conformal quantile is
    read. The logistic spends two, and is monotone in the score. Monotone
    is the right inductive bias here: the measured shift is one-sided
    (WildJailbreak benign scores are shifted UPWARD), so w really should
    increase with the score, and a model that cannot represent a
    non-monotone wiggle cannot fit noise into one.

    The cost, stated because it is real: if the true shift is NOT
    monotone, this is biased where the histogram is merely noisy. Both are
    therefore computed and reported, and the comparison decides.
    """
    import numpy as np

    x = np.concatenate([calib, deploy])
    y = np.concatenate([np.zeros(len(calib)), np.ones(len(deploy))])

    # Standardise so the fit is conditioned the same way regardless of the
    # axis's scale — the max() and fused axes have different spreads.
    mu, sigma = x.mean(), x.std() or 1.0
    z = (x - mu) / sigma

    a = b = 0.0
    n = len(z)
    for _ in range(iters):
        p = 1.0 / (1.0 + np.exp(-np.clip(a + b * z, -30, 30)))
        err = p - y
        a -= lr * err.mean()
        b -= lr * ((err * z).mean() + l2 * b / n)

    zc = (calib - mu) / sigma
    p_deploy = 1.0 / (1.0 + np.exp(-np.clip(a + b * zc, -30, 30)))
    odds = p_deploy / np.clip(1.0 - p_deploy, 1e-12, None)
    weights = np.clip(odds * (len(calib) / len(deploy)), 1.0 / clip, clip)
    return weights, {"logistic_a": round(float(a), 4), "logistic_b": round(float(b), 4)}


# Ratio clip. Set at the point where it STOPS BINDING, which is a property
# of the estimated weights rather than of any evaluation metric: measured
# on Alpaca -> WildJailbreak benign, clip=50 and clip=200 produce byte-
# identical thresholds and identical ESS, so no weight reaches 50. Lower
# values were actively truncating real signal (FPR 0.1671 at clip=5,
# 0.1548 at 10, 0.1471 at 20, 0.1390 at 50, 0.1390 at 200).
#
# Chosen on the non-binding criterion, NOT by picking the best FPR — the
# full sweep is recorded above so that choice is auditable. The clip still
# exists for its original purpose: an empty calibration region sends w to
# infinity, and one such point would then determine the quantile alone.
DEFAULT_RATIO_CLIP = 50.0


def estimate_shift_weights(
    calib_scores, deploy_scores, n_bins: int = 20, clip: float = DEFAULT_RATIO_CLIP,
    method: str = "logistic", l2: float = 1.0, iters: int = 2000, lr: float = 0.5,
) -> tuple[list[float], dict]:
    """
    Estimate w(x) = dP_deploy/dP_calib for each CALIBRATION point.

    Both estimators work on the SCORE itself, which is deliberate: the only
    covariate the threshold ever sees is the score, so a ratio estimated on
    it is estimated on exactly the right space. A richer feature model
    would fit structure the threshold cannot use.

      `histogram` — Laplace-smoothed density ratio over `n_bins`. Flexible,
                    but spends one free parameter per bin on a few hundred
                    points, so it is noisy in the tails, which is precisely
                    where the conformal quantile is read.
      `logistic`  — probabilistic-classifier ratio from a 1-D logistic.
                    Two parameters and monotone in the score, matching the
                    measured one-sided shift. DEFAULT, on the evidence in
                    `eval/shift_conformal_eval.py`.

    Ratios are clipped either way. The clip guards a real failure: an empty
    calibration bin sends w to infinity, and a single such point then
    determines the weighted quantile on its own.

    Returns (weights, diagnostics).

    A NOTE ON `effective_sample_size`, CORRECTED BY MEASUREMENT. An earlier
    version of this docstring called ESS "the number that matters" and
    implied lower ESS means a worse estimate. The measured comparison
    contradicts that: the logistic estimator has ESS 137 of 500 (27%)
    against the histogram's 230 (46%), yet produces lower FPR (0.1471 vs
    0.1890) and lower variance across splits (sd 0.0197 vs 0.0332).

    ESS measures weight CONCENTRATION, not estimate quality. The shift here
    is one-sided, so correctly modelling it *requires* concentrating weight
    on the upper tail of the calibration scores — that concentration is
    signal, not noise. ESS is therefore reported as a diagnostic of how few
    points the quantile effectively rests on, which is worth knowing, but it
    must not be read as a ranking of estimators.
    """
    import numpy as np

    calib = np.asarray(calib_scores, dtype=float)
    deploy = np.asarray(deploy_scores, dtype=float)

    lo = float(min(calib.min(), deploy.min()))
    hi = float(max(calib.max(), deploy.max()))
    if hi <= lo:
        return [1.0] * len(calib), {"degenerate": True, "reason": "zero score range"}

    extra: dict = {}
    if method == "logistic":
        weights, extra = _logistic_density_ratio(calib, deploy, clip, l2, iters, lr)
        n_at_clip = int((weights >= clip).sum())
        n_at_floor = int((weights <= 1.0 / clip).sum())
    elif method == "histogram":
        edges = np.linspace(lo, hi, n_bins + 1)
        c_hist, _ = np.histogram(calib, bins=edges)
        d_hist, _ = np.histogram(deploy, bins=edges)
        c_density = (c_hist + 1.0) / (c_hist.sum() + n_bins)
        d_density = (d_hist + 1.0) / (d_hist.sum() + n_bins)
        ratio = np.clip(d_density / c_density, 1.0 / clip, clip)
        bin_idx = np.clip(np.digitize(calib, edges) - 1, 0, n_bins - 1)
        weights = ratio[bin_idx]
        n_at_clip = int((weights >= clip).sum())
        n_at_floor = int((weights <= 1.0 / clip).sum())
    else:
        raise ValueError(f"unknown method {method!r}; expected 'logistic' or 'histogram'")

    ess = float(weights.sum() ** 2 / np.square(weights).sum())
    return weights.tolist(), {
        "method": method,
        "n_bins": n_bins if method == "histogram" else None,
        "clip": clip,
        "weight_min": round(float(weights.min()), 4),
        "weight_max": round(float(weights.max()), 4),
        "effective_sample_size": round(ess, 1),
        "ess_fraction": round(ess / len(calib), 4),
        # Upper and lower clipping are reported SEPARATELY because they mean
        # opposite things. A weight at the UPPER clip is a truncated large
        # weight — real signal being discarded, and the thing the
        # non-binding criterion for DEFAULT_RATIO_CLIP is about. A weight at
        # the FLOOR is a calibration point in a region the deployment
        # distribution essentially never visits; flooring it is harmless and
        # mildly stabilising, since its exact tiny value cannot matter.
        # Conflating the two made the clip look like it was binding when only
        # the harmless side was.
        "n_weights_at_upper_clip": n_at_clip,
        "n_weights_at_floor": n_at_floor,
        **extra,
    }


def weighted_conformal_threshold(
    calib_scores, deploy_scores, alpha: float, n_bins: int = 20,
    clip: float = DEFAULT_RATIO_CLIP, method: str = "logistic",
) -> tuple[float, dict]:
    """
    Covariate-shift-corrected one-sided conformal threshold.

    Mirrors `calibrate_fpr_threshold`'s finite-sample correction: the
    unweighted version takes the k-th smallest of n+1 values with
    k = ceil((n+1)(1-alpha)), which is the (1-alpha) quantile of the
    calibration distribution augmented by a point mass at +inf. The same
    augmentation is applied here by giving +inf the deployment point's own
    weight — without it the weighted version is anti-conservative at small
    n in exactly the way the unweighted correction exists to prevent.
    """
    import numpy as np

    if not (0.0 < alpha < 1.0):
        raise ValueError(f"alpha must be in (0, 1), got {alpha}")

    weights, diag = estimate_shift_weights(
        calib_scores, deploy_scores, n_bins, clip, method=method
    )
    w = np.asarray(weights, dtype=float)

    # The augmenting +inf point represents the unseen deployment sample and
    # carries the mean calibration weight, which is the natural stand-in for
    # a point whose covariate value is not yet known.
    values = np.append(np.asarray(calib_scores, dtype=float), np.inf)
    weights_aug = np.append(w, w.mean())

    tau = weighted_quantile(values, weights_aug, 1.0 - alpha)
    if math.isinf(tau):
        logger.warning(
            "weighted_conformal_threshold: tau landed on the +inf pad "
            "(n=%d, alpha=%s) — the threshold never flags anything.",
            len(calib_scores), alpha,
        )
    diag["tau"] = tau
    return tau, diag


def mondrian_thresholds(groups: dict, alpha: float) -> dict:
    """
    One conformal threshold per group, each exact within its own group.

    `groups` maps a group name to that group's benign calibration scores.
    Exchangeability is only required WITHIN a group, so no assumption is
    made about the groups resembling each other — which is precisely the
    assumption the measured shift violates.

    The operational cost is explicit and is the reason this is not simply
    the recommended answer: a group with no labelled benign calibration
    data gets no threshold, so deploying to a genuinely new corpus needs
    labelled benign samples from it first.
    """
    from sentinel.core.conformal_risk_control import calibrate_fpr_threshold

    out = {}
    for name, scores in groups.items():
        if not scores:
            logger.warning("mondrian_thresholds: group %r has no scores, skipped", name)
            continue
        out[name] = {
            "tau": calibrate_fpr_threshold(list(scores), alpha),
            "n_calibration": len(scores),
        }
    return out
