"""
Conformal risk control for a formally-guaranteed false-positive-rate bound.

WHY THIS EXISTS
------------------
Every threshold calibrated elsewhere in this project (Youden's J on L1/L2,
Wald's approximation for SPRT in sequential_triage.py) is either a point
estimate from one draw or an *approximate* guarantee that assumes a
correctly-specified model. Neither gives a real, finite-sample, model-free
answer to "if I deploy this threshold, what's the actual worst-case
probability of a false positive on the next benign request." Split-conformal
calibration does — this module implements the textbook one-sided version,
the same 0/1-loss special case Angelopoulos et al.'s "Conformal Risk
Control" (2022) generalizes, itself built on Vovk's original conformal
prediction theory. Nothing novel is being invented in the math here on
purpose: using an already-proven formula instead of a new one is safer,
and its correctness is independently checkable against known closed-form
answers (see tests/test_conformal_risk_control.py).

THE GUARANTEE, STATED PRECISELY
------------------------------------
Given n i.i.d./exchangeable BENIGN-ONLY calibration scores and a target
false-positive rate alpha, calibrate_fpr_threshold returns a threshold tau
such that, for a new benign sample drawn exchangeably with the calibration
set: P(score > tau) <= alpha. This requires no malicious data and no
assumption about the score distribution's shape — only that calibration
and future benign samples come from the same distribution (exchangeability).
That assumption is an empirical question, not a given — see
sentinel/eval/conformal_l1_eval.py, which stress-tests it directly against
corpora the calibration set never saw.
"""

from __future__ import annotations

import logging
import math

logger = logging.getLogger(__name__)


def calibrate_fpr_threshold(calibration_scores: list[float], alpha: float) -> float:
    """
    Split-conformal one-sided threshold selection.

    k = ceil((n + 1) * (1 - alpha))
    tau = k-th smallest value of {calibration_scores, +inf}

    For any alpha in (0, 1), k is mathematically guaranteed to fall in
    [1, n+1] — i.e. always a valid index into the n+1-element augmented
    array, never out of range. The one degenerate case worth flagging is
    k == n+1 (tau lands on the +inf pad itself, "never flag anything"),
    which happens when the calibration set is too small relative to how
    strict `alpha` is — a real, reachable outcome of the formula, not an
    error, but logged so a caller doesn't silently ship an inert threshold.
    """
    if not (0.0 < alpha < 1.0):
        raise ValueError(f"alpha must be in (0, 1), got {alpha}")
    if not calibration_scores:
        raise ValueError("calibration_scores must be non-empty")

    n = len(calibration_scores)
    k = math.ceil((n + 1) * (1 - alpha))

    augmented = sorted(calibration_scores) + [float("inf")]
    tau = augmented[k - 1]

    if tau == float("inf"):
        logger.warning(
            f"calibrate_fpr_threshold: n={n} calibration samples is too "
            f"small for alpha={alpha} (k={k} lands on the +inf pad) — the "
            f"resulting threshold never flags anything. Use a larger "
            f"calibration set or a larger alpha."
        )

    return tau


def empirical_fpr_with_ci(
    scores: list[float], tau: float, confidence: float = 0.95
) -> tuple[float, float, float]:
    """
    Empirical false-positive rate of threshold `tau` against a real
    (labeled-benign) score sample, with a Clopper-Pearson exact confidence
    interval — needed because a bare point FPR on a few hundred samples
    isn't precise enough to honestly say a guarantee "held" or "broke".

    Returns (point_fpr, ci_low, ci_high).
    """
    from scipy import stats

    if not scores:
        raise ValueError("scores must be non-empty")

    n = len(scores)
    x = sum(1 for s in scores if s > tau)
    point = x / n

    alpha_ci = 1 - confidence
    lo = 0.0 if x == 0 else stats.beta.ppf(alpha_ci / 2, x, n - x + 1)
    hi = 1.0 if x == n else stats.beta.ppf(1 - alpha_ci / 2, x + 1, n - x)

    return point, float(lo), float(hi)


def guarantee_significantly_violated(ci_low: float, alpha: float) -> bool:
    """
    Whether a stress-test result constitutes a STATISTICALLY SIGNIFICANT
    violation of the conformal FPR guarantee — i.e. even the most
    favorable (lowest) end of the empirical FPR's confidence interval
    still exceeds the target alpha, so sampling noise alone cannot explain
    the gap.

    Deliberately NOT `ci_high <= alpha` — that would demand the *entire*
    CI sit below alpha, which is far stricter than "consistent with the
    guarantee holding" and would flag a same-distribution sanity check as
    a "violation" purely from finite-sample noise near the alpha boundary
    (a real mistake caught in this project's own first run: n=500
    same-source Alpaca validation landed at point FPR=0.038, comfortably
    under alpha=0.05, but CI=(0.023, 0.059) — `ci_high <= alpha` called
    this a violation, which is statistically wrong. Testing `ci_low >
    alpha` instead answers the right question: can we rule out that the
    true FPR is at or below alpha? Only a "no" there is a real violation.
    """
    return ci_low > alpha
