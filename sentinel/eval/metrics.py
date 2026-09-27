"""
SENTINEL Evaluation — Publication-Grade Metrics.

Computes all metrics required by 02_EVALUATION_TESTING_PLAN.md:
  - Per-layer: Precision, Recall, F1, AUROC, AUPRC (Section 3.1)
  - Pipeline-level: Detection rate, FPR, blocked/flagged/allowed (Section 3.2)
  - Correlation-specific: Ablation support (Section 3.3)
  - Latency: p50, p95, p99 (Section 3.4)
  - Calibration: ECE, reliability diagrams (Section 3.6)
  - Statistical rigor: Bootstrap CIs, McNemar's test (Section 6)

Usage:
    from sentinel.eval.metrics import compute_classification_metrics, bootstrap_ci
    results = compute_classification_metrics(y_true, y_scores, threshold=0.85)
"""

from __future__ import annotations

import json
import logging
import math
from dataclasses import dataclass, field, asdict
from typing import Callable, Optional

import numpy as np

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result containers
# ---------------------------------------------------------------------------
@dataclass
class ClassificationMetrics:
    """Metrics for a binary classification task at a specific threshold."""
    precision: float
    recall: float
    f1: float
    accuracy: float
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    threshold: float
    n_samples: int

    @property
    def fpr(self) -> float:
        """False positive rate."""
        denom = self.false_positives + self.true_negatives
        return self.false_positives / denom if denom > 0 else 0.0

    @property
    def fnr(self) -> float:
        """False negative rate."""
        denom = self.false_negatives + self.true_positives
        return self.false_negatives / denom if denom > 0 else 0.0

    def to_dict(self) -> dict:
        d = asdict(self)
        d["fpr"] = self.fpr
        d["fnr"] = self.fnr
        return d


@dataclass
class ThresholdSweepMetrics:
    """AUROC, AUPRC, and per-threshold metrics across the full sweep."""
    auroc: float
    auprc: float
    precision_at_thresholds: list[float]
    recall_at_thresholds: list[float]
    thresholds: list[float]
    # ROC curve data
    fpr_curve: list[float]
    tpr_curve: list[float]
    roc_thresholds: list[float]

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class CalibrationMetrics:
    """Expected Calibration Error and reliability diagram data."""
    ece: float                          # Expected Calibration Error
    bin_accuracies: list[float]         # Actual accuracy per bin
    bin_confidences: list[float]        # Mean predicted probability per bin
    bin_counts: list[int]               # Number of samples per bin
    n_bins: int

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class LatencyMetrics:
    """Latency percentiles in milliseconds."""
    p50: float
    p95: float
    p99: float
    mean: float
    std: float
    min: float
    max: float
    n_samples: int

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class BootstrapResult:
    """Bootstrap confidence interval for a metric."""
    point_estimate: float
    ci_lower: float
    ci_upper: float
    confidence_level: float
    n_resamples: int

    def to_dict(self) -> dict:
        return asdict(self)

    def __str__(self) -> str:
        return (
            f"{self.point_estimate:.4f} "
            f"[{self.ci_lower:.4f}, {self.ci_upper:.4f}] "
            f"({self.confidence_level*100:.0f}% CI, n={self.n_resamples})"
        )


@dataclass
class PipelineMetrics:
    """End-to-end pipeline metrics: detection rate, FPR, decision breakdown."""
    detection_rate: float               # TP / (TP + FN) on attack samples
    false_positive_rate: float          # FP / (FP + TN) on benign samples
    n_blocked: int                      # Decision = BLOCK
    n_flagged: int                      # Decision = WARN/SUSPICIOUS
    n_allowed: int                      # Decision = ALLOW
    n_total: int
    # Breakdown of flagged tier
    flagged_true_attacks: int           # WARN that were real attacks
    flagged_benign: int                 # WARN that were benign (edge cases)

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Core metric computations
# ---------------------------------------------------------------------------

def compute_classification_metrics(
    y_true: np.ndarray | list,
    y_scores: np.ndarray | list,
    threshold: float = 0.5,
) -> ClassificationMetrics:
    """
    Compute binary classification metrics at a specific threshold.

    Args:
        y_true:    Ground-truth labels (1 = malicious, 0 = benign).
        y_scores:  Predicted scores / probabilities.
        threshold: Decision threshold (score >= threshold → predicted malicious).

    Returns:
        ClassificationMetrics with all standard metrics.
    """
    y_true = np.asarray(y_true, dtype=int)
    y_scores = np.asarray(y_scores, dtype=float)

    y_pred = (y_scores >= threshold).astype(int)

    tp = int(np.sum((y_pred == 1) & (y_true == 1)))
    fp = int(np.sum((y_pred == 1) & (y_true == 0)))
    tn = int(np.sum((y_pred == 0) & (y_true == 0)))
    fn = int(np.sum((y_pred == 0) & (y_true == 1)))

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / len(y_true) if len(y_true) > 0 else 0.0

    return ClassificationMetrics(
        precision=precision,
        recall=recall,
        f1=f1,
        accuracy=accuracy,
        true_positives=tp,
        false_positives=fp,
        true_negatives=tn,
        false_negatives=fn,
        threshold=threshold,
        n_samples=len(y_true),
    )


def compute_threshold_sweep(
    y_true: np.ndarray | list,
    y_scores: np.ndarray | list,
) -> ThresholdSweepMetrics:
    """
    Compute AUROC, AUPRC, and full ROC/PR curves.

    Uses sklearn for reliable computation — this is the standard
    and reviewers will expect sklearn-compatible methodology.
    """
    from sklearn.metrics import (
        roc_auc_score, average_precision_score,
        roc_curve, precision_recall_curve,
    )

    y_true = np.asarray(y_true, dtype=int)
    y_scores = np.asarray(y_scores, dtype=float)

    # Handle edge case: only one class present
    if len(np.unique(y_true)) < 2:
        logger.warning("Only one class present in y_true — AUROC/AUPRC undefined")
        return ThresholdSweepMetrics(
            auroc=float("nan"),
            auprc=float("nan"),
            precision_at_thresholds=[],
            recall_at_thresholds=[],
            thresholds=[],
            fpr_curve=[],
            tpr_curve=[],
            roc_thresholds=[],
        )

    auroc = roc_auc_score(y_true, y_scores)
    auprc = average_precision_score(y_true, y_scores)

    fpr_arr, tpr_arr, roc_thresh = roc_curve(y_true, y_scores)
    pr_prec, pr_rec, pr_thresh = precision_recall_curve(y_true, y_scores)

    return ThresholdSweepMetrics(
        auroc=float(auroc),
        auprc=float(auprc),
        precision_at_thresholds=[float(x) for x in pr_prec],
        recall_at_thresholds=[float(x) for x in pr_rec],
        thresholds=[float(x) for x in pr_thresh],
        fpr_curve=[float(x) for x in fpr_arr],
        tpr_curve=[float(x) for x in tpr_arr],
        roc_thresholds=[float(x) for x in roc_thresh],
    )


def compute_calibration(
    y_true: np.ndarray | list,
    y_scores: np.ndarray | list,
    n_bins: int = 10,
) -> CalibrationMetrics:
    """
    Compute Expected Calibration Error (ECE) and reliability diagram data.

    ECE measures how well a model's predicted probabilities match observed
    frequencies — essential for reporting in the paper (Section 3.6).
    """
    y_true = np.asarray(y_true, dtype=int)
    y_scores = np.asarray(y_scores, dtype=float)

    bin_boundaries = np.linspace(0.0, 1.0, n_bins + 1)
    bin_accuracies = []
    bin_confidences = []
    bin_counts = []

    ece = 0.0
    total = len(y_true)

    for i in range(n_bins):
        lo, hi = bin_boundaries[i], bin_boundaries[i + 1]
        if i == n_bins - 1:
            mask = (y_scores >= lo) & (y_scores <= hi)
        else:
            mask = (y_scores >= lo) & (y_scores < hi)

        count = int(np.sum(mask))
        bin_counts.append(count)

        if count == 0:
            bin_accuracies.append(0.0)
            bin_confidences.append(0.0)
            continue

        acc = float(np.mean(y_true[mask] == (y_scores[mask] >= 0.5).astype(int)))
        conf = float(np.mean(y_scores[mask]))
        bin_accuracies.append(acc)
        bin_confidences.append(conf)

        ece += (count / total) * abs(acc - conf)

    return CalibrationMetrics(
        ece=float(ece),
        bin_accuracies=bin_accuracies,
        bin_confidences=bin_confidences,
        bin_counts=bin_counts,
        n_bins=n_bins,
    )


def compute_latency_metrics(latencies_ms: np.ndarray | list) -> LatencyMetrics:
    """
    Compute latency percentiles from an array of latency measurements (ms).
    """
    arr = np.asarray(latencies_ms, dtype=float)
    if len(arr) == 0:
        return LatencyMetrics(
            p50=0, p95=0, p99=0, mean=0, std=0, min=0, max=0, n_samples=0
        )

    return LatencyMetrics(
        p50=float(np.percentile(arr, 50)),
        p95=float(np.percentile(arr, 95)),
        p99=float(np.percentile(arr, 99)),
        mean=float(np.mean(arr)),
        std=float(np.std(arr)),
        min=float(np.min(arr)),
        max=float(np.max(arr)),
        n_samples=len(arr),
    )


def compute_pipeline_metrics(
    y_true: np.ndarray | list,
    decisions: list[str],
    warn_is_positive: bool = False,
) -> PipelineMetrics:
    """
    Compute pipeline-level metrics from final decisions.

    Args:
        y_true:     Ground-truth (1 = malicious, 0 = benign).
        decisions:  List of "BLOCK", "WARN", or "ALLOW" strings.
        warn_is_positive: If True, WARN counts as a positive detection.
                          If False, only BLOCK counts.
    """
    y_true = np.asarray(y_true, dtype=int)
    assert len(y_true) == len(decisions)

    n_blocked = sum(1 for d in decisions if d == "BLOCK")
    n_flagged = sum(1 for d in decisions if d == "WARN")
    n_allowed = sum(1 for d in decisions if d == "ALLOW")

    # Positive = detected as attack
    if warn_is_positive:
        y_pred = np.array([1 if d in ("BLOCK", "WARN") else 0 for d in decisions])
    else:
        y_pred = np.array([1 if d == "BLOCK" else 0 for d in decisions])

    tp = int(np.sum((y_pred == 1) & (y_true == 1)))
    fp = int(np.sum((y_pred == 1) & (y_true == 0)))
    fn = int(np.sum((y_pred == 0) & (y_true == 1)))
    tn = int(np.sum((y_pred == 0) & (y_true == 0)))

    detection_rate = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    # Breakdown of WARN tier
    flagged_true_attacks = sum(
        1 for d, y in zip(decisions, y_true) if d == "WARN" and y == 1
    )
    flagged_benign = sum(
        1 for d, y in zip(decisions, y_true) if d == "WARN" and y == 0
    )

    return PipelineMetrics(
        detection_rate=detection_rate,
        false_positive_rate=fpr,
        n_blocked=n_blocked,
        n_flagged=n_flagged,
        n_allowed=n_allowed,
        n_total=len(y_true),
        flagged_true_attacks=flagged_true_attacks,
        flagged_benign=flagged_benign,
    )


# ---------------------------------------------------------------------------
# Statistical rigor (Section 6 of eval plan)
# ---------------------------------------------------------------------------

def bootstrap_ci(
    y_true: np.ndarray | list,
    y_scores: np.ndarray | list,
    metric_fn: Callable[[np.ndarray, np.ndarray], float],
    n_resamples: int = 1000,
    confidence_level: float = 0.95,
    seed: int = 42,
    groups: np.ndarray | list | None = None,
) -> BootstrapResult:
    """
    Compute bootstrap confidence interval for any metric.

    Args:
        y_true:           Ground-truth labels.
        y_scores:         Predicted scores.
        metric_fn:        Function(y_true, y_scores) -> float.
        n_resamples:      Number of bootstrap resamples (1000+ for publication).
        confidence_level: Confidence level (default 95%).
        seed:             Random seed for reproducibility.

    Returns:
        BootstrapResult with point estimate and CI bounds.
    """
    rng = np.random.RandomState(seed)
    y_true = np.asarray(y_true)
    y_scores = np.asarray(y_scores)
    n = len(y_true)

    point_estimate = metric_fn(y_true, y_scores)

    # CLUSTER bootstrap when `groups` is given (2026-09-25, R-022): resample whole groups
    # (e.g. tom-gibbs goals, each repeated over 8 cipher configs) with replacement, so
    # the CI reflects the number of independent units, not the number of rows.
    # Stratified by class: a tom-gibbs goal is entirely harmful or entirely benign, so an
    # unstratified group resample can draw one class only (AUROC undefined).
    strata = None
    if groups is not None:
        g = np.asarray(groups)
        uniq = np.unique(g)
        if 1 < len(uniq) < n:
            idx = [np.where(g == u)[0] for u in uniq]
            strata = {}
            for ix in idx:
                strata.setdefault(int(y_true[ix[0]]), []).append(ix)

    bootstrap_estimates = []
    for _ in range(n_resamples):
        if strata is not None:
            parts = []
            for gl in strata.values():
                pick = rng.randint(0, len(gl), size=len(gl))
                parts.extend(gl[k] for k in pick)
            indices = np.concatenate(parts)
        else:
            indices = rng.randint(0, n, size=n)
        try:
            val = metric_fn(y_true[indices], y_scores[indices])
            if val is not None and np.isfinite(val):
                bootstrap_estimates.append(val)
        except Exception:
            # Skip failed resamples (e.g., single-class sample)
            continue

    if not bootstrap_estimates:
        return BootstrapResult(
            point_estimate=point_estimate,
            ci_lower=point_estimate,
            ci_upper=point_estimate,
            confidence_level=confidence_level,
            n_resamples=0,
        )

    bootstrap_estimates = np.array(bootstrap_estimates)
    alpha = 1 - confidence_level
    ci_lower = float(np.percentile(bootstrap_estimates, 100 * alpha / 2))
    ci_upper = float(np.percentile(bootstrap_estimates, 100 * (1 - alpha / 2)))

    return BootstrapResult(
        point_estimate=point_estimate,
        ci_lower=ci_lower,
        ci_upper=ci_upper,
        confidence_level=confidence_level,
        n_resamples=len(bootstrap_estimates),
    )


def mcnemar_test(
    pred_a: np.ndarray | list,
    pred_b: np.ndarray | list,
    y_true: np.ndarray | list,
) -> dict:
    """
    McNemar's test for paired comparison of two classifiers.

    This is the correct test for paired classification comparison
    (Section 6 of the eval plan) — it tests whether the two classifiers
    disagree in a systematic way, not just whether their overall accuracy
    differs.

    Args:
        pred_a: Binary predictions from system A (1/0).
        pred_b: Binary predictions from system B (1/0).
        y_true: Ground-truth labels (1/0).

    Returns:
        Dict with chi2 statistic, p-value, and contingency table.
    """
    pred_a = np.asarray(pred_a, dtype=int)
    pred_b = np.asarray(pred_b, dtype=int)
    y_true = np.asarray(y_true, dtype=int)

    correct_a = (pred_a == y_true).astype(int)
    correct_b = (pred_b == y_true).astype(int)

    # Contingency table of disagreements
    # b01: A correct, B wrong
    # b10: A wrong, B correct
    b01 = int(np.sum((correct_a == 1) & (correct_b == 0)))
    b10 = int(np.sum((correct_a == 0) & (correct_b == 1)))
    b00 = int(np.sum((correct_a == 0) & (correct_b == 0)))
    b11 = int(np.sum((correct_a == 1) & (correct_b == 1)))

    # McNemar's chi-squared statistic (with continuity correction)
    denom = b01 + b10
    if denom == 0:
        chi2 = 0.0
        p_value = 1.0
    else:
        chi2 = (abs(b01 - b10) - 1) ** 2 / denom
        # Compute p-value from chi2 distribution with 1 df
        from scipy.stats import chi2 as chi2_dist
        p_value = float(1 - chi2_dist.cdf(chi2, df=1))

    return {
        "chi2": float(chi2),
        "p_value": p_value,
        "a_correct_b_wrong": b01,
        "a_wrong_b_correct": b10,
        "both_correct": b11,
        "both_wrong": b00,
        "significant_at_005": p_value < 0.05,
        "interpretation": (
            f"System A is {'significantly' if p_value < 0.05 else 'not significantly'} "
            f"different from System B (p={p_value:.4f}). "
            f"A correct where B wrong: {b01}, B correct where A wrong: {b10}."
        ),
    }


# ---------------------------------------------------------------------------
# Formatting utilities
# ---------------------------------------------------------------------------

def format_metrics_table(
    results: dict[str, ClassificationMetrics | dict],
    title: str = "Evaluation Results",
) -> str:
    """Format a dict of named metrics into a markdown table."""
    lines = [f"## {title}\n"]
    lines.append("| System | Precision | Recall | F1 | FPR | Accuracy | N |")
    lines.append("|--------|-----------|--------|----|----|----------|---|")

    for name, m in results.items():
        if isinstance(m, ClassificationMetrics):
            lines.append(
                f"| {name} | {m.precision:.4f} | {m.recall:.4f} | "
                f"{m.f1:.4f} | {m.fpr:.4f} | {m.accuracy:.4f} | {m.n_samples} |"
            )
        elif isinstance(m, dict):
            lines.append(
                f"| {name} | {m.get('precision', 0):.4f} | {m.get('recall', 0):.4f} | "
                f"{m.get('f1', 0):.4f} | {m.get('fpr', 0):.4f} | "
                f"{m.get('accuracy', 0):.4f} | {m.get('n_samples', 0)} |"
            )

    return "\n".join(lines)


def format_bootstrap_table(
    results: dict[str, dict[str, BootstrapResult]],
    title: str = "Results with 95% Bootstrap CIs",
) -> str:
    """Format bootstrap CI results into a publication-ready table."""
    lines = [f"## {title}\n"]
    lines.append("| System | Metric | Estimate | 95% CI |")
    lines.append("|--------|--------|----------|--------|")

    for name, metrics in results.items():
        for metric_name, br in metrics.items():
            lines.append(
                f"| {name} | {metric_name} | {br.point_estimate:.4f} | "
                f"[{br.ci_lower:.4f}, {br.ci_upper:.4f}] |"
            )

    return "\n".join(lines)


def save_results(results: dict, filepath: str) -> None:
    """Save evaluation results to JSON."""
    # Convert dataclass results to dicts
    def _convert(obj):
        if hasattr(obj, "to_dict"):
            return obj.to_dict()
        elif isinstance(obj, np.floating):
            return float(obj)
        elif isinstance(obj, np.integer):
            return int(obj)
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        return obj

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, default=_convert, ensure_ascii=False)
    logger.info(f"Results saved to {filepath}")
