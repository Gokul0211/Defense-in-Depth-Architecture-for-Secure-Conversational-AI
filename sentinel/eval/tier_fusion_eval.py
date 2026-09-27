"""
L1 tier-fusion evaluation — Phase 5 plan item 3B.3.

THE QUESTION
---------------
Is L1's `max()` over its four tiers costing measurable performance versus
a calibrated likelihood-ratio fusion of the same tier scores? Same inputs,
same tiers, same corpus — only the combination rule differs.

WHY THE BAR IS CROSS-CORPUS, NOT A WITHIN-CORPUS SPLIT
---------------------------------------------------------
This project has already established, twice and independently, that a
threshold or model calibrated on one corpus need not transfer to another:
Contribution D's conformal guarantee holds on Alpaca and fails on
WildJailbreak (Part E), and L2's BIPIA-calibrated operating point produces
FPR 0.9245 on sentinel_bench (plan item 3B.2). A within-corpus train/test
split would therefore report a number that this project's own prior
findings say is not the number that matters.

So the protocol is: FIT ON ONE CORPUS, EVALUATE ON ANOTHER, both
directions, and report both. A fusion rule that only wins in the direction
it was fitted has not earned a production change.

WHAT IS COMPARED
-------------------
  max            — L1's current production rule, reproduced exactly from
                   recorded tier scores by core/tier_fusion.max_fusion_score
  naive_bayes    — sum of per-tier calibrated log-LRs over AVAILABLE tiers
                   (assumes conditional independence, known false here)
  pattern_joint  — a joint model per cascade availability pattern, which
                   needs no imputation and makes no independence assumption

Metric is AUROC, deliberately: it is threshold-independent, so this
measures whether the fusion rule RANKS better, without entangling the
comparison with an operating-point choice. Operating-point selection is a
separate, already-calibrated concern (3B.1, 3B.2).

PREREGISTERED INTERPRETATION, written before running this
------------------------------------------------------------
- If the calibrated fusions beat `max` in BOTH cross-corpus directions,
  that is a real result and justifies proposing a production change.
- If they win in one direction and lose in the other, that is reported as
  a non-result: it means the fusion is fitting corpus-specific structure,
  which is the same failure Contribution D documents, and no production
  change is proposed.
- If `max` wins or ties, that is reported plainly. `max` is a legitimate
  fusion rule when one component dominates, and the judge-tier ablation
  (3B.2) showed exactly that regime — the judge alone moves sentinel_bench
  AUROC 0.8094 -> 0.9719. A null result here would be real evidence that
  L1's tiers are dominated by one signal rather than genuinely combining.

STATUS: EVAL-ONLY. Changes nothing in layer1.py.

Usage:
    python -m sentinel.eval.tier_fusion_eval
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path

from sentinel.core.tier_fusion import (
    NaiveBayesTierFusion,
    PatternJointTierFusion,
    availability_pattern,
    max_fusion_score,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

_RESULTS = Path(__file__).parent / "results"


def _auroc(scores: list[float], labels: list[int]) -> float:
    """
    Rank-based AUROC with explicit tie handling (ties get 0.5 credit).

    Written out rather than imported because `max()` fusion produces
    MASSIVE tie clusters — every Tier-1 regex hit scores exactly 0.92 —
    and a tie-blind implementation would flatter or punish the baseline
    depending on sort order. Getting this wrong would silently decide the
    experiment.
    """
    pos = [s for s, y in zip(scores, labels) if y == 1]
    neg = [s for s, y in zip(scores, labels) if y == 0]
    if not pos or not neg:
        return float("nan")
    wins = 0.0
    for p in pos:
        for n in neg:
            if p > n:
                wins += 1.0
            elif p == n:
                wins += 0.5
    return wins / (len(pos) * len(neg))


def _auroc_fast(scores, labels) -> float:
    """
    Rank-based AUROC, identical to `_auroc` but O(n log n) instead of
    O(n_pos * n_neg).

    Needed only because the bootstrap below calls it ~2000 times per
    comparison; on WildJailbreak the quadratic version is 420k
    comparisons per call, which makes CIs unaffordable and is the reason
    the first version of this eval shipped without them.

    `tests/test_tier_fusion_ci.py` pins this against `_auroc` on tie-heavy
    inputs, because the whole reason `_auroc` was written by hand is that
    `max()` fusion produces massive tie clusters and a tie-blind AUROC
    would silently decide the experiment.
    """
    import numpy as np

    scores = np.asarray(scores, dtype=float)
    labels = np.asarray(labels)
    n_pos = int((labels == 1).sum())
    n_neg = int((labels == 0).sum())
    if n_pos == 0 or n_neg == 0:
        return float("nan")

    order = np.argsort(scores, kind="mergesort")
    ranks = np.empty(len(scores), dtype=float)
    sorted_scores = scores[order]
    i = 0
    while i < len(sorted_scores):
        j = i
        while j + 1 < len(sorted_scores) and sorted_scores[j + 1] == sorted_scores[i]:
            j += 1
        # Average rank over the tie block gives ties exactly 0.5 credit,
        # matching `_auroc`.
        ranks[order[i:j + 1]] = (i + j) / 2.0 + 1.0
        i = j + 1

    return float((ranks[labels == 1].sum() - n_pos * (n_pos + 1) / 2.0) / (n_pos * n_neg))


def _paired_bootstrap_delta(
    score_a, score_b, labels, n_boot: int = 2000, seed: int = 7
) -> dict:
    """
    Percentile CI for AUROC(b) - AUROC(a) under stratified resampling of
    the TEST set, with both rules scored on the SAME resample.

    Pairing is the point. The two rules are evaluated on identical inputs,
    so their AUROCs are strongly positively correlated; independent CIs on
    each would be far too wide and would call a real difference
    inconclusive. Resampling is stratified by class so that every replicate
    keeps both classes (an unstratified bootstrap of a 210-benign corpus
    would occasionally draw zero benign and return NaN).

    The model is FIT ONCE on the training corpus and held fixed. This
    deliberately measures sampling error in the TEST corpus only — the
    question is whether this fitted rule beats max() on new data, not how
    much the fit itself would wobble. Fit variability is a separate
    question and is not claimed here.
    """
    import numpy as np

    rng = np.random.default_rng(seed)
    score_a = np.asarray(score_a, dtype=float)
    score_b = np.asarray(score_b, dtype=float)
    labels = np.asarray(labels)
    pos_idx = np.flatnonzero(labels == 1)
    neg_idx = np.flatnonzero(labels == 0)
    if len(pos_idx) == 0 or len(neg_idx) == 0:
        return {"error": "single-class test set"}

    deltas = np.empty(n_boot, dtype=float)
    for b in range(n_boot):
        idx = np.concatenate([
            rng.choice(pos_idx, size=len(pos_idx), replace=True),
            rng.choice(neg_idx, size=len(neg_idx), replace=True),
        ])
        lab = labels[idx]
        deltas[b] = _auroc_fast(score_b[idx], lab) - _auroc_fast(score_a[idx], lab)

    lo, hi = np.percentile(deltas, [2.5, 97.5])
    return {
        "delta_mean": round(float(deltas.mean()), 4),
        "ci95_lo": round(float(lo), 4),
        "ci95_hi": round(float(hi), 4),
        # `p_not_better` and `p_worse` are reported SEPARATELY because on a
        # corpus where max() is already near-perfect they say very
        # different things. On sentinel_bench the fusion reaches AUROC
        # 1.0000, so many replicates contain no pair that max() ranks
        # wrongly and the delta is exactly 0 — a TIE, not a loss. Collapsing
        # ties and losses into one number would report that case as "5% of
        # the time the fusion was not better", which reads as evidence
        # against a rule that in fact never once ranked worse.
        "p_not_better": round(float((deltas <= 0).mean()), 4),
        "p_worse": round(float((deltas < 0).mean()), 4),
        "delta_min": round(float(deltas.min()), 4),
        "n_boot": n_boot,
        "excludes_zero": bool(lo > 0 or hi < 0),
        "never_worse": bool(deltas.min() >= 0),
    }


def _fit_variability(
    train_rows: list[dict], train_labels: list[int],
    test_rows: list[dict], test_labels: list[int],
    n_refits: int | None = None, seed: int = 23,
) -> dict:
    """
    How much does the RESULT move if the model had been fitted on a
    different sample of the same size?

    `_paired_bootstrap_delta` resamples the TEST set with the model held
    fixed, so it answers "does this fitted rule beat max() on new data".
    It says nothing about the fit itself — and the production artifact is
    fitted on 112 samples, where that is the obvious objection. This
    resamples the TRAINING corpus (stratified, with replacement), refits
    from scratch, and scores the FIXED test set each time.

    The number that carries the claim is `frac_refits_beating_max`: if a
    rule refitted on 200 different draws of the training data beats max()
    every time on a held-out corpus, the advantage is not an artifact of
    one lucky fit.

    `n_refits` defaults by training-corpus size because a refit costs
    ~0.25s at n=112 and ~5s at n=2,210, and the small-train direction is
    both the cheaper one and the one carrying the headline transfer result.
    """
    import numpy as np

    if n_refits is None:
        n_refits = 200 if len(train_rows) <= 500 else 40

    rng = np.random.default_rng(seed)
    y_train = np.asarray(train_labels)
    pos_idx = np.flatnonzero(y_train == 1)
    neg_idx = np.flatnonzero(y_train == 0)
    if len(pos_idx) == 0 or len(neg_idx) == 0:
        return {"error": "single-class training set"}

    baseline = _auroc_fast([max_fusion_score(r) for r in test_rows], test_labels)

    aurocs, degenerate = [], 0
    for _ in range(n_refits):
        idx = np.concatenate([
            rng.choice(pos_idx, size=len(pos_idx), replace=True),
            rng.choice(neg_idx, size=len(neg_idx), replace=True),
        ])
        rows = [train_rows[i] for i in idx]
        labels = [train_labels[i] for i in idx]
        model = PatternJointTierFusion().fit(rows, labels)
        # A resample can leave a cascade pattern with fewer than
        # min_samples rows, in which case that pattern degrades to its base
        # rate. That is the model behaving as designed under a thin fit, not
        # an error, but it is counted so the rate is visible.
        if not model.models:
            degenerate += 1
        aurocs.append(_auroc_fast([model.score(r) for r in test_rows], test_labels))

    arr = np.asarray(aurocs, dtype=float)
    return {
        "n_refits": n_refits,
        "max_baseline_auroc": round(float(baseline), 4),
        "auroc_mean": round(float(arr.mean()), 4),
        "auroc_sd": round(float(arr.std(ddof=1)), 4),
        "auroc_p05": round(float(np.percentile(arr, 5)), 4),
        "auroc_p95": round(float(np.percentile(arr, 95)), 4),
        "auroc_min": round(float(arr.min()), 4),
        "frac_refits_beating_max": round(float((arr > baseline).mean()), 4),
        "refits_with_no_joint_model": degenerate,
    }


def load_corpus(result_file: Path) -> tuple[list[dict], list[int], str]:
    """Pull (tier_scores, label) pairs out of a saved L1 eval result."""
    data = json.loads(result_file.read_text(encoding="utf-8"))
    rows, labels = [], []
    skipped = 0
    for sample in data["per_sample"]:
        tier_scores = sample.get("tier_scores")
        if not tier_scores:
            skipped += 1
            continue
        rows.append(tier_scores)
        labels.append(1 if sample["label"] == "malicious" else 0)
    if skipped:
        logger.warning(
            f"{result_file.name}: {skipped} samples had no tier_scores and were skipped "
            f"(pre-Stage--1 result file?)"
        )
    return rows, labels, data["meta"].get("dataset", result_file.stem)


def describe(rows: list[dict], labels: list[int], name: str) -> dict:
    from collections import Counter

    patterns = Counter(availability_pattern(r) for r in rows)
    return {
        "corpus": name,
        "n": len(rows),
        "n_malicious": sum(labels),
        "n_benign": len(labels) - sum(labels),
        "availability_patterns": {"+".join(k) if k else "(none)": v for k, v in patterns.items()},
    }


def evaluate_pair(train: tuple, test: tuple) -> dict:
    train_rows, train_labels, train_name = train
    test_rows, test_labels, test_name = test

    nb = NaiveBayesTierFusion().fit(train_rows, train_labels)
    pj = PatternJointTierFusion().fit(train_rows, train_labels)

    scored = {
        "max": [max_fusion_score(r) for r in test_rows],
        "naive_bayes": [nb.score(r) for r in test_rows],
        "pattern_joint": [pj.score(r) for r in test_rows],
    }

    results = {
        "fit_on": train_name,
        "evaluated_on": test_name,
        "n_train": len(train_rows),
        "n_test": len(test_rows),
        "auroc": {k: _auroc_fast(v, test_labels) for k, v in scored.items()},
    }
    results["delta_vs_max"] = {
        k: results["auroc"][k] - results["auroc"]["max"]
        for k in ("naive_bayes", "pattern_joint")
    }
    # Paired bootstrap CI on each delta. Without this, a +0.0281 delta on a
    # 112-sample corpus and a +0.0969 delta on a 2210-sample one look like
    # the same kind of evidence, and they are not.
    results["delta_ci95"] = {
        k: _paired_bootstrap_delta(scored["max"], scored[k], test_labels)
        for k in ("naive_bayes", "pattern_joint")
    }
    # Sensitivity of the pattern_joint result to the TRAINING sample, which
    # the CI above deliberately holds fixed. Only pattern_joint, because
    # that is the rule proposed for production.
    results["pattern_joint_fit_variability"] = _fit_variability(
        train_rows, train_labels, test_rows, test_labels
    )
    return results


def run_tier_fusion_evaluation(result_files: list[Path]) -> dict:
    corpora = [load_corpus(f) for f in result_files]

    # A corpus with only one class cannot fit a calibration and cannot be
    # scored with AUROC. TensorTrust is malicious-only (570/570), so
    # including it produced rows reading `naive_bayes=0.5000` against
    # `max=0.8094` — which looks like the fusion losing badly and is
    # actually just an undefined comparison. Excluded explicitly and
    # loudly, rather than left to surface as a spurious negative result.
    usable = []
    for rows, labels, name in corpora:
        if not rows:
            continue
        if len(set(labels)) < 2:
            logger.warning(
                f"excluding corpus {name!r}: single-class "
                f"({sum(labels)} malicious / {len(labels) - sum(labels)} benign) — "
                f"cannot fit a calibration or compute AUROC"
            )
            continue
        usable.append((rows, labels, name))
    if len(usable) < 2:
        raise SystemExit(
            "Need at least two corpora with recorded tier_scores. Re-run "
            "`python -m sentinel.eval.runner --layer L1 --dataset <name>` on "
            "current code (tier_scores are only persisted post-Stage--1)."
        )

    out = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "corpora": [describe(r, l, n) for r, l, n in usable],
        "cross_corpus": [],
        "within_corpus_reference": [],
    }

    for i, a in enumerate(usable):
        for j, b in enumerate(usable):
            if i == j:
                # Fit and evaluate on the same corpus. Reported ONLY as a
                # reference point and explicitly NOT as evidence — it is
                # optimistically biased, and this section exists so the
                # size of that bias is visible next to the honest numbers.
                out["within_corpus_reference"].append(evaluate_pair(a, a))
            else:
                out["cross_corpus"].append(evaluate_pair(a, b))

    return out


def _log_table(results: dict) -> None:
    for corpus in results["corpora"]:
        logger.info(
            f"corpus {corpus['corpus']}: n={corpus['n']} "
            f"({corpus['n_malicious']} mal / {corpus['n_benign']} ben)  "
            f"patterns={corpus['availability_patterns']}"
        )
    for section in ("cross_corpus", "within_corpus_reference"):
        logger.info(f"--- {section} ---")
        for row in results[section]:
            a = row["auroc"]
            logger.info(
                f"  fit={row['fit_on']:<16} eval={row['evaluated_on']:<16} "
                f"n_test={row['n_test']:<5} max={a['max']:.4f}"
            )
            for rule in ("naive_bayes", "pattern_joint"):
                ci = row.get("delta_ci95", {}).get(rule, {})
                band = (f"[{ci['ci95_lo']:+.4f}, {ci['ci95_hi']:+.4f}] "
                        f"p_worse={ci['p_worse']:.3f} "
                        f"p_tie_or_worse={ci['p_not_better']:.3f} "
                        f"min={ci['delta_min']:+.4f}"
                        if "ci95_lo" in ci else "(no CI)")
                logger.info(
                    f"      {rule:<14} {a[rule]:.4f} "
                    f"({row['delta_vs_max'][rule]:+.4f})  CI95 {band}"
                )
            fv = row.get("pattern_joint_fit_variability", {})
            if "auroc_mean" in fv:
                logger.info(
                    f"      fit-variability ({fv['n_refits']} refits on resampled train): "
                    f"AUROC {fv['auroc_mean']:.4f} +/- {fv['auroc_sd']:.4f} "
                    f"[p05 {fv['auroc_p05']:.4f}, p95 {fv['auroc_p95']:.4f}] "
                    f"min {fv['auroc_min']:.4f}  "
                    f"beat_max in {fv['frac_refits_beating_max']:.1%}"
                )


def _log_to_ledger(results: dict, chosen: list[Path], out_path: Path,
                   runtime_seconds: float) -> None:
    """
    Record this run in the append-only ledger.

    There is no git repo here, so the ledger is the only thing tying a
    cited number to the code and data that produced it. Every number this
    script emits is destined for the paper, so a run that is not logged is
    a number that cannot be defended.
    """
    from sentinel.eval.results_ledger import code_files_for, safe_append_entry

    safe_append_entry(
        experiment_id=f"tier_fusion_cross_corpus_{datetime.now():%Y%m%d_%H%M%S}",
        phase="Phase 5 / 3B.3",
        code_files=code_files_for(
            "sentinel/core/tier_fusion.py",
            "sentinel/eval/tier_fusion_eval.py",
            "sentinel/layers/layer1.py",
        ),
        dataset_cache_file=str(chosen[0]) if chosen else "",
        split="cross-corpus: fit on one corpus, evaluate on the other, both directions",
        thresholds_used={"metric": "AUROC (threshold-free)"},
        metrics={
            "corpora": results["corpora"],
            "cross_corpus": results["cross_corpus"],
            "within_corpus_reference": results["within_corpus_reference"],
        },
        result_file=str(out_path),
        runtime_seconds=round(runtime_seconds, 1),
        seed=7,
        notes=(
            "Paired bootstrap CI on the AUROC delta (test resampled, model fixed) "
            "plus fit-variability refits (training corpus resampled, test fixed). "
            "Source files selected by RICHEST TIER COVERAGE, not recency: "
            f"{[p.name for p in chosen]}"
        ),
    )


def main() -> None:
    import time

    started = time.monotonic()
    candidates = sorted(_RESULTS.glob("eval_L1_*.json"))
    with_tiers = []
    for path in candidates:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if any(s.get("tier_scores") for s in data.get("per_sample", [])):
            with_tiers.append(path)

    # One run per dataset, chosen by RICHEST TIER COVERAGE — not by recency.
    #
    # BUG FIX (2026-09-18): this selected the most recent run per dataset,
    # which silently picked `eval_L1_sentinel_bench_20260918_192935.json` —
    # the judge-DISABLED ablation run, with tier4 present on 0/112 samples
    # — over the judge-enabled run from eight minutes earlier (72/112).
    # Fitting on a corpus that has never observed the judge tier and then
    # evaluating on WildJailbreak, where 988/2210 samples DO have it,
    # produced a 7.2-point "cross-corpus transfer failure" that was really
    # a missing-tier artifact of file selection. Recency is the wrong
    # criterion: an ablation run is a deliberately degraded measurement of
    # the same corpus, not a fresher one.
    best: dict[str, tuple[int, Path]] = {}
    for path in with_tiers:
        data = json.loads(path.read_text(encoding="utf-8"))
        dataset = data["meta"].get("dataset", path.stem)
        coverage = sum(
            1
            for sample in data.get("per_sample", [])
            for key, value in (sample.get("tier_scores") or {}).items()
            if value is not None
        )
        if dataset not in best or coverage > best[dataset][0]:
            best[dataset] = (coverage, path)
    chosen = [path for _, path in best.values()]
    for dataset, (coverage, path) in best.items():
        logger.info(f"  {dataset}: using {path.name} (tier-score coverage {coverage})")

    logger.info(f"Using {len(chosen)} corpora with recorded tier scores: "
                f"{[p.name for p in chosen]}")
    results = run_tier_fusion_evaluation(chosen)
    _log_table(results)

    _RESULTS.mkdir(exist_ok=True)
    out_path = _RESULTS / f"eval_tier_fusion_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    out_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    logger.info(f"Results saved to {out_path}")
    _log_to_ledger(results, chosen, out_path, time.monotonic() - started)


if __name__ == "__main__":
    main()
