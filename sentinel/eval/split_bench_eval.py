"""
SPLIT-Bench evaluation — does score fusion recover what threshold fusion
provably cannot? (Contribution E, Propositions 1 and 2, measured.)

THE EXPERIMENT
-----------------
SPLIT-Bench samples carry a machine-checked certificate: every layer score
is at least `epsilon` BELOW that layer's threshold, and at least k layers
carry score >= theta_lo. Matched benign controls have the identical
structural shell and are likewise certified sub-threshold on every layer.

That construction makes the first result analytic rather than empirical:
ANY rule of the form "alarm iff some layer crosses its threshold" fires on
exactly zero malicious samples AND zero benign ones. Its TPR is 0 and its
AUROC is undefined (every sample maps to the same decision). This is
Proposition 1 with nothing left to measure, and it is reported as an
anchor, not as a finding.

The empirical question is Proposition 2: does the EVIDENCE survive in the
scores even though it does not survive the thresholds? Three rules are
compared on the same certified layer-score vectors:

    max_layer    — max_i s_i. The strongest threshold-free reading of the
                   CURRENT architecture, and the baseline that actually
                   matters. If this separates the classes, the problem is
                   purely where the threshold sits, and no fusion rule is
                   needed.
    mean_layer   — mean_i s_i. An unweighted, unfitted aggregate. Included
                   because it needs no training at all, so a win here
                   would mean the calibrated model is unnecessary.
    logistic_fusion — a fitted linear combination of the layer scores,
                   scored OUT OF FOLD (see below).

WHY OUT-OF-FOLD AND NOT A SINGLE SPLIT
-----------------------------------------
There is no second SPLIT-Bench corpus to transfer to, so the cross-corpus
protocol used for tier fusion (`tier_fusion_eval.py`) is unavailable here.
Stratified k-fold with OUT-OF-FOLD scoring is used instead: every sample is
scored by a model that never saw it, and the AUROC is computed once on the
pooled out-of-fold scores. A single fit evaluated on its own training data
would report a number this project has twice established is not the number
that matters.

WHAT THIS RESULT CANNOT CLAIM
--------------------------------
SPLIT-Bench is SYNTHETIC and its attack fragments are drawn from small,
individually-measured ladders. A fusion rule fitted on it could in
principle be learning the generator rather than the phenomenon. Two things
bound that risk and neither eliminates it:

  * the benign controls share the exact structural shell (same document
    block, same turn count, same tool call drawn from the same pool), so
    the classes are not separable on shape; and
  * the rules compared here consume ONLY the five layer scores, never the
    text, so there is no lexical artifact for them to memorise.

What remains is that the layer scores themselves are a function of this
generator's fragments. The honest reading of a positive result is
therefore: "within the sub-threshold regime, the layer scores retain
recoverable joint evidence" — a statement about SENTINEL's score outputs,
NOT a measured detection rate against real distributed adversaries. That
distinction must survive into the paper.

Usage:
    python -m sentinel.eval.split_bench_eval
"""

from __future__ import annotations

import json
import logging
from collections import Counter
from datetime import datetime
from pathlib import Path

from sentinel.eval.split_bench import ALL_LAYERS, _DATA_DIR
from sentinel.eval.tier_fusion_eval import _auroc_fast, _paired_bootstrap_delta

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

_RESULTS = Path(__file__).parent / "results"


DATA_DIR = _DATA_DIR      # overridable by --data-dir (SPLIT-Bench v2)


def load_split_bench() -> list[dict]:
    path = DATA_DIR / "all.jsonl"
    if not path.exists():
        raise SystemExit(
            f"{path} not found. Generate it first:\n"
            f"    python -m sentinel.eval.split_bench --per-bucket 40"
        )
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def _vectors(samples: list[dict]) -> tuple[list[list[float]], list[int]]:
    """
    Pull each sample's certified layer-score vector and label.

    The scores come from the CERTIFICATE rather than being recomputed, so
    the vectors evaluated here are provably the same ones the certificate
    was checked against. Recomputing would open a gap between what was
    certified and what was measured.
    """
    X, y = [], []
    for s in samples:
        scores = s["metadata"]["certificate"]["measured_scores"]
        X.append([float(scores.get(layer, 0.0)) for layer in ALL_LAYERS])
        y.append(1 if s["label"] == "malicious" else 0)
    return X, y


def threshold_fusion_anchor(samples: list[dict]) -> dict:
    """
    The analytic anchor: what the real pipeline actually did.

    Uses the recorded `pipeline_decision` / `correlation_fired` from
    generation time — the live decision rule and the live correlation
    engine — rather than re-deriving them, so this reports SENTINEL's
    behaviour and not this file's model of it.
    """
    mal = [s for s in samples if s["label"] == "malicious"]
    ben = [s for s in samples if s["label"] == "benign"]

    def summarise(rows):
        decisions = Counter(r["metadata"].get("pipeline_decision") for r in rows)
        fired = sum(1 for r in rows if r["metadata"].get("correlation_fired"))
        alarmed = sum(1 for r in rows
                      if r["metadata"].get("pipeline_decision") in ("BLOCK", "WARN"))
        return {
            "n": len(rows),
            "decisions": dict(decisions),
            "correlation_fired": fired,
            "alarm_rate": round(alarmed / len(rows), 4) if rows else None,
        }

    return {"malicious": summarise(mal), "benign": summarise(ben)}


def _fit_logistic(X: list[list[float]], y: list[int], l2: float = 1.0,
                  iters: int = 4000, lr: float = 0.5) -> list[float]:
    """
    Plain L2-regularised logistic regression, weights + intercept.

    Written out rather than pulled from scikit-learn for the same reason
    `tier_fusion._fit_logistic_1d` is: the classes here can be close to
    linearly separable on a small corpus, where an unregularised fit
    diverges. The L2 penalty is part of the estimator, not a knob tuned
    against the test numbers.
    """
    import numpy as np

    Xa = np.asarray(X, dtype=float)
    ya = np.asarray(y, dtype=float)
    n, d = Xa.shape
    w = np.zeros(d)
    b = 0.0
    for _ in range(iters):
        z = np.clip(Xa @ w + b, -30, 30)
        p = 1.0 / (1.0 + np.exp(-z))
        err = p - ya
        w -= lr * ((Xa.T @ err) / n + l2 * w / n)
        b -= lr * (err.mean())
    return [*w.tolist(), b]


def _apply(weights: list[float], row: list[float]) -> float:
    return sum(wi * xi for wi, xi in zip(weights[:-1], row)) + weights[-1]


def out_of_fold_scores(X: list[list[float]], y: list[int], n_folds: int = 5,
                       seed: int = 11) -> tuple[list[float], list[dict]]:
    """
    Stratified k-fold, returning one score per sample from the fold that
    did NOT train on it, plus the per-fold weights for inspection.
    """
    import numpy as np

    rng = np.random.default_rng(seed)
    y_arr = np.asarray(y)
    folds = np.empty(len(y), dtype=int)
    for cls in (0, 1):
        idx = np.flatnonzero(y_arr == cls)
        rng.shuffle(idx)
        folds[idx] = np.arange(len(idx)) % n_folds

    oof = [0.0] * len(y)
    per_fold = []
    for f in range(n_folds):
        train = [i for i in range(len(y)) if folds[i] != f]
        test = [i for i in range(len(y)) if folds[i] == f]
        if not test or len({y[i] for i in train}) < 2:
            continue
        w = _fit_logistic([X[i] for i in train], [y[i] for i in train])
        for i in test:
            oof[i] = _apply(w, X[i])
        per_fold.append({
            "fold": f, "n_train": len(train), "n_test": len(test),
            "weights": {layer: round(wi, 4) for layer, wi in zip(ALL_LAYERS, w[:-1])},
            "intercept": round(w[-1], 4),
        })
    return oof, per_fold


def _tpr_at_fpr(scores: list[float], labels: list[int], max_fpr: float = 0.05) -> float:
    """
    Highest TPR achievable while keeping FPR <= max_fpr.

    Reported alongside AUROC because AUROC is a ranking summary over all
    operating points, and a guardrail only ever runs at one — a rule can
    win on AUROC while being useless at the low-FPR end that matters.
    """
    pos = sorted((s for s, l in zip(scores, labels) if l == 1))
    neg = sorted((s for s, l in zip(scores, labels) if l == 0))
    if not pos or not neg:
        return float("nan")
    best = 0.0
    for t in sorted(set(scores)):
        fpr = sum(1 for s in neg if s >= t) / len(neg)
        if fpr <= max_fpr:
            best = max(best, sum(1 for s in pos if s >= t) / len(pos))
    return best


def single_layer_diagnostics(X: list[list[float]], y: list[int]) -> dict:
    """
    Per-layer AUROC, and the best single layer.

    THIS IS THE CIRCULARITY CHECK, and it exists because the first run of
    this evaluation reported AUROC 1.0000 for an UNTRAINED `mean_layer`
    rule — a perfect score from a rule with no parameters, which is a
    result about the generator rather than about fusion. The cause was
    visible only at the per-layer level: L2 scored exactly 0.0000 on all 80
    benign samples and 0.20-0.41 on 61/80 malicious ones, making it a
    presence/absence class indicator.

    So the harness now reports the quantity that would have caught it.
    If the best SINGLE layer already separates the classes, no fusion rule
    can earn credit on this bench, and any headline number is measuring the
    generator's fragment pools.
    """
    per_layer = {}
    for i, layer in enumerate(ALL_LAYERS):
        column = [row[i] for row in X]
        per_layer[layer] = {
            "auroc": round(_auroc_fast(column, y), 4),
            "n_distinct_values": len(set(column)),
            "n_nonzero_benign": sum(1 for c, label in zip(column, y) if label == 0 and c > 0),
            "n_nonzero_malicious": sum(1 for c, label in zip(column, y) if label == 1 and c > 0),
        }
    best = max(per_layer, key=lambda L: per_layer[L]["auroc"])
    return {
        "per_layer": per_layer,
        "best_single_layer": best,
        "best_single_layer_auroc": per_layer[best]["auroc"],
        # A layer that is zero for one entire class is an indicator
        # variable, not a graded detector, and will dominate any aggregate.
        "layers_zero_on_all_benign": [
            L for L, s in per_layer.items() if s["n_nonzero_benign"] == 0
        ],
        "layers_zero_on_all_malicious": [
            L for L, s in per_layer.items() if s["n_nonzero_malicious"] == 0
        ],
    }


def evaluate(samples: list[dict]) -> dict:
    X, y = _vectors(samples)
    if len(set(y)) < 2:
        raise SystemExit("SPLIT-Bench has only one class; regenerate with benign controls")

    rules = {
        # Best single layer and the two parameter-free aggregates are all
        # reported, because the claim "fusion helps" only survives if the
        # fitted rule beats ALL of them. `mean_layer` in particular needs no
        # training at all, so if it matches the fitted rule then the fitted
        # rule is unnecessary here whatever its absolute AUROC.
        "max_layer": [max(row) for row in X],
        "mean_layer": [sum(row) / len(row) for row in X],
    }
    oof, per_fold = out_of_fold_scores(X, y)
    rules["logistic_fusion_oof"] = oof

    out = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "n": len(y),
        "n_malicious": sum(y),
        "n_benign": len(y) - sum(y),
        "layers_scored": list(ALL_LAYERS),
        "threshold_fusion_anchor": threshold_fusion_anchor(samples),
        "single_layer_diagnostics": single_layer_diagnostics(X, y),
        "rules": {},
        "fold_weights": per_fold,
    }
    for name, scores in rules.items():
        out["rules"][name] = {
            "auroc": round(_auroc_fast(scores, y), 4),
            "tpr_at_fpr_05": round(_tpr_at_fpr(scores, y, 0.05), 4),
            "tpr_at_fpr_10": round(_tpr_at_fpr(scores, y, 0.10), 4),
        }

    # The comparison that carries the claim: the fitted fusion against the
    # best threshold-free reading of the current architecture.
    out["delta_vs_max_layer"] = {
        name: _paired_bootstrap_delta(rules["max_layer"], rules[name], y)
        for name in ("mean_layer", "logistic_fusion_oof")
    }

    # Per-bucket AUROC. k=3 samples carry more vectors than k=2, so if the
    # fusion is genuinely aggregating evidence its advantage should GROW
    # with k. If it does not, the mechanism claimed is not the mechanism
    # operating, and that is worth knowing even when the pooled number
    # looks good.
    for k in (2, 3):
        idx = [i for i, s in enumerate(samples)
               if s["label"] == "benign" or s["metadata"]["k_intended"] == k]
        if len({y[i] for i in idx}) < 2:
            continue
        y_k = [y[i] for i in idx]
        out[f"bucket_k{k}"] = {
            "n": len(idx),
            "n_malicious": sum(y_k),
            "auroc": {
                name: round(_auroc_fast([rules[name][i] for i in idx], y_k), 4)
                for name in rules
            },
            # Per-bucket CIs, because the k-trend IS the mechanism claim —
            # fusion should help more where there is more evidence to
            # aggregate — and a trend across two buckets of 40 malicious
            # samples each is exactly the kind of thing that looks real and
            # is noise. Without these the trend must not be asserted.
            "delta_vs_max_layer": {
                name: _paired_bootstrap_delta(
                    [rules["max_layer"][i] for i in idx],
                    [rules[name][i] for i in idx],
                    y_k,
                )
                for name in ("mean_layer", "logistic_fusion_oof")
            },
        }
    return out


def deployed_fusion_readout(samples: list[dict]) -> dict | None:
    """The DEPLOYED fusion alarm (core/pipeline_fusion.py), frozen before SPLIT-Bench was
    seen: recall at its benign-calibrated WARN anchor, false-alarm rate on SPLIT's benign
    shell, AUROC. Reads `fused_probability` recorded at generation (v2) -- the same number
    the live decision rule computed -- so no refit, no threshold picked on this corpus."""
    from sentinel.core.pipeline_fusion import load
    art = load()
    rows = [s for s in samples if s["metadata"].get("fused_probability") is not None]
    if art is None or not rows:
        return None
    tau = float(art["tau_warn"])
    mal = [s["metadata"]["fused_probability"] for s in rows if s["label"] == "malicious"]
    ben = [s["metadata"]["fused_probability"] for s in rows if s["label"] == "benign"]
    out = {"tau_warn": tau, "calibrated_on": art.get("calibrated_on"),
           "recall_at_warn": sum(p >= tau for p in mal) / len(mal) if mal else None,
           "split_benign_fpr_at_warn": sum(p >= tau for p in ben) / len(ben) if ben else None,
           "n_malicious": len(mal), "n_benign": len(ben)}
    if mal and ben:
        out["auroc"] = _auroc_fast(mal + ben, [1] * len(mal) + [0] * len(ben))
    return out


def main() -> None:
    import argparse
    import time

    global DATA_DIR
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", default=None, help="e.g. sentinel/eval/data/split_bench_v2")
    args = ap.parse_args()
    if args.data_dir:
        DATA_DIR = Path(args.data_dir)

    started = time.monotonic()
    samples = load_split_bench()
    result = evaluate(samples)
    result["data_dir"] = str(DATA_DIR)
    dep = deployed_fusion_readout(samples)
    if dep is not None:
        result["deployed_fusion"] = dep
        logger.info(f"--- DEPLOYED fusion alarm (frozen, benign-calibrated) --- {dep}")

    anchor = result["threshold_fusion_anchor"]
    logger.info(f"SPLIT-Bench n={result['n']} "
                f"({result['n_malicious']} mal / {result['n_benign']} ben)")
    logger.info("--- threshold fusion (the live pipeline) ---")
    for cls in ("malicious", "benign"):
        a = anchor[cls]
        logger.info(f"  {cls:<10} n={a['n']:<4} alarm_rate={a['alarm_rate']} "
                    f"correlation_fired={a['correlation_fired']} decisions={a['decisions']}")
    logger.info("--- score fusion ---")
    for name, r in result["rules"].items():
        logger.info(f"  {name:<22} AUROC={r['auroc']:.4f}  "
                    f"TPR@FPR<=0.05={r['tpr_at_fpr_05']:.4f}  "
                    f"TPR@FPR<=0.10={r['tpr_at_fpr_10']:.4f}")
    for name, ci in result["delta_vs_max_layer"].items():
        if "ci95_lo" in ci:
            logger.info(f"  {name} vs max_layer: {ci['delta_mean']:+.4f} "
                        f"CI95 [{ci['ci95_lo']:+.4f}, {ci['ci95_hi']:+.4f}] "
                        f"p_worse={ci['p_worse']:.3f}")
    for k in (2, 3):
        b = result.get(f"bucket_k{k}")
        if not b:
            continue
        logger.info(f"  bucket k={k} (n_mal={b['n_malicious']}): {b['auroc']}")
        for name, ci in b["delta_vs_max_layer"].items():
            if "ci95_lo" in ci:
                logger.info(
                    f"      {name} vs max_layer: {ci['delta_mean']:+.4f} "
                    f"CI95 [{ci['ci95_lo']:+.4f}, {ci['ci95_hi']:+.4f}] "
                    f"p_worse={ci['p_worse']:.3f}"
                )

    # Circularity check, printed LAST so it is the reader's final
    # impression. A perfect score from an untrained rule, or a single layer
    # that is zero across an entire class, means the headline number is a
    # property of the generator and must not be cited as a detection rate.
    diag = result["single_layer_diagnostics"]
    logger.info("--- circularity check ---")
    for layer, s in diag["per_layer"].items():
        logger.info(f"  {layer} AUROC={s['auroc']:.4f} "
                    f"distinct={s['n_distinct_values']:<4} "
                    f"nonzero ben/mal={s['n_nonzero_benign']}/{s['n_nonzero_malicious']}")
    logger.info(f"  best single layer: {diag['best_single_layer']} "
                f"AUROC={diag['best_single_layer_auroc']:.4f}")
    warnings = []
    if diag["layers_zero_on_all_benign"]:
        warnings.append(
            f"layers zero on ALL benign (presence/absence indicators): "
            f"{diag['layers_zero_on_all_benign']}"
        )
    if result["rules"]["mean_layer"]["auroc"] >= 0.999:
        warnings.append(
            "UNTRAINED mean_layer reaches AUROC >= 0.999 — the bench is "
            "separable without any fitted model, so no fusion result here "
            "is evidence about fusion"
        )
    if diag["best_single_layer_auroc"] >= 0.999:
        warnings.append(
            f"a SINGLE layer ({diag['best_single_layer']}) already separates "
            f"the classes perfectly — fusion cannot earn credit on this bench"
        )
    for w in warnings:
        logger.warning(f"  CIRCULARITY: {w}")
    if not warnings:
        logger.info("  no circularity flags raised")
    result["circularity_warnings"] = warnings

    _RESULTS.mkdir(exist_ok=True)
    out_path = _RESULTS / f"eval_split_bench_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    logger.info(f"Results saved to {out_path}")

    from sentinel.eval.results_ledger import code_files_for, safe_append_entry

    safe_append_entry(
        experiment_id=f"split_bench_eval_{datetime.now():%Y%m%d_%H%M%S}",
        phase="Phase 5 / Contribution G",
        code_files=code_files_for(
            "sentinel/eval/split_bench_eval.py",
            "sentinel/eval/split_bench.py",
            "sentinel/eval/tier_fusion_eval.py",
        ),
        dataset_cache_file=str(DATA_DIR / "all.jsonl"),
        split="stratified 5-fold, out-of-fold scoring for the fitted rule",
        thresholds_used={"metric": "AUROC + TPR@FPR<=0.05"},
        metrics={
            "threshold_fusion_anchor": result["threshold_fusion_anchor"],
            "rules": result["rules"],
            "delta_vs_max_layer": result["delta_vs_max_layer"],
            "bucket_k2": result.get("bucket_k2"),
            "bucket_k3": result.get("bucket_k3"),
            "single_layer_diagnostics": result["single_layer_diagnostics"],
            "circularity_warnings": result["circularity_warnings"],
        },
        result_file=str(out_path),
        runtime_seconds=round(time.monotonic() - started, 1),
        seed=11,
        notes=(
            "Threshold-fusion anchor is the LIVE pipeline decision recorded at "
            "generation time, not a re-derivation. `circularity_warnings` must be "
            "read before citing any AUROC here: a perfect score from an untrained "
            "rule is a statement about the generator, not about fusion."
        ),
    )


if __name__ == "__main__":
    main()
