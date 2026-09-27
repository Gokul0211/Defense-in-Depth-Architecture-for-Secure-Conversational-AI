"""
Contribution F — cross-layer e-value fusion, evaluated.

THE CLAIM BEING TESTED
-------------------------
SENTINEL currently decides "is this an attack" by thresholding each layer
and then applying hand-written correlation rules over the booleans. Both
halves throw evidence away (Contribution E, Proposition 1). Contribution F
replaces them with one rule: calibrate each layer's score into an e-value
against BENIGN data only, merge across layers, and alarm when the merged
e-value reaches 1/alpha — at which point Ville's inequality bounds the
false-alarm probability by alpha, with no distributional assumption and no
attack model.

Three things make that worth measuring rather than asserting:

  * the calibration uses benign data only, so nothing is fitted to a
    malicious corpus and nothing has to transfer across corpora;
  * `merge_evalues(method="mean")` is valid under ARBITRARY dependence,
    which matters because the layers ARE dependent on real corpora —
    measured here per corpus rather than assumed, because it does not hold
    uniformly (Phase 4 benign e-values: L1-L3 r = +0.9487; SPLIT-Bench:
    +0.1083). The product form is more powerful and needs independence, so
    it is reported only to price that assumption; and
  * the bound is on the FALSE-ALARM side, so it is checkable: if the
    measured benign alarm rate exceeds alpha, the construction is wrong.

WHAT IS AND IS NOT MEASURED HERE
-----------------------------------
MEASURED: the cross-layer merge, as a single-step e-value test per sample,
against (a) threshold fusion and (b) the real hand-written correlation
rules, on two corpora.

NOT MEASURED: the sequential, anytime-valid part. `EProcess` and
`MixtureEDetector` accumulate across TURNS, and that needs per-turn layer
scores which `pipeline_sim` does not currently expose — it reports a max
over turns. So the detection-delay and change-point claims are NOT
evidenced by this file and must not be cited from it. Stated here rather
than left for a reviewer to notice.

LEAKAGE CONTROL
------------------
Each layer's e-value calibration is an empirical benign tail, so the benign
samples used to CALIBRATE must be disjoint from those used to MEASURE the
false-alarm rate — otherwise every benign sample is being compared against
a distribution that contains it, and the guarantee check is circular.
LEAVE-ONE-OUT over the benign set: each benign sample's e-values are
calibrated from the other n-1, and malicious samples from all n. Leak-free
in both directions, and it maximises the calibration size — which turned
out to be the binding constraint (below).

THE BINDING CONSTRAINT IS CALIBRATION SIZE, NOT DETECTION POWER
------------------------------------------------------------------
Found on the first run and quantified rather than worked around. The
empirical p-value has a floor of 1/(n+1), so a single layer's e-value is
capped at `kappa * (n+1)**(1-kappa)` — and because the mean merge is an
AVERAGE, the merged value is capped at the same number however many layers
agree. If that cap is below 1/alpha, the alarm threshold is unreachable
*by construction* and TPR is 0 for arithmetic reasons.

That is precisely what the first run showed: AUROC 0.9891 on SPLIT-Bench
(near-perfect ranking) alongside TPR 0.0000, because 64 benign calibration
samples cap e at 4.03 against a threshold of 20. The requirement is now
computable — `min_benign_for_alpha(0.05)` is **312** at the optimal kappa
(1,599 at the conventional kappa=0.5) — and is reported with every run as
`alarm_threshold_reachable` and `smallest_reachable_alpha`.

Usage:
    python -m sentinel.eval.evidence_fusion_eval
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path

from sentinel.core.evidence_fusion import (
    calibrate_evalue_threshold,
    merge_evalues,
    ville_threshold,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

_EVAL_DIR = Path(__file__).parent
_RESULTS = _EVAL_DIR / "results"
ALL_LAYERS = ("L1", "L2", "L3", "L4", "L5")

ALPHA = 0.05
N_FOLDS = 5


def load_phase4() -> list[dict]:
    """
    Phase 4 samples with per-sample layer scores, straight out of
    `verify_phase4_benchmark`'s output — so this reuses the exact
    measurements that pass produced rather than re-running the pipeline and
    getting subtly different numbers.
    """
    path = _EVAL_DIR / "data" / "phase4_benchmark" / "verification.jsonl"
    if not path.exists():
        raise SystemExit(
            "verification.jsonl not found. Run:\n"
            "    python -m sentinel.eval.verify_phase4_benchmark"
        )
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
    return [{
        "sample_id": r["sample_id"],
        "label": r["label"],
        "layer_scores": r["layer_scores"],
        "correlation_fired": r["correlation_fired"],
        "bucket": r.get("bucket_intent", ""),
    } for r in rows]


def load_split_bench() -> list[dict]:
    from sentinel.eval.split_bench import _DATA_DIR as _SPLIT_DIR   # follows SPLIT_BENCH_DIR
    path = _SPLIT_DIR / "all.jsonl"
    if not path.exists():
        raise SystemExit(
            "SPLIT-Bench not found. Run:\n"
            "    python -m sentinel.eval.split_bench --per-bucket 40"
        )
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
    return [{
        "sample_id": r["sample_id"],
        "label": r["label"],
        "layer_scores": r["metadata"]["certificate"]["measured_scores"],
        "correlation_fired": r["metadata"].get("correlation_fired"),
        "bucket": f"k={r['metadata']['k_intended']}",
    } for r in rows]


def _dependence_diagnostics(benign: list[dict], usable: list[str],
                            kappa: float) -> dict:
    """
    Measured pairwise dependence between layers on BENIGN data, plus the
    empirical null expectation of each merge rule.

    Dependence must be measured PER CORPUS rather than assumed, because a
    blanket claim either way is wrong. Measured 2026-09-19 on benign
    e-values:

        Phase 4      L1-L3 r = +0.9487, L1-L2 +0.7646, L2-L3 +0.6607
        SPLIT-Bench  L1-L3 r = +0.1083, L1-L2 +0.0483, L2-L3 +0.0095

    So the layers are strongly dependent on Phase 4 and nearly independent
    on SPLIT-Bench — and the latter is a property of its GENERATOR, not of
    real traffic: fragments are placed at independently-drawn positions
    (document / first turn / later turns), so the resulting layer scores
    barely covary. SPLIT-Bench therefore must not be used to license the
    product merge in general.

    TWO DIFFERENT KINDS OF STATEMENT, KEPT APART. The `mean` merge is valid
    under arbitrary dependence *by theorem*, so it needs no measurement and
    is the proposal. The `product` merge needs independence, which is a
    property of the deployment distribution that no in-sample check can
    establish — `product_merge_null_valid` only reports whether the
    necessary condition E_benign[E] <= 1 is violated ON THIS SAMPLE. It
    passing is not permission to use the product merge; it failing is proof
    not to.
    """
    import itertools

    import numpy as np

    cols = {L: np.array([b["layer_scores"].get(L, 0.0) for b in benign]) for L in usable}
    ev = {
        L: np.array([
            calibrate_evalue_threshold(list(cols[L]), v, kappa) for v in cols[L]
        ])
        for L in usable
    }
    pairs = {}
    for a, b in itertools.combinations(usable, 2):
        pairs[f"{a}-{b}"] = {
            "score_r": round(float(np.corrcoef(cols[a], cols[b])[0, 1]), 4),
            "evalue_r": round(float(np.corrcoef(ev[a], ev[b])[0, 1]), 4),
        }
    stacked = np.vstack([ev[L] for L in usable])
    max_abs = max((abs(v["evalue_r"]) for v in pairs.values()), default=0.0)
    null_mean = float(stacked.mean(axis=0).mean())
    null_product = float(stacked.prod(axis=0).mean())

    return {
        "pairwise": pairs,
        # DESCRIPTIVE ONLY — deliberately not the verdict. An earlier
        # version thresholded |r| < 0.2 to decide whether the product merge
        # was admissible, and a test with genuinely independent uniform
        # layers produced max|r| = 0.236 on n=300 and was wrongly rejected.
        # The reason is that e-values are heavily right-skewed (0.5/sqrt(p)
        # at kappa=0.5), so their sample correlation is dominated by a few
        # extreme points and is far noisier than 1/sqrt(n) would suggest.
        # Any fixed correlation cutoff is therefore arbitrary at these
        # sample sizes.
        "max_abs_evalue_correlation": round(max_abs, 4),
        # THE VERDICT, based on the actual validity condition rather than a
        # proxy for it. An e-value must satisfy E_benign[E] <= 1; that is
        # precisely what the product merge can violate under dependence, and
        # it is directly measurable. Necessary rather than sufficient — the
        # guarantee concerns the tail, and this is an in-sample estimate —
        # so it is reported as a check that can FAIL loudly, not as a proof.
        "null_expectation_mean": round(null_mean, 4),
        "null_expectation_product": round(null_product, 4),
        "mean_merge_null_valid": bool(null_mean <= 1.0),
        "product_merge_null_valid": bool(null_product <= 1.0),
    }


def _threshold_fusion_alarm(layer_scores: dict) -> bool:
    """The current architecture: alarm iff some layer crosses WARN."""
    from sentinel.config import WARN_THRESHOLD

    return any(layer_scores.get(L, 0.0) >= WARN_THRESHOLD for L in ALL_LAYERS)


def _evalues_for(sample: dict, benign_by_layer: dict[str, list[float]],
                 kappa: float) -> list[float]:
    return [
        calibrate_evalue_threshold(
            benign_by_layer[L], sample["layer_scores"].get(L, 0.0), kappa
        )
        for L in ALL_LAYERS
        # A layer with no benign variation at all cannot be calibrated: the
        # empirical tail is degenerate and every sample gets the same
        # e-value, which contributes nothing but drags the mean toward 1.
        # Dropping it is the same "absent evidence contributes exactly
        # nothing" rule the tier-fusion module applies to a tier that did
        # not run.
        if len(set(benign_by_layer[L])) > 1
    ]


def evaluate(samples: list[dict], corpus: str, alpha: float = ALPHA,
             kappa: float | None = None) -> dict:
    """
    LEAVE-ONE-OUT over the benign set, not k-fold.

    The binding constraint on this method turned out to be the benign
    calibration SIZE (see `max_attainable_evalue`), so the design must
    maximise it. 5-fold threw away 20% of the calibration set and pushed
    n from 80 down to 64, which on SPLIT-Bench is the difference between
    e_max 6.78 and 5.73. Leave-one-out keeps n-1.

    ASYMMETRY, STATED: a benign sample is scored against the other n-1
    benign samples; a malicious sample is scored against all n. That is the
    standard conformal arrangement and it is leak-free in both directions —
    calibration is benign-only, so a malicious sample can never appear in
    its own calibration set, and a benign sample never appears in its own.
    """
    import numpy as np

    from sentinel.core.evidence_fusion import (
        max_attainable_evalue,
        min_benign_for_alpha,
        optimal_kappa,
        smallest_reachable_alpha,
    )

    malicious = [s for s in samples if s["label"] == "malicious"]
    benign = [s for s in samples if s["label"] == "benign"]
    if not benign:
        raise SystemExit(f"{corpus} has no benign samples; the guarantee is uncheckable")

    n_ben = len(benign)
    # kappa* maximises the attainable e-value at this calibration size. Any
    # kappa in (0,1) is VALID; this is a power choice, and the power that
    # matters here is reachability of the alarm threshold at all.
    k = optimal_kappa(n_ben - 1) if kappa is None else kappa
    bound = ville_threshold(alpha)

    all_by_layer = {L: [s["layer_scores"].get(L, 0.0) for s in benign] for L in ALL_LAYERS}
    usable = [L for L in ALL_LAYERS if len(set(all_by_layer[L])) > 1]

    mal_merged = {m: np.zeros(len(malicious)) for m in ("mean", "product")}
    ben_merged = {m: np.zeros(n_ben) for m in ("mean", "product")}

    for m in ("mean", "product"):
        for i, s in enumerate(malicious):
            mal_merged[m][i] = merge_evalues(_evalues_for(s, all_by_layer, k), m)
        for i in range(n_ben):
            loo = {L: [v for j, v in enumerate(all_by_layer[L]) if j != i]
                   for L in ALL_LAYERS}
            ben_merged[m][i] = merge_evalues(_evalues_for(benign[i], loo, k), m)

    e_max = max_attainable_evalue(n_ben - 1, k)
    out = {
        "corpus": corpus,
        "alpha": alpha,
        "kappa": round(k, 4),
        "ville_alarm_threshold": bound,
        "n_malicious": len(malicious),
        "n_benign": n_ben,
        "calibration_n_leave_one_out": n_ben - 1,
        # THE REACHABILITY BLOCK. Without it a TPR of 0 reads as a detector
        # failure when it is an arithmetic ceiling: the mean merge is an
        # AVERAGE of values each capped at e_max, so if e_max < 1/alpha no
        # configuration of attack evidence can ever alarm.
        "max_attainable_evalue": round(e_max, 4),
        "alarm_threshold_reachable": bool(e_max >= bound),
        "smallest_reachable_alpha": round(smallest_reachable_alpha(n_ben - 1, k), 4),
        "min_benign_for_this_alpha": min_benign_for_alpha(alpha),
        "dependence": _dependence_diagnostics(benign, usable, k),
        # Which layers could be calibrated at all. A layer that is constant
        # across the whole benign set contributes no evidence and is dropped;
        # reporting it prevents a silent "we fused five layers" claim when
        # fewer were usable.
        "calibratable_layers": sorted(usable),
        "layers_dropped_as_constant": sorted(set(ALL_LAYERS) - set(usable)),
        "methods": {},
    }

    for method in ("mean", "product"):
        mal = mal_merged[method]
        ben = np.asarray(ben_merged[method], dtype=float)
        reachable_bound = 1.0 / out["smallest_reachable_alpha"]
        out["methods"][method] = {
            "tpr": round(float((mal >= bound).mean()), 4),
            # TPR at the tightest bound this calibration size can actually
            # certify. Reported because the nominal-alpha TPR is 0 for
            # arithmetic reasons when the threshold is unreachable, and a
            # bare 0 would misrepresent the method.
            "tpr_at_smallest_reachable_alpha": round(
                float((mal >= reachable_bound).mean()), 4),
            "benign_alarm_rate_at_smallest_reachable_alpha": round(
                float((ben >= reachable_bound).mean()), 4),
            "benign_alarm_rate": round(float((ben >= bound).mean()), 4),
            # THE GUARANTEE CHECK. Ville bounds this by alpha; if it is
            # exceeded the construction is wrong, not merely weak.
            "guarantee_held": bool((ben >= bound).mean() <= alpha),
            "median_malicious_evalue": round(float(np.median(mal)), 4),
            "median_benign_evalue": round(float(np.median(ben)), 4),
            "auroc": round(_auroc(list(mal) + list(ben),
                                  [1] * len(mal) + [0] * len(ben)), 4),
        }

    # --- Baselines on the SAME samples -----------------------------------
    thr_mal = [_threshold_fusion_alarm(s["layer_scores"]) for s in malicious]
    thr_ben = [_threshold_fusion_alarm(s["layer_scores"]) for s in benign]
    corr_mal = [bool(s["correlation_fired"]) for s in malicious]
    corr_ben = [bool(s["correlation_fired"]) for s in benign]

    out["baselines"] = {
        "threshold_fusion": {
            "tpr": round(sum(thr_mal) / len(thr_mal), 4),
            "benign_alarm_rate": round(sum(thr_ben) / len(thr_ben), 4),
        },
        "hand_coded_correlation_rules": {
            "tpr": round(sum(corr_mal) / len(corr_mal), 4),
            "benign_alarm_rate": round(sum(corr_ben) / len(corr_ben), 4),
        },
    }

    # Per-bucket TPR for the mean merge, because the mechanism claim is that
    # fusion helps MORE where more layers carry evidence.
    buckets: dict[str, list[int]] = {}
    for i, s in enumerate(malicious):
        buckets.setdefault(s["bucket"], []).append(i)
    out["tpr_by_bucket_mean_merge"] = {
        b: {
            "n": len(idx),
            "evalue_fusion": round(float((mal_merged["mean"][idx] >= bound).mean()), 4),
            "threshold_fusion": round(sum(thr_mal[i] for i in idx) / len(idx), 4),
            "correlation_rules": round(sum(corr_mal[i] for i in idx) / len(idx), 4),
        }
        for b, idx in sorted(buckets.items())
    }
    return out


def _auroc(scores, labels) -> float:
    from sentinel.eval.tier_fusion_eval import _auroc_fast

    return _auroc_fast(scores, labels)


def main() -> None:
    import time

    from sentinel.eval.results_ledger import code_files_for, safe_append_entry

    started = time.monotonic()
    loaders = {"phase4": load_phase4, "split_bench": load_split_bench}
    out = {}
    for corpus, loader in loaders.items():
        try:
            samples = loader()
        except SystemExit as exc:
            logger.warning(f"skipping {corpus}: {exc}")
            continue
        out[corpus] = evaluate(samples, corpus)

    for corpus, res in out.items():
        logger.info(f"=== {corpus} (alpha={res['alpha']}, alarm at e >= "
                    f"{res['ville_alarm_threshold']:.1f}) ===")
        logger.info(f"  n={res['n_malicious']} mal / {res['n_benign']} ben; "
                    f"calibratable layers={res['calibratable_layers']}"
                    + (f", dropped as constant={res['layers_dropped_as_constant']}"
                       if res["layers_dropped_as_constant"] else ""))
        if not res["alarm_threshold_reachable"]:
            logger.warning(
                f"  ALARM THRESHOLD UNREACHABLE: max attainable e-value is "
                f"{res['max_attainable_evalue']:.2f} < {res['ville_alarm_threshold']:.1f}. "
                f"A TPR of 0 at alpha={res['alpha']} here is ARITHMETIC, not detection. "
                f"Smallest reachable alpha at n={res['calibration_n_leave_one_out']} is "
                f"{res['smallest_reachable_alpha']:.4f}; alpha={res['alpha']} needs "
                f"n >= {res['min_benign_for_this_alpha']} benign calibration samples."
            )
        logger.info(f"  {'rule':<34} {'TPR':>8} {'TPR@reach':>10} {'benign':>8} "
                    f"{'AUROC':>8}  guarantee")
        for name, m in res["methods"].items():
            logger.info(f"  {'e-value fusion (' + name + ')':<34} {m['tpr']:>8.4f} "
                        f"{m['tpr_at_smallest_reachable_alpha']:>10.4f} "
                        f"{m['benign_alarm_rate']:>8.4f} {m['auroc']:>8.4f}  "
                        f"{'HELD' if m['guarantee_held'] else 'VIOLATED'}")
        for name, b in res["baselines"].items():
            logger.info(f"  {name:<34} {b['tpr']:>8.4f} {'':>10} "
                        f"{b['benign_alarm_rate']:>8.4f}")
        dep = res["dependence"]
        logger.info(f"  dependence (benign e-values): max|r|="
                    f"{dep['max_abs_evalue_correlation']:.4f} (descriptive); "
                    f"E_null[mean]={dep['null_expectation_mean']:.4f} "
                    f"{'OK' if dep['mean_merge_null_valid'] else 'INVALID'}, "
                    f"E_null[product]={dep['null_expectation_product']:.4f} "
                    f"{'OK' if dep['product_merge_null_valid'] else 'INVALID'}")
        for pair, v in dep["pairwise"].items():
            logger.info(f"      {pair}: score_r={v['score_r']:+.4f} "
                        f"evalue_r={v['evalue_r']:+.4f}")
        for bucket, row in res["tpr_by_bucket_mean_merge"].items():
            logger.info(f"    bucket {bucket:<28} n={row['n']:<4} "
                        f"e-fusion={row['evalue_fusion']:.4f} "
                        f"threshold={row['threshold_fusion']:.4f} "
                        f"corr_rules={row['correlation_rules']:.4f}")

    _RESULTS.mkdir(exist_ok=True)
    path = _RESULTS / f"eval_evidence_fusion_{datetime.now():%Y%m%d_%H%M%S}.json"
    path.write_text(json.dumps(out, indent=2), encoding="utf-8")
    logger.info(f"Results saved to {path}")

    safe_append_entry(
        experiment_id=f"evidence_fusion_{datetime.now():%Y%m%d_%H%M%S}",
        phase="Phase 5 / Contribution F",
        code_files=code_files_for(
            "sentinel/core/evidence_fusion.py",
            "sentinel/eval/evidence_fusion_eval.py",
        ),
        dataset_cache_file=str(_EVAL_DIR / "data" / "split_bench" / "all.jsonl"),
        split=f"stratified {N_FOLDS}-fold over BENIGN only; each fold's e-values "
              f"calibrated from the other folds, so no benign sample is scored "
              f"against a distribution containing it",
        thresholds_used={"alpha": ALPHA, "ville_threshold": ville_threshold(ALPHA)},
        metrics=out,
        result_file=str(path),
        runtime_seconds=round(time.monotonic() - started, 1),
        seed=31,
        notes=(
            "Cross-layer e-value merge only. The SEQUENTIAL/anytime-valid claim "
            "(EProcess, MixtureEDetector) is NOT evidenced here: it needs per-turn "
            "layer scores, which pipeline_sim does not expose (it reports a max over "
            "turns). `mean` merge is valid under arbitrary dependence and is the "
            "proposal; `product` is reported only to price the independence "
            "assumption, which is measured false for these layers."
        ),
    )


if __name__ == "__main__":
    main()
