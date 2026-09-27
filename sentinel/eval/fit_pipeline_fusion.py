"""
Fit + calibrate the deployable cross-layer score fusion (core/pipeline_fusion.py).

DATA DISCIPLINE (nothing here reads SPLIT-Bench, which is what the result is reported on):
  FIT        sentinel_bench mining_set (425: the same labelled split the pattern miner is
             mined on; disjoint from SB test/held_out and from SPLIT-Bench)
  CALIBRATE  benign_pipeline_arm (529 real benign multi-layer sessions: held-out news/code
             documents + benign tool calls), md5 halves: CAL fixes the alarm anchors,
             HOLD reports the achieved benign false-alarm rate (never used to pick anything)
  CHECK      sentinel_bench test (112) and held_out (150): AUROC of the fused score
Anchors: tau_warn = split-conformal at alpha_warn (default 0.02) on CAL; tau_block at
alpha_block (default 0.002), used only under PIPELINE_FUSION=warn_block.
Features: shared-axis layer scores L1..L5 (+ L1H if the harm head is on) and the continuous
channels L2c / L4c / L5c recorded by pipeline_sim. Judge pinned OFF (same regime as
SPLIT-Bench generation). L2 on the shared axis iff L2_SHARED_AXIS -- use the SAME setting
as the SPLIT-Bench version it will be evaluated on.

Usage: L2_SHARED_AXIS=true python -m sentinel.eval.fit_pipeline_fusion [--alpha-warn 0.02]
Writes sentinel/core/artifacts/pipeline_fusion.json (+ a copy in eval/results/).
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import math
import time
from pathlib import Path

import numpy as np


async def _vectors(samples):
    from sentinel.core.pipeline_fusion import features
    from sentinel.eval.pipeline_sim import simulate_pipeline
    X, y, ids = [], [], []
    for s in samples:
        r = await simulate_pipeline(s.text, sample_id=s.sample_id)
        X.append(features(r.layer_scores, r.layer_confidence))
        y.append(1 if s.label == "malicious" else 0)
        ids.append(s.sample_id)
    return np.array(X, float), np.array(y), ids


def _tau(scores, alpha):
    x = np.sort(np.asarray(scores, float)); k = math.ceil((len(x) + 1) * (1 - alpha))
    return float(x[min(k, len(x)) - 1]) if k <= len(x) else 1.0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--alpha-warn", type=float, default=0.02)
    ap.add_argument("--alpha-block", type=float, default=0.002)
    ap.add_argument("--extra-train", default=None,
                    help="dir with all.jsonl of a SEPARATELY generated SPLIT-Bench (different seed): its "
                         "certified sub-threshold attacks + benign shells join the fit set; any text also "
                         "present in --exclude-dir (the test bench) is dropped")
    ap.add_argument("--exclude-dir", default=None)
    a = ap.parse_args()

    import sentinel.config as cfg
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import roc_auc_score
    from sklearn.model_selection import StratifiedKFold
    from sklearn.preprocessing import StandardScaler

    from sentinel.core.pipeline_fusion import FEATURES
    from sentinel.eval.dataset_loaders import load_dataset
    from sentinel.eval.run_config import config_snapshot

    cfg.L1_LLM_JUDGE_ENABLED = False
    t0 = time.time()
    Xm, ym, _ = asyncio.run(_vectors(load_dataset("sentinel_bench", split="mining_set").samples))
    fit_on = "sentinel_bench mining_set"
    if a.extra_train:
        from types import SimpleNamespace
        excl = set()
        if a.exclude_dir:
            excl = {json.loads(l)["text"] for l in open(Path(a.exclude_dir) / "all.jsonl", encoding="utf-8")}
        rows = [json.loads(l) for l in open(Path(a.extra_train) / "all.jsonl", encoding="utf-8")]
        rows = [r for r in rows if r["text"] not in excl]
        extra = [SimpleNamespace(text=r["text"], label=r["label"], sample_id=r["sample_id"] + "_train") for r in rows]
        Xe, ye, _ = asyncio.run(_vectors(extra))
        Xm, ym = np.vstack([Xm, Xe]), np.concatenate([ym, ye])
        fit_on += f" + SPLIT-Bench TRAIN bench {a.extra_train} ({len(rows)} samples, test-bench texts excluded)"
        print("extra train:", len(rows), "samples,", int(ye.sum()), "attacks", flush=True)
    sc = StandardScaler().fit(Xm); Xs = sc.transform(Xm)
    best = None
    for C in (0.01, 0.03, 0.1, 0.3, 1.0, 3.0):
        aucs = [roc_auc_score(ym[te], LogisticRegression(C=C, max_iter=5000, class_weight="balanced")
                              .fit(Xs[tr], ym[tr]).decision_function(Xs[te]))
                for tr, te in StratifiedKFold(5, shuffle=True, random_state=0).split(Xs, ym)]
        if best is None or np.mean(aucs) > best[1]:
            best = (C, float(np.mean(aucs)))
    m = LogisticRegression(C=best[0], max_iter=5000, class_weight="balanced").fit(Xs, ym)
    prob = lambda X: m.predict_proba(sc.transform(X))[:, 1]

    ben = load_dataset("benign_pipeline_arm").samples
    Xb, _, bids = asyncio.run(_vectors(ben))
    cal = np.array([int(hashlib.md5(i.encode()).hexdigest(), 16) % 2 == 0 for i in bids])
    pb = prob(Xb)
    tau_w, tau_b = _tau(pb[cal], a.alpha_warn), _tau(pb[cal], a.alpha_block)
    checks = {}
    for split in ("test", "held_out"):
        Xt, yt, _ = asyncio.run(_vectors(load_dataset("sentinel_bench", split=split).samples))
        if len(set(yt)) > 1:
            pt = prob(Xt)
            checks[f"sentinel_bench_{split}"] = {"auroc": float(roc_auc_score(yt, pt)),
                                                  "recall_at_warn": float(np.mean(pt[yt == 1] >= tau_w)),
                                                  "fpr_at_warn": float(np.mean(pt[yt == 0] >= tau_w))}
    art = {"features": FEATURES, "mean": sc.mean_.tolist(), "scale": sc.scale_.tolist(),
           "coef": m.coef_[0].tolist(), "intercept": float(m.intercept_[0]), "C": best[0],
           "cv_auroc_mining_set": best[1],
           "tau_warn": tau_w, "tau_block": tau_b, "alpha_warn": a.alpha_warn, "alpha_block": a.alpha_block,
           "benign_hold_fpr_at_warn": float(np.mean(pb[~cal] >= tau_w)),
           "benign_hold_fpr_at_block": float(np.mean(pb[~cal] >= tau_b)),
           "n_fit": int(len(ym)), "n_benign_cal": int(cal.sum()), "n_benign_hold": int((~cal).sum()),
           "checks": checks, "fit_on": fit_on, "calibrated_on": "benign_pipeline_arm md5-even half",
           "config": config_snapshot(), "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
           "seconds": round(time.time() - t0, 1)}
    out = Path("sentinel/core/artifacts/pipeline_fusion.json")
    out.write_text(json.dumps(art, indent=1), encoding="utf-8")
    Path(f"sentinel/eval/results/pipeline_fusion_fit_{time.strftime('%Y%m%d_%H%M%S')}.json").write_text(
        json.dumps(art, indent=1), encoding="utf-8")
    print(json.dumps({k: art[k] for k in ("cv_auroc_mining_set", "tau_warn", "tau_block",
                                          "benign_hold_fpr_at_warn", "benign_hold_fpr_at_block", "checks")}, indent=1))
    print("wrote", out, "-- enable with PIPELINE_FUSION=warn (or warn_block)")


if __name__ == "__main__":
    main()
