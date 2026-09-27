"""
Does L4/L5's continuous confidence recover the discrimination their quantised
score throws away?

THE DEFECT (Section VI, interface sites 4 and 6). L4's score is a max() over a
handful of constants -- risk_to_score(level), then max(., 0.7), max(., 0.8),
max(., 0.9). On SPLIT-Bench every session lands on the same branch, so the score
takes ONE distinct value across all 680 sessions and its AUROC is 0.5000 by
construction. L5 is the same shape with three distinct values. The paper reports
this as a defect.

THE CANDIDATE FIX. Both layers already compute a continuous `confidence` --
a noisy-OR over their evidence terms, shared via core.evidence -- and both
already return it. Nothing reads it: the evaluation ranks on `.score`. So the
information may be present and merely discarded at the reporting interface,
which is precisely the paper's thesis applied to its own measurement.

WHAT THIS SCRIPT DOES, AND WHAT IT DELIBERATELY DOES NOT. It compares AUROC of
`score` against AUROC of `confidence`, per layer, on the same sessions. It does
NOT change any decision threshold, and it does not propose that `confidence`
replace `score` as the blocking variable: `score` is calibrated and drives
production BLOCK/ALLOW, and swapping it would invalidate every threshold in the
system for a benchmark gain. AUROC is a RANKING metric, so ranking on the
continuous quantity measures what the layer knows; the gap between the two
numbers is the interface loss, quantified.

A NEGATIVE RESULT HERE IS A REAL RESULT. If confidence is also ~0.5000, then the
layer genuinely has no signal on this corpus and the quantisation is not hiding
anything -- which would strengthen the paper's "dead layer" claim rather than
weaken it. Both outcomes are reported.
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

_RESULTS = Path(__file__).parent / "results"


def _auroc(scores: list[float], labels: list[int]) -> float | None:
    """
    Rank-based AUROC with tie correction (Mann-Whitney U / (n_pos * n_neg)).

    Returns None when one class is absent -- reporting 0.5 there would invent a
    result, and reporting 0.0 would invent a worse one.
    """
    pos = [s for s, y in zip(scores, labels) if y == 1]
    neg = [s for s, y in zip(scores, labels) if y == 0]
    if not pos or not neg:
        return None
    pool = sorted(zip(scores, labels), key=lambda t: t[0])
    ranks, i = [0.0] * len(pool), 0
    while i < len(pool):
        j = i
        while j + 1 < len(pool) and pool[j + 1][0] == pool[i][0]:
            j += 1
        avg = (i + j) / 2 + 1
        for k in range(i, j + 1):
            ranks[k] = avg
        i = j + 1
    rsum_pos = sum(r for r, (_s, y) in zip(ranks, pool) if y == 1)
    n_pos, n_neg = len(pos), len(neg)
    u = rsum_pos - n_pos * (n_pos + 1) / 2
    return u / (n_pos * n_neg)


def _distinct(values: list[float]) -> int:
    return len({round(v, 9) for v in values})


async def measure(corpus: str = "split_bench", limit: int | None = None) -> dict:
    from sentinel.eval.pipeline_sim import simulate_pipeline

    # SPLIT-Bench is not in dataset_loaders' registry -- it ships as a JSONL with
    # its sub-threshold certificates in `metadata`, and eprocess_eval reads it
    # directly. Reuse that loader rather than adding a second reader that could
    # drift from it.
    if corpus == "split_bench":
        from sentinel.eval.eprocess_eval import load_split_bench_texts
        samples = [type("S", (), {"sample_id": r["sample_id"], "text": r["text"],
                                  "label": r["label"]})()
                   for r in load_split_bench_texts()]
    else:
        from sentinel.eval.dataset_loaders import load_dataset
        samples = load_dataset(corpus, split="test", limit=limit).samples
    if limit:
        samples = samples[:limit]

    rows = []
    for s in samples:
        r = await simulate_pipeline(s.text, sample_id=s.sample_id)
        conf = getattr(r, "layer_confidence", {}) or {}
        rows.append({
            "sample_id": s.sample_id,
            "label": 1 if s.label == "malicious" else 0,
            "L4_score": float(r.layer_scores.get("L4", 0.0) or 0.0),
            "L5_score": float(r.layer_scores.get("L5", 0.0) or 0.0),
            "L4_confidence": float(conf.get("L4", 0.0) or 0.0),
            "L5_confidence": float(conf.get("L5", 0.0) or 0.0),
        })

    labels = [r["label"] for r in rows]
    out = {
        "corpus": corpus,
        "n": len(rows),
        "n_malicious": sum(labels),
        "n_benign": len(labels) - sum(labels),
        "layers": {},
        "rows": rows,
    }

    for layer in ("L4", "L5"):
        sc = [r[f"{layer}_score"] for r in rows]
        cf = [r[f"{layer}_confidence"] for r in rows]
        a_sc, a_cf = _auroc(sc, labels), _auroc(cf, labels)
        out["layers"][layer] = {
            "score_auroc": a_sc,
            "confidence_auroc": a_cf,
            "score_distinct_values": _distinct(sc),
            "confidence_distinct_values": _distinct(cf),
            "delta_auroc": (None if (a_sc is None or a_cf is None)
                            else round(a_cf - a_sc, 4)),
            # 2|AUROC - 0.5| is the informativeness weight the effective-capacity
            # calculation uses, so this states the fix's effect in the units the
            # paper's capacity table is denominated in.
            "informativeness_score": (None if a_sc is None
                                      else round(2 * abs(a_sc - 0.5), 4)),
            "informativeness_confidence": (None if a_cf is None
                                           else round(2 * abs(a_cf - 0.5), 4)),
        }
    return out


def main():
    logging.basicConfig(level=logging.WARNING)
    out = asyncio.run(measure())
    _RESULTS.mkdir(parents=True, exist_ok=True)
    path = _RESULTS / "quantisation_recovery.json"
    path.write_text(json.dumps(out, indent=2), encoding="utf-8")

    print(f"corpus {out['corpus']}  n={out['n']} "
          f"({out['n_malicious']} malicious / {out['n_benign']} benign)\n")
    hdr = f"{'layer':<6}{'variable':<12}{'distinct':<10}{'AUROC':<10}{'2|A-0.5|'}"
    print(hdr)
    print("-" * len(hdr))
    for layer, d in out["layers"].items():
        for var, a, n, w in (
            ("score", d["score_auroc"], d["score_distinct_values"],
             d["informativeness_score"]),
            ("confidence", d["confidence_auroc"], d["confidence_distinct_values"],
             d["informativeness_confidence"]),
        ):
            astr = "n/a" if a is None else f"{a:.4f}"
            wstr = "n/a" if w is None else f"{w:.4f}"
            print(f"{layer:<6}{var:<12}{n:<10}{astr:<10}{wstr}")
        print(f"{'':<6}{'delta':<12}{'':<10}{d['delta_auroc']}")
    print(f"\nwrote {path}")
    return out


if __name__ == "__main__":
    main()
