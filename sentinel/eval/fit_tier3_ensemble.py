"""
Fit and FREEZE L1 Tier 3's benign-quantile reference, for the PIGuard ensemble.

WHAT TIER 3 IS TODAY, AND WHY IT IS BEING REPLACED. Tier 3 is Prompt-Guard-86M's
`jailbreak` head. Measured threshold-free on every corpus of ours that has both
classes (`scratch/l1x/guard_bench.py`):

    corpus            shipped pg_jailbreak    PIGuard
    sentinel_bench           0.6975           0.9316
    wildjailbreak            0.5493           0.6619
    bipia_local              0.8200           0.9448

and on over-defense, at a matched 1 % Alpaca budget, NotInject FPR 0.3540 -> 0.1504.
Prompt Guard is also the *irreducible* source of L1's over-defense: the benign
samples no threshold can suppress are 8/339 on NotInject and 14/210 on WildJailbreak
benign, **every one of them Tier 3 saturating at ~1.000**.

WHY AN ENSEMBLE RATHER THAN A STRAIGHT SWAP. PIGuard alone is better at ranking on
all three corpora but is NOT a Pareto improvement over the shipped tier: at a 0.5 %
budget its WildJailbreak recall is 0.4065 against the shipped 0.5620. The unweighted
mean of the two, on a shared axis, beats the shipped tier at EVERY budget on EVERY
corpus (scratch/l1x/tier3_design.py):

    budget   design     NotInject   sentinel_bench   wildjailbreak   bipia_local
    1 %      shipped      0.3540        0.8814           0.6910         0.9596
    1 %      ensemble     0.2124        1.0000           0.8705         0.9606
    0.5 %    shipped      0.2566        0.6271           0.5620         0.8562
    0.5 %    ensemble     0.1976        1.0000           0.8335         0.8966

WHY A SHARED AXIS IS REQUIRED, and why a raw max() or mean() would be meaningless.
Prompt Guard's 99th-percentile score on Alpaca benign is **0.0002**; PIGuard's is
**0.3230**. Combining those raw would simply let Prompt Guard win every comparison.
Each model is therefore mapped through its OWN benign quantile function first, so
"0.7" means the same thing -- *this scores above 70 % of benign traffic* -- for both.
That is the same per-axis discipline L2's two warn anchors needed, and the failure
mode it avoids is this project's recurring RCA-#3 error.

`max()` on the shared axis was measured and REJECTED: sentinel_bench 0.9506 -> 0.8287
and wildjailbreak 0.6071 -> 0.5717 versus the mean. A max is dominated by whichever
model is noisier on the input; a mean requires both to agree.

THE HONEST LIMIT, stated rather than buried. Leave-one-corpus-out selection over the
candidate designs picks a DIFFERENT winner for each held-out corpus (PIGuard alone /
the mean / a PIGuard+ProtectAI max). So no design dominates the others, and the mean
is adopted on a declared criterion -- *be no worse than the shipped tier on any
corpus at any budget* -- which it uniquely satisfies, and not because it topped a
table. PIGuard alone has strictly better over-defense at every budget; if
over-defense is ever the binding constraint, that is the right choice instead and
this artifact supports it via `L1_TIER3_MODE`.

WHAT IS FITTED HERE. Only the two benign quantile references, and only from
label-free benign text. No labels, no malicious corpus, no weights. The combination
is an unweighted mean of two quantile transforms, so there is no coefficient that
could have been tuned to a test split.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path

import numpy as np

ART = Path("sentinel/core/artifacts/l1_tier3_ensemble.json")
ALPACA = Path("sentinel/eval/data/cache/alpaca/test/samples.jsonl")
# Alpaca rows used to build the benign reference. Disjoint from rows 0-500, which
# `conformal_l1_eval.py` uses to calibrate L1_WARN_THRESHOLD, so the threshold and
# this reference are not estimated on the same samples.
FIT_ROWS = (500, 4500)
N_KNOTS = 512          # the reference is stored as quantile knots, not 4000 floats
SEED = 20260922


def _sha256(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _load_benign(lo: int, hi: int) -> list[str]:
    rows = [json.loads(l) for l in ALPACA.open(encoding="utf-8") if l.strip()]
    return [r["text"] for r in rows[lo:hi] if r["label"] == "benign"]


def fit() -> dict:
    texts = _load_benign(*FIT_ROWS)
    if not texts:
        raise SystemExit(f"no benign Alpaca rows in {FIT_ROWS}")

    from sentinel.eval.baselines.injection_guards import PIGuardBaseline
    from sentinel.eval.baselines.prompt_guard import PromptGuardBaseline

    pg = PromptGuardBaseline()
    pig = PIGuardBaseline()

    print(f"scoring {len(texts)} Alpaca benign rows {FIT_ROWS} ...")
    pg_scores = np.array([r["jailbreak_prob"]
                          for r in pg.probs_batch(texts, batch_size=32)],
                         dtype=float)
    pig_scores = np.array(pig.injection_probs(texts, batch_size=32), dtype=float)

    qs = np.linspace(0.0, 1.0, N_KNOTS)
    art = {
        "artifact": ART.name,
        "frozen_at": datetime.now().isoformat(timespec="seconds"),
        "purpose": "benign-quantile reference so Prompt Guard and PIGuard can be "
                   "averaged on one axis; see this module's docstring",
        "fit_benign_corpus": f"alpaca rows {FIT_ROWS[0]}-{FIT_ROWS[1]}",
        "fit_benign_source": str(ALPACA),
        "fit_benign_sha256": _sha256(ALPACA),
        "n_benign": len(texts),
        "disjoint_from": "alpaca rows 0-500, which conformal_l1_eval.py uses to "
                         "calibrate L1_WARN_THRESHOLD",
        "never_fitted_on": ["notinject", "sentinel_bench", "tensortrust",
                            "wildjailbreak", "bipia_local"],
        "quantiles": qs.tolist(),
        "prompt_guard_jailbreak_knots": np.quantile(pg_scores, qs).tolist(),
        "piguard_injection_knots": np.quantile(pig_scores, qs).tolist(),
        "models": {
            "prompt_guard": "meta-llama/Prompt-Guard-86M (jailbreak head)",
            "piguard": "leolee99/PIGuard (injection head, ACL 2025, "
                       "arXiv:2410.22770)",
        },
        "combination": "unweighted mean of the two quantile transforms; max() was "
                       "measured and rejected (sentinel_bench 0.9506 -> 0.8287)",
        "seed": SEED,
    }
    # Percentiles of the raw scores, recorded because they are the evidence that a
    # shared axis is necessary at all.
    art["raw_p99"] = {"prompt_guard_jailbreak": float(np.quantile(pg_scores, 0.99)),
                      "piguard_injection": float(np.quantile(pig_scores, 0.99))}
    return art


def main():
    art = fit()
    ART.parent.mkdir(parents=True, exist_ok=True)
    body = json.dumps(art, indent=1)
    ART.write_text(body, encoding="utf-8")
    prov = ART.with_suffix(".provenance.json")
    prov.write_text(json.dumps(
        {k: v for k, v in art.items()
         if k not in ("quantiles", "prompt_guard_jailbreak_knots",
                      "piguard_injection_knots")}
        | {"artifact_sha256": hashlib.sha256(body.encode()).hexdigest()},
        indent=1), encoding="utf-8")
    print(f"wrote {ART}  ({len(body)} bytes)")
    print(f"wrote {prov}")
    print(f"  raw 99th percentile on Alpaca benign: "
          f"prompt_guard {art['raw_p99']['prompt_guard_jailbreak']:.6f}  "
          f"piguard {art['raw_p99']['piguard_injection']:.6f}")


if __name__ == "__main__":
    main()
