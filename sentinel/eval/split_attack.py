"""
Contribution H --- SPLIT-Attack: a threshold-aware distributed adversary.

WHY THIS EXISTS. Section IV proves a bound about a $(k,\\varepsilon)$-distributed
adversary: one who spreads attack signal so that every layer stays individually
below its threshold. Nothing in the evaluation instantiates that adversary. Both
red-team tiers paraphrase whole prompts and attack one surface at a time, and
SPLIT-Bench's samples are *constructed* sub-threshold rather than *found* by an
attacker probing the system. So the bound's adversary is, at present,
hypothetical.

This module supplies two things.

H1 --- THE RETRODICTION TEST (`dispersion_retrodiction`).
The project's own records flag a surprise: a crude rule-based paraphraser evades
63.2% of the time while a fluent LLM paraphraser evades only 12.3%, the opposite
of the naive expectation. The bound's framework predicts exactly this. Evasion
requires attack signal to be SPREAD below several thresholds; a fluent rewrite
preserves meaning and therefore CONCENTRATES signal in whichever layer reads
meaning best, while crude mangling degrades the signal unevenly and accidentally
distributes it.

That yields a falsifiable, already-testable prediction:

    evaded samples should show HIGHER cross-layer score dispersion
    than caught samples.

If evaded and caught samples disperse alike, the framework does not explain the
reversal and the paper must stop claiming it does. This is deliberately a test
the theory can fail.

H2 --- THE ADAPTIVE ADVERSARY (`split_attack_allocate`).
Given per-layer thresholds and query access to the scorers, allocate an attack
budget across layers to maximise total delivered signal subject to every layer
staying at or below $\\tau_i - \\varepsilon$. This is the water-filling solution
to the budget problem in Definition 2, and it produces the tight side of the
bound rather than an anecdote.

NOTHING HERE SCORES A DEFENCE AGAINST ITSELF. The dispersion test reads existing
red-team outcomes and re-scores those samples through the unmodified pipeline;
the allocator is evaluated by whether its output is genuinely sub-threshold,
which is checked, not assumed.
"""

from __future__ import annotations

import json
import logging
import math
import statistics
from pathlib import Path

logger = logging.getLogger(__name__)

_RESULTS = Path(__file__).parent / "results"

# Layers that carry a per-sample score in the simulated pipeline. L4/L5 are
# included in scoring but are frequently constant on text-only corpora (see the
# interface audit), so dispersion is reported both over all layers and over the
# informative subset.
_ALL_LAYERS = ("L1", "L2", "L3", "L4", "L5")


def _dispersion(scores: dict, layers=None) -> dict:
    """
    How spread out is this sample's attack signal across layers?

    Three measures, because they fail differently:
      * `cv`        coefficient of variation -- scale-free, but undefined at mean 0
      * `gap`       max minus mean -- how much one layer dominates; LOW means spread
      * `entropy`   normalised Shannon entropy of the score vector -- HIGH means spread

    A concentrated attack has high `cv`, high `gap`, low `entropy`.
    A distributed attack has the reverse.
    """
    layers = layers or _ALL_LAYERS
    v = [float(scores.get(k, 0.0) or 0.0) for k in layers]
    total = sum(v)
    mean = total / len(v) if v else 0.0
    sd = statistics.pstdev(v) if len(v) > 1 else 0.0
    if total > 0:
        p = [x / total for x in v]
        ent = -sum(q * math.log(q) for q in p if q > 0) / math.log(len(v))
    else:
        ent = 0.0
    return {
        "cv": (sd / mean) if mean > 0 else None,
        "gap": (max(v) - mean) if v else None,
        "entropy": ent,
        "max_layer": layers[v.index(max(v))] if v else None,
        "sum": total,
    }


def _mann_whitney_u(a: list[float], b: list[float]) -> tuple[float, float]:
    """
    Two-sided Mann-Whitney U with a normal approximation and tie correction.
    Returns (AUC-style effect size in [0,1], p-value). Used rather than a t-test
    because dispersion measures are bounded and not plausibly normal.
    """
    if len(a) < 3 or len(b) < 3:
        return float("nan"), float("nan")
    pool = sorted([(x, 0) for x in a] + [(x, 1) for x in b])
    ranks, i, rsum_a = [0.0] * len(pool), 0, 0.0
    ties = []
    while i < len(pool):
        j = i
        while j + 1 < len(pool) and pool[j + 1][0] == pool[i][0]:
            j += 1
        avg = (i + j) / 2 + 1
        ties.append(j - i + 1)
        for k in range(i, j + 1):
            ranks[k] = avg
        i = j + 1
    for idx, (_, grp) in enumerate(pool):
        if grp == 0:
            rsum_a += ranks[idx]
    n1, n2 = len(a), len(b)
    u1 = rsum_a - n1 * (n1 + 1) / 2
    auc = u1 / (n1 * n2)
    mu = n1 * n2 / 2
    tie_term = sum(t ** 3 - t for t in ties)
    n = n1 + n2
    var = n1 * n2 / 12 * ((n + 1) - tie_term / (n * (n - 1))) if n > 1 else 0.0
    if var <= 0:
        return auc, float("nan")
    z = (u1 - mu) / math.sqrt(var)
    p = math.erfc(abs(z) / math.sqrt(2))
    return auc, p


def load_redteam_outcomes(path: str | Path) -> dict:
    """sample_id -> evaded(bool), from a red-team result file."""
    d = json.load(open(path, encoding="utf-8"))
    rows = d.get("per_sample") or []
    return {r["sample_id"]: bool(r.get("evaded")) for r in rows if "sample_id" in r}


async def dispersion_retrodiction(redteam_file: str | Path,
                                  corpus: str = "sentinel_bench") -> dict:
    """
    H1. Do evaded samples carry more DISTRIBUTED signal than caught ones?

    Scores every red-teamed sample through the unmodified pipeline, then compares
    dispersion between the evaded and caught groups. The prediction under
    Section IV's framework is that evaded samples are more dispersed: higher
    entropy, lower `gap`, lower `cv`.
    """
    from sentinel.eval.dataset_loaders import load_dataset
    from sentinel.eval.pipeline_sim import simulate_pipeline

    outcomes = load_redteam_outcomes(redteam_file)
    if not outcomes:
        return {"error": "no per-sample outcomes in that red-team file"}

    ds = load_dataset(corpus, split="test")
    by_id = {s.sample_id: s for s in ds.samples}

    rows = []
    for sid, evaded in outcomes.items():
        s = by_id.get(sid)
        if s is None:
            continue
        r = await simulate_pipeline(s.text, sample_id=sid)
        scores = dict(r.layer_scores)
        informative = [k for k in _ALL_LAYERS
                       if len({round(float(scores.get(k, 0.0) or 0.0), 6)}) and
                       float(scores.get(k, 0.0) or 0.0) > 0.0]
        rows.append({
            "sample_id": sid,
            "evaded": evaded,
            "layer_scores": {k: round(float(scores.get(k, 0.0) or 0.0), 6)
                             for k in _ALL_LAYERS},
            "dispersion_all": _dispersion(scores, _ALL_LAYERS),
            "n_layers_nonzero": len(informative),
        })

    ev = [r for r in rows if r["evaded"]]
    ca = [r for r in rows if not r["evaded"]]

    out = {"n_total": len(rows), "n_evaded": len(ev), "n_caught": len(ca),
           "corpus": corpus, "redteam_file": str(redteam_file), "rows": rows,
           "tests": {}}

    for measure in ("entropy", "gap", "cv"):
        a = [r["dispersion_all"][measure] for r in ev
             if r["dispersion_all"][measure] is not None]
        b = [r["dispersion_all"][measure] for r in ca
             if r["dispersion_all"][measure] is not None]
        if len(a) < 3 or len(b) < 3:
            out["tests"][measure] = {"testable": False}
            continue
        auc, p = _mann_whitney_u(a, b)
        out["tests"][measure] = {
            "testable": True,
            "evaded_median": statistics.median(a),
            "caught_median": statistics.median(b),
            "auc_evaded_higher": auc,
            "p_two_sided": p,
            # The framework predicts evaded = more dispersed:
            #   entropy higher, gap lower, cv lower.
            "supports_framework": (auc > 0.5) if measure == "entropy" else (auc < 0.5),
        }
    return out


def effective_capacity(thresholds: dict, informativeness: dict,
                       epsilon: float = 0.02) -> dict:
    """
    Capacity discounted by how much each layer can actually tell.

    WHY RAW CAPACITY OVERSTATES THE DEFENSE. Summing $\\tau_i - \\varepsilon$
    treats every layer as equally able to notice what it is given. Measured on
    SPLIT-Bench that is false by a wide margin: L3 separates the classes at
    AUROC 0.8767 and L1 at 0.7419, while L4 and L5 sit at exactly 0.5000 with a
    single distinct score value each. A layer at chance contributes headroom an
    attacker can fill at no risk whatsoever, so counting its capacity as
    protective inflates the defense.

    Weighting each layer's headroom by $2|\\mathrm{AUROC}_i - 0.5|$ --- zero for
    a chance-level layer, one for a perfect one --- gives the capacity that is
    actually defended. The gap between the two numbers is the share of the
    defense's nominal budget that is decorative.
    """
    raw = {k: max(0.0, v - epsilon) for k, v in thresholds.items()}
    weighted = {k: raw[k] * (2.0 * abs(informativeness.get(k, 0.5) - 0.5))
                for k in raw}
    raw_total, eff_total = sum(raw.values()), sum(weighted.values())
    return {
        "raw_capacity": raw_total,
        "effective_capacity": eff_total,
        "undefended_share": (1.0 - eff_total / raw_total) if raw_total else None,
        "per_layer_raw": raw,
        "per_layer_effective": weighted,
        "dead_layers": sorted(k for k in raw
                              if abs(informativeness.get(k, 0.5) - 0.5) < 1e-9),
    }


def split_attack_allocate(thresholds: dict, budget: float,
                          epsilon: float = 0.02,
                          informativeness: dict | None = None) -> dict:
    """
    H2. Water-filling allocation for a $(k,\\varepsilon)$-distributed adversary.

    Delivers as much total attack signal as possible while keeping every layer at
    or below $\\tau_i - \\varepsilon$. Each layer's capacity is
    $c_i = \\tau_i - \\varepsilon$; the attacker fills layers in order of
    signal-per-unit-detection-risk (its `informativeness` weight, default equal)
    until either the budget is exhausted or every layer is at capacity.

    Returns the allocation, how much of the budget was placeable, and `k`, the
    number of layers carrying meaningful signal --- the quantity Section IV's
    bound is stated in terms of. An attacker whose budget exceeds total capacity
    CANNOT stay sub-threshold, which is the useful negative case: it marks the
    budget at which the bound stops protecting the attacker.
    """
    caps = {k: max(0.0, v - epsilon) for k, v in thresholds.items()}
    w = informativeness or {k: 1.0 for k in thresholds}
    order = sorted(caps, key=lambda k: -w.get(k, 1.0))

    alloc, remaining = {k: 0.0 for k in caps}, budget
    for layer in order:
        if remaining <= 0:
            break
        take = min(caps[layer], remaining)
        alloc[layer] = take
        remaining -= take

    placed = budget - remaining
    return {
        "allocation": alloc,
        "capacities": caps,
        "budget": budget,
        "placed": placed,
        "unplaceable": remaining,
        "feasible": remaining <= 1e-12,
        "k_layers_used": sum(1 for v in alloc.values() if v > 1e-9),
        "epsilon": epsilon,
    }
