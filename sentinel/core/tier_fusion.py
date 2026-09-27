"""
Calibrated likelihood-ratio fusion for L1's four tiers — Phase 5 plan
item 3B.3.

THE GAP THIS CLOSES
----------------------
L1 combines its tiers with a maximum:

    combined_sim = max(tier2_semantic, tier3_prompt_guard)
    # then tier4_judge overrides only if strictly higher

`max()` is not the Neyman-Pearson-optimal combination rule. Under NP, the
optimal statistic for deciding between "benign" and "malicious" given
several observations is the LIKELIHOOD RATIO of the joint observation, and
for conditionally-independent components that is the SUM of per-component
log-likelihood-ratios — not the maximum of raw scores. `max()` throws away
three things the LR keeps:

1. **Agreement.** Two tiers each scoring 0.6 is stronger evidence than one
   scoring 0.6 and another 0.0. `max()` reports 0.6 for both.
2. **Disagreement.** A tier confidently saying "benign" is evidence, and
   `max()` cannot represent negative evidence at all.
3. **Ranking resolution.** Measured on WildJailbreak (n=2,210), `max()`
   saturates L1's output so hard that reaching FPR<=0.01 requires a
   threshold of 0.9999 — both classes pile up at the ceiling.

A concrete, measured instance of (2): on sentinel_bench, an input scored
tier2=0.3201 while Prompt Guard scored 1.36e-05 — a near-maximal
disagreement — and `max()` reported 0.3201 as though Prompt Guard had
never spoken.

MISSINGNESS IS INFORMATIVE, AND THAT IS THE HARD PART
--------------------------------------------------------
Measured on sentinel_bench (n=112), tiers do not run independently — L1 is
a cascade, so exactly three availability patterns occur:

    13x  tier1 only                       (regex fired -> early return)
    27x  tier1 + tier2 + tier3            (judge not invoked)
    72x  tier1 + tier2 + tier3 + tier4    (judge invoked)

The pattern is a DETERMINISTIC function of the earlier tiers:
 - tiers 2-4 are absent exactly when tier 1 matched (score fixed at 0.92);
 - tier 4 is absent exactly when max(tier2, tier3) falls outside the
   ambiguous band (L1_SEMANTIC_MEDIUM, L1_SEMANTIC_HIGH].

So this is missing-NOT-at-random with a known mechanism. Mean-imputing an
absent tier, or treating it as 0.0, would inject fabricated evidence — and
would specifically destroy the distinction Stage -1 was built to preserve
(`None` = did not run, `0.0` = ran and found nothing). A tier that did not
run must contribute EXACTLY ZERO log-LR, which is what omitting its term
does, and is why this module fuses by summation over *available* terms
rather than by a fixed-width feature vector.

WHY THIS IS ALSO A PILOT FOR CONTRIBUTION F
----------------------------------------------
Summing per-component log-likelihood-ratios over whatever evidence is
available, with absent evidence contributing zero, is exactly the
e-value/e-process structure Contribution F proposes across L1-L5. Doing it
first *within* one layer, on real labelled data, tests the machinery where
the ground truth is cheap and the blast radius is one layer. The known
risk carries over identically: the tiers all read the same text through
related models, so they are NOT conditionally independent, and a naive sum
will overstate evidence. That is why `NaiveBayesTierFusion` below is
reported alongside, not instead of, a joint model that does not assume it.

STATUS: EVAL-ONLY. Nothing in this module is wired into layer1.py. It is
built to answer "is max() costing us measurable performance, cross-corpus"
before any production change is proposed — same discipline as the Phase
3.1 judge-backend work, which stayed eval-only until it earned adoption.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

TIER_KEYS = ("tier1_regex", "tier2_semantic", "tier3_prompt_guard", "tier4_judge")

# Clamp for log-odds so a perfectly-separating tier cannot contribute
# infinite evidence off a finite sample. 6.0 corresponds to a likelihood
# ratio of ~400:1, well beyond anything a 100-sample corpus can justify.
_MAX_ABS_LOG_LR = 6.0


def _clamp(x: float, lo: float = -_MAX_ABS_LOG_LR, hi: float = _MAX_ABS_LOG_LR) -> float:
    return max(lo, min(hi, x))


def availability_pattern(tier_scores: dict) -> tuple[str, ...]:
    """
    Which tiers produced a value for this sample. This is the cascade's
    state, and it is itself evidence — see the module docstring.
    """
    return tuple(k for k in TIER_KEYS if tier_scores.get(k) is not None)


@dataclass
class _TierCalibration:
    """
    One tier's 1-D logistic calibration: log-odds(y=1 | s) = a + b*s.

    Fitted by plain gradient descent rather than pulling in scikit-learn's
    LogisticRegression, because this needs to run on a handful of columns
    with a controlled, inspectable fit — and because several tiers are
    perfectly or near-perfectly separating on small corpora, where
    sklearn's default unregularised fit diverges. The L2 penalty below is
    what keeps that finite; it is a deliberate part of the estimator, not
    a tuning knob.
    """

    a: float = 0.0
    b: float = 0.0
    n_fit: int = 0

    def log_odds(self, score: float) -> float:
        return self.a + self.b * score


def _fit_logistic_1d(
    scores: list[float], labels: list[int], l2: float = 1.0,
    iters: int = 2000, lr: float = 0.1,
) -> _TierCalibration:
    a, b = 0.0, 0.0
    n = len(scores)
    if n == 0:
        return _TierCalibration(0.0, 0.0, 0)
    for _ in range(iters):
        ga = gb = 0.0
        for s, y in zip(scores, labels):
            z = a + b * s
            p = 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, z))))
            err = p - y
            ga += err
            gb += err * s
        # L2 on the slope only; the intercept absorbs class balance and
        # must stay free.
        a -= lr * (ga / n)
        b -= lr * (gb / n + l2 * b / n)
    return _TierCalibration(a, b, n)


@dataclass
class NaiveBayesTierFusion:
    """
    Sum of per-tier calibrated log-likelihood-ratios over available tiers.

    log LR(x) = sum_{i : tier i ran} [ log-odds_i(s_i) - log-odds_prior ]

    Each bracketed term is tier i's own evidence, measured against the
    base rate so that a tier carrying no information contributes ~0 rather
    than smuggling the prior in once per tier. A tier that did not run
    contributes exactly nothing, which is the correct handling of
    informative missingness (module docstring) and the reason this form
    was chosen over a fixed-width feature vector.

    ASSUMES conditional independence between tiers, which is KNOWN TO BE
    FALSE here — the tiers read the same text through related models. This
    model is therefore expected to be overconfident, and is reported as a
    reference point against the joint model rather than as the proposal.
    """

    calibrations: dict[str, _TierCalibration] = field(default_factory=dict)
    prior_log_odds: float = 0.0

    def fit(self, rows: list[dict], labels: list[int]) -> "NaiveBayesTierFusion":
        n_pos = sum(labels)
        n = len(labels)
        if 0 < n_pos < n:
            self.prior_log_odds = math.log(n_pos / (n - n_pos))
        else:
            self.prior_log_odds = 0.0

        for key in TIER_KEYS:
            pairs = [
                (r.get(key), y) for r, y in zip(rows, labels) if r.get(key) is not None
            ]
            if len({y for _, y in pairs}) < 2:
                # Tier never observed both classes — it cannot be
                # calibrated, so it is given a null calibration and will
                # contribute zero evidence. Recorded rather than silently
                # skipped.
                self.calibrations[key] = _TierCalibration(self.prior_log_odds, 0.0, len(pairs))
                continue
            self.calibrations[key] = _fit_logistic_1d(
                [s for s, _ in pairs], [y for _, y in pairs]
            )
        return self

    def score(self, tier_scores: dict) -> float:
        total = 0.0
        for key in TIER_KEYS:
            value = tier_scores.get(key)
            if value is None:
                continue  # did not run -> contributes no evidence
            cal = self.calibrations.get(key)
            if cal is None:
                continue
            total += _clamp(cal.log_odds(value) - self.prior_log_odds)
        return total


@dataclass
class PatternJointTierFusion:
    """
    A separate joint logistic model per availability pattern.

    Because the cascade produces only three patterns in practice, and each
    pattern has a FIXED set of present tiers, a joint model can be fitted
    within a pattern with no imputation at all — sidestepping both the
    missing-data problem and the conditional-independence assumption
    NaiveBayesTierFusion has to make.

    The cost is sample efficiency: each pattern gets its own fit, so a
    pattern with few samples yields a weak model. That trade is stated
    rather than hidden, and `min_samples` controls when a pattern is
    judged unfittable and falls back to the naive model.
    """

    min_samples: int = 20
    models: dict[tuple[str, ...], dict] = field(default_factory=dict)
    fallback: NaiveBayesTierFusion | None = None
    pattern_log_odds: dict[tuple[str, ...], float] = field(default_factory=dict)

    def fit(self, rows: list[dict], labels: list[int]) -> "PatternJointTierFusion":
        self.fallback = NaiveBayesTierFusion().fit(rows, labels)

        groups: dict[tuple[str, ...], list[int]] = {}
        for i, r in enumerate(rows):
            groups.setdefault(availability_pattern(r), []).append(i)

        for pattern, idxs in groups.items():
            ys = [labels[i] for i in idxs]
            n_pos, n = sum(ys), len(ys)
            # The pattern itself is evidence: P(malicious | this cascade
            # path) differs sharply between "regex fired" and "judge was
            # consulted". Recorded even when the within-pattern model
            # cannot be fitted.
            if 0 < n_pos < n:
                self.pattern_log_odds[pattern] = math.log(n_pos / (n - n_pos))
            elif n_pos == n:
                self.pattern_log_odds[pattern] = _MAX_ABS_LOG_LR
            else:
                self.pattern_log_odds[pattern] = -_MAX_ABS_LOG_LR

            if n < self.min_samples or n_pos in (0, n):
                continue

            per_tier = {}
            for key in pattern:
                vals = [rows[i].get(key) for i in idxs]
                if len(set(vals)) < 2:
                    continue  # constant within this pattern -> no signal
                per_tier[key] = _fit_logistic_1d(vals, ys)
            if per_tier:
                self.models[pattern] = per_tier
        return self

    def score(self, tier_scores: dict) -> float:
        pattern = availability_pattern(tier_scores)
        base = self.pattern_log_odds.get(pattern)
        model = self.models.get(pattern)

        if model is None:
            if base is not None:
                # Pattern seen but unfittable: the pattern's own base rate
                # is still real, usable evidence.
                return base
            assert self.fallback is not None
            return self.fallback.score(tier_scores)

        total = base if base is not None else 0.0
        for key, cal in model.items():
            value = tier_scores.get(key)
            if value is None:
                continue
            total += _clamp(cal.log_odds(value) - (base or 0.0))
        return total


def max_fusion_score(tier_scores: dict) -> float:
    """
    Reproduce L1's current `max()` rule from recorded tier scores, for a
    like-for-like baseline.

    Mirrors layer1.py exactly: tier 1 is a hard 0.92 early return; tiers 2
    and 3 combine by max; tier 4 overrides only if strictly greater. Kept
    here rather than re-deriving inline in the evaluator so the baseline
    cannot silently drift from the production rule it represents.
    """
    if tier_scores.get("tier1_regex"):
        return 0.92
    combined = 0.0
    for key in ("tier2_semantic", "tier3_prompt_guard"):
        value = tier_scores.get(key)
        if value is not None:
            combined = max(combined, value)
    judge = tier_scores.get("tier4_judge")
    if judge is not None and judge > combined:
        combined = judge
    return combined


# ---------------------------------------------------------------------------
# Production wiring support: persistence + score-scale mapping
# ---------------------------------------------------------------------------

def fused_score_to_unit(log_lr: float) -> float:
    """
    Map a fused log-likelihood-ratio onto [0, 1].

    WHY THIS IS NEEDED. The fusion's natural output is a log-LR — measured
    range [0.994, 4.339] when fitted on WildJailbreak — but L1's entire
    interface assumes a score in [0, 1]: `L1_WARN_THRESHOLD` (0.4391),
    `L1_SEMANTIC_MEDIUM`/`HIGH` (the judge band), `L1_BLOCK_THRESHOLD`
    (0.85), and `rescale_layer_score`'s piecewise map onto the shared
    pipeline scale. Emitting a raw log-LR as `L1Result.score` would
    silently break every one of them.

    WHY A LOGISTIC MAP IS SAFE. It is strictly monotone, so it preserves
    ranking exactly — and ranking is the entire measured gain (AUROC
    0.6457 -> 0.7426 cross-corpus). No information is lost; only the axis
    changes. Because L1's operating point is set CONFORMALLY from benign
    data rather than being a fixed constant, the threshold is simply
    re-derived on the new axis: any monotone reparameterisation is
    admissible, and this one keeps the [0,1] contract every consumer
    depends on.

    WHAT IT IS NOT. The output is not a calibrated probability of attack —
    that would require a base rate this system cannot know, and claiming
    it would be an overstatement. It is a bounded, monotone score.
    """
    return 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, log_lr))))


def save_fusion_model(model: "PatternJointTierFusion", path) -> None:
    """
    Freeze a fitted model to JSON.

    A production fusion must be a FROZEN ARTIFACT, not something refitted
    at import time: the whole point of the cross-corpus protocol is that
    the shipped model was fitted on a named corpus that can be audited.
    Storing the fitted coefficients makes "which data produced this
    decision rule" answerable, in the same spirit as
    `results_ledger.py`'s code-and-data hashing.
    """
    import json
    from pathlib import Path

    payload = {
        "kind": "PatternJointTierFusion",
        "min_samples": model.min_samples,
        "pattern_log_odds": {"|".join(k): v for k, v in model.pattern_log_odds.items()},
        "models": {
            "|".join(pattern): {tier: {"a": cal.a, "b": cal.b, "n_fit": cal.n_fit}
                                for tier, cal in per_tier.items()}
            for pattern, per_tier in model.models.items()
        },
        "fallback": {
            "prior_log_odds": model.fallback.prior_log_odds if model.fallback else 0.0,
            "calibrations": {
                tier: {"a": cal.a, "b": cal.b, "n_fit": cal.n_fit}
                for tier, cal in (model.fallback.calibrations if model.fallback else {}).items()
            },
        },
    }
    Path(path).write_text(json.dumps(payload, indent=2), encoding="utf-8")


def load_fusion_model(path) -> "PatternJointTierFusion":
    """Reload a frozen model. Inverse of save_fusion_model."""
    import json
    from pathlib import Path

    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if payload.get("kind") != "PatternJointTierFusion":
        raise ValueError(f"unexpected model kind {payload.get('kind')!r}")

    model = PatternJointTierFusion(min_samples=payload["min_samples"])
    model.pattern_log_odds = {
        tuple(k.split("|")) if k else (): v
        for k, v in payload["pattern_log_odds"].items()
    }
    model.models = {
        tuple(k.split("|")) if k else (): {
            tier: _TierCalibration(c["a"], c["b"], c["n_fit"]) for tier, c in per_tier.items()
        }
        for k, per_tier in payload["models"].items()
    }
    fb = NaiveBayesTierFusion()
    fb.prior_log_odds = payload["fallback"]["prior_log_odds"]
    fb.calibrations = {
        tier: _TierCalibration(c["a"], c["b"], c["n_fit"])
        for tier, c in payload["fallback"]["calibrations"].items()
    }
    model.fallback = fb
    return model
