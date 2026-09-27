"""
L1 Tier 3, with a selectable classifier and a PIGuard ensemble.

WHAT THIS REPLACES. Tier 3 has always been Prompt-Guard-86M's `jailbreak` head. It
is the weakest link in L1 by two independent measurements:

  * RANKING. Threshold-free AUROC on every corpus of ours carrying both classes
    (`scratch/l1x/guard_bench.py`): sentinel_bench 0.6975, wildjailbreak 0.5493,
    bipia_local 0.8200 -- against PIGuard's 0.9316 / 0.6619 / 0.9448.
  * OVER-DEFENSE. It is the *irreducible* source of L1's false positives on
    adversarially-styled benign text. The benign samples no threshold can suppress
    are 8/339 on NotInject and 14/210 on WildJailbreak benign, and **every one of
    them is Tier 3 saturating at ~1.000** (`scratch/l1x/LEDGER.md` EXP-006).

THREE MODES, selected by `config.L1_TIER3_MODE`:

  "prompt_guard"  the shipped tier, byte-identical. DEFAULT.
  "piguard"       PIGuard alone. Best over-defense at every budget measured
                  (NotInject 0.0973 at a 0.5 % Alpaca budget, against the shipped
                  tier's 0.2566), but NOT a Pareto improvement -- its WildJailbreak
                  recall at that budget is 0.4065 against the shipped 0.5620.
  "ensemble"      the unweighted mean of both, on a shared axis. The only candidate
                  that is no worse than the shipped tier on any corpus at any
                  budget.

WHY A SHARED AXIS IS NOT OPTIONAL. Prompt Guard's 99th-percentile score on Alpaca
benign is **0.000163**; PIGuard's is **0.367803** -- a 2,250x difference. Averaging
or maxing those raw would be arithmetic on two incommensurable scales, which is this
project's recurring RCA-#3 error (L3 2026-07-25, L1 2026-09-18, L2's two warn
anchors, and once by hand during the L2 rebuild). Each model is therefore passed
through its own frozen benign-quantile function first, so a score of 0.7 means the
same thing -- *above 70 % of benign traffic* -- for both.

`max()` on that shared axis was measured and REJECTED (sentinel_bench 0.9506 ->
0.8287, wildjailbreak 0.6071 -> 0.5717 versus the mean): a max is decided by
whichever model is noisier on the input, whereas a mean requires both to agree.

WHY THE RESULT IS MAPPED BACK ONTO PROMPT GUARD'S AXIS, and this is the load-bearing
design decision. L1 fuses tiers with `max()` against a cosine-scaled Tier 2, and
both `L1_WARN_THRESHOLD` and the judge-invocation band (0.30, 0.75] are calibrated
for the axis Tier 3 currently publishes on. Emitting a raw quantile would silently
move every one of those. So the ensemble quantile is mapped back through Prompt
Guard's OWN benign knots. Because a quantile transform composed with its inverse is
the identity on the reference distribution, **the benign output distribution is
identical to the shipped tier's by construction** -- Tier 3's false-positive
contribution at any threshold is preserved exactly -- while the ORDERING becomes the
ensemble's. That is precisely the intended change: same benign behaviour, better
ranking, no threshold re-derivation required.

The artifact is frozen by `sentinel/eval/fit_tier3_ensemble.py` and fitted only on
label-free Alpaca benign rows 500-4500, disjoint from rows 0-500 that
`conformal_l1_eval.py` calibrates `L1_WARN_THRESHOLD` on. No labels, no malicious
corpus, no weights.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import numpy as np

logger = logging.getLogger(__name__)

_ARTIFACT = Path(__file__).resolve().parents[1] / "core" / "artifacts" / \
    "l1_tier3_ensemble.json"

_art_cache = None
_piguard_cache = None
_piguard_failed = False

VALID_MODES = ("prompt_guard", "piguard", "ensemble", "agreement")


def _get_artifact():
    """The frozen benign-quantile reference. None if absent, which makes every
    non-default mode fail soft back to the shipped tier rather than guess."""
    global _art_cache
    if _art_cache is None:
        if not _ARTIFACT.exists():
            return None
        d = json.loads(_ARTIFACT.read_text(encoding="utf-8"))
        _art_cache = {
            "q": np.asarray(d["quantiles"], dtype=float),
            "pg": np.asarray(d["prompt_guard_jailbreak_knots"], dtype=float),
            "pi": np.asarray(d["piguard_injection_knots"], dtype=float),
        }
    return _art_cache


def reset_tier3_cache() -> None:
    """Drop cached artifact/model handles. For tests that switch modes."""
    global _art_cache, _piguard_cache, _piguard_failed
    _art_cache = None
    _piguard_cache = None
    _piguard_failed = False


def _get_piguard():
    """Lazy PIGuard singleton. A load failure is recorded once and then the tier
    degrades to Prompt Guard alone -- never to score 0.0, which would read as
    'benign' for every input."""
    global _piguard_cache, _piguard_failed
    if _piguard_failed:
        return None
    if _piguard_cache is None:
        try:
            from sentinel.eval.baselines.injection_guards import PIGuardBaseline
            _piguard_cache = PIGuardBaseline()
            _piguard_cache._load()
        except Exception as e:          # pragma: no cover - environment dependent
            logger.warning(f"PIGuard unavailable, Tier 3 falls back to Prompt "
                           f"Guard alone: {e}")
            _piguard_failed = True
            _piguard_cache = None
    return _piguard_cache


def _to_quantile(x: np.ndarray, knots: np.ndarray, q: np.ndarray) -> np.ndarray:
    """Fraction of the benign reference scoring at or below x."""
    idx = np.searchsorted(knots, np.asarray(x, dtype=float), side="left")
    return q[np.clip(idx, 0, len(q) - 1)]


def _from_quantile(u: np.ndarray, knots: np.ndarray, q: np.ndarray) -> np.ndarray:
    """Inverse of `_to_quantile` against the same reference."""
    idx = np.searchsorted(q, np.asarray(u, dtype=float), side="left")
    return knots[np.clip(idx, 0, len(knots) - 1)]


def tier3_scores(texts: list[str], pg_raw: list[float] | None = None) -> list[float]:
    """Tier 3 for a batch, on the SHIPPED tier-3 axis whatever the mode.

    `pg_raw` lets a caller that already ran Prompt Guard pass its jailbreak
    probabilities in rather than paying for a second forward pass.
    """
    from sentinel import config as cfg

    mode = getattr(cfg, "L1_TIER3_MODE", "prompt_guard")
    if pg_raw is None:
        from sentinel.eval.baselines.prompt_guard import PromptGuardBaseline
        pg = PromptGuardBaseline()
        pg_raw = [r["jailbreak_prob"] for r in pg.probs_batch(texts)]
    pg_arr = np.asarray(pg_raw, dtype=float)

    if mode == "prompt_guard":
        return [float(v) for v in pg_arr]

    guard = _get_piguard()

    if mode == "agreement":
        # THE OVER-DEFENSE FIX (board item #10). A sample is injection-like only if
        # BOTH independent injection classifiers say so. A product is an AND; the
        # `ensemble` mean below is not, which is why it did not reduce false
        # positives at all.
        #
        # WHY AN AND IS THE RIGHT OPERATOR HERE, measured rather than assumed. On
        # NotInject -- benign text deliberately seeded with injection trigger words
        # -- Prompt Guard's benign head is SATURATED: `1 - benign_prob` is 0.9963
        # for the samples L1 flags and 0.9966 for those it does not, i.e. no
        # separation whatever. It believes all 339 benign samples are non-benign and
        # merely splits them between `injection` and `jailbreak`, so `jailbreak_prob`
        # is close to arbitrary in this regime. PIGuard does separate them (0.4948
        # vs 0.1009). Requiring agreement suppresses the arbitrary half.
        #
        # Measured, full cascade, conformal tau on Alpaca rows 0-500 at alpha=0.01:
        #   NotInject FPR   0.0590 -> 0.0383   (20 -> 13 of 339)
        #   Alpaca FPR      0.0055 -> 0.0051
        #   WildJailbreak benign FPR 0.1667 -> 0.1524
        #   sentinel_bench recall / AUROC   unchanged (0.4407 / 0.8094)
        #   TensorTrust recall   0.8439 -> 0.8298
        #   WildJailbreak recall 0.2560 -> 0.2455, AUROC 0.5694 -> 0.5729
        # As a hard-negative separator (attacks vs NotInject benign) the product
        # scores AUROC 0.8790 against `jailbreak_prob`'s 0.7794, so this is improved
        # discrimination and not merely a suppressed score.
        #
        # NO AXIS PROBLEM, which is why no threshold needs re-deriving: both factors
        # are probabilities in [0, 1], so the product is too, and it is always <=
        # `jailbreak_prob`. Tier 3 can therefore only move DOWN, leaving
        # L1_WARN_THRESHOLD and the judge band (0.30, 0.75] meaning what they were
        # calibrated to mean.
        if guard is None:
            return [float(v) for v in pg_arr]
        pi = np.asarray(guard.injection_probs(list(texts)), dtype=float)
        return [float(v) for v in pg_arr * pi]

    art = _get_artifact()
    if art is None or guard is None:
        # Fail soft to the shipped tier. Silently scoring 0.0 here would turn a
        # missing model into "everything is benign".
        return [float(v) for v in pg_arr]

    pi_arr = np.asarray(guard.injection_probs(list(texts)), dtype=float)
    pi_q = _to_quantile(pi_arr, art["pi"], art["q"])

    if mode == "piguard":
        u = pi_q
    else:                                # "ensemble"
        pg_q = _to_quantile(pg_arr, art["pg"], art["q"])
        u = 0.5 * (pg_q + pi_q)

    # Back onto Prompt Guard's axis, so L1_WARN_THRESHOLD and the judge band keep
    # meaning what they were calibrated to mean. See the module docstring.
    return [float(v) for v in _from_quantile(u, art["pg"], art["q"])]


def tier3_score(text: str, pg_raw: float | None = None) -> float:
    """Single-text convenience wrapper."""
    return tier3_scores([text], None if pg_raw is None else [pg_raw])[0]
