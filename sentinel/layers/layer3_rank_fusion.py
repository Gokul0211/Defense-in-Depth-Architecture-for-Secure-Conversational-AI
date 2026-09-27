"""
L3's rank-fusion score: three session statistics, each read against a frozen
benign reference, averaged.

WHY L3 NEEDED A DIFFERENT SCORE, and why §8b.3's ceiling does not apply to this one.
§8b.3 established that L3's two substantive terms are exactly inverted between its
corpora -- `harm x 0.50` scores 0.4392 on MHJ (below chance) and 0.6524 on
tom-gibbs, while `drift x smooth x 0.25` scores 0.7110 and 0.4137 -- and that no
combination rule over THOSE TERMS beats production on both, including oracle
rank-normalised ones. That result stands.

What it did not test is a rule over the families that actually carry signal. Per
feature, the picture is complementary rather than symmetrically inverted:

    feature              MHJ      tom-gibbs   character
    smooth_max           0.8201   0.4947      works on MHJ, CHANCE on tom-gibbs
    harm_max             0.4833   0.6564      chance on MHJ, works on tom-gibbs
    esc_mean             0.6077   0.6788      works on BOTH

A signal at chance adds noise to an average; an inverted one fights it. Averaging
these three therefore transfers where averaging the production terms cannot.

THE MECHANISM THIS ENCODES, stated plainly because it is counter-intuitive: **on
MHJ, malicious conversations drift LESS than benign ones** (drift-from-first 0.8692
vs 0.9938). Real human multi-turn jailbreaks stay coherent while escalating, which
inverts L3's founding assumption. `smooth_max` captures exactly that, and it is not
a length artifact -- turn-count-matched it strengthens, 0.8201 -> 0.9519.

WHY A FROZEN REFERENCE. Raw feature scales are not comparable across corpora, so the
three are combined through their empirical CDFs against a benign reference. Ranking
within the scored corpus would be transductive and is not deployable, so the
reference is `custom_l3`'s 39 benign sessions -- a third corpus, label-free, frozen
at build time, and used nowhere as a reported row for board items #2 or #6. That is
the same role Alpaca plays for `L1_WARN_THRESHOLD`.

MEASURED (session-level, on the §8b.3 substrate):

    reference                              MHJ      tom-gibbs
    production score                       0.6139   0.5949
    rank within the corpus (transductive)  0.7045   0.6466
    rank against the OTHER corpus          0.7012   0.7121
    **frozen custom_l3 benign (shipped)**  **0.6632**  **0.6350**

The frozen reference is weaker than the cross-corpus one because 39 sessions make a
coarse CDF; a larger disjoint L3 corpus would likely recover the gap, and that is
recorded as the next step rather than left implicit.

STREAMING. All three statistics are running aggregates over the session so far --
max smoothness, max harm alignment, mean escalation alignment -- so this computes
incrementally per turn exactly as the production score does.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

_ARTIFACT = Path(__file__).resolve().parents[1] / "core" / "artifacts" / \
    "l3_rank_reference.json"
_ref_cache = None
_REF_MISSING = object()

FEATURES = ("smooth_max", "harm_max", "esc_mean")


def _get_reference():
    """The frozen benign CDFs, or None if the artifact is absent."""
    global _ref_cache
    if _ref_cache is _REF_MISSING:
        return None
    if _ref_cache is not None:
        return _ref_cache
    if not _ARTIFACT.exists():
        _ref_cache = _REF_MISSING
        return None
    d = json.loads(_ARTIFACT.read_text(encoding="utf-8"))
    ref = d.get("reference") or {}
    if not all(k in ref and ref[k] for k in FEATURES):
        logger.warning("l3_rank_reference.json missing a feature; rank fusion off")
        _ref_cache = _REF_MISSING
        return None
    _ref_cache = {k: sorted(float(v) for v in ref[k]) for k in FEATURES}
    return _ref_cache


def reset_rank_reference_cache() -> None:
    global _ref_cache
    _ref_cache = None


def _cdf(x: float, ref: list) -> float:
    """Fraction of the frozen benign reference at or below x."""
    lo, hi = 0, len(ref)
    while lo < hi:
        mid = (lo + hi) // 2
        if ref[mid] <= x:
            lo = mid + 1
        else:
            hi = mid
    return lo / len(ref)


def rank_fusion_score(smooth_max: float, harm_max: float,
                      esc_mean: float) -> float | None:
    """Mean of the three features' benign-CDF values, in [0, 1].

    Returns None when the reference artifact is unavailable, so the caller keeps
    the production score rather than substituting a guess.
    """
    ref = _get_reference()
    if ref is None:
        return None
    vals = (_cdf(float(smooth_max), ref["smooth_max"]),
            _cdf(float(harm_max), ref["harm_max"]),
            _cdf(float(esc_mean), ref["esc_mean"]))
    return float(sum(vals) / len(vals))


class SessionStats:
    """Running session aggregates for the three fusion features.

    Deliberately tiny and independent of L3's other session state, so enabling the
    mode cannot perturb the production path's history handling.
    """

    __slots__ = ("smooth_max", "harm_max", "esc_sum", "esc_n")

    def __init__(self):
        self.smooth_max = 0.0
        self.harm_max = 0.0
        self.esc_sum = 0.0
        self.esc_n = 0

    def update(self, smoothness: float, harm: float, esc: float,
               has_previous_turn: bool = True) -> None:
        """Fold one turn in.

        `has_previous_turn` is load-bearing and its absence was a real bug. L3 sets
        `velocity = 0.0` on the FIRST turn of a session because there is nothing to
        compare against, so `smoothness = 1 - velocity = 1.0` -- a phantom maximum.
        Folding that in made `smooth_max` equal 1.0 for every session from turn one,
        which saturated the CDF and collapsed MHJ to AUROC 0.4818 at FPR 1.0 in a
        real run, against 0.6632 for the identical rule offline. The offline
        reference statistic is computed over CONSECUTIVE-TURN steps only, so
        smoothness is skipped here until a predecessor exists.
        """
        if has_previous_turn:
            self.smooth_max = max(self.smooth_max, float(smoothness))
        self.harm_max = max(self.harm_max, float(harm))
        self.esc_sum += float(esc)
        self.esc_n += 1

    @property
    def esc_mean(self) -> float:
        return self.esc_sum / self.esc_n if self.esc_n else 0.0

    def score(self) -> float | None:
        return rank_fusion_score(self.smooth_max, self.harm_max, self.esc_mean)
