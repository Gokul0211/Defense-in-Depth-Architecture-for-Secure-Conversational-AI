"""
Cost-Aware Sequential Triage — Contribution B (research roadmap doc, Section 3).

THE GAP THIS CLOSES
--------------------
Every layer in the pipeline runs, in fixed order, for every request that
touches it — there's no notion of "how much evidence is enough". A request
L1 already scores at 0.02 still pays for L3's embedding computation and L5's
full output scan. There's also no formal answer anywhere in the system to
"how many layers do I need to run to be confident, given a target error
rate" — the fixed-cascade design was never asked that question.

THE MECHANISM: Wald's Sequential Probability Ratio Test (SPRT)
----------------------------------------------------------------
Treat the pipeline as a sequential hypothesis test between H1 ("this session
is malicious") and H0 ("this session is benign"). After each layer produces
a score, accumulate the log-likelihood ratio:

    log_LLR_n = sum_{i=1}^{n} log[ P(score_i | malicious) / P(score_i | benign) ]

and compare against two boundaries derived from target error rates (alpha =
false-positive rate, beta = false-negative rate), via Wald's approximation:

    log_A = log( (1 - beta) / alpha )   -- cross this: BLOCK
    log_B = log( beta / (1 - alpha) )   -- cross this: ALLOW
    otherwise: CONTINUE to the next layer

Wald's theorem guarantees this stopping rule is optimal in *expected number
of layers run* for the given (alpha, beta) — among all sequential tests
achieving those error bounds, none has a lower expected sample size under
either hypothesis. That is a provable, citable property, not a heuristic.

WHAT THIS MODULE DOES AND DOESN'T CLAIM
-----------------------------------------
The mechanism above is fully implemented and its *statistical* correctness
(does the stopping rule behave the way Wald's theorem says it should) is
independently verifiable via simulation — that doesn't require real attack
data, only correctly-specified synthetic score distributions, and this
module's test suite does exactly that (see tests/test_sequential_triage.py's
TestSPRTStatisticalProperties).

What genuinely does require the labeled corpus from the evaluation plan
doc: fitting LikelihoodModel on this pipeline's *actual* per-layer score
distributions for real attacks vs. real benign traffic, rather than the
synthetic distributions used here for validation. Until that corpus exists,
`LikelihoodModel.fit()` will raise loudly rather than silently accept fewer
than 2 examples per class — there is no honest way to fit a density with
less data than that, and pretending otherwise would produce a
confident-looking but meaningless engine.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Sequence

import numpy as np
from sklearn.neighbors import KernelDensity


class Decision(str, Enum):
    BLOCK = "BLOCK"
    ALLOW = "ALLOW"
    CONTINUE = "CONTINUE"


class LikelihoodModel:
    """
    Fits P(score | malicious) and P(score | benign) for one layer's score
    distribution via 1D kernel density estimation (Gaussian kernel), and
    exposes the resulting log-likelihood-ratio function.

    KDE (rather than a parametric family like Beta) is the right default
    here because layer score distributions are not known to be unimodal or
    symmetric — L1's Tier-1 regex fast path, for instance, produces a sharp
    spike at score=1.0 alongside a continuous tail from the Tier-2 semantic
    scorer, which a Beta fit would smooth away. `bandwidth` is a tunable
    smoothing parameter; the default (0.08) is a reasonable starting point
    for scores in [0, 1], not a calibrated value.
    """

    def __init__(self, layer_name: str, bandwidth: float = 0.08):
        self.layer_name = layer_name
        self.bandwidth = bandwidth
        self._malicious_kde: KernelDensity | None = None
        self._benign_kde: KernelDensity | None = None
        self._fitted = False

    def fit(self, scores: Sequence[float], labels: Sequence[int]) -> None:
        """labels: 1 = malicious, 0 = benign."""
        scores_arr = np.asarray(scores, dtype=float).reshape(-1, 1)
        labels_arr = np.asarray(labels, dtype=int)
        if len(scores_arr) != len(labels_arr):
            raise ValueError("scores and labels must be the same length")

        mal = scores_arr[labels_arr == 1]
        ben = scores_arr[labels_arr == 0]
        if len(mal) < 2 or len(ben) < 2:
            raise ValueError(
                f"LikelihoodModel for layer '{self.layer_name}' needs at "
                f"least 2 examples of each class to fit a density; got "
                f"{len(mal)} malicious, {len(ben)} benign. This is the "
                f"same labeled-corpus dependency described in the "
                f"evaluation plan document — there is no statistically "
                f"honest way to fit this with less data."
            )

        self._malicious_kde = KernelDensity(bandwidth=self.bandwidth).fit(mal)
        self._benign_kde = KernelDensity(bandwidth=self.bandwidth).fit(ben)
        self._fitted = True

    @property
    def fitted(self) -> bool:
        return self._fitted

    def log_likelihood_ratio(self, score: float) -> float:
        """log[ P(score | malicious) / P(score | benign) ]. Positive values
        favor malicious, negative values favor benign."""
        if not self._fitted:
            raise RuntimeError(f"LikelihoodModel for '{self.layer_name}' has not been fit yet.")
        x = np.array([[score]])
        log_p_mal = self._malicious_kde.score_samples(x)[0]
        log_p_ben = self._benign_kde.score_samples(x)[0]
        return float(log_p_mal - log_p_ben)


@dataclass(frozen=True)
class SPRTBoundaries:
    log_A: float  # cross upward -> BLOCK
    log_B: float  # cross downward -> ALLOW
    alpha: float
    beta: float

    @classmethod
    def from_error_rates(cls, alpha: float, beta: float) -> "SPRTBoundaries":
        """
        Wald's approximation:  A = (1-beta)/alpha,  B = beta/(1-alpha).

        alpha: target false-positive rate (probability of blocking a truly
               benign session).
        beta:  target false-negative rate (probability of allowing a truly
               malicious session).

        These boundaries are an approximation — the true achieved error
        rates are guaranteed by Wald's theorem to be *at most* alpha and
        beta respectively (the approximation is conservative, not exact),
        at the cost of a slightly larger expected sample size than the
        theoretical optimum. See TestSPRTStatisticalProperties for an
        empirical check of this bound via simulation.
        """
        if not (0.0 < alpha < 1.0) or not (0.0 < beta < 1.0):
            raise ValueError("alpha and beta must both be in (0, 1)")
        A = (1.0 - beta) / alpha
        B = beta / (1.0 - alpha)
        return cls(log_A=math.log(A), log_B=math.log(B), alpha=alpha, beta=beta)


@dataclass
class TriageResult:
    decision: Decision
    layers_consulted: list[str]
    final_log_llr: float
    exhausted: bool = False  # True if the layer sequence ran out before a boundary was crossed


class SequentialTriageEngine:
    """
    Ties together per-layer LikelihoodModels and SPRT boundaries into a
    decision procedure over an ordered sequence of layer scores, stopping as
    soon as enough evidence has accumulated in either direction.
    """

    def __init__(self, boundaries: SPRTBoundaries):
        self.boundaries = boundaries
        self.models: dict[str, LikelihoodModel] = {}

    def register_model(self, model: LikelihoodModel) -> None:
        if not model.fitted:
            raise ValueError(
                f"Cannot register an unfit LikelihoodModel for layer "
                f"'{model.layer_name}' — call .fit() first."
            )
        self.models[model.layer_name] = model

    def decide(self, log_llr: float) -> Decision:
        if log_llr >= self.boundaries.log_A:
            return Decision.BLOCK
        if log_llr <= self.boundaries.log_B:
            return Decision.ALLOW
        return Decision.CONTINUE

    def run(self, layer_scores: Sequence[tuple[str, float]]) -> TriageResult:
        """
        Run against an ordered sequence of (layer_name, score) — the full
        sequence that *would* run under the naive always-run-all baseline —
        stopping as soon as a boundary is crossed. `len(result.layers_consulted)`
        vs `len(layer_scores)` is the direct, reportable "layers saved" number
        described in the roadmap doc (Section 3).
        """
        log_llr = 0.0
        consulted: list[str] = []
        for layer_name, score in layer_scores:
            model = self.models.get(layer_name)
            if model is None:
                raise KeyError(f"No LikelihoodModel registered for layer '{layer_name}'")
            log_llr += model.log_likelihood_ratio(score)
            consulted.append(layer_name)
            decision = self.decide(log_llr)
            if decision != Decision.CONTINUE:
                return TriageResult(decision=decision, layers_consulted=consulted, final_log_llr=log_llr)

        # Ran out of layers without crossing a boundary. This means the
        # configured layer sequence wasn't informative enough to reach the
        # target (alpha, beta) confidence on this particular input — fail
        # toward whichever side the accumulated evidence leans, but mark
        # `exhausted=True` so a caller can distinguish a confident decision
        # from a forced one (e.g. to fall back to the fixed-cascade decision
        # instead, per the roadmap doc's fallback-mode note).
        decision = Decision.BLOCK if log_llr > 0 else Decision.ALLOW
        return TriageResult(decision=decision, layers_consulted=consulted, final_log_llr=log_llr, exhausted=True)
