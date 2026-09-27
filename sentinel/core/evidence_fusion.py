"""
Contribution F — anytime-valid cross-layer evidence fusion via e-values.

WHAT PROBLEM THIS SOLVES, AND WHY THE OBVIOUS ALTERNATIVES DO NOT
--------------------------------------------------------------------
Three measurements from 2026-09-18 constrain the design, and between them
they rule out every simpler option:

1. **`max()` discards recoverable signal.** A calibrated likelihood-ratio
   fusion of L1's own four tier scores lifts WildJailbreak AUROC
   0.6457 -> 0.7652 (+12.0 points) with no new inputs — same tiers, same
   samples, only the combination rule (plan item 3B.3). The information is
   demonstrably there.

2. **A FITTED fusion does not transfer across corpora.** That same
   calibrated fusion, fitted on sentinel_bench and evaluated on
   WildJailbreak, LOSES 7.2 points. This is the third independent instance
   of the same phenomenon in this project — Contribution D's conformal
   guarantee fails cross-corpus, L2's BIPIA operating point produces FPR
   0.9245 on sentinel_bench, and now this. **So the fusion rule must not
   depend on estimating an attack distribution.**

3. **The layers are not independent.** L1 and L2 share 15 of their anchor
   templates (39.5% of the union) because both lists were re-derived from
   the same corpus by the same method; within-benign Pearson r = 0.9532,
   and 18 of 112 sentinel_bench samples score BIT-IDENTICALLY across the
   two layers. **So a merging rule that assumes independence is invalid
   here**, and invalid in the dangerous direction: it overstates evidence
   on benign sessions, which is exactly where a false-alarm guarantee is
   calibrated. The guarantee would read as holding while failing.

An e-value construction answers all three. It is calibrated from
BENIGN-ONLY data (no attack distribution to estimate, hence nothing to
transfer), it admits merging rules valid under ARBITRARY dependence, and
it is anytime-valid so a multi-turn session can be monitored continuously
rather than judged once.

THE GUARANTEE
----------------
An e-value E for the null (benign) satisfies E_benign[E] <= 1. By Ville's
inequality, for any non-negative supermartingale started at 1,

    P_benign( sup_t E_t >= 1/alpha ) <= alpha.

So alarming the first time accumulated evidence reaches 1/alpha controls
the false-alarm probability over the WHOLE session at level alpha — under
optional stopping, which is what a deployed guardrail actually does: it
looks after every turn and may stop at any of them. A fixed-threshold test
applied repeatedly has no such property, and its false-alarm rate grows
with conversation length.

MERGING UNDER DEPENDENCE — THE LOAD-BEARING CHOICE
-----------------------------------------------------
Given e-values E_1..E_k from k layers:

  * PRODUCT is an e-value only under (conditional) independence. Given
    finding 3 above, it is NOT valid for L1/L2 here.
  * The ARITHMETIC MEAN is an e-value under ARBITRARY dependence
    (Vovk & Wang, "E-values: calibration, combination and applications").
    It costs power relative to the product, and buys validity that this
    system's measured r = 0.9532 says the product does not have.

`mean` is therefore the default. `product` is offered only so the cost of
the dependence assumption can be MEASURED rather than argued about — it
must never be the shipped default without an independence check.

STATUS
---------
Mechanism only. Nothing here is wired into any layer or into app.py. It is
built so Contribution F's claims can be tested against SPLIT-Bench, and
its own gate (measured false-alarm rate must track nominal alpha) must
pass before any adoption is proposed.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field


# Calibrator exponent for the p-to-e transform. Any kappa in (0,1) gives a
# valid e-value; smaller kappa concentrates more weight on very small
# p-values (sharper against strong evidence, weaker against moderate).
# 0.5 is the conventional default and the one Vovk & Wang use as the
# worked example.
_EVALUE_KAPPA = 0.5


def calibrate_evalue_threshold(
    benign_scores: list[float], score: float, kappa: float = _EVALUE_KAPPA
) -> float:
    """
    Convert a layer score into an e-value using the benign empirical
    distribution — no attack model, nothing fitted to a malicious corpus,
    so there is nothing that has to transfer across corpora.

    Two steps:

    1. **Empirical right-tail p-value**, with the standard conservative
       (n+1) correction so it stays valid at finite sample size:

           p_hat = (1 + #{benign >= score}) / (n + 1)

       This is the same correction `conformal_risk_control` already uses,
       so the two mechanisms share a convention rather than each inventing
       one.

    2. **p-to-e calibration**: e = kappa * p^(kappa - 1).

    BUG FIX (2026-09-18, caught by this module's own null-expectation
    test): the first version returned `1 / p_hat` and called it an
    e-value. It is not. For a uniform p-value, E[1/p] = integral of 1/u on
    (0,1] = INFINITY, so the defining property E_null[E] <= 1 fails
    unboundedly. The empirical consequence was immediate and total — a
    measured benign alarm rate of **1.000** against a nominal alpha of
    0.05, i.e. every benign session alarmed. Ville's inequality then
    guarantees nothing, and the whole construction would have reported a
    false-alarm bound it did not have.

    The calibrator family above is the standard fix and is exactly
    valid: E[kappa * U^(kappa-1)] = kappa * integral of u^(kappa-1) on
    (0,1] = kappa * (1/kappa) = 1 for any kappa in (0,1).
    """
    if not benign_scores:
        raise ValueError("benign_scores must be non-empty")
    if not 0.0 < kappa < 1.0:
        raise ValueError(f"kappa must be in (0, 1), got {kappa}")
    n = len(benign_scores)
    exceed = sum(1 for s in benign_scores if s >= score)
    p_hat = (1.0 + exceed) / (n + 1.0)
    return kappa * (p_hat ** (kappa - 1.0))


def max_attainable_evalue(n_benign: int, kappa: float = _EVALUE_KAPPA) -> float:
    """
    Largest e-value a single layer can possibly emit, given `n_benign`
    calibration samples.

    WHY THIS EXISTS — a measured trap, 2026-09-19. The empirical p-value
    has a floor: the smallest value `calibrate_evalue_threshold` can return
    is p = 1/(n+1), achieved when the score exceeds every benign sample. So

        e_max = kappa * (n + 1) ** (1 - kappa)

    and because `merge_evalues("mean")` is an AVERAGE, the merged e-value is
    bounded by the same number no matter how many layers agree. If
    `e_max < 1/alpha`, the alarm threshold is **unreachable by
    construction** and the measured TPR is 0 for arithmetic reasons that
    have nothing to do with detection.

    That is exactly what happened on first run. With 64 benign calibration
    samples and kappa=0.5, e_max = 4.03 against a Ville threshold of 20 for
    alpha=0.05 — TPR 0.0000, alongside an AUROC of 0.9891 that showed the
    ranking was near-perfect. Without this function the contradiction looks
    like a detector failure instead of a sample-size requirement.

    The product merge is NOT bounded this way (it multiplies), which is why
    it alarmed at all in that run — but it is invalid under the dependence
    these layers are measured to have, so it is not a way out.
    """
    if n_benign < 1:
        raise ValueError("n_benign must be >= 1")
    if not 0.0 < kappa < 1.0:
        raise ValueError(f"kappa must be in (0, 1), got {kappa}")
    return kappa * ((n_benign + 1.0) ** (1.0 - kappa))


def optimal_kappa(n_benign: int) -> float:
    """
    The kappa maximising `max_attainable_evalue` for a given calibration
    size: kappa* = 1 / ln(n + 1).

    Derivation: maximise f(k) = k * (n+1)^(1-k) = k * exp((1-k) * L) with
    L = ln(n+1). f'(k) = exp((1-k)L) * (1 - kL), which is zero at k = 1/L.

    Worth using rather than the conventional 0.5 precisely because the
    binding constraint here is reachability, not sharpness: at n = 184,
    kappa=0.5 gives e_max 6.80 while kappa* = 0.192 gives 13.04 — the
    difference between alpha = 0.147 and alpha = 0.077 being reachable at
    all. Any kappa in (0,1) yields a VALID e-value, so this is a power
    choice, not a validity one.
    """
    if n_benign < 2:
        raise ValueError("n_benign must be >= 2")
    return 1.0 / math.log(n_benign + 1.0)


def min_benign_for_alpha(alpha: float, kappa: float | None = None) -> int:
    """
    Smallest benign calibration size at which the Ville threshold 1/alpha is
    reachable at all. `kappa=None` uses the optimal kappa at each size.

    For alpha = 0.05 this is **312** at optimal kappa (and 1,599 at the
    conventional kappa = 0.5) — a concrete experimental-design requirement,
    not a tuning knob: below it, no amount of attack signal can trigger an
    alarm through the mean merge.
    """
    if not 0.0 < alpha < 1.0:
        raise ValueError(f"alpha must be in (0, 1), got {alpha}")
    target = ville_threshold(alpha)
    n = 2
    while n < 10_000_000:
        k = optimal_kappa(n) if kappa is None else kappa
        if max_attainable_evalue(n, k) >= target:
            return n
        n += 1
    raise ValueError(f"alpha={alpha} unreachable below n=1e7")


def smallest_reachable_alpha(n_benign: int, kappa: float | None = None) -> float:
    """Tightest false-alarm bound this calibration size can certify."""
    k = optimal_kappa(n_benign) if kappa is None else kappa
    return 1.0 / max_attainable_evalue(n_benign, k)


def merge_evalues(evalues: list[float], method: str = "mean") -> float:
    """
    Combine per-layer e-values into one.

    `mean`     — valid under ARBITRARY dependence (Vovk & Wang). The default,
                 because this system's layers are measured to be dependent
                 (L1/L2 within-benign r = 0.9532).
    `product`  — valid only under independence. Strictly more powerful when
                 that holds, invalid when it does not. Provided so the cost
                 of the assumption can be measured, never as a default.
    """
    if not evalues:
        return 1.0
    if method == "mean":
        return sum(evalues) / len(evalues)
    if method == "product":
        return math.prod(evalues)
    raise ValueError(f"unknown merge method {method!r} (use 'mean' or 'product')")


def ville_threshold(alpha: float) -> float:
    """Alarm level giving a session-wide false-alarm probability <= alpha."""
    if not 0.0 < alpha < 1.0:
        raise ValueError(f"alpha must be in (0, 1), got {alpha}")
    return 1.0 / alpha


@dataclass
class EProcess:
    """
    Accumulates evidence across turns, alarming the first time the running
    product of per-turn merged e-values reaches 1/alpha.

    The running product across TIME is legitimate here even though the
    product across LAYERS is not: successive turns are the sequential
    dimension an e-process is defined over, and the supermartingale
    property is what Ville's inequality needs. Dependence between LAYERS
    within a turn is handled by `merge_method`, which is a separate
    concern and the reason these two products are not the same operation.

    `alarmed_at` records the turn index at which the boundary was first
    crossed — the quantity a detection-delay analysis needs, and the
    reason this is an e-process rather than a single test.
    """

    alpha: float = 0.05
    merge_method: str = "mean"
    wealth: float = 1.0
    history: list[float] = field(default_factory=list)
    alarmed_at: int | None = None

    def update(self, layer_evalues: list[float]) -> float:
        """Feed one turn's per-layer e-values; returns accumulated wealth."""
        merged = merge_evalues(layer_evalues, self.merge_method)
        self.wealth *= merged
        self.history.append(self.wealth)
        if self.alarmed_at is None and self.wealth >= ville_threshold(self.alpha):
            self.alarmed_at = len(self.history) - 1
        return self.wealth

    @property
    def alarmed(self) -> bool:
        return self.alarmed_at is not None

    def reset(self) -> None:
        self.wealth = 1.0
        self.history.clear()
        self.alarmed_at = None


@dataclass
class MixtureEDetector:
    """
    E-detector for an unknown change point (Shin, Ramdas & Rinaldo).

    A slow-burn attack begins at an unknown turn. A single e-process
    started at turn 0 dilutes early benign evidence into later attack
    evidence; one started at the true change point would not. Since the
    change point is unknown, maintain a MIXTURE over all possible start
    times:

        M_t = sum_tau w_tau * M_t^(tau),    w_tau = 1 / (tau (tau + 1))

    A weighted mixture of e-processes is itself an e-process by linearity
    of expectation, so the guarantee survives, and the weights sum to 1 so
    nothing is double-counted. Implemented with the standard O(1)-per-turn
    recursion rather than one process per start time.

    This is the mechanism aimed squarely at the case SENTINEL's
    `SLOW_BURN_INJECTION` rule cannot catch — and which Contribution E's
    Proposition 1 proves no threshold rule can catch.
    """

    alpha: float = 0.05
    merge_method: str = "mean"
    _running: list[float] = field(default_factory=list)
    mixture: float = 0.0
    alarmed_at: int | None = None
    t: int = 0

    def update(self, layer_evalues: list[float]) -> float:
        merged = merge_evalues(layer_evalues, self.merge_method)
        self.t += 1
        # Every previously-started process is multiplied by this turn's
        # evidence; a new process starts at this turn with wealth 1.
        self._running = [w * merged for w in self._running] + [merged]
        self.mixture = sum(
            w / (tau * (tau + 1.0))
            for tau, w in enumerate(self._running, start=1)
        )
        if self.alarmed_at is None and self.mixture >= ville_threshold(self.alpha):
            self.alarmed_at = self.t - 1
        return self.mixture

    @property
    def alarmed(self) -> bool:
        return self.alarmed_at is not None

    def reset(self) -> None:
        self._running.clear()
        self.mixture = 0.0
        self.alarmed_at = None
        self.t = 0
