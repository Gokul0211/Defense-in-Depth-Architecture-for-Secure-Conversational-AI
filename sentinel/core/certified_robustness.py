"""
Certified robustness via randomized smoothing, for L1's decision.

WHY THIS EXISTS
------------------
The red-team chapter (redteam.py, evaluated in eval/results/eval_redteam_*)
measures EMPIRICAL evasion resistance against specific attackers — a real,
valuable, but inherently incomplete picture, since it only shows what THOSE
attackers achieved, not what is achievable in principle. This module adds a
complementary, PROVABLE guarantee: for a given input and a stated,
bounded perturbation budget, certify that the decision cannot be flipped by
ANY perturbation drawn from that budget's distribution, not just the ones a
particular attacker happened to try.

THE METHOD, STATED HONESTLY
------------------------------
A simplified, majority-vote instantiation of the randomized-smoothing
certification recipe (Cohen et al. 2019's general framework; SAFER [Ye et
al. 2020] for the discrete/text-substitution case) — NOT a full tight-margin
bound re-derivation. Given an input's real production decision d(x) and a
perturbation budget k:
  1. Draw n i.i.d. noisy copies of x from a budget-k perturbation
     distribution (see generate_perturbations below).
  2. Compute the real decision on each copy; count agreements with d(x).
  3. Compute a Clopper-Pearson LOWER confidence bound on the true
     agreement probability (same statistical primitive already used in
     conformal_risk_control.py's empirical_fpr_with_ci).
  4. Certified stable at budget k iff that lower bound exceeds 0.5 — i.e.,
     we can state with the chosen confidence that a MAJORITY of the
     budget-k neighborhood agrees with the original decision, so no single
     deterministic choice within that same perturbation family can
     reliably flip a majority-vote-smoothed version of the decision.

SCOPE, STATED AS PLAINLY AS EVERY OTHER CLAIM IN THIS PROJECT
------------------------------------------------------------------
This certifies robustness against RANDOM synonym substitution (see
generate_perturbations) at a STATED, BOUNDED budget — the exact
perturbation family redteam.py's own RuleBasedParaphraser synonym tier
(iterations 0-2) already uses against this system, chosen deliberately for
that coherence. It does NOT certify against an unbounded, optimization-
guided, or LLM-based attacker — the existing red-team chapter's 12.3%
LLM-tier evasion number already shows that is a different, harder case
this mechanism makes no claim about.
"""

from __future__ import annotations

import random


def generate_perturbations(text: str, k: int, n: int, rng: random.Random) -> list[str]:
    """
    Generate n independent noisy copies of `text` via random synonym
    substitution at budget k, reusing redteam.py's own _SYNONYM_MAP (the
    same perturbation family its RuleBasedParaphraser's synonym tier
    already uses against this system — intentional reuse of an
    underscore-prefixed name, not accidental coupling).

    Budget k is defined as: for each copy, randomly select up to k of the
    _SYNONYM_MAP trigger words actually present in `text` (case-
    insensitive), and substitute each selected one with a randomly-chosen
    synonym. _SYNONYM_MAP has no natural notion of "k words changed" the
    way a per-character or per-token budget would (it substitutes every
    present trigger word, always) — this is the most direct, honest way to
    impose a controllable budget on that existing mechanism rather than
    inventing a parallel perturbation scheme.

    If no _SYNONYM_MAP trigger word is present in `text` at all, every
    returned copy is identical to `text` (no perturbation is possible)
    — callers must treat this as "not eligible for certification at any
    k > 0", not as evidence of stability; see certified_robustness_eval.py
    for how eligibility is filtered and reported honestly.
    """
    from sentinel.eval.redteam import _SYNONYM_MAP

    if k < 0:
        raise ValueError(f"k must be >= 0, got {k}")
    if n <= 0:
        raise ValueError(f"n must be > 0, got {n}")

    lower_text = text.lower()
    present_words = [w for w in _SYNONYM_MAP if w in lower_text]

    copies = []
    for _ in range(n):
        chosen = rng.sample(present_words, min(k, len(present_words))) if present_words else []
        result = text
        for word in chosen:
            synonyms = _SYNONYM_MAP[word]
            replacement = rng.choice(synonyms)
            idx = result.lower().find(word)
            if idx != -1:
                result = result[:idx] + replacement + result[idx + len(word):]
        copies.append(result)
    return copies


def n_eligible_trigger_words(text: str) -> int:
    """How many distinct _SYNONYM_MAP trigger words are present in `text`
    — the real ceiling on how large a budget k can meaningfully test for
    this specific input. Used by the eval script to report honest
    eligibility counts, not silently certify a no-op perturbation."""
    from sentinel.eval.redteam import _SYNONYM_MAP

    lower_text = text.lower()
    return sum(1 for w in _SYNONYM_MAP if w in lower_text)


def certify_decision_stability(
    agreements: int, n: int, confidence: float = 0.95
) -> tuple[float, float, bool]:
    """
    Given `agreements` out of `n` noisy copies whose decision matched the
    original, return (p_hat, p_lo, certified) where p_lo is a
    Clopper-Pearson lower confidence bound on the true agreement
    probability and certified = (p_lo > 0.5).

    Reuses empirical_fpr_with_ci's exact CI machinery by reframing this as
    "empirical disagreement rate with threshold -inf" is awkward — instead
    this computes the same Clopper-Pearson bound directly and independently
    for clarity, since the semantics here (agreement, not false-positive
    rate) are different enough that forcing a shared call site would
    obscure more than it would reuse.
    """
    from scipy import stats

    if n <= 0:
        raise ValueError(f"n must be > 0, got {n}")
    if not (0 <= agreements <= n):
        raise ValueError(f"agreements must be in [0, n], got {agreements} of {n}")

    p_hat = agreements / n
    alpha_ci = 1 - confidence
    p_lo = 0.0 if agreements == 0 else float(stats.beta.ppf(alpha_ci, agreements, n - agreements + 1))
    certified = bool(p_lo > 0.5)

    return p_hat, p_lo, certified
