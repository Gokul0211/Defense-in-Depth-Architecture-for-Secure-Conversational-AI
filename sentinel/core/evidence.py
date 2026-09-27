"""
Continuous evidence aggregation, shared by L4 and L5.

WHY THIS MODULE EXISTS
-------------------------
Four of this system's five layers were found (2026-09-18/19) to destroy
evidence at their own output interface by quantising it:

    L5  score is 0.0, or a floor of 0.55 (leak) / 0.6 (policy).
    L4  score is one of {0.2, 0.5, 0.7, 0.8, 0.9, 0.97, 1.0}.

`WARN_THRESHOLD` is 0.5, so in BOTH layers the only sub-threshold value the
layer can emit is the one an entirely innocuous input produces. Every
sub-threshold sample therefore ties, and each layer's sub-threshold AUROC
is exactly 0.5 *by construction* — L5 measured at 0.5000 on AgentLeak
(Contribution E, E-2), L4 established analytically.

The fix in both cases is the same: emit a CONTINUOUS confidence alongside
the discrete verdict, built from evidence the layer already computes and
currently throws away. Since the fix is the same, the aggregation lives
here once rather than being written twice and drifting.

THE AGGREGATION, AND WHY IT HAS NO FITTED WEIGHTS
----------------------------------------------------
Each layer's evidence sources are independently sufficient to raise
suspicion — a PII match, an exfiltration score, and a provenance match
each mean "something is wrong" on their own. That is exactly the semantics
noisy-OR encodes:

    combined = 1 - prod(1 - e_i)

It is monotone in every component and bounded in [0, 1), and it carries no
free parameters. Inventing per-source weights with no labelled corpus to
fit them against would be the speculative tuning this project avoids;
because the components are also reported individually, a fitted combiner
can replace this later without an interface change.

TWO IMPLEMENTATION DETAILS THAT ARE NOT DETAILS
--------------------------------------------------
**Log space.** Summing -log(1 - e_i) and squashing once at the end is
algebraically identical to multiplying, but keeps full floating-point
resolution in the regime that actually occurs here: several components
near 1.0 at once, where the direct product collapses toward 0.0 and the
result toward 1.0, ties included.

**A per-component clamp.** Without it the function reproduces the very
defect it exists to remove. `risk_to_score("CRITICAL")` is exactly 1.0, so
an uncapped noisy-OR returns exactly 1.0 for every critical call no matter
what the other signals say — re-creating the tie cluster one branch over.
The clamp is the same device, for the same reason, as
`tier_fusion._MAX_ABS_LOG_LR`.

WHAT THE OUTPUT IS NOT
-------------------------
It is an ORDERING, not a calibrated probability of attack — that would
need a base rate the system cannot know. Since AUROC and every fusion rule
downstream are rank-based, the compression near 1.0 costs nothing.
"""

from __future__ import annotations

import math

# Per-component cap, in nats. A single component must not be able to
# contribute total evidence; see the module docstring.
MAX_COMPONENT_EVIDENCE = 6.0


def saturating_count(n: int) -> float:
    """
    Turn a count of findings into evidence in [0, 1).

    Saturating rather than linear because the first finding carries most of
    the information: an output with one PII match and one with four are
    both "leaking", and treating the fourth as four times the evidence
    would let a verbose output outrank a clearly worse terse one. Needs no
    fitted constants.
    """
    return 1.0 - math.exp(-max(0, n))


def noisy_or(terms: dict[str, float] | list[float],
             max_component_evidence: float = MAX_COMPONENT_EVIDENCE) -> float:
    """
    Noisy-OR over independently-sufficient evidence sources, in [0, 1).

    Accumulated in log space with a per-component clamp. Accepts a dict
    (so callers can keep their component names) or a bare sequence.
    """
    values = terms.values() if isinstance(terms, dict) else terms

    total = 0.0
    for value in values:
        value = max(0.0, min(float(value), 1.0))
        term = math.inf if value >= 1.0 else -math.log1p(-value)
        total += min(term, max_component_evidence)

    # expm1 rather than 1 - exp, so small `total` keeps its precision.
    return round(-math.expm1(-total), 9)
