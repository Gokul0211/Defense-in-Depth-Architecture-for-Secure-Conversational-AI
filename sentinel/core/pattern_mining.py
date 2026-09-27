"""
Data-Driven Correlation Pattern Mining — Contribution C (research roadmap
doc, Section 4).

THE GAP THIS CLOSES
--------------------
The correlation engine's rules 1-3 (core/correlation_engine.py) can only
ever catch the three attack chains someone thought to hand-code. That is a
completeness ceiling by construction: any multi-layer attack pattern outside
those three IF-statements is invisible to the system no matter how well each
individual layer performs. This module mines correlation rules from labeled
session data instead of hand-writing them, via sequential pattern mining
(PrefixSpan-style prefix-projected growth) over discretized per-layer event
sequences, then screens candidates for how discriminative they are of the
attack class versus the benign class.

MANDATORY VALIDATION — THIS IS NOT OPTIONAL
----------------------------------------------
Mined patterns are only a real contribution if they generalize to attack
chains *not seen during mining* — otherwise this is just an expensive way to
re-derive the mining set's own examples. `evaluate_pattern_generalization()`
below implements exactly that check: split attack examples by chain *type*
(not just by sequence), mine only on a subset of types, then measure recall
on held-out types the miner never saw. The roadmap document is explicit that
if this comes back near zero, that is a negative result to report and
analyze, not a reason to hide the test — see
tests/test_pattern_mining.py::TestGeneralization for exactly that finding
reported honestly rather than tuned away.

REPRESENTATION
---------------
Each session is represented as an ordered sequence of discrete event
symbols, e.g. `("L1:HIGH", "L3:MEDIUM", "L4:CRITICAL")` — typically produced
by bucketing each layer's continuous score (see `bucket_score`). Patterns
are ordered, not-necessarily-contiguous subsequences of these event
sequences (standard sequential-pattern-mining semantics: pattern P matches
sequence S if P's symbols appear in S in the same relative order, with
arbitrary gaps allowed between them).
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass
from typing import Sequence


def bucket_score(score: float, thresholds: tuple[float, float] = (0.35, 0.7)) -> str:
    """Discretize a continuous [0,1] layer score into LOW/MEDIUM/HIGH. This
    specific 2-cutpoint scheme is a placeholder pending calibration against
    real per-layer score distributions (see the evaluation plan doc) —
    swap in per-layer thresholds once that data exists rather than one
    global scheme for all five layers."""
    low_cut, high_cut = thresholds
    if score < low_cut:
        return "LOW"
    if score < high_cut:
        return "MEDIUM"
    return "HIGH"


def _is_subsequence(pattern: Sequence[str], sequence: Sequence[str]) -> bool:
    """True if `pattern` occurs as an ordered, not-necessarily-contiguous
    subsequence of `sequence`. Uses the standard Python idiom of testing
    membership against a shared iterator, which naturally advances position
    on each successful match."""
    it = iter(sequence)
    return all(item in it for item in pattern)


def mine_frequent_sequential_patterns(
    sequences: list[list[str]],
    min_support: float = 0.1,
    max_pattern_length: int = 5,
) -> list[tuple[str, ...]]:
    """
    Find all sequential patterns with support >= min_support in `sequences`,
    up to `max_pattern_length`, via prefix-projected growth (PrefixSpan).

    Algorithm: start from frequent length-1 patterns; for each, build the
    "projected database" (for every sequence containing that item, the
    suffix immediately after its first occurrence), then recurse — any
    pattern frequent in the projected DB, prefixed with the current item, is
    a frequent pattern of the original DB. This avoids ever generating and
    testing candidates that can't possibly be frequent (the standard
    Apriori-style anti-monotonicity property: no supersequence of an
    infrequent pattern can be frequent), which is what makes prefix
    projection tractable instead of enumerating all O(k^n) candidate
    subsequences directly.

    Returns patterns as tuples, discovered in breadth-first (by length) order.
    """
    n = len(sequences)
    if n == 0:
        return []
    min_count = max(1, math.ceil(min_support * n))
    results: list[tuple[str, ...]] = []

    def project(projected_db: list[list[str]], item: str) -> list[list[str]]:
        projected = []
        for seq in projected_db:
            try:
                idx = seq.index(item)
            except ValueError:
                continue
            projected.append(seq[idx + 1:])
        return projected

    def grow(prefix: tuple[str, ...], projected_db: list[list[str]]) -> None:
        if len(prefix) >= max_pattern_length:
            return
        item_counts: Counter = Counter()
        for seq in projected_db:
            for item in set(seq):  # count each item once per sequence, not per occurrence
                item_counts[item] += 1

        for item, count in item_counts.items():
            if count < min_count:
                continue
            new_prefix = prefix + (item,)
            results.append(new_prefix)
            grow(new_prefix, project(projected_db, item))

    grow((), sequences)
    return results


@dataclass(frozen=True)
class MinedPattern:
    pattern: tuple[str, ...]
    support_positive: float  # fraction of positive (attack) sequences containing this pattern
    support_negative: float  # fraction of negative (benign) sequences containing this pattern
    count_positive: int
    count_negative: int

    @property
    def discriminativeness(self) -> float:
        """support_positive / (support_positive + support_negative), in
        [0, 1]. 1.0 = appears only in attack sequences. 0.5 = equally
        likely in both classes (useless as a rule). Undefined (returned as
        0.0) if the pattern appears in neither class, which shouldn't occur
        for a pattern mined from the positive set with count_positive > 0,
        but is handled defensively."""
        denom = self.support_positive + self.support_negative
        if denom == 0:
            return 0.0
        return self.support_positive / denom


def mine_discriminative_patterns(
    positive_sequences: list[list[str]],
    negative_sequences: list[list[str]],
    min_support_positive: float = 0.1,
    min_discriminativeness: float = 0.8,
    max_pattern_length: int = 4,
) -> list[MinedPattern]:
    """
    Mine sequential patterns frequent among positive (attack) sequences and
    discriminative against negative (benign) sequences — this is what
    correlation_engine.py's mined_rules.json (see the roadmap doc's
    implementation plan) is meant to be populated from.

    Candidates are generated from the positive class only (mine_support is
    evaluated against attack sequences), since a pattern's value here is
    entirely about characterizing attacks — there is no need to also
    generate candidates from the benign class only to discard them.
    """
    candidates = mine_frequent_sequential_patterns(
        positive_sequences, min_support=min_support_positive, max_pattern_length=max_pattern_length
    )

    n_pos, n_neg = len(positive_sequences), len(negative_sequences)
    results = []
    seen = set()
    for pattern in candidates:
        if pattern in seen:
            continue
        seen.add(pattern)
        count_pos = sum(1 for seq in positive_sequences if _is_subsequence(pattern, seq))
        count_neg = sum(1 for seq in negative_sequences if _is_subsequence(pattern, seq))
        mp = MinedPattern(
            pattern=pattern,
            support_positive=count_pos / n_pos if n_pos else 0.0,
            support_negative=count_neg / n_neg if n_neg else 0.0,
            count_positive=count_pos,
            count_negative=count_neg,
        )
        if mp.discriminativeness >= min_discriminativeness:
            results.append(mp)

    results.sort(key=lambda p: (-p.discriminativeness, -p.support_positive))
    return results


@dataclass(frozen=True)
class GeneralizationReport:
    """Result of evaluate_pattern_generalization — see that function's
    docstring. Reported honestly regardless of outcome, per the roadmap
    doc's explicit instruction not to hide a negative result here."""
    mined_patterns: list[MinedPattern]
    held_out_chain_types: list[str]
    held_out_recall: float          # fraction of held-out-type attack sequences matched by >=1 mined pattern
    known_type_recall: float        # fraction of held-in-type (but unseen-during-mining) attack sequences matched
    benign_false_positive_rate: float  # fraction of held-out benign sequences matched by >=1 mined pattern


def evaluate_pattern_generalization(
    attack_sequences_by_type: dict[str, list[list[str]]],
    benign_sequences: list[list[str]],
    held_out_types: list[str],
    min_support_positive: float = 0.15,
    min_discriminativeness: float = 0.8,
    max_pattern_length: int = 4,
    test_fraction: float = 0.3,
    seed: int = 0,
) -> GeneralizationReport:
    """
    The mandatory generalization check: split attack chain *types* (not
    individual sequences) into a mining set and a held-out set. Mine
    patterns only on the mining-set types, then measure recall separately
    on (a) fresh, unseen-during-mining sequences of the SAME types the miner
    was trained on, and (b) sequences of chain types the miner never saw at
    all. (a) validates the mining mechanism generalizes to new instances of
    a known attack shape. (b) is the real test of whether mined patterns
    discover anything that transfers to genuinely novel attack structure —
    the roadmap doc is explicit that a low value here is an expected,
    reportable possible outcome, not a bug to be tuned away.

    `benign_sequences` is split via the same `test_fraction` into a mining
    portion (used as the negative class during pattern discrimination
    screening) and a held-out portion (used only to measure the mined
    patterns' false-positive rate on data not involved in mining at all).
    """
    import random
    rng = random.Random(seed)

    known_types = [t for t in attack_sequences_by_type if t not in held_out_types]
    if not known_types:
        raise ValueError("At least one chain type must remain for mining (not held out)")

    mining_positive: list[list[str]] = []
    held_in_test_positive: list[list[str]] = []
    for t in known_types:
        seqs = list(attack_sequences_by_type[t])
        rng.shuffle(seqs)
        split_idx = max(1, int(len(seqs) * (1 - test_fraction)))
        mining_positive.extend(seqs[:split_idx])
        held_in_test_positive.extend(seqs[split_idx:])

    held_out_positive: list[list[str]] = []
    for t in held_out_types:
        held_out_positive.extend(attack_sequences_by_type[t])

    benign_shuffled = list(benign_sequences)
    rng.shuffle(benign_shuffled)
    split_idx = max(1, int(len(benign_shuffled) * (1 - test_fraction)))
    mining_negative = benign_shuffled[:split_idx]
    held_out_negative = benign_shuffled[split_idx:]

    mined = mine_discriminative_patterns(
        positive_sequences=mining_positive,
        negative_sequences=mining_negative,
        min_support_positive=min_support_positive,
        min_discriminativeness=min_discriminativeness,
        max_pattern_length=max_pattern_length,
    )

    def recall(sequences: list[list[str]]) -> float:
        if not sequences:
            return float("nan")
        matched = sum(
            1 for seq in sequences
            if any(_is_subsequence(mp.pattern, seq) for mp in mined)
        )
        return matched / len(sequences)

    return GeneralizationReport(
        mined_patterns=mined,
        held_out_chain_types=held_out_types,
        held_out_recall=recall(held_out_positive),
        known_type_recall=recall(held_in_test_positive),
        benign_false_positive_rate=recall(held_out_negative),
    )
