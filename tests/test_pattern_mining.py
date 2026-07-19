"""
Tests for the sequential pattern miner (Contribution C).

Three layers:
  1. Core algorithm correctness against hand-verifiable small examples.
  2. mine_discriminative_patterns correctness (support/discriminativeness math).
  3. The mandatory generalization test (TestGeneralization) — this is the
     validation the roadmap document explicitly requires before mined
     patterns can be treated as a real contribution rather than an
     expensive way to restate the mining set. Both directions are reported:
     patterns generalizing well to new instances of KNOWN attack shapes,
     and patterns generalizing poorly to a STRUCTURALLY novel held-out
     chain type — the second finding is reported as the honest result it
     is, not hidden or tuned away.
"""

import pytest

from sentinel.core.pattern_mining import (
    bucket_score, _is_subsequence, mine_frequent_sequential_patterns,
    mine_discriminative_patterns, evaluate_pattern_generalization,
)


# ---------------------------------------------------------------------------
# 1. Core algorithm correctness
# ---------------------------------------------------------------------------

class TestBucketScore:
    def test_buckets_are_ordered_correctly(self):
        assert bucket_score(0.1) == "LOW"
        assert bucket_score(0.5) == "MEDIUM"
        assert bucket_score(0.9) == "HIGH"

    def test_boundary_values(self):
        assert bucket_score(0.35) == "MEDIUM"  # >= low_cut
        assert bucket_score(0.7) == "HIGH"     # >= high_cut


class TestIsSubsequence:
    def test_order_matters(self):
        assert _is_subsequence(("A", "C"), ["A", "B", "C"]) is True
        assert _is_subsequence(("C", "A"), ["A", "B", "C"]) is False

    def test_gaps_allowed(self):
        assert _is_subsequence(("A", "D"), ["A", "B", "C", "D"]) is True

    def test_empty_pattern_always_matches(self):
        assert _is_subsequence((), ["A", "B"]) is True

    def test_missing_item_fails(self):
        assert _is_subsequence(("A", "Z"), ["A", "B", "C"]) is False


class TestMineFrequentSequentialPatterns:
    """Verified against a hand-computed small example — see the exact
    support values in the comments below."""

    SEQS = [
        ["A", "B", "C"],
        ["A", "C"],
        ["B", "C"],
        ["A", "B"],
    ]
    # support(A)=0.75, support(B)=0.75, support(C)=0.75
    # support((A,B))=0.5 [seq0,seq3], support((A,C))=0.5 [seq0,seq1],
    # support((B,C))=0.5 [seq0,seq2]
    # support((A,B,C))=0.25 [seq0 only]

    def test_frequent_singletons_and_pairs_found_at_threshold_0_4(self):
        patterns = set(mine_frequent_sequential_patterns(self.SEQS, min_support=0.4, max_pattern_length=3))
        expected = {("A",), ("B",), ("C",), ("A", "B"), ("A", "C"), ("B", "C")}
        assert patterns == expected

    def test_triple_excluded_below_its_support(self):
        patterns = set(mine_frequent_sequential_patterns(self.SEQS, min_support=0.4, max_pattern_length=3))
        assert ("A", "B", "C") not in patterns

    def test_triple_included_at_lower_threshold(self):
        patterns = set(mine_frequent_sequential_patterns(self.SEQS, min_support=0.2, max_pattern_length=3))
        assert ("A", "B", "C") in patterns

    def test_max_pattern_length_respected(self):
        patterns = mine_frequent_sequential_patterns(self.SEQS, min_support=0.1, max_pattern_length=1)
        assert all(len(p) <= 1 for p in patterns)

    def test_empty_input(self):
        assert mine_frequent_sequential_patterns([], min_support=0.1) == []


class TestMineDiscriminativePatterns:
    def test_pattern_exclusive_to_positive_class_has_discriminativeness_one(self):
        positive = [["L1:HIGH", "L4:HIGH"], ["L1:HIGH", "L4:HIGH", "L5:LOW"]]
        negative = [["L1:LOW", "L2:LOW"], ["L3:LOW"]]
        results = mine_discriminative_patterns(
            positive, negative, min_support_positive=0.5, min_discriminativeness=0.5
        )
        matched = [r for r in results if r.pattern == ("L1:HIGH", "L4:HIGH")]
        assert len(matched) == 1
        assert matched[0].discriminativeness == pytest.approx(1.0)
        assert matched[0].count_negative == 0

    def test_pattern_equally_common_in_both_classes_is_screened_out(self):
        positive = [["L1:HIGH"], ["L1:HIGH"]]
        negative = [["L1:HIGH"], ["L1:HIGH"]]
        results = mine_discriminative_patterns(
            positive, negative, min_support_positive=0.5, min_discriminativeness=0.8
        )
        assert results == []  # discriminativeness would be 0.5, below the 0.8 screen

    def test_results_sorted_by_discriminativeness_then_support(self):
        positive = [
            ["L1:HIGH", "L2:HIGH"],
            ["L1:HIGH", "L2:HIGH"],
            ["L1:HIGH"],
        ]
        negative = [["L1:HIGH"], ["L3:LOW"]]
        results = mine_discriminative_patterns(
            positive, negative, min_support_positive=0.3, min_discriminativeness=0.5
        )
        discriminativenesses = [r.discriminativeness for r in results]
        assert discriminativenesses == sorted(discriminativenesses, reverse=True)


# ---------------------------------------------------------------------------
# 3. The mandatory generalization test
# ---------------------------------------------------------------------------

class TestGeneralization:
    """
    Synthetic setup: four distinct attack "chain types", each a canonical
    event-sequence template with random benign filler events mixed in to
    simulate real-world noise. Types 1-3 use HIGH-bucket symbols; type 4 is
    deliberately constructed with MEDIUM-bucket symbols and no symbol
    overlap with types 1-3 at all — i.e. it is genuinely, structurally
    distinct, not just a noisy variant of a known type.

    This setup is designed to produce an honest split result: patterns
    mined from types 1-3 should generalize well to fresh instances of types
    1-3 (same underlying symbols, different noise draws), and should NOT
    generalize to type 4 (no shared symbols at all) — exactly the negative
    result the roadmap document requires reporting rather than hiding.
    """

    TEMPLATES = {
        "slow_burn":   ["L1:MEDIUM", "L3:MEDIUM", "L3:HIGH", "L1:HIGH"],
        "rag_agent":   ["L2:HIGH", "L4:HIGH"],
        "exfil_probe": ["L1:HIGH", "L5:HIGH"],
        # Held-out type: zero symbol overlap with the three types above
        # (verified: L2:MEDIUM, L4:MEDIUM, L5:MEDIUM appear in none of
        # slow_burn/rag_agent/exfil_probe) — a genuinely novel attack
        # shape, not a noisy variant of a known one.
        "taint_chain": ["L2:MEDIUM", "L4:MEDIUM", "L5:MEDIUM"],
    }

    FILLER_SYMBOLS = ["L1:LOW", "L2:LOW", "L3:LOW", "L4:LOW", "L5:LOW"]

    @staticmethod
    def _generate_sequences(rng, template, n, n_filler_range=(0, 3)):
        sequences = []
        for _ in range(n):
            seq = list(template)
            n_filler = rng.randint(*n_filler_range)
            for _ in range(n_filler):
                pos = rng.randint(0, len(seq))
                seq.insert(pos, rng.choice(TestGeneralization.FILLER_SYMBOLS))
            sequences.append(seq)
        return sequences

    @pytest.fixture(scope="class")
    @classmethod
    def synthetic_data(cls):
        import random
        rng = random.Random(7)

        attack_sequences_by_type = {
            name: TestGeneralization._generate_sequences(rng, template, n=60)
            for name, template in TestGeneralization.TEMPLATES.items()
        }
        benign_sequences = [
            [rng.choice(TestGeneralization.FILLER_SYMBOLS) for _ in range(rng.randint(1, 5))]
            for _ in range(200)
        ]
        return attack_sequences_by_type, benign_sequences

    def test_patterns_generalize_to_new_instances_of_known_types(self, synthetic_data):
        attack_sequences_by_type, benign_sequences = synthetic_data
        report = evaluate_pattern_generalization(
            attack_sequences_by_type=attack_sequences_by_type,
            benign_sequences=benign_sequences,
            held_out_types=["taint_chain"],
            min_support_positive=0.15,
            min_discriminativeness=0.8,
        )
        assert len(report.mined_patterns) > 0
        # Fresh, unseen-during-mining instances of the SAME known types
        # should be well recalled — this validates the mining mechanism
        # itself, independent of the harder cross-type question below.
        assert report.known_type_recall > 0.7

    def test_patterns_do_not_generalize_to_structurally_novel_type(self, synthetic_data):
        """
        THE HONEST NEGATIVE RESULT. The held-out 'taint_chain' type shares
        no event symbols with the mined types at all (MEDIUM-bucket only,
        vs. HIGH-bucket in all three mining types), so recall on it should
        be at or near zero. This is not a failure of the test — it is
        exactly what the roadmap document says to expect and report when
        mined patterns don't transfer to genuinely novel attack structure,
        and it directly motivates why pattern mining should be paired with
        the taint propagation graph (Contribution A) rather than treated as
        a standalone replacement for it: structural novelty at the symbol
        level is invisible to a pattern miner keyed on exact discretized
        scores, but is exactly what continuous trust propagation through a
        graph does not require pre-enumerating.
        """
        attack_sequences_by_type, benign_sequences = synthetic_data
        report = evaluate_pattern_generalization(
            attack_sequences_by_type=attack_sequences_by_type,
            benign_sequences=benign_sequences,
            held_out_types=["taint_chain"],
            min_support_positive=0.15,
            min_discriminativeness=0.8,
        )
        assert report.held_out_recall < 0.15

    def test_false_positive_rate_on_held_out_benign_is_low(self, synthetic_data):
        attack_sequences_by_type, benign_sequences = synthetic_data
        report = evaluate_pattern_generalization(
            attack_sequences_by_type=attack_sequences_by_type,
            benign_sequences=benign_sequences,
            held_out_types=["taint_chain"],
            min_support_positive=0.15,
            min_discriminativeness=0.8,
        )
        assert report.benign_false_positive_rate < 0.1

    def test_requires_at_least_one_non_held_out_type(self, synthetic_data):
        attack_sequences_by_type, benign_sequences = synthetic_data
        with pytest.raises(ValueError):
            evaluate_pattern_generalization(
                attack_sequences_by_type=attack_sequences_by_type,
                benign_sequences=benign_sequences,
                held_out_types=list(attack_sequences_by_type.keys()),
            )
