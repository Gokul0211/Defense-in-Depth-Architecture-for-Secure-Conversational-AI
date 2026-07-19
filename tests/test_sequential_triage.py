"""
Tests for the sequential triage engine (Contribution B).

Two layers, matching the module's own documented scope:
  1. Unit correctness — LikelihoodModel, SPRTBoundaries, and the engine's
     stopping logic in isolation.
  2. A simulation-based statistical validation: generate synthetic per-layer
     score distributions with a KNOWN generating process (so "malicious" and
     "benign" are ground truth by construction), fit the engine on a
     training split, and check on a held-out split that (a) the achieved
     error rates track the target (alpha, beta) bounds and (b) the engine
     actually reduces the expected number of layers consulted relative to
     the naive always-run-all-N baseline. This validates the SPRT MECHANISM
     — it says nothing about this pipeline's real per-layer distributions,
     which is exactly what the evaluation plan document's labeled corpus is
     for.
"""

import math
import numpy as np
import pytest

from sentinel.core.sequential_triage import (
    LikelihoodModel, SPRTBoundaries, SequentialTriageEngine, Decision,
)


# ---------------------------------------------------------------------------
# 1. Unit correctness
# ---------------------------------------------------------------------------

class TestLikelihoodModel:
    def test_raises_on_insufficient_data_per_class(self):
        model = LikelihoodModel("L1")
        with pytest.raises(ValueError):
            model.fit(scores=[0.9], labels=[1])  # only 1 malicious, 0 benign

    def test_llr_is_positive_toward_the_malicious_mode(self):
        model = LikelihoodModel("L1", bandwidth=0.1)
        rng = np.random.default_rng(0)
        mal_scores = rng.normal(0.8, 0.05, 200).clip(0, 1)
        ben_scores = rng.normal(0.1, 0.05, 200).clip(0, 1)
        scores = np.concatenate([mal_scores, ben_scores])
        labels = np.concatenate([np.ones(200), np.zeros(200)])
        model.fit(scores, labels)

        assert model.log_likelihood_ratio(0.8) > 0   # near malicious mode
        assert model.log_likelihood_ratio(0.1) < 0   # near benign mode

    def test_unfit_model_raises_on_use(self):
        model = LikelihoodModel("L1")
        with pytest.raises(RuntimeError):
            model.log_likelihood_ratio(0.5)


class TestSPRTBoundaries:
    def test_boundaries_match_walds_formula(self):
        alpha, beta = 0.05, 0.10
        b = SPRTBoundaries.from_error_rates(alpha, beta)
        assert b.log_A == pytest.approx(math.log((1 - beta) / alpha))
        assert b.log_B == pytest.approx(math.log(beta / (1 - alpha)))

    def test_invalid_error_rates_rejected(self):
        with pytest.raises(ValueError):
            SPRTBoundaries.from_error_rates(0.0, 0.1)
        with pytest.raises(ValueError):
            SPRTBoundaries.from_error_rates(0.1, 1.0)

    def test_tighter_error_rates_widen_boundaries(self):
        """Requiring a lower error rate should require more evidence
        (boundaries further from 0) before stopping."""
        loose = SPRTBoundaries.from_error_rates(0.10, 0.10)
        tight = SPRTBoundaries.from_error_rates(0.01, 0.01)
        assert tight.log_A > loose.log_A
        assert tight.log_B < loose.log_B


class TestSequentialTriageEngineStopping:
    def _engine_with_stub_models(self, boundaries: SPRTBoundaries, constant_llr: float = 3.0) -> SequentialTriageEngine:
        """A model whose LLR is just a fixed constant per layer, to test the
        engine's stopping/accumulation logic in isolation from KDE fitting."""
        engine = SequentialTriageEngine(boundaries)

        class StubModel(LikelihoodModel):
            def __init__(self, name, constant_llr):
                super().__init__(name)
                self._constant = constant_llr
                self._fitted = True

            def log_likelihood_ratio(self, score):
                return self._constant

        for name in ["L1", "L2", "L3", "L4", "L5"]:
            engine.register_model(StubModel(name, constant_llr))
        return engine

    def test_stops_early_once_boundary_crossed(self):
        boundaries = SPRTBoundaries.from_error_rates(0.05, 0.05)  # log_A ~ log(19) ~ 2.94
        engine = self._engine_with_stub_models(boundaries)
        result = engine.run([("L1", 0.9), ("L2", 0.9), ("L3", 0.9), ("L4", 0.9), ("L5", 0.9)])
        # Each layer contributes +3.0 LLR; log_A ~2.94, so a single layer's
        # contribution should already cross it.
        assert result.decision == Decision.BLOCK
        assert result.layers_consulted == ["L1"]
        assert not result.exhausted

    def test_continues_when_evidence_is_weak(self):
        boundaries = SPRTBoundaries.from_error_rates(0.001, 0.001)  # log_A ~ 6.9, log_B ~ -6.9
        engine = self._engine_with_stub_models(boundaries, constant_llr=0.5)
        result = engine.run([("L1", 0.5), ("L2", 0.5), ("L3", 0.5)])
        # 3 layers * 0.5 LLR each = 1.5, well under the ~6.9 boundary.
        assert result.exhausted is True
        assert result.layers_consulted == ["L1", "L2", "L3"]

    def test_missing_model_raises(self):
        boundaries = SPRTBoundaries.from_error_rates(0.05, 0.05)
        engine = SequentialTriageEngine(boundaries)
        with pytest.raises(KeyError):
            engine.run([("L_unregistered", 0.5)])


# ---------------------------------------------------------------------------
# 2. Simulation-based statistical validation
# ---------------------------------------------------------------------------

# Deliberately heterogeneous AND overlapping synthetic layer distributions.
# Note on tuning: an earlier version of these parameters separated classes
# too cleanly (mean separation of ~6.5 standard deviations on L1 alone),
# which meant the SPRT could resolve almost every session from L1 by itself
# — technically correct, but not an interesting demonstration of *sequential,
# multi-layer* behavior, since it never needed to be sequential. These
# parameters overlap enough that most sessions genuinely need several
# layers' accumulated evidence to reach a confident decision, while
# extreme/unambiguous sessions still resolve in 1-2 layers — mirroring a
# real pipeline where no single layer is a perfect classifier on its own.
_LAYER_PARAMS = {
    # (malicious_mean, benign_mean, std)
    "L1": (0.68, 0.32, 0.15),
    "L2": (0.62, 0.28, 0.16),
    "L3": (0.54, 0.38, 0.16),  # weak signal, on purpose
    "L4": (0.65, 0.30, 0.15),
    "L5": (0.52, 0.34, 0.16),  # weak signal, on purpose
}
_LAYER_ORDER = ["L1", "L2", "L3", "L4", "L5"]


def _simulate_session_scores(rng, is_malicious: bool) -> dict[str, float]:
    scores = {}
    for layer, (mal_mean, ben_mean, std) in _LAYER_PARAMS.items():
        mean = mal_mean if is_malicious else ben_mean
        scores[layer] = float(np.clip(rng.normal(mean, std), 0.0, 1.0))
    return scores


@pytest.fixture(scope="module")
def fitted_engine_and_test_set():
    rng = np.random.default_rng(42)
    n_train, n_test = 600, 1000

    train_sessions = (
        [(_simulate_session_scores(rng, True), 1) for _ in range(n_train)]
        + [(_simulate_session_scores(rng, False), 0) for _ in range(n_train)]
    )
    test_sessions = (
        [(_simulate_session_scores(rng, True), 1) for _ in range(n_test)]
        + [(_simulate_session_scores(rng, False), 0) for _ in range(n_test)]
    )

    alpha, beta = 0.05, 0.05
    boundaries = SPRTBoundaries.from_error_rates(alpha, beta)
    engine = SequentialTriageEngine(boundaries)
    for layer in _LAYER_ORDER:
        model = LikelihoodModel(layer, bandwidth=0.10)
        layer_scores = [s[layer] for s, _ in train_sessions]
        layer_labels = [lbl for _, lbl in train_sessions]
        model.fit(layer_scores, layer_labels)
        engine.register_model(model)

    return engine, test_sessions, alpha, beta


class TestSPRTStatisticalProperties:
    """
    Validates the SPRT mechanism itself using synthetic distributions with
    known ground truth (see module docstring). Numbers are checked against
    generous, documented tolerances, not exact theoretical values —
    Wald's exact guarantee assumes the true likelihood ratio is known, and
    here it's estimated via KDE from a finite sample, so some slack against
    the nominal (alpha, beta) is expected and is not itself a bug.
    """

    LAYER_ORDER = _LAYER_ORDER

    def test_achieved_error_rates_track_target_bounds(self, fitted_engine_and_test_set):
        engine, test_sessions, alpha, beta = fitted_engine_and_test_set

        false_positives = 0  # benign decided BLOCK
        false_negatives = 0  # malicious decided ALLOW
        n_benign = sum(1 for _, lbl in test_sessions if lbl == 0)
        n_malicious = sum(1 for _, lbl in test_sessions if lbl == 1)

        for scores, label in test_sessions:
            ordered = [(layer, scores[layer]) for layer in self.LAYER_ORDER]
            result = engine.run(ordered)
            if label == 0 and result.decision == Decision.BLOCK:
                false_positives += 1
            if label == 1 and result.decision == Decision.ALLOW:
                false_negatives += 1

        achieved_fpr = false_positives / n_benign
        achieved_fnr = false_negatives / n_malicious

        # Wald's theorem guarantees achieved error rates are AT MOST the
        # nominal (alpha, beta) — some slack is still allowed here since
        # the likelihood ratio is estimated via KDE from a finite sample
        # rather than known exactly, but it should not blow past the bound.
        assert achieved_fpr <= alpha * 2, f"achieved FPR {achieved_fpr:.3f} far exceeds target alpha={alpha}"
        assert achieved_fnr <= beta * 2, f"achieved FNR {achieved_fnr:.3f} far exceeds target beta={beta}"

    def test_expected_layers_consulted_is_less_than_naive_baseline(self, fitted_engine_and_test_set):
        """The concrete, reportable claim from the roadmap doc: SPRT should
        reduce expected layers run relative to the naive always-run-all-N
        baseline, at (approximately) matched error rates."""
        engine, test_sessions, alpha, beta = fitted_engine_and_test_set
        naive_layers = len(self.LAYER_ORDER)

        layers_consulted_counts = []
        for scores, label in test_sessions:
            ordered = [(layer, scores[layer]) for layer in self.LAYER_ORDER]
            result = engine.run(ordered)
            layers_consulted_counts.append(len(result.layers_consulted))

        avg_layers = sum(layers_consulted_counts) / len(layers_consulted_counts)

        assert avg_layers < naive_layers
        # With the tuned overlapping distributions above, roughly half of
        # all layers are typically skipped at matched error rates — a
        # meaningful, reportable reduction rather than a marginal one. This
        # bound is intentionally looser than the empirically observed ~2.6/5
        # so the test isn't brittle to the exact RNG draw.
        assert avg_layers < naive_layers * 0.75

    def test_confident_sessions_stop_earlier_than_ambiguous_ones(self, fitted_engine_and_test_set):
        """Sanity check on the mechanism's core intuition: a session with
        extreme, unambiguous scores should resolve in fewer layers than one
        with scores near the decision boundary."""
        engine, _, _, _ = fitted_engine_and_test_set

        extreme_malicious = [(layer, 0.95) for layer in self.LAYER_ORDER]
        ambiguous = [(layer, 0.5) for layer in self.LAYER_ORDER]

        extreme_result = engine.run(extreme_malicious)
        ambiguous_result = engine.run(ambiguous)

        assert len(extreme_result.layers_consulted) <= len(ambiguous_result.layers_consulted)
