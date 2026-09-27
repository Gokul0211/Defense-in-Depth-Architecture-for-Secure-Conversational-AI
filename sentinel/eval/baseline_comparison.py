"""
Baseline Comparison — evaluation plan doc, Section 2.

THE GAP THIS CLOSES
--------------------
`--baselines` was documented in runner.py's own module docstring as a
working CLI flag and was never actually in the argument parser — confirmed
by reading the parser directly. The three baseline predictor classes
(PromptGuardBaseline, LlamaGuardBaseline, LLMGuardBaseline) were complete
and unused; none had ever been run against any dataset. This module is the
orchestration that was always supposed to exist: run SENTINEL and one or
more baselines against the same samples, compute the same metrics for each,
and pair every comparison with McNemar's test rather than eyeballing which
number is bigger.

MODEL ACCESS — READ BEFORE RUNNING
--------------------------------------
- Prompt Guard and Llama Guard are both under the gated `meta-llama/`
  namespace on HuggingFace — you need an account with the license accepted
  and either `huggingface-cli login` or an `HF_TOKEN` env var set.
- LLM Guard is a plain `pip install llm-guard`, no gating.
- None of the three need a paid API key.

Baseline instantiation/loading failures (missing internet, missing HF
token, license not accepted, package not installed) are caught per-baseline
and reported as `"status": "unavailable"` with the reason — consistent with
the existing pattern used elsewhere in this eval framework for gracefully
skipping unavailable external resources (see dataset_loaders.py's handling
of ungenerated corpora). A baseline being unavailable does not abort the
whole comparison; SENTINEL's own results and any other available baseline's
results are still computed and returned.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

import numpy as np

from sentinel.eval.dataset_loaders import load_dataset
from sentinel.eval.metrics import compute_classification_metrics, mcnemar_test, bootstrap_ci

logger = logging.getLogger(__name__)

BASELINE_REGISTRY = {
    "prompt_guard": ("sentinel.eval.baselines.prompt_guard", "PromptGuardBaseline"),
    "llama_guard": ("sentinel.eval.baselines.llama_guard", "LlamaGuardBaseline"),
    "llm_guard": ("sentinel.eval.baselines.llm_guard", "LLMGuardBaseline"),
}


def _instantiate_baseline(name: str):
    """Dynamically import and construct a baseline predictor by name.
    Construction itself is cheap (lazy model loading happens on first
    predict() call — see e.g. PromptGuardBaseline._load()), so this step
    succeeding does not guarantee the baseline will actually work; the
    first predict() call is where a missing HF token/license/package
    failure actually surfaces, and that's caught separately below."""
    if name not in BASELINE_REGISTRY:
        raise KeyError(f"Unknown baseline '{name}'. Available: {list(BASELINE_REGISTRY)}")
    module_path, class_name = BASELINE_REGISTRY[name]
    import importlib
    module = importlib.import_module(module_path)
    cls = getattr(module, class_name)
    return cls()


@dataclass
class BaselineRunResult:
    name: str
    status: str  # "ok" | "unavailable"
    unavailable_reason: str | None = None
    classification: dict | None = None
    bootstrap: dict | None = None
    n_evaluated: int = 0
    n_errors: int = 0
    mean_latency_ms: float | None = None

    def to_dict(self) -> dict:
        return {
            "name": self.name, "status": self.status,
            "unavailable_reason": self.unavailable_reason,
            "classification": self.classification, "bootstrap": self.bootstrap,
            "n_evaluated": self.n_evaluated, "n_errors": self.n_errors,
            "mean_latency_ms": self.mean_latency_ms,
        }


def _run_one_baseline(name: str, samples: list, seed: int = 42) -> tuple[BaselineRunResult, list[str] | None, list[int] | None]:
    """
    Returns (result, decisions, valid_indices).

    `valid_indices`: positions into the original `samples` list that this
    baseline actually produced a prediction for — None if the baseline was
    entirely unavailable (nothing to pair for McNemar's test at all).
    `decisions` is aligned 1:1 with `valid_indices`, NOT with `samples`
    directly — a per-sample prediction failure simply omits that index from
    both lists rather than padding with a placeholder, since a fabricated
    placeholder decision would bias McNemar's test exactly the way the
    runner.py error-handling fix was written to prevent for SENTINEL's own
    metrics (see that fix's rationale). The caller re-aligns SENTINEL's
    predictions to the same `valid_indices` before pairing.
    """
    try:
        baseline = _instantiate_baseline(name)
    except Exception as e:
        logger.warning(f"  Baseline '{name}' unavailable at construction: {e}")
        return BaselineRunResult(name=name, status="unavailable", unavailable_reason=str(e)), None, None

    y_true, y_scores, decisions, latencies, valid_indices = [], [], [], [], []
    n_errors = 0

    for i, sample in enumerate(samples):
        try:
            result = baseline.predict(sample.text)
        except Exception as e:
            n_errors += 1
            if n_errors == 1:
                # First failure for this baseline: this is very likely a
                # systemic problem (missing token, no internet, no license)
                # rather than a per-sample fluke — surface it immediately
                # and loudly rather than silently accumulating N failures
                # before anyone notices, same principle as the runner.py
                # per-sample error-handling fix.
                logger.warning(
                    f"  Baseline '{name}' failed on first sample ({sample.sample_id}): {e}\n"
                    f"  This is likely systemic (missing HF token/license/package), not a "
                    f"per-sample issue — continuing to attempt remaining samples, but expect "
                    f"most/all to fail the same way."
                )
            continue

        y_true.append(1 if sample.label == "malicious" else 0)
        y_scores.append(result.score)
        decisions.append(result.decision)
        latencies.append(result.latency_ms)
        valid_indices.append(i)

    n_evaluated = len(y_true)
    if n_evaluated == 0:
        return BaselineRunResult(
            name=name, status="unavailable",
            unavailable_reason=f"All {len(samples)} samples failed (first error above). "
                                f"Likely missing HF token/license/package — see module docstring.",
            n_errors=n_errors,
        ), None, None

    y_true_arr = np.array(y_true)
    y_scores_arr = np.array(y_scores)
    classification = compute_classification_metrics(y_true_arr, y_scores_arr, threshold=0.5)

    bootstrap = None
    if len(np.unique(y_true_arr)) >= 2:
        def _f1(y_t, y_s):
            from sklearn.metrics import f1_score
            return f1_score(y_t, (y_s >= 0.5).astype(int), zero_division=0)
        f1_ci = bootstrap_ci(y_true_arr, y_scores_arr, _f1, seed=seed)
        bootstrap = {"f1": f1_ci.to_dict()}

    result = BaselineRunResult(
        name=name, status="ok", classification=classification.to_dict(), bootstrap=bootstrap,
        n_evaluated=n_evaluated, n_errors=n_errors,
        mean_latency_ms=float(np.mean(latencies)) if latencies else None,
    )
    return result, decisions, valid_indices


def run_baseline_comparison(
    dataset_name: str,
    baseline_names: list[str],
    sentinel_scorer_fn,  # callable(text: str) -> (score: float, decision: str)
    limit: int | None = None,
    seed: int = 42,
) -> dict:
    """
    Run SENTINEL (via `sentinel_scorer_fn`) and each named baseline against
    the same dataset, compute classification metrics for each, and pair
    SENTINEL's decisions against each available baseline's decisions with
    McNemar's test.

    `sentinel_scorer_fn`: caller-supplied, so this module doesn't hardcode
    which SENTINEL layer/pipeline is being compared — pass `_evaluate_l1`
    wrapped to return (score, decision) for an L1-vs-Prompt-Guard
    comparison, or `pipeline_sim.simulate_pipeline`'s result for a
    full-pipeline comparison, etc.
    """
    dataset = load_dataset(dataset_name, limit=limit)
    if not dataset.samples:
        return {"error": f"Dataset '{dataset_name}' has no samples"}

    samples = dataset.samples
    logger.info(f"Baseline comparison: {len(samples)} samples from '{dataset_name}', baselines={baseline_names}")

    # --- SENTINEL's own results on the same samples ---
    sentinel_y_true, sentinel_y_scores, sentinel_decisions = [], [], []
    for sample in samples:
        score, decision = sentinel_scorer_fn(sample.text)
        sentinel_y_true.append(1 if sample.label == "malicious" else 0)
        sentinel_y_scores.append(score)
        sentinel_decisions.append(decision)

    sentinel_y_true_arr = np.array(sentinel_y_true)
    sentinel_classification = compute_classification_metrics(
        sentinel_y_true_arr, np.array(sentinel_y_scores), threshold=0.5
    )
    logger.info(f"  SENTINEL: recall={sentinel_classification.recall:.4f} precision={sentinel_classification.precision:.4f}")

    # --- Each baseline ---
    baseline_results = {}
    mcnemar_results = {}
    for name in baseline_names:
        logger.info(f"  Running baseline: {name}...")
        result, decisions, valid_indices = _run_one_baseline(name, samples, seed=seed)
        baseline_results[name] = result.to_dict()

        if result.status == "ok" and decisions is not None and valid_indices is not None:
            if len(valid_indices) < len(samples):
                logger.warning(
                    f"    '{name}' only produced predictions for {len(valid_indices)}/{len(samples)} "
                    f"samples — McNemar's test below is computed on that aligned subset only."
                )
            aligned_sentinel_decisions = [sentinel_decisions[i] for i in valid_indices]
            aligned_y_true = sentinel_y_true_arr[valid_indices]
            sentinel_pred = np.array([1 if d != "ALLOW" else 0 for d in aligned_sentinel_decisions])
            baseline_pred = np.array([1 if d != "ALLOW" else 0 for d in decisions])
            mcnemar_results[name] = mcnemar_test(sentinel_pred, baseline_pred, aligned_y_true)
            logger.info(
                f"    McNemar's test (SENTINEL vs {name}, n={len(valid_indices)}): "
                f"p={mcnemar_results[name]['p_value']:.4f} "
                f"({'significant' if mcnemar_results[name]['p_value'] < 0.05 else 'not significant'} at α=0.05)"
            )
        else:
            logger.warning(f"    Skipping McNemar's test for '{name}' — baseline unavailable")

    return {
        "meta": {"dataset": dataset_name, "n_samples": len(samples), "baselines_requested": baseline_names},
        "sentinel": {
            "classification": sentinel_classification.to_dict(),
        },
        "baselines": baseline_results,
        "mcnemar_vs_sentinel": mcnemar_results,
    }
