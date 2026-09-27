"""
SPRT Live Evaluation — Contribution B (research roadmap doc, Section 3).

WHAT THIS CLOSES
------------------
`sentinel/core/sequential_triage.py` implements Wald's SPRT fully and its
*statistical* correctness is verified against synthetic score distributions
(`tests/test_sequential_triage.py`) — but until now, nothing had ever fit
`LikelihoodModel` on this pipeline's actual per-layer score distributions or
run `SequentialTriageEngine` against a real session. This module closes that
gap using `sentinel_bench`'s own train/test split: fit per-layer densities
on `train.jsonl`, run the triage engine against `test.jsonl`.

WHAT THIS DOES AND DOESN'T CLAIM — READ BEFORE TRUSTING THE NUMBERS
------------------------------------------------------------------------
This evaluates whether SPRT's *stopping rule* and *decision* are correct
against real per-layer score sequences — it does NOT demonstrate real
wall-clock/compute savings in this harness. `simulate_pipeline()` always
computes all 5 layers' real scores first; SPRT is then applied post-hoc to
the resulting fixed sequence to determine where it *would* have stopped.
`layers_consulted` is therefore a valid count of how many layers SPRT
needed to reach a decision, not a latency measurement — closing that gap
for real would require restructuring `simulate_pipeline` to short-circuit
mid-sequence, a separate engineering task. Same kind of stated
approximation as `pipeline_sim.py`'s own two documented ones.

Small-sample note: `sentinel_bench` train=463 (316 malicious/147 benign) /
test=112 (59/53) is workable for 1D KDE fitting (well above
`LikelihoodModel`'s own >=2-examples-per-class floor) but modest — report
with real n, not to more precision than that supports.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field

from sentinel.eval.dataset_loaders import load_dataset
from sentinel.eval.pipeline_sim import simulate_pipeline
from sentinel.core.sequential_triage import (
    LikelihoodModel, SPRTBoundaries, SequentialTriageEngine, Decision,
)

logger = logging.getLogger(__name__)

ALL_LAYERS = ("L1", "L2", "L3", "L4", "L5")


@dataclass
class SPRTEvalResult:
    n_train: int
    n_test: int
    alpha: float
    beta: float
    log_A: float
    log_B: float
    n_malicious: int
    n_benign: int
    accuracy: float
    precision: float
    recall: float
    fpr: float
    decision_agreement_with_full_cascade: float
    mean_layers_consulted: float
    mean_layers_consulted_malicious: float
    mean_layers_consulted_benign: float
    exhausted_rate: float
    per_sample: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "n_train": self.n_train,
            "n_test": self.n_test,
            "alpha": self.alpha,
            "beta": self.beta,
            "log_A": self.log_A,
            "log_B": self.log_B,
            "n_malicious": self.n_malicious,
            "n_benign": self.n_benign,
            "accuracy": self.accuracy,
            "precision": self.precision,
            "recall": self.recall,
            "fpr": self.fpr,
            "decision_agreement_with_full_cascade": self.decision_agreement_with_full_cascade,
            "mean_layers_consulted": self.mean_layers_consulted,
            "mean_layers_consulted_malicious": self.mean_layers_consulted_malicious,
            "mean_layers_consulted_benign": self.mean_layers_consulted_benign,
            "exhausted_rate": self.exhausted_rate,
            "per_sample": self.per_sample,
        }


async def run_sprt_evaluation(
    alpha: float = 0.05,
    beta: float = 0.05,
    limit: int | None = None,
) -> dict:
    """
    Fit per-layer LikelihoodModels on sentinel_bench's real train split,
    then run the SequentialTriageEngine against real test-split sessions.
    Returns a plain dict (see SPRTEvalResult.to_dict) matching the shape
    of ablation.py's / redteam.py's result dicts for save_results().
    """
    train_dataset = load_dataset("sentinel_bench", split="train", limit=limit)
    test_dataset = load_dataset("sentinel_bench", split="test", limit=limit)

    if not train_dataset.samples or not test_dataset.samples:
        return {"error": "sentinel_bench train/test split not found — generate it first "
                          "with python -m sentinel.eval.generate_sentinel_bench"}

    logger.info(f"SPRT eval: fitting on {len(train_dataset.samples)} train samples, "
                f"testing on {len(test_dataset.samples)} test samples")

    # --- 1. Score every train sample through the real pipeline ---
    train_scores_by_layer: dict[str, list[float]] = {L: [] for L in ALL_LAYERS}
    train_labels_by_layer: dict[str, list[int]] = {L: [] for L in ALL_LAYERS}

    for i, sample in enumerate(train_dataset.samples):
        if (i + 1) % 50 == 0:
            logger.info(f"  [train] {i + 1}/{len(train_dataset.samples)}...")
        result = await simulate_pipeline(sample.text, sample_id=sample.sample_id)
        label = 1 if sample.label == "malicious" else 0
        for L in ALL_LAYERS:
            train_scores_by_layer[L].append(result.layer_scores[L])
            train_labels_by_layer[L].append(label)

    # --- 2. Fit one LikelihoodModel per layer, build the SPRT engine ---
    boundaries = SPRTBoundaries.from_error_rates(alpha=alpha, beta=beta)
    engine = SequentialTriageEngine(boundaries)
    for L in ALL_LAYERS:
        model = LikelihoodModel(L)
        model.fit(train_scores_by_layer[L], train_labels_by_layer[L])
        engine.register_model(model)

    # --- 3. Run the real triage engine against real test-split sessions ---
    n_correct = 0
    n_tp = n_fp = n_fn = n_tn = 0
    n_agree = 0
    n_exhausted = 0
    layers_consulted_all: list[int] = []
    layers_consulted_mal: list[int] = []
    layers_consulted_ben: list[int] = []
    per_sample: list[dict] = []

    for i, sample in enumerate(test_dataset.samples):
        if (i + 1) % 20 == 0:
            logger.info(f"  [test] {i + 1}/{len(test_dataset.samples)}...")
        result = await simulate_pipeline(sample.text, sample_id=sample.sample_id)
        is_malicious = sample.label == "malicious"

        layer_score_seq = [(L, result.layer_scores[L]) for L in ALL_LAYERS]
        triage = engine.run(layer_score_seq)

        sprt_positive = triage.decision == Decision.BLOCK
        cascade_positive = result.final_decision != "ALLOW"

        correct = sprt_positive == is_malicious
        n_correct += correct
        if is_malicious and sprt_positive:
            n_tp += 1
        elif is_malicious and not sprt_positive:
            n_fn += 1
        elif not is_malicious and sprt_positive:
            n_fp += 1
        else:
            n_tn += 1

        if sprt_positive == cascade_positive:
            n_agree += 1

        n_layers = len(triage.layers_consulted)
        layers_consulted_all.append(n_layers)
        (layers_consulted_mal if is_malicious else layers_consulted_ben).append(n_layers)
        if triage.exhausted:
            n_exhausted += 1

        per_sample.append({
            "sample_id": sample.sample_id,
            "label": sample.label,
            "attack_type": sample.attack_type,
            "sprt_decision": triage.decision.value,
            "layers_consulted": triage.layers_consulted,
            "final_log_llr": triage.final_log_llr,
            "exhausted": triage.exhausted,
            "full_cascade_decision": result.final_decision,
        })

    n = len(test_dataset.samples)
    mean = lambda xs: (sum(xs) / len(xs)) if xs else float("nan")

    eval_result = SPRTEvalResult(
        n_train=len(train_dataset.samples),
        n_test=n,
        alpha=alpha,
        beta=beta,
        log_A=boundaries.log_A,
        log_B=boundaries.log_B,
        n_malicious=n_tp + n_fn,
        n_benign=n_fp + n_tn,
        accuracy=n_correct / n if n else float("nan"),
        precision=(n_tp / (n_tp + n_fp)) if (n_tp + n_fp) else float("nan"),
        recall=(n_tp / (n_tp + n_fn)) if (n_tp + n_fn) else float("nan"),
        fpr=(n_fp / (n_fp + n_tn)) if (n_fp + n_tn) else float("nan"),
        decision_agreement_with_full_cascade=n_agree / n if n else float("nan"),
        mean_layers_consulted=mean(layers_consulted_all),
        mean_layers_consulted_malicious=mean(layers_consulted_mal),
        mean_layers_consulted_benign=mean(layers_consulted_ben),
        exhausted_rate=n_exhausted / n if n else float("nan"),
        per_sample=per_sample,
    )

    logger.info(
        f"\nSPRT eval results: accuracy={eval_result.accuracy:.4f} "
        f"precision={eval_result.precision:.4f} recall={eval_result.recall:.4f} "
        f"FPR={eval_result.fpr:.4f}\n"
        f"  decision_agreement_with_full_cascade={eval_result.decision_agreement_with_full_cascade:.4f}\n"
        f"  mean_layers_consulted={eval_result.mean_layers_consulted:.2f}/5 "
        f"(malicious={eval_result.mean_layers_consulted_malicious:.2f}, "
        f"benign={eval_result.mean_layers_consulted_benign:.2f})\n"
        f"  exhausted_rate={eval_result.exhausted_rate:.4f}"
    )

    return eval_result.to_dict()
