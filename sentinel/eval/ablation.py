"""
Ablation Studies — evaluation plan doc, Section 4.

Runs the full pipeline (via pipeline_sim.simulate_pipeline) against
SENTINEL-Bench with each layer, and each correlation rule, individually
disabled — measuring the drop in detection rate relative to the full,
nothing-disabled baseline. This is what answers the specific, predictable
reviewer question the evaluation plan doc names directly: "did you show
each component matters, or are some of them just adding latency?"

WHAT "DETECTION" MEANS FOR THIS PURPOSE
------------------------------------------
A malicious sample counts as detected if `final_decision != "ALLOW"`
(i.e. WARN or BLOCK) — this matches `compute_pipeline_metrics`'s existing
notion of detection used elsewhere in the eval framework, not the stricter
`decision == "BLOCK"` alone.

INTERPRETING THE RESULTS
---------------------------
For each chain type, the corpus already encodes which layers/rule are
*expected* to be relevant (`metadata.layers_involved`,
`metadata.expected_detection.correlation`). This gives a strong, specific
sanity check: disabling a layer NOT involved in a given chain type should
produce close to zero recall drop on samples of that type; disabling a
layer that IS involved should produce a large drop (ideally down to
whatever recall the OTHER involved layers/rules can still catch on their
own). The report below breaks results down per chain type specifically so
this check is easy to make, rather than only reporting one pooled number
that would average away exactly the signal that matters.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field

from sentinel.eval.dataset_loaders import load_dataset
from sentinel.eval.pipeline_sim import simulate_pipeline

logger = logging.getLogger(__name__)

ALL_LAYERS = ("L1", "L2", "L3", "L4", "L5")
ALL_RULES = ("SLOW_BURN_INJECTION", "RAG_PLUS_AGENT_ATTACK", "EXFIL_AFTER_PROBE", "TAINT_PATH_DETECTED")


@dataclass
class AblationConditionResult:
    condition: str  # "baseline", "no_L1", "no_L2", ..., "no_SLOW_BURN_INJECTION", ...
    overall_recall: float          # fraction with final_decision != "ALLOW"
    overall_block_rate: float      # fraction with final_decision == "BLOCK" specifically
    n_malicious: int
    n_detected: int
    n_blocked: int
    recall_by_chain_type: dict[str, float] = field(default_factory=dict)
    block_rate_by_chain_type: dict[str, float] = field(default_factory=dict)
    false_positive_rate: float = 0.0

    def to_dict(self) -> dict:
        return {
            "condition": self.condition,
            "overall_recall": self.overall_recall,
            "overall_block_rate": self.overall_block_rate,
            "n_malicious": self.n_malicious,
            "n_detected": self.n_detected,
            "n_blocked": self.n_blocked,
            "recall_by_chain_type": self.recall_by_chain_type,
            "block_rate_by_chain_type": self.block_rate_by_chain_type,
            "false_positive_rate": self.false_positive_rate,
        }


async def _run_condition(
    condition_name: str,
    malicious_samples: list,
    benign_samples: list,
    disabled_layers: frozenset[str],
    disabled_rules: frozenset[str],
) -> AblationConditionResult:
    detected_by_type: dict[str, int] = defaultdict(int)
    blocked_by_type: dict[str, int] = defaultdict(int)
    total_by_type: dict[str, int] = defaultdict(int)
    n_detected = 0
    n_blocked = 0

    for sample in malicious_samples:
        result = await simulate_pipeline(
            sample.text, sample_id=sample.sample_id,
            disabled_layers=disabled_layers, disabled_rules=disabled_rules,
        )
        detected = result.final_decision != "ALLOW"
        blocked = result.final_decision == "BLOCK"
        chain_type = sample.attack_type or "unknown"
        total_by_type[chain_type] += 1
        if detected:
            detected_by_type[chain_type] += 1
            n_detected += 1
        if blocked:
            blocked_by_type[chain_type] += 1
            n_blocked += 1

    n_fp = 0
    for sample in benign_samples:
        result = await simulate_pipeline(
            sample.text, sample_id=sample.sample_id,
            disabled_layers=disabled_layers, disabled_rules=disabled_rules,
        )
        if result.final_decision != "ALLOW":
            n_fp += 1

    recall_by_chain_type = {
        t: detected_by_type[t] / total_by_type[t] for t in total_by_type
    }
    block_rate_by_chain_type = {
        t: blocked_by_type[t] / total_by_type[t] for t in total_by_type
    }

    return AblationConditionResult(
        condition=condition_name,
        overall_recall=(n_detected / len(malicious_samples)) if malicious_samples else float("nan"),
        overall_block_rate=(n_blocked / len(malicious_samples)) if malicious_samples else float("nan"),
        n_malicious=len(malicious_samples),
        n_detected=n_detected,
        n_blocked=n_blocked,
        recall_by_chain_type=recall_by_chain_type,
        block_rate_by_chain_type=block_rate_by_chain_type,
        false_positive_rate=(n_fp / len(benign_samples)) if benign_samples else float("nan"),
    )


async def run_ablation_study(
    dataset_name: str = "sentinel_bench",
    limit: int | None = None,
    layers: tuple[str, ...] = ALL_LAYERS,
    rules: tuple[str, ...] = ALL_RULES,
) -> dict:
    """
    Run the baseline (nothing disabled) condition, then leave-one-layer-out
    for each layer in `layers`, then leave-one-rule-out for each rule in
    `rules`. Returns a dict with all conditions' results plus, for each
    ablation, the recall DELTA versus baseline (both overall and per chain
    type) — the delta is the number that actually answers "does this
    component matter."
    """
    dataset = load_dataset(dataset_name, limit=limit)
    if not dataset.samples:
        return {"error": f"Dataset '{dataset_name}' has no samples (not generated/downloaded yet?)"}

    malicious = [s for s in dataset.samples if s.label == "malicious"]
    benign = [s for s in dataset.samples if s.label == "benign"]
    if not malicious:
        return {"error": f"Dataset '{dataset_name}' has no malicious samples — nothing to ablate against"}

    logger.info(f"Ablation study: {len(malicious)} malicious, {len(benign)} benign samples from '{dataset_name}'")

    conditions: dict[str, AblationConditionResult] = {}

    logger.info("  Running baseline (nothing disabled)...")
    conditions["baseline"] = await _run_condition(
        "baseline", malicious, benign, frozenset(), frozenset()
    )
    logger.info(
        f"    baseline: recall={conditions['baseline'].overall_recall:.4f} "
        f"block_rate={conditions['baseline'].overall_block_rate:.4f} "
        f"FPR={conditions['baseline'].false_positive_rate:.4f}"
    )

    for layer in layers:
        name = f"no_{layer}"
        logger.info(f"  Running leave-one-out: {name}...")
        conditions[name] = await _run_condition(
            name, malicious, benign, frozenset({layer}), frozenset()
        )
        delta = conditions[name].overall_recall - conditions["baseline"].overall_recall
        block_delta = conditions[name].overall_block_rate - conditions["baseline"].overall_block_rate
        logger.info(f"    {name}: recall={conditions[name].overall_recall:.4f} (delta={delta:+.4f}), block_rate delta={block_delta:+.4f}")

    for rule in rules:
        name = f"no_{rule}"
        logger.info(f"  Running leave-one-out: {name}...")
        conditions[name] = await _run_condition(
            name, malicious, benign, frozenset(), frozenset({rule})
        )
        delta = conditions[name].overall_recall - conditions["baseline"].overall_recall
        block_delta = conditions[name].overall_block_rate - conditions["baseline"].overall_block_rate
        logger.info(f"    {name}: recall={conditions[name].overall_recall:.4f} (delta={delta:+.4f}), block_rate delta={block_delta:+.4f}")

    baseline_recall = conditions["baseline"].overall_recall
    baseline_block_rate = conditions["baseline"].overall_block_rate
    deltas = {
        name: {
            "overall_recall_delta": result.overall_recall - baseline_recall,
            "overall_block_rate_delta": result.overall_block_rate - baseline_block_rate,
            "recall_by_chain_type_delta": {
                t: result.recall_by_chain_type.get(t, float("nan")) - conditions["baseline"].recall_by_chain_type.get(t, float("nan"))
                for t in conditions["baseline"].recall_by_chain_type
            },
        }
        for name, result in conditions.items() if name != "baseline"
    }

    return {
        "meta": {
            "dataset": dataset_name, "n_malicious": len(malicious), "n_benign": len(benign),
            "note": (
                "overall_recall counts final_decision != 'ALLOW' (matches "
                "compute_pipeline_metrics elsewhere). Some correlation rules "
                "(e.g. SLOW_BURN_INJECTION, whose trigger condition requires "
                "L3 > 0.7, which independently already exceeds WARN_THRESHOLD "
                "0.50) can only ever show up in overall_block_rate_delta "
                "(BLOCK downgrading to WARN), never in overall_recall_delta "
                "(WARN is still 'detected') — that's real pipeline behavior, "
                "not a methodology bug. Check both deltas, not recall alone, "
                "when interpreting a correlation rule's ablation result."
            ),
        },
        "conditions": {name: r.to_dict() for name, r in conditions.items()},
        "deltas_vs_baseline": deltas,
    }
