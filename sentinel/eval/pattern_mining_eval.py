"""
Pattern-Mining Live Evaluation — Contribution C (research roadmap doc,
Section 4).

WHAT THIS CLOSES
------------------
`sentinel/core/pattern_mining.py` implements PrefixSpan-style pattern
mining plus a mandatory held-out-chain-type generalization check
(`evaluate_pattern_generalization`), verified only against synthetic
sequences (`tests/test_pattern_mining.py`) until now. `sentinel_bench`
itself was already built with this exact test in mind —
`sentinel/eval/data/sentinel_bench/metadata.json` declares
`held_out_chain_types` and ships two purpose-built files,
`mining_set.jsonl` (the 3 non-held-out chain types + all 200 benign
samples) and `held_out.jsonl` (the 2 held-out chain types, correctly zero
benign) — that groundwork was never actually run through real pipeline
scores. This module does that: real `simulate_pipeline()` scores, bucketed
via the module's own `bucket_score`, fed through the real generalization
check.

REPORTED HONESTLY
--------------------
Per the module's own "mandatory validation, not optional" stance and this
project's standing discipline: `held_out_recall` may come back low (the
synthetic unit test's own honest negative result is exactly this — mined
patterns keyed on exact discretized scores don't transfer to structurally
novel chain types). Report whatever the real number is; do not tune
`min_support_positive`/`min_discriminativeness` to force a better one.
Small-sample note: ~75 samples per chain type — state real per-type n
alongside any recall number.
"""

from __future__ import annotations

import json
import logging
from collections import defaultdict

from sentinel.eval.dataset_loaders import load_dataset, _DATA_DIR
from sentinel.eval.pipeline_sim import simulate_pipeline
from sentinel.core.pattern_mining import bucket_score, evaluate_pattern_generalization

logger = logging.getLogger(__name__)

ALL_LAYERS = ("L1", "L2", "L3", "L4", "L5")


def _pattern_to_str(pattern: tuple[str, ...]) -> str:
    return " -> ".join(pattern)


async def _bucketed_sequence(text: str, sample_id: str) -> list[str]:
    result = await simulate_pipeline(text, sample_id=sample_id)
    return [f"{L}:{bucket_score(result.layer_scores[L])}" for L in ALL_LAYERS]


async def run_pattern_mining_evaluation(
    min_support_positive: float = 0.15,
    min_discriminativeness: float = 0.8,
    max_pattern_length: int = 4,
    test_fraction: float = 0.3,
    limit: int | None = None,
) -> dict:
    """
    Run real sentinel_bench sessions through the pipeline, bucket their
    per-layer scores, and feed the resulting sequences through the real
    mandatory generalization check — held-out chain types read from
    sentinel_bench's own metadata.json rather than hardcoded, so this stays
    correct if the corpus is ever regenerated with different held-out types.
    """
    metadata_path = _DATA_DIR / "sentinel_bench" / "metadata.json"
    if not metadata_path.exists():
        return {"error": "sentinel_bench metadata.json not found — generate the corpus first "
                          "with python -m sentinel.eval.generate_sentinel_bench"}
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    held_out_types = metadata["held_out_chain_types"]

    mining_dataset = load_dataset("sentinel_bench", split="mining_set", limit=limit)
    held_out_dataset = load_dataset("sentinel_bench", split="held_out", limit=limit)

    if not mining_dataset.samples or not held_out_dataset.samples:
        return {"error": "sentinel_bench mining_set.jsonl/held_out.jsonl not found — generate the "
                          "corpus first with python -m sentinel.eval.generate_sentinel_bench"}

    logger.info(f"Pattern-mining eval: {len(mining_dataset.samples)} mining_set samples, "
                f"{len(held_out_dataset.samples)} held_out samples, "
                f"held_out_chain_types={held_out_types}")

    attack_sequences_by_type: dict[str, list[list[str]]] = defaultdict(list)
    benign_sequences: list[list[str]] = []

    all_samples = list(mining_dataset.samples) + list(held_out_dataset.samples)
    for i, sample in enumerate(all_samples):
        if (i + 1) % 50 == 0:
            logger.info(f"  {i + 1}/{len(all_samples)}...")
        seq = await _bucketed_sequence(sample.text, sample.sample_id)
        if sample.label == "malicious":
            attack_sequences_by_type[sample.attack_type].append(seq)
        else:
            benign_sequences.append(seq)

    n_by_type = {t: len(seqs) for t, seqs in attack_sequences_by_type.items()}
    logger.info(f"  Real per-type counts: {n_by_type}, benign={len(benign_sequences)}")

    report = evaluate_pattern_generalization(
        attack_sequences_by_type=dict(attack_sequences_by_type),
        benign_sequences=benign_sequences,
        held_out_types=held_out_types,
        min_support_positive=min_support_positive,
        min_discriminativeness=min_discriminativeness,
        max_pattern_length=max_pattern_length,
        test_fraction=test_fraction,
    )

    result = {
        "held_out_chain_types": held_out_types,
        "n_by_chain_type": n_by_type,
        "n_benign": len(benign_sequences),
        "min_support_positive": min_support_positive,
        "min_discriminativeness": min_discriminativeness,
        "max_pattern_length": max_pattern_length,
        "n_mined_patterns": len(report.mined_patterns),
        "mined_patterns": [
            {
                "pattern": _pattern_to_str(mp.pattern),
                "discriminativeness": mp.discriminativeness,
                "support_positive": mp.support_positive,
                "support_negative": mp.support_negative,
                "count_positive": mp.count_positive,
                "count_negative": mp.count_negative,
            }
            for mp in report.mined_patterns
        ],
        "known_type_recall": report.known_type_recall,
        "held_out_recall": report.held_out_recall,
        "benign_false_positive_rate": report.benign_false_positive_rate,
    }

    logger.info(
        f"\nPattern-mining eval results: {len(report.mined_patterns)} patterns mined\n"
        f"  known_type_recall={report.known_type_recall:.4f}\n"
        f"  held_out_recall={report.held_out_recall:.4f} (types={held_out_types})\n"
        f"  benign_false_positive_rate={report.benign_false_positive_rate:.4f}"
    )

    return result
