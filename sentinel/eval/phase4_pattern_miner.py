"""
Phase 4 Pattern-Miner Integration — PHASE4_PROTOCOL.md Section 2, rows 8-9.

CLOSES THE GAP DOCUMENTED IN THE PROTOCOL
--------------------------------------------
Contribution C's pattern miner (`core/pattern_mining.py`) has only ever
been evaluated standalone (`pattern_mining_eval.py`'s held-out-chain-type
generalization check) — it was never wired into the live
`check_correlations`/`simulate_pipeline` decision path. This means
"Full SENTINEL (everything)" as measurable through the *existing*
pipeline does not actually include the pattern miner. This module is a
genuinely new, eval-only integration: it mines a pattern set once (from
the exact same mining-set sessions and parameters Contribution C's
reported generalization result used — 225 malicious training sessions
across sentinel_bench's 3 non-held-out chain types, 200 benign,
`min_support_positive=0.15`, `min_discriminativeness=0.8`,
`max_pattern_length=4` — see `pattern_mining_eval.py`'s own defaults),
saves it to disk (no prior run did — confirmed by search, not assumed),
and exposes a function that buckets a `PipelineSimResult.layer_scores`
dict into the same discrete-event-sequence representation the miner
already uses and checks it against the mined set.

This is a wrapper AROUND `simulate_pipeline`'s result, never a change to
`correlation_engine.py` itself — mirrors how the L1 judge fallback chain
was added as an eval-only monkeypatch in Phase 3.1, leaving production
untouched.
"""

from __future__ import annotations

import json
import logging
from collections import defaultdict
from pathlib import Path

from sentinel.eval.dataset_loaders import load_dataset, _DATA_DIR as _SB_DATA_DIR
from sentinel.eval.pipeline_sim import simulate_pipeline
from sentinel.core.pattern_mining import bucket_score, mine_discriminative_patterns, MinedPattern

logger = logging.getLogger(__name__)

_RESULTS_DIR = Path(__file__).parent / "results"
ALL_LAYERS = ("L1", "L2", "L3", "L4", "L5")

MIN_SUPPORT_POSITIVE = 0.15
MIN_DISCRIMINATIVENESS = 0.8
MAX_PATTERN_LENGTH = 4

_MINED_PATTERNS_PATH = _RESULTS_DIR / "phase4_mined_patterns.json"


def sequence_for_layer_scores(layer_scores: dict[str, float]) -> list[str]:
    """Same bucketed-event-sequence representation pattern_mining_eval.py
    already uses: one discretized symbol per layer, in fixed L1..L5 order."""
    return [f"{L}:{bucket_score(layer_scores[L])}" for L in ALL_LAYERS]


async def mine_phase4_patterns(force: bool = False) -> list[MinedPattern]:
    """Mine (or load a cached) pattern set from sentinel_bench's own
    mining_set.jsonl (3 non-held-out chain types + all 200 benign, 225
    malicious sessions total — matches Contribution C's original
    generalization-check mining split, NOT a Phase-4-specific corpus:
    the miner stays frozen from earlier work per protocol Section 3.4,
    this benchmark is measurement-only, never used for mining/tuning)."""
    if _MINED_PATTERNS_PATH.exists() and not force:
        data = json.loads(_MINED_PATTERNS_PATH.read_text(encoding="utf-8"))
        return [
            MinedPattern(
                pattern=tuple(p["pattern"]),
                support_positive=p["support_positive"],
                support_negative=p["support_negative"],
                count_positive=p["count_positive"],
                count_negative=p["count_negative"],
            )
            for p in data["mined_patterns"]
        ]

    mining_dataset = load_dataset("sentinel_bench", split="mining_set")
    if not mining_dataset.samples:
        raise RuntimeError("sentinel_bench mining_set.jsonl not found or empty — "
                            "generate the corpus first with generate_sentinel_bench")

    logger.info(f"Mining Phase 4 pattern set from {len(mining_dataset.samples)} mining_set sessions...")
    positive_sequences: list[list[str]] = []
    negative_sequences: list[list[str]] = []
    for i, sample in enumerate(mining_dataset.samples):
        if (i + 1) % 50 == 0:
            logger.info(f"  {i + 1}/{len(mining_dataset.samples)}...")
        result = await simulate_pipeline(sample.text, sample_id=sample.sample_id)
        seq = sequence_for_layer_scores(result.layer_scores)
        if sample.label == "malicious":
            positive_sequences.append(seq)
        else:
            negative_sequences.append(seq)

    logger.info(f"  {len(positive_sequences)} positive, {len(negative_sequences)} negative sequences built")

    mined = mine_discriminative_patterns(
        positive_sequences=positive_sequences,
        negative_sequences=negative_sequences,
        min_support_positive=MIN_SUPPORT_POSITIVE,
        min_discriminativeness=MIN_DISCRIMINATIVENESS,
        max_pattern_length=MAX_PATTERN_LENGTH,
    )
    logger.info(f"  {len(mined)} discriminative patterns mined")

    _RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    _MINED_PATTERNS_PATH.write_text(json.dumps({
        "meta": {
            "n_positive_sequences": len(positive_sequences),
            "n_negative_sequences": len(negative_sequences),
            "min_support_positive": MIN_SUPPORT_POSITIVE,
            "min_discriminativeness": MIN_DISCRIMINATIVENESS,
            "max_pattern_length": MAX_PATTERN_LENGTH,
            "source": "sentinel_bench mining_set.jsonl (3 non-held-out chain types, matches Contribution C's own mining split)",
        },
        "mined_patterns": [
            {
                "pattern": list(mp.pattern),
                "support_positive": mp.support_positive,
                "support_negative": mp.support_negative,
                "count_positive": mp.count_positive,
                "count_negative": mp.count_negative,
                "discriminativeness": mp.discriminativeness,
            }
            for mp in mined
        ],
    }, indent=2), encoding="utf-8")
    logger.info(f"  Saved to {_MINED_PATTERNS_PATH}")

    return mined


def _is_subsequence(pattern: tuple[str, ...], sequence: list[str]) -> bool:
    it = iter(sequence)
    return all(item in it for item in pattern)


def pattern_miner_flags(layer_scores: dict[str, float], mined_patterns: list[MinedPattern]) -> bool:
    """True if this sample's bucketed layer-score sequence matches at
    least one mined pattern — the eval-only "detection" signal rows 8-9
    add on top of simulate_pipeline's own result."""
    seq = sequence_for_layer_scores(layer_scores)
    return any(_is_subsequence(mp.pattern, seq) for mp in mined_patterns)


def main() -> None:
    import argparse
    import asyncio
    parser = argparse.ArgumentParser(description="Mine (or re-mine) the Phase 4 pattern set")
    parser.add_argument("--force", action="store_true", help="Re-mine even if a cached pattern set exists")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(message)s")
    mined = asyncio.run(mine_phase4_patterns(force=args.force))
    logger.info(f"Done: {len(mined)} patterns.")


if __name__ == "__main__":
    main()
