"""
Phase 4 orchestrator — runs pattern mining, benchmark verification, and the
9-configuration ablation matrix in one process, with the L1 judge routed
through OmniRoute's multi-provider fallback chain for the duration.

WHY THE FALLBACK IS NEEDED HERE (not just a Phase-3.1-only concern)
----------------------------------------------------------------------
SENTINEL's own Groq key is exhausted from this session's own heavy eval
traffic (same root cause as Phase 3.1's sweep, not a natural production
traffic pattern) — confirmed by direct observation: a verification/mining
run against the real, unpatched production judge showed the vast majority
of ambiguous-band judge calls returning HTTP 429 and being silently
skipped (`llm_judge_check` returns None on failure by design). Phase 4's
sub_threshold_slow_burn bucket specifically depends on several turns
landing in the ambiguous band (0.30-0.75) that only the judge tier can
resolve — running Phase 4 without a working judge signal would measure an
artifact of this session's own API-quota exhaustion, not the architecture.
Reuses `calibrate_l1_judge_band.py`'s exact, already-spot-checked fallback
chain (openai/gpt-oss-120b -> gemini-3.1-flash-lite -> command-a-03-2025
-> nvidia/nemotron-3-super-120b-a12b via OmniRoute, 127.0.0.1:20128) rather
than reimplementing it. Monkeypatches
`sentinel.layers.layer1_llm_judge.llm_judge_check` for this process's
lifetime only, restored in `finally` — production code and config are
never touched.

Usage:
    python -m sentinel.eval.run_phase4_full
"""

from __future__ import annotations

import asyncio
import logging

import sentinel.layers.layer1_llm_judge as judge_module
from sentinel.eval.calibrate_l1_judge_band import _fallback_judge_check, _JUDGE_FALLBACK_CHAIN, judge_fallback_stats

logger = logging.getLogger(__name__)


async def main() -> None:
    from sentinel.eval.phase4_pattern_miner import mine_phase4_patterns
    from sentinel.eval.verify_phase4_benchmark import verify_phase4_benchmark
    from sentinel.eval.run_phase4_ablation import run_phase4_ablation

    logger.info(f"Routing L1 judge through OmniRoute fallback chain {_JUDGE_FALLBACK_CHAIN} "
                "for this Phase 4 run (SENTINEL's own Groq key is quota-exhausted from this "
                "session's own eval traffic; production code/config untouched).")
    real_judge_check = judge_module.llm_judge_check
    judge_module.llm_judge_check = _fallback_judge_check

    try:
        logger.info("=" * 60)
        logger.info("STEP 1/3: Re-mining Phase 4 pattern set (force=True — the cached set "
                     "from the earlier unpatched run had a degraded judge signal)")
        logger.info("=" * 60)
        await mine_phase4_patterns(force=True)

        logger.info("=" * 60)
        logger.info("STEP 2/3: Verifying Phase 4 benchmark vector counts")
        logger.info("=" * 60)
        await verify_phase4_benchmark()

        logger.info("=" * 60)
        logger.info("STEP 3/3: Running the 9-configuration ablation matrix + U metric")
        logger.info("=" * 60)
        await run_phase4_ablation()

    finally:
        judge_module.llm_judge_check = real_judge_check
        logger.info(f"Restored production llm_judge_check. Fallback usage stats: {judge_fallback_stats}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Run all of Phase 4 (mine, verify, ablate) with the OmniRoute judge fallback active")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(message)s")
    asyncio.run(main())
