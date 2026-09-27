"""
Phase 4 Benchmark Verification — PHASE4_PROTOCOL.md Section 3.1.

A generated sample's "vector count" is construction INTENT only, not a
ground-truth label. This script runs the real, full pipeline (all five
layers, real correlation engine, nothing disabled — the same
`simulate_pipeline` the ablation matrix uses) on every sample in
`sentinel/eval/data/phase4_benchmark/all.jsonl`, counts how many layers'
own score independently crosses `WARN_THRESHOLD` (0.50), and records that
as the MEASURED vector count — the number every downstream Phase 4
analysis (the ablation matrix's per-bucket breakdown, the unique-detection
metric's per-bucket split) actually groups by, not the intended bucket.

ACCEPTANCE CRITERION — one clarification beyond the protocol's literal
text, stated here rather than silently assumed: Section 3.1 says a sample
is "accepted into bucket k" if exactly k layers cross AND the correlation
engine flags the session. Applied literally to the 1-vector bucket this
would be self-contradictory — Section 3.2 describes that bucket as "a
real detection, not a multi-vector case," i.e. explicitly NOT expected to
need correlation. This script therefore requires the correlation-firing
condition only for samples whose own construction `expected_detection`
declares a `correlation` key (every bucket except single_vector_injection);
the 1-vector bucket's acceptance is measured-count-match alone. Both the
raw measured count and the correlation-fired flag are recorded for every
sample regardless, so this interpretation choice is fully auditable from
the output, not hidden in a pass/fail bit.

Usage:
    python -m sentinel.eval.verify_phase4_benchmark
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime
from collections import Counter, defaultdict
from pathlib import Path

from sentinel.config import WARN_THRESHOLD
from sentinel.eval.pipeline_sim import simulate_pipeline

logger = logging.getLogger(__name__)

_DATA_DIR = Path(__file__).parent / "data" / "phase4_benchmark"
_RESULTS_DIR = Path(__file__).parent / "results"
ALL_LAYERS = ("L1", "L2", "L3", "L4", "L5")


async def verify_phase4_benchmark(limit: int | None = None) -> dict:
    in_path = _DATA_DIR / "all.jsonl"
    if not in_path.exists():
        return {"error": f"{in_path} not found — generate the benchmark first with "
                          "python -m sentinel.eval.generate_phase4_benchmark"}

    with open(in_path, encoding="utf-8") as f:
        samples = [json.loads(line) for line in f if line.strip()]
    if limit:
        samples = samples[:limit]

    _started = time.monotonic()
    logger.info(f"Verifying {len(samples)} Phase 4 benchmark samples against the real pipeline...")

    per_sample: list[dict] = []
    mismatch_count = 0
    for i, s in enumerate(samples):
        if (i + 1) % 50 == 0:
            logger.info(f"  {i + 1}/{len(samples)}...")
        result = await simulate_pipeline(s["text"], sample_id=s["sample_id"])
        measured_crossing = [L for L in ALL_LAYERS if result.layer_scores[L] >= WARN_THRESHOLD]
        measured_n = len(measured_crossing)
        intent_n = s["metadata"].get("n_vectors_intent", 0)
        expects_correlation = "correlation" in s["metadata"].get("expected_detection", {})
        correlation_ok = (result.correlation_fired is not None) if expects_correlation else True
        accepted = (measured_n == intent_n) and correlation_ok
        if not accepted:
            mismatch_count += 1

        per_sample.append({
            "sample_id": s["sample_id"],
            "bucket_intent": s["metadata"].get("bucket", "benign"),
            "label": s["label"],
            "n_vectors_intent": intent_n,
            "n_vectors_measured": measured_n,
            "layers_crossing_measured": measured_crossing,
            "layer_scores": {k: round(v, 4) for k, v in result.layer_scores.items()},
            "correlation_fired": result.correlation_fired,
            "final_decision": result.final_decision,
            "accepted_into_intended_bucket": accepted,
        })

    # Per-bucket summary: intent vs measured distribution
    by_bucket: dict[str, list[dict]] = defaultdict(list)
    for row in per_sample:
        if row["label"] == "malicious":
            by_bucket[row["bucket_intent"]].append(row)

    bucket_summary = {}
    for bucket, rows in by_bucket.items():
        measured_dist = Counter(r["n_vectors_measured"] for r in rows)
        n_accepted = sum(1 for r in rows if r["accepted_into_intended_bucket"])
        bucket_summary[bucket] = {
            "n_samples": len(rows),
            "n_vectors_intent": rows[0]["n_vectors_intent"],
            "measured_vector_count_distribution": dict(sorted(measured_dist.items())),
            "n_accepted_into_intended_bucket": n_accepted,
            "n_relabeled": len(rows) - n_accepted,
            "correlation_fired_rate": sum(1 for r in rows if r["correlation_fired"]) / len(rows),
        }

    result_summary = {
        "n_total": len(samples),
        "n_malicious": sum(1 for s in samples if s["label"] == "malicious"),
        "n_benign": sum(1 for s in samples if s["label"] == "benign"),
        "n_mismatched_overall": mismatch_count,
        "warn_threshold_used": WARN_THRESHOLD,
        "bucket_summary": bucket_summary,
    }

    out_path = _DATA_DIR / "verification.jsonl"
    with open(out_path, "w", encoding="utf-8") as f:
        for row in per_sample:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    summary_path = _RESULTS_DIR / "phase4_verification_summary.json"
    _RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(result_summary, f, indent=2)

    logger.info(f"\nVerification complete: {len(samples) - mismatch_count}/{len(samples)} "
                f"matched intended bucket exactly.")
    for bucket, info in bucket_summary.items():
        logger.info(f"  {bucket}: intent={info['n_vectors_intent']}, "
                    f"measured_dist={info['measured_vector_count_distribution']}, "
                    f"accepted={info['n_accepted_into_intended_bucket']}/{info['n_samples']}, "
                    f"corr_rate={info['correlation_fired_rate']:.2f}")
    logger.info(f"Per-sample detail: {out_path}")
    logger.info(f"Summary: {summary_path}")

    # Provenance. With no git repo in this project the ledger is the only
    # thing tying these counts to the code that produced them, and these
    # counts move: the 2026-09-19 re-run measured 209/460 matching intent
    # where the previous run measured 281/460, entirely because L4's
    # duplicate-candidate bug had been inflating crossing counts.
    # `safe_append_entry` cannot fail the run it records.
    import sentinel.config as _cfg
    from sentinel.eval.results_ledger import code_files_for, safe_append_entry

    safe_append_entry(
        experiment_id=f"phase4_verify_{datetime.now():%Y%m%d_%H%M%S}",
        phase="Phase 4 / PHASE4_PROTOCOL 3.1",
        code_files=code_files_for(
            "sentinel/eval/verify_phase4_benchmark.py",
            "sentinel/eval/pipeline_sim.py",
            "sentinel/layers/layer4_agentic/tool_auditor.py",
            "sentinel/layers/layer4_agentic/risk_matrix.py",
        ),
        dataset_cache_file=str(_DATA_DIR / "all.jsonl"),
        split=f"all {len(samples)} Phase 4 benchmark samples",
        thresholds_used={
            "WARN_THRESHOLD": WARN_THRESHOLD,
            "l1_llm_judge_enabled": getattr(_cfg, "L1_LLM_JUDGE_ENABLED", True),
        },
        metrics=result_summary,
        result_file=str(summary_path),
        runtime_seconds=round(time.monotonic() - _started, 1),
        notes=(
            "Measured vector count per sample from the real pipeline, replacing "
            "construction intent. A drop in matched counts is not a regression: it "
            "usually means a layer stopped emitting a spurious crossing."
        ),
    )

    return result_summary


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Verify Phase 4 benchmark vector counts against the real pipeline")
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(message)s")
    asyncio.run(verify_phase4_benchmark(limit=args.limit))


if __name__ == "__main__":
    main()
