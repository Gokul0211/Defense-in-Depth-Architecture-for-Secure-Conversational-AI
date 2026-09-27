"""
Contribution F, sequential half — anytime-valid cross-turn e-processes.

WHAT THIS ADDS OVER evidence_fusion_eval.py
----------------------------------------------
That file evaluates the cross-LAYER merge as a single test per sample. It
explicitly does not evidence the sequential claim, because `pipeline_sim`
used to report only a max over turns. Per-turn L1/L3 scores are now exposed
(`PipelineSimResult.per_turn_layer_scores`), so the claims that were
previously unmeasurable can be measured:

  * **Anytime validity.** `EProcess` accumulates the product of per-turn
    merged e-values and alarms the first time it reaches 1/alpha. Ville's
    inequality bounds the probability that it EVER alarms on a benign
    session by alpha — not per-turn, but over the whole session, with no
    correction for how many turns were looked at. That is the property a
    fixed per-turn threshold does not have, and the reason multiple-testing
    is not an issue here.
  * **Detection delay.** `alarmed_at` gives the turn index at which the
    boundary was first crossed, which is the quantity that actually matters
    for a slow-burn attack: not whether it is eventually caught but how
    many turns of it the model has already answered.
  * **Unknown change point.** `MixtureEDetector` mixes over start times
    with weights 1/(tau(tau+1)), for attacks that begin mid-session.

WHY THE SEQUENTIAL PRODUCT IS LEGITIMATE HERE
------------------------------------------------
Multiplying across TURNS is valid where multiplying across LAYERS is not.
Successive turns are the sequential dimension the e-process is defined
over, and the running product is a non-negative supermartingale under the
null — exactly what Ville needs. Dependence between LAYERS within a turn is
a separate problem, handled by `merge_evalues("mean")`, which is valid under
arbitrary dependence. The two products are not the same operation and the
distinction is load-bearing.

ONLY L1 AND L3 ARE PER-TURN, AND THAT IS SENTINEL'S SHAPE NOT A SHORTCUT
--------------------------------------------------------------------------
L2 (document ingestion), L4 (tool audit) and L5 (output scan) each run once
per session, after the turn loop. So a cross-turn e-process sees two layers
evolving, not five. This is the right regime for the attack class it
targets — `sub_threshold_slow_burn` is precisely an L1+L3 drift pattern, and
it is the bucket where the hand-written correlation rules fire 0/100 — but
it does mean the sequential result is about drift detection specifically,
not about the whole architecture.

THE REACHABILITY CONSTRAINT STILL APPLIES, DIFFERENTLY
--------------------------------------------------------
A single turn's merged e-value is capped at `kappa*(n+1)^(1-kappa)` (see
`evidence_fusion.max_attainable_evalue`). But the e-process MULTIPLIES
across turns, so wealth compounds and the 1/alpha boundary becomes
reachable in a few turns even when one turn alone could never reach it.
That is a real advantage of the sequential form over the single-shot test,
and it is measured here rather than assumed: `turns_to_reach_bound` reports
how many maximally-evidenced turns are needed.

Usage:
    python -m sentinel.eval.eprocess_eval
"""

from __future__ import annotations

import asyncio
import json
import logging
import math
from datetime import datetime
from pathlib import Path

from sentinel.core.evidence_fusion import (
    EProcess,
    MixtureEDetector,
    calibrate_evalue_threshold,
    max_attainable_evalue,
    optimal_kappa,
    ville_threshold,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

_EVAL_DIR = Path(__file__).parent
_RESULTS = _EVAL_DIR / "results"
_CACHE = _EVAL_DIR / "data" / "per_turn_cache"

PER_TURN_LAYERS = ("L1", "L3")
ALPHA = 0.05


async def _per_turn_for_texts(samples: list[dict], cache_name: str) -> list[dict]:
    """
    Per-turn layer scores for each sample, cached to disk.

    Computed by re-running `simulate_pipeline` when a corpus predates the
    per-turn field, and cached because it costs real layer inference and
    every later analysis wants the same numbers. Tier 4 is pinned off so the
    cache is reproducible rather than contingent on a rate limiter.
    """
    _CACHE.mkdir(parents=True, exist_ok=True)
    path = _CACHE / f"{cache_name}.json"
    if path.exists():
        cached = json.loads(path.read_text(encoding="utf-8"))
        if len(cached) == len(samples):
            logger.info(f"  using cached per-turn scores for {cache_name} (n={len(cached)})")
            return cached
        logger.warning(f"  cache for {cache_name} has {len(cached)} rows but corpus has "
                       f"{len(samples)} — recomputing")

    import sentinel.config as cfg
    from sentinel.eval.pipeline_sim import simulate_pipeline

    judge_was = getattr(cfg, "L1_LLM_JUDGE_ENABLED", True)
    cfg.L1_LLM_JUDGE_ENABLED = False
    try:
        out = []
        for i, s in enumerate(samples):
            if (i + 1) % 100 == 0:
                logger.info(f"  scoring per-turn {i + 1}/{len(samples)}...")
            r = await simulate_pipeline(s["text"], sample_id=s["sample_id"])
            out.append({
                "sample_id": s["sample_id"],
                "label": s["label"],
                "bucket": s.get("bucket", ""),
                "per_turn": r.per_turn_layer_scores,
            })
    finally:
        cfg.L1_LLM_JUDGE_ENABLED = judge_was

    path.write_text(json.dumps(out), encoding="utf-8")
    return out


def load_split_bench_texts() -> list[dict]:
    from sentinel.eval.split_bench import _DATA_DIR as _SPLIT_DIR   # follows SPLIT_BENCH_DIR
    path = _SPLIT_DIR / "all.jsonl"
    if not path.exists():
        raise SystemExit("SPLIT-Bench not found; run sentinel.eval.split_bench first")
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
    out = []
    for r in rows:
        entry = {
            "sample_id": r["sample_id"],
            "label": r["label"],
            "text": r["text"],
            "bucket": f"k={r['metadata']['k_intended']}",
        }
        # Prefer per-turn scores recorded at generation time.
        stored = r["metadata"].get("per_turn_layer_scores")
        if stored:
            entry["per_turn"] = stored
        out.append(entry)
    return out


def _calibrators(benign_rows: list[dict]) -> tuple[dict[str, list[float]], float]:
    """
    Per-layer benign TURN-LEVEL score pools, and the kappa to use.

    The calibration population is every benign TURN, not every benign
    sample — which is the right reference class, because the quantity being
    calibrated is "how unusual is this turn's score". It also multiplies the
    calibration size by the turn count, which directly relaxes the
    reachability constraint that bounded the single-shot test.
    """
    pools = {L: [] for L in PER_TURN_LAYERS}
    for row in benign_rows:
        for turn in row["per_turn"]:
            for L in PER_TURN_LAYERS:
                pools[L].append(turn.get(L, 0.0))
    n = min(len(pools[L]) for L in PER_TURN_LAYERS)
    return pools, optimal_kappa(max(n - 1, 2))


def _turn_evalues(turn: dict, pools: dict[str, list[float]], kappa: float) -> list[float]:
    return [
        calibrate_evalue_threshold(pools[L], turn.get(L, 0.0), kappa)
        for L in PER_TURN_LAYERS
        if len(set(pools[L])) > 1
    ]


def _run_detector(rows: list[dict], pools, kappa, alpha, detector: str):
    """Returns (alarmed flags, alarm turn indices or None, final wealth)."""
    alarmed, delays, wealth = [], [], []
    for row in rows:
        proc = (EProcess(alpha=alpha, merge_method="mean") if detector == "eprocess"
                else MixtureEDetector(alpha=alpha, merge_method="mean"))
        for turn in row["per_turn"]:
            proc.update(_turn_evalues(turn, pools, kappa))
        alarmed.append(proc.alarmed)
        delays.append(proc.alarmed_at)
        wealth.append(getattr(proc, "wealth", float("nan")))
    return alarmed, delays, wealth


def evaluate(rows: list[dict], corpus: str, alpha: float = ALPHA) -> dict:
    import numpy as np

    malicious = [r for r in rows if r["label"] == "malicious" and r.get("per_turn")]
    benign = [r for r in rows if r["label"] == "benign" and r.get("per_turn")]
    if not benign or not malicious:
        raise SystemExit(f"{corpus}: need both classes with per-turn scores")

    pools, kappa = _calibrators(benign)
    n_turns_pool = len(pools[PER_TURN_LAYERS[0]])
    bound = ville_threshold(alpha)
    per_turn_cap = max_attainable_evalue(n_turns_pool - 1, kappa)

    out = {
        "corpus": corpus,
        "alpha": alpha,
        "kappa": round(kappa, 4),
        "ville_alarm_threshold": bound,
        "per_turn_layers": list(PER_TURN_LAYERS),
        "n_malicious": len(malicious),
        "n_benign": len(benign),
        "benign_turn_calibration_pool": n_turns_pool,
        "max_evalue_per_turn": round(per_turn_cap, 4),
        # THE SEQUENTIAL ADVANTAGE, made explicit. One turn alone may be
        # unable to reach 1/alpha, but wealth COMPOUNDS across turns, so the
        # boundary becomes reachable in this many maximally-evidenced turns.
        # For the single-shot test this number is effectively infinite unless
        # the cap alone clears the bound.
        "turns_to_reach_bound": (
            None if per_turn_cap <= 1.0
            else int(math.ceil(math.log(bound) / math.log(per_turn_cap)))
        ),
        "detectors": {},
    }

    for detector in ("eprocess", "mixture"):
        m_alarm, m_delay, _ = _run_detector(malicious, pools, kappa, alpha, detector)
        b_alarm, _, _ = _run_detector(benign, pools, kappa, alpha, detector)
        observed_delays = [d for d in m_delay if d is not None]
        out["detectors"][detector] = {
            "tpr": round(sum(m_alarm) / len(m_alarm), 4),
            # The Ville guarantee is on EVER alarming across the whole
            # session, so this is the quantity it bounds — no multiple-
            # testing correction for the number of turns inspected.
            "benign_ever_alarm_rate": round(sum(b_alarm) / len(b_alarm), 4),
            "guarantee_held": bool(sum(b_alarm) / len(b_alarm) <= alpha),
            "median_detection_delay_turns": (
                float(np.median(observed_delays)) if observed_delays else None),
            "mean_detection_delay_turns": (
                round(float(np.mean(observed_delays)), 3) if observed_delays else None),
            "n_detected": len(observed_delays),
            # Per-sample detected set, added 2026-09-19. WHY: the e-process
            # detected 167/340 on SPLIT-Bench, and a threshold sweep of L1
            # ALONE also reaches exactly 167/340 at zero false positives. Two
            # mechanisms landing on the same count is either a coincidence or
            # evidence that the sequential test is recovering one layer's
            # signal — and an aggregate count cannot tell those apart. Storing
            # the ids makes the overlap computable instead of arguable.
            "detected_sample_ids": sorted(
                malicious[i].get("sample_id")
                for i, d in enumerate(m_delay) if d is not None),
            "benign_alarm_sample_ids": sorted(
                benign[i].get("sample_id")
                for i, a in enumerate(b_alarm) if a),
        }

    # Per-bucket TPR + delay for the e-process.
    buckets: dict[str, list[int]] = {}
    for i, r in enumerate(malicious):
        buckets.setdefault(r["bucket"], []).append(i)
    m_alarm, m_delay, _ = _run_detector(malicious, pools, kappa, alpha, "eprocess")
    out["by_bucket_eprocess"] = {
        b: {
            "n": len(idx),
            "tpr": round(sum(m_alarm[i] for i in idx) / len(idx), 4),
            "median_delay": (
                float(np.median([m_delay[i] for i in idx if m_delay[i] is not None]))
                if any(m_delay[i] is not None for i in idx) else None),
        }
        for b, idx in sorted(buckets.items())
    }
    return out


async def _amain() -> dict:
    rows = load_split_bench_texts()
    if not all(r.get("per_turn") for r in rows):
        logger.info("per-turn scores absent from the corpus; computing (cached)...")
        scored = await _per_turn_for_texts(rows, "split_bench")
        by_id = {r["sample_id"]: r["per_turn"] for r in scored}
        for r in rows:
            r["per_turn"] = by_id.get(r["sample_id"], [])
    return {"split_bench": evaluate(rows, "split_bench")}


def main() -> None:
    import time

    from sentinel.eval.results_ledger import code_files_for, safe_append_entry

    started = time.monotonic()
    out = asyncio.run(_amain())

    for corpus, res in out.items():
        logger.info(f"=== {corpus} (alpha={res['alpha']}, alarm at wealth >= "
                    f"{res['ville_alarm_threshold']:.1f}) ===")
        logger.info(f"  per-turn layers={res['per_turn_layers']}; benign turn "
                    f"calibration pool={res['benign_turn_calibration_pool']}; "
                    f"kappa={res['kappa']}")
        logger.info(f"  max e-value per turn={res['max_evalue_per_turn']:.3f} -> "
                    f"compounding reaches the bound in "
                    f"{res['turns_to_reach_bound']} maximally-evidenced turns")
        logger.info(f"  {'detector':<12} {'TPR':>8} {'benign ever-alarm':>19} "
                    f"{'median delay':>13}  guarantee")
        for name, d in res["detectors"].items():
            logger.info(f"  {name:<12} {d['tpr']:>8.4f} {d['benign_ever_alarm_rate']:>19.4f} "
                        f"{str(d['median_detection_delay_turns']):>13}  "
                        f"{'HELD' if d['guarantee_held'] else 'VIOLATED'}")
        for b, row in res["by_bucket_eprocess"].items():
            logger.info(f"    bucket {b:<8} n={row['n']:<4} tpr={row['tpr']:.4f} "
                        f"median_delay={row['median_delay']}")

    _RESULTS.mkdir(exist_ok=True)
    path = _RESULTS / f"eval_eprocess_{datetime.now():%Y%m%d_%H%M%S}.json"
    path.write_text(json.dumps(out, indent=2), encoding="utf-8")
    logger.info(f"Results saved to {path}")

    safe_append_entry(
        experiment_id=f"eprocess_sequential_{datetime.now():%Y%m%d_%H%M%S}",
        phase="Phase 5 / Contribution F (sequential)",
        code_files=code_files_for(
            "sentinel/core/evidence_fusion.py",
            "sentinel/eval/eprocess_eval.py",
            "sentinel/eval/pipeline_sim.py",
        ),
        dataset_cache_file=str(_EVAL_DIR / "data" / "split_bench" / "all.jsonl"),
        split="leave-nothing-out: benign TURNS are the calibration pool; the "
              "Ville bound is on ever-alarming across a session",
        thresholds_used={"alpha": ALPHA, "per_turn_layers": list(PER_TURN_LAYERS)},
        metrics=out,
        result_file=str(path),
        runtime_seconds=round(time.monotonic() - started, 1),
        notes=(
            "Anytime-valid sequential half of Contribution F, previously "
            "unmeasurable because pipeline_sim reported only a max over turns. "
            "Only L1 and L3 are per-turn in this architecture (L2/L4/L5 run once "
            "per session), so this is a drift-detection result specifically. The "
            "cross-turn PRODUCT is legitimate where the cross-layer product is "
            "not: turns are the sequential dimension the supermartingale is "
            "defined over; layers within a turn are merged by mean."
        ),
    )


if __name__ == "__main__":
    main()
