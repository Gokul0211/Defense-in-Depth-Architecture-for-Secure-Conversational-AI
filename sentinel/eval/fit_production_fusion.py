"""
Fit and FREEZE the production L1 tier-fusion artifact — Phase 5 / 3B.3
production wiring.

WHY THE SMALLER CORPUS IS THE TRAINING CORPUS
------------------------------------------------
The obvious choice is to fit on WildJailbreak: it is 20x larger (2,210 vs
112), exhibits all three cascade availability patterns with hundreds of
samples each, and would plainly yield a better-estimated model.

It is the wrong choice here, and the reason is what the artifact has to
EARN, not what it has to be. Every downstream claim this project wants to
make about the fusion is a HELD-OUT claim measured on WildJailbreak:

  * cross-corpus AUROC 0.6457 -> 0.7426 (n=2,210, paired-bootstrap CI95
    [+0.0668, +0.1278], p_worse=0.000 over 2,000 replicates), and
  * the conformal cross-corpus stress test, whose single most informative
    arm is WildJailbreak's 210 benign samples -- the arm where
    Contribution D's guarantee is already known to FAIL (empirical FPR
    0.2667 against alpha=0.05).

Fitting on WildJailbreak would contaminate both. The 210 benign samples
that the conformal stress test exists to probe would have been seen by the
model whose threshold is being stress-tested, and the headline AUROC
transfer number would become in-sample. The gain -- a better-estimated
model -- is not worth converting this project's best evidence into
evidence about itself.

So: FIT ON sentinel_bench (n=112), HOLD OUT WildJailbreak ENTIRELY.

The cost is stated rather than hidden. At n=112 the cascade patterns are
13 / 27 / 72, so `PatternJointTierFusion.min_samples=20` means the
13-sample tier1-only pattern gets no within-pattern model and falls back
to that pattern's base rate. That is a real limitation of the shipped
artifact and is recorded in the provenance sidecar.

WHAT "FROZEN" MEANS
----------------------
The artifact is written once, with a provenance sidecar recording the
source result file, its SHA-256, the sample counts, the fitted patterns,
and the timestamp. Refitting at import time would make "which data
produced this decision rule" unanswerable, which is the same property
`results_ledger.py` exists to preserve.

Usage:
    python -m sentinel.eval.fit_production_fusion
    python -m sentinel.eval.fit_production_fusion --corpus wildjailbreak
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
from datetime import datetime
from pathlib import Path

from sentinel.core.tier_fusion import (
    PatternJointTierFusion,
    availability_pattern,
    save_fusion_model,
)
from sentinel.eval.tier_fusion_eval import load_corpus

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

_RESULTS = Path(__file__).parent / "results"
_ARTIFACT_DIR = Path(__file__).resolve().parents[1] / "core" / "artifacts"

DEFAULT_TRAIN_CORPUS = "sentinel_bench"


def _richest_result_for(dataset: str) -> Path:
    """
    Pick the eval result file for `dataset` with the RICHEST tier-score
    coverage, not the most recent one.

    Same rule, and same reason, as `tier_fusion_eval.main`: recency once
    silently selected the judge-DISABLED ablation run for sentinel_bench
    (tier4 present on 0/112 samples), which is a deliberately degraded
    measurement of the same corpus rather than a fresher one. Shipping a
    production artifact fitted on a corpus that has never observed the
    judge tier would be that bug, frozen.
    """
    best: tuple[int, Path] | None = None
    for path in sorted(_RESULTS.glob("eval_L1_*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if data.get("meta", {}).get("dataset") != dataset:
            continue
        coverage = sum(
            1
            for sample in data.get("per_sample", [])
            for value in (sample.get("tier_scores") or {}).values()
            if value is not None
        )
        if coverage and (best is None or coverage > best[0]):
            best = (coverage, path)
    if best is None:
        raise SystemExit(
            f"no eval result for dataset {dataset!r} with recorded tier_scores. "
            f"Run: python -m sentinel.eval.runner --layer L1 --dataset {dataset}"
        )
    logger.info(f"training corpus: {best[1].name} (tier-score coverage {best[0]})")
    return best[1]


def fit_and_freeze(dataset: str = DEFAULT_TRAIN_CORPUS) -> dict:
    source = _richest_result_for(dataset)
    rows, labels, name = load_corpus(source)
    if len(set(labels)) < 2:
        raise SystemExit(
            f"corpus {name!r} is single-class and cannot calibrate a fusion model"
        )

    model = PatternJointTierFusion().fit(rows, labels)

    from collections import Counter

    patterns = Counter(availability_pattern(r) for r in rows)
    fitted = {"|".join(p) for p in model.models}
    unfitted = {"|".join(p) for p in patterns} - fitted

    _ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    artifact = _ARTIFACT_DIR / "l1_tier_fusion.json"
    save_fusion_model(model, artifact)

    provenance = {
        "artifact": artifact.name,
        "artifact_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
        "frozen_at": datetime.now().isoformat(timespec="seconds"),
        "train_corpus": name,
        "train_source_file": source.name,
        "train_source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "n_train": len(rows),
        "n_malicious": sum(labels),
        "n_benign": len(labels) - sum(labels),
        "availability_patterns": {"|".join(k): v for k, v in patterns.items()},
        "patterns_with_joint_model": sorted(fitted),
        # Patterns that fell back to their own base rate because they had
        # fewer than min_samples rows. A real limitation of this artifact,
        # recorded so it does not have to be rediscovered from the code.
        "patterns_falling_back_to_base_rate": sorted(unfitted),
        "min_samples": model.min_samples,
        "held_out_corpora": ["wildjailbreak", "alpaca", "tensortrust"],
        "held_out_rationale": (
            "WildJailbreak carries every downstream held-out claim (cross-corpus "
            "AUROC and the conformal benign stress test), so it is excluded from "
            "fitting. Alpaca is the conformal calibration set and is likewise never "
            "fitted on."
        ),
    }
    (_ARTIFACT_DIR / "l1_tier_fusion.provenance.json").write_text(
        json.dumps(provenance, indent=2), encoding="utf-8"
    )

    # A frozen PRODUCTION artifact is the single most provenance-critical
    # thing this project writes: it changes L1's score for every request.
    # The sidecar records how it was built; the ledger records that it WAS
    # built, when, and against which code — so an artifact appearing on
    # disk with no ledger line is detectable.
    from sentinel.eval.results_ledger import code_files_for, safe_append_entry

    safe_append_entry(
        experiment_id=f"fit_production_fusion_{datetime.now():%Y%m%d_%H%M%S}",
        phase="Phase 5 / 3B.3 (production artifact)",
        code_files=code_files_for(
            "sentinel/core/tier_fusion.py",
            "sentinel/eval/fit_production_fusion.py",
        ),
        dataset_cache_file=str(source),
        split=f"fit on {name} (n={len(rows)}); wildjailbreak/alpaca/tensortrust held out",
        thresholds_used={"min_samples": model.min_samples},
        metrics=provenance,
        result_file=str(artifact),
        runtime_seconds=0.0,
        notes=(
            "FROZEN PRODUCTION ARTIFACT. Trained on the SMALLER corpus on purpose: "
            "WildJailbreak carries every held-out claim (cross-corpus AUROC and the "
            "conformal benign stress test), so fitting on it would convert this "
            "project's best evidence into evidence about itself."
        ),
    )

    logger.info(f"froze {artifact}")
    logger.info(f"  trained on {name} n={len(rows)} "
                f"({sum(labels)} mal / {len(labels) - sum(labels)} ben)")
    logger.info(f"  joint models fitted for: {sorted(fitted)}")
    if unfitted:
        logger.warning(f"  patterns falling back to base rate: {sorted(unfitted)}")
    return provenance


def main() -> None:
    parser = argparse.ArgumentParser(description="Freeze the production L1 tier-fusion model")
    parser.add_argument("--corpus", default=DEFAULT_TRAIN_CORPUS)
    args = parser.parse_args()
    fit_and_freeze(args.corpus)


if __name__ == "__main__":
    main()
