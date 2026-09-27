"""
Deployable cross-layer SCORE fusion (SPLIT-Bench v2 plan, 2026-09-25; paper Proposition 2).

WHY. SPLIT-Bench certifies every attack below every layer's threshold, so every
threshold rule -- single-layer WARN/BLOCK, the correlation rules, 2-of-5 corroboration --
detects 0 of 340 BY CONSTRUCTION (Proposition 1). The evidence survives in the scores
(max-layer AUROC 0.9406, TPR 0.82 at 5 % FPR; logistic OOF 0.9387; held-out pattern miner
0.7794 at 0 FPR), but nothing in the DEPLOYED decision reads it. This module is that reader:
a frozen logistic over the shared-axis layer scores plus the continuous L4/L5 confidences
(the channels whose discrete scores are quantised to a single sub-threshold value).

NO SPLIT-BENCH DATA TOUCHES IT. Weights are fitted on sentinel_bench's mining_set (the same
labelled split the pattern miner uses, disjoint from SPLIT-Bench and from SB test); the
alarm threshold is split-conformal on BENIGN multi-layer sessions (benign_pipeline_arm),
so its false-alarm guarantee is on real benign traffic, not on SPLIT's benign shell.
Built by sentinel/eval/fit_pipeline_fusion.py; artifact core/artifacts/pipeline_fusion.json.

SCOPE OF THE CLAIM (must survive into the paper). A detector fixed in advance is evaded by
an adversary that certifies below IT as well -- the fusion-aware SPLIT variant
(split_bench.py --fusion-aware) measures exactly that. What this buys is detection of the
paper's (k, epsilon)-distributed adversary, who adapts to per-layer thresholds.
"""
from __future__ import annotations

import json
import logging
import math
from pathlib import Path

logger = logging.getLogger(__name__)

FEATURES = ["L1", "L2", "L3", "L4", "L5", "L1H", "L2c", "L4c", "L5c"]
_ART = Path(__file__).parent / "artifacts" / "pipeline_fusion.json"
_cache: dict | None = None
_missing = False


def features(layer_scores: dict, confidences: dict | None = None) -> list[float]:
    conf = confidences or {}
    f = {**{k: float(layer_scores.get(k, 0.0) or 0.0) for k in ("L1", "L2", "L3", "L4", "L5", "L1H")},
         "L2c": float(conf.get("L2", 0.0) or 0.0),
         "L4c": float(conf.get("L4", 0.0) or 0.0), "L5c": float(conf.get("L5", 0.0) or 0.0)}
    return [f[k] for k in FEATURES]


def load(path: Path | None = None) -> dict | None:
    """The frozen model, or None (fusion inert) -- never a guess."""
    global _cache, _missing
    if path is None and _cache is not None:
        return _cache
    if path is None and _missing:
        return None
    p = path or _ART
    try:
        art = json.loads(Path(p).read_text(encoding="utf-8"))
        if art.get("features") != FEATURES:
            raise ValueError(f"feature list {art.get('features')} != {FEATURES}")
    except Exception as e:                                             # noqa: BLE001
        if path is None:
            _missing = True
        logger.warning(f"pipeline fusion unavailable: {e}")
        return None
    if path is None:
        _cache = art
    return art


def reset_cache() -> None:
    global _cache, _missing
    _cache, _missing = None, False


def fused_probability(art: dict, layer_scores: dict, confidences: dict | None = None) -> float:
    x = features(layer_scores, confidences)
    z = sum(w * (xi - m) / (s if s else 1.0)
            for w, xi, m, s in zip(art["coef"], x, art["mean"], art["scale"])) + art["intercept"]
    return 1.0 / (1.0 + math.exp(-max(-60.0, min(60.0, z))))


def fusion_decision(layer_scores: dict, confidences: dict | None = None) -> str | None:
    """'BLOCK' / 'WARN' from the fused score at its benign-calibrated anchors, or None when
    fusion is off or its artifact is missing."""
    import sentinel.config as c
    mode = getattr(c, "PIPELINE_FUSION", "off")
    if mode == "off":
        return None
    art = load()
    if art is None:
        return None
    p = fused_probability(art, layer_scores, confidences)
    if mode == "warn_block" and art.get("tau_block") is not None and p >= art["tau_block"]:
        return "BLOCK"
    if p >= art["tau_warn"]:
        return "WARN"
    return None
