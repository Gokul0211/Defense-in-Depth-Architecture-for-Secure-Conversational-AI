"""
Multilingual Tier 2 for L1 (L1 review, new mechanism 6; config.L1_TIER2_MULTILINGUAL, off until measured).

WHY. Tier 2 embeds with all-MiniLM-L6-v2, an English-only model, against English anchor phrases, so an injection
written in another language reaches Tier 2 as noise and depends on Prompt Guard (multilingual) and the judge. This adds
the same anchor comparison in a multilingual space: intfloat/multilingual-e5-small (~100 languages; e5 expects the
"query: " prefix on both sides of a symmetric comparison).

AXIS. e5 cosine similarities are compressed high (unrelated texts often score 0.7-0.8), so the raw value is never
compared with L1's thresholds. It is mapped by its own conformal anchor -- the 99th percentile on benign calibration
text (Alpaca rows 7000-7250 + 250 non-English WildChat user turns; sentinel/core/artifacts/l1_new_tiers.json) -> L1's
WARN anchor, capped below BLOCK: it can raise an input to WARN / the judge band, never block alone.

Loaded from the local cache only; absent -> the signal is absent (None).
"""
from __future__ import annotations

import logging

import numpy as np

logger = logging.getLogger(__name__)

MODEL_ID = "intfloat/multilingual-e5-small"
_model = None
_anchors = None
_failed = False


def _get():
    global _model, _anchors, _failed
    if _failed:
        return None
    if _model is None:
        try:
            from sentence_transformers import SentenceTransformer
            from sentinel.layers.layer1 import KNOWN_INJECTIONS
            _model = SentenceTransformer(MODEL_ID, local_files_only=True)
            _anchors = _model.encode([f"query: {a}" for a in KNOWN_INJECTIONS], normalize_embeddings=True)
        except Exception as e:                                     # noqa: BLE001
            logger.warning(f"multilingual model unavailable, signal disabled: {e}")
            _failed = True
            return None
    return _model, _anchors


def reset() -> None:
    global _model, _anchors, _failed
    _model, _anchors, _failed = None, None, False


def max_similarity(windows: list[str]) -> float | None:
    """Max cosine similarity of any window to any anchor in the multilingual space, or None if unavailable."""
    got = _get()
    if got is None or not windows:
        return None
    model, anchors = got
    emb = model.encode([f"query: {w}" for w in windows], normalize_embeddings=True)
    return float(np.max(np.asarray(emb) @ np.asarray(anchors).T))
