"""
Attack-bank nearest-neighbour signal for L1 Tier 2 (L1 review, new mechanism 4; config.L1_ATTACK_BANK, off).

WHY. Tier 2 compares each sentence window with 24 hand-written anchor phrases (KNOWN_INJECTIONS). On SENTINEL-Bench
the original 10 anchors ranked at AUROC 0.2628 (inverted) and the extended set at 0.5996 train / 0.7104 test
(layer1.py's KNOWN_INJECTIONS comment): a handful of phrases cannot cover how
injections are worded, and nothing in it represents benign text that merely SOUNDS like one. This bank holds
embeddings of real labelled attacks AND of benign texts, and scores a window by the MARGIN between its nearest attack
neighbours and its nearest benign neighbours (k-NN, mean of the top k cosine similarities on each side). A benign
neighbour that is as close as the attack neighbours cancels the evidence, which is the trigger-word false-positive
case that plain similarity cannot handle.

DATA (sentinel/core/artifacts/l1_attack_bank.npz + .provenance.json; built by scratch/rca/l1/calibrate_new_tiers.py):
TRAIN splits only of deepset/prompt-injections and Lakera gandalf_ignore_instructions / mosscap_prompt_injection
(attacks), and deepset label-0 + Alpaca rows 6000-7000 (benign). No reported corpus is indexed. Only embeddings are
stored, never the texts.

AXIS. The raw margin is mapped onto L1's axis by its own conformal anchor (benign 99th percentile on Alpaca rows
7000-7500 -> L1's WARN anchor), capped below BLOCK: this signal can raise an input to WARN / the judge band, never
block it alone.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

import numpy as np

logger = logging.getLogger(__name__)

ARTIFACT = Path(__file__).resolve().parent / "artifacts" / "l1_attack_bank.npz"
K = 5

_bank = None
_failed = False


def _load():
    global _bank, _failed
    if _failed:
        return None
    if _bank is None:
        try:
            d = np.load(ARTIFACT)
            att = d["attack"].astype(np.float32)
            ben = d["benign"].astype(np.float32)
            att /= np.linalg.norm(att, axis=1, keepdims=True) + 1e-12
            ben /= np.linalg.norm(ben, axis=1, keepdims=True) + 1e-12
            meta = json.loads(ARTIFACT.with_suffix(".provenance.json").read_text(encoding="utf-8"))
            _bank = {"attack": att, "benign": ben, "tau": float(meta["tau_margin01"]), "meta": meta}
        except Exception as e:                                     # noqa: BLE001
            logger.warning(f"attack bank unavailable, signal disabled: {e}")
            _failed = True
            return None
    return _bank


def reset() -> None:
    global _bank, _failed
    _bank, _failed = None, False


def margins(window_embeddings) -> np.ndarray | None:
    """Per-window margin in [0, 1]: ((mean top-k attack cos) - (mean top-k benign cos) + 1) / 2. None if no bank."""
    b = _load()
    if b is None:
        return None
    w = np.asarray(window_embeddings, dtype=np.float32)
    if w.ndim == 1:
        w = w[None, :]
    w = w / (np.linalg.norm(w, axis=1, keepdims=True) + 1e-12)
    k_a, k_b = min(K, len(b["attack"])), min(K, len(b["benign"]))
    sa = np.sort(w @ b["attack"].T, axis=1)[:, -k_a:].mean(axis=1)
    sb = np.sort(w @ b["benign"].T, axis=1)[:, -k_b:].mean(axis=1)
    return (sa - sb + 1.0) / 2.0


def tau() -> float | None:
    b = _load()
    return None if b is None else b["tau"]
