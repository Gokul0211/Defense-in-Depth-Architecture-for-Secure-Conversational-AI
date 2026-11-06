"""
Windowed perplexity for L1 (L1 review, new mechanism 3; config.L1_PERPLEXITY_TIER, off until measured).

WHY. Optimisation-based jailbreaks (GCG-style adversarial suffixes) are token soups with exceedingly high perplexity
under a small LM (Alon & Kamfonas 2023, arXiv 2308.14132; Jain et al. 2023, "Baseline Defenses", windowed filter).
None of L1's tiers targets them. A whole-text perplexity dilutes a short suffix inside a long fluent prompt, so the
signal here is the MAX mean negative log-likelihood over sliding windows (Jain et al.'s windowed filter).

KNOWN LIMITS (from the same literature): fluent optimised attacks (AutoDAN, arXiv 2310.15140) and synonym-swap
attacks keep perplexity low and pass; benign code, URLs, hashes and IDs have high perplexity. So this is only a
"look closer" signal: in layer1 it raises an input to the judge band, and a benign hosted verdict clears it.

Model: GPT-2 small (openai-community/gpt2), loaded from the local cache only (`local_files_only=True`); absent ->
the signal is absent (None), never "benign".
"""
from __future__ import annotations

import logging
import math

logger = logging.getLogger(__name__)

MODEL_ID = "openai-community/gpt2"
WINDOW = 16          # tokens per window
STRIDE = 8
MAX_TOKENS = 1024    # GPT-2 context; longer inputs are scored in consecutive 1024-token blocks

_lm = None
_failed = False


def _get_lm():
    global _lm, _failed
    if _failed:
        return None
    if _lm is None:
        try:
            import torch
            from transformers import AutoModelForCausalLM, AutoTokenizer
            tok = AutoTokenizer.from_pretrained(MODEL_ID, local_files_only=True)
            model = AutoModelForCausalLM.from_pretrained(MODEL_ID, local_files_only=True)
            model.eval()
            _lm = (tok, model, torch)
        except Exception as e:                                     # noqa: BLE001
            logger.warning(f"perplexity model unavailable, signal disabled: {e}")
            _failed = True
            return None
    return _lm


def reset() -> None:
    global _lm, _failed
    _lm, _failed = None, False


def token_nll(text: str) -> list[float] | None:
    """Per-token negative log-likelihood (nats) of `text` under GPT-2, first token excluded. None if unavailable."""
    lm = _get_lm()
    if lm is None or not text or not text.strip():
        return None
    tok, model, torch = lm
    ids = tok(text, return_tensors="pt", add_special_tokens=False)["input_ids"][0]
    out: list[float] = []
    with torch.no_grad():
        for start in range(0, len(ids), MAX_TOKENS):
            block = ids[start:start + MAX_TOKENS]
            if len(block) < 2:
                continue
            logits = model(block.unsqueeze(0)).logits[0]
            logp = torch.log_softmax(logits[:-1].float(), dim=-1)
            nll = -logp.gather(1, block[1:].unsqueeze(1)).squeeze(1)
            out.extend(float(v) for v in nll)
    return out


def windowed_nll(text: str) -> dict | None:
    """{"max_window": max mean NLL over WINDOW-token windows, "mean": whole-text mean NLL, "tokens": n}, or None.
    Inputs shorter than one window report their whole-text mean as `max_window`."""
    nll = token_nll(text)
    if not nll:
        return None
    mean = sum(nll) / len(nll)
    if len(nll) <= WINDOW:
        return {"max_window": mean, "mean": mean, "tokens": len(nll)}
    best = -math.inf
    for s in range(0, len(nll) - WINDOW + 1, STRIDE):
        best = max(best, sum(nll[s:s + WINDOW]) / WINDOW)
    tail = nll[-WINDOW:]
    best = max(best, sum(tail) / WINDOW)
    return {"max_window": best, "mean": mean, "tokens": len(nll)}
