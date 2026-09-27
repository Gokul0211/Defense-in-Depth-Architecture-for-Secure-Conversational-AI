"""
Intent-level safety signal shared by L1 and L3 (fixing.md A/B/C, 2026-09-24).

WHY THIS EXISTS -- the root cause R-011 measured. Three open rows (#3 WildJailbreak,
#2 MHJ, #6 tom-gibbs) label harmful INTENT across a full hazard taxonomy, and no layer
was built to read it: L1 reads injection FORM (regex, similarity to injection anchors,
Prompt Guard, PIGuard, an injection-focused judge) and L3's "content" is cosine to five
anchor phrases. Detection tracked topic COVERAGE, not intent: tom-gibbs goals in the five
anchor topics 0.42-0.84, outside them 0.15-0.40, with false alarms concentrated on the
same five topics; MHJ 0/19 misinformation, 0/14 hate; WildJailbreak flat 0.14-0.36.

WHAT IT IS. A third-party guard model -- Qwen3Guard-Gen-0.6B (Apache-2.0, 9 policy
categories incl. Jailbreak, a separate Controversial class) -- read as a probability,
never generated from: after the model's own moderation template and the forced prefix
"Safety:", the next-token distribution over {Safe, Unsafe, Controversial} is
renormalised and P(Unsafe) is the score (the pre-declared "loose" readout of A-002).

Two modes, both the model's NATIVE template:
  score_prompt(text)            one message (L1, and tom-gibbs's DECODED instruction)
  score_conversation(turns)     the last user turn IN CONTEXT of the earlier ones (L3)

OPTIONAL HEAD. `SAFETY_GUARD_HEAD` may name a frozen logistic head over the model's
hidden state at the label position (scratch/trackA/A007_head.py, trained on OR-Bench-80K
vs OR-Bench-toxic -- same generator, same topics, opposite label -- so it learns harm vs
harm-adjacent rather than topic). Absent artifact -> zero-shot readout, never a guess.

FAIL-SOFT, like every other model in this system: no transformers, no weights, or any
inference error -> None, which callers treat as "signal absent", never as "benign".

COST. 0.6B parameters in fp32 on CPU: ~0.3-1 s per call with threads. Callers gate it
(L1 only below its own WARN; L3 only when its mode asks for it) and it is OFF by default
until the promotion gate in fixing.md passes.
"""

from __future__ import annotations

import copy
import json
import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

_MARK = "<<<SENTINEL_PAYLOAD>>>"
_MARK2 = "<<<SENTINEL_PAYLOAD_2>>>"
_MAX_PAYLOAD_TOKENS = 1024          # single mode: head + tail kept (A-002 setting)
_MAX_TURN_TOKENS = 384              # context mode, per turn (B-008 setting)
_MAX_CONTEXT_TURNS = 12

_singleton = None
_failed = False


class _Guard:
    def __init__(self, model_id: str, device: str | None = None):
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer

        threads = int(os.getenv("SENTINEL_TORCH_THREADS", "1"))
        if threads > 0:
            torch.set_num_threads(threads)
        self.torch = torch
        self.tok = AutoTokenizer.from_pretrained(model_id)
        self.model = AutoModelForCausalLM.from_pretrained(model_id, dtype=torch.float32).eval()
        # GPU when one is selected (guard_device.py): decoder on the GPU, tied embedding /
        # LM head on the CPU, all fp32 -- same scores within ~1e-6 (parity test: 2e-3).
        self.model_id, self.on_gpu, self.cpu_fallbacks, self._twin = model_id, False, 0, None
        if device != "cpu":
            from sentinel.core.guard_device import split_device
            m = split_device(self.model)
            self.on_gpu, self.model = m is not self.model, m

        # Split the model's own template around two placeholder turns, so the
        # policy prefix is encoded ONCE and reused, and a conversation is the prefix
        # plus one "USER: ...\n\n" piece per turn plus the fixed suffix.
        full = self.tok.apply_chat_template(
            [{"role": "user", "content": _MARK}, {"role": "user", "content": _MARK2}],
            tokenize=False, add_generation_prompt=True)
        i = full.index("USER: " + _MARK)
        k = full.index(_MARK2) + len(_MARK2)
        self.pre = full[:i]
        rest = full[k:]
        if not rest.startswith("\n\n"):
            raise ValueError("unexpected guard template layout")
        self.post_ids = self._ids(rest[2:] + "Safety:")
        self.pre_ids = self._ids(self.pre)
        with torch.no_grad():
            self.pre_cache = self.model(torch.tensor([self.pre_ids]), use_cache=True).past_key_values
        # SINGLE-MESSAGE mode reproduces scratch/trackA/qwen3guard.py's tokenisation
        # EXACTLY (prefix including "USER: ", payload tokens, suffix), because
        # L1_SAFETY_TAU was derived on scores produced that way; the conversation mode
        # reproduces B-008's piecewise layout (measured identical to joint tokenisation
        # on 40/40 sessions).
        one = self.tok.apply_chat_template([{"role": "user", "content": _MARK}],
                                           tokenize=False, add_generation_prompt=True)
        pre1, post1 = one.split(_MARK)
        self.single_pre_ids = self._ids(pre1)
        self.single_post_ids = self._ids(post1 + "Safety:")
        with torch.no_grad():
            self.single_pre_cache = self.model(torch.tensor([self.single_pre_ids]),
                                               use_cache=True).past_key_values
        base = self._ids("Safety:")
        self.label_ids = [self._ids("Safety: " + lab)[len(base)] for lab in ("Safe", "Unsafe", "Controversial")]
        if len(set(self.label_ids)) != 3:
            raise ValueError(f"label tokens not distinct: {self.label_ids}")
        self.head = _load_head()

    def _ids(self, s: str) -> list[int]:
        return self.tok(s, add_special_tokens=False)["input_ids"]

    def _piece(self, text: str, cap: int) -> list[int]:
        ids = self._ids(text)
        if len(ids) > cap:  # keep head and tail: payloads often sit at the end of a wrapper
            h = cap // 2
            text = self.tok.decode(ids[:h]) + " ... " + self.tok.decode(ids[-h:])
        return self._ids("USER: " + text + "\n\n")

    def _readout(self, pieces: list[list[int]], single: bool = False) -> dict:
        torch = self.torch
        if single:
            ids = pieces[0] + self.single_post_ids
            cache = copy.deepcopy(self.single_pre_cache)
            L = len(self.single_pre_ids)
        else:
            ids = [t for p in pieces for t in p] + self.post_ids
            cache = copy.deepcopy(self.pre_cache)
            L = len(self.pre_ids)
        try:
            with torch.no_grad():
                out = self.model(torch.tensor([ids]), past_key_values=cache, use_cache=True,
                                 output_hidden_states=self.head is not None,
                                 attention_mask=torch.ones(1, L + len(ids), dtype=torch.long))
        except torch.cuda.OutOfMemoryError:
            # One very long input on a 4 GB GPU: score THIS item on a CPU twin (same fp32
            # model), counted, instead of failing it.
            del cache
            torch.cuda.empty_cache()
            self.cpu_fallbacks += 1
            if self._twin is None:
                self._twin = _Guard(self.model_id, device="cpu")
            return self._twin._readout(pieces, single=single)
        p = torch.softmax(torch.log_softmax(out.logits[0, -1], -1)[self.label_ids], -1).tolist()
        res = {"p_safe": p[0], "p_unsafe": p[1], "p_controversial": p[2], "head": None}
        if self.head is not None:
            import numpy as np
            if self.head.get("type") == "trajectory":
                h = np.stack([out.hidden_states[i][0, -1].float().numpy() for i in self.head["layers"]])
            else:
                h = np.concatenate([out.hidden_states[i][0, -1].float().numpy() for i in self.head["layers"]])
            res["head"] = _apply_head(self.head, h)
        return res

    def score_prompt(self, text: str) -> dict:
        pay = self._ids(text)
        if len(pay) > _MAX_PAYLOAD_TOKENS:      # token-level head + tail, as A-002
            h = _MAX_PAYLOAD_TOKENS // 2
            pay = pay[:h] + pay[-h:]
        return self._readout([pay], single=True)

    def score_conversation(self, turns: list[str]) -> dict:
        turns = [t for t in turns if t and t.strip()][-_MAX_CONTEXT_TURNS:]
        if not turns:
            return {"p_safe": 1.0, "p_unsafe": 0.0, "p_controversial": 0.0, "head": None}
        return self._readout([self._piece(t, _MAX_TURN_TOKENS) for t in turns])


def _load_head():
    """The frozen hidden-state head, or None (zero-shot readout)."""
    import sentinel.config as cfg

    name = getattr(cfg, "SAFETY_GUARD_HEAD", "") or ""
    if not name:
        return None
    path = Path(name)
    if not path.is_absolute():
        path = Path(__file__).resolve().parent / "artifacts" / name
    try:
        import numpy as np

        art = json.loads(path.read_text(encoding="utf-8"))
        if art.get("model_id") != getattr(cfg, "SAFETY_GUARD_MODEL", None):
            raise ValueError(f"head fitted on {art.get('model_id')}, config pins {cfg.SAFETY_GUARD_MODEL}")
        if (art.get("gate") or {}).get("passed") is False:
            # Loaded because it was asked for by name (an experiment), but never quietly:
            # the A-007 head failed fixing.md A2's promotion gate (2026-09-24).
            logger.warning(f"safety head {path.name} FAILED its promotion gate "
                           f"({art['gate'].get('checks')}); loaded only because SAFETY_GUARD_HEAD names it")
        if art.get("type") == "trajectory":
            # A-008 (2026-09-25): per-layer standardisation + harm direction, cosine
            # projection per layer, then a logistic over the trajectory (+ deltas).
            n = int(art["n_layers"])
            return {"type": "trajectory", "layers": list(range(1, n + 1)),
                    "mu": np.asarray(art["mu"], float), "sd": np.asarray(art["sd"], float),
                    "dir": np.asarray(art["directions"], float),
                    "delta": art.get("representation") == "traj+delta",
                    "mean": np.asarray(art["feat_mean"], float), "scale": np.asarray(art["feat_scale"], float),
                    "coef": np.asarray(art["coef"], float), "intercept": float(art["intercept"])}
        layers = art["hidden_layers"]            # e.g. [-1] (last), [20], or [-1, 20] (concat)
        return {"layers": [int(i) for i in layers], "mean": np.asarray(art["mean"], float),
                "scale": np.asarray(art["scale"], float), "coef": np.asarray(art["coef"], float),
                "intercept": float(art["intercept"])}
    except Exception as e:                                            # noqa: BLE001
        logger.warning(f"safety head unavailable, using the zero-shot readout: {e}")
        return None


def _trajectory_features(head: dict, H) -> "np.ndarray":
    """H: (L, d) final-position states of layers 1..L -> the A-008 feature vector."""
    import numpy as np
    Z = (H - head["mu"]) / head["sd"]
    Z = Z / (np.linalg.norm(Z, axis=1, keepdims=True) + 1e-9)
    t = np.einsum("ld,ld->l", Z, head["dir"])
    return np.concatenate([t, np.diff(t)]) if head["delta"] else t


def _apply_head(head: dict, h) -> float:
    import numpy as np

    if head.get("type") == "trajectory":
        h = _trajectory_features(head, h)
    z = (h - head["mean"]) / np.where(head["scale"] == 0, 1.0, head["scale"])
    logit = float(np.dot(z, head["coef"]) + head["intercept"])
    return float(1.0 / (1.0 + np.exp(-max(-60.0, min(60.0, logit)))))


def get_guard():
    """The loaded guard, or None if unavailable. Never raises."""
    global _singleton, _failed
    if _failed:
        return None
    if _singleton is None:
        import sentinel.config as cfg
        try:
            _singleton = _Guard(getattr(cfg, "SAFETY_GUARD_MODEL", "Qwen/Qwen3Guard-Gen-0.6B"))
        except Exception as e:                                        # noqa: BLE001
            logger.warning(f"safety guard unavailable, intent signal disabled: {e}")
            _failed = True
            return None
    return _singleton


def reset_guard() -> None:
    """Drop the singleton (tests, or after changing the head/model config)."""
    global _singleton, _failed
    _singleton = None
    _failed = False


def _pick(res: dict | None) -> float | None:
    """The configured readout: the head when one is loaded, else P(Unsafe)."""
    if res is None:
        return None
    return res["head"] if res.get("head") is not None else res["p_unsafe"]


# EXACT-TEXT MEMO (2026-09-25). The guard is deterministic (fp32, eval mode, fixed
# template), so an identical input always yields the identical score; recomputing it is
# pure waste. It is not rare: tom-gibbs repeats every decoded goal across 8 cipher
# formats, and L3 re-scores the growing conversation. Bounded; keyed by the head in use so a
# head change can never return a stale readout. Failures (None) are never cached.
_MEMO: "OrderedDict[tuple, float]" = None
_MEMO_MAX = 20000


def _memo_get(key):
    return None if _MEMO is None else _MEMO.get(key)


def _memo_put(key, val):
    global _MEMO
    from collections import OrderedDict
    if _MEMO is None:
        _MEMO = OrderedDict()
    _MEMO[key] = val
    if len(_MEMO) > _MEMO_MAX:
        _MEMO.popitem(last=False)


def _head_tag():
    import sentinel.config as cfg
    return getattr(cfg, "SAFETY_GUARD_HEAD", "") or ""


def safety_score_prompt(text: str) -> float | None:
    g = get_guard()
    if g is None or not text:
        return None
    key = ("p", _head_tag(), text)
    hit = _memo_get(key)
    if hit is not None:
        return hit
    try:
        val = _pick(g.score_prompt(text))
    except Exception as e:                                            # noqa: BLE001
        logger.warning(f"safety guard inference failed: {e}")
        return None
    if val is not None:
        _memo_put(key, val)
    return val


def safety_score_conversation(turns: list[str]) -> float | None:
    g = get_guard()
    if g is None or not turns:
        return None
    key = ("c", _head_tag(), tuple(turns))
    hit = _memo_get(key)
    if hit is not None:
        return hit
    try:
        val = _pick(g.score_conversation(turns))
    except Exception as e:                                            # noqa: BLE001
        logger.warning(f"safety guard inference failed: {e}")
        return None
    if val is not None:
        _memo_put(key, val)
    return val


def map_to_layer_axis(s: float, tau_s: float, layer_warn: float, layer_top: float) -> float:
    """
    Piecewise-linear, strictly monotone map of a safety score onto a layer's own axis:
    0 -> 0, tau_s (the channel's conformal anchor) -> the layer's WARN anchor, 1 -> layer_top.
    Monotone, so it moves the operating point and never the ranking (AUROC-invariant),
    exactly like core.models.rescale_layer_score.
    """
    s = max(0.0, min(1.0, float(s)))
    if tau_s <= 0 or tau_s >= 1:
        return layer_warn if s >= tau_s else 0.0
    if s <= tau_s:
        return s / tau_s * layer_warn
    return layer_warn + (s - tau_s) / (1.0 - tau_s) * (layer_top - layer_warn)
