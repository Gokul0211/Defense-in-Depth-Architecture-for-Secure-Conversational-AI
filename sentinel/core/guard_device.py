"""
Run the Qwen3Guard causal LM on a small GPU without changing a single score (2026-09-26).

WHY. Every guard run before this date went to the CPU: the environment's torch was the
CPU-only build, while the machine has an idle RTX 3050 Laptop (4 GB). The guard is the
bottleneck of every harm / L3 / probe run (~2.5 s per prompt on CPU).

HOW IT FITS 4 GB. Qwen3Guard-Gen-0.6B in fp32 is ~3.0 GB, of which 0.62 GB is the TIED
word-embedding / LM-head matrix (151,936 x 1,024). The decoder stack (2.4 GB) goes to the
GPU; the tied matrix stays on the CPU, where the two things it is used for are cheap:
the input embedding lookup (exact -- a row gather) and ONE final projection of the
last-position hidden state (every caller reads only `logits[0, -1]`). Both run in fp32 on
the CPU exactly as before, and TF32 is disabled, so the only difference from the CPU
path is GPU vs CPU fp32 summation order in the decoder (~1e-6; the parity test's
tolerance is 2e-3).

DROP-IN. `split_device(model)` returns the model itself on CPU (behaviour unchanged) or a
callable with the same call signature the wrappers use -- `(input_ids, past_key_values=,
use_cache=, output_hidden_states=, attention_mask=)` -- whose output carries:
  .logits          (1, 1, V) CPU fp32, the LAST position only
  .hidden_states   tuple of (1, 1, d) CPU fp32, last position of every layer (if asked)
  .past_key_values the cache, on the GPU (deep-copyable, extendable in place)

Device: SENTINEL_GUARD_DEVICE = auto (cuda if available) | cuda | cpu.
"""
from __future__ import annotations

import os
from types import SimpleNamespace


def guard_device() -> str:
    import torch
    d = os.getenv("SENTINEL_GUARD_DEVICE", "auto").strip().lower()
    if d == "auto":
        d = "cuda" if torch.cuda.is_available() else "cpu"
    if d.startswith("cuda") and not torch.cuda.is_available():
        d = "cpu"
    return d


class _SplitCausalLM:
    """Decoder on the GPU, tied embedding + LM head on the CPU (see module docstring)."""

    def __init__(self, model, device: str):
        import torch
        torch.backends.cuda.matmul.allow_tf32 = False
        torch.backends.cudnn.allow_tf32 = False
        self.torch = torch
        self.device = torch.device(device)
        self.full = model                                   # kept for .config / CPU twin
        inner = model.model
        self.embed = inner.embed_tokens                     # CPU, fp32
        self.lm_head = model.lm_head                        # CPU, tied to self.embed
        inner.layers.to(self.device)
        inner.norm.to(self.device)
        inner.rotary_emb.to(self.device)
        self.inner = inner
        self.config = model.config

    def __call__(self, input_ids=None, past_key_values=None, use_cache=True,
                 output_hidden_states=False, attention_mask=None, **_):
        torch = self.torch
        with torch.no_grad():
            emb = self.embed(input_ids).to(self.device)
            am = attention_mask.to(self.device) if attention_mask is not None else None
            out = self.inner(inputs_embeds=emb, past_key_values=past_key_values, use_cache=use_cache,
                             attention_mask=am, output_hidden_states=output_hidden_states)
            last = out.last_hidden_state[:, -1:, :].to("cpu")
            logits = self.lm_head(last)                     # (1, 1, V) on CPU, fp32
            hs = None
            if output_hidden_states:
                hs = tuple(h[:, -1:, :].to("cpu") for h in out.hidden_states)
        return SimpleNamespace(logits=logits, hidden_states=hs, past_key_values=out.past_key_values)

    def eval(self):
        return self


def split_device(model):
    """The model itself on CPU; the GPU split wrapper when a GPU is selected."""
    d = guard_device()
    if d == "cpu":
        return model
    return _SplitCausalLM(model, d)


def classifier_cuda_ok(name: str = "") -> bool:
    """May this small classifier take the GPU? False when SENTINEL_CLASSIFIER_DEVICE=cpu (set
    whenever the guard shares the 4 GB card) UNLESS `name` is on the SENTINEL_GPU_CLASSIFIERS
    allow-list (e.g. "piguard,minilm": 0.83 GB beside the guard's measured 2.1 GB peak;
    Prompt Guard's 1.1 GB would not fit)."""
    import torch
    if not torch.cuda.is_available():
        return False
    allow = {x.strip().lower() for x in os.getenv("SENTINEL_GPU_CLASSIFIERS", "").split(",") if x.strip()}
    if name and name.strip().lower() in allow:
        return True
    return os.getenv("SENTINEL_CLASSIFIER_DEVICE", "auto").strip().lower() != "cpu"
