"""
One-off diagnostic: compare candidate judge backends on the same real
WildJailbreak samples, to find one trustworthy enough for BULK EVALUATION
judge calls (sweeps, full-corpus reruns) — see layer1_llm_judge.py's
rate-limit findings, 2026-09-14: Groq's account-level daily request cap
and per-window token bucket make repeated bulk eval runs against
SENTINEL's own Groq key unreliable same-day. Ollama/phi3.5 (local, 3.8B)
was tried and found too weak (AUROC ~0.5, chance level) specifically on
the indirect/fictionally-framed jailbreaks this corpus is dominated by.
This run tries OmniRoute (a local multi-provider router,
127.0.0.1:20128/v1) routed to a SEPARATE Groq account's
openai/gpt-oss-120b — same model family SENTINEL's own judge uses, larger
size, genuinely different quota pool.

Does NOT touch production config — calls llm_judge_check() with
monkeypatched sentinel.config values, restoring them after.

Usage:
    python -m sentinel.eval.compare_judge_backends
"""

from __future__ import annotations

import asyncio
import json

import sentinel.config as config
from sentinel.layers.layer1_llm_judge import llm_judge_check


async def _judge_with(text: str, backend: str, api_key: str, model: str, timeout: float = 6.0) -> float | None:
    orig_backend, orig_key, orig_model = config.LLM_BACKEND, config.LLM_API_KEY, config.LLM_MODEL_OVERRIDE
    config.LLM_BACKEND, config.LLM_API_KEY, config.LLM_MODEL_OVERRIDE = backend, api_key, model
    # The judge's own model/effort take precedence over LLM_MODEL_OVERRIDE, so a
    # backend comparison must set them too or it silently measures the default judge.
    orig_jm, orig_eff = config.L1_JUDGE_MODEL, config.LLM_JUDGE_REASONING_EFFORT
    config.L1_JUDGE_MODEL, config.LLM_JUDGE_REASONING_EFFORT = model, ""
    try:
        return await llm_judge_check(text, timeout=timeout)
    finally:
        config.LLM_BACKEND, config.LLM_API_KEY, config.LLM_MODEL_OVERRIDE = orig_backend, orig_key, orig_model
        config.L1_JUDGE_MODEL, config.LLM_JUDGE_REASONING_EFFORT = orig_jm, orig_eff


async def main() -> None:
    with open("/tmp/judge_compare_samples.json", encoding="utf-8") as f:
        samples = json.load(f)

    omniroute_backend = "http://127.0.0.1:20128/v1/chat/completions"
    omniroute_key = "unused"  # REQUIRE_API_KEY=false on this local instance
    omniroute_model = "openai/gpt-oss-120b"

    rows = []
    for i, s in enumerate(samples):
        text, label = s["text"], s["label"]
        score = await _judge_with(text, omniroute_backend, omniroute_key, omniroute_model, timeout=30.0)
        rows.append({"i": i, "label": label, "omniroute_gpt_oss_120b": score})
        print(f"[{i:2d}] label={label:9s} score={score}")

    print("\n--- summary (OmniRoute / openai/gpt-oss-120b) ---")
    ok = [r for r in rows if r["omniroute_gpt_oss_120b"] is not None]
    print(f"succeeded: {len(ok)}/{len(rows)}")

    if ok:
        import numpy as np
        o = np.array([r["omniroute_gpt_oss_120b"] for r in ok])
        y = np.array([1 if r["label"] == "malicious" else 0 for r in ok])
        o_pred = (o >= 0.5).astype(int)
        o_acc = (o_pred == y).mean()
        print(f"accuracy vs real label (threshold 0.5): {o_acc:.3f}")
        if len(set(y.tolist())) > 1:
            from sklearn.metrics import roc_auc_score
            print(f"AUROC vs real label: {roc_auc_score(y, o):.3f}")
        print(f"mean score, malicious samples: {o[y==1].mean() if (y==1).any() else float('nan'):.3f}")
        print(f"mean score, benign samples:    {o[y==0].mean() if (y==0).any() else float('nan'):.3f}")

    with open("sentinel/eval/results/judge_backend_comparison.json", "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=2)


if __name__ == "__main__":
    asyncio.run(main())
