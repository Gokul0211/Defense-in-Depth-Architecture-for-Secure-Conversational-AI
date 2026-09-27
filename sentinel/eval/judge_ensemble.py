"""
Multi-model LLM judge for evaluation runs — fallback chains and ensembles.

WHY THIS EXISTS
------------------
Production's `llm_judge_check` is deliberately a single call with no
retries: it sits on the live request path and must fail fast rather than
block a request (see that module's PRODUCTION-PATH DISCIPLINE note). That
is the right design there, and this module does not change it.

Bulk evaluation has the opposite requirements. A 2,210-sample corpus with
a ~48% judge-invocation rate makes ~1,000 judge calls; at the single-call
failure rates measured on 2026-09-18 (40-sample WildJailbreak benchmark,
real calls) a meaningful fraction of them silently degrade to "no signal":

    cohere/command-a-03-2025                    AUROC 0.7562    0/40 failed
    openrouter/nemotron-3-super-120b-a12b:free  AUROC 0.6850    5/40 failed
    nvidia/openai/gpt-oss-20b                   AUROC 0.6375    8/40 failed
    openai/gpt-oss-120b   (direct Groq)         AUROC 0.5875   17/40 failed
    openai/gpt-oss-20b    (direct Groq)         AUROC 0.5000   39/40 failed

A run whose judge tier is unavailable on a third of samples is not
measuring the system it claims to measure — Phase 3.1 hit exactly this and
had to discard a sweep. So evaluation gets redundancy that production
does not.

TWO MODES
------------
`fallback`  — try models in order, take the first usable score. Cheapest
              (≈1 call/sample) and targets RELIABILITY: it converts a
              provider hiccup into a retry against a different provider
              rather than into a missing signal.
`ensemble`  — query every model, aggregate the usable scores. Costs
              N calls/sample and targets ACCURACY, on the standard
              argument that averaging decorrelated weak judges beats any
              single one. Whether that holds here is an empirical
              question, not an assumption — measure it before adopting.

HONEST SCOPE
---------------
EVAL-ONLY. Nothing here is imported by `layer1.py`, `app.py`, or any
production path; `install()` must be called explicitly. Any run that uses
it is running a DIFFERENT judge from production's single `gpt-oss-20b`
call, and that difference has to be disclosed in whatever number the run
produces — it is a change to the system under test, not a neutral
speed-up.

Parsing, the score regex and the system prompt are all imported from
`layer1_llm_judge` rather than reimplemented, so a judge fix lands in both
places at once. That matters: two of the three bugs found on 2026-09-18
were parsing bugs.
"""

from __future__ import annotations

import asyncio
import logging
import os
import statistics

from sentinel.layers.layer1_llm_judge import (
    _JUDGE_SYSTEM_PROMPT,
    _SCORE_RE,
    _extract_judge_text,
)

logger = logging.getLogger(__name__)

# Measured-best ordering (see the table above). Reliability first: the
# lead model is the only one that returned a usable score on every sample.
DEFAULT_CHAIN = (
    "cohere/command-a-03-2025",
    "openrouter/nvidia/nemotron-3-super-120b-a12b:free",
    "nvidia/openai/gpt-oss-20b",
)

_OMNIROUTE_ENDPOINT = "http://127.0.0.1:20128/v1/chat/completions"

_stats = {"calls": 0, "failures": 0, "by_model": {}, "fallback_used": 0, "no_usable": 0}


def get_stats() -> dict:
    """Per-model call/failure counts for the run. Report these alongside
    any number this judge produced — a result whose judge silently failed
    on a third of samples is not the result it appears to be."""
    return {k: (dict(v) if isinstance(v, dict) else v) for k, v in _stats.items()}


def reset_stats() -> None:
    _stats.update({"calls": 0, "failures": 0, "by_model": {}, "fallback_used": 0, "no_usable": 0})


async def _score_one(client, model: str, text: str, timeout: float) -> float | None:
    """One judge call. Returns None on any failure — same contract as
    production's `llm_judge_check`, so a caller can never mistake a failed
    call for a confident 0.0."""
    bucket = _stats["by_model"].setdefault(model, {"calls": 0, "failures": 0})
    _stats["calls"] += 1
    bucket["calls"] += 1
    try:
        resp = await client.post(
            _OMNIROUTE_ENDPOINT,
            json={
                "model": model,
                "temperature": 0.0,
                "max_tokens": int(os.getenv("LLM_JUDGE_MAX_TOKENS", "300")),
                "messages": [
                    {"role": "system", "content": _JUDGE_SYSTEM_PROMPT},
                    {"role": "user", "content": f"<text>\n{text}\n</text>\n\nScore:"},
                ],
            },
            headers={
                "Authorization": f"Bearer {os.environ['OMNIROUTE_API_KEY']}",
                "Content-Type": "application/json",
            },
            timeout=timeout,
        )
        resp.raise_for_status()
        raw = _extract_judge_text(resp.json())
        if raw is None:
            raise ValueError("no usable text field")
        match = _SCORE_RE.search(raw)
        if not match:
            raise ValueError(f"unparseable: {raw[:40]!r}")
        return max(0.0, min(1.0, float(match.group(0))))
    except Exception as e:
        _stats["failures"] += 1
        bucket["failures"] += 1
        logger.debug(f"judge model {model} failed: {type(e).__name__}: {str(e)[:80]}")
        return None


def make_judge(
    chain: tuple[str, ...] = DEFAULT_CHAIN,
    mode: str = "fallback",
    aggregate: str = "mean",
    timeout: float = 30.0,
    min_interval: float = 0.0,
):
    """
    Build a drop-in replacement for `llm_judge_check(text) -> float|None`.

    `aggregate` applies only in ensemble mode. "mean" is the default
    because it uses every usable vote; "median" is more robust to a single
    badly-miscalibrated model; "max" is deliberately NOT offered — it would
    reproduce the same one-signal-dominates failure that plan item 3B.3
    exists to fix, one level down.

    `min_interval` throttles SAMPLES (not individual model calls — the
    ensemble's calls fan out concurrently on purpose). 0.0 is right for a
    short benchmark; a bulk run over thousands of samples should set a
    small positive value, because ensemble mode multiplies call volume by
    len(chain) and the measured burst rate was ~20 calls/sec, which is
    where Phase 3.1's 429 storm started.
    """
    import httpx

    # Lock-free on purpose. An `asyncio.Lock()` created here is bound to
    # the event loop that created it, but the eval runner calls
    # `asyncio.run(...)` PER SAMPLE — a fresh loop each time — so a shared
    # Lock deadlocks the second sample onward. Observed live on
    # 2026-09-18: a WildJailbreak run logged 29 HTTP requests and then
    # hung silently for 9 minutes with no error. Judge calls are
    # sequential within a sample anyway (the ensemble's concurrency is the
    # gather below, which is inside one loop), so a plain timestamp is
    # both sufficient and loop-agnostic.
    pacing = {"last": 0.0}

    if aggregate not in ("mean", "median"):
        raise ValueError(f"unsupported aggregate {aggregate!r} (use mean or median)")
    if mode not in ("fallback", "ensemble"):
        raise ValueError(f"unsupported mode {mode!r}")

    async def judge(text: str, timeout_override: float | None = None) -> float | None:
        t = timeout_override or timeout
        if min_interval > 0:
            import time as _time
            wait = min_interval - (_time.monotonic() - pacing["last"])
            if wait > 0:
                await asyncio.sleep(wait)
            pacing["last"] = _time.monotonic()
        async with httpx.AsyncClient(timeout=t) as client:
            if mode == "fallback":
                for i, model in enumerate(chain):
                    score = await _score_one(client, model, text, t)
                    if score is not None:
                        if i > 0:
                            _stats["fallback_used"] += 1
                        return score
                _stats["no_usable"] += 1
                return None

            results = await asyncio.gather(
                *(_score_one(client, m, text, t) for m in chain)
            )
            usable = [s for s in results if s is not None]
            if not usable:
                _stats["no_usable"] += 1
                return None
            return statistics.mean(usable) if aggregate == "mean" else statistics.median(usable)

    return judge


def install(**kwargs) -> None:
    """
    Monkeypatch the multi-model judge over `layer1`'s reference to
    `llm_judge_check` for the lifetime of this process.

    `layer1.layer1_check` imports the symbol INSIDE the function body, so
    patching the source module is what actually takes effect — verified by
    reading layer1.py rather than assumed. Mirrors how Phase 3.1 installed
    its fallback chain: eval-only, explicit, and reverted by simply not
    calling this.
    """
    import sentinel.layers.layer1_llm_judge as judge_module

    if "OMNIROUTE_API_KEY" not in os.environ:
        raise RuntimeError(
            "OMNIROUTE_API_KEY is not set — the multi-model judge routes through "
            "the local OmniRoute gateway and cannot authenticate without it."
        )
    judge_module.llm_judge_check = make_judge(**kwargs)
    logger.info(
        f"multi-model judge installed: mode={kwargs.get('mode', 'fallback')} "
        f"chain={kwargs.get('chain', DEFAULT_CHAIN)}"
    )
