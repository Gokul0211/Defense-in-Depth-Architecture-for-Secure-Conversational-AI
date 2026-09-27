"""
Independent POLICY judge on Gemini (OpenAI-compatible endpoint), key pool from
GEMINI_API_KEYS. Used for LABELLING work -- the benign-arm audit (deep_rca.md R-021) --
where the labeller should NOT be the same model family as any detector under test
(Groq's gpt-oss-safeguard is the production judge). Never used on a production decision
path, so it cannot change a reported detector number.

Returns a float in [0, 1] (the policy prompt asks for one number) or None when every key
is out of quota or the call fails -- callers treat None as "unlabelled", never as benign.
Keys rotate on 429; a key that says its DAILY quota is spent is parked for the process.
"""
from __future__ import annotations

import asyncio
import os
import re
import time

import httpx

_BASE = "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
_NUM = re.compile(r"(?<![\d.])(0(?:\.\d+)?|1(?:\.0+)?)(?![\d.])")

_keys: list[str] | None = None
_dead: set[int] = set()
_next_ok: dict[int, float] = {}
_idx = 0
_lock = asyncio.Lock()
calls = {"ok": 0, "failed": 0, "rate_limited": 0, "keys_exhausted": 0}


def _pool() -> list[str]:
    global _keys
    if _keys is None:
        try:
            from dotenv import load_dotenv
            load_dotenv(".env")
        except Exception:                                              # noqa: BLE001
            pass
        _keys = [k.strip() for k in os.getenv("GEMINI_API_KEYS", "").split(",") if k.strip()]
    return _keys


def model_name() -> str:
    # Gemini 3 family only (2.5 is closed to new accounts; verified on all 4 keys
    # 2026-09-25): 3.1-flash-lite answered on every key in 2-7 s; 3.5-flash is stronger
    # but returned 503 (overloaded) on half the attempts. Override with GEMINI_JUDGE_MODEL.
    return os.getenv("GEMINI_JUDGE_MODEL", "gemini-3.1-flash-lite")


async def gemini_policy_check(text: str, system_prompt: str, timeout: float = 60.0,
                              min_interval: float = 6.5) -> float | None:
    """One policy-judge call. `min_interval` paces each key (free tier ~10 RPM)."""
    global _idx
    keys = _pool()
    if not keys:
        return None
    for _attempt in range(len(keys) * 3):
        async with _lock:
            live = [i for i in range(len(keys)) if i not in _dead]
            if not live:
                return None
            i = live[_idx % len(live)]
            _idx += 1
            wait = _next_ok.get(i, 0.0) - time.monotonic()
            if wait > 0:
                await asyncio.sleep(wait)
            _next_ok[i] = time.monotonic() + min_interval
        try:
            async with httpx.AsyncClient(timeout=timeout) as c:
                r = await c.post(_BASE, headers={"Authorization": f"Bearer {keys[i]}"}, json={
                    "model": model_name(), "temperature": 0.0, "reasoning_effort": "low",
                    "messages": [{"role": "system", "content": system_prompt},
                                 {"role": "user", "content": f"<text>\n{text}\n</text>\n\nScore:"}]})
        except Exception:                                              # noqa: BLE001
            calls["failed"] += 1
            continue
        if r.status_code == 429:
            calls["rate_limited"] += 1
            body = r.text.lower()
            if "per day" in body or "perday" in body or "daily" in body:
                _dead.add(i); calls["keys_exhausted"] += 1
            else:
                _next_ok[i] = time.monotonic() + 30.0
            continue
        if r.status_code in (500, 502, 503, 504):           # overloaded: retry later, not a failure
            calls.setdefault("overloaded", 0)
            calls["overloaded"] += 1
            _next_ok[i] = time.monotonic() + 15.0
            continue
        if r.status_code != 200:
            calls["failed"] += 1
            continue
        try:
            content = r.json()["choices"][0]["message"]["content"] or ""
        except Exception:                                              # noqa: BLE001
            calls["failed"] += 1
            continue
        m = _NUM.search(content.strip())
        if not m:
            calls["failed"] += 1
            return None
        calls["ok"] += 1
        return float(m.group(1))
    return None
