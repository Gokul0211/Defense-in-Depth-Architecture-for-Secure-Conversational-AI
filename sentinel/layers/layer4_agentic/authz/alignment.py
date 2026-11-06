"""
Local per-call ALIGNMENT check (config.L4_ALIGNMENT_LOCAL, 2026-11-01): does this tool call, with these arguments,
serve the user's request? The local Qwen3-4B (core/local_judge.py) answers the existing ACTION_ALIGNMENT_V1 question
(core/policy_prompts.py) as yes / no, read as log-odds; nothing leaves the machine.

WHY (scratch/rca/l2/L2_REDESIGN.md, results.md §20.15–20.16). Offline, L4 decides "requested" with a verb lexicon or an
intent contract that lists only the side effects a request clearly implies. Agents also call tools the user never
named that still serve the task (ASB: 81 / 100 legitimate calls held with the lexicon, 40 / 100 with the local
contract on vague tasks). Task Shield (Jia et al., ACL 2025) and MELON judge each call against the user's task; this is
that check, local. It can only RESCUE a call that would otherwise be held (a confident "yes, the request implies this
call"); it never loosens a block, and an attacker's call carries the injected instruction in its arguments, which the
question reads.
"""
from __future__ import annotations

import hashlib
import json

ALIGN_SYSTEM = None          # built lazily from policy_prompts.ACTION_ALIGNMENT_V1
ALIGN_FMT = "{0}\n\nAnswer:"
_CACHE: dict[str, float] = {}


def _system() -> str:
    from sentinel.core.policy_prompts import ACTION_ALIGNMENT_V1
    head = ACTION_ALIGNMENT_V1.split("Output ONLY a single number")[0].rstrip()
    return head + ("\n\nAnswer with ONLY one word: yes if this tool call is something the user's request asks for or "
                   "clearly implies (YES above), no otherwise (NO above). No other words.")


def call_text(user_request: str, tool: str, params: dict, description: str = "") -> str:
    from sentinel.core.policy_prompts import action_alignment_text
    t = action_alignment_text(user_request, tool, params or {})
    return t + (f"\nTOOL DESCRIPTION: {description[:400]}" if description else "")


def alignment_log_odds(user_request: str, tool: str, params: dict, description: str = "") -> float | None:
    """log-odds that the call serves the user's request (yes), or None without the local model."""
    text = call_text(user_request, tool, params, description)
    key = hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()[:24]
    if key in _CACHE:
        return _CACHE[key]
    from sentinel.core import local_judge as lj
    j = lj.get_local_judge()
    if j is None:
        return None
    with lj._lock:
        if "l4align" not in getattr(j, "templates", {}):
            j.add_template("l4align", _system(), ALIGN_FMT, escape=lambda s: s)
        lo = float(j.read_template("l4align", text)["log_odds"])
    _CACHE[key] = lo
    return lo


def prompt_md5() -> str:
    return hashlib.md5((_system() + ALIGN_FMT).encode("utf-8")).hexdigest()


def describe(params) -> str:
    try:
        return json.dumps(params, ensure_ascii=False, default=str)[:200]
    except Exception:                                                 # noqa: BLE001
        return str(params)[:200]
