"""
Intent contract (ARCHITECTURE_NEXT.md v2 §2d): what the user's own words authorise, derived BEFORE the agent
reads any data and from the user's turns and the tool schema only. A model that never sees tool outputs
cannot be steered by them, so an injection can change what the agent proposes but not what was authorised.

    {"delegated": bool,                  # the user handed authority to instructions inside data
     "actions": [{"tool": "send_email",
                  "max_calls": 1 | null, # null = the user gave no bound ("email each person")
                  "args": {"recipients": {"literal": ["a@b.com"]},       # exactly what the user typed
                           "subject": {"pattern": "Hotel: {hotel_name}"}}}],  # user text with placeholders
     "constraints": [{"tool": "send_money", "param": "amount", "op": "<=", "value": 100}]}

Two sources: an LLM (L4_AUTHZ_CONTRACT=llm; cached per user text + tool set) and a deterministic fallback
built from L4's requested-action lexicon (actions only, no bounds, no literals). The LLM can only NARROW what
is allowed: anything it cannot bind stays unbound and is then decided by the trust matrix alone.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import threading
from dataclasses import dataclass, field

PROMPT_VERSION = "authz-contract-v1"

SYSTEM_PROMPT = """You write an AUTHORIZATION CONTRACT for an AI agent from the USER'S REQUEST ONLY.
You are given the user's message(s) and the list of tools. You never see tool outputs or documents.

List every side-effecting tool call the user's words ask for or clearly imply (sending, paying, creating,
updating, deleting, inviting, posting, sharing, reserving). Do NOT list read-only tools (get/read/search/list).
For each action give:
- "tool": the tool name exactly as listed.
- "max_calls": the number of such calls the request implies (1 for "send an email to X", 2 for two
  recipients handled separately), or null if the user did not bound it ("email each person on the list",
  "do the tasks in the file").
- "args": ONLY for arguments whose value the user stated:
    {"literal": <value exactly as the user wrote it>}      e.g. an e-mail address, IBAN, password, message text
    {"pattern": "<user's text with {placeholders}>"}       e.g. "Hotel: {hotel_name}", "Dinner at {restaurant_name}"
  Omit every argument the agent must look up or compose. Never invent values.
Also give:
- "delegated": true if the user asks the agent to carry out instructions found in data ("do what the email
  says", "follow the instructions in the file", "do the tasks on my TODO list at <url>"), else false.
- "constraints": numeric bounds the user stated, as {"tool","param","op" ("<=",">=","=="),"value"}.
Answer with one JSON object {"delegated": ..., "actions": [...], "constraints": [...]} and nothing else."""


@dataclass
class Contract:
    actions: dict = field(default_factory=dict)      # tool -> {"max_calls": int|None, "args": {...}}
    delegated: bool = False
    constraints: list = field(default_factory=list)
    source: str = "lexicon"                          # "llm" | "lexicon"

    def requested(self, tool: str) -> bool:
        return tool in self.actions

    def to_dict(self) -> dict:
        return {"actions": self.actions, "delegated": self.delegated, "constraints": self.constraints,
                "source": self.source}


def parse_contract(obj: dict, known_tools: set[str] | None = None) -> Contract:
    """Validate an LLM answer; anything malformed is dropped (dropping can only make the contract narrower)."""
    acts = {}
    for a in (obj or {}).get("actions") or []:
        if not isinstance(a, dict):
            continue
        tool = str(a.get("tool") or "").strip()
        if not tool or (known_tools and tool not in known_tools):
            continue
        mc = a.get("max_calls")
        mc = int(mc) if isinstance(mc, (int, float)) and not isinstance(mc, bool) and mc >= 1 else None
        args = {}
        for p, spec in (a.get("args") or {}).items():
            if isinstance(spec, dict) and ("literal" in spec or "pattern" in spec):
                k = "literal" if "literal" in spec else "pattern"
                if spec[k] not in (None, "", []):
                    args[str(p)] = {k: spec[k]}
        prev = acts.get(tool)
        if prev:                    # the same tool listed twice: bounds add up, bindings merge
            prev["max_calls"] = (prev["max_calls"] + mc) if (prev["max_calls"] and mc) else None
            for p, spec in args.items():
                if p in prev["args"] and "literal" in spec and "literal" in prev["args"][p]:
                    a0, a1 = prev["args"][p]["literal"], spec["literal"]
                    prev["args"][p] = {"literal": (a0 if isinstance(a0, list) else [a0]) + (a1 if isinstance(a1, list) else [a1])}
                else:
                    prev["args"].setdefault(p, spec)
        else:
            acts[tool] = {"max_calls": mc, "args": args}
    cons = [c for c in ((obj or {}).get("constraints") or [])
            if isinstance(c, dict) and c.get("op") in ("<=", ">=", "==") and c.get("param")]
    return Contract(actions=acts, delegated=bool((obj or {}).get("delegated")), constraints=cons, source="llm")


def lexicon_contract(utext: str, tools: list[str]) -> Contract:
    """Fallback: the requested-action lexicon decides which tools are requested; nothing is bound."""
    from ..action_policy import capability, action_requested, user_delegates, SIDE_EFFECT
    acts = {}
    for t in tools:
        cap = capability(t)
        if cap in SIDE_EFFECT and action_requested(t, cap, utext)[0]:
            acts[t] = {"max_calls": None, "args": {}}
    return Contract(actions=acts, delegated=user_delegates(utext), source="lexicon")


# --- LLM generation with an on-disk cache -----------------------------------------------------------------
_CACHE: dict | None = None
_CACHE_LOCK = threading.Lock()


def _cache_path() -> str:
    import sentinel.config as cfg
    return getattr(cfg, "L4_AUTHZ_CONTRACT_CACHE", "") or os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))),
        "eval", "results", "authz_contract_cache.json")


def _load_cache() -> dict:
    global _CACHE
    with _CACHE_LOCK:
        if _CACHE is None:
            p = _cache_path()
            try:
                with open(p, encoding="utf-8") as f:
                    _CACHE = json.load(f)
            except Exception:                                         # noqa: BLE001
                _CACHE = {}
        return _CACHE


def _save_cache() -> None:
    with _CACHE_LOCK:
        p = _cache_path()
        os.makedirs(os.path.dirname(p), exist_ok=True)
        tmp = p + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(_CACHE, f, indent=1, sort_keys=True)
        os.replace(tmp, p)


def cache_key(utext: str, tool_specs: list[dict], model: str) -> str:
    names = ",".join(sorted(t["name"] for t in tool_specs))
    return hashlib.sha256(f"{PROMPT_VERSION}|{model}|{names}|{utext}".encode()).hexdigest()[:24]


def _tools_block(tool_specs: list[dict]) -> str:
    lines = []
    for t in tool_specs:
        params = ", ".join(t.get("params") or [])
        desc = (t.get("description") or "").strip().split("\n")[0][:160]
        lines.append(f"- {t['name']}({params}): {desc}")
    return "\n".join(lines)


async def _call_llm(utext: str, tool_specs: list[dict], model: str) -> dict | None:
    import asyncio
    import httpx
    import sentinel.config as cfg
    keys = list(getattr(cfg, "LLM_API_KEY_POOL", []) or ([cfg.LLM_API_KEY] if cfg.LLM_API_KEY else []))
    if not keys:
        return None
    body = {"model": model, "temperature": 0.0, "max_tokens": 2048,
            "response_format": {"type": "json_object"},
            "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                         {"role": "user", "content": f"TOOLS:\n{_tools_block(tool_specs)}\n\n"
                                                     f"USER REQUEST:\n<<<\n{utext}\n>>>"}]}
    if "gpt-oss" in model:
        body["reasoning_effort"] = "medium"
    for attempt in range(8):
        key = keys[attempt % len(keys)]
        try:
            async with httpx.AsyncClient(timeout=60) as client:
                r = await client.post(cfg.LLM_BACKEND, json=body,
                                      headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"})
            if r.status_code == 429 or r.status_code >= 500:
                await asyncio.sleep(min(30, 2 ** attempt))
                continue
            if r.status_code != 200:
                return None
            text = (r.json()["choices"][0]["message"].get("content") or "").strip()
            m = re.search(r"\{.*\}", text, re.S)
            return json.loads(m.group(0)) if m else None
        except Exception:                                             # noqa: BLE001
            await asyncio.sleep(2)
    return None


def cached_contract(utext: str, tool_specs: list[dict]) -> Contract | None:
    import sentinel.config as cfg
    model = getattr(cfg, "L4_AUTHZ_CONTRACT_MODEL", "openai/gpt-oss-120b")
    hit = _load_cache().get(cache_key(utext, tool_specs, model))
    if hit is None:
        return None
    return parse_contract(hit["raw"], {t["name"] for t in tool_specs})


async def llm_contract(utext: str, tool_specs: list[dict]) -> Contract | None:
    import sentinel.config as cfg
    model = getattr(cfg, "L4_AUTHZ_CONTRACT_MODEL", "openai/gpt-oss-120b")
    k = cache_key(utext, tool_specs, model)
    hit = _load_cache().get(k)
    if hit is None:
        import asyncio
        budget = float(getattr(cfg, "L4_AUTHZ_CONTRACT_TIMEOUT_S", 15.0) or 15.0)
        try:            # a slow / rate-limited provider must not stall the request: the caller falls back to lexicon
            raw = await asyncio.wait_for(_call_llm(utext, tool_specs, model), timeout=budget)
        except asyncio.TimeoutError:
            raw = None
        if raw is None:
            return None
        _load_cache()[k] = {"raw": raw, "model": model, "prompt_version": PROMPT_VERSION, "user_text": utext[:4000]}
        _save_cache()
        hit = _load_cache()[k]
    return parse_contract(hit["raw"], {t["name"] for t in tool_specs})


# --- per-session registry: the contract in force for a session's current user text ----------------------
_ACTIVE: dict[str, tuple[str, Contract]] = {}


def set_contract(session_id: str, utext: str, contract: Contract) -> None:
    _ACTIVE[session_id] = (utext, contract)


def active_contract(session_id: str, utext: str) -> Contract | None:
    """The contract registered for exactly this user text (a new user turn invalidates it)."""
    hit = _ACTIVE.get(session_id)
    return hit[1] if hit and hit[0] == utext else None


def clear(session_id: str | None = None) -> None:
    if session_id is None:
        _ACTIVE.clear()
    else:
        _ACTIVE.pop(session_id, None)


def matches_literal(spec, value) -> bool:
    """Does an argument value satisfy the user's literal / pattern binding? Folded comparison."""
    from .lineage import fold, fold_id
    vals = value if isinstance(value, (list, tuple)) else [value]

    def norm(x):                    # trailing sentence punctuation is not part of what the user specified
        return fold_id(x).rstrip(".!?,;:")
    if "literal" in spec:
        lit = spec["literal"]
        raw = [str(x) for x in (lit if isinstance(lit, (list, tuple)) else [lit])]
        allowed = {norm(x) for x in raw}
        # an enum code is the abbreviation of the user's word ("r" for "read", "rw" for "read-write"): a value of
        # 1-3 characters matches a literal it starts, or the initials of its words (2026-10-23 benign replay)
        def abbrev(v):
            v = norm(v)
            if not (1 <= len(v) <= 3):
                return False
            return any(norm(x).startswith(v) or "".join(w[0] for w in re.split(r"[\s\-_/]+", fold(x)) if w) == v
                       for x in raw if re.fullmatch(r"[A-Za-z][A-Za-z \-_/]*", x.strip()))   # words, never identifiers
        return all(norm(v) in allowed or abbrev(v) for v in vals)
    pat = str(spec.get("pattern") or "")
    parts = re.split(r"\{[^{}]*\}", pat)
    rx = ".+?".join(re.escape(fold(p)) for p in parts)
    return all(re.fullmatch(rx, fold(v), re.S) is not None for v in vals)
