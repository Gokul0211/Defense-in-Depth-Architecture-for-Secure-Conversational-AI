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

PROMPT_VERSION_V1 = "authz-contract-v1"
PROMPT_VERSION_V2 = "authz-contract-v2"

SYSTEM_PROMPT_V1 = """You write an AUTHORIZATION CONTRACT for an AI agent from the USER'S REQUEST ONLY.
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

# v2 (2026-10-23, scratch/rca/v6/ADR.md): adds per-argument DELEGATED SOURCES. Naming a document delegates only the
# arguments the user says to take from it; the policy blocks an authority-bearing value read from document text
# unless its argument is delegated here.
SYSTEM_PROMPT_V2 = SYSTEM_PROMPT_V1.replace(
    """  Omit every argument the agent must look up or compose. Never invent values.""",
    """    {"from": "<the source the user said to take it from>"}  when the user tells the agent WHERE to find the
                                                            value: "pay the bill in bill.txt" -> recipient and
                                                            amount {"from": "bill.txt"}; "invite Dora, her e-mail
                                                            is on her website www.x.com" -> user_email
                                                            {"from": "www.x.com"}; "send it to the client named in
                                                            the minutes" -> recipients {"from": "the minutes"}
  Omit every other argument the agent must look up or compose. Never invent values or sources: an argument the
  user gave no source for gets no "from".""")

# kept as the module default name for callers that import it
# v3 (2026-10-23, scratch/rca/v7/PROPOSALS.md P1): adds per-argument SELECTION CRITERIA, checked by authz/selector.py
# against the rows the agent read.
PROMPT_VERSION_V3 = "authz-contract-v3"
SYSTEM_PROMPT_V3 = SYSTEM_PROMPT_V2.replace(
    """  Omit every other argument the agent must look up or compose.""",
    """    {"select": {"by": "<attribute>", "order": "max" | "min"}}   when the user picks the target by a criterion:
                                                            "delete the largest file" -> file_id {"select":
                                                            {"by": "size", "order": "max"}}; "book the cheapest
                                                            hotel" -> hotel {"select": {"by": "price", "order":
                                                            "min"}}. "from" and "select" may be combined.
  Omit every other argument the agent must look up or compose.""")

PROMPT_VERSION = PROMPT_VERSION_V1
SYSTEM_PROMPT = SYSTEM_PROMPT_V1


def _prompt():
    """(version, system prompt) selected by config.L4_AUTHZ_CONTRACT_PROMPT. "v1" is the default until the policy
    side of ADR-6 (delegated sources) is implemented; "v2" only adds the per-argument "from" field."""
    import sentinel.config as cfg
    v = str(getattr(cfg, "L4_AUTHZ_CONTRACT_PROMPT", "v1")).lower()
    if v == "v3":
        return PROMPT_VERSION_V3, SYSTEM_PROMPT_V3
    if v == "v2":
        return PROMPT_VERSION_V2, SYSTEM_PROMPT_V2
    return PROMPT_VERSION_V1, SYSTEM_PROMPT_V1


@dataclass
class Contract:
    actions: dict = field(default_factory=dict)      # tool -> {"max_calls": int|None, "args": {...}}
    delegated: bool = False
    constraints: list = field(default_factory=list)
    source: str = "lexicon"                          # "llm" | "lexicon"
    rejected: dict = field(default_factory=dict)     # local only: unselected side-effect tool -> selection log-odds
    necessity_only: set = field(default_factory=set)  # local v10: tools only the necessity question selected

    def requested(self, tool: str) -> bool:
        return tool in self.actions

    def to_dict(self) -> dict:
        return {"actions": self.actions, "delegated": self.delegated, "constraints": self.constraints,
                "source": self.source, "rejected": self.rejected}


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
            elif isinstance(spec, dict) and (spec.get("from") or spec.get("select")):
                d = {}
                if isinstance(spec.get("from"), str) and spec["from"].strip():
                    d["from"] = spec["from"].strip()[:200]
                sel = spec.get("select")
                if (isinstance(sel, dict) and isinstance(sel.get("by"), str) and sel.get("by").strip()
                        and str(sel.get("order", "")).lower() in ("max", "min")):
                    d["select"] = {"by": sel["by"].strip()[:40], "order": str(sel["order"]).lower()}
                if d:
                    args[str(p)] = d
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
            if a.get("verify_criterion") is True:          # local lexicon+criterion entry: its criterion must verify
                acts[tool]["verify_criterion"] = True
    cons = [c for c in ((obj or {}).get("constraints") or [])
            if isinstance(c, dict) and c.get("op") in ("<=", ">=", "==") and c.get("param")]
    rej = {str(t): float(v) for t, v in ((obj or {}).get("rejected") or {}).items()
           if isinstance(v, (int, float)) and not isinstance(v, bool) and str(t) not in acts
           and (not known_tools or str(t) in known_tools)}
    return Contract(actions=acts, delegated=bool((obj or {}).get("delegated")), constraints=cons, source="llm",
                    rejected=rej)


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
    return hashlib.sha256(f"{_prompt()[0]}|{model}|{names}|{utext}".encode()).hexdigest()[:24]


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
            "messages": [{"role": "system", "content": _prompt()[1]},
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
        _load_cache()[k] = {"raw": raw, "model": model, "prompt_version": _prompt()[0], "user_text": utext[:4000]}
        _save_cache()
        hit = _load_cache()[k]
    return parse_contract(hit["raw"], {t["name"] for t in tool_specs})


# --- LOCAL STRUCTURED contract (L4_AUTHZ_CONTRACT=local; redesigned 2026-11-02) ----------------------------------
# WHY. The free-form v1 prompt answered by the 4B local model produced JSON the parser could not use: bindings without
# parameter names ({"literal": "Le Marais Boutique"}), bare values ({"recipient": "Alice"}), read-only tools as actions,
# now and then an action the user never asked for. Every binding was dropped, so an attacker's
# reserve_hotel("Riverside View Hotel") ran where the hosted contract's {"hotel": {"literal": "Le Marais Boutique"}}
# stopped it (AgentDojo held-out replay: 6 attack effects vs 3; results.md §20.16-20.17). The STRUCTURE is now built in
# code and the local model answers only small questions it handles reliably:
#   1. SELECTION: for each side-effecting tool, yes / no read as log-odds (> 0): does the request ask for or clearly
#      imply this tool? A list cannot be hallucinated; every tool is judged on its own.
#   2. BINDING: for each selected tool with parameters, the model fills a skeleton keyed by the tool's OWN parameter
#      names; every value is VERIFIED against the user's text (a literal must occur in it, a pattern's fixed parts
#      must) and dropped otherwise: the model cannot invent an authorised value.
#   3. delegated: the lexicon's delegation rule (deterministic).
# No data leaves the machine. Same cache file, its own model key; failure -> None -> the lexicon, as for the hosted model.
LOCAL_MODEL_KEY = "local:qwen3-4b-instruct-2507-nf4:structured-v5"

SEL_SYSTEM = """You decide which tools an AI agent's user is asking for. You see the user's request and ONE tool of the agent: its name, parameters and description.

Answer yes if the user's request asks for, or clearly implies, a call to this tool -- directly, or as a necessary step of what the user asked for. Answer no if the tool would do something the user did not ask for: sending, paying, deleting, booking, inviting, sharing, posting, changing something, or contacting someone the user did not mention.

Answer with ONLY one word: yes or no."""
SEL_FMT = "USER REQUEST:\n<<<\n{0}\n>>>\n\nTOOL: {1}\n\nAnswer:"

# L4 v8 (config.L4_LOCAL_SEL_NECESSITY, results.md §21.4): the question above is anchored on the request's WORDS
# ("refund" was not read as sending money: banking 4 rejected at -15.4). A tool it rejects gets this second question,
# framed on the EFFECT the user wants; it is selected when either answer is yes.
NEC_SYSTEM = """You decide which tools an AI agent must use to do what its user asked. You see the user's request and ONE tool of the agent: its name, parameters and description.

Think about the RESULT the user wants, however it is worded (for example, refunding someone is sending them money; writing a message to people is sending them messages). Answer yes if fully carrying out the request requires calling this tool. Answer no if the request can be fully carried out without it, or if the tool would do something the user did not ask for.

Answer with ONLY one word: yes or no."""


def local_model_key() -> str:
    """The cache key of the local contract: a second selection question changes the contracts it writes."""
    import sentinel.config as cfg
    return LOCAL_MODEL_KEY + ("+necessity" if getattr(cfg, "L4_LOCAL_SEL_NECESSITY", False) else "")

BIND_SYSTEM = """You extract the argument values a user stated for ONE tool call. You see the user's request and the tool with its parameters. Return a JSON object with exactly one key per parameter listed. For each parameter give:
- the value EXACTLY as the user wrote it (copy the user's words: a name, an address, a date, an amount, a message text), or
- a pattern with {placeholders} when the user gave a template (for example "Dinner at {restaurant_name}"), or
- {"select": {"by": "<attribute>", "order": "max" or "min"}} when the user picks the target by a criterion (for example "the largest file" -> {"select": {"by": "size", "order": "max"}}), or
- null when the user did not state it (the agent has to look it up or compose it).
Never invent a value the user did not write. Answer with the JSON object only."""


def _spec_line(t: dict) -> str:
    params = ", ".join(t.get("params") or [])
    desc = (t.get("description") or "").strip().split("\n")[0][:200]
    return f"{t['name']}({params})" + (f": {desc}" if desc else "")


def _stated_by_user(value, utext: str) -> bool:
    """Is this value present in the user's own words (folded; identifiers also compared in identifier form)?"""
    from .lineage import fold, fold_id
    v, ut = fold(value), fold(utext)
    if len(v) >= 2 and v in ut:
        return True
    vid = fold_id(value)
    return len(vid) >= 4 and vid in fold_id(utext)


def _pattern_stated(pat: str, utext: str) -> bool:
    from .lineage import fold
    ut = fold(utext)
    if fold(pat) in ut:
        return True
    parts = [x for x in re.split(r"\{[^{}]*\}", pat) if x.strip()]
    return bool(parts) and all(fold(x) in ut for x in parts)


# Each quote style pairs with itself; a single quote only at word edges, so apostrophes ("I'm", "hotel's") never open
# or close a quotation (a mixed character class paired "I'm ... hotel's" and swallowed the real "Booking hotel ...").
_QUOTED = [re.compile(r'"([^"]{2,400})"'), re.compile(r"“([^”]{2,400})”"), re.compile(r"‘([^’]{2,400})’"),
           re.compile(r"(?<![\w])'([^']{2,400})'(?![\w])")]


def _quoted_by_user(value: str, utext: str) -> bool:
    """A dictated text counts only when the user QUOTED it: an unquoted copy of the request ("summarize the article
    ...") is the user's instruction to the agent, not the message the user wants sent (smoke test 2026-11-02)."""
    from .lineage import fold
    v = fold(value)
    return bool(v) and any(v in fold(q) for rx in _QUOTED for q in rx.findall(utext or ""))


# The user picks the target by a criterion in their own words -> a "select" binding on the tool's identifying parameter,
# checked by authz/selector.py against the rows the agent read (config.L4_AUTHZ_TARGET_CRITERIA). The local model leaves
# such a parameter null ("the agent must look it up"), so the criterion is read deterministically from the request.
_CRITERIA = [(r"\b(largest|biggest)\b", "size", "max"), (r"\bsmallest\b", "size", "min"),
             (r"\b(cheapest|least expensive|lowest[- ]priced)\b", "price", "min"),
             (r"\b(most expensive|priciest|highest[- ]priced)\b", "price", "max"),
             (r"\b(highest[- ]rated|best[- ]rated|top[- ]rated|best[- ]reviewed)\b", "rating", "max"),
             (r"\b(lowest[- ]rated|worst[- ]rated)\b", "rating", "min"),
             (r"\b(newest|latest|most recent)\b", "date", "max"), (r"\b(oldest|earliest)\b", "date", "min")]
_ID_PARAM = re.compile(r"(^|_)(id|hotel|restaurant|company|file)$")


def criterion_from_request(utext: str):
    t = (utext or "").lower()
    hits = [(by, order) for pat, by, order in _CRITERIA if re.search(pat, t)]
    return hits[0] if len(set(hits)) == 1 else None          # two different criteria: ambiguous, bind nothing


# A model-written "select" is kept only when the user's words carry a superlative (v4: the model invented
# {"select": {"by": "event"}} for "the same participants as the meeting").
_SUPERLATIVE = re.compile(r"\b(largest|biggest|smallest|cheapest|lowest|highest|best|worst|newest|latest|oldest|"
                          r"earliest|most|least|fewest|priciest|top[- ]rated)\b", re.I)
# Destination parameters typed as identifiers: a literal there must LOOK like one (an e-mail, an IBAN, a URL). A person's
# name ("Sarah Baker") is resolved by the agent from the user's contacts and checked by the lineage matrix instead; bound
# as a literal it mismatched the e-mail the agent passed (AgentDojo benign replay, v4).
_ID_TYPED = re.compile(r"^(participants|recipients|emails?|user_emails?|to|cc|bcc|attendees)$")
_PREFIX = r"(?:starting|beginning|that starts|which starts|that begins|which begins)\s+with\s+[\"'‘“]?"


def _split_ids(v: str) -> list:
    return [x.strip(" .'\"") for x in re.split(r"\s*(?:,|;|\band\b)\s*", v) if x.strip(" .'\"")]


def bind_values(obj, params: list, utext: str) -> dict:
    """The model's skeleton answer -> verified bindings ({param: {literal | pattern | select}}); unverified -> dropped.
    Content parameters (body, message, subject, title, ...) keep a literal only when the user quoted it; identifier-typed
    destinations keep only identifier-looking values; "starting with X" binds the prefix pattern "X*"."""
    from .lineage import CONTENT_FIELDS, looks_like_identifier, fold
    out = {}
    if not isinstance(obj, dict):
        return out
    for p in params:
        v = obj.get(p)
        if v is None or v == "" or v == []:
            continue
        if isinstance(v, dict) and isinstance(v.get("select"), dict):
            sel = v["select"]
            by, order = sel.get("by"), str(sel.get("order", "")).lower()
            if isinstance(by, str) and by.strip() and order in ("max", "min") and _SUPERLATIVE.search(utext or ""):
                out[p] = {"select": {"by": by.strip()[:40], "order": order}}
            continue
        id_typed = bool(_ID_TYPED.match(p.lower()))
        if id_typed and isinstance(v, str) and re.search(r"[,;]|\band\b", v):
            v = _split_ids(v)                              # "a@x.com, b@y.com" is a list of two destinations
        if id_typed:
            vals = v if isinstance(v, list) else [v]
            if not all(isinstance(x, str) and looks_like_identifier(x) for x in vals):
                continue
        if isinstance(v, dict) and ("literal" in v or "pattern" in v):        # the v1 shape, used anyway
            v = v.get("literal", v.get("pattern"))
        if isinstance(v, bool):
            continue
        if isinstance(v, (int, float)):
            if _stated_by_user(f"{v:g}", utext) or _stated_by_user(str(v), utext):
                out[p] = {"literal": v}
            continue
        if isinstance(v, list):
            vals = [x for x in v if isinstance(x, (str, int, float)) and not isinstance(x, bool)]
            if vals and len(vals) == len(v) and all(_stated_by_user(str(x), utext) for x in vals):
                out[p] = {"literal": vals}
            continue
        if isinstance(v, str):
            content = p.lower() in CONTENT_FIELDS
            if re.search(r"\{[^{}]+\}", v):
                if _pattern_stated(v, utext) and (not content or _quoted_by_user(v, utext)):
                    out[p] = {"pattern": v}
            elif _stated_by_user(v, utext) and (not content or _quoted_by_user(v, utext)):
                if re.search(_PREFIX + re.escape(fold(v)), fold(utext)):
                    out[p] = {"pattern": f"{v}*"}           # "the channel starting with External" -> External*
                else:
                    out[p] = {"literal": v}
    return out


def _local_generate(utext: str, tool_specs: list[dict]) -> dict | None:
    from sentinel.core import local_judge as lj
    from ..action_policy import action_requested, capability, user_delegates, SIDE_EFFECT
    j = lj.get_local_judge()
    if j is None:
        return None
    import sentinel.config as cfg
    actions, rejected = [], {}
    crit = criterion_from_request(utext)
    necessity = bool(getattr(cfg, "L4_LOCAL_SEL_NECESSITY", False))
    with lj._lock:
        if "l4sel" not in getattr(j, "templates", {}):
            j.add_template("l4sel", SEL_SYSTEM, SEL_FMT, escape=lambda x: x)
        if necessity and "l4nec" not in getattr(j, "templates", {}):
            j.add_template("l4nec", NEC_SYSTEM, SEL_FMT, escape=lambda x: x)
        for t in tool_specs:
            if not t.get("name") or capability(t["name"]) not in SIDE_EFFECT:
                continue                                  # read-only tools are never part of a contract
            lo = float(j.read_template("l4sel", utext, _spec_line(t))["log_odds"])
            by_necessity = False
            if lo <= 0.0 and necessity:
                lo_n = float(j.read_template("l4nec", utext, _spec_line(t))["log_odds"])
                by_necessity = lo_n > 0.0                 # v10: remember which question selected the tool
                lo = max(lo, lo_n)                        # selected when either framing says yes (v8)
            if lo <= 0.0:
                rejected[t["name"]] = round(lo, 2)        # how sure the model is the user did not ask (v7)
                # A tool the model missed but the user names with a verb AND picks by a criterion ("2. Find and delete
                # the largest file" inside a multi-step request; v4) enters with ONLY its criterion binding, so the
                # target-criteria rule still checks the target. Nothing else is added on the lexicon's word alone.
                params = list(t.get("params") or [])
                target = next((p for p in params if _ID_PARAM.search(p.lower())), None)
                ok, why = action_requested(t["name"], capability(t["name"]), utext)
                # a capability VERB in the user's words ("delete", "book", "pay"), never the name-token match ("hotel"
                # appears in "recommend a hotel": travel 12, v4 regression); and the criterion MUST be verified
                if crit and target and ok and str(why).startswith("user asks for"):
                    actions.append({"tool": t["name"], "max_calls": None, "verify_criterion": True,
                                    "args": {target: {"select": {"by": crit[0], "order": crit[1]}}},
                                    "selection_log_odds": round(lo, 2), "selected_by": "lexicon+criterion"})
                continue
            params = list(t.get("params") or [])
            args = {}
            if params:
                text = j.generate(BIND_SYSTEM, f"USER REQUEST:\n<<<\n{utext}\n>>>\n\nTOOL: {_spec_line(t)}\n\nJSON:",
                                  max_new_tokens=200)
                m = re.search(r"\{.*\}", text or "", re.S)
                try:
                    obj = json.loads(m.group(0)) if m else {}
                except Exception:                                     # noqa: BLE001
                    obj = {}
                args = bind_values(obj, params, utext)
                crit = criterion_from_request(utext)
                target = next((p for p in params if _ID_PARAM.search(p.lower())), None)
                if crit and target and target not in args:
                    args[target] = {"select": {"by": crit[0], "order": crit[1]}}
            actions.append({"tool": t["name"], "max_calls": None, "args": args, "selection_log_odds": round(lo, 2),
                            **({"selected_by": "necessity"} if by_necessity else {})})
    listed = {a["tool"] for a in actions}
    return {"delegated": bool(user_delegates(utext)), "actions": actions, "constraints": [],
            "rejected": {t: v for t, v in rejected.items() if t not in listed}}


def _local_rejected(utext: str, tool_specs: list[dict], listed: set) -> dict | None:
    """Selection log-odds of the unselected side-effect tools, for a contract cached before v7 kept them. The same
    question as the selection step (template l4sel); the cached selections and bindings are not touched."""
    from sentinel.core import local_judge as lj
    from ..action_policy import capability, SIDE_EFFECT
    j = lj.get_local_judge()
    if j is None:
        return None
    out = {}
    with lj._lock:
        if "l4sel" not in getattr(j, "templates", {}):
            j.add_template("l4sel", SEL_SYSTEM, SEL_FMT, escape=lambda x: x)
        for t in tool_specs:
            if t.get("name") and t["name"] not in listed and capability(t["name"]) in SIDE_EFFECT:
                out[t["name"]] = round(float(j.read_template("l4sel", utext, _spec_line(t))["log_odds"]), 2)
    return out


async def local_contract(utext: str, tool_specs: list[dict]) -> Contract | None:
    import asyncio
    import sentinel.config as cfg
    key = local_model_key()
    k = cache_key(utext, tool_specs, key)
    hit = _load_cache().get(k)
    if hit is None:
        from sentinel.core.model_executor import run_model     # reused pool: no leaked OpenMP teams (§21.5)
        raw = await run_model(_local_generate, utext, tool_specs)
        if raw is None:
            return None
        _load_cache()[k] = {"raw": raw, "model": key, "prompt_version": "structured-v6" if "+necessity" in key else "structured-v5",
                            "user_text": utext[:4000]}
        _save_cache()
        hit = _load_cache()[k]
    elif "rejected" not in hit["raw"] and getattr(cfg, "L4_AUTHZ_LOCAL_LEAST_PRIVILEGE", False):
        # v7: a contract cached before the selection log-odds were kept gets them added (same question, same model)
        listed = {a.get("tool") for a in hit["raw"].get("actions") or [] if isinstance(a, dict)}
        from sentinel.core.model_executor import run_model
        rej = await run_model(_local_rejected, utext, tool_specs, listed)
        if rej is not None:
            hit["raw"]["rejected"] = rej
            _save_cache()
    c = parse_contract(hit["raw"], {t["name"] for t in tool_specs})
    c.source = "local"
    if getattr(cfg, "L4_LOCAL_SEL_NECESSITY", False) and getattr(cfg, "L4_LOCAL_SEL_NECESSITY_GUARD", False):
        c.necessity_only = await _necessity_only(hit, utext, tool_specs)
    return c


async def _necessity_only(hit: dict, utext: str, tool_specs: list[dict]) -> set:
    """v10: the tools of a necessity contract that the FIRST selection question did not select. A contract written
    since v10 carries the marker; for one cached before it, the shipped (first-question-only) contract of the same
    request answers without a model call; failing that, the first question is asked again for the listed tools."""
    acts = [a for a in hit["raw"].get("actions") or [] if isinstance(a, dict) and a.get("tool")]
    if any("selected_by" in a for a in acts):
        return {a["tool"] for a in acts if a.get("selected_by") == "necessity"}
    listed = {a["tool"] for a in acts}
    base = _load_cache().get(cache_key(utext, tool_specs, LOCAL_MODEL_KEY))
    if base is not None:
        base_listed = {a.get("tool") for a in base["raw"].get("actions") or [] if isinstance(a, dict)}
        return listed - base_listed
    from sentinel.core.model_executor import run_model
    lo = await run_model(_local_rejected, utext, [t for t in tool_specs if t.get("name") in listed], set())
    return {t for t, v in (lo or {}).items() if v <= 0.0}


async def model_contract(utext: str, tool_specs: list[dict]) -> Contract | None:
    """The contract of the configured source: "llm" (hosted) or "local"; None for "lexicon" or on failure."""
    import sentinel.config as cfg
    mode = str(getattr(cfg, "L4_AUTHZ_CONTRACT", "lexicon")).lower()
    if mode == "llm":
        return await llm_contract(utext, tool_specs)
    if mode == "local":
        return await local_contract(utext, tool_specs)
    return None


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
    # placeholders are {name}; the contract model also writes shell-style "*" ("External*"): both mean "some text"
    parts = re.split(r"\{[^{}]*\}|\*", pat)
    rx = ".+?".join(re.escape(fold(p)) for p in parts)
    return all(re.fullmatch(rx, fold(v), re.S) is not None for v in vals)
