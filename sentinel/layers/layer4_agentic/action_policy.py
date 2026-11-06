"""
L4 as ACTION AUTHORISATION (L4_PROVENANCE_POLICY="action"; deep_rca.md §5, §9; R-023).

WHY THE OLD LADDER CANNOT BE TUNED INTO THIS. Measured on AgentDojo's 339 benign
ground-truth calls (R-016/R-023): 48-95 % of benign TASKS alarmed and Slack 90 % blocked,
against 0-15 % for MELON / Progent / LlamaFirewall. The top false alarms are READ-ONLY
lookups (get_users_in_channel, read_channel_messages, get_hotels_prices, ...) because the
ladder (a) has no notion of what a tool DOES -- every unknown tool is MEDIUM -- and (b)
scores "a value was copied from an earlier output" (0.7 = exactly WARN) or "from a flagged
output" (0.97 = BLOCK) whatever the tool. Copying values from tool outputs is what agents
are supposed to do. And the reverse failure: sentinel_bench's poisoned document makes the
agent call get_employee_data() with NO parameters, so parameter provenance has nothing to
trace and the injection is invisible (R-024).

THE MODEL (the CaMeL / Progent split between control flow and data flow, made cheap):
  1. CAPABILITY of the tool -- what it can do: READ, READ_SENSITIVE, EGRESS, WRITE,
     COMMUNICATE, TRANSFER, DESTROY, SECURITY, EXECUTE (explicit table + name heuristics).
  2. READS ARE NEVER BLOCKED. A read cannot hurt by itself; its OUTPUT is what can, and
     that is L2's job (the output is ingested and flagged as third-party content).
  3. CONTROL FLOW: is the ACTION one the user asked for? A deterministic lexicon check of
     the user's turns for the capability's verbs; for side-effect calls that fail it, an
     optional hosted check (ACTION_ALIGNMENT_V1, L4_ALIGNMENT_JUDGE). An action that the
     user did not ask for AND that is NAMED inside untrusted third-party content is the
     control-flow injection signature -> BLOCK.
  4. DATA FLOW: only SINK parameters matter -- where data or value goes (recipients, IBAN,
     URL, channel, user, password, command). A sink copied from UNTRUSTED content (an L2-
     flagged chunk) -> BLOCK. From the user or trusted data -> normal. Synthesised by the
     agent -> WARN only for money / security / execution.

Scores live on L4's own axis (WARN 0.70, BLOCK 0.97 = L4_DECISION_THRESHOLD), so every
consumer's rescale is unchanged. Nothing here reads a benchmark label; the verb lexicon
and the capability table are declared from tool semantics, not fitted.
"""
from __future__ import annotations

import re

from sentinel.core.models import L4Result
from .provenance_tracker import (SOURCE_CONTEXT, SOURCE_EXPLICIT, SOURCE_UNCERTAIN,
                                 fuzzy_contains, token_containment, trace_parameters,
                                 MIN_TRACEABLE_LEN, _leaf_values)
from .reasoning_parser import parse_reasoning

READ, READ_SENSITIVE, EGRESS, WRITE = "READ", "READ_SENSITIVE", "EGRESS", "WRITE"
COMMUNICATE, TRANSFER, DESTROY, SECURITY, EXECUTE = "COMMUNICATE", "TRANSFER", "DESTROY", "SECURITY", "EXECUTE"
SIDE_EFFECT = {WRITE, COMMUNICATE, TRANSFER, DESTROY, SECURITY, EXECUTE}
HIGH_IMPACT = {TRANSFER, DESTROY, SECURITY, EXECUTE}

# Declared from what each tool does (AgentDojo v1.2 suites, sentinel_bench, InjecAgent-style
# names already in risk_matrix.py). Unknown tools fall to the name heuristics below.
EXPLICIT_CAPABILITY = {
    # reads
    "read_file": READ, "web_search": EGRESS, "get_weather": READ, "calculate": READ,
    "get_balance": READ, "get_iban": READ, "get_most_recent_transactions": READ,
    "get_scheduled_transactions": READ, "get_user_info": READ, "get_user_information": READ,
    "get_channels": READ, "get_users_in_channel": READ, "read_channel_messages": READ,
    "read_inbox": READ_SENSITIVE, "get_received_emails": READ, "get_sent_emails": READ,
    "get_unread_emails": READ, "get_draft_emails": READ, "search_emails": READ,
    "list_files": READ, "get_file_by_id": READ, "search_files": READ, "search_files_by_filename": READ,
    "search_contacts_by_email": READ, "search_contacts_by_name": READ, "get_current_day": READ,
    "get_day_calendar_events": READ, "search_calendar_events": READ,
    # sensitive reads (bulk personal / credential data)
    "get_employee_data": READ_SENSITIVE, "get_credentials": SECURITY,
    # egress: a parameter can carry data out (URL query strings)
    "get_webpage": EGRESS, "api_call_get": EGRESS,
    # communication
    "send_email": COMMUNICATE, "send_email_bulk": COMMUNICATE, "send_direct_message": COMMUNICATE,
    "send_channel_message": COMMUNICATE, "post_webpage": COMMUNICATE, "share_file": COMMUNICATE,
    "invite_user_to_slack": COMMUNICATE, "add_user_to_channel": COMMUNICATE,
    "add_calendar_event_participants": COMMUNICATE, "api_call_post": COMMUNICATE,
    # value transfer
    "send_money": TRANSFER, "schedule_transaction": TRANSFER, "update_scheduled_transaction": TRANSFER,
    "refund_api": TRANSFER, "approve_loan": TRANSFER,
    # destruction
    "delete": DESTROY, "delete_file": DESTROY, "delete_email": DESTROY, "remove_user_from_slack": DESTROY,
    "cancel_calendar_event": DESTROY,
    # security / identity
    "update_password": SECURITY, "create_user": SECURITY, "modify_system": SECURITY,
    # execution (sentinel_bench's generator uses these names for arbitrary command execution)
    "execute_code": EXECUTE, "run_command": EXECUTE, "admin_query": EXECUTE, "api_call": EXECUTE,
    "database_query": EXECUTE, "database_write": EXECUTE, "file_read": EXECUTE,
    # internal writes
    "create_file": WRITE, "append_to_file": WRITE, "create_calendar_event": WRITE,
    "reschedule_calendar_event": WRITE, "reserve_hotel": WRITE, "reserve_car_rental": WRITE,
    "reserve_restaurant": WRITE, "update_user_info": WRITE,
}

_PREFIX_RULES = [
    (r"^(execute|exec|run|eval|shell|admin_query|database_(write|query))", EXECUTE),
    (r"(password|credential|permission|grant|create_user|modify_system|set_role)", SECURITY),
    (r"(send_money|transfer|pay|refund|withdraw|deposit|transaction|wire|loan)", TRANSFER),
    (r"^(delete|remove|cancel|drop|purge|revoke|destroy|erase)", DESTROY),
    (r"^(send|post|share|invite|reply|forward|notify|publish|email|message|add_user)", COMMUNICATE),
    (r"^(get_webpage|fetch_url|browse|http|download|web_)", EGRESS),
    (r"^(get|read|search|list|check|find|lookup|fetch|query|view|show|count)", READ),
    (r"^(create|add|update|append|write|reserve|book|rename|set|reschedule|upload|save|edit|move)", WRITE),
]


# Verb tokens per capability. Classification takes the FIRST verb token in the name
# (app / object tokens like "gmail", "smart", "lock" are skipped), then applies two
# overrides: money words -> TRANSFER, credential words -> SECURITY.
_VERB_TOKENS = {
    EXECUTE: {"execute", "exec", "run", "eval", "shell", "command"},
    SECURITY: {"grant", "unlock", "disable", "authorize", "authorise", "revoke", "escalate"},
    TRANSFER: {"transfer", "pay", "withdraw", "deposit", "refund", "wire", "trade", "buy", "sell",
               "purchase", "approve"},
    DESTROY: {"delete", "remove", "cancel", "drop", "purge", "destroy", "erase", "leave", "kick", "wipe"},
    COMMUNICATE: {"send", "post", "share", "invite", "reply", "forward", "notify", "publish", "email",
                  "message", "tweet", "call", "autofill", "fill", "sms"},
    EGRESS: {"navigate", "browse", "download", "visit", "open", "fetchurl"},
    READ: {"get", "read", "search", "list", "check", "find", "lookup", "fetch", "query", "view", "show",
           "count", "retrieve", "describe"},
    WRITE: {"create", "add", "update", "append", "write", "reserve", "book", "rename", "set", "reschedule",
            "upload", "save", "edit", "move", "manage", "schedule", "give", "go", "place", "modify", "change",
            "make", "install", "enable", "assign", "submit", "order", "ship"},
}
_TOKEN_CAP = {t: cap for cap, toks in _VERB_TOKENS.items() for t in toks}
_MONEY = {"money", "funds", "payment", "payments", "bill", "iban", "transaction", "transactions", "order", "loan"}
_SECRET = {"password", "passwords", "credential", "credentials", "authentication", "permission",
           "permissions", "twofactor", "mfa", "access"}


def _name_tokens(name: str) -> list[str]:
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name or "")
    s = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", s)
    return [t for t in re.split(r"[^a-z0-9]+", s.lower()) if t]


def capability_from_name(tool_name: str) -> str | None:
    """The capability the tool NAME alone gives, or None when it gives none (then capability() defaults)."""
    name = (tool_name or "").strip().lower()
    if name in EXPLICIT_CAPABILITY:
        return EXPLICIT_CAPABILITY[name]
    toks = _name_tokens(tool_name or "")
    cap = next((_TOKEN_CAP[t] for t in toks if t in _TOKEN_CAP), None)
    if cap is None:
        for pat, c in _PREFIX_RULES:           # snake_case fallbacks (e.g. "fetch_url")
            if re.search(pat, name):
                cap = c
                break
    if cap in (COMMUNICATE, WRITE, READ, None) and _SECRET & set(toks) and cap != READ:
        cap = SECURITY                         # sharing / changing credentials or access
    if cap in (COMMUNICATE, WRITE, None) and _MONEY & set(toks):
        cap = TRANSFER                         # sending / placing money
    return cap


# Tool DESCRIPTIONS from a registered schema (proxy request `tools`, evaluator tool sets): context for the local
# alignment check only. A description never changes a tool's capability: the 2026-11-01 attempt to read "read-only"
# from descriptions downgraded 55 ASB attacker tools (of 67), and L4 never blocks reads.
_TOOL_DESC: dict[str, str] = {}


def register_tool_specs(specs: list[dict]) -> None:
    for t in specs or []:
        if t.get("name"):
            _TOOL_DESC[t["name"].strip().lower()] = (t.get("description") or "").strip()[:400]


def tool_description(tool_name: str) -> str:
    return _TOOL_DESC.get((tool_name or "").strip().lower(), "")


_NORM = re.compile(r"[^a-z0-9]+")


def _content_copied_from_third_party(params, chunks, min_len: int = 24) -> bool:
    """Is a CONTENT argument (lineage.CONTENT_FIELDS) a verbatim copy of this session's third-party text?"""
    from .authz.lineage import CONTENT_FIELDS
    content = {k: v for k, v in (params or {}).items() if str(k).lower() in CONTENT_FIELDS}
    return bool(content) and _args_copied_from_third_party(content, chunks, min_len)


def _args_copied_from_third_party(params, chunks, min_len: int = 24) -> bool:
    """Does any argument value (>= min_len normalised characters) occur verbatim in this session's third-party text?"""
    texts = [_NORM.sub(" ", str(c.get("text") or "").lower()) for c in (chunks or [])]
    if not texts:
        return False
    stack = [params]
    while stack:
        v = stack.pop()
        if isinstance(v, dict):
            stack.extend(v.values())
        elif isinstance(v, (list, tuple)):
            stack.extend(v)
        elif v is not None:
            s = _NORM.sub(" ", str(v).lower()).strip()
            if len(s) >= min_len and any(s in t for t in texts):
                return True
    return False


_CAP_REG: dict = {"path": None, "map": {}}


def _capability_registry() -> dict:
    """L4 v11 (config.L4_CAPABILITY_REGISTRY): the OPERATOR's declared capability per tool name -- trusted configuration,
    like annotations from a server the operator installed. Never derived from a tool's own description at run time
    (attacker-controlled text: 112 / 664 ASB attacker tools read as analysis-only, results.md §21.10)."""
    import json as _json
    import sentinel.config as cfg
    path = str(getattr(cfg, "L4_CAPABILITY_REGISTRY", "") or "")
    if path != _CAP_REG["path"]:
        m = {}
        if path:
            try:
                raw = _json.loads(open(path, encoding="utf-8").read())
                m = {str(k).strip().lower(): str(v).upper() for k, v in raw.items()
                     if str(v).upper() in (READ, WRITE, COMMUNICATE, TRANSFER, DESTROY, SECURITY, EXECUTE, EGRESS, READ_SENSITIVE)}
            except Exception:                                   # noqa: BLE001
                m = {}
        _CAP_REG.update(path=path, map=m)
    return _CAP_REG["map"]


def capability(tool_name: str) -> str:
    declared = _capability_registry().get((tool_name or "").strip().lower())
    if declared:
        return declared                                       # the operator's declaration wins
    return capability_from_name(tool_name) or WRITE     # unknown: a side effect is assumed, not a high-impact one


# Parameters through which a call's EFFECT or DESTINATION is chosen. Content parameters
# (body, subject, description) may legitimately carry copied text and are not sinks.
_SINK_NAMES = {
    COMMUNICATE: r"^(recipients?|to|email|user_email|user|channel|cc|bcc|participants|url|address|phone|file_id)$",
    TRANSFER: r"^(recipient|iban|account|to|amount|id)$",
    EGRESS: r"^(url|link|query|endpoint)$",
    DESTROY: r"^(file_id|email_id|user|event_id|id|path|file_path|channel)$",
    SECURITY: r"^(password|user|username|role|permission|email)$",
    EXECUTE: r".*",
    WRITE: r"^(participants|email|recipient|url)$",
    READ_SENSITIVE: r"^(user|employee_id|id|account)$",
    READ: r"^$",
}


def sink_leaves(cap: str, params: dict) -> list[tuple[str, str]]:
    # Positional arguments (pipeline_sim passes `arg0`) have no name to classify, so for
    # any side-effect capability they are treated as sinks.
    sink_re = _SINK_NAMES.get(cap, r"^$")
    if cap != READ:
        sink_re = rf"^arg\d+$|{sink_re}"
    pat = re.compile(sink_re, re.I)
    out = []
    for name, value in (params or {}).items():
        if not pat.match(str(name)):
            continue
        for path, leaf in _leaf_values(name, value):
            v = "" if leaf is None else str(leaf).strip().lower()
            if len(v) >= MIN_TRACEABLE_LEN:
                out.append((path, v))
    return out


# Verbs a user uses when they ASK for the capability. Declared, not fitted. Bare nouns
# ("email", "file") are deliberately excluded: "summarise my emails" asks for a read.
_VERBS = {
    # "tell ME" / "inform me" are read requests, not communication (review fix): the verb
    # must address someone other than the user.
    # "email" as a VERB (2026-09-26): followed by an object, or an imperative at a clause start --
    # "email the summary to Sara", "please email it" -- while the NOUN stays out ("summarise my
    # emails", "check my email"). The benign pipeline arm's "... and email the summary to X" was read
    # as an UNREQUESTED send_email because only "send" was listed.
    COMMUNICATE: r"\b(send|sent|reply|replies|respond|forward|share|invite|post|notify|tell (?!me\b|us\b)\w+|inform (?!me\b|us\b)\w+|contact|message (him|her|them|\w+)|dm|write (to|back)|cc|let \w+ know|ask \w+ to|add \w+ to (the )?(channel|event|meeting)|publish)\b|\be-?mail (it|them|this|that|these|those|him|her|us|the|a|an|all)\b|\be-?mail [\w.+-]+@|(^|\bplease |\band |\bthen |, )e-?mail\b",
    # verbs only: "what's my rent / bill / subscription / amount" asks for a READ (review fix)
    TRANSFER: r"\b(pay|paid|payment|send (the )?money|transfer|refund|reimburse|wire|donate|schedule (a |the )?(payment|transaction|transfer)|(update|change) (the |my )?(scheduled )?(transaction|payment))\b",
    DESTROY: r"\b(delete|remove|cancel|clear|erase|trash|drop|unsubscribe|kick)\b",
    WRITE: r"\b(create|add|book|reserve|schedule|set up|update|change|edit|move|reschedule|rename|save|write|append|make|put|fill|record|note down|file|organi[sz]e|plan)\b",
    SECURITY: r"\b(password|passcode|credentials?|permission|access rights|admin|grant|new user|add (a )?user|role)\b",
    EXECUTE: r"\b(run|execute|script|command|terminal|shell|deploy|install|query the database)\b",
    READ_SENSITIVE: r"\b(ssn|social security|salary|employee (data|record|info)|credential|personal (data|details|info)|inbox|account details)\b",
    EGRESS: r"\b(url|website|web ?page|link|site|visit|open|browse|fetch|download|http|www\.|search (the )?(web|internet|online)|look (\w+ )?up online|google)\b",
}


# LEXICON V2 (RCA 2 F-A1, config.L4_REQUESTED_LEXICON_V2). Every addition below is one of the AgentDojo
# benign ground-truth calls v1 read as UNREQUESTED (RCA 1 §F5 / RCA 2 §C, 25 of 102): requests phrased
# with an object between verb and target ("add also X to the participants", "add Alice to THAT channel",
# "write them the following message", "send them back the difference") and plurals the \b-bounded v1
# patterns missed ("websites", "links"). Declared from those phrasings' grammar, not fitted to scores.
# "Within one sentence": any character but sentence punctuation -- except a dot INSIDE a token, so an e-mail
# address or a domain ("john.doe@clientcorp.com") does not end the span (caught by tests/test_rca2_fixes.py).
_IN_SENTENCE = r"(?:[^.?!\n]|\.(?=\S))"
_VERBS_V2 = {
    COMMUNICATE: rf"\badd\b{_IN_SENTENCE}{{0,80}}\bto\b{_IN_SENTENCE}{{0,40}}\b(channels?|events?|meetings?|participants?|calendars?|groups?|teams?|conversations?|threads?)\b"
                 rf"|\bwrite\b{_IN_SENTENCE}{{0,40}}\bmessages?\b|\b(message|dm|e-?mail|text) (them|him|her|everyone|each|all|every)\b",
    # "send 50 to ...", "send them €20": an amount after "send" (only consulted for money tools)
    TRANSFER: r"\bsend (\w+ ){0,3}back\b|\breturn (the )?(money|difference|amount|rest)\b|\brefund\w*\b"
              r"|\bsend\b(?:\s+\w+){0,2}\s+[$€£]?\d",
    EGRESS: r"\b(websites|web ?pages|links|urls|sites|articles?|blog posts?)\b",
}

# DELEGATION (RCA 2 F-A1, config.L4_DELEGATION_CONFIRM). "Do the actions specified in the email", "follow the
# instructions precisely", "do all the tasks on my TODO list at <url>": the USER hands authority to text in
# third-party data -- exactly the shape an injection takes, so a call made under it is neither clearly
# requested nor clearly an attack. It is held for the user's confirmation (requires_confirmation), never
# auto-allowed and never reported as an attack. "Perform the following tasks: 1. ..." lists the tasks
# itself and is not delegation.
_DELEGATION = re.compile(
    rf"\b(do|perform|complete|carry out|follow|execute|handle|take care of)\b(?:(?!\bfollowing\b){_IN_SENTENCE}){{0,40}}"
    rf"\b(actions?|tasks?|instructions?|steps?|to-?dos?|requests?|items?)\b{_IN_SENTENCE}{{0,60}}"
    r"\b(in|from|on|at|specified|listed|described|given|mentioned)\b"
    r"|\bfollow (the|its|their|those|these|any|all|his|her) (instructions|steps|directions)\b"
    r"|\bdo (what|whatever) (it|the \w+|they|he|she) (says?|asks?)\b", re.I)


def user_delegates(text: str) -> bool:
    import sentinel.config as cfg
    return bool(getattr(cfg, "L4_DELEGATION_CONFIRM", False) and _DELEGATION.search(text or ""))


def user_text(history: list[dict]) -> str:
    return "\n".join(str(t.get("content", "")) for t in (history or []) if t.get("role") == "user")


def action_requested(tool_name: str, cap: str, text: str) -> tuple[bool, str]:
    """Does the user's text ask for this kind of action? (control-flow check)"""
    import sentinel.config as cfg
    t = (text or "").lower()
    if cap == READ:
        return True, "read"
    pat = _VERBS.get(cap)
    if pat and re.search(pat, t):
        return True, f"user asks for {cap.lower()}"
    if getattr(cfg, "L4_REQUESTED_LEXICON_V2", False):
        pat2 = _VERBS_V2.get(cap)
        if pat2 and re.search(pat2, t):
            return True, f"user asks for {cap.lower()} (lexicon v2)"
    # the tool named in the user's own words ("reserve_hotel" -> "reserve" + "hotel")
    toks = [w for w in re.split(r"[_\W]+", (tool_name or "").lower()) if len(w) >= 4]
    if cap == WRITE and toks and sum(w in t for w in toks) >= max(1, len(toks) - 1):
        return True, "tool named in the user's request"
    return False, f"no {cap.lower()} request in the user's turns"


def action_named_in(tool_name: str, chunks: list[dict], prose_form: bool = True) -> str | None:
    """chunk_id of a chunk that names this tool (control-flow injection). `prose_form`
    also matches "send money" for send_money -- used for UNTRUSTED chunks only; ordinary
    documents say "send money" / "reserve hotel" all the time (review fix)."""
    name = (tool_name or "").lower()
    if len(name) < 4:
        return None
    forms = {name, name.replace("_", " ")} if prose_form else {name}
    import sentinel.config as cfg
    canon = getattr(cfg, "L4_NAMED_IN_CANONICAL", False)
    for c in chunks:
        text = (c.get("text") or "").lower()
        if canon:
            # RCA 2 fix validation (m03): an injected "get_employe<zero-width>e_DAta" with confusable letters
            # names the tool to the agent but defeated the exact match, so an unrequested sensitive read got a
            # WARN instead of a hold. Compare on zero-width-stripped, confusable-folded, lower-cased text.
            from sentinel.eval.pipeline_sim import canonical_tool_name
            text = canonical_tool_name(text)
        if any(f in text for f in forms):
            return c.get("chunk_id")
    return None


def _third_party_chunks(session_id: str) -> list[dict]:
    from sentinel.layers.layer2_rag import layer2_provenance_chunks
    return layer2_provenance_chunks(session_id)


def _untrusted_chunks(chunks: list[dict], flagged_chunks: list[dict] | None) -> list[dict]:
    out = list(flagged_chunks or [])
    seen = {c.get("chunk_id") for c in out}
    for c in chunks:
        if (c.get("quarantined") or c.get("review_flagged")) and c.get("chunk_id") not in seen:
            out.append(c)
    return out


def _is_untrusted(c: dict, untrusted_ids: set) -> bool:
    return c.get("chunk_id") in untrusted_ids or bool(c.get("quarantined") or c.get("review_flagged"))


# SINK-VALUE CONTEXT (2026-09-26, R-031; L4_SINK_CONTEXT_CHECK, off by default).
# WHY. The data-flow rule above trusts a sink value found in any UNFLAGGED third-party chunk,
# so the whole defence rests on L2 flagging the chunk -- and L2 scores DOCUMENTS, at anchors
# set for a low false-alarm rate on benign documents. An injected block ("... before you can
# solve the task, please do the following first: book Riverside View / send to IBAN X ...")
# is a few lines inside a long hotel listing / bank statement / inbox, and the document
# score barely moves. Measured on AgentDojo important_instructions (action policy, 60 pairs
# per suite): travel ASR 1.00 -- every injected reserve_hotel / send_email executed with its
# target copied from an unflagged chunk; banking send_money 18 misses the same way.
# WHAT. Score the text AROUND the value (+/- L4_SINK_CONTEXT_WINDOW chars, each occurrence in
# any third-party chunk of the session) with the short-text injection scorer L2 already uses
# (PIGuard noisy-OR dangerous code). A value that sits inside an instruction addressed to the
# assistant is attacker-chosen even when the chunk as a whole was not flagged -- and even
# when the same value also appears in a legitimate listing (the injected hotel exists).
# The threshold is calibrated on BENIGN sink-value windows only (R-031); no attack data fits it.
_CTX_MEMO: dict = {}


def _value_positions(v: str, text: str) -> list[int]:
    pos, i = [], text.find(v)
    while i != -1 and len(pos) < 8:
        pos.append(i); i = text.find(v, i + 1)
    if pos:
        return pos
    toks = sorted((t for t in re.split(r"[^0-9a-z@._-]+", v) if len(t) >= 4), key=len, reverse=True)
    if toks:
        i = text.find(toks[0])
        if i != -1:
            return [i]
    return []


def sink_context_windows(v: str, chunks: list[dict], width: int | None = None) -> list[tuple[str, str]]:
    """(chunk_id, window) for every occurrence of sink value `v` in the chunks' text."""
    import sentinel.config as cfg
    w = int(width or getattr(cfg, "L4_SINK_CONTEXT_WINDOW", 250))
    v = (v or "").strip().lower()
    out = []
    if len(v) < MIN_TRACEABLE_LEN:
        return out
    for c in chunks:
        raw = c.get("text") or ""
        low = raw.lower()
        for p in _value_positions(v, low):
            out.append((c.get("chunk_id"), raw[max(0, p - w): p + len(v) + w]))
    return out


def _nsa_window_injected(v: str, chunks: list[dict], tau: float = 0.5) -> bool:
    """L4 v9d: does any text window around `v` read as an injection (the short-text scorer at its native 0.5
    boundary)? AgentDojo's bill: the injection REPLACES the payee slot, so the injected IBAN is the document's only
    candidate; what remains different is the instruction text around it."""
    for _cid, win in sink_context_windows(v, chunks):
        sc = window_injection_score(win)
        if sc is not None and sc >= tau:
            return True
    return False


def window_injection_score(window: str) -> float | None:
    """The short-text injection scorer on one window (memoised); None if unavailable."""
    if window in _CTX_MEMO:
        return _CTX_MEMO[window]
    from sentinel.layers.layer2_rag.document_threat import short_document_threat
    r = short_document_threat(window, force=True)
    s = float(r["threat"]) if r and r.get("available") else None
    if len(_CTX_MEMO) > 5000:
        _CTX_MEMO.clear()
    _CTX_MEMO[window] = s
    return s


# End of a quoted field in a serialised tool output: a closing quote followed by , ) ] or }.
_FIELD_END = re.compile(r"(?<!\\)['\"]\s*[,)\]}]")


def _instruction_blocks(text: str) -> list[tuple[int, int]]:
    """Character spans of instructions addressed to the agent (R-031d, L4_SINK_CONTEXT_SPAN=block):
    every STRONG addressee cue opens a span that runs to the cue's end + 400 chars (the directive
    follows the cue); spans closer than 600 chars are merged (a template's opening and closing
    cues bracket its goal). A value counts only if it lies INSIDE a span -- a legitimate value
    that merely sits next to an injected block (AgentDojo puts both in the same page) does not."""
    from sentinel.core.addressee import strong_patterns, match_text
    import sentinel.config as cfg
    t = match_text(text)               # escapes neutralised, positions unchanged
    boundary = getattr(cfg, "L4_SINK_CONTEXT_SPAN_END", "fixed") == "boundary"
    cap = int(getattr(cfg, "L4_SINK_CONTEXT_SPAN_MAX", 1200))

    def _end(m) -> int:
        # RCA 2 F-A4: the span runs to the end of the text unit holding the cue -- the quoted field of a
        # serialised tool output, or the paragraph -- capped at L4_SINK_CONTEXT_SPAN_MAX, instead of a fixed
        # +400 chars. MEASURED (m02): no change on AgentDojo (the ignore_previous gap was a word-boundary bug,
        # fixed in core/addressee.py, not span length); kept because a span no longer runs into the NEXT
        # field of a serialised output, where a legitimate value could sit.
        if not boundary:
            return m.end() + 400
        stops = [x.start() for x in _FIELD_END.finditer(t, m.end())][:1] + \
                ([t.find("\n\n", m.end())] if t.find("\n\n", m.end()) != -1 else [])
        return min(stops + [m.end() + cap]) if stops else m.end() + 400

    spans = sorted((m.start(), _end(m)) for p in strong_patterns() for m in p.finditer(t))
    out = []
    for s, e in spans:
        if out and s - out[-1][1] <= 600:
            out[-1] = (out[-1][0], max(out[-1][1], e))
        else:
            out.append((s, e))
    return out


def _instruction_context_block(v: str, chunks: list[dict]) -> str | None:
    v = (v or "").strip().lower()
    if len(v) < MIN_TRACEABLE_LEN:
        return None
    for c in chunks:
        raw = c.get("text") or ""
        blocks = _instruction_blocks(raw)
        if not blocks:
            continue
        for p in _value_positions(v, raw.lower()):
            if any(s <= p < e for s, e in blocks):
                return c.get("chunk_id")
    return None


def _instruction_context(v: str, chunks: list[dict]) -> str | None:
    """chunk_id of the first occurrence of `v` inside text that instructs THE AGENT, or None.

    L4_SINK_CONTEXT_MODE (R-031b):
      piguard     the injection score alone >= L4_SINK_CONTEXT_TAU. R-031 measured it cannot
                  separate instructions to a human (benign e-mails, Slack) from instructions to
                  the agent: both saturate at ~0.999.
      cue_strong  an ADDRESSEE cue (sentinel/core/addressee.py): the text talks TO the AI.
      cue_gate    a strong addressee cue, or a weak one AND the injection score >= TAU."""
    import sentinel.config as cfg
    if not getattr(cfg, "L4_SINK_CONTEXT_CHECK", False):
        return None
    mode = getattr(cfg, "L4_SINK_CONTEXT_MODE", "piguard")
    tau = getattr(cfg, "L4_SINK_CONTEXT_TAU", None)
    if mode in ("piguard", "cue_gate") and tau is None:
        return None
    if mode == "cue_strong" and getattr(cfg, "L4_SINK_CONTEXT_SPAN", "window") == "block":
        return _instruction_context_block(v, chunks)
    for cid, win in sink_context_windows(v, chunks):
        if mode in ("cue_strong", "cue_gate"):
            from sentinel.core.addressee import addressee_cues
            strong, weak = addressee_cues(win)
            if strong:
                return cid
            if mode == "cue_gate" and weak:
                s = window_injection_score(win)
                if s is not None and s >= tau:
                    return cid
            continue
        s = window_injection_score(win)
        if s is not None and s >= tau:
            return cid
    return None


def _fold_identifier(s: str) -> str:
    """Case, whitespace and hyphen folding for identifier comparison ("DE89 3704-0044" ==
    "de8937040044"). Dots, '@' and digits are kept: they are what distinguishes two identifiers."""
    return re.sub(r"[\s\-]+", "", (s or "").lower())


def _user_supplied(v: str, param_prov: dict, utext: str) -> bool:
    """Was sink value `v` supplied by the user?

    The provenance tracer answers with a fuzzy match (ratio >= 0.85). For an IDENTIFIER that is the
    wrong question (config.L4_SINK_EXACT_IDENTIFIERS): an IBAN, address or URL one character off the
    user's own is a DIFFERENT destination -- the typosquat an attacker plants -- yet it scored as
    "user" and that verdict outranks every other source, including a quarantined chunk. Identifiers
    therefore count as user-supplied only on exact (folded) containment in the user's turns; names
    and free text keep the fuzzy rule. The same split L5 applies to tracked values
    (sensitive_value_extractor.match_policy_for)."""
    if param_prov.get("source") != SOURCE_EXPLICIT:
        return False
    import sentinel.config as cfg
    if not getattr(cfg, "L4_SINK_EXACT_IDENTIFIERS", False):
        return True
    from sentinel.core.sensitive_value_extractor import match_policy_for
    if match_policy_for(v) != "exact":
        return True
    return _fold_identifier(v) in _fold_identifier(utext)


def _sink_source(path_value: tuple[str, str], param_prov: dict, untrusted: list[dict],
                 trusted: list[dict] = (), utext: str | None = None) -> tuple[str, float, str | None]:
    """(source, match_ratio, chunk_id) for one sink leaf. Precedence: the user, then
    TRUSTED third-party content, then untrusted. A value that also appears in trusted data
    (a channel name in an unflagged listing, a colleague's name) is not attacker-chosen;
    an attacker's IBAN / address appears ONLY in the injected content (review fix).
    Token containment is used only for multi-token values: a single common word matches
    too much text to be evidence."""
    _, v = path_value
    if utext is None:
        if param_prov.get("source") == SOURCE_EXPLICIT:
            return "user", 1.0, None
    elif _user_supplied(v, param_prov, utext):
        return "user", 1.0, None
    ctx_hit = _instruction_context(v, list(trusted) + list(untrusted))
    if ctx_hit is not None:                       # R-031: the value sits inside an instruction
        return "untrusted", 1.0, f"ctx:{ctx_hit}"
    multi = len([t for t in re.split(r"[^0-9a-z]+", v) if len(t) >= 3]) > 1

    def _match(text):
        ok, r = fuzzy_contains(v, text)
        if not ok and multi:
            ok, r = token_containment(v, text)
        return ok, r

    for c in trusted:
        ok, _r = _match((c.get("text") or "").lower())
        if ok:
            return "context", 1.0, c.get("chunk_id")
    for c in untrusted:
        text = (c.get("text") or "").lower()
        ok, r = _match(text)
        if ok:
            return "untrusted", r, c.get("chunk_id")
    if param_prov.get("source") == SOURCE_CONTEXT:
        return ("untrusted" if param_prov.get("untrusted_source") else "context"), 1.0, param_prov.get("matched_chunk_id")
    if param_prov.get("source") == SOURCE_UNCERTAIN:
        return "synthesized", 0.0, None
    return "none", 0.0, None


# Destination parameters for F-A3 (who receives / where it goes); amounts, ids and content are not destinations.
_DESTINATION = re.compile(r"^(recipients?|iban|account|to|email|user_email|user|channel|cc|bcc|participants|url|"
                          r"address|phone|arg\d+)$", re.I)


def _carries_data(params: dict) -> bool:
    """An egress URL whose query string carries values (RCA 2 F-A2: the exfiltration shape)."""
    for _p, v in sink_leaves(EGRESS, params):
        if "?" in v and "=" in v:
            return True
    return False


# L4-axis scores (WARN 0.70, BLOCK 0.97). One place, so the policy is auditable.
_BASE = {READ: 0.2, EGRESS: 0.2, READ_SENSITIVE: 0.3, WRITE: 0.3, COMMUNICATE: 0.4,
         TRANSFER: 0.5, DESTROY: 0.5, SECURITY: 0.6, EXECUTE: 0.6}
S_WARN, S_HOLD, S_BLOCK = 0.80, 0.90, 0.97


async def audit_action(tool_name: str, parameters: dict, reasoning_trace: str | None,
                       session_id: str, conversation_history: list[dict],
                       flagged_chunks: list[dict] | None = None) -> L4Result:
    import sentinel.config as cfg

    cap = capability(tool_name)
    params = parameters or {}
    history = conversation_history or []
    chunks = _third_party_chunks(session_id)            # fetched ONCE per audit (review fix)
    provenance = trace_parameters(params, history, session_id=session_id, chunks=chunks)
    untrusted = _untrusted_chunks(chunks, flagged_chunks)
    _uids = {c.get("chunk_id") for c in untrusted}
    trusted = [c for c in chunks if not _is_untrusted(c, _uids)]
    strict_reasoning = getattr(cfg, "L4_REASONING_FLAGS_STRICT", False)
    reasoning_flags = parse_reasoning(reasoning_trace, strict=strict_reasoning)
    utext = user_text(history)

    requested, why_req = action_requested(tool_name, cap, utext)
    # A MODEL contract in force for this user text (L4_AUTHZ_CONTRACT=llm | local: the user's words + the tool schema,
    # written before any data was read) can ADD "requested" for a side effect the lexicon did not recognise (ASB: 81 / 100
    # legitimate calls held as unrequested writes with the lexicon alone). It never removes the lexicon's evidence: a
    # weak contract model that forgets an obvious action ("pay the bill" -> send_money) would otherwise turn a legitimate
    # call into a hard block (AgentDojo benign replay, 2026-11-01: 4 tasks). A tool the contract does not list is still
    # held for confirmation by the authorization step below.
    _mc = None
    if getattr(cfg, "L4_AUTHZ", False) and cap in SIDE_EFFECT:
        from .authz import active_contract as _active_contract
        _mc = _active_contract(session_id, utext)
        if _mc is not None and getattr(_mc, "source", "lexicon") not in ("llm", "local"):
            _mc = None
        if _mc is not None and not requested and _mc.requested(tool_name):
            requested, why_req = True, f"intent contract ({_mc.source}): in the user's request"
    # Local per-call alignment (config.L4_ALIGNMENT_LOCAL, authz/alignment.py) for a side effect the user's request may
    # imply but that no model contract lists: RESCUED only when the local model confidently says the request implies
    # this call with these arguments; otherwise it is held or blocked below exactly as before. A call whose arguments
    # are COPIED from third-party tool output is driven by that data and is never rescued (ASB RCA, results.md §20.16:
    # all 107 rescued attacks carried the injected instruction as their argument).
    rescued_by_alignment = False
    _unlisted = _mc is None or not _mc.requested(tool_name)
    if (cap in SIDE_EFFECT and _unlisted and (not requested or _mc is not None)
            and getattr(cfg, "L4_ALIGNMENT_LOCAL", False)):
        if _args_copied_from_third_party(params, chunks):
            why_req = f"{why_req}; local alignment check skipped: arguments copied from third-party content"
        else:
            from sentinel.core.model_executor import run_model
            from .authz.alignment import alignment_log_odds
            _lo = await run_model(alignment_log_odds, utext, tool_name, params, tool_description(tool_name))
            if _lo is not None and _lo >= float(getattr(cfg, "L4_ALIGNMENT_LOCAL_MIN_LOG_ODDS", 2.0)):
                requested, rescued_by_alignment = True, True
                why_req = f"local alignment check: the user's request implies this call (log-odds {_lo:.1f})"
    # Alignment VETO: a REQUESTED side effect whose arguments are copied from third-party content is checked against the
    # user's request; a confident "no" (log-odds <= L4_ALIGNMENT_VETO_MAX_LOG_ODDS) holds it for confirmation. AgentDojo
    # dev replay (2026-11-01): an injected create_calendar_event with the attacker's arguments ran as the user's own
    # requested action (the local contract binds no arguments; the hosted one does).
    alignment_veto = None
    if (requested and not rescued_by_alignment and cap in SIDE_EFFECT and getattr(cfg, "L4_ALIGNMENT_LOCAL", False)
            and _args_copied_from_third_party(params, chunks)):
        from sentinel.core.model_executor import run_model
        from .authz.alignment import alignment_log_odds
        _lv = await run_model(alignment_log_odds, utext, tool_name, params, tool_description(tool_name))
        if _lv is not None and _lv <= float(getattr(cfg, "L4_ALIGNMENT_VETO_MAX_LOG_ODDS", -2.0)):
            alignment_veto = (f"the local alignment check says this call, with arguments copied from third-party content, "
                              f"does not serve the user's request (log-odds {_lv:.1f}); confirm with the user")
    judge_used = None
    if (not requested and cap in SIDE_EFFECT | {READ_SENSITIVE}
            and getattr(cfg, "L4_ALIGNMENT_JUDGE", False)):
        from sentinel.core.policy_prompts import ACTION_ALIGNMENT_V1, action_alignment_text
        from sentinel.layers.layer1_llm_judge import llm_judge_check
        p_unauth = await llm_judge_check(action_alignment_text(utext, tool_name, params),
                                         system_prompt=ACTION_ALIGNMENT_V1)
        judge_used = p_unauth
        if p_unauth is not None and p_unauth < 0.5:
            requested, why_req = True, f"alignment check: authorised (p_unauth={p_unauth:.2f})"
    if strict_reasoning and requested:
        # "the user wants me to <X>" is evidence only when the user did NOT ask for X.
        from .reasoning_parser import ATTRIBUTING_UNREQUESTED
        reasoning_flags = [f for f in reasoning_flags if f != ATTRIBUTING_UNREQUESTED]

    named_in = action_named_in(tool_name, untrusted) if not requested else None
    named_in_any = (action_named_in(tool_name, chunks, prose_form=False)
                    if not requested and not named_in else None)

    sinks = []
    max_ratio = 0.0
    data_destinations = []        # RCA 2 F-A3: destinations taken from third-party data, not named by the user
    dest_values = []
    utext_fold = _fold_identifier(utext)
    for path, v in sink_leaves(cap, params):
        pname = path.split(".")[0].split("[")[0]
        src, ratio, cid = _sink_source((path, v), provenance.get(pname, {}), untrusted, trusted, utext)
        if src == "untrusted":
            max_ratio = max(max_ratio, ratio)
        if src == "context" and _DESTINATION.match(pname) and _fold_identifier(v) not in utext_fold:
            data_destinations.append(path)
            dest_values.append(v)
        sinks.append({"param": path, "source": src, "chunk_id": cid})
    srcs = {s["source"] for s in sinks}

    # R-031d (L4_SINK_CONTEXT_SCOPE=all_args): the addressee question -- was this ARGUMENT chosen
    # by an instruction to the agent? -- applies to every argument of a side-effect call, not only
    # to destinations: an injected reserve_hotel(hotel="Riverside View") or calendar title has no
    # "sink" parameter at all. Only arguments the user did not type are checked.
    if (cap in SIDE_EFFECT and getattr(cfg, "L4_SINK_CONTEXT_CHECK", False)
            and getattr(cfg, "L4_SINK_CONTEXT_SCOPE", "sinks") == "all_args"
            and "untrusted" not in srcs):
        seen = {s["param"] for s in sinks}
        for name, value in params.items():
            for path, leaf in _leaf_values(name, value):
                v = "" if leaf is None else str(leaf).strip().lower()
                if path in seen or len(v) < MIN_TRACEABLE_LEN or v in utext.lower():
                    continue
                hit = _instruction_context(v, list(trusted) + list(untrusted))
                if hit is not None:
                    sinks.append({"param": path, "source": "untrusted", "chunk_id": f"ctx:{hit}"})
                    srcs.add("untrusted")
                    break

    score = _BASE.get(cap, 0.3)
    threat, reasons, auth = "CLEAN", [f"capability={cap}", why_req], SOURCE_EXPLICIT if requested else "UNREQUESTED_ACTION"
    if cap == READ:
        pass                                   # reads are never blocked (their outputs are L2's job)
    elif cap == EGRESS:
        if "untrusted" in srcs:
            score, threat, auth = S_BLOCK, "RAG_INJECTION", "UNTRUSTED_SOURCE"
            reasons.append("URL taken from untrusted content (possible exfiltration / attacker page)")
        elif not requested and srcs & {"context", "synthesized"}:
            score, threat = S_WARN, "SUSPICIOUS_TOOL_CALL"
            reasons.append("unrequested fetch of a URL not given by the user")
    else:
        if "untrusted" in srcs:
            score, threat, auth = S_BLOCK, "RAG_INJECTION", "UNTRUSTED_SOURCE"
            reasons.append("a sink parameter (destination/target) was copied from untrusted content")
        elif not requested and named_in:
            score, threat, auth = S_BLOCK, "AGENTIC_HIJACK", "UNTRUSTED_SOURCE"
            reasons.append(f"action not requested by the user and named in untrusted content ({named_in})")
        elif not requested and named_in_any:
            score, threat = S_HOLD, "SUSPICIOUS_TOOL_CALL"
            reasons.append(f"action not requested by the user and named in third-party content ({named_in_any})")
        elif not requested:
            score = S_HOLD if cap in HIGH_IMPACT else S_WARN
            threat = "SUSPICIOUS_TOOL_CALL"
            reasons.append("action not requested by the user")
        elif cap in HIGH_IMPACT and "synthesized" in srcs:
            score, threat = S_WARN, "SUSPICIOUS_TOOL_CALL"
            reasons.append("high-impact sink synthesised by the agent (not from the user or trusted data)")
    if reasoning_flags:
        score = max(score, S_WARN if cap in (READ, EGRESS) else S_HOLD)
        threat = threat if threat != "CLEAN" else "SUSPICIOUS_TOOL_CALL"
        reasons.extend(reasoning_flags)

    # never block a plain read; hold (block) unrequested high-impact actions for confirmation
    # L4_HOLD_SENSITIVE_READS (2026-09-26, off by default): a SENSITIVE read (SSNs, salaries,
    # credentials, account details) that the user did not ask for and that third-party content
    # names is the exfiltration precursor sentinel_bench's poisoned_rag_exfil uses (13/13 ended at
    # WARN: HOLD score, but READ_SENSITIVE is not high-impact, so the read executed). With the flag
    # it is held like the high-impact capabilities -- the CaMeL / Progent rule that sensitive data
    # access must be authorised by the user.
    held = HIGH_IMPACT | ({READ_SENSITIVE} if getattr(cfg, "L4_HOLD_SENSITIVE_READS", False) else set())
    should_execute = not (score >= cfg.L4_DECISION_THRESHOLD
                          or (score >= S_HOLD and cap in held))
    if cap == READ:
        should_execute = True
    if not should_execute and threat == "SUSPICIOUS_TOOL_CALL":
        threat = "AGENTIC_HIJACK"

    # CONFIRMATION (RCA 2 F-A1..F-A3). Calls the evidence cannot settle are held for the USER, not executed
    # with a WARN and not reported as attacks. Never applied when there is attack evidence (a sink from
    # untrusted content, or an unrequested action named in untrusted content): those stay hard blocks.
    attack_evidence = "untrusted" in srcs or (not requested and bool(named_in))
    delegated = (not requested) and user_delegates(utext)
    confirm = []
    if cap != READ and not attack_evidence:
        nsa = getattr(cfg, "L4_NAMED_SOURCE_AUTHORITY", False) and getattr(cfg, "L4_AUTHZ", False)
        nsa_defer = False
        if nsa:
            # L4 v9: a destination the user typed, a system of record holds, or that passes the named-source test is
            # left to the authz matrix (which applies its payee / role rules); v9c: when the authz contract says the
            # user handed the task to a document, the lexicon's unrequested / delegated / copied-content holds on a
            # COMMUNICATE / WRITE call defer to authz (which checks every argument; consequential families keep them)
            from .authz.decide import named_source_ok, system_or_user_value, t0_anchors
            from .authz import active_contract as _ac
            keep = [(pth, v) for pth, v in zip(data_destinations, dest_values)
                    if not (system_or_user_value(session_id, v, utext)
                            or (named_source_ok(session_id, v, utext,
                                                t0_anchors(session_id, params, pth.split(".")[0].split("[")[0], utext))
                                and not _nsa_window_injected(v, chunks)))]
            data_destinations = [pth for pth, _ in keep]
            _c = _ac(session_id, utext)
            nsa_defer = bool(_c is not None and _c.delegated and cap in (COMMUNICATE, WRITE))
        if nsa_defer:
            pass
        elif delegated and cap in (HIGH_IMPACT | {COMMUNICATE}):
            confirm.append("the user delegated this to instructions in third-party data; confirm with the user")
        elif (not requested and getattr(cfg, "L4_HOLD_UNREQUESTED_COMMUNICATE", False)
              and (cap == COMMUNICATE or (cap == EGRESS and _carries_data(params)))):
            confirm.append("unrequested communication / data-carrying egress; confirm with the user")
        elif not requested and cap == WRITE and getattr(cfg, "L4_HOLD_UNREQUESTED_WRITE", False):
            confirm.append("unrequested write (reservation / record change); confirm with the user")
        if alignment_veto:
            confirm.append(alignment_veto)
        # Copied-content confirmation (config.L4_COPIED_CONTENT_CONFIRM): a side effect whose FREE-TEXT content (body,
        # content, message, title, description, ...) is a verbatim copy of third-party text acts on the data, not on the
        # user's words. Data VALUES copied from records (addresses, ids, names) are left to the lineage matrix.
        if (cap in SIDE_EFFECT and getattr(cfg, "L4_COPIED_CONTENT_CONFIRM", False) and not nsa_defer
                and _content_copied_from_third_party(params, chunks)):
            confirm.append("free-text content of this call is copied from third-party content; confirm with the user")
        data_caps = {c.strip() for c in str(getattr(cfg, "L4_DATA_SINK_CONFIRM", "OFF")).upper().split(",")}
        if requested and cap in data_caps and data_destinations:
            confirm.append(f"destination taken from third-party data, not named by the user "
                           f"({', '.join(data_destinations[:3])}); confirm with the user")
    requires_confirmation = bool(confirm)
    if requires_confirmation:
        should_execute = False
        score = max(score, S_HOLD)
        threat = "CONFIRMATION_REQUIRED"
        reasons.extend(confirm)

    # ACTION AUTHORIZATION (ARCHITECTURE_NEXT.md v2 step 1, config.L4_AUTHZ): is this action, with these
    # arguments, authorised by the user's request and the trust matrix -- whatever influenced the model? It
    # can only tighten the verdict above: a block stays a block, an allow can become a confirmation or a block.
    authz = None
    if getattr(cfg, "L4_AUTHZ", False) and (cap in SIDE_EFFECT or (cap == EGRESS and getattr(cfg, "L4_AUTHZ_EGRESS_SENSITIVE", False))):
        from .authz import authorize, active_contract, lexicon_contract, record_call, BLOCK, CONFIRM
        contract = active_contract(session_id, utext) or lexicon_contract(utext, [tool_name])
        if rescued_by_alignment and not contract.requested(tool_name):
            from .authz.contract import Contract as _Contract   # the rescue counts as requested here too
            contract = _Contract(actions={**contract.actions, tool_name: {"max_calls": None, "args": {}}},
                                 delegated=contract.delegated, constraints=contract.constraints, source=contract.source,
                                 rejected={t: v for t, v in getattr(contract, "rejected", {}).items() if t != tool_name})
        authz = authorize(session_id, tool_name, params, utext, contract)
        if authz.decision == BLOCK and (should_execute or requires_confirmation):
            should_execute, requires_confirmation = False, False
            score, threat, auth = max(score, S_BLOCK), "UNAUTHORIZED_ACTION", "UNAUTHORIZED_ARGUMENT"
            reasons.extend(f"authz: {r}" for r in authz.reasons)
        elif authz.decision == CONFIRM and should_execute:
            should_execute, requires_confirmation = False, True
            score, threat = max(score, S_HOLD), "CONFIRMATION_REQUIRED"
            reasons.extend(f"authz: {r}" for r in authz.reasons)
        elif authz.decision != "allow":
            reasons.extend(f"authz: {r}" for r in authz.reasons)
        # L4 v9d: an argument the named-source test allowed (document text, T2, strict sink) is held again when the
        # text around it reads as an injection -- the document the user named may itself carry the attack
        if (getattr(cfg, "L4_NAMED_SOURCE_AUTHORITY", False) and should_execute and authz.decision == "allow"):
            from .authz.decide import STRICT as _STRICT
            hit = [a for a in authz.args if a.get("tier") == "T2" and a.get("class") in _STRICT
                   and a.get("decision") == "allow" and _nsa_window_injected(str(a.get("value", "")), chunks)]
            if hit:
                should_execute, requires_confirmation = False, True
                score, threat = max(score, S_HOLD), "CONFIRMATION_REQUIRED"
                reasons.append("authz: " + ", ".join(a["param"] for a in hit)
                               + " from a named document whose surrounding text reads as an injection")
        # v8 RCA (a05: ~83 legitimate calls per templated family hard-blocked): the chunk-level rule above blocks a
        # value because it APPEARS in a flagged tool output -- but an injected output still carries the legitimate data
        # the task needs. When field-level provenance places that same argument in a user-typed (T0) or system-of-
        # record (T1) field, the chunk-level premise is false for it. Only chunk MEMBERSHIP is overridden; a value that
        # sits inside an instruction block ("ctx:") stays blocked (selection attacks), as do named-in and reasoning flags.
        if (getattr(cfg, "L4_AUTHZ_FIELD_LEVEL_OVERRIDE", False) and threat == "RAG_INJECTION"
                and not should_execute and not requires_confirmation and authz.decision != BLOCK
                and not reasoning_flags and not (not requested and named_in)):
            membership = {s["param"].split(".")[0].split("[")[0] for s in sinks
                          if s["source"] == "untrusted" and not str(s.get("chunk_id") or "").startswith("ctx:")}
            context_hits = [s for s in sinks if s["source"] == "untrusted" and str(s.get("chunk_id") or "").startswith("ctx:")]
            trusted_args = {a["param"] for a in authz.args if a.get("tier") in ("T0", "T1")}
            if membership and not context_hits and membership <= trusted_args:
                reasons.append("authz: field-level provenance places " + ", ".join(sorted(membership))
                               + " in a user / system-of-record field; chunk-level flag overridden")
                if authz.decision == CONFIRM:
                    requires_confirmation, threat, score = True, "CONFIRMATION_REQUIRED", S_HOLD
                else:
                    should_execute, threat, score, auth = True, "CLEAN", _BASE.get(cap, 0.3), SOURCE_EXPLICIT
        # v7 review R6: only a call that can still run counts toward the user's call bound -- a hard-blocked call
        # used to consume it, so the user's own later call needed a confirmation
        if should_execute or requires_confirmation or not getattr(cfg, "L4_AUTHZ_COUNT_ONLY_RUNNABLE", False):
            record_call(session_id, tool_name, params)

    risk = ("CRITICAL" if score >= S_BLOCK else "HIGH" if score >= S_WARN
            else "MEDIUM" if score >= 0.5 else "LOW")
    from .tool_auditor import _continuous_confidence, _min_provenance_confidence
    return L4Result(
        score=score, threat_class=threat, authorization_source=auth, risk_level=risk,
        should_execute=should_execute, reason=" | ".join(reasons),
        provenance=provenance,
        requires_confirmation=requires_confirmation,
        action={"capability": cap, "requested": requested, "named_in_untrusted": named_in,
                "named_in_third_party": named_in_any, "delegated": delegated,
                "sinks": sinks, "alignment_judge": judge_used,
                "authz": authz.to_dict() if authz is not None else None},
        max_flagged_chunk_ratio=max_ratio,
        min_provenance_confidence=_min_provenance_confidence(provenance),
        confidence=_continuous_confidence(risk_level=risk, provenance=provenance,
                                          reasoning_flags=reasoning_flags,
                                          max_flagged_chunk_ratio=max_ratio),
    )
