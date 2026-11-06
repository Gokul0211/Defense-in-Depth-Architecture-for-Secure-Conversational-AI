"""
Authorization decision for one side-effecting tool call (ARCHITECTURE_NEXT.md v2 §2c, §4).

Question answered: is THIS action, with THESE arguments, authorised -- whatever influenced the model to propose
it? Three checks, each can only tighten the decision (allow < confirm < block):

  1. contract   the user asked for this tool; within the call bound; literal / pattern bindings hold;
                stated numeric constraints hold. Unrequested side effects need the user's confirmation.
  2. matrix     every argument: sink class x source tier (+ role) -> allow / confirm / block.
                Identifiers inside CONTENT arguments (links, addresses, IBANs) are traced the same way.
  3. global     operator limits no contract can lift (transfer amount above which a human approves).

Detector evidence (L1/L2 flags, addressee cues, replay) is NOT consulted here; L4's existing checks keep doing
that and the two verdicts are combined by taking the stricter one.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import lineage as lin
from .sinks import (sink_class, COMMITMENT_TARGET, MONEY_DESTINATION, AMOUNT, EXTERNAL_RECIPIENT, ACCESS, CREDENTIAL,
                    PUBLICATION, EXECUTION, DESTRUCTIVE_TARGET, INTERNAL, CONTENT)

ALLOW, CONFIRM, BLOCK = "allow", "confirm", "block"
_RANK = {ALLOW: 0, CONFIRM: 1, BLOCK: 2}

#                       T0      T1      T2       T3      T4
MATRIX = {
    MONEY_DESTINATION:  (ALLOW, ALLOW, CONFIRM, BLOCK, BLOCK),     # T1 only as payee / own account, see below
    COMMITMENT_TARGET:  (ALLOW, ALLOW, CONFIRM, BLOCK, CONFIRM),   # T1 = an entry of the provider's own catalogue
    EXTERNAL_RECIPIENT: (ALLOW, ALLOW, CONFIRM, BLOCK, BLOCK),
    ACCESS:             (ALLOW, ALLOW, CONFIRM, BLOCK, BLOCK),
    CREDENTIAL:         (ALLOW, CONFIRM, BLOCK, BLOCK, BLOCK),
    PUBLICATION:        (ALLOW, ALLOW, CONFIRM, BLOCK, CONFIRM),
    EXECUTION:          (ALLOW, CONFIRM, BLOCK, BLOCK, BLOCK),
    DESTRUCTIVE_TARGET: (ALLOW, ALLOW, CONFIRM, BLOCK, CONFIRM),
    INTERNAL:           (ALLOW, ALLOW, ALLOW, CONFIRM, ALLOW),
    CONTENT:            (ALLOW, ALLOW, ALLOW, CONFIRM, ALLOW),     # identifiers found inside content
}
_TIERS = (lin.T0, lin.T1, lin.T2, lin.T3, lin.T4)
STRICT = {COMMITMENT_TARGET, MONEY_DESTINATION, EXTERNAL_RECIPIENT, ACCESS, CREDENTIAL, PUBLICATION, EXECUTION, DESTRUCTIVE_TARGET}
PAYEE_ROLES = {"payee", "self"}

# Action families for least privilege (ADR-6 change 2). A consequential family needs the user's request to name an
# action of the same family; tools of one family are interchangeable for this purpose, so the contract choosing a
# sibling tool (schedule vs update a transaction) does not count as "not requested".
CONSEQUENTIAL = {"TRANSFER", "DESTROY", "SECURITY", "EXECUTE", "COMMIT"}


def action_family(tool: str, cap: str) -> str:
    import re as _r
    if _r.search(r"(^|_)(reserve|book|order|purchase|buy|subscribe|checkout)(_|$)", (tool or "").lower()):
        return "COMMIT"
    return cap
# The user asked for this KIND of value to be sent ("send my passport number to the agency", "forward the code").
import re as _re
_DISCLOSURE = {
    "credential": _re.compile(r"\b(passwords?|pass ?codes?|pins?|(security|verification|login|access|reset) codes?|codes?|"
                              r"credit ?cards?|card numbers?|cvv|tokens?|api ?keys?)\b", _re.I),
    "personal": _re.compile(r"\b(passports?|id numbers?|identity|ssn|social security|tax id|bank account|account numbers?|"
                            r"iban|dates? of birth|birthday|driver'?s? licen[cs]e|personal (details|information|info|data)|"
                            r"user (info|information|details))\b", _re.I),
}


@dataclass
class AuthzDecision:
    decision: str = ALLOW
    reasons: list = field(default_factory=list)
    args: list = field(default_factory=list)        # [{param, value, class, tier, roles, decision}]
    requested: bool | None = None
    contract_source: str | None = None
    checks: dict = field(default_factory=dict)      # which check produced the decision: contract / matrix / global

    def tighten(self, d: str, why: str, check: str) -> None:
        if _RANK[d] > _RANK[ALLOW]:
            self.reasons.append(why)
            self.checks[check] = max(self.checks.get(check, ALLOW), d, key=_RANK.get)
        if _RANK[d] > _RANK[self.decision]:
            self.decision = d

    def to_dict(self) -> dict:
        return {"decision": self.decision, "reasons": self.reasons, "args": self.args,
                "requested": self.requested, "contract_source": self.contract_source, "checks": self.checks}

    def card(self, tool: str) -> dict:
        """What a confirmation must show the user (v7 P2): the action, every authority-bearing argument with its
        origin and source, whether the user requested the action, and why it is held. Values are shown in full --
        hiding arguments behind a summary is how approval prompts are abused."""
        return {"tool": tool, "decision": self.decision, "requested": self.requested,
                "held_because": self.reasons[:6],
                "arguments": [{k: a.get(k) for k in ("param", "value", "class", "tier", "sources", "decision")}
                              for a in self.args],
                "contract": self.contract_source}


def _leaves(value):
    if isinstance(value, dict):
        for v in value.values():
            yield from _leaves(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from _leaves(v)
    elif value is not None and not isinstance(value, bool):
        yield value


def _shortened_from(value, literal) -> bool:
    """Every word of the content value occurs in the user's literal (case-insensitive), and there are at least two.
    One direction only: a value that adds words the user did not write is not 'shortened'."""
    import re as _r
    vw = [w for w in _r.findall(r"\w+", str(value).lower())]
    lit = literal if isinstance(literal, str) else " ".join(map(str, literal if isinstance(literal, list) else [literal]))
    lw = set(_r.findall(r"\w+", lit.lower()))
    return len(vw) >= 2 and all(w in lw for w in vw)


def _needs_delegation(contract, tool: str, param: str, cfg) -> bool:
    """True when a T2 value (text of a document the user pointed at) must not be confirmed: an LLM contract (prompt
    v2, which can express per-argument sources) exists, the user did not hand everything to the data, and this
    argument carries no `from`. The lexicon fallback and v1 contracts cannot express delegation -> old behaviour.
    LOCAL contract (L4 v6, L4_AUTHZ_LOCAL_DELEGATION): it names no sources, so only an action the user did not ask for
    -- not in the contract's per-tool selection (an alignment rescue is added to it by the caller) -- is held to the
    rule; a requested tool keeps the confirmation (the user may have named the source). The lexicon's evidence is NOT
    consulted: it is per capability ("user asks for communicate"), so a "message them" request would exempt
    post_webpage (v6 dev replay: 16 attack calls exempted that way)."""
    if contract is None or contract.delegated:
        return False
    if not getattr(cfg, "L4_AUTHZ_REQUIRE_DELEGATION", True):
        return False
    if contract.source == "local":
        # v10 (L4_LOCAL_SEL_NECESSITY_GUARD): a tool only the necessity question selected counts as requested for
        # the contract check, but stays under this rule (v8 RCA: it turned a block into a confirmation)
        guarded = (getattr(cfg, "L4_LOCAL_SEL_NECESSITY_GUARD", False) and tool in getattr(contract, "necessity_only", ()))
        return bool(getattr(cfg, "L4_AUTHZ_LOCAL_DELEGATION", False)) and (not contract.requested(tool) or guarded)
    if contract.source != "llm":
        return False
    if str(getattr(cfg, "L4_AUTHZ_CONTRACT_PROMPT", "v1")).lower() not in ("v2", "v3"):
        return False
    spec = ((contract.actions.get(tool) or {}).get("args") or {}).get(param) or {}
    return "from" not in spec


# L4 v9: the user's own words ask for this KIND of value ("her e-mail is on her website", "pay the bill", "the link").
_KIND_CUE = {
    "email": _re.compile(r"\b((her|his|their) e-?mail|e-?mail address(es)?|address(es)?)\b", _re.I),   # an ADDRESS, not "the emails" (messages): v9 dev RCA
    "iban": _re.compile(r"\b(iban|account( number)?|bill|invoice|pay|payment|refund|rent)\b", _re.I),
    "url": _re.compile(r"\b(links?|urls?|website|web ?page|page|site)\b", _re.I),
    "phone": _re.compile(r"\b(phone|number|call)\b", _re.I),
}


def _asks_for_kind(utext: str, value) -> bool:
    kinds = {k for k, _ in lin.identifiers_in(str(value))}
    return bool(kinds) and all(k in _KIND_CUE and _KIND_CUE[k].search(utext or "") for k in kinds)


def system_or_user_value(session_id: str, value, utext: str) -> bool:
    """The value's best source is the user's own words (T0) or a declared system of record (T1)."""
    v = str(value)
    return lin.resolve(session_id, v, utext).tier in (lin.T0, lin.T1) or lin.resolve(session_id, v.upper(), utext).tier in (lin.T0, lin.T1)


def named_source_ok(session_id: str, value, utext: str, anchors: list | None = None) -> bool:
    """L4 v9 named-source test: `value` is document text (T2) only from reads the user located directly, the document
    names exactly one identifier of its kind, and the user's words ask for that kind of value -- or (v10,
    L4_NAMED_SOURCE_ANCHOR) the value sits in that document next to an entity the user typed in the same call
    ("invite Dora" + Dora's page holding her address)."""
    import sentinel.config as cfg
    value = str(value)
    if not lin.identifiers_in(value) and lin.identifiers_in(value.upper()):
        value = value.upper()          # callers that lower-case argument values (action_policy.sink_leaves): IBANs
    if not (lin.resolve(session_id, value, utext).tier == lin.T2 and lin.directly_named(session_id, value)
            and lin.candidates_in_source(session_id, value) == 1):
        return False
    if _asks_for_kind(utext, value):
        return True
    return bool(anchors) and getattr(cfg, "L4_NAMED_SOURCE_ANCHOR", False) and lin.anchored(session_id, value, anchors)


def t0_anchors(session_id: str, params: dict, exclude, utext: str) -> list:
    """Values of the call's OTHER arguments that the user typed (T0): the entities a named-source value may attach to."""
    return [x for q, val in (params or {}).items() if q != exclude for x in _leaves(val)
            if isinstance(x, str) and len(x.strip()) >= 3 and lin.resolve(session_id, x, utext).tier == lin.T0]


def _matrix(cls: str, res: lin.Resolution) -> str:
    d = MATRIX[cls][_TIERS.index(res.tier)]
    if cls == MONEY_DESTINATION and res.tier == lin.T1 and not (res.roles & PAYEE_ROLES):
        d = CONFIRM            # a value the bank lists, but not someone the user has paid: confirmation of payee
    return d


def _num(v):
    try:
        return float(str(v).replace(",", ""))
    except (TypeError, ValueError):
        return None


def authorize(session_id: str, tool: str, params: dict, utext: str, contract=None) -> AuthzDecision:
    import sentinel.config as cfg
    from ..action_policy import capability, SIDE_EFFECT
    cap = capability(tool)
    out = AuthzDecision(contract_source=getattr(contract, "source", None))
    params = params or {}
    if cap == "EGRESS" and getattr(cfg, "L4_AUTHZ_EGRESS_SENSITIVE", False) and getattr(cfg, "L4_AUTHZ_SENSITIVE_EGRESS", True):
        # v7 review R3: a fetch / browse call carries its arguments to a remote server (a URL query string), so a
        # sensitive value this session read leaves through it exactly as through a message body
        for p, value in params.items():
            for leaf in _leaves(value):
                for val, cat in lin.sensitive_in(session_id, str(leaf)):
                    if lin.resolve(session_id, val, utext).tier == lin.T0 or _DISCLOSURE[cat].search(utext or ""):
                        continue
                    d = BLOCK if cat == "credential" else CONFIRM
                    out.args.append({"param": p, "value": "<sensitive>", "class": f"EGRESS:sensitive:{cat}",
                                     "tier": "-", "roles": [], "decision": d})
                    out.tighten(d, f"{p} would send a {cat} value this session read to a remote server", "outbound")
        return out
    if cap not in SIDE_EFFECT:
        return out

    # 1. contract -------------------------------------------------------------------------------------------
    if contract is not None:
        out.requested = contract.requested(tool)
        if not out.requested:
            why = ("the user delegated to instructions in data; this action is not in the user's request"
                   if contract.delegated else "action not in the user's request (intent contract)")
            fam = action_family(tool, cap)
            scope = str(getattr(cfg, "L4_AUTHZ_LEAST_PRIVILEGE_SCOPE", "consequential")).lower()
            fam_ok = fam in CONSEQUENTIAL or scope == "all"      # v8 RCA: unrequested low-impact writes too
            least_priv = (getattr(cfg, "L4_AUTHZ_BLOCK_UNREQUESTED_CONSEQUENTIAL", False)
                          and contract.source == "llm" and not contract.delegated and fam_ok
                          and not any(action_family(t, capability(t)) == fam for t in contract.actions))
            # L4 v7 (L4_AUTHZ_LOCAL_LEAST_PRIVILEGE): the local contract's per-tool selection can tell "not asked"
            # from "not recognised" only when it was SURE: a consequential tool it rejected at log-odds <= m (fixed on
            # the dev benign tasks, a09_lp_margin.py) is refused; an uncertain "no" still only asks the user
            if (not least_priv and contract.source == "local" and getattr(cfg, "L4_AUTHZ_LOCAL_LEAST_PRIVILEGE", False)
                    and not contract.delegated and fam in CONSEQUENTIAL and tool in contract.rejected
                    and contract.rejected[tool] <= float(getattr(cfg, "L4_AUTHZ_LOCAL_LP_MAX_LOG_ODDS", -2.0))
                    and not any(action_family(t, capability(t)) == fam for t in contract.actions)):
                least_priv = True
            # L4 v9 (L4_NAMED_SOURCE_AUTHORITY): the user handed the task to a document ("do the actions in the email
            # from X"); a NON-consequential action (message, append) it leads to is the user's request by delegation.
            # Its arguments still go through the matrix below; money / delete / security / execute / booking keep
            # the confirmation.
            nsa_delegated = (not least_priv and contract.delegated and fam not in CONSEQUENTIAL
                             and cap in ("COMMUNICATE", "WRITE") and getattr(cfg, "L4_NAMED_SOURCE_AUTHORITY", False))
            if nsa_delegated:
                out.reasons.append("delegated to a document the user named; arguments checked by the matrix")
            else:
                # the lexicon fallback cannot tell "not asked" from "not recognised", so it only asks the user
                out.tighten(BLOCK if least_priv else CONFIRM,
                            f"{fam.lower()} action not in the user's request" if least_priv else why, "contract")
        else:
            spec = contract.actions[tool]
            n_prior = lin.prior_calls(session_id, tool)
            if spec.get("max_calls") and n_prior >= spec["max_calls"]:
                out.tighten(CONFIRM, f"call {n_prior + 1} of {tool} exceeds the {spec['max_calls']} the user asked for",
                            "contract")
            from .contract import matches_literal
            for p, b in (spec.get("args") or {}).items():
                if p not in params or params[p] in (None, "", []):
                    continue
                if "select" in b and getattr(cfg, "L4_AUTHZ_TARGET_CRITERIA", False):
                    from .selector import check as _sel_check, VIOLATION
                    for v in _leaves(params[p]):
                        verdict, info = _sel_check(session_id, v, b["select"])
                        out.args.append({"param": p, "value": str(v)[:120], "class": "TARGET_CRITERION",
                                         "tier": "-", "roles": [], "decision": verdict, "criterion": info})
                        if verdict == VIOLATION:
                            fam = action_family(tool, cap)
                            out.tighten(BLOCK if fam in CONSEQUENTIAL else CONFIRM,
                                        f"{p} is not the {info.get('order')} by {info.get('attribute')} among the "
                                        f"{info.get('candidates')} candidates read", "target")
                        elif verdict != "ok" and spec.get("verify_criterion"):
                            # a contract entry that stands ONLY on its criterion (local lexicon+criterion) must have
                            # the criterion verified; unverifiable -> ask the user (AgentDojo dev replay, v4)
                            out.tighten(CONFIRM, f"{p}: the user's criterion ({b['select'].get('order')} by "
                                                 f"{b['select'].get('by')}) cannot be checked yet", "target")
                if "from" in b or "select" in b:
                    continue           # a named source / criterion is not a value to compare
                cls = sink_class(tool, p, cap)
                if cls in (INTERNAL, AMOUNT):
                    # dates, times, file names, permissions: a binding there is format, not authority (the
                    # contract writes "January 11th 2025" for 2025-01-11); amounts are bounded by constraints
                    continue
                if cls == CONTENT and "literal" in b and _shortened_from(params[p], b["literal"]):
                    continue           # the agent shortened the user's own phrase ("Hiking Trip" from "hiking trip
                                       # with Mark"); content that ADDS words still mismatches
                if not matches_literal(b, params[p]):
                    # The contract is an LLM's reading of the user's words and can be wrong in FORMAT ("read" for the
                    # schema's "r", 2026-10-21 benign replay), so a mismatch alone only asks the user. It blocks when
                    # the replacing value was read from document content (T2/T3): the user stated a value and the
                    # call substitutes one from data -- the injection pattern itself.
                    from_docs = any(lin.resolve(session_id, v, utext).tier in (lin.T2, lin.T3)
                                    for v in _leaves(params[p]) if len(str(v).strip()) > 3)
                    d = BLOCK if (cls in STRICT and from_docs) else CONFIRM
                    out.tighten(d, f"{p} differs from what the user specified", "contract")
        for c in contract.constraints:
            if c.get("tool") not in (None, tool) or c.get("param") not in params:
                continue
            v, lim = _num(params[c["param"]]), _num(c.get("value"))
            if v is None or lim is None:
                continue
            ok = {"<=": v <= lim + 1e-9, ">=": v >= lim - 1e-9, "==": abs(v - lim) < 1e-6}[c["op"]]
            if not ok:
                out.tighten(CONFIRM, f"{c['param']}={v:g} violates the user's bound {c['op']} {lim:g}", "contract")

    # 2. matrix --------------------------------------------------------------------------------------------
    content_ids = getattr(cfg, "L4_AUTHZ_CONTENT_IDENTIFIERS", True)
    egress = getattr(cfg, "L4_AUTHZ_SENSITIVE_EGRESS", True)
    for p, value in params.items():
        cls = sink_class(tool, p, cap)
        for leaf in _leaves(value):
            s = str(leaf).strip()
            if not s:
                continue
            if cls == AMOUNT:
                continue                       # numbers have no lineage; bounded by the global policy below
            if cls == CONTENT:
                if egress and cap in ("COMMUNICATE", "TRANSFER"):
                    for val, cat in lin.sensitive_in(session_id, s):
                        if lin.resolve(session_id, val, utext).tier == lin.T0 or _DISCLOSURE[cat].search(utext or ""):
                            continue           # the user typed it, or asked for this kind of value to be sent
                        d = BLOCK if cat == "credential" else CONFIRM
                        out.args.append({"param": p, "value": "<sensitive>", "class": f"CONTENT:sensitive:{cat}",
                                         "tier": "-", "roles": [], "decision": d})
                        out.tighten(d, f"{p} carries a {cat} value this session read, not requested by the user",
                                    "outbound")
                if not content_ids:
                    continue
                for kind, ident in lin.identifiers_in(s):
                    res = lin.resolve(session_id, ident, utext)
                    d = _matrix(CONTENT, res)
                    if (d == ALLOW and kind == "url" and res.tier == lin.T2 and cap == "COMMUNICATE"
                            and getattr(cfg, "L4_AUTHZ_CONTENT_LINK_CONFIRM", False)):
                        d = CONFIRM            # v8 RCA: a link that only document text supplies, sent to someone
                    out.args.append({"param": p, "value": ident[:120], "class": f"CONTENT:{kind}",
                                     "tier": res.tier, "roles": sorted(res.roles), "decision": d})
                    out.tighten(d, f"{kind} {ident[:60]!r} in {p} comes from {res.tier} content", "matrix")
                continue
            if cls == INTERNAL and (len(s) < 4 or _num(s) is not None):
                continue                       # dates, counts, ids of the user's own objects: no lineage
            if cls != CREDENTIAL and len(s) <= 3 and not lin.looks_like_identifier(s):
                continue                       # an enum value ("r", "rw", "yes") has no source to trace
            res = lin.resolve(session_id, s, utext)
            d = _matrix(cls, res)
            if (d == CONFIRM and cls in STRICT and res.tier == lin.T2 and _needs_delegation(contract, tool, p, cfg)
                    and not (getattr(cfg, "L4_AUTHZ_ENTITY_ANCHOR", True) and lin.anchored(session_id, s, [
                        x for q, val in params.items() if q != p for x in _leaves(val)
                        if isinstance(x, str) and lin.resolve(session_id, x, utext).tier == lin.T0]))):
                d = BLOCK                      # ADR-6 change 1: origin is document text, argument not delegated
                out.tighten(BLOCK, f"{p} ({cls}) comes from document text the user did not name as its source",
                            "delegation")
            elif (d == CONFIRM and res.tier == lin.T2 and cls in (MONEY_DESTINATION, PUBLICATION)
                    and getattr(cfg, "L4_AUTHZ_AMBIGUOUS_DELEGATION_BLOCK", False)):
                n = lin.candidates_in_source(session_id, s)
                if n >= 2:                     # v8 RCA: the delegated document names several candidates
                    d = BLOCK
                    out.tighten(BLOCK, f"{p} ({cls}): the document it came from names {n} different candidates; "
                                       "the user must say which", "ambiguity")
            elif (d == CONFIRM and cls in STRICT and res.tier == lin.T2
                    and getattr(cfg, "L4_NAMED_SOURCE_AUTHORITY", False)
                    and named_source_ok(session_id, s, utext, t0_anchors(session_id, params, p, utext))):
                # L4 v9: an identifier read from a document the user located themself (they typed its file name /
                # URL / sender), which names exactly ONE identifier of that kind: the user delegated this value
                # ("her e-mail is on her website"). An injection in the same document adds a second candidate and
                # keeps the confirmation; a one-hop source or a non-identifier value is unchanged.
                d = ALLOW
            out.args.append({"param": p, "value": s[:120], "class": cls, "tier": res.tier,
                             "roles": sorted(res.roles), "decision": d,
                             "sources": [f"{t}:{tool_}.{fld}" for t, tool_, fld in res.sources[:3]]})
            out.tighten(d, f"{p} ({cls}) from {res.tier}{' as ' + '/'.join(sorted(res.roles)) if res.roles else ''}",
                        "matrix")

    # 3. global policy --------------------------------------------------------------------------------------
    lim = getattr(cfg, "L4_AUTHZ_TRANSFER_CONFIRM_ABOVE", None)
    if lim is not None:
        for p, value in params.items():
            if sink_class(tool, p, cap) != AMOUNT:
                continue
            v = _num(value)
            if v is not None and v > float(lim) and lin.resolve(session_id, value, utext).tier != lin.T0:
                out.tighten(CONFIRM, f"{p}={v:g} above the {float(lim):g} limit and not stated by the user", "global")
    return out


def card_from_dict(tool: str, authz: dict | None) -> dict | None:
    """The confirmation card (AuthzDecision.card) rebuilt from the dict L4 attaches to its result."""
    if not authz:
        return None
    return {"tool": tool, "decision": authz.get("decision"), "requested": authz.get("requested"),
            "held_because": (authz.get("reasons") or [])[:6],
            "arguments": [{k: a.get(k) for k in ("param", "value", "class", "tier", "sources", "decision")}
                          for a in authz.get("args") or []],
            "contract": authz.get("contract_source")}
