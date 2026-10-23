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


def _leaves(value):
    if isinstance(value, dict):
        for v in value.values():
            yield from _leaves(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from _leaves(v)
    elif value is not None and not isinstance(value, bool):
        yield value


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
    if cap not in SIDE_EFFECT:
        return out
    params = params or {}

    # 1. contract -------------------------------------------------------------------------------------------
    if contract is not None:
        out.requested = contract.requested(tool)
        if not out.requested:
            why = ("the user delegated to instructions in data; this action is not in the user's request"
                   if contract.delegated else "action not in the user's request (intent contract)")
            out.tighten(CONFIRM, why, "contract")
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
                cls = sink_class(tool, p, cap)
                if cls in (INTERNAL, AMOUNT):
                    # dates, times, file names, permissions: a binding there is format, not authority (the
                    # contract writes "January 11th 2025" for 2025-01-11); amounts are bounded by constraints
                    continue
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
            out.args.append({"param": p, "value": s[:120], "class": cls, "tier": res.tier,
                             "roles": sorted(res.roles), "decision": d})
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
