"""
Criterion-bound targets (v7 proposal P1, scratch/rca/v7/PROPOSALS.md).

When the user picks a target by a criterion ("delete the largest file", "book the highest-rated hotel", "pay the
cheapest offer"), the intent contract records it as {"select": {"by": "<attribute>", "order": "max" | "min"}}. This
module checks the target the agent chose against the rows the agent actually read:

  ok            the chosen target is (one of) the extremal row(s) under the criterion, among the candidates read
  violation     a different row is extremal -- the chosen target does not satisfy the user's criterion
  unverifiable  no row carries the chosen value, or no candidate carries a numeric attribute matching `by`
                (computed criteria such as "the channel with the fewest messages" are not stored attributes)

Only "violation" changes a decision (authz/decide.py); "unverifiable" never does. Deterministic; no model involved
after the contract is written.
"""
from __future__ import annotations

import re

from . import lineage as lin

OK, VIOLATION, UNVERIFIABLE = "ok", "violation", "unverifiable"
_ID_FIELD = re.compile(r"(^|_)(id|ids|key|name|filename|title|handle|slug)(_|$)|^_key$|^id_$")


def _num(v):
    try:
        return float(str(v).replace(",", ""))
    except (TypeError, ValueError):
        return None


def _attr(row: dict, by: str) -> str | None:
    """The row field that best matches the criterion attribute ("size" -> size; "rating" -> rating)."""
    b = re.sub(r"[^a-z]", "", (by or "").lower())
    if not b:
        return None
    best = None
    for k, v in row.items():
        if k == "_key" or _num(v) is None:
            continue
        kk = re.sub(r"[^a-z]", "", k)
        if kk == b:
            return k
        if kk and (b in kk or kk in b):
            best = best or k
    return best


def check(session_id: str, value, spec: dict) -> tuple[str, dict]:
    by, order = str((spec or {}).get("by") or ""), str((spec or {}).get("order") or "").lower()
    if order not in ("max", "min") or not by:
        return UNVERIFIABLE, {"why": "no usable criterion"}
    v = lin.fold(value)
    rows = lin.session(session_id).records
    # the target identifies a row through an identifier-like field (id / name / key / title); matching any field
    # would let a numeric id collide with an attribute value (file id 13 vs a size of 13)
    hits = [(b, t, r) for b, t, r in rows if v and any(val == v for k, val in r.items() if _ID_FIELD.search(k))]
    if not hits:
        hits = [(b, t, r) for b, t, r in rows if v and v in r.values()]
    if not hits:
        return UNVERIFIABLE, {"why": "chosen value not found in any row read"}
    for batch, tool, row in reversed(hits):                 # the most recent listing that contains the target
        a = _attr(row, by)
        if a is None:
            continue
        cands = [r for b, _, r in rows if b == batch and _attr(r, by) == a and _num(r.get(a)) is not None]
        if len(cands) < 2:
            continue
        vals = [_num(r[a]) for r in cands]
        target = max(vals) if order == "max" else min(vals)
        mine = _num(row[a])
        detail = {"attribute": a, "order": order, "candidates": len(cands), "chosen": mine, "extremal": target,
                  "tool": tool}
        return (OK if mine == target else VIOLATION), detail
    return UNVERIFIABLE, {"why": f"no numeric attribute matching {by!r} among the candidates"}
