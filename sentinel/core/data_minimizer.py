"""
Data minimizer for L5's inferred field policy (config.L5_INFERRED_POLICY; results.md §24).

When a session has no declared field policy, L5 cannot know which values of a retrieved record the task may disclose:
measured on AgentLeak (results.md §21.6), most of the shipped heuristic's false positives are values the task was allowed
to use, and its misses are private values it never tracked. This module infers the task's allowed fields the way
AirGapAgent does (Bagdasarian et al., CCS 2024: an LLM "data minimizer" selects the user data a task needs before the
conversation): per record field, the local model answers "does the assistant need this field's value to complete the
task?" and P(yes) is read from the first-token yes / no logits. Field NAMES only -- no value is shown to the model.

Zero-shot on purpose (no fitting to a benchmark's task templates). Runs on the already-loaded local 4B model
(core/local_judge.py), one left-padded batch per record, no KV cache shared with the judge's templates. Fail soft: if the
local model is unavailable, returns None and the caller keeps the shipped behaviour.
"""
from __future__ import annotations

import logging
import math
from functools import lru_cache

logger = logging.getLogger(__name__)

# Revision 1 (results.md §24, 2026-11-11 09:16; the one pre-registered DEV revision): a strict minimization norm.
MINIMIZER_SYSTEM = (
    "You are a strict data-minimization checker for an AI assistant. A record retrieved for a user's task contains "
    "many fields, and most of them must NOT be disclosed. A field's value is needed only if the task explicitly asks for "
    "that information, or if it identifies the person, case or item the task is about. Medical, financial, legal, "
    "employment and personal details (diagnoses, medications, allergies, notes, dates of birth, identifiers, account or "
    "card numbers, contact details, income, salary, ratings, history) are NOT needed unless the task explicitly asks "
    "for them. Answer 'yes' only if the field's value is needed; otherwise answer 'no'.")
MINIMIZER_USER = ("Task: {request}\nRecord fields: {fields}\nField:{field}\n"
                  "Does the assistant need the value of this field to complete the task? Answer yes or no.")
_MARK = "⁣⁣FIELD⁣⁣"
_MAX_REQUEST_CHARS = 2000
_BATCH = 16


def _chat(j, request: str, fields: list[str], field: str) -> str:
    msgs = [{"role": "system", "content": MINIMIZER_SYSTEM},
            {"role": "user", "content": MINIMIZER_USER.format(request=(request or "")[:_MAX_REQUEST_CHARS],
                                                              fields=", ".join(fields), field=field)}]
    return j.tok.apply_chat_template(msgs, tokenize=False, add_generation_prompt=True)


def _prompt_ids(j, request: str, fields: list[str], field: str) -> list[int]:
    """The full prompt of one field (the parity reference for the prefix-cached path)."""
    return j.tok(_chat(j, request, fields, " " + field), add_special_tokens=False)["input_ids"]


def _score_record(j, request: str, fields: list[str]) -> list[float]:
    """P(yes) for every field of one record. The shared prefix (system + task + field list + 'Field:') runs once; the
    per-field suffixes (' <field>' + question + assistant header) are left-padded into one batch over the repeated prefix
    cache with explicit positions, so the last real token of every row sits at the last index."""
    import copy
    from transformers import DynamicCache
    torch = j.torch
    full = _chat(j, request, fields, _MARK)
    i = full.index(_MARK)
    pre = j.tok(full[:i], add_special_tokens=False)["input_ids"]
    tail = full[i + len(_MARK):]
    sufs = [j.tok(" " + f + tail, add_special_tokens=False)["input_ids"] for f in fields]
    n0 = len(pre)
    cache = DynamicCache()
    with torch.no_grad():
        j.model(input_ids=torch.tensor([pre], device="cuda:0"), past_key_values=cache, use_cache=True)
    pad = j.tok.pad_token_id if j.tok.pad_token_id is not None else j.tok.eos_token_id
    out: list[float] = []
    for k in range(0, len(sufs), _BATCH):
        rows = sufs[k:k + _BATCH]; b = len(rows); ls = max(len(r) for r in rows)
        ids = torch.full((b, ls), pad, dtype=torch.long, device="cuda:0")
        mask = torch.zeros((b, n0 + ls), dtype=torch.long, device="cuda:0"); mask[:, :n0] = 1
        pos = torch.full((b, ls), n0, dtype=torch.long, device="cuda:0")
        for r, row in enumerate(rows):
            ids[r, ls - len(row):] = torch.tensor(row, device="cuda:0")
            mask[r, n0 + ls - len(row):] = 1
            pos[r, ls - len(row):] = torch.arange(n0, n0 + len(row), device="cuda:0")
        c = copy.deepcopy(cache); c.batch_repeat_interleave(b)
        with torch.no_grad():
            o = j.model(input_ids=ids, attention_mask=mask, position_ids=pos, past_key_values=c, use_cache=True,
                        cache_position=torch.arange(n0, n0 + ls, device="cuda:0"), logits_to_keep=1)
        lp = torch.log_softmax(o.logits[:, -1].float(), -1)
        ly = torch.logsumexp(lp[:, j.yes], -1); ln = torch.logsumexp(lp[:, j.no], -1)
        out += [float(x) for x in torch.sigmoid(ly - ln).cpu()]
        del c, o
    return out


def _score_batch(j, rows: list[list[int]]) -> list[float]:
    """P(yes) per row: left-padded batch, explicit positions, the last real token of every row at the last index."""
    torch = j.torch
    n = max(len(r) for r in rows)
    pad = j.tok.pad_token_id if j.tok.pad_token_id is not None else j.tok.eos_token_id
    ids = torch.full((len(rows), n), pad, dtype=torch.long, device="cuda:0")
    mask = torch.zeros((len(rows), n), dtype=torch.long, device="cuda:0")
    pos = torch.zeros((len(rows), n), dtype=torch.long, device="cuda:0")
    for i, r in enumerate(rows):
        ids[i, n - len(r):] = torch.tensor(r, device="cuda:0")
        mask[i, n - len(r):] = 1
        pos[i, n - len(r):] = torch.arange(len(r), device="cuda:0")
    with torch.no_grad():
        out = j.model(input_ids=ids, attention_mask=mask, position_ids=pos, use_cache=False, logits_to_keep=1)
    lp = torch.log_softmax(out.logits[:, -1].float(), -1)
    ly = torch.logsumexp(lp[:, j.yes], -1); ln = torch.logsumexp(lp[:, j.no], -1)
    return [float(x) for x in torch.sigmoid(ly - ln).cpu()]


@lru_cache(maxsize=4096)
def _minimize_cached(request: str, fields: tuple) -> tuple | None:
    from sentinel.core.local_judge import _lock, get_local_judge
    j = get_local_judge()
    if j is None:
        return None
    try:
        with _lock:
            ps = _score_record(j, request, list(fields))
        return tuple(ps)
    except Exception as e:                                   # noqa: BLE001 -- fail soft: no inferred policy
        logger.warning(f"data minimizer failed on one record: {e}")
        try:
            j.torch.cuda.empty_cache()
        except Exception:                                    # noqa: BLE001
            pass
        return None


def minimize_fields(request: str, fields: list[str]) -> dict[str, float] | None:
    """{field: P(the task needs this field's value)} for a record's field names, or None if the local model cannot run."""
    names = tuple(dict.fromkeys(str(f) for f in fields if str(f).strip()))
    if not names:
        return {}
    ps = _minimize_cached(request or "", names)
    if ps is None:
        return None
    return {f: p for f, p in zip(names, ps) if not math.isnan(p)}


def infer_field_policy(session, fields: dict, user_text: str, threshold: float) -> list[str] | None:
    """The inferred field policy (config.L5_INFERRED_POLICY): fields with P(needed) >= threshold are allowed, every other
    value of the record (> 3 characters, not typed by the user) becomes a private value of the session, exactly as a
    declared policy would (sensitive_value_extractor.track_field_policy). Returns the allowed fields, or None (no policy:
    the caller keeps the shipped behaviour) when the model is unavailable."""
    from sentinel.core.sensitive_value_extractor import track_field_policy
    p = minimize_fields(user_text, list((fields or {}).keys()))
    if p is None:
        return None
    allowed = [f for f, v in p.items() if v >= threshold]
    track_field_policy(session, fields, allowed, user_text)
    return allowed


def record_fields(response_text: str) -> dict | None:
    """The fields of a structured record in a tool response: a JSON object (or a one-element list holding one) with at
    least two scalar fields -> {field: str(value)}; anything else -> None (free text keeps the heuristic tracking)."""
    import json
    try:
        obj = json.loads(response_text)
    except (TypeError, ValueError):
        return None
    if isinstance(obj, list) and len(obj) == 1:
        obj = obj[0]
    if not isinstance(obj, dict):
        return None
    out = {str(k): str(v) for k, v in obj.items() if isinstance(v, (str, int, float)) and not isinstance(v, bool)}
    return out if len(out) >= 2 else None


def track_tool_output(session, response_text: str, user_text: str) -> str:
    """Production entry point for a tool response (app.py). With config.L5_INFERRED_POLICY on (and no declared-policy
    mode, config.L5_FIELD_POLICY off), a structured record is minimized against the user's request and enforced as an
    inferred field policy; otherwise -- free text, the flag off, or the model unavailable -- the shipped heuristic
    tracking runs (sensitive_value_extractor.track_sensitive_values). Returns "inferred" or "heuristic"."""
    import sentinel.config as cfg
    from sentinel.core.sensitive_value_extractor import track_field_policy, track_sensitive_values
    lib = str(getattr(cfg, "L5_POLICY_LIBRARY", "") or "")
    inf = bool(getattr(cfg, "L5_INFERRED_POLICY", False))
    if (lib or inf) and not getattr(cfg, "L5_FIELD_POLICY", False):
        fields = record_fields(response_text)
        if fields:
            if lib:                                   # the operator's task-policy library (results.md §24.2)
                from sentinel.core.policy_library import library_allowed
                allowed = library_allowed(user_text, list(fields), lib, int(getattr(cfg, "L5_POLICY_LIBRARY_K", 3)),
                                          float(getattr(cfg, "L5_POLICY_LIBRARY_SMIN", 0.7)),
                                          float(getattr(cfg, "L5_INFERRED_POLICY_T", 0.5)) if inf else None)
                if allowed is not None:
                    track_field_policy(session, fields, allowed, user_text)
                    return "library"
            elif infer_field_policy(session, fields, user_text, float(getattr(cfg, "L5_INFERRED_POLICY_T", 0.5))) is not None:
                return "inferred"
    track_sensitive_values(session, response_text)
    return "heuristic"


def reset_minimizer_cache():
    """Tests / reloads only."""
    _minimize_cached.cache_clear()
