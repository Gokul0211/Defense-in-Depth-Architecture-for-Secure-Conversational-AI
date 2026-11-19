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
# Round 3 (results.md §33, 2026-11-15): the DISCLOSURE question. The label of a leak is whether the REPLY states a field,
# not whether the task needs it (a diagnosis can be needed to book the right department and still must not be stated).
DISCLOSE_SYSTEM = (
    "You are a strict privacy checker for an AI assistant's replies. A record retrieved for a user's task holds many "
    "fields. Under the minimum-necessary principle the reply may state a field's value only if the reply cannot do its "
    "job without it: the information the task asks for, and what names the person, case or item the reply is about. "
    "Every other field must not appear in the reply, even when it was useful for doing the task: identifiers, contact "
    "details, dates of birth, medical, financial, legal or employment details the task does not ask for, ratings, "
    "history and internal notes. Answer 'yes' only if the reply may state the field's value; otherwise answer 'no'.")
DISCLOSE_USER = ("{examples}Task: {request}\nRecord fields: {fields}\nField:{field}\n"
                 "May the reply to this task state the value of this field? Answer yes or no.")
EXAMPLES_HEAD = "Replies to similar tasks may state only these fields:\n"
EXAMPLE_ROW = "- Task: {request}\n  Record fields: {fields}\n  The reply may state: {allowed}\n"
MODES = ("needed", "disclose", "disclose_rag")                # "transfer" (no model) lives in core/policy_library.py
_MARK = "⁣⁣FIELD⁣⁣"
_MAX_REQUEST_CHARS = 2000
_BATCH = 16
# prefix-cache copies per batch are bounded by tokens (n0 x batch): 16 rows up to a 250-token prefix (every M0 / M1
# record, unchanged), fewer for the longer worked-example prompts of disclose_rag (a 470-token prefix x 16 ran the
# 4 GB card out of memory, results.md §33.4)
_BATCH_TOKENS = 4000
# disclose_rag (worked examples, ~450-token prefixes): at 8 rows the card was oversubscribed by ~0.4 GB and paged
# to shared system memory (66 min for what M1 does in 7); 1,000 tokens gives 2 rows (§33.5). Every other mode keeps
# _BATCH_TOKENS, so its stored design scores stay exact.
_BATCH_TOKENS_RAG = 1000


def format_examples(tasks: list[dict]) -> str:
    """Worked examples for mode "disclose_rag": library tasks {request, fields, allowed} (requests already masked)."""
    rows = [EXAMPLE_ROW.format(request=t.get("request", ""), fields=", ".join(t.get("fields") or []),
                               allowed=", ".join(t.get("allowed") or []) or "none") for t in tasks]
    return (EXAMPLES_HEAD + "".join(rows)) if rows else ""


def _chat(j, request: str, fields: list[str], field: str, mode: str = "needed", examples: str = "") -> str:
    req = (request or "")[:_MAX_REQUEST_CHARS]
    if mode in ("disclose", "disclose_rag"):
        ex = (examples + "\n") if (examples and mode == "disclose_rag") else ""
        msgs = [{"role": "system", "content": DISCLOSE_SYSTEM},
                {"role": "user", "content": DISCLOSE_USER.format(examples=ex, request=req, fields=", ".join(fields),
                                                                 field=field)}]
    else:
        msgs = [{"role": "system", "content": MINIMIZER_SYSTEM},
                {"role": "user", "content": MINIMIZER_USER.format(request=req, fields=", ".join(fields), field=field)}]
    return j.tok.apply_chat_template(msgs, tokenize=False, add_generation_prompt=True)


def _prompt_ids(j, request: str, fields: list[str], field: str, mode: str = "needed", examples: str = "") -> list[int]:
    """The full prompt of one field (the parity reference for the prefix-cached path)."""
    return j.tok(_chat(j, request, fields, " " + field, mode, examples), add_special_tokens=False)["input_ids"]


def _score_record(j, request: str, fields: list[str], mode: str = "needed", examples: str = "") -> list[float]:
    """P(yes) for every field of one record. The shared prefix (system + task + field list + 'Field:') runs once; the
    per-field suffixes (' <field>' + question + assistant header) are left-padded into one batch over the repeated prefix
    cache with explicit positions, so the last real token of every row sits at the last index."""
    import copy
    from transformers import DynamicCache
    torch = j.torch
    full = _chat(j, request, fields, _MARK, mode, examples)
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
    budget = _BATCH_TOKENS_RAG if mode == "disclose_rag" else _BATCH_TOKENS
    bsz = max(1, min(_BATCH, budget // max(1, n0)))
    for k in range(0, len(sufs), bsz):
        rows = sufs[k:k + bsz]; b = len(rows); ls = max(len(r) for r in rows)
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
def _minimize_cached(request: str, fields: tuple, mode: str = "needed", examples: str = "") -> tuple | None:
    from sentinel.core.local_judge import _lock, get_local_judge
    j = get_local_judge()
    if j is None:
        return None
    try:
        with _lock:
            ps = _score_record(j, request, list(fields), mode, examples)
        return tuple(ps)
    except Exception as e:                                   # noqa: BLE001 -- fail soft: no inferred policy
        logger.warning(f"data minimizer failed on one record: {e}")
        try:
            j.torch.cuda.empty_cache()
        except Exception:                                    # noqa: BLE001
            pass
        return None


def minimize_fields(request: str, fields: list[str], mode: str | None = None,
                    examples: str = "") -> dict[str, float] | None:
    """{field: P(yes)} for a record's field names, or None if the local model cannot run. mode "needed" (default, §24):
    P(the task needs the value); "disclose" / "disclose_rag" (§33): P(the reply may state it), the latter with worked
    examples (format_examples). Default mode: config.L5_MINIMIZER_MODE (unknown values -> "needed")."""
    import sentinel.config as cfg
    mode = mode or str(getattr(cfg, "L5_MINIMIZER_MODE", "needed") or "needed")
    if mode not in MODES:
        mode = "needed"
    names = tuple(dict.fromkeys(str(f) for f in fields if str(f).strip()))
    if not names:
        return {}
    ps = _minimize_cached(request or "", names, mode, examples if mode == "disclose_rag" else "")
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
    from sentinel.core.policy_library import library_allowed, policy_source
    src = policy_source(cfg)                          # operator library, else the §33 starter library, else None
    inf = bool(getattr(cfg, "L5_INFERRED_POLICY", False))
    lib = src[0] if src else ""
    if (lib or inf) and not getattr(cfg, "L5_FIELD_POLICY", False):
        fields = record_fields(response_text)
        if fields:
            if lib:                                   # task-policy library (results.md §24.2 / §33)
                allowed = library_allowed(user_text, list(fields), lib, int(getattr(cfg, "L5_POLICY_LIBRARY_K", 3)),
                                          src[2], src[1])
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
