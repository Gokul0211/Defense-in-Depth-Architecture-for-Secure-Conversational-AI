"""
Task-policy library for L5 (config.L5_POLICY_LIBRARY, a JSON path; empty = off; results.md §24.2).

Round 1 of the L5 inferred-policy work (results.md §24) showed that a zero-shot data minimizer cannot reproduce an
operator's privacy policy: on AgentLeak 995 / 1,245 leaked-field instances (DEV) are fields a general minimization norm
calls task-relevant (third-party names, case type, department, ratings) but the operator's policy forbids. The policy is
the operator's information. This module lets the operator declare it once per TASK TYPE instead of per session: a
library of example tasks {request, fields, allowed}; a new request is matched to the most similar library tasks
(sentence embedding of the request with names / identifiers masked) and each field of the retrieved record takes the
library's majority decision among the neighbours that contain that field. Fields no neighbour covers, or requests
with no close enough match, fall back to the zero-shot data minimizer (core/data_minimizer.py) when it is available.

Embeddings: the cached all-MiniLM-L6-v2 on the GPU when present, else the CPU (no download). Masking is lexical and fixed (no learned part).
"""
from __future__ import annotations

import json
import logging
import re
from functools import lru_cache
from pathlib import Path

logger = logging.getLogger(__name__)

_NAME = re.compile(r"\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+\b")              # two or more capitalised words: a person / party
_IDTOK = re.compile(r"\S*\d\S*")                                        # any token holding a digit: ids, dates, amounts
_state: dict = {}


def mask_request(text: str) -> str:
    """The request with person names (2+ capitalised words) and digit-bearing tokens masked: the task TYPE remains."""
    t = _NAME.sub("<NAME>", text or "")
    return _IDTOK.sub("<ID>", t)


def _encoder():
    if "enc" not in _state:
        import torch
        from sentence_transformers import SentenceTransformer
        dev = "cuda" if torch.cuda.is_available() else "cpu"          # the GPU when present (~90 MB beside the 4B model)
        _state["enc"] = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2", device=dev)
    return _state["enc"]


@lru_cache(maxsize=8)
def load_library(path: str) -> dict | None:
    """{tasks: [{request, fields, allowed}], emb: matrix} or None if unreadable / empty."""
    try:
        tasks = json.loads(Path(path).read_text(encoding="utf-8"))
        tasks = [t for t in tasks if t.get("request") and t.get("fields")]
        if not tasks:
            return None
        emb = _encoder().encode([mask_request(t["request"]) for t in tasks], normalize_embeddings=True, batch_size=64)
        return {"tasks": tasks, "emb": emb}
    except Exception as e:                                       # noqa: BLE001 -- fail soft: no library
        logger.warning(f"L5 policy library unreadable ({path}): {e}")
        return None


def library_decision(request: str, fields: list[str], path: str, k: int = 3, s_min: float = 0.7,
                     min_field_overlap: float = 0.5) -> tuple[dict, dict]:
    """({field: allowed? True / False / None (not covered)}, info). Neighbours: the k most similar library tasks whose
    field sets share >= min_field_overlap of this record's fields; none at similarity >= s_min -> every field None."""
    lib = load_library(path)
    fset = set(fields)
    if lib is None or not fset:
        return {f: None for f in fields}, {"match": False, "reason": "no library"}
    q = _encoder().encode([mask_request(request)], normalize_embeddings=True)[0]
    sims = lib["emb"] @ q
    order = sims.argsort()[::-1]
    nb = []
    for i in order:
        t = lib["tasks"][int(i)]
        tf = set(t["fields"])
        if len(fset & tf) / max(1, len(fset)) >= min_field_overlap:
            nb.append((float(sims[int(i)]), t))
        if len(nb) >= k:
            break
    nb = [(s, t) for s, t in nb if s >= s_min]
    if not nb:
        return {f: None for f in fields}, {"match": False, "best_sim": round(float(sims[order[0]]), 4)}
    out = {}
    for f in fields:
        votes = [(s, f in set(t["allowed"])) for s, t in nb if f in set(t["fields"])]
        if not votes:
            out[f] = None
            continue
        w_yes = sum(s for s, a in votes if a); w_all = sum(s for s, _ in votes)
        out[f] = w_yes / w_all >= 0.5
    return out, {"match": True, "neighbours": len(nb), "best_sim": round(nb[0][0], 4)}


def nearest_tasks(request: str, path: str, k: int = 3) -> list[dict]:
    """The k library tasks most similar to the request (masked-request similarity, no threshold): the worked examples
    of the "disclose_rag" minimizer (results.md §33). Requests are returned masked."""
    lib = load_library(path)
    if lib is None or k <= 0:
        return []
    q = _encoder().encode([mask_request(request)], normalize_embeddings=True)[0]
    order = (lib["emb"] @ q).argsort()[::-1][:k]
    return [{"request": mask_request(lib["tasks"][int(i)]["request"]), "fields": list(lib["tasks"][int(i)]["fields"]),
             "allowed": list(lib["tasks"][int(i)].get("allowed") or [])} for i in order]


STARTER_LIBRARY = Path(__file__).resolve().parents[1] / "layers" / "layer5_output" / "l5_starter_library.json"


def policy_source(cfg) -> tuple[str, float | None, float] | None:
    """(library path, fallback cut or None, s_min) for a session WITHOUT a declared policy: the operator's library
    (config.L5_POLICY_LIBRARY; the minimizer fallback only with L5_INFERRED_POLICY), else -- with L5_NOPOLICY_V3 on --
    the shipped starter library with the general minimizer as its fallback (results.md §33); None = no library."""
    lib = str(getattr(cfg, "L5_POLICY_LIBRARY", "") or "")
    if lib:
        fb = float(getattr(cfg, "L5_INFERRED_POLICY_T", 0.5)) if getattr(cfg, "L5_INFERRED_POLICY", False) else None
        return lib, fb, float(getattr(cfg, "L5_POLICY_LIBRARY_SMIN", 0.7))
    if getattr(cfg, "L5_NOPOLICY_V3", False):
        path = str(getattr(cfg, "L5_STARTER_LIBRARY", "") or "") or str(STARTER_LIBRARY)
        return path, float(getattr(cfg, "L5_NOPOLICY_V3_T", 0.5)), float(getattr(cfg, "L5_STARTER_LIBRARY_SMIN", 0.8))
    return None


def library_allowed(request: str, fields: list[str], path: str, k: int, s_min: float,
                    fallback_t: float | None, mode: str | None = None) -> list[str] | None:
    """The allowed fields for a record: the library's decision per field; uncovered fields fall back to the general
    minimizer (P >= fallback_t; mode = config.L5_MINIMIZER_MODE unless given: "needed" / "disclose" / "disclose_rag",
    or "transfer" = the k nearest tasks' vote without s_min, no model) when fallback_t is set, else they count as
    private. None only if neither the library nor the fallback can decide anything (the caller keeps the heuristic)."""
    import sentinel.config as cfg
    mode = mode or str(getattr(cfg, "L5_MINIMIZER_MODE", "needed") or "needed")
    dec, info = library_decision(request, fields, path, k=k, s_min=s_min)
    if not info.get("match") and fallback_t is None:
        return None
    open_fields = [f for f, d in dec.items() if d is None]
    p = {}
    if open_fields and fallback_t is not None:
        if mode == "transfer":
            d2, _ = library_decision(request, fields, path, k=k, s_min=-1.0)
            p = {f: (1.0 if d2.get(f) else 0.0) for f in open_fields if d2.get(f) is not None}
        else:
            from sentinel.core.data_minimizer import format_examples, minimize_fields
            if mode == "needed":                          # the §24 call, unchanged
                p = minimize_fields(request, open_fields) or {}
            else:
                ex = format_examples(nearest_tasks(request, path, 3)) if mode == "disclose_rag" else ""
                p = minimize_fields(request, open_fields, mode=mode, examples=ex) or {}
        if not info.get("match") and not p:
            return None
    cut = fallback_t if fallback_t is not None else 2.0          # no fallback: an uncovered field is private
    return [f for f in fields if dec[f] is True or (dec[f] is None and p.get(f, 0.0) >= cut)]


def reset_policy_library():
    """Tests / reloads only."""
    load_library.cache_clear()
    _state.clear()
