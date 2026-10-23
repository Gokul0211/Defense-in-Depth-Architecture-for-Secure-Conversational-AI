"""
ADR -- the ADDRESSEE model: is this text addressed TO AN AI SYSTEM as a request? (v3, 2026-10-18)

WHY. The confused deputy, one level down: every injection classifier DIDA could use (PIGuard,
Prompt Guard, ProtectAI, the L1 stack) scores an instruction written for a HUMAN reader -- "please
send me the report", "run pip install", "book early" -- like an instruction for the AI (R-031: both
~0.999). That one confusion explains L2's short-bin ceiling anchors (0.9997), the hand lexicon L4's
sink check had to fall back to, the benign Slack outputs the live agent lost, the poisoned_rag_exfil
documents no local detector sees, and BIPIA's weak email scenario (scratch/rca/v3/RCA_AND_PLAN.md F3).
An indirect prompt injection is, by definition, third-party data that addresses the model. ADR
answers that question directly, sentence by sentence.

HOW IT WAS BUILT (sentinel/eval/build_addressee_corpus.py, fit_addressee_model.py). Trained ONLY on
benign conversations -- prompts people wrote to an assistant vs the assistant's replies, the user's
pasted data and news -- so no injection was ever fitted on and every injection benchmark is zero-shot
for it. Encoder: the MiniLM DIDA already loads (no new model); head: frozen in
core/artifacts/addressee_model.json, with its training sources, controls and gate.

USE. Third-party channels only (retrieved documents, tool outputs, the text around a tool-call
argument). On the USER channel every message addresses the AI by design, so ADR says nothing there.

FAIL-SOFT, like every model here: no artifact, an artifact fitted on another embedding revision, or
any error -> None ("signal absent"), never "benign".
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path

import numpy as np

logger = logging.getLogger(__name__)

_ART = Path(__file__).resolve().parent / "artifacts" / "addressee_model.json"
_MISSING = object()
_cache = None

# The same sentence split and merge rule as core.text_windowing.split_into_windows (the unit ADR was
# trained on), kept here with character offsets so a caller can redact exactly what scored high --
# extended for SERIALISED tool output (v3 c03): agent tools return object dumps such as
# `Email(id_='26', sender='...', body='Hi Emma,\nThanks ...')` with ESCAPED newlines, which the
# sentence split never splits, so ADR was scoring serialisation syntax it had never seen (held-out
# AgentDojo benign windows: 20 % of sentences at >= 0.99). Escaped newlines and the `', key=` field
# boundaries of such dumps are window boundaries too, and each window is scored on its prose only
# (keys, quotes and brackets stripped; windows with too little prose score 0).
_SPLIT = re.compile(r"(?<=[.!?])\s+|\n+|(?:\\n)+|(?<=['\"]),\s*(?=[A-Za-z_]\w*=)|(?<=[)\]]),\s*(?=[A-Z]\w*\()")
_MIN_WINDOW_CHARS = 20
_MAX_WINDOWS = 40
_KEY = re.compile(r"\b[A-Za-z_]\w*=(?=['\"\[{(\w])")
_CTOR = re.compile(r"\b[A-Z]\w*\(")
_SYNTAX = re.compile(r"[\[\]{}()'\"]|\\[nt'\"]")
_MIN_PROSE_CHARS = 20


def prose(window: str) -> str:
    """The natural-language content of a window: serialisation keys, constructors, quotes and
    escapes removed, whitespace collapsed. '' when too little prose remains to judge."""
    t = _CTOR.sub(" ", window or "")
    t = _KEY.sub(" ", t)
    t = _SYNTAX.sub(" ", t)
    t = re.sub(r"\s+", " ", t).strip(" ,;:")
    letters = sum(ch.isalpha() for ch in t)
    if len(t) < _MIN_PROSE_CHARS or letters < 0.5 * len(t):
        return ""
    return t


def _load():
    global _cache
    if _cache is _MISSING:
        return None
    if _cache is not None:
        return _cache
    try:
        art = json.loads(_ART.read_text(encoding="utf-8"))
        import sentinel.config as cfg
        want = getattr(cfg, "EMBEDDING_MODEL_REVISION", None)
        if want and art.get("embedding_revision") != want:
            raise ValueError(f"ADR fitted on embedding revision {art.get('embedding_revision')}, config pins {want}")
        p = art["params"]
        art["_mean"] = np.asarray(art["mean"], dtype=np.float32)
        art["_scale"] = np.asarray(art["scale"], dtype=np.float32)
        if art["type"] == "lr":
            art["_w"] = (np.asarray(p["coef"], dtype=np.float32), float(p["intercept"]))
        elif art["type"] == "mlp":
            art["_w"] = (np.asarray(p["W1"], dtype=np.float32), np.asarray(p["b1"], dtype=np.float32),
                         np.asarray(p["W2"], dtype=np.float32), float(p["b2"]))
        else:
            raise ValueError(f"unknown ADR head type {art['type']!r}")
    except Exception as e:                                            # noqa: BLE001
        logger.warning(f"addressee model unavailable, ADR signal absent: {e}")
        _cache = _MISSING
        return None
    _cache = art
    return art


def reset_cache() -> None:
    """Drop the loaded artifact (tests; or after re-fitting)."""
    global _cache, _MEMO
    _cache = None
    _MEMO = {}


def available() -> bool:
    return _load() is not None


def _probs(art, E: np.ndarray) -> np.ndarray:
    Z = (E - art["_mean"]) / art["_scale"]
    if art["type"] == "lr":
        w, b = art["_w"]
        logit = Z @ w + b
    else:
        W1, b1, W2, b2 = art["_w"]
        logit = np.maximum(0.0, Z @ W1 + b1) @ W2 + b2
    return 1.0 / (1.0 + np.exp(-np.clip(logit, -60.0, 60.0)))


_MEMO: dict = {}


def score_windows(windows: list[str]) -> list[float] | None:
    """P(addressed to an AI) for each window (scored on its prose; no prose -> 0.0), or None if
    ADR is unavailable."""
    art = _load()
    if art is None:
        return None
    if not windows:
        return []
    texts = [prose(w) for w in windows]
    todo = [t for t in dict.fromkeys(texts) if t and t not in _MEMO]
    if todo:
        try:
            from sentinel.core.embedding import get_model
            E = np.asarray(get_model().encode(todo), dtype=np.float32)
        except Exception as e:                                        # noqa: BLE001
            logger.warning(f"ADR encoding failed: {e}")
            return None
        if len(_MEMO) > 50000:
            _MEMO.clear()
        for t, p in zip(todo, _probs(art, E)):
            _MEMO[t] = float(p)
    return [_MEMO[t] if t else 0.0 for t in texts]


def spans(text: str) -> list[tuple[int, int, str]]:
    """(start, end, window_text) per window, offsets into `text`; windows are built exactly like
    core.text_windowing.split_into_windows (sentences merged until >= 20 chars, at most 40)."""
    text = text or ""
    pieces, pos = [], 0
    for m in _SPLIT.finditer(text):
        seg = text[pos:m.start()]
        if seg.strip():
            lead = len(seg) - len(seg.lstrip())
            pieces.append((pos + lead, pos + len(seg.rstrip()), seg.strip()))
        pos = m.end()
    seg = text[pos:]
    if seg.strip():
        lead = len(seg) - len(seg.lstrip())
        pieces.append((pos + lead, pos + len(seg.rstrip()), seg.strip()))
    wins, buf = [], None
    for s, e, t in pieces:
        buf = (buf[0], e, f"{buf[2]} {t}") if buf else (s, e, t)
        if len(buf[2]) >= _MIN_WINDOW_CHARS:
            wins.append(buf)
            buf = None
    if buf:
        if wins:
            s0, _e0, t0 = wins[-1]
            wins[-1] = (s0, buf[1], f"{t0} {buf[2]}")
        else:
            wins.append(buf)
    if not wins:
        return [(0, len(text), text)] if text else []
    n = len(wins)
    if n <= _MAX_WINDOWS:
        return wins
    base, extra = divmod(n, _MAX_WINDOWS)
    out, i = [], 0
    for g in range(_MAX_WINDOWS):
        size = base + (1 if g < extra else 0)
        grp = wins[i:i + size]
        out.append((grp[0][0], grp[-1][1], " ".join(w[2] for w in grp)))
        i += size
    return out


def score_text(text: str) -> dict | None:
    """Max-over-windows ADR score for a piece of third-party text, with the argmax window.
    None if ADR is unavailable."""
    sp = spans(text)
    if not sp:
        return {"score": 0.0, "window": "", "n_windows": 0}
    ps = score_windows([w for _s, _e, w in sp])
    if ps is None:
        return None
    i = int(np.argmax(ps))
    return {"score": float(ps[i]), "window": sp[i][2], "start": sp[i][0], "end": sp[i][1],
            "n_windows": len(sp)}


def ai_addressed_spans(text: str, tau: float) -> list[tuple[int, int, float]] | None:
    """Character spans whose window scores >= tau (for surgical redaction). None if unavailable."""
    sp = spans(text)
    ps = score_windows([w for _s, _e, w in sp]) if sp else []
    if ps is None:
        return None
    return [(s, e, p) for (s, e, _w), p in zip(sp, ps) if p >= tau]


def redact(text: str, tau: float, marker: str = "[removed by DIDA: text addressed to the AI assistant]") -> tuple[str, int] | None:
    """`text` with every AI-addressed window replaced by `marker`; (text, n_removed). None if unavailable."""
    hits = ai_addressed_spans(text, tau)
    if hits is None:
        return None
    out, last = [], 0
    for s, e, _p in hits:
        out.append(text[last:s])
        out.append(marker)
        last = e
    out.append(text[last:])
    return "".join(out), len(hits)
