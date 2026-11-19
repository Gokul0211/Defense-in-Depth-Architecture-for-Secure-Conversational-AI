"""
L3 v4 multi-turn defence (results.md §34 / §34.2; flag config.L3_MT_V4, default off).

WHY. The shipped L3 reads embeddings of each user turn against fixed harm anchors; on human multi-turn jailbreaks (MHJ)
it catches 8 % (§29), and 53 of MHJ's 110 test attacks never show their intent in the user turns at all. Two signals on
the shared local 4B close the two halves:
  probe  per USER turn: the 4B reads the user-turn history ("User: <turn>" lines, whitespace collapsed, <= 1,200
         characters per turn) under the L1 judge policy (LocalJudge.read, early exit after layer 24); a logistic probe on
         the last-token states of layers 16 / 20 / 24 (artifact core/artifacts/l3_mt_probe.npz). The session is flagged
         from the first prefix whose score exceeds the artifact's tau on (a latch: the evaluated decision rule is "any
         prefix").
  reply  per assistant REPLY (L5's output stage): the v6 pair-read probe (harm_local variant D) with L3's own threshold,
         calibrated on the protected model's replies to benign multi-turn chats (artifact core/artifacts/l3_mt_reply.npz,
         a variant-D harm artifact whose tau is tau_L3).
The arithmetic is the evaluated one (scratch/rca/l3/l3v4_02_feat.py render / fp16 features, l3v4_07_test.py scoring,
l3v4_09_reply_l3.py reply read). FAIL-SOFT: no local model or artifact -> None ("signal absent", never "benign").
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path

logger = logging.getLogger(__name__)

_ART = Path(__file__).resolve().parents[1] / "core" / "artifacts"
PROBE_ART = _ART / "l3_mt_probe.npz"
REPLY_ART = _ART / "l3_mt_reply.npz"
LAYERS = (16, 20, 24)
_MAX_TURN_CHARS = 1200

_lock = threading.Lock()
_sessions: dict[str, dict] = {}
_probe: dict | None = None
_probe_loaded = False
_reply_art: dict | None = None
_reply_loaded = False


def render(turns, k=None) -> str:
    """The user-turn history exactly as the probe was fitted on (l3v4_02_feat.render)."""
    return "\n".join("User: " + " ".join(str(t).split())[:_MAX_TURN_CHARS] for t in turns[:k])


def load_probe(path: Path | None = None) -> dict | None:
    path = Path(path or PROBE_ART)
    if not path.exists():
        return None
    import numpy as np
    z = np.load(path)
    art = {"mu": z["mu"].astype("float32").reshape(1, -1), "sd": z["sd"].astype("float32").reshape(1, -1),
           "coef": z["coef"].astype("float32").reshape(-1), "intercept": float(np.ravel(z["intercept"])[0]),
           "tau": float(np.ravel(z["tau"])[0]), "layers": [int(v) for v in np.atleast_1d(z["layers"])]}
    if tuple(art["layers"]) != LAYERS or art["coef"].shape[0] != art["mu"].shape[1]:
        raise ValueError("l3_mt_probe.npz: layers / shapes do not match the evaluated probe")
    return art


def probe_score(art: dict, hidden: dict) -> float | None:
    """Score of one prefix from the read's hidden states {layer: vector}: fp16 round trip (the fitted features were
    stored as fp16), standardised, logistic decision (l3v4_07_test.py arithmetic)."""
    import numpy as np
    if not all(L in hidden for L in LAYERS):
        return None
    x = np.stack([np.asarray(hidden[L]) for L in LAYERS]).astype(np.float16).astype(np.float32).reshape(1, -1)
    if x.shape[1] != art["mu"].shape[1]:
        return None
    return float((((x - art["mu"]) / art["sd"]) @ art["coef"])[0] + art["intercept"])


def mt_turn(session_id: str, user_input: str) -> dict | None:
    """Record one user turn and read the history so far. {score, tau, margin, fired, latched} or None (signal absent)."""
    global _probe, _probe_loaded
    from sentinel.core import local_judge as lj
    st = _sessions.setdefault(session_id, {"turns": [], "latched": False, "max_margin": None})
    st["turns"].append(user_input or "")
    j = lj.get_local_judge()
    if j is None:
        return None
    try:
        with lj._lock:
            if not _probe_loaded:
                _probe = load_probe()
                _probe_loaded = True
                if _probe is not None:
                    j.ensure_hooks(LAYERS)
            if _probe is None:
                return None
            r = j.read(render(st["turns"]), stop_after_layer=max(LAYERS), hidden_layers=LAYERS)
            s = probe_score(_probe, r.get("hidden") or {})
    except Exception as e:                                  # noqa: BLE001 -- fail soft
        logger.warning(f"L3 multi-turn probe failed on one turn: {e}")
        return None
    if s is None:
        return None
    m = s - _probe["tau"]
    st["latched"] = st["latched"] or m > 0
    st["max_margin"] = m if st["max_margin"] is None else max(st["max_margin"], m)
    return {"score": s, "tau": _probe["tau"], "margin": m, "fired": m > 0, "latched": st["latched"]}


def mt_reply(request: str, reply: str) -> dict | None:
    """The L3 reply signal on one (user turn, reply): {score, tau, fired} or None (signal absent)."""
    global _reply_art, _reply_loaded
    from sentinel.core import local_judge as lj
    from sentinel.layers.layer5_output import harm_local as hl
    j = lj.get_local_judge()
    if j is None:
        return None
    try:
        with lj._lock:
            if not _reply_loaded:
                _reply_art = hl.load_harm_artifact(REPLY_ART)
                _reply_loaded = True
                if _reply_art is not None and _reply_art["variant"] not in hl.PAIR_VARIANTS:
                    raise ValueError("l3_mt_reply.npz must be a pair-read (variant D) artifact")
                if _reply_art is not None:
                    hl.register_pair(j)
            if _reply_art is None:
                return None
            s = hl.harm_score_pair(_reply_art, hl.pair_features(j, request or "", reply or ""))
    except Exception as e:                                  # noqa: BLE001 -- fail soft
        logger.warning(f"L3 multi-turn reply signal failed on one reply: {e}")
        return None
    if s is None:
        return None
    return {"score": s, "tau": _reply_art["tau"], "fired": s > _reply_art["tau"]}


def reset_mt_state():
    """Tests / demo reset: sessions and loaded artifacts."""
    global _probe, _probe_loaded, _reply_art, _reply_loaded
    _sessions.clear()
    _probe, _probe_loaded, _reply_art, _reply_loaded = None, False, None, False
