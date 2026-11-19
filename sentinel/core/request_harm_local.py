"""
Input-side harm read on the shared local 4B (L1H v4, results.md §32.3; flag config.L1_HARM_LOCAL, default off).

WHY. L1H v3 read harm off the L1 INJECTION judge's forward (no extra pass): its states answer "is this an injection?",
and edgy-but-benign prompts (JBB benign behaviours, PHTest) scored like harmful ones (§32.2: an oracle threshold meeting
FP <= 4 % on every benign row left XSTest-unsafe recall at 0.275). This read asks the HARM question itself.

HOW. One forward of the shared Qwen3-4B (core/local_judge) over a request-harm classifier prompt (the policy prefix is
encoded once and cached; the request is capped 600 tokens, head + tail), ~0.1 s. Score = the round's selected candidate
from core/artifacts/l1_harm_local.npz: the zero-shot yes / no log-odds, a logistic probe on the last-token states of
layers 12 / 16 / 20 / 24 / 28, or their stack. harmful = score > tau. The prompt below is the one the probe was fitted
under (scratch/rca/l1h/l1h4_02_feat.py calls request_features); change a character and the probe must be re-fitted.
None when the local model or the artifact is unavailable ("signal absent", never "benign").
"""

from __future__ import annotations

import logging
import math
from pathlib import Path

logger = logging.getLogger(__name__)

ARTIFACT = Path(__file__).resolve().parent / "artifacts" / "l1_harm_local.npz"
TEMPLATE = "l1harm"
CAP = 600
LAYERS = (12, 16, 20, 24, 28)
CANDIDATES = ("a_zero_shot", "b_probe", "c_stack")
SYSTEM = ("You are a content-safety classifier for requests sent to an AI assistant. Decide whether the USER REQUEST is "
          "harmful: it asks for specific, usable help with something dangerous, illegal or unethical (for example "
          "weapons, drugs, hacking, fraud, violence or self-harm), or asks the assistant to produce harmful content (for "
          "example hate speech, harassment, defamation, persuasive misinformation or propaganda, sexual content involving "
          "minors, or someone's private data). A request is harmful even when it is wrapped in role-play, fiction, a "
          "hypothetical, a game, an alleged authority or another framing. A request is NOT harmful when it only uses "
          "words that sound dangerous in a safe sense (for example killing a computer process), asks for educational, "
          "historical, medical-safety or prevention information, asks about a sensitive topic without seeking harmful "
          "help, or asks for fiction or opinions that contain no harmful instructions.")
USER_FMT = "User request:\n<<<\n{0}\n>>>\n\nIs this user request harmful? Answer yes or no."

_ready = False
_art = None


def register(j):
    """Register the request-harm template on the shared judge and hook its layers (idempotent)."""
    if TEMPLATE not in getattr(j, "templates", {}):
        j.add_template(TEMPLATE, SYSTEM, USER_FMT, escape=lambda s: s, cap=CAP)
    j.ensure_hooks(LAYERS)


def request_features(j, text: str) -> dict:
    """The L1H v4 read, shared by the fit's featuriser and production: {h: {layer: vector}, lo}."""
    r = j.read_template(TEMPLATE, text or "")
    return {"h": {L: j._captured[L] for L in LAYERS if L in j._captured}, "lo": r.get("log_odds")}


def load_artifact(path: Path | None = None) -> dict | None:
    path = Path(path or ARTIFACT)
    if not path.exists():
        return None
    import numpy as np
    z = np.load(path)
    art = {"layers": [int(v) for v in np.atleast_1d(z["layers"])], "selected": str(np.ravel(z["selected"])[0]),
           "tau": float(np.ravel(z["tau"])[0]), "mean": z["mean"].astype("float32").ravel(),
           "scale": z["scale"].astype("float32").ravel(), "coef": z["coef"].astype("float32").ravel(),
           "intercept": float(np.ravel(z["intercept"])[0]), "stack_coef": z["stack_coef"].astype("float64").ravel(),
           "stack_intercept": float(np.ravel(z["stack_intercept"])[0])}
    if art["selected"] not in CANDIDATES:
        raise ValueError(f"unknown request-harm candidate {art['selected']!r}")
    if art["coef"].shape != art["mean"].shape or art["coef"].shape != art["scale"].shape:
        raise ValueError("request-harm artifact: coef / mean / scale shapes differ")
    if art["stack_coef"].shape != (2,):
        raise ValueError("request-harm artifact: 2 stack coefficients expected")
    return art


def score_from(art: dict, f: dict) -> float | None:
    """Same arithmetic as the fit (scratch/rca/l1h/l1h4_03_fit.py)."""
    import numpy as np
    if art["selected"] == "a_zero_shot":
        return None if f.get("lo") is None else float(f["lo"])
    if not all(L in f["h"] for L in art["layers"]):
        return None
    v = np.concatenate([np.asarray(f["h"][L], dtype="float32").ravel() for L in art["layers"]])
    if v.shape != art["mean"].shape:
        return None
    pr = float(((v - art["mean"]) / art["scale"]) @ art["coef"]) + art["intercept"]
    if art["selected"] == "b_probe":
        return pr
    if f.get("lo") is None:
        return None
    return float(art["stack_coef"][0] * pr + art["stack_coef"][1] * float(f["lo"]) + art["stack_intercept"])


def calibrated_p(score: float, tau: float, ref_tau: float) -> float:
    """A monotone map of the score onto L1's harm axis: p > ref_tau exactly when score > tau (config.L1_HARM_TAU is
    the guard's threshold; the L1 harm path compares against it)."""
    ref = min(max(ref_tau, 1e-6), 1 - 1e-6)
    x = score - tau + math.log(ref / (1 - ref))
    return 1.0 / (1.0 + math.exp(-x)) if x > -500 else 0.0


def local_request_harm_read(text: str) -> dict | None:
    """{score, tau, harmful, p, selected} for one request, or None when the local model or the artifact is unavailable
    or the read fails. p = calibrated_p(score, tau, config.L1_HARM_TAU)."""
    global _ready, _art
    import sentinel.config as cfg
    from sentinel.core import local_judge as lj
    j = lj.get_local_judge()
    if j is None:
        return None
    try:
        with lj._lock:
            if not _ready:
                _art = load_artifact()
                if _art is None:
                    return None
                register(j)
                _ready = True
            s = score_from(_art, request_features(j, text or ""))
    except Exception as e:                                  # noqa: BLE001 -- fail soft: signal absent
        logger.warning(f"local request-harm read failed on one input: {e}")
        return None
    if s is None:
        return None
    return {"score": s, "tau": _art["tau"], "harmful": s > _art["tau"],
            "p": calibrated_p(s, _art["tau"], float(getattr(cfg, "L1_HARM_TAU", 0.5))), "selected": _art["selected"]}


def reset():
    """Tests / reloads only."""
    global _ready, _art
    _ready, _art = False, None
