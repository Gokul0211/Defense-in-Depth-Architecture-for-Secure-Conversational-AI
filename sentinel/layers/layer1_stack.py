"""
L1 v12 stack (config.L1_STACK_V12, default off; scratch/rca/l1/TT_REDESIGN.md §14-§18, results.md §23).

Applied by layer1_check to USER text, after the shipped tiers (arm A) have produced their final score:
  z_FT   a fine-tuned DeBERTa-v3 stage (weights outside git, config.L1_FT_V12_DIR): logit margin, head + tail at 512
         tokens, z-scored over the three benign calibration pools
  z_S1   ENS3 (the local 4B read under the judge policy, core/artifacts/l1_llm_probe.npz) + 0.25 * z(ProtectAI v2)
  z_D24  a domain probe on decoder layer 24 of the same read (core/artifacts/l1_d24_probe.npz)
  score  max(z_S1, z_D24, z_FT)  -- or the learned stack over (z_ens3, z_D24, z_FT) when the artifact says so
  hold   arm A fired, no hard Tier-1 reason, z_S1 < t_auth          -> just below WARN (AUTH, v8)
  lift   score > tau (CAL group-conditional conformal, alpha 0.01)   -> at least WARN
Cascade (step E, results.md §23.2): the 4B read runs only when it can change the decision. Exactly skipped when arm A
fired on a hard Tier-1 reason (AUTH cannot hold it) or, for the max rule, when z_FT > tau (flagged either way);
approximately skipped when arm A did not fire and z_FT < b_skip (b_skip chosen on VAL so that VAL and CAL decisions are
identical to the full rule). Thresholds, z-statistics and b_skip: core/artifacts/l1_stack_v12.json.
Fail-soft: without the artifact or the fine-tuned weights nothing changes; without the 4B read nothing is held.
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import threading
import time
from pathlib import Path

logger = logging.getLogger(__name__)
_ART = Path(__file__).resolve().parents[1] / "core" / "artifacts"
_lock = threading.Lock()
_state: dict = {}


def load_artifact() -> dict | None:
    """The v12 stack artifact (+ the D24 probe vectors), or None when absent / built for another ENS3 probe."""
    if "art" in _state:
        return _state["art"]
    art = None
    p = _ART / "l1_stack_v12.json"
    try:
        if p.exists():
            import numpy as np
            art = json.loads(p.read_text(encoding="utf-8"))
            ens = _ART / "l1_llm_probe.npz"
            if art.get("ens3_probe_md5") and ens.exists() and \
                    hashlib.md5(ens.read_bytes()).hexdigest() != art["ens3_probe_md5"]:
                logger.warning("l1_stack_v12.json was calibrated on another ENS3 probe; the v12 stack is off")
                art = None
            else:
                z = np.load(_ART / art.get("d24_file", "l1_d24_probe.npz"))
                art["_d24"] = {"layer": int(z["layer"]), "mu": z["mu"].astype("float32"),
                               "sd": z["sd"].astype("float32"), "w": z["w"].astype("float32"),
                               "b": float(np.ravel(z["b"])[0]), "zmu": float(np.ravel(z["zmu"])[0]),
                               "zsd": float(np.ravel(z["zsd"])[0])}
    except Exception as e:                                       # noqa: BLE001 -- fail soft: stack off
        logger.warning(f"L1 v12 stack artifact unreadable: {e}")
        art = None
    _state["art"] = art
    return art


def ft_dir() -> Path:
    import sentinel.config as cfg
    return Path(os.path.expanduser(getattr(cfg, "L1_FT_V12_DIR", "~/.cache/sentinel/l1-ft-v12")))


class _FineTuned:
    """The fine-tuned stage, exactly as scored offline (tt52 Clf.score): [CLS] head + tail [SEP], fp16 autocast."""

    def __init__(self, d: Path, base: str, maxlen: int):
        import torch
        from transformers import AutoTokenizer
        self.torch = torch
        want = os.getenv("L1_FT_V12_DEVICE", "auto").strip().lower()      # auto | cuda | cpu
        self.dev = "cuda" if torch.cuda.is_available() and want != "cpu" else "cpu"
        self.tok = AutoTokenizer.from_pretrained(str(d))
        if base == "protectai":
            from transformers import AutoModelForSequenceClassification
            self.model = AutoModelForSequenceClassification.from_pretrained(str(d)).to(self.dev).eval()
            self.head = None
        else:
            from transformers import DebertaV2Config, DebertaV2Model
            sd = torch.load(d / "piguard_ft.pt", map_location="cpu", weights_only=True)
            self.model = DebertaV2Model(DebertaV2Config.from_pretrained(str(d)))
            self.model.load_state_dict(sd["encoder"])
            self.head = torch.nn.Linear(self.model.config.hidden_size, 2)
            self.head.load_state_dict(sd["head"])
            self.model, self.head = self.model.to(self.dev).eval(), self.head.to(self.dev).eval()
        if self.dev == "cuda" and os.getenv("L1_FT_V12_HALF", "false").lower() == "true":
            # fp16 weights (~0.37 GB instead of 0.74 GB beside the 4B model); scores move ~1e-3 vs the offline fp32 +
            # autocast scoring, so this is a measured option, not the default
            self.model = self.model.half()
            self.head = self.head.half() if self.head is not None else None
        self.keep = maxlen - 2

    def ids(self, text: str) -> list[int]:
        x = self.tok(text or "", add_special_tokens=False)["input_ids"]
        if len(x) > self.keep:
            x = x[:self.keep // 2] + x[-(self.keep - self.keep // 2):]
        return [self.tok.cls_token_id] + list(x) + [self.tok.sep_token_id]

    def margin(self, text: str) -> float:
        torch = self.torch
        inp = torch.tensor([self.ids(text)], device=self.dev)
        att = torch.ones_like(inp)
        with torch.no_grad(), torch.autocast(self.dev, dtype=torch.float16, enabled=self.dev == "cuda"):
            if self.head is None:
                lg = self.model(input_ids=inp, attention_mask=att).logits
            else:
                lg = self.head(self.model(input_ids=inp, attention_mask=att).last_hidden_state[:, 0, :])
        lg = lg.float()[0]
        return float(lg[1] - lg[0])


def _ft(art: dict):
    if "ft" not in _state:
        try:
            d = ft_dir()
            if not (d / "zstats.json").exists():
                raise FileNotFoundError(f"fine-tuned weights not found at {d} (scratch/rca/l1/tt55_export_stack.py)")
            zs = json.loads((d / "zstats.json").read_text(encoding="utf-8"))
            if abs(zs["zmu"] - art["ft"]["zmu"]) > 1e-6 or zs["base"] != art["ft"]["base"]:
                raise ValueError("fine-tuned weights do not match l1_stack_v12.json")
            _state["ft"] = _FineTuned(d, zs["base"], int(zs.get("maxlen", 512)))
        except Exception as e:                                   # noqa: BLE001 -- fail soft: stack off
            logger.warning(f"L1 v12 fine-tuned stage unavailable, the stack is off: {e}")
            _state["ft"] = None
    return _state["ft"]


def _protectai_z(art: dict, text: str) -> float | None:
    if "pai" not in _state:
        try:
            from sentinel.eval.baselines.injection_guards import ProtectAIv2Baseline
            m = ProtectAIv2Baseline()
            m._load()
            _state["pai"] = m
        except Exception as e:                                   # noqa: BLE001
            logger.warning(f"ProtectAI v2 unavailable for the v12 stack: {e}")
            _state["pai"] = None
    m = _state["pai"]
    if m is None:
        return None
    p = min(max(float(m.injection_probs([text], 1)[0]), 1e-7), 1 - 1e-7)
    return (math.log(p / (1 - p)) - art["pai_mu"]) / art["pai_sd"]


def _d24_z(art: dict, hidden: dict) -> float | None:
    d = art["_d24"]
    v = hidden.get(d["layer"])
    if v is None:
        return None
    x = float(((v - d["mu"]) / d["sd"]) @ d["w"] + d["b"])
    return (x - d["zmu"]) / d["zsd"]


def stack_decision(text: str, arm_a_fired: bool, hard_reason: bool, judge_flagged: bool = False) -> dict | None:
    """The v12 verdict for one USER text, given arm A's verdict. None = the stack cannot run (arm A stands).
    judge_flagged: a hosted-judge verdict >= 0.5 exists (never measured with AUTH: such an input is never held)."""
    import sentinel.config as cfg
    art = load_artifact()
    if art is None:
        return None
    t0 = time.perf_counter()
    tau, out = float(art["tau"]), {"tau": float(art["tau"]), "local_read": False}
    if arm_a_fired and hard_reason:
        out.update(flag=True, held=False, lifted=False, path="hard_tier1")
        return out
    with _lock:
        ft = _ft(art)
        if ft is None:
            return None
        z_ft = (ft.margin(text) - art["ft"]["zmu"]) / art["ft"]["zsd"]
    out["z_ft"] = round(z_ft, 4)
    use_cascade = getattr(cfg, "L1_STACK_CASCADE", True)
    if art["combine"] == "max" and z_ft > tau:
        out.update(flag=True, held=False, lifted=not arm_a_fired, path="ft_above_tau")
    elif use_cascade and not arm_a_fired and z_ft < float(art["b_skip"]):
        out.update(flag=False, held=False, lifted=False, path="ft_below_band")
    else:
        from sentinel.core.local_judge import local_judge_read
        kw = {"hidden_layers": (art["_d24"]["layer"],)}
        if getattr(cfg, "L1_STACK_EARLY_EXIT", False):
            kw["stop_after_layer"] = int(art["deepest_layer"])
        lj = local_judge_read(text, **kw)
        z_p = _protectai_z(art, text)
        if lj is None or lj.get("probe") is None or z_p is None:
            # no 4B read: nothing is held; lifted only by the stage that did run
            flag = arm_a_fired or (art["combine"] == "max" and z_ft > tau)
            out.update(flag=flag, held=False, lifted=flag and not arm_a_fired, path="no_local_read")
        else:
            z_e3 = float(lj["probe"])
            z_d = _d24_z(art, lj.get("hidden") or {})
            z_s1 = z_e3 + float(art["w_protectai"]) * z_p
            if art["combine"] == "stack":
                w, b = art["stack"]["weights"], float(art["stack"]["bias"])
                score = w[0] * z_e3 + w[1] * (z_d if z_d is not None else -1e9) + w[2] * z_ft + b
            else:
                score = max(z_s1, z_d if z_d is not None else -math.inf, z_ft)
            held = arm_a_fired and not hard_reason and not judge_flagged and z_s1 < float(art["t_auth"])
            fires = score > tau
            flag = (arm_a_fired and not held) or fires
            out.update(flag=flag, held=held and not fires, lifted=fires and not arm_a_fired, path="local_read",
                       local_read=True, z_s1=round(z_s1, 4), z_ens3=round(z_e3, 4),
                       z_d24=None if z_d is None else round(z_d, 4), score=round(float(score), 4))
    out["ms"] = round((time.perf_counter() - t0) * 1000, 1)
    return out


def apply_stack(result, text: str) -> None:
    """Mutates an L1Result for a USER text (layer1_check, config.L1_STACK_V12): AUTH hold / v12 lift."""
    import sentinel.config as cfg
    from sentinel.layers.layer1 import _tier1_reason
    warn = cfg.l1_warn_threshold()
    fired = result.score >= warn
    hard = fired and _tier1_reason(text, exclude_soft=True) is not None
    ts = result.tier_scores if isinstance(getattr(result, "tier_scores", None), dict) else None
    judge = (ts or {}).get("tier4_judge")
    v = stack_decision(text, fired, hard, judge_flagged=judge is not None and judge >= 0.5)
    if v is None:
        return
    v["arm_a_score"] = round(float(result.score), 6)
    if ts is not None:
        ts["l1_stack_v12"] = v
    from sentinel.layers.layer1 import _threat_class_bands
    hi, med = _threat_class_bands()
    if fired and not v["flag"]:
        result.score = min(result.score, warn - 1e-6)
        result.threat_class = "INJECTION" if result.score > hi else ("SUSPICIOUS" if result.score > med else "CLEAN")
        result.confidence = result.score if result.threat_class != "CLEAN" else 1.0 - result.score
        result.reason = (f"Held below WARN by the v12 stack: no hard Tier-1 reason and the local probe ensemble "
                         f"reads it as benign (z_S1 {v.get('z_s1')} < {load_artifact()['t_auth']})")
    elif not fired and v["flag"]:
        result.score = warn
        if result.threat_class == "CLEAN":
            result.threat_class = "INJECTION" if warn > hi else "SUSPICIOUS"
        result.confidence = warn
        result.reason = (f"Flagged by the v12 stack (score {v.get('score', v.get('z_ft'))} > {v['tau']:.3f}, "
                         f"path {v['path']})")
        result.tier_used = 4


def reset_stack():
    """Tests / reloads only."""
    _state.clear()
