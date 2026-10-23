"""
Fit ADR, the addressee model (scratch/rca/v3/RCA_AND_PLAN.md Phase 2), and freeze it as
sentinel/core/artifacts/addressee_model.json.

Encoder: the MiniLM DIDA already loads (core.embedding.get_model, pinned revision) -- no new model.
Heads compared (declared before fitting): logistic regression (C in {0.1, 1, 10}, chosen on the
in-distribution dev split) and a one-hidden-layer MLP (256 ReLU units). Training data: benign
conversations only (build_addressee_corpus.py) -- no attack text is ever fitted on.

SELECTION RULE, v2 (declared before any v2 score was seen; v1's rule and its failure are recorded
in build_addressee_corpus.py). PRIMARY: window-level recall at 1 % benign-window FPR, positives =
held-out injection attempts (Lakera gandalf_ignore_instructions VALIDATION, gandalf_summarization
VALIDATION windows, deepset TEST label 1), negatives = windows of BIPIA TRAIN contexts, md5-ODD half
(never trained on: build_addressee_corpus uses the even half). The head with the higher primary wins;
within 0.01, the logistic head (simpler). SECONDARY, reported: document-level recall at 1 % FPR with
BIPIA's train attacks inserted into the odd-half contexts. BIPIA TEST, DIDA-Bench, AgentDojo,
InjecAgent and every other paper benchmark stay untouched for the final, held-out report.

REPORTED, not selected on: in-distribution dev AUROC; the length-only control AUROC (check C3 --
the corpus is length-matched, so this must stay near 0.5).

GATE G2 (declared in RCA_AND_PLAN.md): dev AUROC >= 0.95 and length-control AUROC <= 0.65.

    python -m sentinel.eval.fit_addressee_model [--no-mlp]
"""
from __future__ import annotations

import argparse
import datetime
import glob
import hashlib
import json
import random
import re
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "sentinel" / "eval" / "data" / "addressee"
BIPIA = ROOT / "sentinel" / "eval" / "data" / "bipia_local"
ART = ROOT / "sentinel" / "core" / "artifacts" / "addressee_model.json"
CACHE = ROOT / "scratch" / "rca" / "v3" / "emb_cache"
HUB = Path.home() / ".cache" / "huggingface" / "hub"


def _load(path):
    return [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]


def encode(texts: list[str]) -> np.ndarray:
    """MiniLM sentence embeddings, cached on disk by content hash."""
    from sentinel.config import EMBEDDING_MODEL_REVISION
    from sentinel.core.embedding import get_model
    CACHE.mkdir(parents=True, exist_ok=True)
    key = hashlib.md5(("\x00".join(texts) + EMBEDDING_MODEL_REVISION).encode("utf-8")).hexdigest()
    f = CACHE / f"{key}.npy"
    if f.exists():
        return np.load(f)
    e = np.asarray(get_model().encode(texts, batch_size=256, show_progress_bar=False), dtype=np.float32)
    np.save(f, e)
    return e


def auroc(y, s) -> float:
    from sklearn.metrics import roc_auc_score
    return float(roc_auc_score(y, s)) if len(set(y)) == 2 else float("nan")


def recall_at_fpr(y, s, fpr=0.01) -> tuple[float, float]:
    y, s = np.asarray(y), np.asarray(s)
    neg = np.sort(s[y == 0])
    if len(neg) == 0:
        return float("nan"), float("nan")
    k = int(np.ceil((len(neg) + 1) * (1 - fpr)))          # conformal-style benign quantile
    tau = float(neg[min(k, len(neg)) - 1]) if k <= len(neg) else float("inf")
    pos = s[y == 1]
    return float(np.mean(pos > tau)) if len(pos) else float("nan"), tau


class Head:
    """A frozen head over standardised embeddings: 'lr' or 'mlp'."""

    def __init__(self, kind, mean, scale, params):
        self.kind, self.mean, self.scale, self.p = kind, mean, scale, params

    def prob(self, E: np.ndarray) -> np.ndarray:
        Z = (E - self.mean) / self.scale
        if self.kind == "lr":
            logit = Z @ self.p["coef"] + self.p["intercept"]
        else:
            H = np.maximum(0.0, Z @ self.p["W1"] + self.p["b1"])
            logit = H @ self.p["W2"] + self.p["b2"]
        return 1.0 / (1.0 + np.exp(-np.clip(logit, -60, 60)))


def fit_heads(Xtr, ytr, Xdv, ydv, with_mlp=True, seed=20261018):
    from sklearn.linear_model import LogisticRegression
    from sklearn.neural_network import MLPClassifier
    mean = Xtr.mean(0)
    scale = Xtr.std(0)
    scale[scale == 0] = 1.0
    Ztr, Zdv = (Xtr - mean) / scale, (Xdv - mean) / scale
    heads, log = {}, {}
    best = None
    for C in (0.1, 1.0, 10.0):
        m = LogisticRegression(C=C, max_iter=3000)
        m.fit(Ztr, ytr)
        a = auroc(ydv, m.predict_proba(Zdv)[:, 1])
        log[f"lr_C{C}"] = a
        if best is None or a > best[0]:
            best = (a, C, m)
    _, C, m = best
    heads["lr"] = Head("lr", mean, scale, {"coef": m.coef_[0].astype(float), "intercept": float(m.intercept_[0]), "C": C})
    if with_mlp:
        mlp = MLPClassifier(hidden_layer_sizes=(256,), alpha=1e-4, early_stopping=True, max_iter=200,
                            random_state=seed)
        mlp.fit(Ztr, ytr)
        heads["mlp"] = Head("mlp", mean, scale, {
            "W1": mlp.coefs_[0].astype(float), "b1": mlp.intercepts_[0].astype(float),
            "W2": mlp.coefs_[1][:, 0].astype(float), "b2": float(mlp.intercepts_[1][0])})
        log["mlp"] = auroc(ydv, heads["mlp"].prob(Xdv))
    return heads, log


def windows(text: str) -> list[str]:
    from sentinel.core.text_windowing import split_into_windows
    return split_into_windows(text or "")


def _bipia_attacks(split: str) -> list[str]:
    out = []
    for f in (f"text_attack_{split}.json", f"code_attack_{split}.json"):
        p = BIPIA / f
        if p.exists():
            d = json.loads(p.read_text(encoding="utf-8"))
            for v in d.values():
                out.extend(x for x in v if isinstance(x, str))
    return out


def _bipia_contexts(split: str) -> list[str]:
    """Context text per BIPIA sample; the table scenario stores rows as a list."""
    out = []
    for scen in ("email", "table", "code"):
        p = BIPIA / scen / f"{split}.jsonl"
        if not p.exists():
            continue
        for r in _load(p):
            c = r.get("context")
            if isinstance(c, list):
                c = "\n".join(str(x) for x in c)
            if isinstance(c, str) and c.strip():
                out.append(c)
    return out


def selection_set(seed=20261018, max_docs=600):
    """BIPIA TRAIN, md5-ODD contexts only (the even half is training data): windows (attack vs
    context windows) and documents (attack inserted at a random sentence boundary vs the clean
    context)."""
    rng = random.Random(seed)
    atk = _bipia_attacks("train")
    ctx = [c for c in _bipia_contexts("train")
           if int(hashlib.md5(c.encode("utf-8")).hexdigest(), 16) % 2 == 1]
    rng.shuffle(ctx)
    ctx = ctx[:max_docs]
    docs, labels = [], []
    for c in ctx:
        parts = re.split(r"(?<=[.!?])\s+", c)
        i = rng.randrange(len(parts) + 1)
        a = rng.choice(atk)
        docs.append(" ".join(parts[:i] + [a] + parts[i:]))
        labels.append(1)
        docs.append(c)
        labels.append(0)
    win_pos = [w for a in atk for w in windows(a)]
    win_neg = [w for c in ctx for w in windows(c)]
    return {"docs": docs, "doc_labels": labels, "win_pos": win_pos, "win_neg": win_neg,
            "n_attacks": len(atk), "n_contexts": len(ctx)}


def doc_scores(head: Head, docs: list[str]) -> np.ndarray:
    wins, owner = [], []
    for i, d in enumerate(docs):
        for w in windows(d):
            wins.append(w)
            owner.append(i)
    p = head.prob(encode(wins))
    out = np.zeros(len(docs))
    for i, v in zip(owner, p):
        out[i] = max(out[i], v)
    return out


def heldout_injection_windows() -> list[str]:
    """Held-out injection attempts for the PRIMARY selection metric (never trained on)."""
    import pandas as pd
    out = []
    for pat, col, filt in (
            ("datasets--Lakera--gandalf_ignore_instructions/snapshots/*/data/validation-*.parquet", "text", None),
            ("datasets--Lakera--gandalf_summarization/snapshots/*/data/validation-*.parquet", "text", None),
            ("datasets--deepset--prompt-injections/snapshots/*/data/test-*.parquet", "text", "label")):
        paths = glob.glob(str(HUB / pat))
        if not paths:
            continue
        d = pd.read_parquet(paths[0])
        rows = d[d[filt].astype(str) == "1"][col] if filt else d[col]
        for t in rows:
            if isinstance(t, str) and t.strip():
                out.extend(windows(t))
    return out


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-mlp", action="store_true")
    a = ap.parse_args(argv)
    tr, dv = _load(DATA / "train.jsonl"), _load(DATA / "dev.jsonl")
    Xtr, ytr = encode([r["text"] for r in tr]), np.array([r["label"] for r in tr])
    Xdv, ydv = encode([r["text"] for r in dv]), np.array([r["label"] for r in dv])
    heads, sweep = fit_heads(Xtr, ytr, Xdv, ydv, with_mlp=not a.no_mlp)

    length_auc = auroc(ydv, [len(r["text"]) for r in dv])
    sel = selection_set()
    Ewp, Ewn = encode(sel["win_pos"]), encode(sel["win_neg"])
    inj = heldout_injection_windows()
    Einj = encode(inj)
    report = {}
    for name, h in heads.items():
        dv_auc = auroc(ydv, h.prob(Xdv))
        neg = h.prob(Ewn)
        # PRIMARY: held-out injection attempts vs held-out BIPIA context windows (odd half)
        yi = [1] * len(Einj) + [0] * len(Ewn)
        si = np.concatenate([h.prob(Einj), neg])
        i_rec, i_tau = recall_at_fpr(yi, si)
        # SECONDARY: BIPIA train attacks (windows, and inserted into documents)
        ys = [1] * len(Ewp) + [0] * len(Ewn)
        ss = np.concatenate([h.prob(Ewp), neg])
        w_rec, _w_tau = recall_at_fpr(ys, ss)
        ds = doc_scores(h, sel["docs"])
        d_rec, d_tau = recall_at_fpr(sel["doc_labels"], ds)
        report[name] = {"dev_auroc": dv_auc,
                        "primary_injection_window_auroc": auroc(yi, si),
                        "primary_injection_window_recall_at_1pct": i_rec, "primary_window_tau_1pct": i_tau,
                        "bipia_attack_window_auroc": auroc(ys, ss), "bipia_attack_window_recall_at_1pct": w_rec,
                        "bipia_doc_auroc": auroc(sel["doc_labels"], ds), "bipia_doc_recall_at_1pct": d_rec,
                        "bipia_doc_tau_1pct": d_tau, "n_injection_windows": len(inj)}
    key = "primary_injection_window_recall_at_1pct"
    pick = "lr"
    if "mlp" in report and report["mlp"][key] > report["lr"][key] + 0.01:
        pick = "mlp"
    h = heads[pick]
    g2 = {"dev_auroc>=0.95": report[pick]["dev_auroc"] >= 0.95, "length_control<=0.65": length_auc <= 0.65}
    from sentinel.config import EMBEDDING_MODEL, EMBEDDING_MODEL_REVISION
    stats = json.loads((DATA / "stats.json").read_text(encoding="utf-8"))
    params = {k: (v.tolist() if isinstance(v, np.ndarray) else v) for k, v in h.p.items()}
    art = {
        "model": "addressee", "version": 2, "type": pick,
        "question": "P(text is addressed to an AI system as a request), per sentence window",
        "embedding_model": EMBEDDING_MODEL, "embedding_revision": EMBEDDING_MODEL_REVISION,
        "mean": h.mean.tolist(), "scale": h.scale.tolist(), "params": params,
        "trained_on": stats, "n_train": int(len(ytr)), "n_dev": int(len(ydv)),
        "c_sweep_dev_auroc": sweep, "length_control_dev_auroc": length_auc,
        "selection_set": {"source": "held-out injection attempts (Lakera val, deepset test) vs BIPIA train "
                                    "contexts md5-odd; secondary BIPIA train attacks in odd contexts",
                          "n_attacks": sel["n_attacks"], "n_contexts": sel["n_contexts"],
                          "rule": "primary window recall @1% FPR, LR unless MLP better by > 0.01"},
        "report": report, "picked": pick,
        "gate": {"name": "G2", "checks": g2, "passed": all(g2.values())},
        "created": datetime.date.today().isoformat(),
    }
    ART.write_text(json.dumps(art), encoding="utf-8")
    print(json.dumps({k: v for k, v in art.items() if k not in ("mean", "scale", "params", "trained_on")}, indent=2))


if __name__ == "__main__":
    main()
