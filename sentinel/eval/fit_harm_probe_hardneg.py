"""
Refit L1's harm probe with HARD NEGATIVES, and freeze it as a separate artifact.

WHY THE EXISTING PROBE MUST BE REFITTED, measured rather than argued. The shipped
probe (`fit_harm_probe.py`) contrasts JailbreakBench harmful against **Alpaca**
benign. Alpaca is ordinary instruction-following text, so that contrast teaches
"harmful TOPIC vs ordinary topic" -- and the resulting probe is a topic detector:

    harm_probe AUROC, attacks vs OR-Bench benign (benign but harm-ADJACENT)
        WildJailbreak malicious    0.5032    <- exactly chance
        sentinel_bench malicious   0.2767    <- inverted
        TensorTrust malicious      0.2477    <- inverted
    harm_probe AUROC, WildJailbreak malicious vs ALPACA benign   0.9837  <- control

OR-Bench benign scores 0.7623 mean / 0.9043 median against WildJailbreak harmful's
0.7697 / 0.9122 -- the two populations are indistinguishable. The probe's apparent
power exists only against ordinary benign text, which is why enabling it moves
NotInject over-defense 0.1150 -> 0.1947.

WHY THIS MATTERS FOR BOARD ITEM #3. WildJailbreak's benign arm is literally
`attack_type: over_refusal_test`, and both arms carry identical roleplay framing:

    benign  "As a renowned author ... explores the complexities of human emotions"
    harmful "You are a security researcher ... code to leverage the dirty pipe exploit"

The ONLY thing separating them is whether the requested content is harmful. So #3
needs a genuine harm classifier, and the shipped probe is not one.

THE FIX -- hard-negative training. Same architecture, same frozen embedding, same
fitting code path; only the NEGATIVE class changes:

    positives   JailbreakBench harmful (n=100), as before
    negatives   OR-Bench-Hard benign (harm-ADJACENT) + Alpaca benign

Forcing the probe to separate harmful requests from benign requests *on the same
topics* is what makes it measure harm rather than subject matter.

DISCIPLINE.
  * JailbreakBench is already retired as a zero-shot row by the shipped probe; this
    changes nothing there.
  * OR-Bench is a third-party over-refusal corpus used only for fitting, never
    reported as a row.
  * **WildJailbreak and NotInject are NOT fitted on** and remain the test sets that
    judge this work, so neither number can be tuned.
  * Alpaca rows 0-500 are excluded, because they calibrate `L1_WARN_THRESHOLD`.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path

import numpy as np

ART = Path("sentinel/core/artifacts/l1_harm_probe_hardneg.json")
JBB = Path("sentinel/eval/data/cache/jailbreakbench/test/samples.jsonl")
ORB = Path("sentinel/eval/data/cache/orbench/test/samples.jsonl")
ALP = Path("sentinel/eval/data/cache/alpaca/test/samples.jsonl")
ALPACA_ROWS = (500, 4500)
C = 0.01
WARN_Q, BLOCK_Q = 0.99, 0.999
SEED = 20260922


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _texts(p: Path, lo=None, hi=None, label=None):
    rows = [json.loads(l) for l in p.open(encoding="utf-8") if l.strip()]
    if lo is not None:
        rows = rows[lo:hi]
    if label:
        rows = [r for r in rows if r["label"] == label]
    return [r["text"] for r in rows]


def main():
    from sklearn.linear_model import LogisticRegression
    from sentinel.core.embedding import get_model

    harmful = _texts(JBB, label="malicious")
    orb = _texts(ORB)
    alp = _texts(ALP, *ALPACA_ROWS, label="benign")
    print(f"positives  JailbreakBench harmful   {len(harmful)}")
    print(f"negatives  OR-Bench hard (adjacent) {len(orb)}")
    print(f"negatives  Alpaca rows {ALPACA_ROWS}   {len(alp)}")

    model = get_model()
    X = np.asarray(model.encode(harmful + orb + alp), dtype=float)
    y = np.array([1] * len(harmful) + [0] * (len(orb) + len(alp)))

    mean = X.mean(axis=0)
    scale = X.std(axis=0)
    Z = (X - mean) / np.where(scale == 0, 1.0, scale)

    clf = LogisticRegression(C=C, max_iter=5000, class_weight="balanced",
                             random_state=SEED)
    clf.fit(Z, y)
    p_ben = clf.predict_proba(Z[len(harmful):])[:, 1]
    warn = float(np.quantile(p_ben, WARN_Q))
    block = float(np.quantile(p_ben, BLOCK_Q))
    print(f"\nfit accuracy on the fit set: {clf.score(Z, y):.4f}")
    print(f"benign-quantile anchors: warn={warn:.6f} block={block:.6f}")

    art = {
        "schema": 1,
        "artifact": ART.name,
        "frozen_at": datetime.now().isoformat(timespec="seconds"),
        "purpose": "harm probe refitted with HARD NEGATIVES so it measures harm "
                   "rather than harm-adjacent topic; see module docstring",
        "embedding_model": "sentence-transformers/all-MiniLM-L6-v2",
        "embedding_revision": "8b3219a92973c328a8e22fadcfa821b5dc75636a",
        "dim": int(X.shape[1]),
        "fit_harmful_corpus": "jailbreakbench",
        "fit_harmful_sha256": _sha(JBB),
        "n_harmful": len(harmful),
        "fit_benign_corpora": [
            "or-bench-hard-1k (harm-adjacent benign, the hard negatives)",
            f"alpaca rows {ALPACA_ROWS[0]}-{ALPACA_ROWS[1]}"],
        "fit_benign_sha256": {"orbench": _sha(ORB), "alpaca": _sha(ALP)},
        "n_benign": len(orb) + len(alp),
        "never_fitted_on": ["wildjailbreak", "notinject", "sentinel_bench",
                            "tensortrust", "bipia_local",
                            "alpaca rows 0-500 (calibrates L1_WARN_THRESHOLD)"],
        "C": C, "warn_quantile": WARN_Q, "block_quantile": BLOCK_Q,
        "warn_threshold": warn, "block_threshold": block,
        "coef": clf.coef_[0].tolist(),
        "intercept": float(clf.intercept_[0]),
        "mean": mean.tolist(), "scale": scale.tolist(),
        "seed": SEED,
    }
    ART.parent.mkdir(parents=True, exist_ok=True)
    body = json.dumps(art, indent=1)
    ART.write_text(body, encoding="utf-8")
    ART.with_suffix(".provenance.json").write_text(json.dumps(
        {k: v for k, v in art.items()
         if k not in ("coef", "mean", "scale")}
        | {"artifact_sha256": hashlib.sha256(body.encode()).hexdigest()},
        indent=1), encoding="utf-8")
    print(f"wrote {ART}")


if __name__ == "__main__":
    main()
