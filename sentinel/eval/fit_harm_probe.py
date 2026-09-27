"""
Fit and FREEZE L1's off-corpus harm probe.

    python -m sentinel.eval.fit_harm_probe            # dry run, prints only
    python -m sentinel.eval.fit_harm_probe --write    # writes the artifact

WHAT THIS IS AND WHY IT EXISTS. L1's four shipped tiers all ask a version of
"does this look like a conventional injection attempt". That question is answered
well on TensorTrust (recall 0.8947) and poorly on WildJailbreak (AUROC 0.5694),
and the reason is structural rather than a tuning failure: WildJailbreak's benign
class (`adversarial_benign`, n=210) is ADVERSARIALLY STYLE-MATCHED to its
malicious class -- jailbreak-phrased prompts with genuinely harmless intent,
included precisely to catch detectors that key on phrasing. A style detector
cannot separate them even in principle, because both classes have the style.

What separates them is INTENT. This probe supplies that missing axis: a linear
readout of the sentence embedding trained to answer "is the underlying request
harmful", fitted on corpora chosen so that the corpora it is evaluated on are
never seen.

    fit on   JailbreakBench harmful behaviours (n=100)
             Alpaca benign instructions, rows 500-2000 (n=1500)
    held out WildJailbreak, TensorTrust, sentinel_bench, Alpaca rows 0-500

MEASURED, ALL ZERO-SHOT (see results.md 8c.3 for the controls):

    WildJailbreak   0.5694 -> 0.8105   (probe alone)
    sentinel_bench  0.8094 -> 0.8670
    TensorTrust vs Alpaca benign       0.9326

and, fused into L1 as this module's frozen calibration prescribes:

    WildJailbreak   0.5694 -> 0.7835      TensorTrust recall 0.8947 -> 0.9228
    sentinel_bench  0.8094 -> 0.8561      Alpaca FPR        0.0300 -> 0.0080

CONTROLS THAT HAD TO PASS FIRST, because this project has already had two
apparent breakthroughs turn out to be corpus artifacts:

    shape-only transfer (no semantics)     0.4137   below chance
    permuted fit labels, 50 refits         0.5076   [0.3416, 0.6384]
    fit-set bootstrap, 200 refits          0.7992   CI [0.7723, 0.8275]

THE DISCLOSURE THAT COMES WITH IT, stated here because it is a real cost.
JailbreakBench and Alpaca are BOTH reported L1 rows (`runner.py`'s L1 dataset
list). Fitting on them means JailbreakBench is no longer a zero-shot row for this
component, and Alpaca must be reported on rows 0-500, which are never fitted on.
That is the price of supervision and it is paid explicitly rather than hidden.

WHY THE CALIBRATION QUANTILES ARE WHAT THEY ARE. The probe's raw output is a
logistic probability on its own scale, so it is mapped onto the shared 0.50/0.85
axis by `rescale_layer_score` using (warn, block) taken as benign quantiles of the
FIT half -- never of anything evaluated. The quantile pair was selected by a rule
fixed before the numbers were read: *the probe's benign budget must not exceed
L1's own measured benign rate*, so adding a tier cannot spend more false-positive
budget than the layer already had. Measured:

    quantiles      WJB      SB    TT recall   Alpaca FPR
    0.95 /0.99     0.7845  0.8746   0.9404      0.0360   <- exceeds L1's 0.0300
    0.99 /0.999    0.7835  0.8561   0.9228      0.0080   <- selected
    0.995/0.9999   0.7797  0.8478   0.9053      0.0040

THE ONE THING THAT GETS WORSE, recorded because it is inherent, not incidental.
False positives on WildJailbreak's `adversarial_benign` over-refusal set rise
from 0.2619 to 0.4095. A detector that is genuinely better at recognising harmful
intent will also refuse more prompts that merely sound like attacks. That is a
policy trade-off for the deployer, which is why this ships behind
`L1_HARM_PROBE_TIER`, default OFF.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime
from pathlib import Path

import numpy as np

_ARTIFACT_DIR = Path(__file__).resolve().parents[1] / "core" / "artifacts"
_DATA = Path(__file__).resolve().parent / "data"

FIT_HARMFUL = ("jailbreakbench", None)
FIT_BENIGN_ROWS = (500, 2000)
EVAL_BENIGN_ROWS = (0, 500)
C = 0.01
WARN_QUANTILE = 0.99
BLOCK_QUANTILE = 0.999
HELD_OUT = ["wildjailbreak", "tensortrust", "sentinel_bench",
            f"alpaca rows {EVAL_BENIGN_ROWS[0]}-{EVAL_BENIGN_ROWS[1]}"]


def _sha256(p: Path) -> str:
    h = hashlib.sha256()
    h.update(p.read_bytes())
    return h.hexdigest()


def _cache_path(name: str) -> Path:
    p = _DATA / "cache" / name / "test" / "samples.jsonl"
    return p if p.exists() else _DATA / name / "test.jsonl"


def _load(name: str, cap: int | None = None):
    p = _cache_path(name)
    rows = [json.loads(l) for l in p.open(encoding="utf-8") if l.strip()]
    if cap:
        rows = rows[:cap]
    return rows, p


def _embed(texts: list[str]) -> np.ndarray:
    from sentinel.core.embedding import get_model
    m = get_model()
    return np.vstack([np.asarray(m.encode(texts[i:i + 64]))
                      for i in range(0, len(texts), 64)])


def fit():
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler

    jbb_rows, jbb_path = _load(FIT_HARMFUL[0])
    alp_rows, alp_path = _load("alpaca", cap=FIT_BENIGN_ROWS[1])

    harmful = [r["text"] for r in jbb_rows if r["label"] == "malicious"]
    benign = [r["text"] for r in alp_rows[FIT_BENIGN_ROWS[0]:FIT_BENIGN_ROWS[1]]
              if r["label"] != "malicious"]
    if not harmful or not benign:
        raise SystemExit("fit corpora are empty -- run the loaders first")

    X = _embed(harmful + benign)
    y = np.array([1] * len(harmful) + [0] * len(benign))

    clf = make_pipeline(StandardScaler(),
                        LogisticRegression(max_iter=5000, C=C))
    clf.fit(X, y)

    scaler = clf.named_steps["standardscaler"]
    lr = clf.named_steps["logisticregression"]

    # the probe's own benign scores, used ONLY to place the axis anchors
    benign_scores = clf.predict_proba(X[len(harmful):])[:, 1]
    warn = float(np.quantile(benign_scores, WARN_QUANTILE))
    block = float(np.quantile(benign_scores, BLOCK_QUANTILE))
    if block <= warn:
        block = warn + 1e-9

    from sentinel.config import EMBEDDING_MODEL, EMBEDDING_MODEL_REVISION

    artifact = {
        "schema": "l1_harm_probe/v1",
        "embedding_model": EMBEDDING_MODEL,
        "embedding_revision": EMBEDDING_MODEL_REVISION,
        "dim": int(X.shape[1]),
        "mean": scaler.mean_.astype(float).tolist(),
        "scale": scaler.scale_.astype(float).tolist(),
        "coef": lr.coef_[0].astype(float).tolist(),
        "intercept": float(lr.intercept_[0]),
        "warn_threshold": warn,
        "block_threshold": block,
    }
    provenance = {
        "artifact": "l1_harm_probe.json",
        "frozen_at": datetime.now().isoformat(timespec="seconds"),
        "fit_harmful_corpus": FIT_HARMFUL[0],
        "fit_harmful_source": str(jbb_path),
        "fit_harmful_sha256": _sha256(jbb_path),
        "n_harmful": len(harmful),
        "fit_benign_corpus": f"alpaca rows {FIT_BENIGN_ROWS[0]}-{FIT_BENIGN_ROWS[1]}",
        "fit_benign_source": str(alp_path),
        "fit_benign_sha256": _sha256(alp_path),
        "n_benign": len(benign),
        "C": C,
        "warn_quantile": WARN_QUANTILE,
        "block_quantile": BLOCK_QUANTILE,
        "quantile_selection_rule":
            "the probe's benign budget on the fit half must not exceed L1's own "
            "measured benign rate (Alpaca FPR 0.0300), so adding a tier cannot "
            "spend more false-positive budget than the layer already had",
        "held_out_corpora": HELD_OUT,
        "held_out_rationale":
            "WildJailbreak, TensorTrust and sentinel_bench carry every claim this "
            "probe is evaluated against and are never fitted on. Alpaca is split: "
            "rows 500-2000 fit, rows 0-500 evaluate, disjoint by construction. "
            "JailbreakBench is a reported L1 row and is RETIRED as a zero-shot row "
            "for this component by being fitted on -- see the module docstring.",
        "controls_passed": {
            "shape_only_transfer_wildjailbreak": 0.4137,
            "permuted_labels_mean_50_refits": 0.5076,
            "fitset_bootstrap_mean_200_refits": 0.7992,
            "fitset_bootstrap_ci95": [0.7723, 0.8275],
        },
    }
    return artifact, provenance, benign_scores


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--write", action="store_true",
                    help="write the frozen artifact (default: dry run)")
    args = ap.parse_args()

    artifact, provenance, benign_scores = fit()
    print(f"fitted on {provenance['n_harmful']} harmful + "
          f"{provenance['n_benign']} benign, dim={artifact['dim']}")
    print(f"benign score quantiles: "
          f"median={np.median(benign_scores):.6f} "
          f"q{WARN_QUANTILE}={artifact['warn_threshold']:.6f} "
          f"q{BLOCK_QUANTILE}={artifact['block_threshold']:.6f}")
    print(f"held out: {', '.join(HELD_OUT)}")

    if not args.write:
        print("\ndry run -- pass --write to freeze")
        return

    _ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    path = _ARTIFACT_DIR / "l1_harm_probe.json"
    path.write_text(json.dumps(artifact, indent=1), encoding="utf-8")
    provenance["artifact_sha256"] = _sha256(path)
    (_ARTIFACT_DIR / "l1_harm_probe.provenance.json").write_text(
        json.dumps(provenance, indent=2), encoding="utf-8")
    print(f"\nwrote {path}")
    print(f"wrote {_ARTIFACT_DIR / 'l1_harm_probe.provenance.json'}")


if __name__ == "__main__":
    main()
