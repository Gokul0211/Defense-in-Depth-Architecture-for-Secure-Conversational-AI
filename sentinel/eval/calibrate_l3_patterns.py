"""
Calibrate L3's HARM_ANCHOR_PHRASES against MHJ's weak tactics (Direct
Request, Obfuscation) using the TRAIN split only, then report a
confirmatory (held-out) check against the TEST split. Same train/test
discipline as calibrate_l1_templates.py / calibrate_l2_density.py, applied
to layer3.py's harm-alignment signal instead of L1/L2's template lists.

WHY THIS EXISTS
------------------
MHJ's own tactic breakdown (SENTINEL_COMPLETE_RESULTS_RECORD.md B.7) found
Direct Request (AUROC 0.547) and Obfuscation (AUROC 0.613) sitting near
chance while other tactics score 0.70-0.76 — concentrated in the two
largest tactic categories, over half the set. MHJ previously shipped no
train/test split at all (fixed in dataset_loaders.py's _load_mhj this
session — see that function's docstring), so any "held-out-calibrated"
claim about fixing this would have been false; this script is the first
one built against the real split.

WHAT'S ISOLATED, AND WHY
----------------------------
Mirrors L1/L2's calibration scripts: isolate just the specific signal
being tuned (here, `_harm_alignment`'s per-turn max cosine similarity
against HARM_ANCHOR_PHRASES, layer3.py:212-216) rather than running the
full L3Result.score (which entangles velocity/drift/escalation too, and
would muddy which component any AUROC change is actually attributable
to). The per-SESSION signal used below is the max harm_alignment across
all of a session's turns — "would any point in this conversation have
tripped the harm-anchor check on its own."

EXPECTED OUTCOME, STATED UP FRONT
-------------------------------------
Obfuscation is flagged in advance as a likely non-fix: cosine similarity
to plain-language anchor sentences is structurally blind to ciphered/
word-substituted text by construction. Run it anyway for completeness and
report whatever the real number is — do not force a fix that doesn't
exist, per this project's standing discipline (see the module docstring
of pattern_mining.py for the same posture on a different mechanism).

REQUIRES a working embedding model. Run this on your machine.

Usage:
    python -m sentinel.eval.calibrate_l3_patterns
"""

from __future__ import annotations

import numpy as np
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.metrics import roc_auc_score, roc_curve

from sentinel.core.embedding import get_model
from sentinel.eval.l3_utils import parse_l3_conversation
from sentinel.eval.dataset_loaders import load_dataset
from sentinel.layers.layer3 import HARM_ANCHOR_PHRASES, ESCALATION_ANCHOR_PHRASES

# --------------------------------------------------------------------------
# EDIT THIS after reading the train-set excerpts printed below — using
# general patterns you notice, not phrases copied from the test split
# (which this script only opens in the final confirmatory step).
# --------------------------------------------------------------------------
CANDIDATE_HARM_ANCHORS: list[str] = list(HARM_ANCHOR_PHRASES) + [
    # Direct Request tactic (per MHJ's own tactic field): plain, undisguised
    # asks for harmful how-to information, often narrower/more specific than
    # the original 5 broad-category anchors (e.g. drug dosages, specific
    # illicit-acquisition logistics) rather than roleplay/authority framing
    # (which ESCALATION_ANCHOR_PHRASES already targets separately, now
    # semantic-similarity-based too — see layer3.py's 2026-09-11 conversion).
    "Specific dosage amounts or acquisition methods for illegal or controlled drugs.",
    "Direct request for step-by-step instructions to commit a specific illegal act.",
    "Direct request for restricted professional or medical information without authorization.",
]


def _session_max_harm_alignment(text: str, anchor_embeddings: np.ndarray) -> float:
    """Isolated harm_alignment signal: max over all turns of max cosine
    similarity against the given anchor set — same math as layer3.py's
    _harm_alignment, parameterized on candidate anchors and applied across
    a whole session instead of one turn."""
    turns = parse_l3_conversation(text)
    if not turns:
        return 0.0
    turn_embeddings = get_model().encode(turns)
    sims = cosine_similarity(turn_embeddings, anchor_embeddings)
    return float(max(0.0, sims.max()))


def score_all(texts: list[str], anchors: list[str]) -> np.ndarray:
    anchor_emb = get_model().encode(anchors)
    return np.array([_session_max_harm_alignment(t, anchor_emb) for t in texts])


def report(name: str, mal_scores: np.ndarray, ben_scores: np.ndarray) -> float:
    y = np.concatenate([np.ones(len(mal_scores)), np.zeros(len(ben_scores))])
    s = np.concatenate([mal_scores, ben_scores])
    auroc = roc_auc_score(y, s) if len(set(y)) > 1 else float("nan")
    print(f"--- {name} ---")
    print(f"  malicious: n={len(mal_scores)} mean={mal_scores.mean():.3f} median={np.median(mal_scores):.3f}")
    print(f"  benign:    n={len(ben_scores)} mean={ben_scores.mean():.3f} median={np.median(ben_scores):.3f}")
    print(f"  AUROC: {auroc:.4f}")
    if len(set(y)) > 1:
        fpr, tpr, thresh = roc_curve(y, s)
        j = tpr - fpr
        best_idx = int(np.argmax(j))
        print(f"  suggested threshold (Youden's J): {thresh[best_idx]:.3f} (TPR={tpr[best_idx]:.3f}, FPR={fpr[best_idx]:.3f})")
    print()
    return auroc


def _tactic_texts(dataset, tactic: str) -> list[str]:
    return [s.text for s in dataset.samples if s.label == "malicious" and s.metadata.get("tactic") == tactic]


def _benign_texts(dataset) -> list[str]:
    return [s.text for s in dataset.samples if s.label == "benign"]


def calibrate_tactic(tactic: str) -> None:
    print("#" * 78)
    print(f"# TACTIC: {tactic}")
    print("#" * 78)

    train = load_dataset("mhj", split="train")
    test = load_dataset("mhj", split="test")

    train_mal = _tactic_texts(train, tactic)
    train_ben = _benign_texts(train)
    test_mal = _tactic_texts(test, tactic)
    test_ben = _benign_texts(test)
    print(f"train: {len(train_mal)} malicious ({tactic}), {len(train_ben)} benign")
    print(f"test:  {len(test_mal)} malicious ({tactic}), {len(test_ben)} benign\n")

    print("=" * 78)
    print(f"STEP 1: current HARM_ANCHOR_PHRASES on TRAIN split ({tactic})")
    print("=" * 78)
    report("current anchors (train)", score_all(train_mal, HARM_ANCHOR_PHRASES), score_all(train_ben, HARM_ANCHOR_PHRASES))

    print("=" * 78)
    print(f"STEP 2: a few TRAIN-split {tactic} turns, for pattern reference")
    print("        (do not open the test split for this)")
    print("=" * 78)
    for text in train_mal[:6]:
        turns = parse_l3_conversation(text)
        preview = " | ".join(t[:100] for t in turns[:3])
        print("  -", preview)
    print()

    print("=" * 78)
    print(f"STEP 3: candidate anchors on TRAIN split ({tactic})")
    print("=" * 78)
    report("candidate anchors (train)", score_all(train_mal, CANDIDATE_HARM_ANCHORS), score_all(train_ben, CANDIDATE_HARM_ANCHORS))

    print("=" * 78)
    print(f"STEP 4: CONFIRMATORY check on TEST split ({tactic}, never used above)")
    print("=" * 78)
    report(
        "candidate anchors (test, held out)",
        score_all(test_mal, CANDIDATE_HARM_ANCHORS),
        score_all(test_ben, CANDIDATE_HARM_ANCHORS),
    )
    print(
        "If this AUROC is meaningfully lower than step 3's, that gap is real "
        "signal the candidates were still shaped by something train-specific "
        "— report it honestly rather than tuning further against the test "
        "split to close it.\n"
    )


def main() -> None:
    calibrate_tactic("Direct Request")
    calibrate_tactic("Obfuscation")


if __name__ == "__main__":
    main()
