"""
Fit calibrated L3 weights (L3_VELOCITY_WEIGHT / L3_DRIFT_WEIGHT /
L3_ESCALATION_WEIGHT) from labeled data instead of the current hand-set
0.40 / 0.35 / 0.25 defaults — the "calibrated thresholds, not magic
numbers" item in 01_RESEARCH_GRADE_ROADMAP.md, Section 6.3.

REQUIRES a working embedding model (i.e. real internet/HuggingFace access).
Run this on your machine, not in an offline sandbox.

Usage:
    python -m sentinel.eval.calibrate_l3_weights
    python -m sentinel.eval.calibrate_l3_weights --cv-folds 5

--------------------------------------------------------------------------
WHY THIS SCRIPT EXISTS (2026-07-24 RCA on custom_l3 AUROC=0.44) —
UPDATED 2026-07-25 after a live run scored AUROC=0.26 (worse than before)
--------------------------------------------------------------------------
Two real bugs were found and fixed on 2026-07-24:
  1. generate_l3_corpus.py had a role-alternation bug that leaked blank
     turns and a literal "(Assistant responds helpfully)" filler string
     into ~82% of samples (see that module's docstring/comments).
  2. runner.py's `_evaluate_l3` scored only the LAST turn of a conversation
     instead of the max-scoring turn across the whole conversation, which
     doesn't match how sentinel/app.py actually evaluates live traffic
     (every turn is scored and acted on as it arrives).

Neither was the primary explanation for AUROC < 0.5. A subsequent real run
(real embedding model, not a proxy) confirmed the hypothesis this script
was originally written to test: on custom_l3, raw semantic_velocity is
*anti-correlated* with the malicious label, because 100% of the malicious
set is "crescendo"-style attacks engineered to escalate via small, natural
steps (low velocity, by construction — that's the whole threat model),
while several benign categories (`topic_shift_*`, `rapid_topic_changes`)
are engineered to have large, visible topic jumps (high velocity) as a
deliberate false-positive stress test. A positively weighted ADDITIVE
combination of velocity + drift can only push the score in the direction
the raw signal points, and here that direction is wrong for velocity — no
reweighting of an additive sum fixes that.

**Fix applied in `sentinel/layers/layer3.py`**: velocity and drift are now
combined multiplicatively — `drift * (1 - velocity)` — rewarding high
cumulative drift achieved smoothly (the crescendo signature) and
discounting the same drift achieved via a visible jump (the benign
topic-shift signature). See that module's docstring for the full writeup.

This script now fits TWO things so you can verify both parts of that
finding against the REAL embedding model, since everything above was only
confirmed with a disclaimed offline proxy (`tests/fake_embedder.py`) or
with the real model's live eval output taken as a whole (not decomposed
feature-by-feature):

  1. The ORIGINAL diagnostic: logistic regression on the raw
     [velocity, drift, escalation] features. A negative velocity
     coefficient here, under the real model, is direct confirmation of the
     mechanism above (not just the proxy's suggestion of it).
  2. The NEW production formula's actual feature:
     [drift * (1 - velocity), escalation]. This is what the fitted
     coefficients here should inform — the relative weight between
     "smooth cumulative drift" and "escalation phrase hit" (i.e. how
     (L3_DRIFT_WEIGHT + L3_VELOCITY_WEIGHT) should split against
     L3_ESCALATION_WEIGHT), not the old three-way split.

Either way, plug the result into config.py yourself and confirm on
test.jsonl — this script never touches test.jsonl and never edits
config.py automatically.

The escalation_found feature is included in both fits for completeness,
but as of the 2026-07-24 RCA it was 0/300 across the entire custom_l3
corpus (see generate_l3_corpus.py's ESCALATION_STRATEGIES) — a corpus
built from natural, plausible-sounding crescendo attacks simply never
trips any phrase in ESCALATION_PHRASES. Do not "fix" this by adding
phrases scraped from this benchmark's own text — that is tuning the
detector to the test set it's meant to be evaluated against, not
calibrating it, and would invalidate any AUROC improvement it produced
(see 01_RESEARCH_GRADE_ROADMAP.md Section 9's risk register).

--------------------------------------------------------------------------
UPDATED 2026-07-25 (RCA #2, same day) — a confirmed real-model run of the
above fix still only reached AUROC=0.6145, below the "something's wrong"
line the project's own testing guide sets. Root cause: velocity/drift
geometry alone cannot separate this benchmark's classes at all (checked
directly against a real semantic embedder, not just re-confirmed with the
same BOW proxy) — natural conversation drifts smoothly regardless of
whether it's benign or adversarial, so "how far / how smoothly" is
topic-agnostic. The fix adds `harm_alignment` (max cosine similarity to a
small fixed set of harm-topic anchor sentences in layer3.py) as a
content-aware signal, now the dominant term in the score. See that
module's docstring for the full writeup and honesty caveats (anchors are
original text but their category coverage overlaps this corpus's
taxonomy — disclosed there, not hidden). This script now fits a
4-feature diagnostic raw fit, and a 3-feature production fit
[drift*(1-velocity), harm_alignment, escalation].
"""

from __future__ import annotations

import argparse
import logging
import sys

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(message)s")


def _extract_features(dataset_name: str, split: str):
    """
    Returns (X, y, sample_ids) where X is an (n_samples, 3) array of
    [semantic_velocity, cumulative_drift, escalation_found] taken from the
    MAX-scoring turn of each conversation (matching _evaluate_l3's
    post-2026-07-24 behavior), and y is 1 for malicious / 0 for benign.
    """
    import numpy as np
    from sentinel.eval.dataset_loaders import load_dataset
    from sentinel.eval.runner import _evaluate_l3
    from sentinel.eval.l3_utils import parse_l3_conversation

    dataset = load_dataset(dataset_name, split=split, limit=None)
    if not dataset.samples:
        raise SystemExit(
            f"No samples loaded for {dataset_name}/{split}. "
            f"Generate the corpus first: python -m sentinel.eval.generate_l3_corpus"
        )

    X = []
    y = []
    sample_ids = []
    n_errors = 0
    for i, sample in enumerate(dataset.samples):
        turns = parse_l3_conversation(sample.text)
        if not turns:
            n_errors += 1
            continue
        try:
            result = _evaluate_l3(turns)
        except Exception as e:
            logger.warning(f"  Error on {sample.sample_id}: {e}")
            n_errors += 1
            continue
        velocity = result.details.get("semantic_velocity", 0.0)
        drift = result.details.get("cumulative_drift", 0.0)
        harm_alignment = result.details.get("harm_alignment", 0.0)
        escalation = 1.0 if result.details.get("escalation_found", False) else 0.0
        X.append([velocity, drift, harm_alignment, escalation])
        y.append(1 if sample.label == "malicious" else 0)
        sample_ids.append(sample.sample_id)
        if (i + 1) % 50 == 0:
            logger.info(f"  Processed {i + 1}/{len(dataset.samples)}...")

    if n_errors:
        logger.warning(f"  {n_errors} sample(s) skipped due to errors/empty turns.")

    return np.array(X), np.array(y), sample_ids


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dataset", type=str, default="custom_l3")
    parser.add_argument("--split", type=str, default="train", help="NEVER pass 'test' here — that defeats the point of held-out evaluation.")
    parser.add_argument("--cv-folds", type=int, default=5)
    args = parser.parse_args()

    if args.split == "test":
        print(
            "Refusing to calibrate against the 'test' split — fit on 'train' "
            "(the default), then evaluate the result against test.jsonl "
            "separately with `python -m sentinel.eval.runner --layer L3 "
            "--dataset custom_l3`.",
            file=sys.stderr,
        )
        raise SystemExit(1)

    import numpy as np
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import StratifiedKFold, cross_val_score
    from sklearn.metrics import roc_auc_score, roc_curve, precision_recall_curve

    logger.info(f"Extracting features from {args.dataset}/{args.split} "
                f"(replaying every conversation through the real L3 detector)...")
    X, y, _ = _extract_features(args.dataset, args.split)
    n_mal, n_ben = int(y.sum()), int((y == 0).sum())
    logger.info(f"\n{len(y)} samples ({n_mal} malicious, {n_ben} benign)")

    if n_mal < 5 or n_ben < 5:
        raise SystemExit("Too few samples of one class to fit anything meaningful. Check the corpus.")

    # Cross-validated AUROC on TRAIN ONLY — this tells you whether the fit
    # generalizes within the training distribution. It is NOT the number to
    # report anywhere; it exists so you don't walk into the held-out test
    # run blind.
    clf = LogisticRegression()
    skf = StratifiedKFold(n_splits=min(args.cv_folds, n_mal, n_ben), shuffle=True, random_state=42)
    try:
        cv_scores = cross_val_score(clf, X, y, cv=skf, scoring="roc_auc")
        logger.info(f"Cross-val AUROC on TRAIN (informational only, not a held-out number): "
                     f"{cv_scores.mean():.4f} +/- {cv_scores.std():.4f}")
    except ValueError as e:
        logger.warning(f"  Skipping cross-validation ({e})")

    # Final fit on all of train.
    clf.fit(X, y)
    coef = clf.coef_[0]  # [velocity_coef, drift_coef, harm_alignment_coef, escalation_coef]
    train_auroc = roc_auc_score(y, clf.decision_function(X))

    velocity_coef, drift_coef, harm_alignment_coef, escalation_coef = coef
    logger.info("\n" + "=" * 60)
    logger.info("Fitted logistic-regression coefficients (train, full fit):")
    logger.info(f"  velocity:       {velocity_coef:+.4f}")
    logger.info(f"  drift:          {drift_coef:+.4f}")
    logger.info(f"  harm_alignment: {harm_alignment_coef:+.4f}")
    logger.info(f"  escalation:     {escalation_coef:+.4f}")
    logger.info(f"  train AUROC (fit on what it was trained on — expect optimistic): {train_auroc:.4f}")
    logger.info("=" * 60)

    negative = [name for name, c in [("velocity", velocity_coef), ("drift", drift_coef),
                                      ("harm_alignment", harm_alignment_coef), ("escalation", escalation_coef)] if c < 0]
    if negative:
        logger.warning(
            f"\nWARNING: {', '.join(negative)} has a NEGATIVE coefficient — meaning HIGHER "
            f"{', '.join(negative)} predicts BENIGN, not malicious, on this training data. "
            f"If 'harm_alignment' is in this list, that's a serious finding — it would mean the "
            f"harm-topic anchors (HARM_ANCHOR_PHRASES in layer3.py) are themselves not "
            f"discriminating on this data under the real model, and RCA #2's fix should be "
            f"revisited rather than shipped as-is. If only 'velocity'/'drift' are negative, "
            f"that's the expected, already-understood RCA #1 finding — production no longer "
            f"uses the raw additive formula; see the second fit below."
        )
    else:
        logger.info(
            "\nNo negative coefficients here. Still use the second fit below for the actual "
            "weight split, since that's what production computes now; this first fit is "
            "diagnostic only."
        )

    # -----------------------------------------------------------------
    # Second fit: the features the PRODUCTION formula actually computes.
    # `sentinel/layers/layer3.py` computes `drift * (1 - velocity)` ("smooth
    # cumulative drift"), `harm_alignment` (max similarity to the fixed harm
    # anchors — RCA #2), and adds escalation on top. Fit against THOSE
    # features so the suggested weights are for the formula that's actually
    # running, not an earlier retired one.
    # -----------------------------------------------------------------
    smooth_drift = X[:, 1] * (1.0 - X[:, 0])  # drift * (1 - velocity)
    harm_alignment_feature = X[:, 2]
    X2 = np.column_stack([smooth_drift, harm_alignment_feature, X[:, 3]])  # [smooth_drift, harm_alignment, escalation]

    clf2 = LogisticRegression()
    try:
        cv_scores2 = cross_val_score(clf2, X2, y, cv=skf, scoring="roc_auc")
        logger.info(f"\nCross-val AUROC on TRAIN, production feature "
                     f"[drift*(1-velocity), harm_alignment, escalation] (informational only): "
                     f"{cv_scores2.mean():.4f} +/- {cv_scores2.std():.4f}")
    except ValueError as e:
        logger.warning(f"  Skipping cross-validation for production feature ({e})")

    clf2.fit(X2, y)
    smooth_drift_coef, harm_alignment_coef2, escalation_coef2 = clf2.coef_[0]
    train_auroc2 = roc_auc_score(y, clf2.decision_function(X2))

    logger.info("\n" + "=" * 60)
    logger.info("Fitted logistic-regression coefficients for the PRODUCTION feature (train, full fit):")
    logger.info(f"  drift*(1-velocity): {smooth_drift_coef:+.4f}")
    logger.info(f"  harm_alignment:     {harm_alignment_coef2:+.4f}")
    logger.info(f"  escalation:         {escalation_coef2:+.4f}")
    logger.info(f"  train AUROC (fit on what it was trained on — expect optimistic): {train_auroc2:.4f}")
    logger.info("=" * 60)

    if harm_alignment_coef2 < 0:
        logger.warning(
            "\nWARNING: harm_alignment has a NEGATIVE coefficient under the real model. That "
            "would mean RCA #2's fix does not hold here, and the honest conclusion is that "
            "HARM_ANCHOR_PHRASES need revision (different/more anchor sentences) rather than "
            "another reweighting of the existing features. Please report this back."
        )
    elif smooth_drift_coef < 0:
        logger.warning(
            "\nWARNING: drift*(1-velocity) has a negative coefficient under the real model "
            "(harm_alignment is fine). That's consistent with RCA #2's finding that geometric "
            "drift/smoothness alone doesn't separate this benchmark — consider dropping it to "
            "0 weight rather than forcing a positive split; harm_alignment can carry the score "
            "on its own."
        )
    else:
        positive2 = {
            "drift_smooth": max(smooth_drift_coef, 0.0),
            "harm_alignment": max(harm_alignment_coef2, 0.0),
            "escalation": max(escalation_coef2, 0.0),
        }
        total2 = sum(positive2.values())
        if total2 > 0:
            normalized2 = {k: v / total2 for k, v in positive2.items()}
            logger.info(
                "\nSuggested config.py weight SPLIT for the production formula (normalized to "
                "sum to 1 — this is the combined budget across (L3_DRIFT_WEIGHT + "
                "L3_VELOCITY_WEIGHT), L3_HARM_ALIGNMENT_WEIGHT, and L3_ESCALATION_WEIGHT; the "
                "internal L3_DRIFT_WEIGHT / L3_VELOCITY_WEIGHT split no longer matters on its "
                "own since both multiply the same drift*(1-velocity) term):"
            )
            logger.info(f"  L3_DRIFT_WEIGHT + L3_VELOCITY_WEIGHT (combined) = {normalized2['drift_smooth']:.4f}")
            logger.info(f"  L3_HARM_ALIGNMENT_WEIGHT                        = {normalized2['harm_alignment']:.4f}")
            logger.info(f"  L3_ESCALATION_WEIGHT                            = {normalized2['escalation']:.4f}")

    logger.info(
        "\nNext step: manually edit sentinel/config.py with the values above (only if you "
        "understood and accept any warning printed above), then re-run this script (weights "
        "changed => the threshold suggestion below needs recomputing against the new scale) "
        "before trusting the threshold numbers just below."
    )

    # -----------------------------------------------------------------
    # RCA #3 (2026-07-25, session 3): threshold suggestion.
    #
    # A confirmed real run scored L3 alone at AUROC=0.9795 (excellent
    # ranking) but Precision=Recall=FPR=0.0000 at the shared
    # WARN_THRESHOLD=0.50 — every single L3 score in the test set fell
    # below 0.50, malicious or benign. AUROC is threshold-independent, so
    # the ranking above already proves the signal works; what's missing is
    # a threshold that's actually reachable on THIS score's real scale.
    #
    # This computes the ACTUAL production score (the exact formula in
    # layer3.py, using WHATEVER weights are currently in config.py right
    # now — not the logistic-regression coefficients above, which are on a
    # different, unbounded scale) for every train sample, then picks two
    # operating points off its ROC curve:
    #   - L3_WARN_THRESHOLD: the point maximizing Youden's J (tpr - fpr) —
    #     the best overall separation point.
    #   - L3_BLOCK_THRESHOLD: the smallest threshold with precision >= 0.90
    #     on train (a stricter, more confident point before an autonomous
    #     block) — falls back to the highest score any BENIGN sample
    #     reached (plus a small margin) if 0.90 precision isn't reachable,
    #     so BLOCK never sits below WARN.
    # -----------------------------------------------------------------
    from sentinel.config import (
        L3_VELOCITY_WEIGHT, L3_DRIFT_WEIGHT, L3_HARM_ALIGNMENT_WEIGHT, L3_ESCALATION_WEIGHT,
    )

    velocity_arr, drift_arr, harm_arr, escalation_arr = X[:, 0], X[:, 1], X[:, 2], X[:, 3]
    smoothness_arr = np.clip(1.0 - velocity_arr, 0.0, None)
    drift_component_arr = drift_arr * smoothness_arr
    production_scores = (
        harm_arr * L3_HARM_ALIGNMENT_WEIGHT
        + drift_component_arr * (L3_DRIFT_WEIGHT + L3_VELOCITY_WEIGHT)
        + escalation_arr * L3_ESCALATION_WEIGHT
    )
    production_scores = np.clip(production_scores, 0.0, 1.0)

    logger.info("\n" + "=" * 60)
    logger.info(f"Production score distribution on TRAIN (current config.py weights: "
                f"harm={L3_HARM_ALIGNMENT_WEIGHT}, drift+vel={L3_DRIFT_WEIGHT + L3_VELOCITY_WEIGHT}, "
                f"escalation={L3_ESCALATION_WEIGHT}):")
    logger.info(f"  malicious: min={production_scores[y==1].min():.4f} "
                f"mean={production_scores[y==1].mean():.4f} max={production_scores[y==1].max():.4f}")
    logger.info(f"  benign:    min={production_scores[y==0].min():.4f} "
                f"mean={production_scores[y==0].mean():.4f} max={production_scores[y==0].max():.4f}")

    fpr_arr, tpr_arr, roc_thresholds = roc_curve(y, production_scores)
    production_auroc = roc_auc_score(y, production_scores)
    logger.info(f"  AUROC of the actual production score (should match/be close to what "
                f"`runner.py --layer L3 --dataset custom_l3` reports on TEST): {production_auroc:.4f}")

    if production_scores.max() < 1e-6:
        logger.warning(
            "\nWARNING: every production score on train is ~0. Something upstream is broken "
            "(all weights zero, or every feature zero) — the threshold suggestion below is "
            "meaningless; fix that first."
        )
    else:
        youden_j = tpr_arr - fpr_arr
        best_idx = int(np.argmax(youden_j))
        suggested_warn = float(roc_thresholds[best_idx])
        # roc_curve's first threshold is +inf by convention; guard against
        # picking that as "the best" on a degenerate/tiny sample.
        if not np.isfinite(suggested_warn):
            suggested_warn = float(production_scores.max())

        precision_arr, recall_arr, pr_thresholds = precision_recall_curve(y, production_scores)
        # precision_recall_curve's arrays are 1 longer than pr_thresholds;
        # align by dropping the last precision/recall point (which has no
        # corresponding threshold).
        precise_enough = precision_arr[:-1] >= 0.90
        if precise_enough.any():
            suggested_block = float(pr_thresholds[precise_enough].min())
        else:
            # Fallback: the highest score any benign train sample reached,
            # plus a small margin — guarantees BLOCK sits above every
            # observed false positive on train, even if 90% precision
            # isn't reachable on this small a sample.
            suggested_block = float(production_scores[y == 0].max()) + 0.05
        suggested_block = max(suggested_block, suggested_warn + 0.01)  # BLOCK must sit above WARN
        suggested_block = min(suggested_block, 1.0)

        logger.info("\n" + "=" * 60)
        logger.info("Suggested thresholds for config.py (from TRAIN only — confirm on TEST after):")
        logger.info(f"  L3_WARN_THRESHOLD  = {suggested_warn:.4f}   (Youden's-J-optimal point)")
        logger.info(f"  L3_BLOCK_THRESHOLD = {suggested_block:.4f}   (>=0.90 precision point, or benign-max+0.05 fallback)")
        logger.info("=" * 60)
        logger.info(
            "\nApply these as environment variables (or edit config.py's defaults directly):\n"
            f"  export L3_WARN_THRESHOLD={suggested_warn:.4f}\n"
            f"  export L3_BLOCK_THRESHOLD={suggested_block:.4f}\n"
            "Then confirm on the held-out split:\n"
            "  python -m sentinel.eval.runner --layer L3 --dataset custom_l3 -v\n"
            "That command now uses L3_WARN_THRESHOLD automatically as L3's default "
            "classification cutoff (see runner.py's _default_layer_threshold) instead of the "
            "shared WARN_THRESHOLD, and sentinel/app.py rescales L3's raw score through both "
            "thresholds before combining it with L1/L2 (see core/models.py's "
            "rescale_layer_score) — so this is the number that actually governs both eval and "
            "the live pipeline for L3 specifically."
        )


if __name__ == "__main__":
    main()
