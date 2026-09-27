"""
Corpus degeneracy audit: can a trivial statistic classify this corpus?

WHY THIS EXISTS. On 2026-09-19, sentinel_bench's multi-turn subset was found to
be perfectly separable by TURN COUNT alone — all 20 malicious sessions have
exactly 4 turns, all 25 benign have exactly 3, with zero overlap. AUROC 1.0000
from a classifier that never reads the text. Every multi-turn class-separation
number measured on that corpus is therefore uninterpretable, and the confound
cannot even be controlled for: no turn-count bin contains both classes, so there
is no counterfactual to compare within.

Nobody had checked. The corpus had been used for L3 evaluation for months.

The failure class is general: a benchmark assembled from per-class templates
inherits per-class structural regularities, and a detector can score well by
reading the regularity instead of the threat. The check is cheap — a few
seconds, no model calls — so it should gate every corpus before use rather than
be discovered afterwards.

WHAT IS CHECKED. For each trivial, content-free statistic:

    turn count, total characters, mean characters per turn, mean words per turn

compute the class AUROC. Then report, per statistic:

  * AUROC and whether |AUROC - 0.5| is large enough to be a usable shortcut;
  * the overlap in the statistic's support between classes — because an AUROC of
    1.0000 with disjoint support is unfixable, while 0.85 with full overlap can
    at least be controlled for by stratifying;
  * whether a within-bin control is COMPUTABLE at all (it is not, if no bin
    holds both classes).

Thresholds are deliberately conservative: this is a screening tool, and a false
alarm costs a stratified re-analysis while a miss costs a retracted result.
"""

from __future__ import annotations

import re

# A statistic this far from chance is a usable shortcut and must be reported
# alongside any detection metric on the corpus.
SUSPICIOUS_DELTA = 0.15
# Above this, the corpus cannot support a class-separation claim at all.
DISQUALIFYING_DELTA = 0.35

_TURN_RE = re.compile(r"\[Turn \d+\]\s*")


def split_turns(text: str) -> list[str]:
    return [p.strip() for p in _TURN_RE.split(text) if p.strip()]


def trivial_statistics(text: str) -> dict[str, float]:
    """Content-free structural statistics. None of these look at what is said."""
    turns = split_turns(text)
    n = len(turns) or 1
    words = sum(len(t.split()) for t in turns)
    return {
        "n_turns": float(len(turns)),
        "total_chars": float(len(text)),
        "mean_chars_per_turn": len(text) / n,
        "mean_words_per_turn": words / n,
    }


def auroc(pos: list[float], neg: list[float]) -> float:
    if not pos or not neg:
        return float("nan")
    wins = 0.0
    for p in pos:
        for q in neg:
            wins += 1.0 if p > q else (0.5 if p == q else 0.0)
    return wins / (len(pos) * len(neg))


def audit_samples(samples, min_turns: int = 1) -> dict:
    """
    `samples` is any iterable of objects with `.text` and `.label`.

    `min_turns` matters: a corpus can be clean overall and degenerate on the
    multi-turn subset that an L3-style evaluation actually uses. That is exactly
    what happened with sentinel_bench, so audit the subset you will evaluate on.
    """
    rows = []
    for s in samples:
        if s.label not in ("benign", "malicious"):
            continue
        stats = trivial_statistics(s.text)
        if stats["n_turns"] < min_turns:
            continue
        stats["label"] = s.label
        rows.append(stats)

    mal = [r for r in rows if r["label"] == "malicious"]
    ben = [r for r in rows if r["label"] == "benign"]
    out = {
        "n_malicious": len(mal),
        "n_benign": len(ben),
        "min_turns": min_turns,
        "statistics": {},
        "verdict": "insufficient_data",
    }
    if len(mal) < 5 or len(ben) < 5:
        return out

    worst = 0.0
    for key in ("n_turns", "total_chars", "mean_chars_per_turn", "mean_words_per_turn"):
        p = [r[key] for r in mal]
        n = [r[key] for r in ben]
        a = auroc(p, n)
        delta = abs(a - 0.5)
        worst = max(worst, delta)

        # Support overlap, and whether stratification is even possible. Only
        # meaningful for the discrete statistic; for continuous ones an interval
        # overlap is the honest analogue.
        if key == "n_turns":
            sp, sn = {int(v) for v in p}, {int(v) for v in n}
            shared = sorted(sp & sn)
            binnable = any(
                sum(1 for v in p if int(v) == b) >= 3 and
                sum(1 for v in n if int(v) == b) >= 3
                for b in shared)
            overlap = {"shared_values": shared,
                       "malicious_values": sorted(sp),
                       "benign_values": sorted(sn),
                       "disjoint": not shared,
                       "within_bin_control_computable": binnable}
        else:
            lo = max(min(p), min(n))
            hi = min(max(p), max(n))
            overlap = {"interval_overlap": max(0.0, hi - lo),
                       "disjoint": hi <= lo,
                       "within_bin_control_computable": hi > lo}

        out["statistics"][key] = {
            "auroc": a,
            "delta_from_chance": delta,
            "suspicious": delta >= SUSPICIOUS_DELTA,
            "disqualifying": delta >= DISQUALIFYING_DELTA,
            "overlap": overlap,
        }

    out["worst_delta"] = worst
    out["verdict"] = (
        "DEGENERATE" if worst >= DISQUALIFYING_DELTA else
        "CONFOUNDED" if worst >= SUSPICIOUS_DELTA else
        "clean")
    return out


def format_report(name: str, audit: dict) -> str:
    lines = [f"{name}  (>= {audit['min_turns']} turns)  "
             f"n={audit['n_malicious']} mal / {audit['n_benign']} ben"]
    if audit["verdict"] == "insufficient_data":
        lines.append("  insufficient data to audit (need >= 5 per class)")
        return "\n".join(lines)
    lines.append(f"  VERDICT: {audit['verdict']}  "
                 f"(worst |AUROC-0.5| = {audit['worst_delta']:.4f})")
    for key, st in audit["statistics"].items():
        flag = ("  <-- DISQUALIFYING" if st["disqualifying"]
                else "  <-- suspicious" if st["suspicious"] else "")
        lines.append(f"    {key:<22} AUROC {st['auroc']:.4f}{flag}")
        ov = st["overlap"]
        if ov["disjoint"]:
            lines.append("      support is DISJOINT between classes — the "
                         "confound cannot be controlled for")
        elif not ov["within_bin_control_computable"]:
            lines.append("      no bin holds enough of both classes — within-bin "
                         "control not computable")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    import argparse

    from sentinel.eval.dataset_loaders import load_dataset

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("corpora", nargs="*",
                    default=["sentinel_bench", "mhj", "tomgibbs_mt",
                             "wildjailbreak", "tensortrust"])
    ap.add_argument("--min-turns", type=int, nargs="*", default=[1, 3],
                    help="audit each corpus at each of these minimum turn counts; "
                         "a corpus can be clean overall and degenerate on the "
                         "multi-turn subset an L3 evaluation actually uses")
    args = ap.parse_args(argv)

    worst_verdict = "clean"
    rank = {"clean": 0, "insufficient_data": 0, "CONFOUNDED": 1, "DEGENERATE": 2}
    for corpus in args.corpora:
        try:
            ds = load_dataset(corpus, split="test")
        except Exception as e:                                   # noqa: BLE001
            print(f"{corpus}: could not load ({type(e).__name__}: {e})")
            continue
        for mt in args.min_turns:
            a = audit_samples(ds.samples, min_turns=mt)
            print(format_report(corpus, a))
            if rank.get(a["verdict"], 0) > rank[worst_verdict]:
                worst_verdict = a["verdict"]
        print()
    print(f"worst verdict across audited corpora: {worst_verdict}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
