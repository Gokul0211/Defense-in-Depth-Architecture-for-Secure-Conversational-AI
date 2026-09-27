"""
Recompute the A/B/C/D partition in already-written ablation artifacts.

WHY THIS EXISTS. Two ablation runs (phase4_ablation_phase4_20260919_191712 and
phase4_ablation_split_bench_20260919_204613) were executed while
`_abcd_partition` still used BLOCK_THRESHOLD as the "a layer already detected
this" bar. That bar is wrong: `final_decision != "ALLOW"` is true from
WARN_THRESHOLD upward (pipeline_sim.py:437-439), so using BLOCK holds the
correlation engine to a stricter standard than the layers it is compared
against. On Phase 4 it published |C| = 1 novel correlation detection where the
correct figure is 0 — the independent-cascade comparison (rows 5 and 6 both
229/230) says 0, and at WARN the partition reproduces that exactly.

The 340/230-sample matrices take 25-83 minutes each, and re-running them to fix
an arithmetic label would be wasteful and would also perturb the recorded
runtime. The `*_per_sample.json` sidecar carries every field the partition needs,
so the correction is a pure recomputation.

PROVENANCE DISCIPLINE. This does NOT overwrite the original `abcd_partition`
key. It adds:

  * `abcd_partition_corrected` — the recomputed values at both thresholds;
  * `_correction_note`         — what was wrong, why, and when it was fixed.

The original stays in place, clearly marked as superseded, so a reader who
encounters the old number elsewhere can trace it. Silently replacing a published
number with a better one destroys exactly the audit trail that makes the
correction credible.

Usage:
    python -m sentinel.eval.fix_abcd_partition_artifacts            # dry run
    python -m sentinel.eval.fix_abcd_partition_artifacts --write
"""

from __future__ import annotations

import argparse
import glob
import json
from pathlib import Path

from sentinel.config import BLOCK_THRESHOLD, WARN_THRESHOLD
from sentinel.eval.run_phase4_ablation import _abcd_partition

_RESULTS_DIR = Path(__file__).parent / "results"

NOTE = (
    "The `abcd_partition` key written by the original run used BLOCK_THRESHOLD "
    "as the 'a layer already detected this' bar. That is wrong: "
    "`final_decision != \"ALLOW\"` is true from WARN_THRESHOLD upward "
    "(pipeline_sim.py:437-439), so BLOCK holds correlation to a stricter bar "
    "than the layers it is compared against and overstates novel detections. "
    "Superseded by `abcd_partition_corrected`, recomputed from the per-sample "
    "sidecar on 2026-09-19. The original key is retained unmodified for "
    "traceability. See PHASE_B_C_PARALLEL_ANALYSIS.md appendix G.2."
)


def _find_pairs() -> list[tuple[Path, Path]]:
    pairs = []
    for side in sorted(_RESULTS_DIR.glob("phase4_ablation_*_per_sample.json")):
        try:
            meta = json.load(open(side, encoding="utf-8"))["meta"]
        except Exception:                                        # noqa: BLE001
            continue
        summary = _RESULTS_DIR / meta.get("summary", "")
        if summary.exists():
            pairs.append((summary, side))
    return pairs


def correct(summary_path: Path, sidecar_path: Path, write: bool) -> dict:
    side = json.load(open(sidecar_path, encoding="utf-8"))
    summary = json.load(open(summary_path, encoding="utf-8"))

    full = None
    for name, rows in side["conditions"].items():
        if "full" in name:
            full = rows
            break
    if full is None:
        return {"path": summary_path.name, "status": "no full row in sidecar"}

    corrected = {
        "primary_at_warn": _abcd_partition(full, WARN_THRESHOLD),
        "escalation_at_block": _abcd_partition(full, BLOCK_THRESHOLD),
    }

    old = summary.get("abcd_partition") or {}
    old_C = None
    if old and "primary_at_warn" not in old:
        old_C = (old.get("malicious") or {}).get("C_correlation_novel")
    new_C = corrected["primary_at_warn"].get("malicious", {}).get("C_correlation_novel")

    out = {
        "path": summary_path.name,
        "old_schema": "none" if not old else
                      ("already corrected" if "primary_at_warn" in old else "block-only"),
        "old_C_malicious": old_C,
        "new_C_malicious_at_warn": new_C,
        "coverage": corrected["primary_at_warn"].get("malicious", {}).get(
            "correlation_coverage"),
    }

    if write:
        summary["abcd_partition_corrected"] = corrected
        summary["_correction_note"] = NOTE
        summary["meta"]["warn_threshold"] = WARN_THRESHOLD
        summary["meta"]["block_threshold"] = BLOCK_THRESHOLD
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)
        out["written"] = True
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--write", action="store_true",
                    help="apply the correction; without this it is a dry run")
    args = ap.parse_args(argv)

    pairs = _find_pairs()
    if not pairs:
        print("no summary/sidecar pairs found")
        return 1

    print(f"{'artifact':<52}{'old schema':<18}{'old |C|':>9}{'|C| @WARN':>11}{'coverage':>10}")
    for summary, side in pairs:
        r = correct(summary, side, args.write)
        if "status" in r:
            print(f"{r['path'][:50]:<52}{r['status']}")
            continue
        cov = r["coverage"]
        print(f"{r['path'][:50]:<52}{r['old_schema']:<18}"
              f"{str(r['old_C_malicious']):>9}{str(r['new_C_malicious_at_warn']):>11}"
              f"{(f'{cov:.4f}' if isinstance(cov, float) else '-'):>10}")
    if not args.write:
        print("\ndry run — pass --write to apply")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
