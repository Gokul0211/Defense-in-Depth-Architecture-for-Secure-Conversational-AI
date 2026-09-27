"""
Build the AUDITED benign multi-turn arms (deep_rca.md §10.1) from
scratch/trackB/audit_benign_arms.py's output.

Writes, for each corpus with an audit file, only the sessions audited "benign":
  sentinel/eval/data/benign_mt/<corpus>.jsonl      (read by the runner loaders
                                                    oasst_mt / mhj_oasst / mhj_wildchat_clean)
  scratch/trackB/data/<corpus>_clean.jsonl          (read by B-008 / B-009 / extract_jsonl)
and benign_mt/MANIFEST.json recording counts per label and the audit method (keyword-only
or keyword + policy judge, number adjudicated by hand), so every downstream number can say
which benign arm it used.

Usage: python -m sentinel.eval.build_benign_multiturn
"""
import json
from pathlib import Path

SRC = Path("scratch/trackB/data")
AUD = SRC / "audit"
OUT = Path(__file__).parent / "data" / "benign_mt"
CORPORA = ["oasst_ref", "oasst_test", "wildchat_ref", "wildchat_test", "wildchat_sens_ref", "wildchat_sens_test"]


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    manifest = {}
    for c in CORPORA:
        a, s = AUD / f"{c}.jsonl", SRC / f"{c}.jsonl"
        if not (a.exists() and s.exists()):
            print("skip (no audit or source):", c)
            continue
        aud = {r["sample_id"]: r for r in map(json.loads, open(a, encoding="utf-8"))}
        rows = [json.loads(l) for l in open(s, encoding="utf-8")]
        keep = [r for r in rows if aud.get(r["sample_id"], {}).get("audited_label") == "benign"]
        body = "\n".join(json.dumps({**r, "label": "benign", "benign_arm": c}, ensure_ascii=False) for r in keep)
        (OUT / f"{c}.jsonl").write_text(body, encoding="utf-8")
        (SRC / f"{c}_clean.jsonl").write_text(body, encoding="utf-8")
        labs = [aud.get(r["sample_id"], {}).get("audited_label", "unaudited") for r in rows]
        manifest[c] = {"n_source": len(rows), "n_benign_kept": len(keep),
                       "labels": {k: labs.count(k) for k in sorted(set(labs))},
                       "judge_used": any(v.get("judge_p") is not None for v in aud.values()),
                       "adjudicated": sum(bool(v.get("adjudicated")) for v in aud.values())}
        print(f"{c:20} kept {len(keep)}/{len(rows)}  {manifest[c]['labels']}")
    (OUT / "MANIFEST.json").write_text(json.dumps(manifest, indent=1), encoding="utf-8")
    print("wrote", OUT / "MANIFEST.json")


if __name__ == "__main__":
    main()
