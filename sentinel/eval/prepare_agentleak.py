"""
One-time AgentLeak corpus preparation — L5 external validation.

WHY THIS EXISTS
------------------
AgentLeak (github.com/Privatris/AgentLeak, arXiv:2602.11510, IEEE Access
2026) has no usable HuggingFace mirror — `humain2/AgentLeak` is a confirmed
empty stub (README only). The real data is 5,006 real execution-trace JSON
files in the GitHub repo's own reproduction results
(`benchmarks/ieee_repro/results/traces/` +
`benchmarks/ieee_repro/results/tools/traces/`), from the paper's own
5-model run (Claude-3.5-Sonnet, GPT-4o, GPT-4o-mini, Llama-3.3-70B,
Mistral-Large). This script condenses those into one local JSONL file,
mirroring `generate_sentinel_bench.py`'s pattern of shipping a prepared
local corpus rather than depending on a live external fetch at eval time.

EXTRACTION RULE — VERIFIED, NOT ASSUMED
-------------------------------------------
Each trace's `channel_messages` list carries per-message ground truth
(`channel`, `has_leak`, `leaked_fields`, `content`). Multi-agent traces
contain several C1-channel ("final output to user") messages — an early
single-agent attempt plus the actual final compiled answer. Confirmed
directly against all 5,006 traces before writing this script: the **last**
C1-channel message in each trace's `channel_messages` list matches that
trace's own `results.c1_leaked` verdict with 100% agreement. That is the
extraction rule used below — not a guess.

VAULT CONTEXT — ADDED 2026-09-14, CLOSING A REAL EVALUATION-CONSTRUCT GAP
------------------------------------------------------------------------------
The original version of this script discarded each trace's `input.vault`
dict (the earlier-context record a real tool call would have retrieved
before the agent's final response — e.g. `patient_name: "Jocelyn
Wright"`). That meant the standard L5 evaluation harness (runner.py),
which only ever saw the final output text, could never populate
`session.tracked_sensitive_values` and so could never exercise L5's
provenance-based leak check — only a bespoke side-script
(verify_l5_provenance.py) ever did, using a completely different
evaluation path (bypassing layer5_scan_output's real policy/exfil/canary
checks entirely) that produced a real but not directly comparable number.
`vault_text` (the same serialized-vault-values string
verify_l5_provenance.py already builds and verified against) is now
included in `metadata` so the standard harness can populate real
per-sample session state and exercise the REAL, full `layer5_scan_output`
pipeline end to end — one evaluation protocol, not two.

HONEST EXPECTATION — READ BEFORE TRUSTING A RUN AGAINST THIS CORPUS
------------------------------------------------------------------------
A 400-trace sample of real `leaked_fields` found 74% of leaks are
`patient_name` — free-text name disclosures in prose, not structured PII.
`sentinel/layers/layer5_output/pii_scanner.py`'s own RCA comment already
documents free-text name/medical disclosure as a known, deliberately
unfixed gap (needs NER or an LLM-based PHI classifier, not a regex
addition). Expect a real but weak number for a reason that's already
diagnosed, not a new mystery.

Usage:
    python -m sentinel.eval.prepare_agentleak --source-dir <path to a clone of Privatris/AgentLeak>
"""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

_DEFAULT_SOURCE = "C:/Users/gokul/AppData/Local/Temp/agentleak_scratch"
_OUT_DIR = Path(__file__).parent / "data" / "agentleak"


def _trace_files(source_dir: Path) -> list[Path]:
    results_dir = source_dir / "benchmarks" / "ieee_repro" / "results"
    files = sorted((results_dir / "traces").glob("*.json"))
    files += sorted((results_dir / "tools" / "traces").glob("*.json"))
    return files


def _extract_sample(trace: dict) -> dict | None:
    c1_messages = [m for m in trace.get("channel_messages", []) if m.get("channel") == "C1"]
    if not c1_messages:
        return None
    last_c1 = c1_messages[-1]

    label = "malicious" if last_c1.get("has_leak") else "benign"
    attack_type = trace.get("attack_family") or "none"

    vault = trace.get("input", {}).get("vault", {})
    if not isinstance(vault, dict):
        vault = {}
    vault_text = " ".join(str(v) for v in vault.values())

    return {
        "text": last_c1.get("content", ""),
        "label": label,
        "attack_type": attack_type,
        "target_layer": "L5",
        "source_benchmark": "agentleak",
        "sample_id": trace.get("trace_id", ""),
        "metadata": {
            "leaked_fields": last_c1.get("leaked_fields", []),
            "model": trace.get("model", ""),
            "vertical": trace.get("vertical", ""),
            "scenario_id": trace.get("scenario_id", ""),
            "n_c1_messages": len(c1_messages),
            "official_c1_leaked": trace.get("results", {}).get("c1_leaked"),
            "vault_text": vault_text,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", type=str, default=_DEFAULT_SOURCE,
                         help="Path to a local clone of github.com/Privatris/AgentLeak")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    source_dir = Path(args.source_dir)
    files = _trace_files(source_dir)
    if not files:
        raise SystemExit(
            f"No trace files found under {source_dir}/benchmarks/ieee_repro/results/ — "
            f"clone github.com/Privatris/AgentLeak first and pass --source-dir."
        )

    logger.info(f"Found {len(files)} trace files, extracting real last-C1-message samples...")

    samples = []
    n_skipped_no_c1 = 0
    n_agree = 0
    for fp in files:
        trace = json.loads(fp.read_text(encoding="utf-8"))
        sample = _extract_sample(trace)
        if sample is None:
            n_skipped_no_c1 += 1
            continue
        # Sanity check baked in at prep time, not just claimed in a docstring:
        # confirm the extraction rule still matches the trace's own official
        # verdict for every single trace, not just the earlier spot sample.
        derived_leaked = sample["label"] == "malicious"
        if derived_leaked == sample["metadata"]["official_c1_leaked"]:
            n_agree += 1
        samples.append(sample)

    if n_agree != len(samples):
        raise SystemExit(
            f"Extraction rule mismatch: only {n_agree}/{len(samples)} samples' derived "
            f"label agrees with the trace's own official c1_leaked verdict. The "
            f"'last C1 message' rule was verified at 100% agreement before writing this "
            f"script — investigate before trusting this output."
        )

    n_malicious = sum(1 for s in samples if s["label"] == "malicious")
    n_benign = len(samples) - n_malicious
    logger.info(
        f"Extracted {len(samples)} samples ({n_malicious} malicious / {n_benign} benign), "
        f"skipped {n_skipped_no_c1} traces with no C1 message. "
        f"100% agreement with official c1_leaked confirmed ({n_agree}/{len(samples)})."
    )

    _OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = _OUT_DIR / "test.jsonl"
    with open(out_path, "w", encoding="utf-8") as f:
        for s in samples:
            f.write(json.dumps(s, ensure_ascii=False) + "\n")
    logger.info(f"Wrote {out_path}")


if __name__ == "__main__":
    main()
