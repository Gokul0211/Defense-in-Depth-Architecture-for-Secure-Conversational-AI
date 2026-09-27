"""
D.3 corpus-scale verification — L5 provenance-based leak detection vs.
real AgentLeak name-type leaks.

WHY THIS EXISTS
------------------
B.8 measured L5's pure-regex pipeline against the full AgentLeak corpus
and found patient_name/name/employee_name leaks (48% of real malicious
samples) sitting at or near chance (AUROC 0.50-0.53) — a known,
documented gap (see pii_scanner.py's own RCA comment). D.3 built a
provenance-based fix (sensitive_value_extractor.py + layer5.py's
_provenance_leak_findings) but had not been measured at corpus scale
against AgentLeak's real name categories — this script does that.

WHY THIS NEEDS THE RAW TRACES, NOT THE PREPARED test.jsonl
-------------------------------------------------------------
sentinel/eval/data/agentleak/test.jsonl (built by prepare_agentleak.py)
only keeps the final C1 output text + ground-truth leak labels — it
deliberately discards each trace's earlier context, because the standard
L5 evaluator interface only scores text-in/text-out. But the provenance
mechanism's whole premise is "did a value seen earlier this session
reappear in the output" — it has nothing to check without that earlier
context. Each raw trace's `input.vault` dict (verified present in all
4 verticals: healthcare/finance/legal/corporate) *is* that earlier
context: the real sensitive record (e.g. `patient_name: "Jocelyn
Wright"`) a tool call would have retrieved before the agent's final
response. This script simulates real ingestion by running
extract_sensitive_value_candidates over the serialized vault (the same
function real ingestion points call on tool-response content), then
checks the trace's actual last-C1-message output against those tracked
values — exactly the D.3 mechanism, on exactly the data shape it was
built for.

METHODOLOGY, MATCHING B.8 FOR A FAIR BEFORE/AFTER
------------------------------------------------------
Same extraction rule as prepare_agentleak.py (verified 100% agreement
with each trace's official c1_leaked verdict): label = has_leak on the
last C1-channel message. "Name-type" category = leaked_fields containing
patient_name, name, employee_name, customer_name, client_name, or
candidate_name — the direct superset of B.8's cited
patient_name/name/employee_name cluster (opposing_party excluded: it is
often a party *description*, not reliably a "First Last" name string in
the vault).

Reports, on the real 5,006-trace corpus:
  1. Regex-only (existing pii_scanner) recall/precision/FPR on name-type
     leaks vs. all malicious samples — the B.8 baseline, recomputed here
     directly for a same-script apples-to-apples comparison.
  2. Provenance-only signal recall/precision/FPR on the same split.
  3. Combined (regex OR provenance) — the real production behavior,
     since layer5_scan_output takes both into account.

Usage:
    python -m sentinel.eval.verify_l5_provenance
"""

from __future__ import annotations

import json
from pathlib import Path

from sentinel.core.sensitive_value_extractor import extract_sensitive_value_candidates
from sentinel.layers.layer5_output.layer5 import _provenance_leak_findings
from sentinel.layers.layer5_output.pii_scanner import scan_for_pii

_SOURCE_DIR = Path(r"C:\Users\gokul\AppData\Local\Temp\agentleak_scratch")
_NAME_FIELDS = {"patient_name", "name", "employee_name", "customer_name", "client_name", "candidate_name"}


def _trace_files() -> list[Path]:
    results_dir = _SOURCE_DIR / "benchmarks" / "ieee_repro" / "results"
    files = sorted((results_dir / "traces").glob("*.json"))
    files += sorted((results_dir / "tools" / "traces").glob("*.json"))
    return files


def _extract(trace: dict) -> dict | None:
    c1_messages = [m for m in trace.get("channel_messages", []) if m.get("channel") == "C1"]
    if not c1_messages:
        return None
    last_c1 = c1_messages[-1]
    vault = trace.get("input", {}).get("vault", {})
    if not isinstance(vault, dict):
        vault = {}
    vault_text = " ".join(str(v) for v in vault.values())
    return {
        "text": last_c1.get("content", ""),
        "has_leak": bool(last_c1.get("has_leak")),
        "leaked_fields": last_c1.get("leaked_fields", []),
        "vault_text": vault_text,
    }


def main() -> None:
    files = _trace_files()
    if not files:
        raise SystemExit(f"No trace files found under {_SOURCE_DIR} — raw AgentLeak clone missing.")

    samples = []
    for fp in files:
        trace = json.loads(fp.read_text(encoding="utf-8"))
        sample = _extract(trace)
        if sample is not None:
            samples.append(sample)

    n_malicious = sum(1 for s in samples if s["has_leak"])
    n_benign = len(samples) - n_malicious
    name_type = [s for s in samples if s["has_leak"] and _NAME_FIELDS & set(s["leaked_fields"])]
    non_name_malicious = [s for s in samples if s["has_leak"] and not (_NAME_FIELDS & set(s["leaked_fields"]))]
    print(f"n_samples={len(samples)}  n_malicious={n_malicious}  n_benign={n_benign}")
    print(f"n_name_type_leaks={len(name_type)}  n_non_name_malicious={len(non_name_malicious)}")

    def eval_signal(fn, label):
        tp_name = sum(1 for s in name_type if fn(s))
        tp_all_malicious = sum(1 for s in samples if s["has_leak"] and fn(s))
        fp = sum(1 for s in samples if not s["has_leak"] and fn(s))
        recall_name = tp_name / len(name_type) if name_type else 0.0
        recall_all = tp_all_malicious / n_malicious if n_malicious else 0.0
        precision = tp_all_malicious / (tp_all_malicious + fp) if (tp_all_malicious + fp) else 0.0
        fpr = fp / n_benign if n_benign else 0.0
        print(f"\n[{label}]")
        print(f"  recall on name-type leaks : {recall_name:.4f}  ({tp_name}/{len(name_type)})")
        print(f"  recall on all malicious   : {recall_all:.4f}  ({tp_all_malicious}/{n_malicious})")
        print(f"  precision (all malicious) : {precision:.4f}")
        print(f"  FPR (on benign)           : {fpr:.4f}  ({fp}/{n_benign})")

    def regex_fires(s):
        findings, _ = scan_for_pii(s["text"])
        return bool(findings)

    def provenance_fires(s):
        tracked = extract_sensitive_value_candidates(s["vault_text"])
        findings, _ratio = _provenance_leak_findings(s["text"], tracked)
        return bool(findings)

    def combined_fires(s):
        return regex_fires(s) or provenance_fires(s)

    eval_signal(regex_fires, "Regex-only (B.8 baseline mechanism)")
    eval_signal(provenance_fires, "Provenance-only (D.3 new signal)")
    eval_signal(combined_fires, "Combined (real production behavior)")


if __name__ == "__main__":
    main()
