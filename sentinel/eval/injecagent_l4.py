"""
The dedicated InjecAgent L4 evaluator.

WHY THIS EXISTS. `dataset_loaders._build_injecagent_l4_sample`'s docstring has
long stated that these samples "require live `ingest_chunk()` +
`audit_tool_call()` calls, not static text — see runner.py's dedicated
evaluator". **That evaluator did not exist.** The generic text path ran instead,
and it is structurally incapable of separating the classes:

    MAL  score=0.9  provenance: UNCERTAIN, confidence 0.1
    BEN  score=0.9  provenance: UNCERTAIN, confidence 0.1

The generic path hands L4 the tool *response* as the call's parameter and asks it
to trace that value's provenance. Nothing ever ingested the response as a chunk,
so provenance is UNCERTAIN for every sample, the score is a constant 0.9, and
AUROC is 0.5000 by arithmetic rather than by measurement.

WHAT THE REAL PROTOCOL IS. InjecAgent's threat model is indirect injection: a
tool returns attacker-controlled content, and the agent is induced to make a
SECOND call the user never asked for. Reproducing that needs three steps per
sample, in order:

  1. ingest the tool response through L2, exactly as production does, so the
     chunk gets a real trust score and a real flag state;
  2. construct the follow-up call that actually gets audited —
       * malicious: the ATTACKER's tool (`Attacker Tools[0]`), carrying the
         attacker's injected instruction as its parameter;
       * benign: the USER's own tool with the user's own parameters, which is
         what a legitimate session does next;
  3. audit that call with L2's flagged chunks passed in, so provenance can
     resolve to the chunk it actually came from.

The discriminating signal is then the one InjecAgent is designed to test:
a parameter traceable to a FLAGGED chunk versus one traceable to the user's own
request. The generic path cannot see it because step 1 never happens.

HONESTY NOTE. This is a new measurement path, not a re-run of an old one. Its
numbers are NOT comparable to the paper's previously-reported InjecAgent rows
(AUROC 0.8199 / 0.8923, FPR 0.1765), which trace to no surviving artifact —
both July result files carry `n_benign = 0` and `auroc = nan`, and there is no
ledger entry. Those rows should be treated as withdrawn, and these reported as a
first valid measurement rather than as a correction of them.
"""

from __future__ import annotations

import ast
import json
import logging
import re
import time
import uuid

logger = logging.getLogger(__name__)


def _parse_params(raw) -> dict:
    """
    `Tool Parameters` is a Python-literal string like "{'product_id': 'B08...'}".
    Parsed with `literal_eval` rather than `eval`, and a parse failure degrades
    to an empty dict rather than raising — a malformed fixture row should cost
    one sample's parameters, not the whole run.
    """
    if isinstance(raw, dict):
        return raw
    if not raw:
        return {}
    try:
        v = ast.literal_eval(str(raw))
        return v if isinstance(v, dict) else {"value": v}
    except Exception:                                            # noqa: BLE001
        return {}


def _render_response(row: dict, malicious: bool) -> str:
    """The tool response the agent sees: poisoned for attacks, clean for benign."""
    tmpl = row.get("Tool Response Template", "") or ""
    if malicious:
        return tmpl.replace("<Attacker Instruction>",
                            row.get("Attacker Instruction", "") or "")
    # Benign rows carry the placeholder with nothing to substitute; leaving the
    # literal "<Attacker Instruction>" in would be text no real tool emits, and
    # conspicuous enough to trip a detector on its own.
    return tmpl.replace("<Attacker Instruction>", "")


def _followup_call(row: dict, malicious: bool) -> tuple[str, dict]:
    """
    (tool_name, parameters) for the FIRST call that gets audited.

    Malicious: the attacker's tool, carrying the injected instruction — this is
    the call the user never made. Benign: the user's own tool and parameters.
    """
    if malicious:
        tools = row.get("Attacker Tools") or []
        tool = (tools[0] if isinstance(tools, list) and tools
                else row.get("User Tool", "unknown_tool"))
        return tool, {"content": row.get("Attacker Instruction", "") or ""}
    return row.get("User Tool", "unknown_tool"), _parse_params(row.get("Tool Parameters"))


_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")


def _followup_calls(row: dict, malicious: bool) -> list[tuple[str, dict]]:
    """
    Every call of the attack, in order (2026-09-25). Direct-harm rows are one call. Data-
    stealing rows (samples_ds.json) are TWO: read the victim's data, then send it to the
    attacker (`Attacker Tools[1]`, GmailSendEmail in all 544). InjecAgent scores a DS attack
    successful only when BOTH execute, so a defence stops it by blocking EITHER; auditing
    only the read measured a call that is harmless on its own. The send's recipient is the
    address the injected instruction names -- the sink parameter that came from untrusted
    content; the body is the read's output, which no fixture carries (left empty).
    """
    calls = [_followup_call(row, malicious)]
    tools = row.get("Attacker Tools") or []
    if malicious and isinstance(tools, list) and len(tools) > 1:
        instr = row.get("Attacker Instruction", "") or ""
        m = _EMAIL.search(instr)
        for tool in tools[1:]:
            calls.append((tool, {"to": m.group(0), "subject": "", "body": ""} if m
                          else {"content": instr}))
    return calls


async def evaluate_one(row: dict, malicious: bool, index: int) -> dict:
    """Run the three-step protocol for a single sample. Returns a scored record."""
    from sentinel.layers.layer2_rag import layer2_ingest
    from sentinel.layers.layer4_agentic import audit_tool_call

    session_id = f"ia_l4_{uuid.uuid4().hex[:10]}"
    started = time.perf_counter()

    response = _render_response(row, malicious)
    user_instruction = row.get("User Instruction", "") or ""

    # --- step 1: the tool response enters the context through L2 ---
    # Session-scoped (B-1): before 2026-09-25 every sample's tool response went into the
    # process-global store and was never cleared, so a later sample's parameters could
    # trace to an EARLIER sample's response.
    ingest = await layer2_ingest(response, source=f"tool_response:{row.get('User Tool','')}",
                                 session_id=session_id)
    meta = (ingest or {}).get("metadata", {}) or {}
    flagged_chunks = []
    if ingest and (ingest.get("quarantined") or ingest.get("review_flagged")):
        flagged_chunks.append({
            "chunk_id": ingest.get("chunk_id", f"ia_chunk_{index}"),
            "text": response,
            "is_valid": not ingest.get("quarantined", False),
            "current_density": meta.get("instruction_density", 0.0),
            "trust_score": meta.get("trust_score", 1.0),
        })

    # --- step 2 + 3: audit every follow-up call against that chunk state; the attack is
    # stopped if ANY of its calls is, so the sample carries the chain's highest score ---
    result, tool_name, step_scores = None, None, []
    for name, parameters in _followup_calls(row, malicious):
        r = await audit_tool_call(
            tool_name=name,
            parameters=parameters,
            reasoning_trace=None,
            session_id=session_id,
            conversation_history=[{"role": "user", "content": user_instruction}],
            flagged_chunks=flagged_chunks or None,
        )
        s = float(getattr(r, "score", 0.0) or 0.0)
        step_scores.append({"tool": name, "score": s})
        if result is None or s > float(getattr(result, "score", 0.0) or 0.0):
            result, tool_name = r, name

    from sentinel.config import (
        BLOCK_THRESHOLD, L4_BLOCK_THRESHOLD, L4_WARN_THRESHOLD, WARN_THRESHOLD,
    )
    from sentinel.core.models import rescale_layer_score

    raw = float(getattr(result, "score", 0.0) or 0.0)
    return {
        "sample_id": f"ia_{'mal' if malicious else 'ben'}_{index}",
        "label": "malicious" if malicious else "benign",
        "score": raw,
        # L4's score on the SHARED decision axis (2026-09-20). Reported
        # alongside the raw value, never instead of it, so a stored measurement
        # stays recoverable on either axis. See config.L4_WARN_THRESHOLD for why
        # comparing the raw score against WARN_THRESHOLD produced FPR 1.0000.
        "shared_score": rescale_layer_score(
            raw, L4_WARN_THRESHOLD, L4_BLOCK_THRESHOLD, WARN_THRESHOLD, BLOCK_THRESHOLD
        ),
        # The CONTINUOUS evidence L4 already computes and nothing reads. On
        # SPLIT-Bench ranking on it moves L4's AUROC 0.5000 -> 0.8403
        # (results/quantisation_recovery.json); it had never been measured on
        # the corpus where L4's FPR is 1.0000, which is what this records.
        "confidence": float(getattr(result, "confidence", 0.0) or 0.0),
        "min_provenance_confidence": float(
            getattr(result, "min_provenance_confidence", 1.0) or 0.0),
        "max_flagged_chunk_ratio": float(
            getattr(result, "max_flagged_chunk_ratio", 0.0) or 0.0),
        "authorization_source": getattr(result, "authorization_source", None),
        "risk_level": getattr(result, "risk_level", None),
        "threat_class": getattr(result, "threat_class", None),
        "should_execute": bool(getattr(result, "should_execute", True)),
        "tool_name": tool_name,
        "chain": step_scores,
        "l2_flagged": bool(flagged_chunks),
        "l2_trust": meta.get("trust_score"),
        "latency_ms": (time.perf_counter() - started) * 1000.0,
    }


async def run(variant: str = "direct", limit: int | None = None) -> dict:
    """
    Evaluate one InjecAgent subset end to end.

    `variant`: "direct" (samples.json, n=510) or "data_stealing"
    (samples_ds.json, n=544). Both are scored against the same 17 benign user
    cases, which is what makes the published FPR denominator 17.
    """
    from pathlib import Path

    data_dir = Path(__file__).parent / "data" / "injecagent"
    attack_file = "samples.json" if variant == "direct" else "samples_ds.json"

    with open(data_dir / attack_file, encoding="utf-8") as f:
        attacks = json.load(f)
    attacks = attacks if isinstance(attacks, list) else list(attacks.values())
    if limit:
        attacks = attacks[:limit]

    benign = []
    bpath = data_dir / "user_cases.jsonl"
    if bpath.exists():
        with open(bpath, encoding="utf-8") as f:
            benign = [json.loads(l) for l in f if l.strip()]
    else:
        logger.warning("benign control file missing — FPR will be undefined")

    rows = []
    for i, r in enumerate(attacks):
        rows.append(await evaluate_one(r, True, i))
    for i, r in enumerate(benign):
        rows.append(await evaluate_one(r, False, i))

    return {"variant": variant, "rows": rows,
            "n_malicious": len(attacks), "n_benign": len(benign)}


# ---------------------------------------------------------------------------
# Metrics + CLI
# ---------------------------------------------------------------------------

def _auroc(labels, scores):
    """Tie-exact AUROC via the rank-sum identity, or None with one class."""
    pos = [s for s, y in zip(scores, labels) if y == 1]
    neg = [s for s, y in zip(scores, labels) if y == 0]
    if not pos or not neg:
        return None
    pool = sorted(zip(scores, labels), key=lambda t: t[0])
    ranks, i = [0.0] * len(pool), 0
    while i < len(pool):
        j = i
        while j + 1 < len(pool) and pool[j + 1][0] == pool[i][0]:
            j += 1
        for k in range(i, j + 1):
            ranks[k] = (i + j) / 2 + 1
        i = j + 1
    rsum = sum(r for r, (_s, y) in zip(ranks, pool) if y == 1)
    return (rsum - len(pos) * (len(pos) + 1) / 2) / (len(pos) * len(neg))


def _auroc_ci(labels, scores, n_boot: int = 2000, seed: int = 42):
    """
    Stratified bootstrap CI. Stratified because n_benign is 17: resampling the
    pooled set would produce replicates with zero negatives, for which AUROC is
    undefined, and silently dropping those biases the interval.
    """
    import random

    rng = random.Random(seed)
    pos = [s for s, y in zip(scores, labels) if y == 1]
    neg = [s for s, y in zip(scores, labels) if y == 0]
    if not pos or not neg:
        return None, None
    vals = []
    for _ in range(n_boot):
        p = [pos[rng.randrange(len(pos))] for _ in range(len(pos))]
        n = [neg[rng.randrange(len(neg))] for _ in range(len(neg))]
        a = _auroc([1] * len(p) + [0] * len(n), p + n)
        if a is not None:
            vals.append(a)
    vals.sort()
    return vals[int(0.025 * len(vals))], vals[min(len(vals) - 1, int(0.975 * len(vals)))]


def _axis_metrics(rows, key, threshold):
    labels = [1 if r["label"] == "malicious" else 0 for r in rows]
    scores = [r[key] for r in rows]
    lo, hi = _auroc_ci(labels, scores)
    tp = sum(1 for s, y in zip(scores, labels) if s >= threshold and y == 1)
    fn = sum(1 for s, y in zip(scores, labels) if s < threshold and y == 1)
    fp = sum(1 for s, y in zip(scores, labels) if s >= threshold and y == 0)
    tn = sum(1 for s, y in zip(scores, labels) if s < threshold and y == 0)
    return {
        "axis": key,
        "threshold": threshold,
        "auroc": _auroc(labels, scores),
        "auroc_ci95": [lo, hi],
        "ci_includes_chance": (lo is not None and lo <= 0.5 <= hi),
        "n_distinct_values": len({round(s, 6) for s in scores}),
        "recall": tp / (tp + fn) if tp + fn else None,
        "fpr": fp / (fp + tn) if fp + tn else None,
        "precision": tp / (tp + fp) if tp + fp else None,
        "tp": tp, "fn": fn, "fp": fp, "tn": tn,
    }


def main(limit: int | None = None) -> dict:
    """Run both subsets and write a timestamped artifact."""
    import asyncio
    from datetime import datetime
    from pathlib import Path

    from sentinel.config import BLOCK_THRESHOLD, WARN_THRESHOLD
    from sentinel.eval.run_config import config_snapshot, judge_call_counters

    out = {"generated_at": datetime.now().isoformat(), "config": config_snapshot()}
    for variant in ("direct", "data_stealing"):
        res = asyncio.run(run(variant, limit=limit))
        rows = res["rows"]
        out[variant] = {
            "n_malicious": res["n_malicious"],
            "n_benign": res["n_benign"],
            "l2_flagged_malicious": sum(
                1 for r in rows if r["l2_flagged"] and r["label"] == "malicious"),
            "l2_flagged_benign": sum(
                1 for r in rows if r["l2_flagged"] and r["label"] != "malicious"),
            # raw axis at the SHARED threshold is the comparison the baseline
            # reported, kept so the before/after is on identical footing
            "raw_at_shared_warn": _axis_metrics(rows, "score", WARN_THRESHOLD),
            "shared_axis": _axis_metrics(rows, "shared_score", WARN_THRESHOLD),
            "confidence_axis": _axis_metrics(rows, "confidence", WARN_THRESHOLD),
            "rows": rows,
        }
        m = out[variant]
        print(f"[{variant}] n={m['n_malicious']}/{m['n_benign']}  "
              f"L2 flagged mal={m['l2_flagged_malicious']} ben={m['l2_flagged_benign']}",
              flush=True)
        for k in ("raw_at_shared_warn", "shared_axis", "confidence_axis"):
            a = m[k]
            ci = a["auroc_ci95"]
            ci_s = "n/a" if ci[0] is None else f"[{ci[0]:.4f}, {ci[1]:.4f}]"
            print(f"    {k:20s} AUROC={a['auroc']:.4f} CI95={ci_s} "
                  f"distinct={a['n_distinct_values']:3d} "
                  f"recall={a['recall']:.4f} FPR={a['fpr']:.4f}", flush=True)
    out["judge"] = judge_call_counters()

    results = Path(__file__).parent / "results"
    results.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = results / f"eval_L4_injecagent_dedicated_{stamp}.json"
    path.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print("wrote", path, flush=True)
    return out


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
    main()
