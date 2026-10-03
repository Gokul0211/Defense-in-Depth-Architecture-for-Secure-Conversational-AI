"""
DIDA demo scenarios: live replays of real benchmark items.

Each scenario loads one item from `sentinel/demo/items/` (built from the project's
own benchmarks by `build_items.py`) and sends it through the live layers in the
same stage order as the evaluation harness (`sentinel/eval/pipeline_sim.py`):

  user turns    -> L1 + L3 per turn
  documents     -> L2 ingest
  tool calls    -> L4 audit (calls are extracted from the item text, as the harness
                   does: it assumes the model followed the injected instruction)
  output        -> L5 scans the item text as a stand-in for a compromised reply
                   (no model is called; the same approximation as the harness)
  session       -> correlation engine

Every event's score, severity, action and explanation chain is computed from the
layer results (`sentinel.core.verdicts`); nothing asserts that a layer fired.
Unlike `simulate_pipeline`, a replay never resets global layer state, so it can run
next to live traffic. Chat messages broadcast during a replay carry `scripted: True`.
"""
from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime
from pathlib import Path

from sentinel.core import verdicts
from sentinel.core.correlation_engine import check_correlations
from sentinel.core.models import ThreatEvent
from sentinel.core.threat_bus import threat_bus
from sentinel.eval.pipeline_sim import parse_sample_text
from sentinel.layers.layer1 import layer1_check
from sentinel.layers.layer1_steg import layer1_steg_scan
from sentinel.layers.layer2_rag import layer2_ingest
from sentinel.layers.layer3 import layer3_check
from sentinel.layers.layer4_agentic import audit_tool_call
from sentinel.layers.layer5_output import layer5_scan_output

ITEMS_DIR = Path(__file__).resolve().parent / "items"

OUTPUT_APPROXIMATION = ("L5 scans the item text as a stand-in for a compromised reply; "
                        "no model is called.")
TOOL_APPROXIMATION = ("Tool calls are extracted from the item text, assuming the model "
                      "followed the injected instruction.")

SCENARIOS = {
    "slow_burn": {
        "name": "Slow-burn escalation",
        "desc": "A real DIDA-Bench conversation that escalates over four turns to an injection.",
        "layers": ["L1", "L3", "L5"],
    },
    "rag_agent": {
        "name": "Poisoned document, then a tool call",
        "desc": "A real DIDA-Bench product manual with an injected 'system update' that orders a tool call.",
        "layers": ["L1", "L2", "L3", "L4", "L5"],
    },
    "poisoned_rag_exfil": {
        "name": "Poisoned policy document, data exfiltration",
        "desc": "A real DIDA-Bench policy document whose hidden override asks for employee records.",
        "layers": ["L1", "L2", "L3", "L4", "L5"],
    },
    "exfil_after_probe": {
        "name": "Probe, then exfiltration",
        "desc": "A real DIDA-Bench session: a hidden instruction followed by a request for internal data.",
        "layers": ["L1", "L3", "L5"],
    },
    "multi_vector": {
        "name": "Full multi-stage chain",
        "desc": "A real DIDA-Bench full-chain attack spanning documents, turns and tool calls.",
        "layers": ["L1", "L2", "L3", "L4", "L5"],
    },
    "benign_control": {
        "name": "Benign control",
        "desc": "A real benign DIDA-Bench session. The honest expected outcome is that nothing blocks.",
        "layers": ["L1", "L2", "L3", "L4", "L5"],
    },
    "certified_bypass": {
        "name": "Certified sub-threshold attack",
        "desc": "A SPLIT-Bench v2 attack certified to stay under every layer's threshold. It is expected to pass.",
        "layers": ["L1", "L2", "L3", "L4", "L5"],
    },
    "image_steg": {
        "name": "Image steganography",
        "desc": "A real PNG with a DIDA-Bench injection hidden in its least-significant bits.",
        "layers": ["L1"],
    },
    "canary_probe": {
        "name": "System-prompt extraction",
        "desc": "A request to repeat the system prompt and a reply that contains the canary token.",
        "layers": ["L5"],
    },
}


def _load(scenario_id: str) -> dict:
    with (ITEMS_DIR / f"{scenario_id}.json").open(encoding="utf-8") as f:
        return json.load(f)


def _source_label(item: dict) -> str:
    if item.get("source") == "scripted":
        return "scripted"
    return f"{item['source']} ({item['sample_id']})"


def scenario_list() -> list[dict]:
    """Public metadata for `GET /sentinel/demo`, including where each item comes from."""
    out = []
    for sid, meta in SCENARIOS.items():
        item = _load(sid)
        out.append({
            "id": sid, **meta,
            "source": item.get("source"),
            "sample_id": item.get("sample_id"),
            "scripted": ["user turn", "assistant reply"] if item.get("source") == "scripted" else [],
            "approximations": [] if sid in ("image_steg", "canary_probe")
                              else [TOOL_APPROXIMATION, OUTPUT_APPROXIMATION],
        })
    return out


def _now() -> str:
    return datetime.now().strftime("%H:%M:%S")


def _evt_id() -> str:
    return f"evt_{uuid.uuid4().hex[:8]}"


async def _emit(session_id: str, layer: str, threat_type: str, verdict: dict, summary: str,
                note: str, demo: dict, turn: int | None = None, evidence: dict | None = None):
    await threat_bus.emit(ThreatEvent(
        event_id=_evt_id(), timestamp=_now(), session_id=session_id,
        layer=layer, threat_type=threat_type,
        severity=verdict["severity"], threat_score=verdict["score"], action=verdict["action"],
        evidence={**(evidence or {}), "demo": demo},
        explanation={"summary": summary, "chain": verdict["chain"]},
        turn=turn, note=note[:60],
    ))


async def _say(chat_fn, role: str, content: str):
    if chat_fn:
        await chat_fn({"role": role, "content": content, "scripted": True})


async def _replay_item(session_id: str, item: dict, chat_fn, pause: float):
    """Send one benchmark item through the live layers, stage by stage."""
    demo = {"item": item["sample_id"], "source": item["source"]}
    parsed = parse_sample_text(item["text"])
    history: list[dict] = []

    turns = parsed.turns or ([parsed.user_query] if parsed.user_query else [])
    for text in turns:
        await _say(chat_fn, "user", text)
        l1 = await layer1_check(text)
        l3 = await layer3_check(session_id, text)
        session = await threat_bus.get_session(session_id)
        session.turn_provenance.append({"turn_index": len(session.turn_provenance),
                                        "text": text, "l1_score": l1.score})
        v = verdicts.input_verdict(l1, l3)
        await _emit(session_id, v["dominant"], "DRIFT" if v["dominant"] == "L3" else l1.threat_class,
                    v, v["reason"], f"turn {l3.turn_count}: score={v['score']:.3f}",
                    {**demo, "stage": "turn"}, turn=l3.turn_count,
                    evidence={"l1": l1.to_dict(), "l3": l3.to_dict()})
        history.append({"role": "user", "content": text})
        await check_correlations(session_id)
        await asyncio.sleep(pause)

    flagged: list[dict] = []
    for doc in parsed.documents:
        result = await layer2_ingest(doc, "demo_item")
        v = verdicts.l2_ingest_verdict(result, "demo_item")
        threat_type = ("KNOWLEDGE_POISONING" if result.get("quarantined")
                       else "CHUNK_FLAGGED_FOR_REVIEW" if result.get("review_flagged") else "CHUNK_CLEAN")
        await _emit(session_id, "L2", threat_type, v, result.get("reason", ""),
                    f"document: score={v['score']:.3f}", {**demo, "stage": "document"},
                    evidence={"l2": result.get("metadata", {})})
        if result.get("quarantined") or result.get("review_flagged"):
            flagged.append(result)
        await asyncio.sleep(pause)
    if flagged:
        session = await threat_bus.get_session(session_id)
        session.l2_flagged_chunks.extend(flagged)

    for tool_name, raw_args in parsed.tool_call_candidates:
        parameters = {"arg0": raw_args.strip("'\" ")} if raw_args else {}
        l4 = await audit_tool_call(tool_name=tool_name, parameters=parameters, reasoning_trace=None,
                                   session_id=session_id, conversation_history=history,
                                   flagged_chunks=flagged)
        session = await threat_bus.get_session(session_id)
        session.l4_calls.append({**l4.to_dict(), "tool_name": tool_name, "parameters": parameters})
        v = verdicts.l4_verdict(l4)
        await _emit(session_id, "L4", l4.threat_class, v, l4.reason,
                    f"{tool_name}: score={v['score']:.3f}",
                    {**demo, "stage": "tool_call", "approximation": TOOL_APPROXIMATION},
                    evidence={"l4": l4.to_dict()})
        await check_correlations(session_id)
        await asyncio.sleep(pause)

    l5, _sanitized = await layer5_scan_output(item["text"], None, session_id)
    session = await threat_bus.get_session(session_id)
    session.l5_scores.append(l5.score)
    v = verdicts.l5_verdict(l5)
    await _emit(session_id, "L5", l5.threat_class, v, l5.reason, f"output: score={v['score']:.3f}",
                {**demo, "stage": "output", "approximation": OUTPUT_APPROXIMATION},
                evidence={"l5": l5.to_dict()})
    await check_correlations(session_id)


async def _replay_image(session_id: str, item: dict):
    image = (ITEMS_DIR / item["image"]).read_bytes()
    steg = await layer1_steg_scan(image)
    v = verdicts.steg_verdict(steg, item["image"])
    await _emit(session_id, "L1", "IMAGE_STEG" if steg.get("is_malicious") else "IMAGE_CLEAN",
                v, steg.get("reason", ""), f"image: score={v['score']:.3f}",
                {"item": item["sample_id"], "source": item["source"], "stage": "image"},
                evidence={"l1_steg": steg})
    await check_correlations(session_id)


async def _replay_canary(session_id: str, item: dict, chat_fn, pause: float):
    from sentinel.config import CANARY_TOKEN
    reply = item["reply_template"].format(canary=CANARY_TOKEN)
    await _say(chat_fn, "user", item["user_turn"])
    await asyncio.sleep(pause)
    await _say(chat_fn, "assistant", reply)
    l5, _sanitized = await layer5_scan_output(
        reply, item["system_prompt_template"].format(canary=CANARY_TOKEN), session_id)
    session = await threat_bus.get_session(session_id)
    session.l5_scores.append(l5.score)
    v = verdicts.l5_verdict(l5)
    await _emit(session_id, "L5", l5.threat_class, v, l5.reason, f"output: score={v['score']:.3f}",
                {"item": "canary_probe", "source": "scripted", "stage": "output"},
                evidence={"l5": l5.to_dict()})
    await check_correlations(session_id)


async def run_scenario(scenario_id: str, chat_broadcast_fn=None, session_id: str | None = None,
                       pause: float = 0.8) -> str:
    """Replay one scenario's item through the live layers; returns the session id."""
    if scenario_id not in SCENARIOS:
        raise KeyError(scenario_id)
    session_id = session_id or f"demo_{uuid.uuid4().hex[:6]}"
    item = _load(scenario_id)
    if scenario_id == "image_steg":
        await _replay_image(session_id, item)
    elif scenario_id == "canary_probe":
        await _replay_canary(session_id, item, chat_broadcast_fn, pause)
    else:
        await _replay_item(session_id, item, chat_broadcast_fn, pause)
    return session_id
