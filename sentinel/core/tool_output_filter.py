"""
Field-level withholding of tool outputs (v7 proposal P3; config TOOL_OUTPUT_POLICY).

The tool-response contract used to withhold an ENTIRE output once L1 scored it at or above BLOCK. Live AgentDojo lost
17 of 18 user tasks under attack that way (results.md §13.1): the same output held the data the task needed. Here only
the prose fields L1 flags are replaced by a fixed marker; structural fields (ids, names, amounts, dates) and unflagged
prose pass. If the filtered output still scores at or above BLOCK, the whole output is withheld as before.

Statuses: "clean" (nothing flagged), "filtered" (some fields replaced), "withheld" (fallback).
"""
from __future__ import annotations

import re
from dataclasses import dataclass

MARKER = "[field withheld by DIDA]"


@dataclass
class Filtered:
    text: str
    status: str
    fields_total: int = 0
    fields_withheld: int = 0


def _prose_spans(text: str) -> list[tuple[int, int]]:
    from sentinel.layers.layer1 import _FIELD_RE, _MIN_FIELD_WORDS
    s = text.lstrip()
    if not (s[:1] in "[{(" or re.match(r"^[A-Za-z_]\w*\(", s)):
        return [(0, len(text))] if len(re.findall(r"\w+", text)) >= _MIN_FIELD_WORDS else []
    spans = []
    for m in _FIELD_RE.finditer(text):
        g = 1 if m.group(1) is not None else 2
        if len(re.findall(r"\w+", (m.group(g) or "").replace("\\n", " "))) >= _MIN_FIELD_WORDS:
            spans.append((m.start(g), m.end(g)))
    return spans


async def _score(text: str) -> float:
    from sentinel.layers.layer1 import layer1_check
    return (await layer1_check(text, harm_head=False, source="tool_output")).score


async def filter_output(text: str, threshold: float | None = None) -> Filtered:
    import sentinel.config as cfg
    thr = cfg.l1_tool_output_block() if threshold is None else threshold
    if not (text or "").strip() or await _score(text) < thr:
        return Filtered(text or "", "clean")
    spans = _prose_spans(text)
    out, last, withheld = [], 0, 0
    for a, b in spans:
        if await _score(text[a:b].replace("\\n", "\n")) >= thr:
            out.append(text[last:a]); out.append(MARKER); last = b; withheld += 1
    out.append(text[last:])
    filtered = "".join(out)
    # nothing useful left (every unit replaced, e.g. a one-paragraph page) is withholding, not filtering
    nothing_left = len(re.findall(r"\w+", filtered.replace(MARKER, ""))) < 3
    if withheld == 0 or nothing_left or await _score(filtered) >= thr:
        return Filtered("", "withheld", len(spans), len(spans))
    return Filtered(filtered, "filtered", len(spans), withheld)
