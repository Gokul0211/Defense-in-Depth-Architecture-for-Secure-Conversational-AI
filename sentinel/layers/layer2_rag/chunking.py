"""
Sentence-aware chunking for ingested documents (L2 review C7, 2026-10-28; config.L2_CHUNKING, default "sentence").

The PDF upload cut the extracted text at fixed 1,000-character offsets, with no overlap and no regard for sentence
boundaries, so a sentence -- an injected instruction among them -- that straddled a cut was split into two halves and
each half was scored alone. Corpus-poisoning studies show chunking decides which poison survives to retrieval
("When Poison Fails After Retrieval", arXiv 2606.11265), so chunking is part of the defence.

Here chunks are built from whole sentences up to TARGET_CHARS, and consecutive chunks overlap by the trailing
sentences of the previous chunk (up to OVERLAP_CHARS), so a sentence near a boundary is whole in at least one chunk.
A single sentence longer than TARGET_CHARS is split at whitespace (never mid-word) with the same overlap.
"legacy" restores the fixed cuts.
"""
from __future__ import annotations

import re

TARGET_CHARS = 1000
OVERLAP_CHARS = 200
_SENT = re.compile(r"(?<=[.!?])\s+|\n{2,}")


def _hard_split(s: str) -> list[str]:
    out, start = [], 0
    while start < len(s):
        end = min(len(s), start + TARGET_CHARS)
        if end < len(s):
            sp = s.rfind(" ", start + TARGET_CHARS - OVERLAP_CHARS, end)
            end = sp if sp > start else end
        out.append(s[start:end].strip())
        if end >= len(s):
            break
        start = max(end - OVERLAP_CHARS, start + 1)
        sp = s.find(" ", start)
        start = sp + 1 if 0 <= sp < end else start
    return [c for c in out if c]


def chunk_text(text: str) -> list[str]:
    """Overlapping, sentence-aligned chunks of `text` (L2_CHUNKING="sentence") or the legacy fixed cuts."""
    import sentinel.config as cfg
    text = (text or "").strip()
    if not text:
        return []
    if getattr(cfg, "L2_CHUNKING", "sentence") == "legacy":
        return [c.strip() for c in (text[i:i + TARGET_CHARS] for i in range(0, len(text), TARGET_CHARS)) if c.strip()]
    sents = []
    for s in (p.strip() for p in _SENT.split(text)):
        if not s:
            continue
        sents.extend(_hard_split(s) if len(s) > TARGET_CHARS else [s])
    chunks, cur = [], []
    for s in sents:
        if cur and len(" ".join(cur)) + 1 + len(s) > TARGET_CHARS:
            chunks.append(" ".join(cur))
            carry, size = [], 0
            for prev in reversed(cur):
                if size + len(prev) > OVERLAP_CHARS:
                    break
                carry.insert(0, prev)
                size += len(prev) + 1
            cur = carry
        cur.append(s)
    if cur:
        tail = " ".join(cur)
        if not chunks or tail != chunks[-1]:
            chunks.append(tail)
    return chunks
