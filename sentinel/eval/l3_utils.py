"""
Shared helpers for L3 (Conversational Drift Tracker) evaluation and
calibration tooling.

Factored out of sentinel/eval/runner.py during the 2026-07-24 RCA so that
`_evaluate_l3` (runner.py) and `calibrate_l3_weights.py` parse and clean
conversation turns identically — before this existed, any future change to
one would silently drift out of sync with the other.
"""

from __future__ import annotations

import re

# Literal filler strings a buggy earlier version of generate_l3_corpus.py
# could leak into real turn text (see that module's RCA comments). Stripped
# defensively here regardless of whether the corpus on disk has already been
# cleaned, so this parser is safe to run against old or new corpus files.
_ARTIFACT_STRINGS = ("(Assistant responds helpfully)", "(Assistant responds naturally)")

_TURN_RE = re.compile(r"\[Turn \d+\]\s*(.*?)(?=\[Turn \d+\]|$)", re.DOTALL)


def parse_l3_conversation(text: str) -> list[str]:
    """
    Parse a sample's "[Turn N] ..." formatted text into a clean list of
    turn strings, in order. Drops blank turns and any leaked generation
    artifact strings.
    """
    turns = _TURN_RE.findall(text)
    turns = [t.strip() for t in turns if t.strip()]
    if not turns:
        # Fallback: split on newlines (for text that never used the
        # "[Turn N]" format at all).
        turns = [line.strip() for line in text.split("\n") if line.strip()]

    cleaned = []
    for t in turns:
        for artifact in _ARTIFACT_STRINGS:
            t = t.replace(artifact, "").strip()
        if t:
            cleaned.append(t)
    return cleaned
