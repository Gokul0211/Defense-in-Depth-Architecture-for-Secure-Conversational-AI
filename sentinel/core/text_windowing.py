"""
Shared text-windowing helper used by both L1's semantic injection check
(layer1.py) and L2's instruction-density scoring (instruction_density.py).

Lives in sentinel/core/ rather than inside layer2_rag/ specifically so
layer1.py can import it directly: layer2_rag/__init__.py eagerly imports
chunk_store.py, which imports layer1_check from layer1.py — so having
layer1.py import anything from the layer2_rag package (even a leaf
submodule like instruction_density.py) creates a circular import the
moment layer2_rag's __init__.py runs before layer1.py has finished
defining layer1_check. Putting the shared helper in sentinel/core/,
which nothing in sentinel/layers/ is a dependency of, avoids that.
"""

import re

_SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+|\n+")

# Windows below this length get merged into a neighbor rather than scored
# alone — a 2-3 word fragment produces a noisy, not-very-meaningful
# embedding on its own.
MIN_WINDOW_CHARS = 20

# Defensive cap on how many windows a single input gets split into, so one
# pathologically long document can't turn one call into hundreds of
# embedding calls.
MAX_WINDOWS = 40


def split_into_windows(text: str) -> list[str]:
    """
    Split `text` into sentence-sized windows for similarity scoring.

    WHY THIS EXISTS: both instruction_density.py's chunk scoring and
    layer1.py's semantic injection check originally embedded their ENTIRE
    input as a single pooled vector and compared that one vector against a
    small set of template phrases. A short malicious instruction embedded
    inside an otherwise long, benign multi-paragraph document — the
    realistic RAG-poisoning pattern L2 exists to catch, and something
    chunk_store.py also feeds through layer1_check() during ingestion —
    gets averaged into the surrounding document's pooled embedding, driving
    the whole-text similarity score down toward the noise floor even when
    the malicious sentence itself would score very high in isolation.

    Confirmed twice on real data: once directly for instruction_density.py
    (a one-sentence injected command in an otherwise-plain product manual
    scored far below the quarantine threshold as a whole chunk), and again
    for layer1.py after calibrate_l2_trust.py's fitted logistic regression
    returned a NEGATIVE coefficient for L1's own score on these documents —
    a sign the evidence was inverted, not just weak, from this exact bug.

    Scoring each window independently and taking the max fixes this
    without any hand-coded keyword/regex detection of the injected
    phrasing itself — it stays a purely embedding-based signal, just
    applied at the right granularity. For short, single-sentence inputs
    (L1's normal per-turn usage, most L2 chunks) this produces exactly one
    window, identical to the previous whole-text behavior.
    """
    raw_pieces = [p.strip() for p in _SENTENCE_SPLIT_RE.split(text) if p.strip()]

    windows: list[str] = []
    buf = ""
    for piece in raw_pieces:
        buf = f"{buf} {piece}".strip() if buf else piece
        if len(buf) >= MIN_WINDOW_CHARS:
            windows.append(buf)
            buf = ""
    if buf:
        if windows:
            windows[-1] = f"{windows[-1]} {buf}".strip()
        else:
            windows.append(buf)

    if not windows:
        windows = [text]

    return _compress_to_cap(windows)


def _compress_to_cap(windows: list[str]) -> list[str]:
    """
    Reduce `windows` to at most MAX_WINDOWS while keeping EVERY sentence.

    THE BUG THIS REPLACES (found and measured 2026-09-20). This was
    `return windows[:MAX_WINDOWS]` — a hard truncation that silently discarded
    every window past the 40th. For any document longer than the cap, the tail
    never reached the scorer at all, so an injection placed near the end was
    invisible to L2's instruction density and to L1's Tier 2 *by construction* —
    not scored low, not scored at all.

    Measured on BIPIA's real malicious samples, which record where the attack was
    inserted (`metadata.position`):

        scenario  position  n     at cap   attack span DISCARDED
        abstract  end       400   73       63   (15.8% of the scenario)
        code      end       400    5        5   ( 1.3%)
        abstract  start     400   85        0
        (email / qa / table never reach the cap)

    So roughly one in six `abstract` end-insertion attacks could not be detected
    by any scoring rule, however good, because the text was dropped before
    embedding. That is an information-loss defect, not a detection weakness, and
    it is invisible in an aggregate AUROC.

    THE FIX, AND WHY IT IS THE RIGHT SHAPE. The cap exists to bound embedding
    cost — one pathologically long document must not become hundreds of model
    calls. Keeping the FIRST N windows honours the cost bound but discards
    coverage; merging adjacent windows honours it while keeping every sentence.
    The cost is identical (still at most MAX_WINDOWS embeddings) and the only
    price is coarser granularity inside merged windows, which dilutes a short
    injected sentence somewhat. Diluted is strictly better than absent: the
    previous behaviour scored those spans as if they did not exist.

    Documents at or under the cap are returned UNCHANGED, so every existing
    calibrated number that was measured on short content is bit-identical. Only
    over-cap documents — which were broken — see any difference.

    Merging is by near-equal consecutive groups rather than by content, so it
    introduces no new heuristic and no new tunable.
    """
    n = len(windows)
    if n <= MAX_WINDOWS:
        return windows

    merged: list[str] = []
    # near-equal contiguous partition: the first (n % MAX_WINDOWS) groups take
    # one extra window, which keeps group sizes within 1 of each other.
    base, extra = divmod(n, MAX_WINDOWS)
    i = 0
    for g in range(MAX_WINDOWS):
        size = base + (1 if g < extra else 0)
        merged.append(" ".join(windows[i:i + size]).strip())
        i += size
    return merged
