"""
L6 Answer-Provenance Guard (v8, scratch/rca/v7/LAYERS_V8.md; config L6_ANSWER_GUARD = off | report | enforce).

The action-authorization layer governs side effects. A reply can still carry what third-party text put into it: a
link, an address or phone number to contact, an instruction addressed to the reader. This layer traces those elements
of the reply through the session's provenance store (authz/lineage.py) -- deterministic, no model:

  * unverified identifier: a link / e-mail / phone in the reply whose most trusted origin is third-party text (T3) or
    document text (T2) -- never typed by the user, not from the user's own records;
  * relayed instruction: a reply sentence that addresses the reader with an instruction AND copies >= 6 consecutive
    words from tool-output text.

enforce: unverified identifiers are replaced with a notice; relayed instructions get a provenance note appended.
report:  findings only. Faithfulness of a summary is NOT checked (that is semantic).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from sentinel.layers.layer4_agentic.authz import lineage as lin

LINK_NOTICE = "[link removed: it came from third-party content, not from you or your own records]"
NOTE = ("\n\n[Note from DIDA: part of this answer repeats instructions found in third-party content "
        "(a tool result or document); treat them with care.]")
_INSTRUCTION = re.compile(r"\b(visit|click|open|go to|call|contact|send|transfer|pay|wire|log ?in|sign ?in|download|"
                          r"install|reply|forward|share|enter|provide|update your|reset your|verify your|confirm your)\b",
                          re.I)
_SENT = re.compile(r"(?<=[.!?])\s+|\n+")
_NGRAM = 6


@dataclass
class AnswerReport:
    text: str
    unverified: list = field(default_factory=list)      # [(kind, value, tier)]
    relayed: list = field(default_factory=list)         # [sentence]
    changed: bool = False

    @property
    def findings(self) -> int:
        return len(self.unverified) + len(self.relayed)


def _ngrams(words: list[str], n: int) -> set:
    return {" ".join(words[i:i + n]) for i in range(len(words) - n + 1)}


def _content_leaves(session_id: str, addressed_only: bool) -> list:
    """Third-party text leaves (T2 / T3, not structural); with addressed_only, only those that address THE AI
    (core/addressee.py cues: L6 v2 -- 2026-11-04, scratch/rca/l6/L6_RCA.md: all 92 injection texts carry a cue,
    0 / 443 benign third-party leaves do)."""
    leaves = [lf for lf in lin.session(session_id).leaves if lf.tier in (lin.T2, lin.T3) and not lf.structural]
    if not addressed_only:
        return leaves
    return [s for s in (_addressed_span(lf) for lf in leaves) if s is not None]


class _Span:
    def __init__(self, text: str):
        self.text = text


def _addressed_span(leaf):
    """The part of a third-party leaf that addresses the AI: from the first to the last sentence carrying an addressee
    cue, one sentence either side (the injected goal sits between the framing sentences, right after the last one, or
    just before the first). None without a cue. v2.1 (2026-11-04): the whole leaf made answers that quote the benign
    part of a poisoned document count too; dropping the sentence before the span lost 2 / 21 dev relays."""
    from sentinel.core.addressee import addressee_cues
    if sum(addressee_cues(leaf.text)) == 0:
        return None
    sents = [s for s in _SENT.split(leaf.text) if s.strip()]
    idx = [i for i, s in enumerate(sents) if sum(addressee_cues(s)) > 0]
    if not idx:                                       # the cue spans a sentence break (markup): keep the whole leaf
        return _Span(leaf.text)
    return _Span(" ".join(sents[max(0, min(idx) - 1): max(idx) + 2]))


def _content_ngrams(leaves: list) -> set:
    out = set()
    for leaf in leaves:
        out |= _ngrams(re.findall(r"\w+", leaf.text.lower()), _NGRAM)
    return out


def check_answer(session_id: str, reply: str, user_text: str = "", mode: str | None = None) -> AnswerReport:
    """v2 (config.L6_ADDRESSEE_GATE, default on): a reply element counts only when the third-party text it came from
    addresses the AI -- an identifier from such a leaf, or a sentence copying >= 6 consecutive words of one (no
    instruction verb needed: advertising injections carry none). v1 (gate off): any T2 / T3 identifier, and copied
    sentences with an instruction verb. Limit: human-addressed phishing in third-party text is not flagged by v2."""
    import sentinel.config as cfg
    mode = (mode or getattr(cfg, "L6_ANSWER_GUARD", "off")).lower()
    rep = AnswerReport(reply or "")
    if mode == "off" or not (reply or "").strip():
        return rep
    gate = bool(getattr(cfg, "L6_ADDRESSEE_GATE", True))
    leaves = _content_leaves(session_id, addressed_only=gate)
    text = reply
    for kind, ident in lin.identifiers_in(reply):
        res = lin.resolve(session_id, ident, user_text)
        if res.tier not in (lin.T2, lin.T3):
            continue
        if gate and not any(lin.fold(ident) in lf.text for lf in leaves):
            continue                                  # it came from text that addresses people, not the AI
        rep.unverified.append((kind, ident, res.tier))
        if mode == "enforce" and kind in ("url", "email", "phone"):
            text = text.replace(ident, LINK_NOTICE)
    grams = _content_ngrams(leaves)
    if grams:
        for sent in _SENT.split(reply):
            if not gate and not _INSTRUCTION.search(sent):
                continue
            if _ngrams(re.findall(r"\w+", sent.lower()), _NGRAM) & grams:
                rep.relayed.append(sent.strip()[:300])
    if mode == "enforce" and rep.relayed:
        text = text + NOTE
    rep.changed = text != reply
    rep.text = text
    return rep
