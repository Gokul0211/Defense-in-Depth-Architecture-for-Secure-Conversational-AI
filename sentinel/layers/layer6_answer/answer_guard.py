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
    scores: list = field(default_factory=list)          # v3: the relay judge's max P(yes) per candidate finding
    judge_ms: float = 0.0                               # v3: wall time of the judge pass (0 without candidates)

    @property
    def findings(self) -> int:
        return len(self.unverified) + len(self.relayed)

    @property
    def score(self) -> float:
        """Ranking score: v3 the judge's max P(yes) over candidates (0 without one); v2.1 1 / 0 (flagged or not)."""
        if self.scores:
            return max(self.scores)
        return 1.0 if self.findings else 0.0


def _ngrams(words: list[str], n: int) -> set:
    return {" ".join(words[i:i + n]) for i in range(len(words) - n + 1)}


def _content_leaves(session_id: str, addressed_only: bool) -> list:
    """Third-party text leaves (T2 / T3, not structural); with addressed_only, only those that address THE AI
    (core/addressee.py cues: L6 v2 -- 2026-11-04, scratch/rca/l6/L6_RCA.md: all 92 injection texts carry a cue,
    0 / 443 benign third-party leaves do)."""
    leaves = [lf for lf in lin.session(session_id).leaves if lf.tier in (lin.T2, lin.T3) and not lf.structural]
    if not addressed_only:
        return leaves
    import sentinel.config as cfg
    if getattr(cfg, "L6_STRUCTURED_SPAN", False):
        return [sp for lf in leaves for sp in _structured_spans(lf)]
    return [s for s in (_addressed_span(lf) for lf in leaves) if s is not None]


class _Span:
    def __init__(self, text: str, seq: int = 0):
        self.text = text
        self.seq = seq                                # the tool output the span came from (lineage Leaf.seq)


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
        return _Span(leaf.text, getattr(leaf, "seq", 0))
    return _Span(" ".join(sents[max(0, min(idx) - 1): max(idx) + 2]), getattr(leaf, "seq", 0))


# v3 (config.L6_STRUCTURED_SPAN; results.md §26.2): segments end at sentence ends, real line breaks and serialized
# escapes (a tool output dumped as a Python / JSON string keeps its newlines as backslash + n)
_SEG = re.compile(r"(?<=[.!?])\s+|\n+|\\[nrt]")
_MAX_RAW = 200_000          # larger outputs are not parsed (v2.1's span is used)
_MAX_UNITS = 5_000          # walk cap: a YAML alias bomb cannot make the walk explode


_WRAP = re.compile(r"^\s*(?:<<|```[\w-]*)\s*(.*?)\s*(?:>>|```)\s*$", re.S)
# v3.4 (config.L6_SPAN_CLOSE_TAG; results.md §26.12): the closing form of the STRONG markup cue (core/addressee.py)
_CLOSE_TAG = re.compile(r"</\s*(?:information|instructions?|system|important|admin|sys|inst)\s*>", re.I)


def _parse_struct(t: str):
    """A list / mapping from the safe YAML loader, or None (plain text, a scalar, too large, not YAML)."""
    if not t or len(t) > _MAX_RAW or not ("\n" in t or t.lstrip()[:1] in "[{-"):
        return None
    try:
        import yaml
        obj = yaml.load(t, Loader=getattr(yaml, "CSafeLoader", yaml.SafeLoader))   # noqa: S506 -- safe loader
    except Exception:                                                              # noqa: BLE001 -- not YAML
        return None
    return obj if isinstance(obj, (list, dict)) else None


def _units(raw: str) -> list[str]:
    """v3: the units of a raw tool output -- the string keys and values of a YAML / flow-mapping parse when it yields a
    list or mapping (one transaction's subject, one e-mail's body, one hotel's reviews), else the raw text itself.
    Parsed with the safe loader only; a scalar parse result is ignored (a plain scalar folds line breaks away).
    v3.3 (config.L6_SPAN_V33; results.md §26.10): a wrapped output -- a spotlighting delimiter pair "<<" ... ">>", a code
    fence, or a serialized object embedded in other text -- is parsed inside its wrapper; text around an embedded
    object stays a unit of its own."""
    import sentinel.config as cfg
    t = raw or ""
    obj, extra = _parse_struct(t), []
    if obj is None and getattr(cfg, "L6_SPAN_V33", False):
        m = _WRAP.match(t)
        if m:
            obj = _parse_struct(m.group(1))
        if obj is None:
            i = min([k for k in (t.find("{"), t.find("[")) if k >= 0], default=-1)
            j = max(t.rfind("}"), t.rfind("]"))
            if 0 <= i < j and (i > 0 or j < len(t) - 1):
                obj = _parse_struct(t[i:j + 1])
                if obj is not None:
                    extra = [x for x in (t[:i], t[j + 1:]) if re.search(r"[A-Za-z]{2}", x)]
    if obj is None:
        return [t]
    out, stack, seen = [], [obj], 0
    while stack and seen < _MAX_UNITS:
        o = stack.pop()
        seen += 1
        if isinstance(o, dict):
            for k, v in o.items():
                if isinstance(k, str) and k.strip():
                    out.append(k)
                stack.append(v)
        elif isinstance(o, list):
            stack.extend(o)
        elif isinstance(o, str) and o.strip():
            out.append(o)
    return (out[::-1] + extra) or [t]


def _span_end(idx: list, n: int) -> int:
    """v3.1 (config.L6_SPAN_AFTER; results.md §26.4): the span keeps k segments after the last cue (v3: k = 1); -1 = to
    the end of the unit."""
    import sentinel.config as cfg
    k = int(getattr(cfg, "L6_SPAN_AFTER", 1))
    return n if k < 0 else max(idx) + 1 + k


def _ident_in(v: str, text: str) -> bool:
    """Is the folded identifier inside `text`? v3.2 (config.L6_BOUNDED_IDENT; results.md §26.7): as a whole token only
    (lineage's `_bounded_in`), so "informations.com" is not found inside "true-informations.com"."""
    import sentinel.config as cfg
    if not v:
        return False
    return lin._bounded_in(v, text) if getattr(cfg, "L6_BOUNDED_IDENT", False) else v in text


def _tainted(session_id: str, ident: str, res, spans: list) -> bool:
    """v3.1 first-seen taint (config.L6_TAINT_FIRST_SEEN; results.md §26.4): an identifier the user did not type whose
    FIRST appearance in the session's tool outputs lies inside an addressed span stays a finding, even when a later
    trusted record holds it (the transaction history after the agent's own transfer; a write tool echoing its
    arguments) -- taint propagates, as in information-flow-control agents (FIDES, CaMeL)."""
    if any(t == lin.T0 for t, _, _ in res.sources):
        return False                                  # the user typed it
    v, vid = lin.fold(ident), lin.fold_id(ident)
    hit = [sp.seq for sp in spans if _ident_in(v, sp.text)]
    if not hit:
        return False
    first = min((lf.seq for lf in lin.session(session_id).leaves
                 if _ident_in(v, lf.text) or _ident_in(vid, lin.fold_id(lf.text))), default=None)
    return first is not None and min(hit) <= first


def _structured_spans(leaf) -> list:
    """v3: the addressed spans of one leaf, per unit: from the first to the last segment carrying an addressee cue, plus
    ONE segment after (the goal of "Ignore ... . Do X instead."), none before (results.md §26.2: the -1 window only
    ever added ordinary text). Falls back to v2.1's span when no single unit carries the leaf's cue."""
    import sentinel.config as cfg
    from sentinel.core.addressee import addressee_cues
    if sum(addressee_cues(leaf.text)) == 0:
        return []
    v33 = bool(getattr(cfg, "L6_SPAN_V33", False))
    close_tag = bool(getattr(cfg, "L6_SPAN_CLOSE_TAG", False))
    out = []
    for unit in _units(getattr(leaf, "raw", "") or leaf.text):
        if sum(addressee_cues(unit)) == 0:
            continue
        segs = [x for x in _SEG.split(unit) if x.strip()]
        idx = [i for i, x in enumerate(segs) if sum(addressee_cues(x)) > 0]
        if idx and v33:                               # v3.3: nothing before the first framing cue
            from sentinel.core.addressee import first_cue_start
            k0 = first_cue_start(segs[min(idx)])
            if k0:
                segs[min(idx)] = segs[min(idx)][k0:]
        end = _span_end(idx, len(segs)) if idx else 0
        if idx and close_tag:                         # v3.4: an explicit closing tag ends the block, no +1 window
            last = segs[max(idx)]
            tags = list(_CLOSE_TAG.finditer(last))
            if tags:
                segs[max(idx)] = last[:tags[-1].end()]
                end = max(idx) + 1
        out.append(_Span(lin.fold(" ".join(segs[min(idx): end]) if idx else unit),
                         getattr(leaf, "seq", 0)))
    if not out:
        old = _addressed_span(leaf)
        return [old] if old is not None else []
    return out


def _content_ngrams(leaves: list) -> set:
    out = set()
    for leaf in leaves:
        out |= _ngrams(re.findall(r"\w+", leaf.text.lower()), _NGRAM)
    return out


def _windows(regions_per_leaf: list, leaves: list) -> list[str]:
    """v3: marked source windows for one candidate finding -- its longest copied regions over the addressed spans."""
    from sentinel.layers.layer6_answer import relay_judge as rj
    cand = sorted(((b - a, i, a, b) for i, regs in enumerate(regions_per_leaf) for a, b in regs),
                  key=lambda t: (-t[0], t[1], t[2]))
    return [rj.marked_window(leaves[i].text, a, b) for _, i, a, b in cand[:rj.MAX_REGIONS]]


def _confirm(rep: AnswerReport, pending: list) -> None:
    """v3 (config.L6_RELAY_JUDGE; results.md §26.1): keep a candidate iff the local model reads one of its copied source
    regions as written TO the AI. Fail toward flagging: no window or no model -> the v2.1 finding stands (score 1)."""
    import time
    from sentinel.layers.layer6_answer import relay_judge as rj
    t0 = time.perf_counter()
    ps = rj.score_windows([w for _, _, ws in pending for w in ws])
    rep.judge_ms = (time.perf_counter() - t0) * 1000.0
    for typ, payload, ws in pending:
        vals = [ps.get(w) for w in ws]
        score = 1.0 if (not ws or any(v is None for v in vals)) else max(vals)
        rep.scores.append(score)
        if score >= rj.THRESHOLD:
            (rep.unverified if typ == "id" else rep.relayed).append(payload)


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
    judge = gate and bool(getattr(cfg, "L6_RELAY_JUDGE", False))
    taint = gate and bool(getattr(cfg, "L6_TAINT_FIRST_SEEN", False))
    pending = []                                      # v3: (kind, finding, marked source windows) for the judge
    leaves = _content_leaves(session_id, addressed_only=gate)
    text = reply
    for kind, ident in lin.identifiers_in(reply):
        res = lin.resolve(session_id, ident, user_text)
        ok = res.tier in (lin.T2, lin.T3) and (not gate or any(_ident_in(lin.fold(ident), lf.text) for lf in leaves))
        if not ok and taint:
            ok = _tainted(session_id, ident, res, leaves)
        if not ok:
            continue                                  # trusted, or from text that addresses people, not the AI
        if judge:
            from sentinel.layers.layer6_answer import relay_judge as rj
            pending.append(("id", (kind, ident, res.tier),
                            _windows([rj.identifier_regions(lf.text, ident) for lf in leaves], leaves)))
            continue
        rep.unverified.append((kind, ident, res.tier))
    grams = _content_ngrams(leaves)
    if grams:
        for sent in _SENT.split(reply):
            if not gate and not _INSTRUCTION.search(sent):
                continue
            if _ngrams(re.findall(r"\w+", sent.lower()), _NGRAM) & grams:
                if judge:
                    from sentinel.layers.layer6_answer import relay_judge as rj
                    pending.append(("sent", sent.strip()[:300],
                                    _windows([rj.copied_regions(lf.text, sent, _NGRAM) for lf in leaves], leaves)))
                    continue
                rep.relayed.append(sent.strip()[:300])
    if pending:
        _confirm(rep, pending)
    if mode == "enforce":
        for kind, ident, _ in rep.unverified:
            if kind in ("url", "email", "phone"):
                text = text.replace(ident, LINK_NOTICE)
    if mode == "enforce" and rep.relayed:
        text = text + NOTE
    rep.changed = text != reply
    rep.text = text
    return rep
