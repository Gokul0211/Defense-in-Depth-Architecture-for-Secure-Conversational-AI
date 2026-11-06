"""
Translate-to-English view for the local document detector (L2 v7 round, scratch/rca/l2/L2_REDESIGN.md).

WHY. The document probe reads injections in German / French / Spanish at 0.94-0.99 but Chinese / Italian / Russian /
Dutch at 0.90-0.92 (TEST t9), and its English recall is higher still. Translate-then-detect beat direct cross-lingual
classifiers in 13 / 16 languages for toxicity (Bell et al., WMT 2025). An injection usually sits INSIDE an otherwise
English document, so the unit is the SEGMENT, not the document: every line (long lines: every sentence) that is clearly
not English is replaced by its machine translation (Helsinki-NLP/opus-mt-mul-en, local copy), the rest is kept, and
the result is one more reading of the document (it fires if any reading fires, like the unhide view).

Foreign segment (deterministic, no language-ID model): mostly letters (code / tables are never translated) and either
mostly non-Latin letters, or Latin letters with almost no English function words. Loaded from the local cache only;
absent -> no view (the other readings still run).
"""
from __future__ import annotations

import logging
import re
import threading
import unicodedata
from pathlib import Path

logger = logging.getLogger(__name__)

MODEL_DIR = Path.home() / ".cache" / "sentinel" / "mt" / "opus-mt-mul-en"
MIN_LATIN_WORDS = 4          # shorter Latin segments are never judged (names, headers, "Danke!")
MIN_OTHER_CHARS = 6          # non-Latin letters needed to judge a segment by script
MIN_LETTER_SHARE = 0.7       # letters / non-space characters: below this the segment is code, a table or numbers
MAX_SEGMENTS = 40            # per document; the rest is left as it is
ENGLISH_FUNCTION_MAX = 0.15  # Latin segment is foreign below this English-function-word share (fixed on DEV, l2p47_lid_dev.py)

_EN = set("""a about above after again against all also am an and any are as at be because been before being below
between both but by can could did do does doing down during each few for from further had has have having he her here
hers him his how i if in into is it its just me more most my no nor not now of off on once only or other our out over
own please same she should so some such than that the their them then there these they this those through to too under
until up very was we were what when where which while who whom why will with would you your yours""".split())
_WORD = re.compile(r"[^\W\d_]+", re.UNICODE)
_SENT = re.compile(r"(?<=[.!?。！？])\s+")


def _latin_share(letters: str) -> float:
    if not letters:
        return 1.0
    lat = sum(1 for ch in letters if "LATIN" in unicodedata.name(ch, ""))
    return lat / len(letters)


_SYMBOLS = set("=(){}[];<>$_\\/#*`|^~")
MAX_SYMBOL_SHARE = 0.05      # code / JSON lines are denser in these (DEV: an '=' inside an attack must not exclude it)
MAX_CAPITALISED = 0.75       # headings and name lists are ~0.9-1.0; German prose (nouns capitalised) ~0.3-0.6


def is_foreign(seg: str, en_max: float = ENGLISH_FUNCTION_MAX) -> bool:
    """Natural-language prose that is not English. Structure is never translated (DEV RCA, l2p47_lid_dev.py: table
    rows, code, JSON keys and name lists made 37-86 % of English DEV documents look foreign): cell pipes or
    tab-separated cells, symbol density, too few letters, mostly Capitalised words. Non-Latin script: foreign by script.
    Latin script: foreign when English function words are rare."""
    s = seg.strip()
    if not s or s.count("|") > 1 or s.count("\t") > 1:
        return False
    nonspace = [c for c in s if not c.isspace()]
    letters = "".join(c for c in nonspace if c.isalpha())
    if not letters or sum(c in _SYMBOLS for c in nonspace) / len(nonspace) > MAX_SYMBOL_SHARE:
        return False
    if _latin_share(letters) < 0.5:                                  # CJK, Cyrillic, Arabic, ... (digits allowed)
        return len(letters) >= MIN_OTHER_CHARS and len(letters) / len(nonspace) >= 0.5
    if len(letters) / len(nonspace) < MIN_LETTER_SHARE:
        return False
    raw = _WORD.findall(s)
    if len(raw) < MIN_LATIN_WORDS or sum(w[:1].isupper() for w in raw) / len(raw) > MAX_CAPITALISED:
        return False
    return sum(w.lower() in _EN for w in raw) / len(raw) < en_max


def segments(body: str) -> list[str]:
    """Lines, and the sentences of long lines -- the units that are judged and translated."""
    out = []
    for line in body.split("\n"):
        if len(line) > 400:
            out.extend(p for p in _SENT.split(line))
        else:
            out.append(line)
    return out


_lock = threading.Lock()
_mt = None
_failed = False


def _load():
    global _mt, _failed
    if _mt is not None or _failed:
        return _mt
    try:
        import torch
        from transformers import MarianMTModel, MarianTokenizer
        if not MODEL_DIR.exists():
            raise FileNotFoundError(str(MODEL_DIR))
        dev = "cuda:0" if torch.cuda.is_available() else "cpu"
        tok = MarianTokenizer.from_pretrained(str(MODEL_DIR))
        m = MarianMTModel.from_pretrained(str(MODEL_DIR))
        m = (m.half() if dev != "cpu" else m).to(dev).eval()
        _mt = (tok, m, dev)
    except Exception as e:                                          # noqa: BLE001 -- fail soft
        logger.warning(f"translation model unavailable ({e}); no translated view")
        _failed = True
    return _mt


def translate(texts: list[str]) -> list[str] | None:
    mt = _load()
    if mt is None or not texts:
        return None if mt is None else []
    import torch
    tok, m, dev = mt
    out = []
    with _lock:
        for i in range(0, len(texts), 16):
            b = tok(texts[i:i + 16], return_tensors="pt", padding=True, truncation=True, max_length=400).to(dev)
            with torch.no_grad():
                g = m.generate(**b, num_beams=4, max_new_tokens=400)
            out += tok.batch_decode(g, skip_special_tokens=True)
    return out


def translated_view(body: str, en_max: float = ENGLISH_FUNCTION_MAX, translator=None) -> str | None:
    """The document with its foreign segments replaced by English translations; None when nothing is foreign or the
    translation model is unavailable. `translator` (list[str] -> list[str]) is for tests and offline pipelines."""
    segs = segments(body)
    idx = [i for i, s in enumerate(segs) if is_foreign(s, en_max)][:MAX_SEGMENTS]
    if not idx:
        return None
    tr = (translator or translate)([segs[i].strip() for i in idx])
    if not tr:
        return None
    for i, t in zip(idx, tr):
        segs[i] = t
    out, k = [], 0
    for line in body.split("\n"):                    # re-join: long lines were split into sentences
        if len(line) > 400:
            n = len(_SENT.split(line))
            out.append(" ".join(segs[k:k + n])); k += n
        else:
            out.append(segs[k]); k += 1
    view = "\n".join(out)
    return view if view != body else None
