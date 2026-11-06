"""
Encoded views of a text, for L1's obfuscation pass (L1 review B4 / B5, 2026-10-27).

L1 decoded base64 / hex / ROT13 only and checked the plaintext with the Tier-1 regex alone. This module finds every
encoded span of the encodings that commonly carry hidden instructions, decodes it, and returns the distinct
plaintexts ("views"), nested to `max_depth` (base64 of base64, URL-encoding of an entity, ...).

Kinds:
  Base64 / Base64URL   spans of 8+ alphabet characters that decode to printable ASCII (the shipped rule)
  Hex                  spans of 8+ hex digits that decode to printable ASCII (the shipped rule)
  URL                  percent-encoding, when the text carries >= 3 escapes
  HTML                 character references (&#105; &#x69; &lt;), when the text carries >= 3
  UnicodeEscape        \\uXXXX / \\xXX / \\U00XXXXXX escapes, when the text carries >= 3
  Reversed             the whole text reversed, only when the reversed form reads as English and the original
                       does not (function-word count; a declared rule, no fitted constant)

B5. There is no count cap: `_decoded_candidates` used to stop after 32 SUCCESSFUL decodes, so 32 harmless leading
blobs hid the real one (the first-span bug of v3 again, at 32). Decoding is linear in the input (base64 yields at
most 3/4 of its span, hex 1/2), so every span is decoded; duplicates are dropped, and longer plaintexts come first.
`_HARD_CHAR_LIMIT` bounds only pathological inputs.

Pure functions; no model, no network. Never used to generate encodings.
"""
from __future__ import annotations

import base64
import codecs
import html
import re
import urllib.parse

# The shipped span rules (layer1.try_decode_base64 / try_decode_hex), word-bounded as before.
_B64 = re.compile(r"\b[A-Za-z0-9+/]{8,}={0,2}\b")
_B64URL = re.compile(r"\b[A-Za-z0-9_-]{8,}={0,2}\b")
_HEX = re.compile(r"\b[0-9a-fA-F]{8,}\b")
_PCT = re.compile(r"%[0-9a-fA-F]{2}")
_ENTITY = re.compile(r"&(?:#\d{2,7}|#[xX][0-9a-fA-F]{2,6}|[A-Za-z]{2,8});")
_UESC = re.compile(r"\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}|\\U[0-9a-fA-F]{8}")
_WORD = re.compile(r"[a-z]+")
_FUNCTION_WORDS = frozenset(
    "the and to of a in is you your that it for on with as this be are or all from not now".split())
_HARD_CHAR_LIMIT = 1_000_000
_MIN_ESCAPES = 3


def _printable_ascii(s: str) -> bool:
    return len(s) > 4 and all(32 <= ord(c) < 127 or c in "\r\n\t" for c in s)


def _b64(span: str, altchars: bytes | None) -> str | None:
    core = span.rstrip("=")
    try:
        raw = base64.b64decode(core + "=" * (-len(core) % 4), altchars=altchars, validate=True)
        s = raw.decode("utf-8", errors="strict")
    except Exception:                                                  # noqa: BLE001
        return None
    return s if _printable_ascii(s) else None


def _hex(span: str) -> str | None:
    try:
        s = bytes.fromhex(span).decode("utf-8", errors="strict")
    except Exception:                                                  # noqa: BLE001
        return None
    return s if _printable_ascii(s) else None


def _function_words(s: str) -> int:
    return sum(w in _FUNCTION_WORDS for w in _WORD.findall(s.lower()))


def _single_level(text: str, legacy_kinds_only: bool = False) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for m in _B64.finditer(text):
        s = _b64(m.group(0), None)
        if s:
            out.append(("Base64", s))
    if not legacy_kinds_only:
        for m in _B64URL.finditer(text):
            span = m.group(0)
            if "-" in span or "_" in span:                          # pure-alphabet spans were tried as Base64
                s = _b64(span, b"-_")
                if s:
                    out.append(("Base64URL", s))
    for m in _HEX.finditer(text):
        s = _hex(m.group(0))
        if s:
            out.append(("Hex", s))
    if legacy_kinds_only:
        return out
    if len(_PCT.findall(text)) >= _MIN_ESCAPES:
        s = urllib.parse.unquote(text)
        if s != text:
            out.append(("URL", s))
    if len(_ENTITY.findall(text)) >= _MIN_ESCAPES:
        s = html.unescape(text)
        if s != text:
            out.append(("HTML", s))
    if len(_UESC.findall(text)) >= _MIN_ESCAPES:
        try:
            s = _UESC.sub(lambda m: codecs.decode(m.group(0), "unicode_escape"), text)
        except Exception:                                              # noqa: BLE001
            s = text
        if s != text:
            out.append(("UnicodeEscape", s))
    rev = text[::-1]
    fw_rev, fw_fwd = _function_words(rev), _function_words(text)
    if fw_rev >= 2 and fw_rev > fw_fwd:
        out.append(("Reversed", rev))
    return out


def decode_views(text: str, max_depth: int = 2, legacy_kinds_only: bool = False) -> list[tuple[str, str]]:
    """Distinct (kind, plaintext) views of every encoded span in `text`, nested up to `max_depth` levels.

    Nested kinds read "Base64>URL". `legacy_kinds_only` restricts the kinds to the shipped base64 / hex pair (the
    B5 fix without the B4 decoders)."""
    text = (text or "")[:_HARD_CHAR_LIMIT]
    seen = {text}
    views: list[tuple[str, str]] = []
    frontier = [("", text)]
    for _ in range(max(1, max_depth)):
        nxt = []
        for prefix, src in frontier:
            for kind, s in _single_level(src, legacy_kinds_only):
                if s in seen:
                    continue
                seen.add(s)
                k = f"{prefix}>{kind}" if prefix else kind
                views.append((k, s))
                if not kind == "Reversed":                         # reversing twice is the original
                    nxt.append((k, s))
        frontier = nxt
        if not frontier:
            break
    views.sort(key=lambda kv: -len(kv[1]))
    return views
