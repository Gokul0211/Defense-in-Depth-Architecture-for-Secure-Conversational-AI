"""
Hidden text in uploaded PDFs (L2 review N1, 2026-10-28; config.L2_PDF_HIDDEN_TEXT, off until measured).

WHY. Document-borne prompt injection hides text from the HUMAN reader while the text layer -- what the LLM reads --
still carries it: white-on-white text, sub-point fonts, text placed off the page, the invisible text render mode
(Tr 3), and optional-content layers switched off by default. `pypdf.extract_text` returns hidden and visible text
alike, so the upload path ingested both indiscriminately. Structure analysis is the most reliable layer in the
published detectors (pdf-injection-scanner; PhantomLint, arXiv 2508.17884; CrackedPDFs, arXiv 2607.19396).

HOW. One pass over each page's content stream through pypdf's visitors: the operand visitor tracks the graphics
state a text-showing operator runs under (fill colour from g / rg / k / sc / scn, render mode from Tr, marked-content
optional groups from BDC / EMC), and the text visitor classifies every shown string:

  invisible_render   render mode 3 (neither fill nor stroke) or 7 (clip only)
  white_fill         fill luminance >= WHITE_LUMINANCE (assumes a light page; a dark banner is a known false positive)
  tiny_font          effective font size (font size x text-matrix scale x CTM scale) < MIN_FONT_PT
  off_page           the text origin is outside the page's MediaBox (with a small margin)
  hidden_layer       inside marked content of an optional-content group that is OFF in the default configuration

LIMITS, stated: colour is compared with white, not with what is actually painted underneath (a white-on-dark-banner
heading reads as hidden); text covered by an opaque shape is not detected; scanned (image) PDFs have no text layer
(OCR is L1's job). This finds hiding, it does not judge content: what hidden text SAYS is scored by L2 as usual.
"""
from __future__ import annotations

import io
import logging

logger = logging.getLogger(__name__)

WHITE_LUMINANCE = 0.95
MIN_FONT_PT = 1.5
OFF_PAGE_MARGIN = 2.0
MIN_HIDDEN_CHARS = 1


def _luminance(op: bytes, args) -> float | None:
    try:
        vals = [float(a) for a in args]
    except (TypeError, ValueError):
        return None
    if op in (b"g",) and len(vals) == 1:
        return vals[0]
    if op in (b"rg",) and len(vals) == 3:
        r, g, b = vals
        return 0.2126 * r + 0.7152 * g + 0.0722 * b
    if op in (b"k",) and len(vals) == 4:
        c, m, y, k = vals
        r, g, b = (1 - c) * (1 - k), (1 - m) * (1 - k), (1 - y) * (1 - k)
        return 0.2126 * r + 0.7152 * g + 0.0722 * b
    if op in (b"sc", b"scn"):
        if len(vals) == 1:
            return vals[0]
        if len(vals) == 3:
            r, g, b = vals
            return 0.2126 * r + 0.7152 * g + 0.0722 * b
    return None


def _scale(m) -> float:
    """Vertical scale of a 6-element matrix [a b c d e f] (the length of its y basis vector)."""
    try:
        return (float(m[2]) ** 2 + float(m[3]) ** 2) ** 0.5
    except (TypeError, ValueError, IndexError):
        return 1.0


def _off_groups(reader) -> set:
    """Indirect references of optional-content groups that are OFF in the default configuration."""
    try:
        oc = reader.trailer["/Root"].get("/OCProperties")
        if not oc:
            return set()
        d = oc.get_object().get("/D")
        off = d.get_object().get("/OFF", []) if d else []
        return {getattr(x, "idnum", None) for x in off}
    except Exception:                                                  # noqa: BLE001
        return set()


def scan_pdf(data: bytes) -> dict:
    """{"pages", "visible_text", "hidden_text", "hidden_chars", "spans": [{"page", "reason", "chars"}...]}.

    Never raises on a malformed PDF: returns {"error": ...} instead (the caller decides)."""
    from pypdf import PdfReader
    try:
        reader = PdfReader(io.BytesIO(data))
    except Exception as e:                                             # noqa: BLE001
        return {"error": f"unreadable PDF: {e}"}
    off = _off_groups(reader)
    visible_parts, hidden_parts, spans = [], [], []

    for pno, page in enumerate(reader.pages, 1):
        try:
            box = page.mediabox
            x0, y0, x1, y1 = float(box.left), float(box.bottom), float(box.right), float(box.top)
        except Exception:                                              # noqa: BLE001
            x0 = y0 = -1e9
            x1 = y1 = 1e9
        props = {}
        try:
            res = page.get("/Resources") or {}
            for name, ref in (res.get_object().get("/Properties") or {}).items():
                props[str(name)] = getattr(ref, "idnum", None)
        except Exception:                                              # noqa: BLE001
            pass
        state = {"fill": 0.0, "render": 0, "oc_stack": [], "stack": []}

        def before(op, args, cm, tm):
            if op in (b"g", b"rg", b"k", b"sc", b"scn"):
                lum = _luminance(op, args)
                if lum is not None:
                    state["fill"] = lum
            elif op == b"Tr" and args:
                try:
                    state["render"] = int(args[0])
                except (TypeError, ValueError):
                    pass
            elif op == b"q":
                state["stack"].append((state["fill"], state["render"]))
            elif op == b"Q" and state["stack"]:
                state["fill"], state["render"] = state["stack"].pop()
            elif op == b"BDC":
                hidden = False
                try:
                    if len(args) >= 2 and str(args[0]) == "/OC":
                        hidden = props.get(str(args[1])) in off if off else False
                except Exception:                                      # noqa: BLE001
                    hidden = False
                state["oc_stack"].append(hidden)
            elif op == b"BMC":
                state["oc_stack"].append(False)
            elif op == b"EMC" and state["oc_stack"]:
                state["oc_stack"].pop()

        def on_text(text, cm, tm, font_dict, font_size):
            if not text or not text.strip():
                visible_parts.append(text or "")
                return
            reasons = []
            if state["render"] in (3, 7):
                reasons.append("invisible_render")
            if state["fill"] >= WHITE_LUMINANCE and state["render"] not in (1, 2, 5, 6):
                reasons.append("white_fill")
            try:
                eff = float(font_size or 0) * _scale(tm) * _scale(cm)
            except (TypeError, ValueError):
                eff = 12.0
            if 0 < eff < MIN_FONT_PT:
                reasons.append("tiny_font")
            try:
                x = float(tm[4]) * float(cm[0]) + float(cm[4])
                y = float(tm[5]) * float(cm[3]) + float(cm[5])
                if (x < x0 - OFF_PAGE_MARGIN or x > x1 + OFF_PAGE_MARGIN
                        or y < y0 - OFF_PAGE_MARGIN or y > y1 + OFF_PAGE_MARGIN):
                    reasons.append("off_page")
            except (TypeError, ValueError, IndexError):
                pass
            if any(state["oc_stack"]):
                reasons.append("hidden_layer")
            if reasons:
                hidden_parts.append(text)
                spans.append({"page": pno, "reason": "+".join(reasons), "chars": len(text.strip())})
            else:
                visible_parts.append(text)

        try:
            page.extract_text(visitor_operand_before=before, visitor_text=on_text)
        except Exception as e:                                         # noqa: BLE001
            logger.warning(f"hidden-text scan failed on page {pno}: {e}")
        visible_parts.append("\n")
        hidden_parts.append("\n")

    hidden = "".join(hidden_parts).strip()
    return {"pages": len(reader.pages), "visible_text": "".join(visible_parts).strip(), "hidden_text": hidden,
            "hidden_chars": len("".join(hidden.split())), "spans": spans}
