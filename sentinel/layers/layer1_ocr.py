"""
L1 visual prompt-injection scan: text RENDERED in an image (L1 review, new mechanism 5; config.L1_IMAGE_OCR, off).

WHY. Real multimodal prompt injection is mostly readable text inside the picture -- small, low-contrast, at an edge,
in a screenshot or a document photo -- which a vision model reads and a person may overlook. The LSB scanner
(layer1_steg.py) looks for a different and much rarer thing: a hidden bit-plane payload that a vision model cannot
perceive at all. This module reads the visible text with a local OCR engine (RapidOCR: PP-OCR models on ONNX Runtime,
no network after its one-time model fetch) and scores it with the ordinary L1 cascade (`source="image"`, harm head
off).

Fail-soft: OCR unavailable or the image unreadable -> {"available": False, ...}; never "benign".
"""
from __future__ import annotations

import io
import logging

logger = logging.getLogger(__name__)

MAX_PIXELS = 40_000_000           # refuse to OCR absurd images (decompression-bomb guard on top of Pillow's)
_engine = None
_failed = False


def _get_engine():
    global _engine, _failed
    if _failed:
        return None
    if _engine is None:
        try:
            from rapidocr import RapidOCR
            _engine = RapidOCR()
        except Exception as e:                                          # noqa: BLE001
            logger.warning(f"OCR unavailable, image text scan disabled: {e}")
            _failed = True
            return None
    return _engine


def reset() -> None:
    global _engine, _failed
    _engine, _failed = None, False


def ocr_text(image_bytes: bytes) -> str | None:
    """The text lines OCR reads in the image, joined top-to-bottom with newlines; "" if none; None if unavailable."""
    eng = _get_engine()
    if eng is None:
        return None
    try:
        import numpy as np
        from PIL import Image
        img = Image.open(io.BytesIO(image_bytes))
        if img.size[0] * img.size[1] > MAX_PIXELS:
            logger.warning("image too large for OCR (%dx%d)", *img.size)
            return None
        arr = np.asarray(img.convert("RGB"))[:, :, ::-1]           # RGB -> BGR, the engine's convention
        res = eng(arr)
    except Exception as e:                                              # noqa: BLE001
        logger.warning(f"OCR failed: {e}")
        return None
    txts = getattr(res, "txts", None)
    if not txts:
        return ""
    return "\n".join(t for t in txts if t and t.strip())


async def ocr_scan(image_bytes: bytes) -> dict:
    """{"available", "text_chars", "l1": L1Result dict or None, "is_malicious", "suspicious", "score"}.

    The decision is L1's own on the shared axis (`L1Result.decision`): BLOCK -> malicious, WARN -> suspicious."""
    text = ocr_text(image_bytes)
    if text is None:
        return {"available": False, "text_chars": 0, "l1": None, "is_malicious": False, "suspicious": False,
                "score": 0.0}
    if not text.strip():
        return {"available": True, "text_chars": 0, "l1": None, "is_malicious": False, "suspicious": False,
                "score": 0.0}
    from sentinel.config import BLOCK_THRESHOLD, L1_BLOCK_THRESHOLD, WARN_THRESHOLD, l1_warn_threshold
    from sentinel.core.models import rescale_layer_score
    from sentinel.layers.layer1 import layer1_check
    r = await layer1_check(text, harm_head=False, source="image")
    shared = rescale_layer_score(r.score, l1_warn_threshold(), L1_BLOCK_THRESHOLD, WARN_THRESHOLD, BLOCK_THRESHOLD)
    return {"available": True, "text_chars": len(text), "l1": r.to_dict(), "is_malicious": r.decision == "BLOCK",
            "suspicious": r.decision == "WARN", "score": round(float(shared), 4)}


def merge_image_results(steg: dict, ocr: dict | None) -> dict:
    """The image verdict from the LSB scan and (when run) the OCR scan: malicious / suspicious if either is, score
    the max on the shared axis, both results kept (`steg` fields at top level for API compatibility, `ocr` nested)."""
    if ocr is None:
        return steg
    out = dict(steg)
    out["ocr"] = ocr
    out["is_malicious"] = bool(steg.get("is_malicious")) or bool(ocr.get("is_malicious"))
    out["suspicious"] = (not out["is_malicious"]) and (bool(steg.get("suspicious")) or bool(ocr.get("suspicious")))
    out["score"] = max(float(steg.get("score", 0.0)), float(ocr.get("score", 0.0)))
    if ocr.get("is_malicious") or ocr.get("suspicious"):
        l1 = ocr.get("l1") or {}
        out["reason"] = (f"Text rendered in the image ({ocr.get('text_chars', 0)} chars) scores "
                         f"{l1.get('decision', '?')} in L1: {l1.get('reason', '')}"
                         + (f" | {steg.get('reason', '')}" if steg.get("payload_found") else ""))
    return out
