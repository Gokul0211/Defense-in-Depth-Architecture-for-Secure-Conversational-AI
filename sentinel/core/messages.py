"""
OpenAI-style chat message content, read safely (L1 review B7, 2026-10-27).

A message's `content` is a string OR a list of parts ({"type": "text", "text": ...}, {"type": "image_url",
"image_url": {"url": ...}}, ...), the standard multimodal format. The proxy assumed a string everywhere, so a list
reached `layer1_check` and raised TypeError inside the regex pass (HTTP 500), and the canary insertion
(`m["content"] += ...`) raised on a list-valued system message. These helpers are the one place content is read.
"""
from __future__ import annotations

import hashlib

_TEXT_PART_TYPES = ("text", "input_text")


def message_text(content) -> str:
    """All text a message carries: the string itself, or its text parts joined by newlines. Non-text parts are
    ignored here (see `image_parts`); anything else is ""."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        out = []
        for part in content:
            if isinstance(part, str):
                out.append(part)
            elif isinstance(part, dict) and part.get("type") in _TEXT_PART_TYPES and isinstance(part.get("text"), str):
                out.append(part["text"])
        return "\n".join(out)
    return ""


def image_parts(content) -> list[str]:
    """The image URLs of a multimodal message (data: URLs and remote URLs alike; callers decide what to fetch)."""
    if not isinstance(content, list):
        return []
    urls = []
    for part in content:
        if isinstance(part, dict) and part.get("type") in ("image_url", "input_image"):
            iu = part.get("image_url")
            url = iu.get("url") if isinstance(iu, dict) else iu
            if isinstance(url, str) and url:
                urls.append(url)
    return urls


def append_text(message: dict, text: str) -> None:
    """Append text to a message whatever its content shape (string, parts list, or missing)."""
    c = message.get("content")
    if isinstance(c, list):
        c.append({"type": "text", "text": text})
    elif isinstance(c, str) and c:
        message["content"] = c + text
    else:
        message["content"] = text.lstrip("\n")


def text_digest(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8", "surrogatepass")).hexdigest()
