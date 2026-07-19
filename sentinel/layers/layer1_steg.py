"""
SENTINEL Layer 1 — LSB Steganography Detector (Real)

Uses pure Python + Pillow (already installed). No PyTorch, no heavy models.

Algorithm:
  1. Load image → extract all pixel values
  2. Collect LSBs from R, G, B channels across all pixels
  3. Decode the first N bits as ASCII to extract any hidden payload
  4. Run chi-square randomness test on LSB distribution
     (natural images have non-random LSBs; injected payloads produce flat/random distribution)
  5. Feed decoded text through the real L1 text injection classifier

Returns:
  - payload_found: bool
  - decoded_text: str (what was hidden in the image)
  - chi_score: float (higher = more suspicious LSB distribution)
  - l1_score: float (injection score of the decoded text)
  - is_malicious: bool
"""

import io
import math
import struct
from typing import Optional

try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False


# Sentinel marker: if the decoded payload starts with this, it's a SENTINEL-injected test image
SENTINEL_PAYLOAD_MARKER = "SENTINEL_STEG:"


def extract_lsbs(pixels: list[tuple], max_bits: int = 2048) -> list[int]:
    """Extract LSBs from R, G, B channels of each pixel."""
    bits = []
    for pixel in pixels:
        if len(bits) >= max_bits:
            break
        r, g, b = pixel[0], pixel[1], pixel[2]
        bits.append(r & 1)
        bits.append(g & 1)
        bits.append(b & 1)
    return bits[:max_bits]


def bits_to_ascii(bits: list[int]) -> str:
    """Convert bit list to ASCII text. Stop at null byte."""
    chars = []
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        if byte == 0:
            break  # null terminator — end of payload
        if 32 <= byte < 128:  # printable ASCII only
            chars.append(chr(byte))
        # Non-printable bytes: skip rather than break, so we don't truncate valid payloads
        # that have isolated non-printable chars mid-stream (e.g., line-endings embedded)
    return "".join(chars)


def chi_square_lsb(bits: list[int]) -> float:
    """
    Chi-square test on LSB distribution.
    Natural images: LSBs are NOT uniformly random (texture/gradient patterns).
    Steganographic images: LSBs approach 50/50 due to payload injection.
    Returns a score from 0.0 (natural) to 1.0 (suspicious / injected).
    """
    if len(bits) < 32:
        return 0.0
    ones = sum(bits)
    zeros = len(bits) - ones
    n = len(bits)
    expected = n / 2.0
    # chi-square value
    chi2 = ((ones - expected) ** 2 + (zeros - expected) ** 2) / expected
    # Normalize: chi2 < 1 → suspicious (too uniform), chi2 > 50 → natural
    # We invert: high suspicion = chi2 near 0
    suspicion = max(0.0, 1.0 - min(chi2 / 30.0, 1.0))
    return round(suspicion, 4)


def encode_payload_into_image(
    payload: str,
    width: int = 64,
    height: int = 64,
) -> bytes:
    """
    Create a small PNG image with a text payload hidden in LSBs.
    Used by the demo scenario to generate a real steg image on-the-fly.
    """
    if not PIL_AVAILABLE:
        return b""

    import random

    # Start with a gradient image (natural-looking)
    img = Image.new("RGB", (width, height))
    pixels = []
    for y in range(height):
        for x in range(width):
            r = (x * 255) // width
            g = (y * 255) // height
            b = ((x + y) * 255) // (width + height)
            pixels.append((r, g, b))
    img.putdata(pixels)

    # Encode payload as bits (null-terminated)
    payload_bytes = (payload + "\x00").encode("ascii", errors="ignore")
    payload_bits = []
    for byte in payload_bytes:
        for i in range(7, -1, -1):
            payload_bits.append((byte >> i) & 1)

    # Embed bits into LSBs
    px = list(img.getdata())
    bit_idx = 0
    new_px = []
    for pixel in px:
        r, g, b = pixel
        if bit_idx < len(payload_bits):
            r = (r & 0xFE) | payload_bits[bit_idx]; bit_idx += 1
        if bit_idx < len(payload_bits):
            g = (g & 0xFE) | payload_bits[bit_idx]; bit_idx += 1
        if bit_idx < len(payload_bits):
            b = (b & 0xFE) | payload_bits[bit_idx]; bit_idx += 1
        new_px.append((r, g, b))
    img.putdata(new_px)

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


async def layer1_steg_scan(image_bytes: bytes) -> dict:
    """
    Main entry point: analyze image bytes for steganographic payload.

    Returns dict with:
      payload_found, decoded_text, chi_score, l1_score, is_malicious, reason
    """
    if not PIL_AVAILABLE:
        return {
            "payload_found": False,
            "decoded_text": "",
            "chi_score": 0.0,
            "l1_score": 0.0,
            "is_malicious": False,
            "reason": "PIL not available — install Pillow"
        }

    try:
        img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    except Exception as e:
        return {
            "payload_found": False,
            "decoded_text": "",
            "chi_score": 0.0,
            "l1_score": 0.0,
            "is_malicious": False,
            "reason": f"Could not open image: {e}"
        }

    pixels = list(img.getdata())
    bits = extract_lsbs(pixels, max_bits=4096)

    # Step 1: chi-square suspicion score
    chi_score = chi_square_lsb(bits)

    # Step 2: try to decode text payload from LSBs
    decoded_text = bits_to_ascii(bits)
    payload_found = len(decoded_text) > 8  # at least 9 printable chars = likely real payload

    # Step 3: run L1 injection classifier on decoded text
    l1_score = 0.0
    l1_reason = "No payload decoded"

    if payload_found:
        from sentinel.layers.layer1 import layer1_check
        l1_result = await layer1_check(decoded_text)
        l1_score = l1_result.score
        l1_reason = l1_result.reason

    # Final verdict
    # Malicious if: chi_score high (LSBs look injected) AND (payload found OR l1_score high)
    is_malicious = (chi_score > 0.6 and payload_found) or l1_score > 0.7

    if is_malicious:
        reason = f"LSB payload extracted ({len(decoded_text)} chars). Injection score: {l1_score:.2f}. Chi-sq suspicion: {chi_score:.2f}. Decoded: '{decoded_text[:80]}'"
    elif chi_score > 0.5:
        reason = f"Suspicious LSB distribution (chi={chi_score:.2f}) but no readable payload found"
    else:
        reason = f"Image appears clean. Chi-sq={chi_score:.2f}, no payload decoded"

    return {
        "payload_found": payload_found,
        "decoded_text": decoded_text[:200],
        "chi_score": chi_score,
        "l1_score": l1_score,
        "is_malicious": is_malicious,
        "reason": reason,
    }
