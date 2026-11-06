"""
SENTINEL Layer 1 — LSB Steganography Detector (Real)

Uses pure Python + Pillow (already installed). No PyTorch, no heavy models.

Algorithm:
  1. Load image → read only the pixels a sequential LSB payload can occupy
  2. Collect LSBs from R, G, B channels in pixel order
  3. Decode them as a null-terminated ASCII string (strict: every byte printable)
  4. Pairs-of-values chi-square (Westfeld & Pfitzmann 1999) on the same pixels:
     LSB replacement equalises the counts of each value pair (2k, 2k+1)
  5. Feed any decoded text through the real L1 text injection classifier

Returns:
  - payload_found: bool
  - decoded_text: str (what was hidden in the image)
  - chi_score: float (pairs-of-values embedding probability, 0..1)
  - l1_score: float (injection score of the decoded text)
  - is_malicious: bool (hidden text that L1 itself would BLOCK)
  - suspicious: bool (hidden text that L1 does not block; WARN)

L1 REVIEW B13 (2026-10-27, scratch/rca/l1/L1_REVIEW.md), config.L1_STEG_STRICT (default on; "false" restores the
previous scanner). The previous version flagged ordinary photographs, by arithmetic rather than by measurement:
  * `chi_square_lsb` tested ones vs zeros, and sensor-noise / decoded-JPEG LSBs ARE close to 50/50, so its
    "suspicion" was ~0.97 on a typical photo;
  * `bits_to_ascii` SKIPPED non-printable bytes, so random bits yield ~90 printable characters before the first
    null byte, and `payload_found` (> 8 characters) was ~95 % true on pure noise;
  * `list(img.getdata())` built a Python tuple for every pixel of the image (~1.5 GB for 20 MP) to read ~1,400.
Strict decoding needs >= 9 printable bytes followed by a null (or a fully printable budget): on random bits that is
~1e-6.

THE STATISTIC IS INFORMATION, NOT A VERDICT. The pairs-of-values test separates an embedded region from a histogram
with pair structure beyond sampling noise, but over the ~33k channel values read here a SMOOTH natural histogram is
dominated by Poisson noise and also scores near 1 (expected chi2 ~ 0.5 per pair on ~128 pairs; analysis, not run).
It therefore cannot raise WARN or BLOCK on its own; only a strictly decoded payload can.
"""

import io
import math

try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False


# Sentinel marker: if the decoded payload starts with this, it's a SENTINEL-injected test image
SENTINEL_PAYLOAD_MARKER = "SENTINEL_STEG:"

# Bits read in strict mode: 4 KiB of payload (32,768 bits = 10,923 pixels), so a payload longer than the
# previous 512-byte window is still decoded in full.
STRICT_MAX_BITS = 8 * 4096
_MIN_PAYLOAD_CHARS = 9
_PRINTABLE_EXTRA = (9, 10, 13)          # \t \n \r


def _pixel_list(img) -> list:
    """Pixels in raster order; `getdata` is deprecated from Pillow 12 (removed in 14)."""
    flat = getattr(img, "get_flattened_data", None)
    return list(flat() if flat is not None else img.getdata())


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
    """LEGACY decoder (L1_STEG_STRICT=false): ASCII text, skipping non-printable bytes, stopping at null."""
    chars = []
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        if byte == 0:
            break  # null terminator — end of payload
        if 32 <= byte < 128:  # printable ASCII only
            chars.append(chr(byte))
    return "".join(chars)


def decode_payload_strict(bits: list[int]) -> str | None:
    """A sequential LSB text payload, or None.

    Accepted only when EVERY byte before the terminator is printable ASCII (or tab / newline / CR), there are at least
    _MIN_PAYLOAD_CHARS of them, and the string is null-terminated or fills the whole bit budget. The first
    non-printable byte rejects the stream: skipping it, as the legacy decoder did, is what turns noise into text."""
    chars = []
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        if byte == 0:
            return "".join(chars) if len(chars) >= _MIN_PAYLOAD_CHARS else None
        if 32 <= byte < 127 or byte in _PRINTABLE_EXTRA:
            chars.append(chr(byte))
        else:
            return None
    return "".join(chars) if len(chars) >= _MIN_PAYLOAD_CHARS else None


def chi_square_lsb(bits: list[int]) -> float:
    """
    LEGACY suspicion score (L1_STEG_STRICT=false): how close the LSBs are to 50/50, 0.0 natural .. 1.0 suspicious.
    Not a steganalysis test — natural-photo LSBs are close to 50/50 too (see the module docstring).
    """
    if len(bits) < 32:
        return 0.0
    ones = sum(bits)
    zeros = len(bits) - ones
    n = len(bits)
    expected = n / 2.0
    chi2 = ((ones - expected) ** 2 + (zeros - expected) ** 2) / expected
    suspicion = max(0.0, 1.0 - min(chi2 / 30.0, 1.0))
    return round(suspicion, 4)


def pov_chi_square(values: list[int]) -> float:
    """
    Pairs-of-values chi-square attack (Westfeld & Pfitzmann, "Attacks on Steganographic Systems", 1999).

    LSB replacement with a random-looking message makes the counts of 2k and 2k+1 converge to their mean. With
    n_{2k} the observed count and e_k = (n_{2k} + n_{2k+1}) / 2, chi2 = sum (n_{2k} - e_k)^2 / e_k over pairs with
    e_k >= 5 (the usual validity condition); the embedding probability is the upper tail P(X >= chi2), X ~ chi2(k - 1).
    Near 1 means the pairs are as equal as embedding makes them; near 0 is the uneven histogram of a natural image.
    0.0 when too few pairs qualify to say anything.
    """
    hist = [0] * 256
    for v in values:
        hist[v & 0xFF] += 1
    stat, pairs = 0.0, 0
    for k in range(128):
        a, b = hist[2 * k], hist[2 * k + 1]
        e = (a + b) / 2.0
        if e >= 5:
            stat += (a - e) ** 2 / e
            pairs += 1
    if pairs < 2:
        return 0.0
    from scipy.stats import chi2 as _chi2
    return float(round(_chi2.sf(stat, pairs - 1), 4))


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
    px = _pixel_list(img)
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


def _leading_pixels(img, n_pixels: int) -> list[tuple]:
    """The first `n_pixels` pixels in raster order, as RGB tuples, without materialising the rest of the image.

    Only the rows that hold them are cropped and converted; the decoder still decodes the image once (compact C
    memory), but no per-pixel Python objects exist beyond the ones read."""
    w, h = img.size
    if w <= 0 or h <= 0:
        return []
    rows = min(h, max(1, math.ceil(n_pixels / w)))
    region = img.crop((0, 0, w, rows)).convert("RGB")
    return _pixel_list(region)[:n_pixels]


def _clean(reason: str) -> dict:
    return {"payload_found": False, "decoded_text": "", "chi_score": 0.0, "l1_score": 0.0,
            "is_malicious": False, "suspicious": False, "score": 0.0, "reason": reason}


async def layer1_steg_scan(image_bytes: bytes) -> dict:
    """
    Main entry point: analyze image bytes for steganographic payload.

    Returns dict with:
      payload_found, decoded_text, chi_score, l1_score, is_malicious, suspicious, score (shared axis), reason
    """
    if not PIL_AVAILABLE:
        return _clean("PIL not available — install Pillow")

    import sentinel.config as cfg
    strict = getattr(cfg, "L1_STEG_STRICT", True)

    try:
        img = Image.open(io.BytesIO(image_bytes))     # lazy; raises DecompressionBombError on absurd sizes
    except Exception as e:                                            # noqa: BLE001
        return _clean(f"Could not open image: {e}")

    max_bits = STRICT_MAX_BITS if strict else 4096
    try:
        if strict:
            pixels = _leading_pixels(img, math.ceil(max_bits / 3))
        else:
            pixels = _pixel_list(img.convert("RGB"))
    except Exception as e:                                            # noqa: BLE001
        return _clean(f"Could not read image pixels: {e}")
    bits = extract_lsbs(pixels, max_bits=max_bits)

    if strict:
        decoded = decode_payload_strict(bits)
        decoded_text = decoded or ""
        payload_found = decoded is not None
        # The statistic is read over the pixels a sequential payload occupies when one was decoded (the embedded
        # region), else over the whole scanned prefix.
        span = math.ceil((len(decoded_text) + 1) * 8 / 3) if payload_found else len(pixels)
        chi_score = pov_chi_square([c for p in pixels[:span] for c in p[:3]])
    else:
        chi_score = chi_square_lsb(bits)
        decoded_text = bits_to_ascii(bits)
        payload_found = len(decoded_text) > 8

    l1_score = 0.0
    if payload_found:
        from sentinel.layers.layer1 import layer1_check
        l1_result = await layer1_check(decoded_text)
        l1_score = l1_result.score

    if strict:
        from sentinel.config import BLOCK_THRESHOLD, L1_BLOCK_THRESHOLD, WARN_THRESHOLD, l1_warn_threshold
        from sentinel.core.models import rescale_layer_score
        l1_shared = rescale_layer_score(l1_score, l1_warn_threshold(), L1_BLOCK_THRESHOLD,
                                        WARN_THRESHOLD, BLOCK_THRESHOLD) if payload_found else 0.0
        is_malicious = payload_found and l1_shared >= BLOCK_THRESHOLD
        suspicious = payload_found and not is_malicious
        # Score on the shared WARN / BLOCK axis, from the evidence that decided the action: L1's own score for a
        # payload L1 blocks; the WARN anchor for hidden text L1 does not block (a declared policy level: readable
        # text in the LSB plane is not accidental, ~1e-6 on noise); 0 without a payload (the statistic is not evidence).
        if is_malicious:
            score = l1_shared
        elif suspicious:
            score = max(l1_shared, WARN_THRESHOLD)
        else:
            score = 0.0
    else:
        is_malicious = (chi_score > 0.6 and payload_found) or l1_score > 0.7
        suspicious = is_malicious
        score = max(chi_score, l1_score)

    snippet = decoded_text[:80].encode("unicode_escape").decode("ascii")
    if is_malicious:
        reason = (f"LSB payload extracted ({len(decoded_text)} chars). Injection score: {l1_score:.2f}. "
                  f"Chi-sq embedding probability: {chi_score:.2f}. Decoded: '{snippet}'")
    elif payload_found:
        reason = (f"Hidden text in the image's LSBs ({len(decoded_text)} chars); L1 does not block it "
                  f"(injection score {l1_score:.2f}). Decoded: '{snippet}'")
    elif not strict and chi_score > 0.5:
        reason = f"Suspicious LSB distribution (chi={chi_score:.2f}) but no readable payload found"
    else:
        reason = f"No hidden payload decoded (pairs-of-values statistic {chi_score:.2f}, informational)" if strict             else f"Image appears clean. Chi-sq={chi_score:.2f}, no payload decoded"

    return {
        "payload_found": payload_found,
        "decoded_text": decoded_text[:200],
        "chi_score": chi_score,
        "l1_score": l1_score,
        "is_malicious": is_malicious,
        "suspicious": suspicious,
        "score": round(float(score), 4),
        "reason": reason,
    }
