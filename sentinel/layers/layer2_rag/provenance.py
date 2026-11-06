import hmac
import hashlib
import os
import secrets

# The signing key. It used to be the literal b"sentinel_l2_secret_key" -- public in the source, so anyone could forge a
# "valid" chunk signature (scratch/rca/v5, Phase 7). Now DIDA_PROVENANCE_KEY, or a random key per process: chunks live
# in memory only (chunk_store keeps no persistent copy), so a per-process key loses nothing.
PROVENANCE_SECRET = (os.getenv("DIDA_PROVENANCE_KEY") or secrets.token_hex(32)).encode()

def sign_chunk(chunk_id: str, text: str) -> str:
    """Sign a chunk's ID and text to ensure it hasn't been tampered with post-ingestion."""
    payload = f"{chunk_id}:{text}".encode('utf-8')
    signature = hmac.new(PROVENANCE_SECRET, payload, hashlib.sha256).hexdigest()
    return signature

def verify_chunk(chunk_id: str, text: str, signature: str) -> bool:
    """Verify that a chunk's signature matches its ID and text."""
    expected_signature = sign_chunk(chunk_id, text)
    return hmac.compare_digest(expected_signature, signature)


def _record_payload(chunk_id: str, text: str, metadata: dict, embedding) -> bytes:
    """Canonical bytes of what a stored chunk's verdict depends on (L2 review C11)."""
    import json
    import numpy as _np
    dt = metadata.get("document_threat") or {}
    emb = _np.asarray(embedding, dtype="float32").tobytes() if embedding is not None else b""
    fields = {
        "chunk_id": chunk_id,
        "text_sha256": hashlib.sha256((text or "").encode("utf-8", "surrogatepass")).hexdigest(),
        "source": str(metadata.get("source", "")),
        "ingested_by": str(metadata.get("ingested_by", "")),
        "trust_score": repr(float(metadata.get("trust_score", 0.0))),
        "threat": repr(float(dt.get("threat", 0.0))) if dt else "",
        "scorer_version": str(metadata.get("scorer_version", "")),
        "embedding_sha256": hashlib.sha256(emb).hexdigest(),
    }
    return json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()


def sign_record(chunk_id: str, text: str, metadata: dict, embedding) -> str:
    """HMAC over the text AND the verdict-bearing metadata and embedding (L2 review C11). `sign_chunk` covers the text
    only, so an edited trust score could promote a held chunk and an edited embedding could make one chunk retrieved
    for every query without breaking the check."""
    return hmac.new(PROVENANCE_SECRET, _record_payload(chunk_id, text, metadata, embedding), hashlib.sha256).hexdigest()


def verify_record(chunk_id: str, text: str, metadata: dict, embedding, signature: str) -> bool:
    return hmac.compare_digest(sign_record(chunk_id, text, metadata, embedding), signature or "")
