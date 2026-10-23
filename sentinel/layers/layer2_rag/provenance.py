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
