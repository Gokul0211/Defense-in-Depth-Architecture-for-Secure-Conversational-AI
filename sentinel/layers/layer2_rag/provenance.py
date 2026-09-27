import hmac
import hashlib

# Uses a secret key for provenance. In production, this would be a secure, rotated key.
PROVENANCE_SECRET = b"sentinel_l2_secret_key"

def sign_chunk(chunk_id: str, text: str) -> str:
    """Sign a chunk's ID and text to ensure it hasn't been tampered with post-ingestion."""
    payload = f"{chunk_id}:{text}".encode('utf-8')
    signature = hmac.new(PROVENANCE_SECRET, payload, hashlib.sha256).hexdigest()
    return signature

def verify_chunk(chunk_id: str, text: str, signature: str) -> bool:
    """Verify that a chunk's signature matches its ID and text."""
    expected_signature = sign_chunk(chunk_id, text)
    return hmac.compare_digest(expected_signature, signature)
