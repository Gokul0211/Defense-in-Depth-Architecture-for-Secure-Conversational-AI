"""
Shared embedding model singleton.
Ensures the SentenceTransformer is loaded exactly ONCE per process,
preventing OOM on memory-constrained environments like Render's free tier.
"""

import torch
from sentence_transformers import SentenceTransformer
from sentinel.config import EMBEDDING_MODEL

# Load once, shared across all layers
_model: SentenceTransformer | None = None


def get_model() -> SentenceTransformer:
    global _model
    if _model is None:
        _model = SentenceTransformer(EMBEDDING_MODEL, device="cpu")
        _model.eval()  # inference-only, no gradient tracking needed
        # Reduce inter-op threads to lower memory overhead
        torch.set_num_threads(1)
    return _model
