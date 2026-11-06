"""
Shared embedding model singleton.
Ensures the SentenceTransformer is loaded exactly ONCE per process,
preventing OOM on memory-constrained environments like Render's free tier.

The model revision is pinned for reproducibility (see config.py).
"""

import torch
from sentence_transformers import SentenceTransformer
from sentinel.config import EMBEDDING_MODEL, EMBEDDING_MODEL_REVISION

# Load once, shared across all layers
_model: SentenceTransformer | None = None


def get_model() -> SentenceTransformer:
    global _model
    if _model is None:
        # Use GPU if available (RTX 3050 / CUDA), fallback to CPU
        from sentinel.core.guard_device import classifier_cuda_ok
        device = "cuda" if classifier_cuda_ok("minilm") else "cpu"
        _model = SentenceTransformer(
            EMBEDDING_MODEL,
            revision=EMBEDDING_MODEL_REVISION,
            device=device,
        )
        _model.eval()  # inference-only, no gradient tracking needed
        if device == "cpu":
            # NOTE (2026-09-23, scratch/rca/LEDGER.md R-012): set_num_threads sets the
            # INTRA-op pool for the whole process, not "inter-op threads" as this comment
            # used to say -- so loading the embedding model silently pinned Prompt Guard,
            # PIGuard and every other torch model in the process to ONE core. Kept as the
            # default (it was chosen for a 512 MB free-tier host, and multi-threaded float
            # reductions are not bitwise-identical to the recorded artifacts), but now
            # overridable: SENTINEL_TORCH_THREADS=0 leaves torch's own default.
            import os
            # 2026-11-04: the default was briefly 0 (torch's own 12-thread pool) for the CPU harm head's latency; the full
            # test suite then crashed twice at the same model load (access violation, ~45 %) and passed at 1
            # (results.md §21.5) -> back to 1. The harm head gets its own multi-threaded worker instead
            # (core/model_executor.py, SENTINEL_GUARD_THREADS). SENTINEL_TORCH_THREADS=0 still leaves torch's default.
            n = int(os.getenv("SENTINEL_TORCH_THREADS", "1"))
            if n > 0:
                torch.set_num_threads(n)
    return _model
