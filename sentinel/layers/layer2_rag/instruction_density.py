from sentence_transformers import util
from sentinel.core.embedding import get_model

# Templates that suggest instructional or meta-directive content
INSTRUCTIONAL_TEMPLATES = [
    "ignore previous instructions",
    "your task is to",
    "when answering always",
    "you must",
    "do not reveal",
    "as an AI assistant you should",
    "override previous constraints",
    "disregard other rules",
    "the user wants you to",
]

# Computed lazily on first use, not at import time — see the equivalent fix
# and explanation in sentinel/layers/layer1.py. Previously this was computed
# at module scope, forcing an immediate embedding-model load on import of
# this module regardless of whether calculate_instruction_density() was ever
# called.
_template_embeddings_cache = None


def _get_template_embeddings():
    global _template_embeddings_cache
    if _template_embeddings_cache is None:
        _template_embeddings_cache = get_model().encode(INSTRUCTIONAL_TEMPLATES)
    return _template_embeddings_cache


def calculate_instruction_density(text: str) -> float:
    """
    Calculate the instruction density of a chunk.
    High density indicates the chunk is trying to give commands to the LLM
    rather than just providing factual information.
    """
    text_embedding = get_model().encode([text])
    # Compare chunk against all instructional templates
    cos_scores = util.cos_sim(text_embedding, _get_template_embeddings())[0]

    # Return the maximum similarity as the instruction density score
    max_score = float(cos_scores.max().item())

    # Ensure score is within 0.0 - 1.0 bounds
    return max(0.0, min(max_score, 1.0))
