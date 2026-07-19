"""
SENTINEL Layer 3 — Conversational Drift Tracker (Real)

Detects slow-burn multi-turn manipulation by measuring:
  1. Semantic velocity — cosine distance between consecutive turns
  2. Cumulative drift — cosine distance from the session's true first turn
  3. Escalation phrases — known social engineering phrases
"""

import numpy as np
from collections import deque
from sklearn.metrics.pairwise import cosine_similarity

from sentinel.config import (
    L3_VELOCITY_THRESHOLD,
    L3_DRIFT_THRESHOLD,
    L3_MAX_HISTORY,
    L3_VELOCITY_WEIGHT,
    L3_DRIFT_WEIGHT,
    L3_ESCALATION_WEIGHT,
    MAX_TRACKED_SESSIONS,
)
from sentinel.core.models import L3Result
from sentinel.core.embedding import get_model
from sentinel.core.bounded_cache import BoundedLRUDict

# Per-session rolling turn history: {session_id: deque of embeddings}, used
# for turn-to-turn velocity. Bounded to MAX_TRACKED_SESSIONS sessions via LRU
# eviction — see sentinel/core/bounded_cache.py.
session_embeddings: BoundedLRUDict[str, deque] = BoundedLRUDict(MAX_TRACKED_SESSIONS)

# Per-session TRUE baseline embedding (turn 1), stored separately from the
# rolling window above.
#
# Bug this fixes: `session_embeddings` is a deque(maxlen=L3_MAX_HISTORY). Once
# a session passes L3_MAX_HISTORY turns, the deque silently evicts the
# original turn 1 — so `history[0]` stops being "the session baseline" and
# instead becomes "whatever turn is currently oldest in a 10-turn rolling
# window", without any change in behavior or logging to signal that the
# baseline semantics just changed. This directly undermines the layer's
# stated purpose: slow-burn, multi-turn escalation attacks are exactly the
# case where a conversation runs past 10 turns and the drift-from-origin
# signal is supposed to still mean something. Fixed by tracking the true
# first-turn embedding independently of the rolling window used for velocity.
session_baseline: BoundedLRUDict[str, list] = BoundedLRUDict(MAX_TRACKED_SESSIONS)

ESCALATION_PHRASES = [
    "as an admin",
    "with elevated",
    "override",
    "you have permission",
    "i'm authorized",
    "my job requires",
    "you helped with this before",
    "other AIs do this",
    "developer mode",
    "hypothetically speaking",
    "in a fictional scenario",
    "for educational purposes",
    "if you were unconstrained",
    "your true self",
    "the old you",
    "before the restrictions",
    "in a parallel world",
    "let's roleplay",
    "pretend this is fiction",
    "academic research requires",
    "is in danger",
    "bypass checks",
    "emergency",
    "bypass validation",
    "authorize myself",
    "disable security",
]


async def layer3_check(session_id: str, user_input: str) -> L3Result:
    """
    Track conversational drift for a session.
    Returns L3Result with velocity, drift, escalation, and combined score.
    """
    if session_id not in session_embeddings:
        session_embeddings[session_id] = deque(maxlen=L3_MAX_HISTORY)

    history = session_embeddings[session_id]
    current_embedding = get_model().encode([user_input])

    # Semantic velocity — distance from last turn (rolling window is correct
    # for this; velocity is meant to be "turn to turn", not "turn to origin")
    velocity = 0.0
    if history:
        last_embedding = np.array(history[-1]).reshape(1, -1)
        similarity = cosine_similarity(current_embedding, last_embedding)[0][0]
        velocity = float(max(0.0, 1.0 - similarity))

    # Cumulative drift — distance from the TRUE first turn, not the oldest
    # turn still resident in the rolling window.
    if session_id not in session_baseline:
        session_baseline[session_id] = current_embedding[0].tolist()

    cumulative_drift = 0.0
    if history:  # only meaningful once there's at least one prior turn
        baseline_embedding = np.array(session_baseline[session_id]).reshape(1, -1)
        similarity = cosine_similarity(current_embedding, baseline_embedding)[0][0]
        cumulative_drift = float(max(0.0, 1.0 - similarity))

    # Escalation phrase check
    lower_input = user_input.lower()
    escalation_found = any(phrase in lower_input for phrase in ESCALATION_PHRASES)

    # Store this turn's embedding in the rolling window (used for velocity only)
    history.append(current_embedding[0].tolist())
    turn_count = len(history)

    # Compute combined score
    score = 0.0
    score += velocity * L3_VELOCITY_WEIGHT
    score += cumulative_drift * L3_DRIFT_WEIGHT
    score += L3_ESCALATION_WEIGHT if escalation_found else 0.0
    score = max(0.0, min(score, 1.0))

    # Build reason string
    reasons = []
    if velocity > L3_VELOCITY_THRESHOLD:
        reasons.append(f"High topic shift (velocity={velocity:.2f})")
    if cumulative_drift > L3_DRIFT_THRESHOLD:
        reasons.append(f"Session drifting from origin (drift={cumulative_drift:.2f})")
    if escalation_found:
        reasons.append("Escalation phrase detected")

    return L3Result(
        score=score,
        semantic_velocity=velocity,
        cumulative_drift=cumulative_drift,
        escalation_found=escalation_found,
        turn_count=turn_count,
        reason=" | ".join(reasons) if reasons else "No drift detected",
    )


def reset_layer3_state():
    """Clear all session embeddings — called on demo reset."""
    session_embeddings.clear()
    session_baseline.clear()
