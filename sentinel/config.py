"""
SENTINEL Configuration — All thresholds, environment variables, and tunable parameters.
"""

import os
from dotenv import load_dotenv

import uuid

load_dotenv()

# System Canary Token (Generated per server run)
CANARY_TOKEN = f"SENTINEL-CANARY-{uuid.uuid4().hex}"

# Server
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8080"))

# LLM Backend
LLM_BACKEND = os.getenv("LLM_BACKEND", "https://api.groq.com/openai/v1/chat/completions")
LLM_API_KEY = os.getenv("GROQ_API_KEY", os.getenv("OPENAI_API_KEY", ""))
LLM_MODEL_OVERRIDE = os.getenv("LLM_MODEL_OVERRIDE", "llama-3.1-8b-instant")

# Decision Thresholds
BLOCK_THRESHOLD = float(os.getenv("BLOCK_THRESHOLD", "0.85"))
WARN_THRESHOLD = float(os.getenv("WARN_THRESHOLD", "0.50"))

# Layer 1 — Input Injection Classifier
L1_TIER1_THRESHOLD = 0.45
L1_BLOCK_THRESHOLD = 0.85
L1_SEMANTIC_HIGH = 0.75       # Cosine sim above this → definite injection
L1_SEMANTIC_MEDIUM = 0.55     # Cosine sim above this → suspicious

# Layer 3 — Conversational Drift Tracker
L3_VELOCITY_THRESHOLD = 0.45
L3_DRIFT_THRESHOLD = 0.60
L3_MAX_HISTORY = 10           # Max turns to keep in embedding history

# Layer 3 — Score Weights
L3_VELOCITY_WEIGHT = 0.40
L3_DRIFT_WEIGHT = 0.35
L3_ESCALATION_WEIGHT = 0.25

# Embedding Model
EMBEDDING_MODEL = "all-MiniLM-L6-v2"

# Bounded in-memory state — every session-keyed store in this codebase
# (Layer 3's drift tracker, the Threat Bus's session table, the correlation
# engine's fired-rule tracker) previously grew without eviction for the
# lifetime of the process. These caps bound that memory growth via LRU
# eviction (see sentinel/core/bounded_cache.py). Tune upward for higher
# expected concurrent-session volume in production.
MAX_TRACKED_SESSIONS = int(os.getenv("MAX_TRACKED_SESSIONS", "10000"))
MAX_STORED_EVENTS = int(os.getenv("MAX_STORED_EVENTS", "5000"))
