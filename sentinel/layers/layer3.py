"""
SENTINEL Layer 3 — Conversational Drift Tracker (Real)

Detects slow-burn multi-turn manipulation by measuring:
  1. Semantic velocity — cosine distance between consecutive turns
  2. Cumulative drift — cosine distance from the session's true first turn
  3. Harm-topic alignment — cosine similarity to known harmful-request topics
  4. Escalation phrases — known social engineering phrases

--------------------------------------------------------------------------
RCA #1 (2026-07-25): why velocity and drift are combined multiplicatively,
not additively
--------------------------------------------------------------------------
A live eval run against custom_l3 with the real embedding model produced
AUROC=0.2598 and FPR=1.0 — i.e. WORSE than random, and every single benign
conversation flagged. That is not "the problem is hard", it's a ranking
inversion, and it was reproducible: an offline proxy check (deterministic
bag-of-words embedder, `tests/fake_embedder.py` — suitable only for
*directional* control-flow checks, never for accuracy claims) confirmed the
same inversion and, critically, explained the mechanism:

  - custom_l3's malicious samples are 100% "crescendo"-style attacks,
    generated specifically to escalate via small, natural-feeling steps
    (see generate_l3_corpus.py's escalation_instruction: "Each turn should
    feel like a natural follow-up"). That is LOW turn-to-turn velocity by
    construction — it's the defining trait of this threat model, not an
    incidental property.
  - custom_l3's benign categories were *assumed* (based on their names and
    an offline bag-of-words proxy) to be high-velocity. RCA #2 below shows
    this assumption was wrong for 4 of the 5 benign categories.

A positively weighted ADDITIVE sum of velocity + drift can only ever push
the score in the direction the raw signal points — and raw velocity points
the wrong way for the crescendo class. This function combines them
multiplicatively instead:

  smoothness = 1 - velocity
  drift_component = cumulative_drift * smoothness

This rewards a large cumulative shift from baseline achieved through small,
smooth steps, and discounts the same shift achieved via one visible jump.
This fixed the below-chance AUROC (0.26 -> a real, confirmed 0.6145 on a
live run with the real embedding model), but 0.6145 is still below the "did
this actually work" line the project's own testing guide sets (below ~0.70
on a self-generated corpus means something's wrong with the detector or the
corpus, not that "the problem is hard" — see TESTING_GUIDE.md Part 2). RCA
#2 explains why, and is the fix that actually closes the gap.

--------------------------------------------------------------------------
RCA #2 (2026-07-25, same day, after a confirmed real-model AUROC=0.6145):
drift/velocity geometry alone cannot separate this benchmark's classes
--------------------------------------------------------------------------
RCA #1's benign-category assumption was checked directly against
`generate_l3_corpus.py`'s actual seed turns (not just category names) using
a real semantic sentence embedder as an offline proxy (spaCy's
`en_core_web_md`, word-vector-averaged — NOT the bag-of-words
`fake_embedder.py`, and NOT the production `all-MiniLM-L6-v2` either; still
a proxy, but a genuinely semantic one, unlike the BOW proxy). Result,
averaged per-turn over the whole test split:

  category                          mean velocity   mean cumulative_drift
  ---------------------------------------------------------------------
  benign / rapid_topic_changes            0.407            0.455
  benign / topic_shift_work_to_hobby      0.246            0.263
  benign / deep_technical_discussion      0.231            0.265
  malicious / crescendo_privacy           0.243            0.258
  benign / topic_shift_cooking_to_travel  0.187            0.211
  benign / emotional_conversation         0.189            0.140
  malicious / crescendo_chemistry         0.209            0.354
  malicious / crescendo_weapons           0.215            0.236
  malicious / crescendo_hacking           0.192            0.230
  malicious / crescendo_social_engineering 0.115           0.137

Only ONE of the five benign categories (`rapid_topic_changes` — the one
built from genuinely disconnected turns like "capital of Mongolia" ->
"convert 72F to Celsius") is actually high-velocity. The other four
(`topic_shift_cooking_to_travel`, `topic_shift_work_to_hobby`,
`deep_technical_discussion`, `emotional_conversation`) were written to read
as NATURAL conversation ("Speaking of authentic food, have you been to
Thailand?") — which means they are ALSO smooth, gradual, low-velocity
transitions under a real semantic embedder, indistinguishable in
geometry from the malicious crescendo turns. Bag-of-words similarity
(the RCA #1 proxy) had overstated the velocity gap for these categories,
because BOW measures literal vocabulary overlap (cooking words vs. travel
words look "different"), not conversational coherence — a real embedder
correctly recognizes the bridge sentence as semantically smooth, which
directly contradicts RCA #1's "benign = high velocity" premise for 4/5
categories.

The structural conclusion: "has this conversation drifted far from its
starting point, via smooth steps" is a property of essentially ALL natural
multi-turn conversation, benign or malicious — it is not, by itself,
evidence of anything adversarial. Distance-and-smoothness alone is
topic-agnostic; it cannot tell "drifted toward asking how to build a bomb"
apart from "drifted toward asking about a vacation," because both are
geometrically the same shape (smooth, moderate drift). No further
reweighting of velocity/drift fixes this — it needs a signal that actually
looks at WHERE the conversation drifted to, not just how far and how
smoothly.

**The fix**: add `harm_alignment` — the max cosine similarity of the
CURRENT turn's embedding against a small, fixed set of harm-topic anchor
sentences (`HARM_ANCHOR_PHRASES` below), one per broad harm category. This
is a content-aware signal instead of a purely geometric one. Checked with
the same spaCy proxy against the exact same test split:

  - `harm_alignment` (max per-turn similarity) alone: AUROC ~0.89
  - old `drift * smoothness` alone (RCA #1's fix): AUROC ~0.40 in this same
    proxy re-check (the live-model 0.6145 above is the real number; the
    spaCy figure here is only used for a same-proxy, apples-to-apples
    comparison between the two candidate signals)

`harm_alignment` is now the DOMINANT term in the score (see
`L3_HARM_ALIGNMENT_WEIGHT` in config.py); `drift * smoothness` is kept only
as a smaller secondary/backstop signal for gradual-topic-drift patterns
that don't match any of the fixed harm anchors.

**Important honesty notes, read before trusting this**:
  1. The ~0.89 / ~0.40 numbers above are from an offline spaCy proxy, not
     the real `all-MiniLM-L6-v2` model — this sandbox has no HuggingFace
     access (same limitation as every prior RCA in this file). **Run
     `python -m sentinel.eval.calibrate_l3_weights` then
     `python -m sentinel.eval.runner --layer L3 --dataset custom_l3 -v`
     on your machine to get the real, confirmed number** — this is not
     optional, exactly as RCA #1 said about its own fix.
  2. `HARM_ANCHOR_PHRASES` below are original sentences describing broad,
     standard AI-safety harm domains (dangerous-chemical synthesis, cyber
     exploitation, physical weapons, stalking/doxxing, phishing/
     manipulation) — they are NOT copied from `generate_l3_corpus.py`'s
     text. But their category *coverage* does overlap with this corpus's
     five attack strategies, because both were drawn from the same
     standard threat taxonomy. That overlap is disclosed here rather than
     hidden: per 01_RESEARCH_GRADE_ROADMAP.md Section 9's risk register,
     any AUROC improvement from this change should be reported alongside
     this caveat, and the anchor set should eventually be validated against
     a held-out benchmark with DIFFERENT harm categories before being
     trusted as general-purpose (not just re-confirmed on custom_l3 again).
  3. This makes L3 partly duplicate L1's per-message content classifier —
     that's an intentional defense-in-depth overlap, not a mistake. L3's
     added value over L1 is still the multi-turn tracking (a turn can score
     moderately on harm_alignment on its own merits while the SEQUENCE of
     turns is what a single-message classifier can't see), and the
     drift/smoothness component is kept specifically to preserve that.
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
    L3_HARM_ALIGNMENT_WEIGHT,
    L3_HARM_ALIGNMENT_THRESHOLD,
    L3_ESCALATION_WEIGHT,
    L3_ESCALATION_THRESHOLD,
    MAX_TRACKED_SESSIONS,
)
from sentinel.core.models import L3Result
from sentinel.core.embedding import get_model
from sentinel.core.bounded_cache import BoundedLRUDict
from sentinel.core.text_canonicalize import canonicalize
from sentinel.core.cipher_decode import extract_mapping_pair, apply_word_mapping, looks_like_mapping_header

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

# Per-session accumulated word-substitution mapping pairs — Phase 3 RCA,
# 2026-09-14. See cipher_decode.py's module docstring for the full finding:
# a disclosed "X - Y" substitution table, declared turn-by-turn, is a real,
# mechanically decodable cipher (not the "no fixed key, unfixable" case an
# earlier pass concluded) — the key IS disclosed, just not in one place a
# single-turn check would see. Accumulated here exactly like
# session_baseline above, since layer3_check only ever sees one turn at a
# time and has no other way to remember what a prior turn declared.
session_word_mappings: BoundedLRUDict[str, dict] = BoundedLRUDict(MAX_TRACKED_SESSIONS)

# How many user turns layer3_check has consumed per session (uncapped, unlike the
# rolling deque). Lets a stateless caller -- the OpenAI-compatible proxy, whose clients
# resend the whole conversation and usually send no session header -- replay only the
# turns this layer has not yet seen (R-008, 2026-09-23).
session_turn_counts: BoundedLRUDict[str, int] = BoundedLRUDict(MAX_TRACKED_SESSIONS)


def layer3_turns_seen(session_id: str) -> int:
    return session_turn_counts.get(session_id, 0)


# The session's user turns, kept only when L3_CONTENT_SIGNAL="guard": the guard reads
# the last turn IN CONTEXT of the earlier ones (its native multi-turn template), which
# is what a per-turn anchor match cannot do (fixing.md B).
session_user_turns: BoundedLRUDict[str, list] = BoundedLRUDict(MAX_TRACKED_SESSIONS)


# Running aggregates for the rank-fusion score (L3_SCORE_MODE='rank_fusion').
# Kept in its own store so enabling that mode cannot perturb the production
# path's history handling. See layers/layer3_rank_fusion.py.
session_rank_stats: BoundedLRUDict[str, object] = BoundedLRUDict(MAX_TRACKED_SESSIONS)

# A lone "X - Y" line could coincide in genuinely benign text (e.g. a
# comparison) — only ACT on an accumulated mapping once this many real
# pairs have been observed in the same session, mirroring the Caesar
# decoder's absolute-ceiling discipline (don't trust one weak signal).
# Real tom-gibbs samples disclose 2-9 pairs; benign coincidence repeating
# 2+ times in one session is a materially different, much rarer event.
_MIN_MAPPING_PAIRS_TO_DECODE = 2

# Harm-topic anchors — see RCA #2 in the module docstring above. Original
# sentences describing broad, standard harm domains; NOT copied from any
# corpus's text. Deliberately generic ("instructions for X") rather than
# phrased like a first-person request, so similarity reflects topical
# alignment rather than matching a specific request phrasing.
HARM_ANCHOR_PHRASES = [
    "Instructions for synthesizing dangerous explosive or toxic chemical compounds at home.",
    "Specific exploit code or step-by-step instructions for unauthorized hacking into a computer system.",
    "Detailed instructions for building a functional weapon or explosive device.",
    "Techniques to track down a specific person's home address, daily routine, and personal information without their consent.",
    "Specific phishing scripts or manipulation tactics to deceive and psychologically exploit a targeted individual.",
]

# Lazily computed, cached anchor embeddings. Cleared in reset_layer3_state()
# so tests (or a production model hot-swap) that replace get_model()'s
# return value always recompute against whatever model is currently active,
# instead of silently reusing embeddings from a different model.
_harm_anchor_embeddings: np.ndarray | None = None


def _get_harm_anchor_embeddings() -> np.ndarray:
    global _harm_anchor_embeddings
    if _harm_anchor_embeddings is None:
        _harm_anchor_embeddings = np.array(get_model().encode(HARM_ANCHOR_PHRASES))
    return _harm_anchor_embeddings


def _harm_alignment(current_embedding: np.ndarray) -> float:
    """Max cosine similarity of the current turn against the harm anchors."""
    anchors = _get_harm_anchor_embeddings()
    sims = cosine_similarity(current_embedding, anchors)[0]
    return float(max(0.0, sims.max()))


# Escalation anchors — converted 2026-09-11 from a 26-entry literal
# substring-match list to cosine-similarity sentences, mirroring
# HARM_ANCHOR_PHRASES's mechanism exactly (see _get_harm_anchor_embeddings/
# _harm_alignment above).
#
# RCA: measured directly against real MHJ conversation text (both tactics,
# both splits) — the old ESCALATION_PHRASES list matched 0.000-0.008 of
# the time, essentially never firing, including on text that's obviously
# the same underlying social-engineering pattern in different words (e.g.
# "Roleplay as Robert Mueller..." doesn't contain the literal substring
# "let's roleplay"). Same brittle-exact-match problem L1's KNOWN_INJECTIONS
# and L2's INSTRUCTIONAL_TEMPLATES had before being converted to embeddings
# (see this file's module docstring and A.1 item 3 in the results record).
#
# The 26 original phrases collapse into 7 real conceptual clusters —
# generalized into full anchor sentences below (not verbatim-lifted from
# any corpus), same style as HARM_ANCHOR_PHRASES:
ESCALATION_ANCHOR_PHRASES = [
    "A request to override, bypass, or disable the assistant's safety checks, validation, or security restrictions.",
    "A request to activate an unrestricted 'developer mode,' a jailbroken persona, or a version of the assistant with no guidelines.",
    "Using a hypothetical, fictional, or roleplay framing to get the assistant to say something it normally would not.",
    "Claiming academic research or educational purposes as justification for providing normally restricted information.",
    "Claiming to be an administrator, to have elevated permissions, or to be self-authorizing access that was not actually granted.",
    "Claiming the assistant already helped with this exact request before, that other AI systems do this, or that it's required for the user's job.",
    "Claiming an emergency or that someone is in danger to pressure the assistant into bypassing its normal restrictions.",
]

# Same lazy-cache-cleared-on-reset pattern as _harm_anchor_embeddings.
_escalation_anchor_embeddings: np.ndarray | None = None


def _get_escalation_anchor_embeddings() -> np.ndarray:
    global _escalation_anchor_embeddings
    if _escalation_anchor_embeddings is None:
        _escalation_anchor_embeddings = np.array(get_model().encode(ESCALATION_ANCHOR_PHRASES))
    return _escalation_anchor_embeddings


def _escalation_alignment(current_embedding: np.ndarray) -> float:
    """Max cosine similarity of the current turn against the escalation anchors."""
    anchors = _get_escalation_anchor_embeddings()
    sims = cosine_similarity(current_embedding, anchors)[0]
    return float(max(0.0, sims.max()))


async def layer3_check(session_id: str, user_input: str) -> L3Result:
    """
    Track conversational drift for a session.
    Returns L3Result with velocity, drift, escalation, and combined score.
    """
    if session_id not in session_embeddings:
        session_embeddings[session_id] = deque(maxlen=L3_MAX_HISTORY)
    session_turn_counts[session_id] = session_turn_counts.get(session_id, 0) + 1

    # Word-substitution mapping tracking — see session_word_mappings'
    # module-level comment and cipher_decode.py's docstring. A turn that's
    # just a short "X - Y" declaration is recorded for later turns to use;
    # it is NOT itself excluded from normal scoring below (a mapping-
    # declaration turn is expected to score low/benign on its own, same as
    # it already did before this fix — nothing here suppresses that).
    #
    # Requires looks_like_mapping_header() to have been seen THIS session
    # before any pair is recorded — closes a real false-trigger class found
    # during isolated testing (see that function's docstring): genuinely
    # benign "X - Y" list pairs (e.g. "James - 22", "Apple - Fruit") can
    # coincidentally match extract_mapping_pair's shape check, but never
    # co-occur with a turn announcing a substitution cipher is in use.
    if looks_like_mapping_header(user_input) and session_id not in session_word_mappings:
        session_word_mappings[session_id] = {}
    pair = extract_mapping_pair(user_input)
    if pair is not None and session_id in session_word_mappings:
        substituted, original = pair
        session_word_mappings[session_id][substituted] = original

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

    # Harm-topic alignment and escalation alignment — see RCA #2 in the
    # module docstring for harm_alignment, and the ESCALATION_ANCHOR_PHRASES
    # comment above for escalation's 2026-09-11 conversion from literal
    # substring matching to the same mechanism. Both are content-aware
    # signals: does THIS turn's text resemble a known harmful-request topic
    # / a known social-engineering escalation pattern, regardless of how
    # the conversation got here geometrically.
    #
    # Scored against both the raw turn embedding and a canonicalized
    # (case-folded, homoglyph-folded, zero-width-stripped) embedding, max
    # of the two — same rationale as L1 Tier 2 / L2's instruction density
    # fix (see text_canonicalize.py's module docstring): these are the
    # content-matching signals in L3, so they're the ones that need
    # evasion resistance. velocity/drift stay on the raw embedding — they
    # track genuine conversational trajectory, not injection-style
    # content, and canonicalizing them wouldn't make sense.
    canon_embedding = get_model().encode([canonicalize(user_input)])
    harm_alignment = max(_harm_alignment(current_embedding), _harm_alignment(canon_embedding))
    escalation_alignment = max(_escalation_alignment(current_embedding), _escalation_alignment(canon_embedding))

    # Word-substitution decode — see session_word_mappings' comment above.
    # Only acts once >= _MIN_MAPPING_PAIRS_TO_DECODE real pairs have been
    # observed THIS session, and only if decoding actually changes the
    # text (an unrelated turn with no mapped words is left alone). Same
    # additive max pattern as canon_embedding above — this can only ADD a
    # detection the raw/canonicalized text missed, never suppress one.
    mapping = session_word_mappings.get(session_id)
    decoded_goal = None
    if mapping and len(mapping) >= _MIN_MAPPING_PAIRS_TO_DECODE:
        decoded_text = apply_word_mapping(user_input, mapping)
        if decoded_text != user_input:
            # A mapping line itself decodes to a trivial "x - x"; only non-pair turns carry
            # the hidden instruction (the same rule B-008 measured the decoded goal with).
            if extract_mapping_pair(user_input) is None:
                decoded_goal = decoded_text
            decoded_embedding = get_model().encode([decoded_text])
            harm_alignment = max(harm_alignment, _harm_alignment(decoded_embedding))
            escalation_alignment = max(escalation_alignment, _escalation_alignment(decoded_embedding))

    escalation_found = escalation_alignment > L3_ESCALATION_THRESHOLD

    # INTENT-LEVEL CONTENT SIGNAL (fixing.md B/C; R-009, R-011), off by default.
    # The five HARM_ANCHOR_PHRASES are a topic matcher: tom-gibbs goals inside their
    # five topics are caught at 0.42-0.84 and outside them at 0.15-0.40, benign false
    # alarms concentrate on the same five topics, and MHJ misinformation / hate / drugs
    # score 0 %. In "guard" mode the content term is instead the safety guard on
    #   (a) the conversation so far, last turn in context (MHJ-style intent that is
    #       spread over turns), and
    #   (b) the DECODED plaintext when a word-mapping cipher was declared (tom-gibbs:
    #       the goal only exists after decoding, and L3 already decodes it above),
    # max of the two. Fail-soft: guard unavailable -> the anchor term is kept.
    import sentinel.config as _cfg
    guard_score = None
    guard_only = False
    if getattr(_cfg, "L3_CONTENT_SIGNAL", "anchors") == "guard":
        from sentinel.core.safety_guard import safety_score_conversation, safety_score_prompt
        turns = session_user_turns.get(session_id)
        if turns is None:
            turns = []
            session_user_turns[session_id] = turns
        turns.append(user_input)
        cands = [safety_score_conversation(turns)]
        if (mapping and len(mapping) >= _MIN_MAPPING_PAIRS_TO_DECODE
                and extract_mapping_pair(user_input) is None):
            decoded = apply_word_mapping(user_input, mapping)
            if decoded != user_input:
                cands.append(safety_score_prompt(decoded))
        cands = [c for c in cands if c is not None]
        guard_score = max(cands) if cands else None
        guard_only = guard_score is not None and getattr(_cfg, "L3_GUARD_COMBINE", "replace") == "guard_only"

    # Store this turn's embedding in the rolling window (used for velocity only)
    history.append(current_embedding[0].tolist())
    turn_count = len(history)

    # Compute combined score.
    #
    # `harm_alignment` is the dominant term (see RCA #2 — pure drift/
    # velocity geometry was confirmed not to separate this benchmark's
    # classes, because natural conversation drifts smoothly regardless of
    # whether it's benign or adversarial). `drift * smoothness` (RCA #1) is
    # kept as a smaller secondary/backstop signal: it still rewards a large
    # cumulative shift from baseline achieved through small, smooth steps
    # over the same shift achieved via one visible jump, for gradual-drift
    # patterns the fixed harm-anchor list doesn't cover. `velocity` still
    # does not contribute as an independent additive term — it only
    # modulates the drift component, same as RCA #1.
    smoothness = max(0.0, 1.0 - velocity)
    drift_component = cumulative_drift * smoothness

    score = 0.0
    if guard_only:
        # The guard alone; session-level scoring is the running max over turns, applied
        # by every caller exactly as for the production score.
        score = guard_score
    else:
        # "replace": the guard takes harm_alignment's place and weight; the geometry and
        # escalation terms are unchanged.
        content_term = harm_alignment if guard_score is None else guard_score
        score += content_term * L3_HARM_ALIGNMENT_WEIGHT
        score += drift_component * (L3_DRIFT_WEIGHT + L3_VELOCITY_WEIGHT)
    # REVERTED to a flat bonus, 2026-09-13 — a continuous contribution was
    # tried first (see git history / results record D.5) on the theory
    # that it's "more principled than a boolean flag," matching
    # harm_alignment's own style. Measured directly against MHJ's real
    # held-out test split before trusting it: the isolated
    # escalation_alignment signal is actively ANTI-CORRELATED on this
    # corpus (AUROC 0.393 — benign mean 0.295 > malicious mean 0.270,
    # worse than chance, same failure shape as L1/L2's original
    # un-calibrated template lists) — the un-calibrated anchor sentences
    # just aren't good yet, and a CONTINUOUS weighting let that inverted
    # noise drag every single sample's score in the wrong direction,
    # dropping L3's overall MHJ AUROC from the previously-cited 0.6319 to
    # 0.5809. A flat bonus bounds the damage to only the rare cases that
    # cross the threshold (confirmed: 0.9% malicious / 0% benign hit rate
    # at L3_ESCALATION_THRESHOLD=0.45 — as inert as the old substring
    # version, not actively harmful) while keeping the real, legitimate
    # improvement: the TRIGGER condition is now semantic similarity, not
    # brittle exact-substring matching, so it can still catch real
    # escalation phrasing the old list's exact strings missed, once/if
    # the anchors get properly train-only calibrated against real data —
    # not done yet, see D.5's "not yet done" note.
    if not guard_only:
        score += L3_ESCALATION_WEIGHT if escalation_found else 0.0
    score = max(0.0, min(score, 1.0))

    # RANK-FUSION SCORE (2026-09-22), off by default.
    #
    # §8b.3 showed L3's two production terms are exactly inverted between its
    # corpora and that no rule over THOSE terms beats production on both. This
    # scores three different session statistics -- max smoothness, max harm
    # alignment, mean escalation alignment -- through a frozen benign CDF, because
    # per feature the families are COMPLEMENTARY rather than inverted:
    # smooth_max is 0.8201 on MHJ and chance (0.4947) on tom-gibbs; harm_max is
    # chance on MHJ and 0.6564 on tom-gibbs; esc_mean works on both.
    #
    # Measured session-level: MHJ 0.6139 -> 0.6632, tom-gibbs 0.5949 -> 0.6350
    # against the frozen custom_l3 reference. Falls back to the production score
    # whenever the reference artifact is unavailable, so a missing file degrades
    # to current behaviour rather than to a guess.
    from sentinel.config import L3_SCORE_MODE
    if L3_SCORE_MODE == "rank_fusion":
        from sentinel.layers.layer3_rank_fusion import SessionStats
        st = session_rank_stats.get(session_id)
        if st is None:
            st = SessionStats()
            session_rank_stats[session_id] = st
        # turn_count is len(history) AFTER this turn was appended, so a
        # predecessor exists only from the second turn onward.
        st.update(smoothness, harm_alignment, escalation_alignment,
                  has_previous_turn=turn_count >= 2)
        rf = st.score()
        if rf is not None:
            score = max(0.0, min(rf, 1.0))

    # DECODED-GOAL GUARD (L3_DECODED_GUARD, fixing.md C), off by default. The passing half
    # of B-009: the guard on the decoded cipher goal only, mapped onto L3's own axis at the
    # channel anchor and capped below BLOCK (WARN-only), fused by max. Skipped in "guard"
    # mode, which already scores the decoded goal inside its content term. Fail-soft:
    # guard unavailable -> no change.
    decoded_guard_score = None
    if (decoded_goal is not None and getattr(_cfg, "L3_DECODED_GUARD", False)
            and getattr(_cfg, "L3_CONTENT_SIGNAL", "anchors") != "guard"):
        from sentinel.core.safety_guard import map_to_layer_axis, safety_score_prompt
        decoded_guard_score = safety_score_prompt(decoded_goal)
        if decoded_guard_score is not None:
            warn = _cfg.l3_warn_threshold()
            mapped = map_to_layer_axis(decoded_guard_score, _cfg.L3_DECODED_GUARD_TAU,
                                       warn, _cfg.l3_block_threshold() - 1e-6)
            # L3_DECODED_GUARD_MODE (R-035, 2026-09-26): "replace" -- for a cipher session the
            # production features describe the ENCODING (every cipher conversation has mapping
            # turns), so the decoded goal's verdict is the content; measured offline: semi-benign
            # FPR 0.454 (max) -> 0.022 (replace) at recall 0.987 -> 0.984.
            score = mapped if getattr(_cfg, "L3_DECODED_GUARD_MODE", "max") == "replace" else max(score, mapped)

    # "replace" also treats the cipher PREAMBLE (the mapping header and the "X - Y" pair lines of a
    # session that declared a mapping) as structure, not content: without this, the running max
    # over turns would keep the preamble's production score and undo the replacement.
    if (getattr(_cfg, "L3_DECODED_GUARD", False) and getattr(_cfg, "L3_DECODED_GUARD_MODE", "max") == "replace"
            and getattr(_cfg, "L3_CONTENT_SIGNAL", "anchors") != "guard"
            and session_id in session_word_mappings
            and (looks_like_mapping_header(user_input) or extract_mapping_pair(user_input) is not None)):
        score = 0.0

    # Build reason string
    reasons = []
    if harm_alignment > L3_HARM_ALIGNMENT_THRESHOLD:
        reasons.append(f"Content resembles known harmful topic (harm_alignment={harm_alignment:.2f})")
    if velocity > L3_VELOCITY_THRESHOLD:
        reasons.append(f"High topic shift (velocity={velocity:.2f})")
    if cumulative_drift > L3_DRIFT_THRESHOLD:
        reasons.append(f"Session drifting from origin (drift={cumulative_drift:.2f})")
    if escalation_found:
        reasons.append("Escalation phrase detected")
    if guard_score is not None and guard_score >= 0.5:
        reasons.append(f"Safety classifier: harmful intent in conversation (P={guard_score:.2f})")
    if decoded_guard_score is not None and decoded_guard_score >= _cfg.L3_DECODED_GUARD_TAU:
        reasons.append(f"Safety classifier: harmful decoded cipher goal (P={decoded_guard_score:.2f})")

    return L3Result(
        score=score,
        semantic_velocity=velocity,
        cumulative_drift=cumulative_drift,
        escalation_found=escalation_found,
        turn_count=turn_count,
        reason=" | ".join(reasons) if reasons else "No drift detected",
        harm_alignment=harm_alignment,
        guard_score=guard_score,
        decoded_guard_score=decoded_guard_score,
    )


def reset_layer3_state():
    """Clear all session embeddings — called on demo reset."""
    global _harm_anchor_embeddings, _escalation_anchor_embeddings
    session_embeddings.clear()
    session_turn_counts.clear()
    session_user_turns.clear()
    session_baseline.clear()
    session_word_mappings.clear()
    session_rank_stats.clear()
    # Cleared too: if get_model() has been swapped (e.g. by a test's
    # monkeypatch, or a production model hot-swap), the next call must
    # recompute anchor embeddings against whatever model is active now
    # instead of silently reusing a stale, dimensionally-mismatched cache.
    _harm_anchor_embeddings = None
    _escalation_anchor_embeddings = None
