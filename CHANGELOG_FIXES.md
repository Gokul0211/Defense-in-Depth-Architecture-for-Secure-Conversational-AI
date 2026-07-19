# Fix Pass Changelog

Everything below was found by reading the full pipeline end to end and cross-checking it against `README.md`'s own claims, then fixed in the order shown. Verified by: full-repo `py_compile`, clean import of every module (including the full `sentinel.app` FastAPI entrypoint) with **zero network calls**, and a new regression suite (`tests/test_bugfixes.py`, 19/19 passing) that specifically targets each bug below so it can't silently come back.

This is the engineering-fix pass (roadmap doc Section 6 + everything else found while reading). It does **not** yet include Contributions A/B/C (taint graph, sequential triage, pattern mining) from `01_RESEARCH_GRADE_ROADMAP.md` — those are new subsystems, not bugfixes, and depend on the labeled corpus from `02_EVALUATION_TESTING_PLAN.md` that doesn't exist yet.

---

## Priority 0 — Credibility

**Deleted `sentinel/core/mock_layers.py`.** Confirmed unreferenced anywhere in the live pipeline (only `app.py` had a comment noting it was "kept for reference"). A mock random-score generator has no reason to exist in a repo that's about to be evaluated for a paper — removed entirely rather than gated, since it wasn't providing any value even as a demo fallback.

---

## Priority 1 — Bugs with real security/correctness consequences

1. **L2 detected tampering but never acted on it** (`layer2_rag/chunk_store.py`). `retrieve_and_validate()` re-checked each chunk's HMAC signature at retrieval time and correctly *detected* a mismatch — but the chunk's text was still returned to the caller regardless, and the chunk stayed in the active, retrievable collection. Detection with no enforcement isn't a security control. Fixed: a chunk that fails re-validation is now actually moved out of the active collection into quarantine and excluded from future retrievals (`_quarantine_after_failed_revalidation`). Text is still available on the returned dict (gated behind an explicit `blocked` flag) because Layer 4's provenance tracer legitimately needs the real content for forensic tracing — but any caller assembling LLM-facing context must check `blocked` first, and this is now documented in the function's docstring.

2. **`L2Result.quarantined` was hardcoded `False`** (`layer2_rag/layer2.py`), even when the result's own `threat_class` was `KNOWLEDGE_POISONING`. Now reflects whether any chunk in that retrieval was actually quarantined.

3. **L5 forbidden-topic matching produced guaranteed false positives** (`layer5_output/policy_verifier.py`). A topic like `guarantee_returns` was split into keyword stems (`guarantee`, `returns`) and matched with `any()` — meaning the word "return" appearing anywhere in a response (e.g. "please return the item within 30 days") was enough to flag `guarantee_returns`, with zero relation to "guarantee". Changed to `all()`, requiring every stem to co-occur before flagging — consistent with how `required_disclaimers` in the same file already worked.

4. **L3's "cumulative drift from session baseline" wasn't actually measuring drift from the baseline** (`layers/layer3.py`). `session_embeddings` is a `deque(maxlen=L3_MAX_HISTORY)` (default 10). Drift was computed against `history[0]` — which, once a session passes 10 turns, is silently *not* turn 1 anymore, it's whichever turn is currently oldest in the rolling window. This directly undermines the layer's stated purpose (catching slow-burn, many-turn escalation). Fixed by tracking a separate, persistent `session_baseline` dict populated once on turn 1, independent of the rolling window used for velocity. Covered by a regression test that pushes a session well past `L3_MAX_HISTORY` turns and asserts the stored baseline embedding never changes.

---

## Priority 2 — Unbounded memory growth

Three separate in-memory stores grew without any eviction for the lifetime of the process — every `session_id` ever seen stayed in memory forever:

- `layer3.py`'s `session_embeddings`
- `threat_bus.py`'s `sessions` (this one was also a correctness bug, not just memory: `stats["active_sessions"]` reported the cumulative count of every session ever created, not sessions that are actually active)
- `correlation_engine.py`'s `_fired_rules`

Fixed with one shared utility, `sentinel/core/bounded_cache.py`'s `BoundedLRUDict` — a bounded-size dict that evicts the least-recently-used entry once it exceeds a configured cap (`MAX_TRACKED_SESSIONS`, default 10,000, new in `config.py`). `threat_bus.events` gets the same treatment via a simple trim-on-append (kept as a plain list rather than a `deque`, because `app.py` does `threat_bus.events[-limit:]` slicing elsewhere, which `deque` doesn't support — caught this via the regression suite before it shipped).

---

## Priority 3 — Documentation/implementation mismatches

These matter specifically because a paper built on top of this code will describe the *documented* mechanism — if the code doesn't actually do what the docs say, that's a correctness gap that surfaces the moment a reviewer reads both.

5. **L2 trust score formula didn't match the documented formula** (`layer2_rag/chunk_store.py`). README claimed `trust_score = 1.0 - (0.6 * density + 0.4 * l1)`; the code actually computed `1.0 - max(l1_penalty, density_penalty)` with `density_penalty` hard-zeroed below 0.4 (a discontinuous cliff at exactly 0.4, not a weighted sum). Fixed to implement the documented continuous weighted formula.

6. **L2 quarantine threshold didn't match documented thresholds, and the documented "flagged for review" tier didn't exist at all.** Docs: quarantine below 0.4, review between 0.4–0.6, trusted above 0.6. Code: single quarantine cutoff at 0.5, no middle tier. Implemented the full three-tier system (`collection` / `review_store` / `quarantine_store`).

7. **L4 provenance tracing did exact substring matching, not the documented Levenshtein/fuzzy matching** (`layer4_agentic/provenance_tracker.py`). This had a real precision consequence in both directions: it missed values that an LLM had reformatted slightly (whitespace, punctuation, minor paraphrase), and — more seriously — a short param value like `"1"` would substring-match almost any surrounding text, producing high-confidence `EXPLICIT_USER_REQUEST` results with no real basis. Fixed with a guarded sliding-window `difflib.SequenceMatcher`-based fuzzy match (`fuzzy_contains`), plus a `MIN_TRACEABLE_LEN` guard: values under 4 characters are reported as `UNCERTAIN` rather than confidently (and wrongly) traced. The same unguarded exact-substring pattern existed independently in `layer4_agentic/tool_auditor.py`'s direct chunk-tracing block — fixed to use the same guarded helper, which mattered more there since that path triggers an immediate `CRITICAL` block.

8. **Correlation engine Rule 2 (`RAG_PLUS_AGENT_ATTACK`) didn't actually check for a causal link** (`core/correlation_engine.py`). It fired whenever `l2_findings` was non-empty AND *any* L4 call in the session had `HIGH`/`CRITICAL` risk with `SUSPICIOUS`/`CONTEXT_DERIVED` authorization — two unrelated events anywhere in the same session would trip it and get reported as one correlated attack chain, which is a false correlation, not a detection of the pattern the rule is named after. Fixed to require the L4 call to specifically carry `threat_class == "RAG_INJECTION"`, which `tool_auditor.py` only assigns when it has actually traced a tool-call parameter to a specific flagged chunk. (A general, non-hand-coded version of this — arbitrary traced chains, not just this one pattern — is exactly what the taint propagation graph in the research roadmap document is for.)

9. **L4 risk matrix example tools in the README didn't exist in the actual `TOOL_RISK_MATRIX`** (`layer4_agentic/risk_matrix.py`), and the described scoring mechanism ("average of normalised impact and inverted reversibility") was never actually implemented — the real mechanism is a static category lookup plus keyword-based risk escalation. Reconciled both directions: added the documented example tools (`delete_file`, `modify_system`, `send_email_bulk`, `create_user`, `get_weather`, `calculate`) to the actual matrix, and corrected the README to describe the real mechanism instead of one that was never built.

10. **`layer2_validate_context`'s type annotation said `-> L2Result`** while it actually returned `(L2Result, list)`. Callers already handled this correctly via an `isinstance` check, so it wasn't a runtime bug, just a type-hint lie — fixed the annotation to `-> tuple[L2Result, list]`.

11. **L3 config weights didn't match the README** — docs said `0.40/0.40/0.30` (which sums to 1.10), code had `0.40/0.35/0.25`. Corrected the README to match the actual values and noted they're hand-set placeholders pending the ROC-based calibration described in the evaluation plan.

12. **Correlation evidence messages referenced `call.get('tool_name')`, but `L4Result.to_dict()` never included a `tool_name` field** — every correlation event's evidence text silently printed `None` where the tool name should have been. Fixed at the call site in `app.py` to store `tool_name` alongside the result dict.

---

## Priority 4 — Blocking issues for testing/portability

13. **`layer1.py` and `instruction_density.py` computed their reference embeddings at module import time**, not lazily (`INJECTION_EMBEDDINGS = get_model().encode(...)` at module scope). This meant simply *importing* either module forced an immediate embedding-model load — defeating the lazy-singleton pattern `embedding.py` was written for, and making the module impossible to import in any environment without model access (this was actively blocking verification of these fixes in this sandbox). Fixed both to compute their reference embeddings lazily on first use, cached after that. Verified: the entire `sentinel.app` FastAPI entrypoint now imports cleanly with zero network calls required.

14. Removed unused `SentenceTransformer` and `numpy` imports left over in a couple of files after the above fix.

---

## Priority 5 — Precision/correctness cleanups

15. **PII scanner position tracking was inconsistent** (`layer5_output/pii_scanner.py`). Each PII type was matched by re-scanning the text *after* earlier types had already redacted their matches, so each finding's recorded `position` was an offset into a different intermediate string each time — not into the original text or the final sanitized text. Rewritten as a single pass: find all matches against the original text, resolve overlaps once, then build the sanitized text — every reported position is now consistently an offset into the original input.

16. **Email regex had a stray literal `|` inside a character class** (`[A-Z|a-z]` → `[A-Za-z]`) — a classic copy-paste mistake (`|` means alternation outside a character class, but is a literal character inside one), which let the regex consume pipe-joined trailing text into what it reported as the email's TLD.

17. **Exfiltration score and evidence text could silently disagree** (`layer5_output/exfil_detector.py`). Semantic/token overlap below their own documented evidence thresholds (0.65 / 0.40) still contributed to the numeric score, so a response could get pushed toward WARN/BLOCK with no evidence text explaining why. Fixed so a signal only contributes to the score once it has actually crossed its documented threshold — score and evidence now always agree.

---

## New files

- `sentinel/core/bounded_cache.py` — shared `BoundedLRUDict` utility (Priority 2).
- `tests/test_bugfixes.py` + `tests/fake_embedder.py` — regression suite. The fake embedder is a deterministic offline bag-of-words stand-in used only so tests don't require network access to the real model; it's explicitly documented as unsuitable for any accuracy claims, only for control-flow/threshold testing.
- `pytest.ini` — enables `pytest-asyncio` auto mode for the async layer functions.

## Config additions

- `MAX_TRACKED_SESSIONS` (default 10,000) and `MAX_STORED_EVENTS` (default 5,000) in `config.py`, both overridable via environment variables.

## Known follow-ups not addressed in this pass

- `generate_test_assets.py`'s docstring comments reference the old trust-score numbers (e.g. "trust_score≈0.08") — cosmetic, doesn't affect any assertion, but worth updating for accuracy since the actual number a reader would now compute is different (though still correctly below the quarantine threshold).
- The dashboard frontend (`dashboard/static/*.js`) doesn't currently render `review_flagged` state distinctly from `quarantined` — it wasn't rendering either field before this pass, so this isn't a regression, just an opportunity now that the three-tier state actually exists in the backend.
- Contributions A/B/C from the roadmap document (taint graph, sequential triage, pattern mining) are new subsystems, not covered here — next phase, and gated on the labeled corpus from the evaluation plan.
