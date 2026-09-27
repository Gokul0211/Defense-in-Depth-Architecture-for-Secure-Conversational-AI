"""
SENTINEL Evaluation — Corpus Sanity Checker.

Validates generated corpora BEFORE running evaluations to catch
data issues that would invalidate results. Run this once after
corpus generation, not repeatedly.

Checks:
  1. Label consistency — malicious samples contain attack patterns,
     benign samples don't
  2. Train/test split disjointness — no sample appears in both
  3. Duplicate detection — no exact-text duplicates within a split
  4. Held-out vs mining set separation (SENTINEL-Bench)
  5. Schema validation — all required fields present
  6. Distribution sanity — reasonable class balance, no empty splits

Usage:
    python -m sentinel.eval.sanity_check
"""

from __future__ import annotations

import json
import hashlib
import logging
import sys
from collections import Counter
from pathlib import Path

logger = logging.getLogger(__name__)

_DATA_DIR = Path(__file__).parent / "data"

# Known injection / attack signal words that should appear in malicious samples
_ATTACK_SIGNALS = [
    "ignore", "override", "system prompt", "previous instructions",
    "ADMIN", "execute", "run_command", "admin_query", "OVERRIDE",
    "HIDDEN", "bypass", "disregard", "curl", "payload",
    "attacker", "unauthorized", "exploit", "inject",
]

# Patterns that should NOT appear in "benign" samples
_RED_FLAGS_IN_BENIGN = [
    "ignore all previous instructions",
    "SYSTEM OVERRIDE",
    "ADMIN OVERRIDE",
    "run_command",
    "admin_query",
    "curl http://attacker",
    "HIDDEN INSTRUCTION",
]


class SanityCheckResult:
    def __init__(self, name: str):
        self.name = name
        self.passed: list[str] = []
        self.warnings: list[str] = []
        self.failures: list[str] = []

    def ok(self, msg: str):
        self.passed.append(msg)

    def warn(self, msg: str):
        self.warnings.append(msg)

    def fail(self, msg: str):
        self.failures.append(msg)

    @property
    def is_clean(self) -> bool:
        return len(self.failures) == 0

    def summary(self) -> str:
        lines = [f"\n{'='*60}", f"  {self.name}", f"{'='*60}"]
        for p in self.passed:
            lines.append(f"  [PASS] {p}")
        for w in self.warnings:
            lines.append(f"  [WARN] {w}")
        for f in self.failures:
            lines.append(f"  [FAIL] {f}")

        status = "PASS" if self.is_clean else "FAIL"
        lines.append(f"\n  Result: {status} ({len(self.passed)} passed, {len(self.warnings)} warnings, {len(self.failures)} failures)")
        return "\n".join(lines)


def _load_jsonl(path: Path) -> list[dict]:
    """Load a JSONL file."""
    if not path.exists():
        return []
    samples = []
    with open(path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                samples.append(json.loads(line))
            except json.JSONDecodeError as e:
                logger.warning(f"  Malformed JSON at {path}:{line_num}: {e}")
    return samples


def _text_hash(text: str) -> str:
    """Deterministic hash of text content."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Check 1: Schema validation
# ---------------------------------------------------------------------------

def check_schema(samples: list[dict], dataset_name: str) -> SanityCheckResult:
    """Verify all required fields are present and have valid values."""
    result = SanityCheckResult(f"{dataset_name} — Schema Validation")

    required_fields = ["text", "label", "attack_type", "target_layer", "source_benchmark", "sample_id"]
    valid_labels = {"malicious", "benign"}

    missing_fields = Counter()
    invalid_labels = []
    empty_texts = 0

    for i, s in enumerate(samples):
        for field in required_fields:
            if field not in s:
                missing_fields[field] += 1

        if s.get("label") not in valid_labels:
            invalid_labels.append((i, s.get("label")))

        if not s.get("text", "").strip():
            empty_texts += 1

    if not missing_fields:
        result.ok(f"All {len(samples)} samples have all required fields")
    else:
        for field, count in missing_fields.items():
            result.fail(f"Field '{field}' missing in {count}/{len(samples)} samples")

    if not invalid_labels:
        result.ok(f"All labels are valid ('malicious' or 'benign')")
    else:
        result.fail(f"{len(invalid_labels)} samples have invalid labels: {invalid_labels[:5]}")

    if empty_texts == 0:
        result.ok("No empty text fields")
    else:
        result.fail(f"{empty_texts} samples have empty text")

    return result


# ---------------------------------------------------------------------------
# Check 2: Label consistency
# ---------------------------------------------------------------------------

def check_label_consistency(samples: list[dict], dataset_name: str) -> SanityCheckResult:
    """Verify malicious samples contain attack patterns, benign don't."""
    result = SanityCheckResult(f"{dataset_name} — Label Consistency")

    malicious = [s for s in samples if s.get("label") == "malicious"]
    benign = [s for s in samples if s.get("label") == "benign"]

    # Check: malicious samples should contain attack-relevant signals
    # The signal set depends on the attack type / target layer:
    #   - L5 (PII leakage): SSN patterns, credit cards, phone numbers, etc.
    #   - L5 (canary): system prompt, API key, canary token, etc.
    #   - All others (injection): "ignore", "override", "system prompt", etc.
    _PII_SIGNALS = [
        "ssn", "social security", "credit card", "card number",
        "phone:", "email:", "DOB:", "diagnosis", "patient",
        "account", "balance", "salary", "prescription",
        "shipping address", "contact information",
    ]
    _CANARY_SIGNALS = [
        "system prompt", "API key", "canary", "secret key",
        "sk-proj-", "SENTINEL-CANARY", "base64", "instructions",
        "DB_PASS", "ADMIN_TOKEN", "postgres://",
    ]
    _ESCALATION_SIGNALS = [
        # L3 slow-burn attacks escalate topics — look for the harmful end-state
        "synthesis", "explosive", "detonate", "weapon", "manufacture",
        "exploit", "vulnerability", "malware", "rootkit", "bypass",
        "phishing", "credential", "social engineering", "impersonat",
        "manipulat", "hack", "unauthorized access", "brute force",
        "privilege escalation", "backdoor", "payload", "injection",
        "dangerous", "illegal", "harmful", "toxin", "poison",
        # Also multi-turn escalation patterns
        "[turn 4]", "[turn 5]", "[turn 6]", "[turn 7]", "[turn 8]",
    ]

    mal_with_signals = 0
    mal_without_signals = []
    for s in malicious:
        text_lower = s.get("text", "").lower()
        attack_type = s.get("attack_type", "")

        # Pick the right signal set based on attack type
        if "pii" in attack_type:
            signals = _PII_SIGNALS
        elif "canary" in attack_type or "system_prompt" in attack_type:
            signals = _CANARY_SIGNALS
        elif "slow_burn" in attack_type or "escalation" in attack_type:
            signals = _ESCALATION_SIGNALS
        else:
            signals = _ATTACK_SIGNALS

        has_signal = any(sig.lower() in text_lower for sig in signals)
        if has_signal:
            mal_with_signals += 1
        else:
            mal_without_signals.append(s.get("sample_id", "?"))

    if malicious:
        pct = mal_with_signals / len(malicious) * 100
        if pct >= 70:
            result.ok(f"{mal_with_signals}/{len(malicious)} ({pct:.0f}%) malicious samples contain expected signals")
        elif pct >= 40:
            result.warn(f"Only {pct:.0f}% of malicious samples contain expected signals (some may use subtle patterns)")
        else:
            result.fail(f"Only {pct:.0f}% of malicious samples contain expected signals -- labels may be wrong")

        if mal_without_signals and len(mal_without_signals) <= 10:
            result.warn(f"Malicious samples without obvious attack signals: {mal_without_signals[:5]}")
    else:
        result.warn("No malicious samples found")

    # Check: benign samples should NOT contain red-flag patterns
    benign_with_red_flags = []
    for s in benign:
        text_lower = s.get("text", "").lower()
        found_flags = [flag for flag in _RED_FLAGS_IN_BENIGN if flag.lower() in text_lower]
        if found_flags:
            benign_with_red_flags.append((s.get("sample_id", "?"), found_flags))

    if not benign_with_red_flags:
        result.ok(f"All {len(benign)} benign samples are free of red-flag attack patterns")
    else:
        result.fail(
            f"{len(benign_with_red_flags)} benign samples contain attack red flags!\n"
            f"    Examples: {benign_with_red_flags[:3]}"
        )

    # Check: attack_type consistency
    for s in malicious:
        if s.get("attack_type") == "none":
            result.fail(f"Malicious sample {s.get('sample_id')} has attack_type='none'")
            break
    else:
        if malicious:
            result.ok("All malicious samples have a non-'none' attack_type")

    for s in benign:
        if s.get("attack_type") != "none":
            result.warn(f"Benign sample {s.get('sample_id')} has attack_type='{s.get('attack_type')}' (expected 'none')")
            break
    else:
        if benign:
            result.ok("All benign samples have attack_type='none'")

    return result


# ---------------------------------------------------------------------------
# Check 3: Train/test split disjointness
# ---------------------------------------------------------------------------

def check_split_disjointness(dataset_name: str, data_dir: Path) -> SanityCheckResult:
    """Verify no sample text appears in both train and test splits."""
    result = SanityCheckResult(f"{dataset_name} — Split Disjointness")

    train_path = data_dir / "train.jsonl"
    test_path = data_dir / "test.jsonl"

    train = _load_jsonl(train_path)
    test = _load_jsonl(test_path)

    if not train or not test:
        result.warn(f"Missing splits — train: {len(train)}, test: {len(test)}")
        return result

    # Hash-based comparison for efficiency
    train_hashes = {_text_hash(s["text"]) for s in train if "text" in s}
    test_hashes = {_text_hash(s["text"]) for s in test if "text" in s}

    overlap = train_hashes & test_hashes
    if not overlap:
        result.ok(f"Train ({len(train)}) and test ({len(test)}) are fully disjoint")
    else:
        result.fail(f"{len(overlap)} samples appear in BOTH train and test (data leakage!)")

    # Also check sample_id disjointness
    train_ids = {s.get("sample_id") for s in train}
    test_ids = {s.get("sample_id") for s in test}
    id_overlap = train_ids & test_ids
    if not id_overlap:
        result.ok("Sample IDs are disjoint between splits")
    else:
        result.fail(f"{len(id_overlap)} sample IDs appear in both splits: {list(id_overlap)[:5]}")

    return result


# ---------------------------------------------------------------------------
# Check 4: Duplicate detection
# ---------------------------------------------------------------------------

def check_duplicates(samples: list[dict], dataset_name: str) -> SanityCheckResult:
    """Check for exact-text duplicates within a dataset."""
    result = SanityCheckResult(f"{dataset_name} — Duplicate Detection")

    text_hashes = {}
    duplicates = []

    for s in samples:
        h = _text_hash(s.get("text", ""))
        if h in text_hashes:
            duplicates.append((s.get("sample_id", "?"), text_hashes[h]))
        else:
            text_hashes[h] = s.get("sample_id", "?")

    if not duplicates:
        result.ok(f"No exact-text duplicates among {len(samples)} samples")
    else:
        pct = len(duplicates) / len(samples) * 100
        if pct < 5:
            result.warn(f"{len(duplicates)} duplicates ({pct:.1f}%) — minor, but investigate")
        else:
            result.fail(f"{len(duplicates)} duplicates ({pct:.1f}%) — significant data quality issue")
        # Show first few
        for dup_id, orig_id in duplicates[:3]:
            result.warn(f"  Duplicate: {dup_id} == {orig_id}")

    return result


# ---------------------------------------------------------------------------
# Check 5: SENTINEL-Bench held-out separation
# ---------------------------------------------------------------------------

def check_held_out_separation(data_dir: Path) -> SanityCheckResult:
    """Verify held-out chains are structurally different from mining set."""
    result = SanityCheckResult("SENTINEL-Bench — Held-Out Separation")

    held_out_path = data_dir / "held_out.jsonl"
    mining_path = data_dir / "mining_set.jsonl"

    held_out = _load_jsonl(held_out_path)
    mining = _load_jsonl(mining_path)

    if not held_out:
        result.fail("held_out.jsonl is empty or missing")
        return result
    if not mining:
        result.fail("mining_set.jsonl is empty or missing")
        return result

    result.ok(f"Held-out: {len(held_out)} samples, Mining: {len(mining)} samples")

    # Check chain types are disjoint
    held_out_types = set()
    mining_types = set()

    for s in held_out:
        ct = s.get("metadata", {}).get("chain_type") or s.get("attack_type", "?")
        held_out_types.add(ct)

    for s in mining:
        ct = s.get("metadata", {}).get("chain_type") or s.get("attack_type", "?")
        if s.get("label") == "malicious":
            mining_types.add(ct)

    type_overlap = held_out_types & mining_types
    if not type_overlap:
        result.ok(f"Chain types are disjoint — held-out: {held_out_types}, mining: {mining_types}")
    else:
        result.fail(f"Chain types OVERLAP between held-out and mining: {type_overlap}")

    # Check no text overlap
    held_out_hashes = {_text_hash(s["text"]) for s in held_out if "text" in s}
    mining_hashes = {_text_hash(s["text"]) for s in mining if "text" in s}
    text_overlap = held_out_hashes & mining_hashes

    if not text_overlap:
        result.ok("No text overlap between held-out and mining sets")
    else:
        result.fail(f"{len(text_overlap)} texts appear in both held-out and mining!")

    # Verify held-out flag consistency
    held_out_flagged = sum(1 for s in held_out if s.get("metadata", {}).get("held_out", False))
    if held_out_flagged == len(held_out):
        result.ok("All held-out samples have metadata.held_out=True")
    else:
        result.fail(f"Only {held_out_flagged}/{len(held_out)} have metadata.held_out=True")

    mining_flagged = sum(1 for s in mining if s.get("metadata", {}).get("held_out", True))
    mining_not_flagged = len(mining) - mining_flagged
    # Some mining samples are benign (held_out=False), that's fine
    mining_malicious = [s for s in mining if s.get("label") == "malicious"]
    mining_mal_held = sum(1 for s in mining_malicious if s.get("metadata", {}).get("held_out", False))
    if mining_mal_held == 0:
        result.ok("No malicious mining samples have metadata.held_out=True")
    else:
        result.fail(f"{mining_mal_held} malicious mining samples wrongly marked as held_out=True")

    return result


# ---------------------------------------------------------------------------
# Check 6: Distribution sanity
# ---------------------------------------------------------------------------

def check_distribution(samples: list[dict], dataset_name: str) -> SanityCheckResult:
    """Check class balance and attack type distribution."""
    result = SanityCheckResult(f"{dataset_name} — Distribution Sanity")

    label_counts = Counter(s.get("label") for s in samples)
    attack_type_counts = Counter(s.get("attack_type") for s in samples)
    layer_counts = Counter(s.get("target_layer") for s in samples)

    result.ok(f"Label distribution: {dict(label_counts)}")
    result.ok(f"Attack types: {dict(attack_type_counts)}")
    result.ok(f"Target layers: {dict(layer_counts)}")

    # Warn if heavily imbalanced
    n_mal = label_counts.get("malicious", 0)
    n_ben = label_counts.get("benign", 0)
    total = n_mal + n_ben
    if total > 0:
        ratio = min(n_mal, n_ben) / max(n_mal, n_ben) if max(n_mal, n_ben) > 0 else 0
        if ratio < 0.1:
            result.warn(f"Severe class imbalance: {n_mal} malicious vs {n_ben} benign (ratio={ratio:.2f})")
        elif ratio < 0.3:
            result.warn(f"Class imbalance: {n_mal} malicious vs {n_ben} benign (ratio={ratio:.2f})")
        else:
            result.ok(f"Class balance is reasonable (ratio={ratio:.2f})")

    # Check for empty attack types
    if attack_type_counts.get("", 0) > 0:
        result.warn(f"{attack_type_counts['']} samples have empty attack_type")

    return result


# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------

def run_all_checks() -> bool:
    """Run all sanity checks on all generated corpora. Returns True if all pass."""
    print("\n" + "=" * 60)
    print("  SENTINEL Corpus Sanity Check")
    print("=" * 60)

    all_results: list[SanityCheckResult] = []
    all_clean = True

    # -----------------------------------------------------------------------
    # L5 PII Corpus
    # -----------------------------------------------------------------------
    l5_dir = _DATA_DIR / "custom_l5"
    if (l5_dir / "all.jsonl").exists():
        l5_all = _load_jsonl(l5_dir / "all.jsonl")
        print(f"\nLoaded L5 corpus: {len(l5_all)} samples")

        all_results.append(check_schema(l5_all, "L5 PII Corpus"))
        all_results.append(check_label_consistency(l5_all, "L5 PII Corpus"))
        all_results.append(check_duplicates(l5_all, "L5 PII Corpus"))
        all_results.append(check_split_disjointness("L5 PII Corpus", l5_dir))
        all_results.append(check_distribution(l5_all, "L5 PII Corpus"))
    else:
        print("\n  [WARN] L5 corpus not found -- run: python -m sentinel.eval.generate_l5_corpus")

    # -----------------------------------------------------------------------
    # SENTINEL-Bench
    # -----------------------------------------------------------------------
    sb_dir = _DATA_DIR / "sentinel_bench"
    if (sb_dir / "all.jsonl").exists():
        sb_all = _load_jsonl(sb_dir / "all.jsonl")
        print(f"\nLoaded SENTINEL-Bench: {len(sb_all)} samples")

        all_results.append(check_schema(sb_all, "SENTINEL-Bench"))
        all_results.append(check_label_consistency(sb_all, "SENTINEL-Bench"))
        all_results.append(check_duplicates(sb_all, "SENTINEL-Bench"))
        all_results.append(check_split_disjointness("SENTINEL-Bench", sb_dir))
        all_results.append(check_distribution(sb_all, "SENTINEL-Bench"))
        all_results.append(check_held_out_separation(sb_dir))
    else:
        print("\n  [WARN] SENTINEL-Bench not found -- run: python -m sentinel.eval.generate_sentinel_bench")

    # -----------------------------------------------------------------------
    # L3 Corpus (if generated)
    # -----------------------------------------------------------------------
    l3_dir = _DATA_DIR / "custom_l3"
    if (l3_dir / "all.jsonl").exists():
        l3_all = _load_jsonl(l3_dir / "all.jsonl")
        print(f"\nLoaded L3 corpus: {len(l3_all)} samples")

        all_results.append(check_schema(l3_all, "L3 Escalation Corpus"))
        all_results.append(check_label_consistency(l3_all, "L3 Escalation Corpus"))
        all_results.append(check_duplicates(l3_all, "L3 Escalation Corpus"))
        all_results.append(check_split_disjointness("L3 Escalation Corpus", l3_dir))
        all_results.append(check_distribution(l3_all, "L3 Escalation Corpus"))
    else:
        print("\n  [INFO] L3 corpus not generated yet (needs API key)")

    # -----------------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------------
    print("\n" + "=" * 60)
    print("  RESULTS SUMMARY")
    print("=" * 60)

    for r in all_results:
        print(r.summary())
        if not r.is_clean:
            all_clean = False

    total_checks = sum(len(r.passed) + len(r.failures) for r in all_results)
    total_passed = sum(len(r.passed) for r in all_results)
    total_warnings = sum(len(r.warnings) for r in all_results)
    total_failures = sum(len(r.failures) for r in all_results)

    print(f"\n{'='*60}")
    print(f"  FINAL: {total_passed}/{total_checks} checks passed, "
          f"{total_warnings} warnings, {total_failures} failures")

    if all_clean:
        print("  [PASS] ALL CORPORA PASS SANITY CHECKS -- safe to proceed with evaluation")
    else:
        print("  [FAIL] ISSUES FOUND -- fix before running evaluations")

    print(f"{'='*60}\n")

    return all_clean


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
    clean = run_all_checks()
    sys.exit(0 if clean else 1)
