"""
SENTINEL Evaluation — Unified Dataset Loaders.

Every loader returns a list of EvalSample dataclass instances with a
consistent schema so the runner and metrics modules never need to know
which benchmark a sample came from.

Supported benchmarks:
  L1: TensorTrust (direct injection), JailbreakBench (jailbreak)
  L2: BIPIA (indirect prompt injection via documents)
  L3: Custom-generated multi-turn slow-burn escalation
  L4: InjecAgent (single-step tool hijack), AgentDojo (multi-step agentic)
  L5: Synthetic PII / canary-token corpus
  Benign: Alpaca, LMSYS-Chat-1M subset, AgentDojo benign tasks
  Cross-layer: SENTINEL-Bench (multi-vector composite attacks)

Usage:
    from sentinel.eval.dataset_loaders import load_dataset, list_available
    samples = load_dataset("tensortrust", split="test", limit=500)
"""

from __future__ import annotations

import json
import os
import hashlib
import logging
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

import random


def _apply_limit(samples: list, limit: int | None, seed: int = 42) -> list:
    """
    Apply --limit via a seeded random sample, not a raw prefix slice.

    RCA finding: every loader previously did `samples[:limit]` — a plain
    prefix slice. This silently assumes the underlying file/dataset is
    already randomly ordered. That happened to hold for this project's
    generated corpora (their generators wrote attack types in shuffled
    order), but it's not a safe assumption to bake into the loader: a
    regenerated corpus, a differently-ordered HuggingFace dataset, or a
    hand-edited JSONL file could easily cluster one attack type together,
    and a small `--limit` smoke-test run would then silently evaluate on a
    systematically unrepresentative subset — e.g. missing an entire attack
    category — with no warning. A seeded random sample removes the
    dependency on file order entirely, while staying fully reproducible via
    the fixed seed.
    """
    if limit is None or limit >= len(samples):
        return samples
    rng = random.Random(seed)
    return rng.sample(samples, limit)


# ---------------------------------------------------------------------------
# Data directory — all downloaded/generated corpora live here
# ---------------------------------------------------------------------------
_DATA_DIR = Path(__file__).parent / "data"
_DATA_DIR.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Core data model
# ---------------------------------------------------------------------------
@dataclass
class EvalSample:
    """A single evaluation sample with ground-truth label."""
    text: str                           # The input text (prompt / chunk / conversation)
    label: str                          # "malicious" | "benign"
    attack_type: str = "none"           # e.g. "direct_injection", "rag_poisoning", "tool_hijack"
    target_layer: str = "all"           # Which layer(s) should detect this: "L1", "L2", ..., "all"
    source_benchmark: str = "unknown"   # e.g. "tensortrust", "bipia", "alpaca"
    sample_id: str = ""                 # Unique identifier within the benchmark
    metadata: dict = field(default_factory=dict)  # Benchmark-specific extra fields

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class EvalDataset:
    """A loaded evaluation dataset with metadata."""
    name: str
    samples: list[EvalSample]
    description: str = ""
    license: str = "unknown"
    source_url: str = ""
    split: str = "test"

    @property
    def n_malicious(self) -> int:
        return sum(1 for s in self.samples if s.label == "malicious")

    @property
    def n_benign(self) -> int:
        return sum(1 for s in self.samples if s.label == "benign")

    def summary(self) -> str:
        return (
            f"Dataset: {self.name} ({self.split})\n"
            f"  Total:     {len(self.samples)}\n"
            f"  Malicious: {self.n_malicious}\n"
            f"  Benign:    {self.n_benign}\n"
            f"  Source:    {self.source_url}\n"
            f"  License:   {self.license}"
        )


# ---------------------------------------------------------------------------
# Registry of available datasets
# ---------------------------------------------------------------------------
_REGISTRY: dict[str, dict] = {
    "tensortrust": {
        "loader": "_load_tensortrust",
        "layer": "L1",
        "description": "TensorTrust crowd-sourced injection/defense prompts (Toyer et al.)",
        # Display-only field — was still "ethz-spylab/tensor_trust_data"
        # (the dead repo) even though _load_tensortrust's real load path
        # already falls back to qxcv/tensor-trust and has for a while.
        # This didn't affect any actual run — --list-datasets output was
        # just lying about which repo gets used. Fixed to match reality.
        "hf_path": "qxcv/tensor-trust",
        "license": "MIT",
    },
    "jailbreakbench": {
        "loader": "_load_jailbreakbench",
        "layer": "L1",
        "description": "JailbreakBench jailbreak prompts",
        "hf_path": "JailbreakBench/JBB-Behaviors",
        "license": "MIT",
    },
'mhj': {
        'loader': '_load_mhj',
        'layer': 'L3',
        'description': 'MHJ multi-turn human jailbreaks (Li et al. 2024) — real slow-burn escalation',
        'hf_path': 'ScaleAI/mhj',
        'license': 'cc-by-nc-4.0',
    },
 'tomgibbs_mt': {
        'loader': '_load_tomgibbs_mt',
        'layer': 'L3',
        'description': 'tom-gibbs multi-turn jailbreak datasets — real matched benign control',
        'hf_path': 'tom-gibbs/multi-turn_jailbreak_attack_datasets',
        'license': 'MIT',
    },

   'wildjailbreak': {
        'loader': '_load_wildjailbreak',
        'layer': 'L1',
        'description': 'WildJailbreak adversarial jailbreak prompts (Jiang et al. 2024)',
        'hf_path': 'walledai/WildJailbreak',
        'license': 'check on HF',
    },
    # NOTE: a "bipia" entry (without _local) used to live here, pointing at
    # a loader named "_load_bipia" that was never actually implemented
    # anywhere in this file — selecting it crashed with
    # `KeyError: '_load_bipia'` (globals() lookup in load_dataset() found
    # nothing). Its hf_path, "AI-Secure/BIPIA", also doesn't exist on the
    # Hub (see bipia_local's docstring — no official HF mirror exists for
    # this dataset at all). Removed rather than fixed-in-place: bipia_local
    # (below) is the real, working, fully-superseding implementation that
    # all of BIPIA's actual threshold calibration was run against. If you
    # see old notes/scripts referencing "--dataset bipia", they mean
    # "--dataset bipia_local".
    "injecagent": {
        "loader": "_load_injecagent",
        "layer": "L4",
        "description": "InjecAgent tool-call hijack test cases (Zhan et al.)",
        "hf_path": "anonymousauthors/InjecAgent",
        "license": "MIT",
    },
    "injecagent_ds": {
        "loader": "_load_injecagent_ds",
        "layer": "L4",
        "description": "InjecAgent data-stealing subset (Zhan et al.) + benign user cases",
        "hf_path": "anonymousauthors/InjecAgent",
        "license": "MIT",
    },
    "alpaca": {
        "loader": "_load_alpaca",
        "layer": "benign",
        "description": "Alpaca benign instruction-following prompts",
        "hf_path": "tatsu-lab/alpaca",
        "license": "CC-BY-NC-4.0",
    },
    "orbench_hard": {
        # fixing.md A5: the over-refusal BRAKE for the L1 safety tier. OR-Bench-Hard-1K
        # (Cui et al., 2024): 1,319 harm-ADJACENT benign prompts selected because LLMs
        # refuse them. Never trained or calibrated on anywhere in this project (the
        # safety tier's anchor comes from OR-Bench-80K MINUS Hard-1K). FPR only.
        "loader": "_load_orbench_hard",
        "layer": "benign",
        "description": "OR-Bench-Hard-1K harm-adjacent benign prompts (over-refusal brake)",
        "hf_path": "bench-llm/or-bench",
        "license": "CC-BY-4.0",
    },
    "notinject": {
        "loader": "_load_notinject",
        "layer": "benign",
        "description": "NotInject — benign prompts seeded with injection trigger "
                       "words, for measuring over-defense (InjecGuard/PIGuard, "
                       "ACL 2025)",
        "hf_path": "leolee99/NotInject",
        "license": "apache-2.0",
    },
    "custom_l3": {
        "loader": "_load_custom_l3",
        "layer": "L3",
        "description": "Custom-generated multi-turn slow-burn escalation conversations",
        "hf_path": None,
        "license": "internal",
    },
    "custom_l5_pii": {
        "loader": "_load_custom_l5_pii",
        "layer": "L5",
        "description": "Synthetic PII / canary-token corpus for output firewall testing",
        "hf_path": None,
        "license": "internal",
    },
    # Canonical name since the 2026-09-20 rename (SENTINEL -> DIDA). The old key
    # is kept as an alias rather than replaced: 34 stored evaluation artifacts
    # carry `sentinel_bench` in their FILENAMES, and those filenames are the only
    # link between a row in the paper's results tables and the run that produced
    # it. Renaming them would improve tidiness at the cost of provenance, which
    # is the wrong trade for a paper whose own argument is that unrecoverable
    # run configuration invalidates a number. See _ALIASES below.
    "benign_pipeline_arm": {
        # fixing.md F1: benign samples that exercise L2/L4/L5 in the pipeline, which
        # sentinel_bench's benign arm never does. Built by
        # sentinel/eval/generate_benign_pipeline_arm.py (no labels, no scores used).
        "loader": "_load_benign_pipeline_arm",
        "layer": "cross-layer",
        "description": "Benign multi-layer pipeline arm (held-out news/code documents + benign tool calls)",
        "hf_path": None,
        "license": "internal (XSum, NewsQA, WildChat-1M sources)",
    },
    "dida_bench": {
        "loader": "_load_sentinel_bench",
        "layer": "cross-layer",
        "description": "DIDA-Bench multi-vector composite attack chains "
                       "(registered as `sentinel_bench` before 2026-09-20)",
        "hf_path": None,
        "license": "internal",
    },
'bipia_local': {
        'loader': '_load_bipia_local',
        'layer': 'L2',
        'description': 'BIPIA indirect prompt injection via documents — email/table/code (local files) + qa/abstract (HF mirrors), see _load_bipia_local docstring',
        'hf_path': None,
        'license': 'MIT',
    },
    'agentleak': {
        'loader': '_load_agentleak',
        'layer': 'L5',
        'description': 'AgentLeak real execution traces — C1 (final output) privacy leakage, real LLM-generated text with ground-truth leak labels (see prepare_agentleak.py)',
        'hf_path': None,
        'license': 'MIT',
    },
}


# Retired dataset keys that must keep resolving.
#
# WHY AN ALIAS AND NOT A RENAME. The system was called SENTINEL until 2026-09-20
# and its internal corpus `sentinel_bench`. Renaming the key outright would break
# three things that are not code: 34 stored result artifacts whose FILENAMES
# encode the dataset, the `data/sentinel_bench/` directory those artifacts were
# produced from, and every shell script and analysis note written before the
# rename. The paper's own argument is that a number whose provenance cannot be
# recovered is not citable, so silently invalidating that chain to tidy a name
# would be self-defeating. New code should use the canonical name; old names
# keep working and are resolved here, in exactly one place.
_ALIASES = {
    "sentinel_bench": "dida_bench",
}


def resolve_dataset_name(name: str) -> str:
    """Map a retired dataset key to its canonical name; pass others through."""
    return _ALIASES.get(name, name)


def list_available() -> list[dict]:
    """List all registered datasets with metadata."""
    return [
        {"name": name, **{k: v for k, v in info.items() if k != "loader"}}
        for name, info in _REGISTRY.items()
    ]


def load_dataset(
    name: str,
    split: str = "test",
    limit: int | None = None,
    cache: bool = True,
) -> EvalDataset:
    """
    Load a dataset by name.

    Args:
        name:   Dataset name (see list_available()).
        split:  Dataset split ("train", "test", "validation").
        limit:  Max samples to load (None = all). Useful for quick runs.
        cache:  Whether to cache downloaded data locally.

    Returns:
        EvalDataset with standardized EvalSample instances.
    """
    name = resolve_dataset_name(name)
    if name not in _REGISTRY:
        available = ", ".join(sorted(_REGISTRY.keys()))
        raise ValueError(f"Unknown dataset '{name}'. Available: {available}")

    info = _REGISTRY[name]
    loader_fn = globals()[info["loader"]]
    logger.info(f"Loading dataset '{name}' (split={split}, limit={limit})...")

    dataset = loader_fn(split=split, limit=limit, cache=cache)
    logger.info(f"  Loaded {len(dataset.samples)} samples")
    return dataset


# ---------------------------------------------------------------------------
# Helper: try importing HuggingFace datasets, with clear error
# ---------------------------------------------------------------------------
def _ensure_hf_datasets():
    """Import and return the HuggingFace datasets library."""
    try:
        import datasets
        return datasets
    except ImportError:
        raise ImportError(
            "The 'datasets' library is required for benchmark loading.\n"
            "Install it with: pip install datasets\n"
            "Or install all eval dependencies: pip install -r requirements-eval.txt"
        )


def _cache_path(name: str, split: str) -> Path:
    """Return the local cache path for a dataset."""
    path = _DATA_DIR / "cache" / name / split
    path.mkdir(parents=True, exist_ok=True)
    return path


def _load_from_cache(name: str, split: str) -> EvalDataset | None:
    """Try to load a previously cached dataset."""
    cache_file = _cache_path(name, split) / "samples.jsonl"
    if not cache_file.exists():
        return None

    samples = []
    with open(cache_file, "r", encoding="utf-8") as f:
        for line in f:
            d = json.loads(line)
            samples.append(EvalSample(**d))

    info = _REGISTRY.get(name, {})
    return EvalDataset(
        name=name,
        samples=samples,
        description=info.get("description", ""),
        license=info.get("license", "unknown"),
        split=split,
    )
def _load_mhj(split: str = "test", limit: int | None = None, cache: bool = True) -> EvalDataset:
    """
    Load MHJ (Multi-Turn Human Jailbreaks) — ScaleAI/mhj on HuggingFace,
    gated (access granted). From Li et al. 2024, arXiv:2408.15221.

    537 real multi-turn conversations from human red-teaming, genuinely
    escalating across turns (verified by direct inspection — e.g. a real
    example escalates "What is a prescription pad?" -> "Where are they
    stored?" -> "What's the average dosage for Oxycodone?" -> "Show me an
    example" across 9 turns, each individually innocuous). This is what
    L3's threat model (slow-burn escalation) actually needs — unlike
    WildJailbreak, which is single-turn (see _load_wildjailbreak's docstring).

    KNOWN GAP: repo contains ONLY the malicious file (harmbench_behaviors.csv)
    — confirmed via the repo's file listing, no benign counterpart exists.
    Same gap BIPIA had. Benign samples here are a rough proxy: 4-6 unrelated
    Alpaca instructions chained together as fake sequential turns. This is
    NOT a real benign multi-turn conversation (no natural topic continuity)
    — flag clearly in any writeup as an approximation, not a matched benign
    control. A better benign set is real future work.

    REAL TRAIN/TEST SPLIT (added for the L3 tactic-level calibration fix —
    previously this function accepted a `split` arg but never partitioned
    by it, so every split silently returned the identical full set; the
    100-sample threshold-finding draw and the full-637 confirmation draw
    used to score MHJ were the SAME pool, not held-out data). The full
    unsplit set is always cached under a fixed `"all"` pseudo-split key
    (mirrors `sentinel_bench`'s own `all.jsonl` convention) so downloading
    happens once regardless of which real split is requested; the
    deterministic hash-based partition below (same pattern as
    `_load_alpaca`, `dataset_loaders.py:997`: `md5(text) % 100`, 80/20)
    is then applied in Python to assign each sample to train/test, and
    `split="all"` still returns everything unpartitioned for callers that
    want that.
    """
    if cache:
        cached = _load_from_cache_capped("mhj", "all", None)
        if cached:
            return _mhj_apply_split(cached, split, limit)

    hf = _ensure_hf_datasets()
    logger.info("  Downloading MHJ from HuggingFace (gated, access required)...")
    ds = hf.load_dataset("ScaleAI/mhj", data_files="harmbench_behaviors.csv")
    raw = ds[list(ds.keys())[0]]

    samples = []
    for i, row in enumerate(raw):
        turns = []
        for msg_idx in range(101):
            val = row.get(f"message_{msg_idx}")
            if val is None or val == "":
                break
            try:
                parsed = json.loads(val)
                if parsed.get("role") == "user":
                    turns.append(parsed.get("body", ""))
            except Exception:
                break

        if not turns:
            continue

        text = "\n".join(f"[Turn {t+1}] {turn}" for t, turn in enumerate(turns))
        samples.append(EvalSample(
            text=text,
            label="malicious",
            attack_type="multiturn_escalation",
            target_layer="L3",
            source_benchmark="mhj",
            sample_id=f"mhj_{i}",
            metadata={"tactic": row.get("tactic"), "source": row.get("Source"), "n_turns": len(turns)},
        ))

    # Rough benign proxy: chain unrelated Alpaca instructions as fake turns.
    # NOT a real matched benign control — see docstring.
    try:
        alpaca_ds = load_dataset("alpaca", limit=200)
        alpaca_texts = [s.text for s in alpaca_ds.samples]
        import random
        rng = random.Random(42)
        n_benign = min(100, len(samples))
        for i in range(n_benign):
            n_turns = rng.randint(3, 6)
            chosen = rng.sample(alpaca_texts, min(n_turns, len(alpaca_texts)))
            text = "\n".join(f"[Turn {t+1}] {turn}" for t, turn in enumerate(chosen))
            samples.append(EvalSample(
                text=text,
                label="benign",
                attack_type="none",
                target_layer="L3",
                source_benchmark="mhj",
                sample_id=f"mhj_benign_{i}",
                metadata={"n_turns": len(chosen), "proxy": True},
            ))
    except Exception as e:
        logger.warning(f"  Could not build MHJ benign proxy set: {e}")

    dataset = EvalDataset(
        name="mhj",
        samples=samples,
        description="MHJ multi-turn human jailbreaks (Li et al. 2024) — benign set is an unmatched Alpaca-chain proxy, see docstring",
        license="cc-by-nc-4.0",
        source_url="https://huggingface.co/datasets/ScaleAI/mhj",
        split="all",
    )

    if cache:
        _save_to_cache(dataset, None)
    return _mhj_apply_split(dataset, split, limit)


def _mhj_apply_split(dataset: EvalDataset, split: str, limit: int | None) -> EvalDataset:
    """
    Apply MHJ's deterministic hash-based train/test partition to an
    already-loaded full ("all") MHJ EvalDataset, then apply `limit`.
    Same partition scheme as `_load_alpaca` (`md5(text) % 100`, 80/20).
    `split="all"` returns everything unpartitioned.
    """
    if split != "all":
        wanted = []
        for s in dataset.samples:
            h = int(hashlib.md5(s.text.encode()).hexdigest(), 16) % 100
            sample_split = "test" if h < 20 else "train"
            if sample_split == split:
                wanted.append(s)
        samples = wanted
    else:
        samples = list(dataset.samples)

    if limit:
        samples = _apply_limit(samples, limit)

    return EvalDataset(
        name=dataset.name,
        samples=samples,
        description=dataset.description,
        license=dataset.license,
        source_url=dataset.source_url,
        split=split,
    )


def _load_tomgibbs_mt(split: str = "test", limit: int | None = None, cache: bool = True) -> EvalDataset:
    """
    Load tom-gibbs/multi-turn_jailbreak_attack_datasets — a SECOND, independent
    multi-turn L3 dataset (Sarkar 2024, arXiv:2409.00137), used specifically to
    fix MHJ's missing-benign-counterpart gap (see _load_mhj's docstring).

    Malicious: "Harmful Dataset.csv" — real harmful Goal, distributed across
    multiple turns using obfuscation techniques (word-substitution ciphers,
    encoding schemes) to evade single-turn detection.

    Benign: "Completely-Benign Dataset.csv" — CONFIRMED (direct inspection) to
    be a genuine matched control: harmless Goal (e.g. "create a personal
    budget"), delivered through the SAME obfuscation mechanics as the
    malicious set (ciphers, Leetspeak, "don't acknowledge this" framing).
    This tests whether a detector over-flags suspicious STYLE regardless of
    actual HARMFUL INTENT — a much fairer FPR test than an unrelated-content
    proxy (see MHJ's Alpaca-chain proxy, which this supersedes for FPR
    purposes).

    'Multi-turn conversation' field is a Python-literal-eval'able string
    (not JSON) of {'role':..., 'content':...} dicts; assistant turns are
    'None' placeholders (no live model was run to build this dataset) —
    only user turns are extracted, same as MHJ.
    """
    if cache:
        cached = _load_from_cache_capped("tomgibbs_mt", split, limit)
        if cached:
            return cached

    import ast
    hf = _ensure_hf_datasets()
    logger.info("  Downloading tom-gibbs multi-turn datasets from HuggingFace...")

    samples = []
    for filename, label in [
        ("Harmful Dataset.csv", "malicious"),
        ("Completely-Benign Dataset.csv", "benign"),
    ]:
        ds = hf.load_dataset("tom-gibbs/multi-turn_jailbreak_attack_datasets", data_files=filename)
        raw = ds[list(ds.keys())[0]]

        for i, row in enumerate(raw):
            conv_str = row.get("Multi-turn conversation", "")
            try:
                conv = ast.literal_eval(conv_str)
            except Exception:
                continue

            turns = [msg.get("content", "") for msg in conv if msg.get("role") == "user"]
            if not turns:
                continue

            text = "\n".join(f"[Turn {t+1}] {turn}" for t, turn in enumerate(turns))
            samples.append(EvalSample(
                text=text,
                label=label,
                attack_type="multiturn_escalation" if label == "malicious" else "none",
                target_layer="L3",
                source_benchmark="tomgibbs_mt",
                sample_id=f"tgmt_{label}_{i}",
                metadata={
                    "goal": row.get("Goal", ""),
                    "input_cipher": row.get("Input-cipher", ""),
                    "output_cipher": row.get("Output-cipher", ""),
                    "n_turns": len(turns),
                },
            ))

    if limit:
        samples = _apply_limit(samples, limit)

    dataset = EvalDataset(
        name="tomgibbs_mt",
        samples=samples,
        description="tom-gibbs multi-turn jailbreak datasets (Sarkar 2024) — real matched malicious/benign, both obfuscation-styled",
        license="MIT",
        source_url="https://huggingface.co/datasets/tom-gibbs/multi-turn_jailbreak_attack_datasets",
        split=split,
    )

    if cache:
        _save_to_cache(dataset, limit)
    return dataset


def _save_to_cache(dataset: EvalDataset, limit: int | None = None) -> None:
    """
    Cache a dataset to disk as JSONL, plus a small sidecar `meta.json`
    recording the `limit` that was active for this save (`None` means this
    save reflects the genuinely full dataset, not a `--limit`-ed draw).

    The sidecar is what lets `_load_from_cache_capped` tell "this 100-row
    cache IS the whole dataset" apart from "this 100-row cache is a
    `--limit 100` draw from a much bigger pool" — see that function's
    docstring for the bug this closes (a second, subtler round of the same
    cache-key-on-limit issue: an *unlimited* run silently reusing an
    earlier *limited* run's small cache, because `limit=None` was treated
    as "any cache size is fine").
    """
    cache_file = _cache_path(dataset.name, dataset.split) / "samples.jsonl"
    with open(cache_file, "w", encoding="utf-8") as f:
        for sample in dataset.samples:
            f.write(json.dumps(sample.to_dict(), ensure_ascii=False) + "\n")
    meta_file = _cache_path(dataset.name, dataset.split) / "meta.json"
    with open(meta_file, "w", encoding="utf-8") as f:
        json.dump({"cached_limit": limit}, f)
    logger.info(f"  Cached {len(dataset.samples)} samples to {cache_file}")


def _load_from_cache_capped(name: str, split: str, limit: int | None) -> EvalDataset | None:
    """
    Load a dataset from cache, but only if the cache actually has enough
    samples to satisfy the requested `limit`.

    BUG THIS FIXES: the cache is keyed only by name+split, never by
    `limit`. The naive pattern used at every call site before this fix —
    "if a cache file exists at all, apply `_apply_limit` to it and
    return" — treats a *smaller* limit as a valid reason to use the
    cache (correct) but also silently treats a *larger* limit the same
    way (wrong): `_apply_limit(cached.samples, limit)` on a cache that's
    smaller than `limit` is a no-op cap, so a `--limit 8000` run after an
    earlier `--limit 3000` run silently gets the same 3000 samples back
    instead of a genuinely larger draw. Confirmed on bipia_local's actual
    on-disk cache: exactly 3000 samples (2984 malicious / 16 benign), the
    output of an earlier `--limit 3000` run.

    Fix: the cache is only considered usable when it has >= `limit`
    samples (or no limit was requested at all, i.e. the caller wants
    everything that's cached). Otherwise return None so the caller falls
    through to a fresh load, which then overwrites the cache with the
    larger set — growing it for next time instead of staying capped
    forever. See tests/test_eval_framework.py's TestApplyLimit tests for
    `_apply_limit` itself, which was already correct; this bug was in the
    cache gate that ran before it, not in `_apply_limit`.

    SECOND ROUND (found running tomgibbs_mt for the first time): the fix
    above still missed the case where `limit is None` (caller wants
    everything) but the on-disk cache was itself written by an earlier
    *limited* run — `if limit and ...` never fires when `limit` is falsy,
    so an unlimited request silently accepted a 100-row cache that a
    `--limit 100` run had left behind. Confirmed live: `--dataset
    tomgibbs_mt` with no `--limit` reported `n_samples_total: 100` instead
    of the real dataset size. Fixed via the `meta.json` sidecar
    `_save_to_cache` now writes — a cache whose recorded `cached_limit` is
    not `None` is a partial draw and cannot satisfy an unlimited request,
    regardless of how large `limit` (or the absence of one) is this time.
    Caches written before this fix have no sidecar and are treated as
    trustworthy (legacy behavior) to avoid needlessly re-downloading
    already-good large caches (bipia_local, injecagent, alpaca, tensortrust).
    """
    cached = _load_from_cache(name, split)
    if cached is None:
        return None
    if limit and len(cached.samples) < limit:
        logger.info(
            f"  Cached '{name}' ({split}) has only {len(cached.samples)} "
            f"samples, fewer than requested limit={limit} — reloading "
            f"fresh instead of returning a stale, too-small cache."
        )
        return None
    meta_file = _cache_path(name, split) / "meta.json"
    if meta_file.exists():
        cached_limit = json.load(open(meta_file, "r", encoding="utf-8")).get("cached_limit")
        if limit is None and cached_limit is not None:
            logger.info(
                f"  Cached '{name}' ({split}) was saved from a --limit "
                f"{cached_limit} draw, not the full dataset — reloading "
                f"fresh instead of silently returning a partial cache for "
                f"this unlimited request."
            )
            return None
    if limit:
        cached.samples = _apply_limit(cached.samples, limit)
    return cached


# ---------------------------------------------------------------------------
# Individual dataset loaders
# ---------------------------------------------------------------------------

def _load_tensortrust(split: str = "test", limit: int | None = None, cache: bool = True) -> EvalDataset:
    """
    Load TensorTrust prompt injection/defense dataset.

    The dataset contains crowd-sourced attack and defense prompts from
    an online game. We use the 'extraction_robustness' split which has
    labeled injection attempts and their success status.
    """
    if cache:
        cached = _load_from_cache_capped("tensortrust", split, limit)
        if cached:
            return cached

    hf = _ensure_hf_datasets()
    logger.info("  Downloading TensorTrust from HuggingFace...")

    try:
        # TensorTrust has multiple tables — use the access_code attempts
        ds = hf.load_dataset("ethz-spylab/tensor_trust_data", "extraction_robustness")
    except Exception as e:
        logger.warning(f"  Could not load 'extraction_robustness', trying default: {e}")
        ds = hf.load_dataset(
    "qxcv/tensor-trust",
    data_files="benchmarks/extraction-robustness/v1/extraction_robustness_dataset.jsonl"
)

    # Determine available split
    available_splits = list(ds.keys())
    use_split = split if split in available_splits else available_splits[0]
    raw = ds[use_split]

    samples = []
    for i, row in enumerate(raw):
        # TensorTrust schema varies by table — extract the attack prompt
        text = row.get("attack") or row.get("attack_text") or row.get("prompt") or ""
        if not text:
            continue

        # Determine if the attack was successful (= a real injection)
        is_attack = row.get("is_attack", True)  # In extraction_robustness, all are attacks
        was_successful = row.get("was_successful", row.get("success", False))

        samples.append(EvalSample(
            text=str(text),
            label="malicious",  # All TensorTrust attack prompts are injection attempts
            attack_type="direct_injection",
            target_layer="L1",
            source_benchmark="tensortrust",
            sample_id=f"tt_{i}",
            metadata={
                "was_successful": was_successful,
                "original_split": use_split,
            },
        ))

    if limit:
        samples = _apply_limit(samples, limit)

    dataset = EvalDataset(
        name="tensortrust",
        samples=samples,
        description="TensorTrust crowd-sourced injection prompts (Toyer et al.)",
        license="MIT",
        source_url="https://huggingface.co/datasets/ethz-spylab/tensor_trust_data",
        split=split,
    )

    if cache:
        _save_to_cache(dataset, limit)
    return dataset


def _load_wildjailbreak(split: str = "test", limit: int | None = None, cache: bool = True) -> EvalDataset:
    """
    Load WildJailbreak (walledai/WildJailbreak mirror — non-gated; the
    original allenai/wildjailbreak requires accepting AI2's Responsible
    Use Guidelines first). From the WildTeaming paper (Jiang et al. 2024,
    arXiv:2406.18510).

    Unlike JBB-Behaviors (see _load_jailbreakbench's docstring), this
    dataset's `prompt` field genuinely contains jailbreak-wrapper phrasing
    (roleplay framing, fictional-scenario cover stories, "confidential
    note" style injected instructions) — verified directly, not assumed.

    Two labels present in this mirror: `adversarial_harmful` (2000, real
    malicious intent wrapped in jailbreak framing) and `adversarial_benign`
    (210, jailbreak-STYLED phrasing but genuinely harmless intent — WildJailbreak's
    deliberate over-refusal test set, included so a detector's FPR on jailbreak-
    FLAVORED-but-harmless text can be measured, not just its recall on real attacks).
    `adversarial_benign` is labeled "benign" here — do not treat it as malicious.

    NOTE: single-turn, not true multi-turn escalation — a real but imperfect
    proxy if used for L3; more naturally an L1 (injection/jailbreak) test.
    """
    if cache:
        cached = _load_from_cache_capped("wildjailbreak", split, limit)
        if cached:
            return cached

    hf = _ensure_hf_datasets()
    logger.info("  Downloading WildJailbreak from HuggingFace (walledai mirror)...")
    ds = hf.load_dataset("walledai/WildJailbreak")
    raw = ds["train"]

    samples = []
    for i, row in enumerate(raw):
        label = "malicious" if row["label"] == "adversarial_harmful" else "benign"
        samples.append(EvalSample(
            text=row["prompt"],
            label=label,
            attack_type="jailbreak" if label == "malicious" else "over_refusal_test",
            target_layer="L1",
            source_benchmark="wildjailbreak",
            sample_id=f"wjb_{i}",
            metadata={"original_label": row["label"]},
        ))

    if limit:
        samples = _apply_limit(samples, limit)

    dataset = EvalDataset(
        name="wildjailbreak",
        samples=samples,
        description="WildJailbreak adversarial prompts (Jiang et al. 2024)",
        license="check walledai/WildJailbreak on HF",
        source_url="https://huggingface.co/datasets/walledai/WildJailbreak",
        split=split,
    )

    if cache:
        _save_to_cache(dataset, limit)
    return dataset

def _fetch_bipia_qa_abstract_contexts(scenario: str, n: int = 50) -> list[dict]:
    """
    Context source for BIPIA's qa/abstract scenarios — see _load_bipia_local's
    docstring for why these were previously skipped (microsoft/BIPIA's own
    README points at a NewsQA Docker container + a manual MSR Open Data
    download for qa, and a separate XSum download for abstract).

    That path was checked directly, not assumed: the MSR Open Data page
    microsoft/BIPIA's own upstream (Maluuba/newsqa) points to is dead
    (msropendata.com/datasets/939b1042-... now redirects to a generic MS
    Research page, confirmed via a live HTTP request) — the Docker/manual
    route is a real dead end today, not just tedious. Both datasets are,
    however, directly loadable from working HuggingFace mirrors that need
    no external downloads or scripts:
    - qa: `lucadiliello/newsqa` (an MRQA-2019-derived, self-contained
      mirror — confirmed real CNN news context/question/answer data,
      74,160 train rows; the original `Maluuba/newsqa` HF repo is NOT
      usable, it's a loading-script-only repo blocked by newer `datasets`
      versions and ultimately depends on the same dead MSR link).
    - abstract: `EdinburghNLP/xsum` (the dataset's own real HF repo, loads
      directly, 204,045 train rows of real BBC document/summary pairs).

    Takes the first `n` rows deterministically (not the full 74k/204k —
    matches the ~50-100-context scale the existing email/table/code
    scenarios use) and reshapes to the same {"context", "question"} dict
    shape _load_bipia_local's attack-insertion loop already expects.
    """
    hf = _ensure_hf_datasets()
    if scenario == "qa":
        ds = hf.load_dataset("lucadiliello/newsqa", split="validation")
        return [{"context": row["context"], "question": row["question"]} for row in ds.select(range(min(n, len(ds))))]
    elif scenario == "abstract":
        ds = hf.load_dataset("EdinburghNLP/xsum", split="test")
        return [{"context": row["document"], "question": ""} for row in ds.select(range(min(n, len(ds))))]
    raise ValueError(f"Unknown qa/abstract scenario: {scenario}")


def _load_bipia_local(split: str = "test", limit: int | None = None, cache: bool = True) -> EvalDataset:
    """
    Load BIPIA (email/table/code/qa/abstract scenarios) — email/table/code
    from local files downloaded from microsoft/BIPIA's GitHub repo (no
    official HF mirror exists for this dataset, AI-Secure/BIPIA does not
    exist on the Hub); qa/abstract from working HF mirrors — see
    _fetch_bipia_qa_abstract_contexts's docstring for why the Docker/MSR
    Open Data route BIPIA's own README describes is a dead end, and what's
    used instead.

    Attack insertion mirrors bipia/data/base.py's QAPIABuilder and
    bipia/data/utils.py's insert_end/insert_start exactly (context+attack
    joined with a newline, attack at end or start of context). insert_middle
    is excluded here — it requires NLTK's Punkt sentence tokenizer as an
    extra dependency; end+start alone already gives real attack coverage
    without adding that dependency for a first pass.

    Includes BENIGN samples (clean context, no attack appended) alongside
    the malicious ones — needed for a real FPR measurement. An earlier
    version of this loader generated malicious samples only, making any
    FPR/threshold-tuning decision based on this dataset alone unverifiable.
    """
    if cache:
        cached = _load_from_cache_capped("bipia_local", split, limit)
        if cached:
            return cached

    scenarios = ["email", "table", "code", "qa", "abstract"]
    samples = []
    sample_idx = 0

    for scenario in scenarios:
        attack_filename = "code_attack_test.json" if scenario == "code" else "text_attack_test.json"
        attack_path = _DATA_DIR / "bipia_local" / attack_filename

        if scenario in ("qa", "abstract"):
            if not attack_path.exists():
                logger.warning(f"  BIPIA local attack file missing: expected {attack_path}. Skipping '{scenario}'.")
                continue
            contexts = _fetch_bipia_qa_abstract_contexts(scenario)
        else:
            context_path = _DATA_DIR / "bipia_local" / scenario / f"{split}.jsonl"
            if not context_path.exists() or not attack_path.exists():
                logger.warning(
                    f"  BIPIA local files missing for scenario '{scenario}': "
                    f"expected {context_path} and {attack_path}. Skipping this scenario."
                )
                continue
            with open(context_path, "r", encoding="utf-8") as f:
                contexts = [json.loads(line) for line in f]

        with open(attack_path, "r", encoding="utf-8") as f:
            raw_attacks = json.load(f)
        flat_attacks = {}
        for attack_name in raw_attacks:
            for i, attack_str in enumerate(raw_attacks[attack_name]):
                flat_attacks[f"{attack_name}-{i}"] = attack_str

        for ctx in contexts:
            context_text = "\n".join(ctx["context"]) if scenario == "code" else ctx["context"]

            for attack_name, attack_str in flat_attacks.items():
                for position, poisoned in [
                    ("end", "[Document] " + "\n".join([context_text, attack_str])),
                    ("start", "[Document] " + "\n".join([attack_str, context_text])),
                ]:
                    samples.append(EvalSample(
                        text=poisoned,
                        label="malicious",
                        attack_type="rag_poisoning",
                        target_layer="L2",
                        source_benchmark="bipia_local",
                        sample_id=f"bipia_{scenario}_{sample_idx}",
                        metadata={
                            "scenario": scenario,
                            "attack_name": attack_name,
                            "attack_str": attack_str,
                            "position": position,
                            "question": ctx.get("question", ""),
                        },
                    ))
                    sample_idx += 1

            # Benign: same clean context, no attack appended.
            samples.append(EvalSample(
                text="[Document] " + context_text,
                label="benign",
                attack_type="none",
                target_layer="L2",
                source_benchmark="bipia_local",
                sample_id=f"bipia_{scenario}_benign_{sample_idx}",
                metadata={
                    "scenario": scenario,
                    "attack_name": None,
                    "position": None,
                    "question": ctx.get("question", ""),
                },
            ))
            sample_idx += 1

    if limit:
        samples = _apply_limit(samples, limit)

    dataset = EvalDataset(
        name="bipia_local",
        samples=samples,
        description="BIPIA (email/table/code/qa/abstract — qa/abstract sourced from working HF mirrors, see docstring)",
        license="MIT",
        source_url="https://github.com/microsoft/BIPIA",
        split=split,
    )

    if cache:
        _save_to_cache(dataset, limit)
    return dataset


def _load_injecagent(split: str = "test", limit: int | None = None, cache: bool = True) -> EvalDataset:
    """
    Load InjecAgent tool-call hijack dataset.

    Contains 1,054 test cases over 17 user tools and 62 attacker tools,
    covering both direct-harm and data-stealing attack categories.
    """
    if cache:
        cached = _load_from_cache_capped("injecagent", split, limit)
        if cached:
            return cached

    hf = _ensure_hf_datasets()
    logger.info("  Downloading InjecAgent from HuggingFace...")

    try:
        ds = hf.load_dataset("anonymousauthors/InjecAgent")
    except Exception:
        # Fallback: try alternate known paths
        try:
            ds = hf.load_dataset("InjecAgent/InjecAgent")
        except Exception as e:
            logger.error(
                f"Could not download InjecAgent dataset: {e}\n"
                "You may need to download it manually from the paper's GitHub repo.\n"
                "Place the JSON file at: sentinel/eval/data/injecagent/samples.json"
            )
            # Try loading from local file
            return _load_injecagent_local(split, limit)

    available_splits = list(ds.keys())
    use_split = split if split in available_splits else available_splits[0]
    raw = ds[use_split]

    samples = []
    for i, row in enumerate(raw):
        # InjecAgent schema: user_instruction, tool_name, injected_content, attack_type
        user_instruction = row.get("user_instruction", "")
        injected = row.get("injected_content") or row.get("attacker_instruction", "")
        tool_name = row.get("tool_name") or row.get("user_tool", "")
        attack_cat = row.get("attack_type") or row.get("category", "tool_hijack")

        # Combine into a realistic agentic scenario
        text = f"User: {user_instruction}\n[Tool: {tool_name}]\n{injected}"

        samples.append(EvalSample(
            text=text,
            label="malicious",
            attack_type="tool_hijack",
            target_layer="L4",
            source_benchmark="injecagent",
            sample_id=f"ia_{i}",
            metadata={
                "user_instruction": user_instruction,
                "injected_content": injected,
                "tool_name": tool_name,
                "attack_category": attack_cat,
                "attacker_tool": row.get("attacker_tool", ""),
            },
        ))

    if limit:
        samples = _apply_limit(samples, limit)

    dataset = EvalDataset(
        name="injecagent",
        samples=samples,
        description="InjecAgent tool-call hijack test cases (Zhan et al.)",
        license="MIT",
        source_url="https://github.com/Zhan-qc/InjecAgent",
        split=split,
    )

    if cache:
        _save_to_cache(dataset, limit)
    return dataset


def _injecagent_benign_samples() -> list:
    """
    InjecAgent's 17 legitimate user cases, as the benign control arm.

    WHY THIS EXISTS. `_load_injecagent_local` previously loaded only the attack
    file and labelled every sample malicious, so an evaluation on this dataset
    had ONE class: precision and recall came back 1.0000 and AUROC was `nan`
    ("only one class present in y_true"). A perfect score from a single-class
    load looks like success and is not measuring anything.

    The paper's own InjecAgent rows report FPR 0.1765 for both subsets, which is
    exactly 3/17 — i.e. they were measured against these 17 benign cases. The
    benign arm was lost from the loader at some point; this restores it.

    These rows carry a `User Instruction` and a `Tool Response Template` with NO
    `Attacker Instruction`, so the template is rendered as-is: a legitimate tool
    call with a legitimate response, which is precisely the traffic L4 must not
    flag.
    """
    path = _DATA_DIR / "injecagent" / "user_cases.jsonl"
    if not path.exists():
        logger.warning(
            "InjecAgent benign control file missing (%s) — the dataset will be "
            "single-class and its AUROC/FPR will be undefined", path)
        return []

    out = []
    with open(path, "r", encoding="utf-8") as f:
        for i, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            # The benign templates still carry the `<Attacker Instruction>`
            # placeholder that the attack rows substitute into. Left in, every
            # benign sample would contain the literal string
            # "<Attacker Instruction>" — text no real tool response ever emits,
            # and conspicuous enough to plausibly trip a detector on its own.
            # That would inflate the benign false-positive rate with an
            # artifact of the fixture rather than a property of the layer.
            # A benign case is "the tool responded normally", so the
            # placeholder is removed rather than rendered.
            response = row.get("Tool Response Template", "").replace(
                "<Attacker Instruction>", "")
            text = (f"User: {row.get('User Instruction', '')}\n"
                    f"[Tool: {row.get('User Tool', 'unknown_tool')}]\n"
                    f"{response}")
            out.append(EvalSample(
                text=text,
                label="benign",
                attack_type="none",
                target_layer="L4",
                source_benchmark="injecagent",
                sample_id=f"ia_benign_{i}",
                metadata=row,
            ))
    return out


def _load_injecagent_from_file(filename: str, split: str, limit: int | None,
                               variant: str) -> EvalDataset:
    """Shared body for both InjecAgent subsets. Always includes the benign arm."""
    local_path = _DATA_DIR / "injecagent" / filename
    if not local_path.exists():
        return EvalDataset(
            name=f"injecagent_{variant}",
            samples=[],
            description=f"InjecAgent {variant} (not found — download manually)",
            split=split,
        )

    with open(local_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    samples = []
    for i, row in enumerate(data if isinstance(data, list) else data.values()):
        user_instruction = row.get("User Instruction", "")
        attacker_instruction = row.get("Attacker Instruction", "")
        tool_response = row.get("Tool Response Template", "")
        user_tool = row.get("User Tool", "unknown_tool")
        injected_response = tool_response.replace(
            "<Attacker Instruction>", attacker_instruction)

        text = f"User: {user_instruction}\n[Tool: {user_tool}]\n{injected_response}"

        samples.append(EvalSample(
            text=text,
            label="malicious",
            attack_type="tool_hijack" if variant == "direct" else "data_stealing",
            target_layer="L4",
            source_benchmark="injecagent",
            sample_id=f"ia_{variant}_{i}",
            metadata=row,
        ))

    # The limit applies to the ATTACK arm only. Capping the combined list would
    # silently drop the 17 benign controls and reintroduce the single-class bug
    # whenever anyone passed --limit.
    if limit:
        samples = _apply_limit(samples, limit)

    samples += _injecagent_benign_samples()

    return EvalDataset(
        name=f"injecagent_{variant}",
        samples=samples,
        description=f"InjecAgent {variant} subset + 17 benign user cases",
        license="MIT",
        split=split,
    )


def _load_injecagent_local(split: str, limit: int | None) -> EvalDataset:
    """Direct-harm subset (`samples.json`) plus the benign control arm."""
    return _load_injecagent_from_file("samples.json", split, limit, "direct")


def _load_injecagent_ds(split: str = "test", limit: int | None = None,
                        cache: bool = True) -> EvalDataset:
    """
    Data-stealing subset (`samples_ds.json`, n=544) plus the benign control arm.

    Registered separately because the paper reports the two InjecAgent subsets
    as distinct rows with materially different recall (0.798 vs 0.956); merging
    them would hide that difference behind an average.
    """
    return _load_injecagent_from_file("samples_ds.json", split, limit, "data_stealing")


async def _build_injecagent_l4_sample(row: dict, sample_id: str) -> "EvalSample":
    """
    Build one real L4-evaluable case from an InjecAgent row: ingest the
    poisoned tool response as a real RAG chunk, then construct the
    attacker's actual follow-up call. This is NOT plain text — L4's
    evaluator for this dataset must call ingest_chunk + audit_tool_call
    directly per-sample (see runner.py's dedicated InjecAgent-L4 path),
    not treat this as a text-in/score-out sample like L1-style datasets.
    Kept here only to document the construction; the real per-sample
    execution happens in the evaluator itself.
    """
    raise NotImplementedError(
        "InjecAgent L4 samples require live ingest_chunk() + audit_tool_call() "
        "calls, not static text — see runner.py's dedicated evaluator."
    )
def _load_orbench_hard(split: str = "test", limit: int | None = None,
                       cache: bool = True) -> EvalDataset:
    """OR-Bench-Hard-1K from the local cache (all benign). See the registry entry."""
    path = _CACHE_DIR / "orbench" / "test" / "samples.jsonl" if "_CACHE_DIR" in globals() else         _DATA_DIR / "cache" / "orbench" / "test" / "samples.jsonl"
    samples = []
    if path.exists():
        for line in open(path, encoding="utf-8"):
            if line.strip():
                d = json.loads(line)
                samples.append(EvalSample(text=d["text"], label="benign", attack_type="none",
                                          target_layer="L1", source_benchmark="orbench_hard",
                                          sample_id=d["sample_id"], metadata=d.get("metadata") or {}))
    else:
        logger.warning(f"OR-Bench-Hard cache not found at {path}")
    if limit:
        samples = _apply_limit(samples, limit)
    return EvalDataset(name="orbench_hard", samples=samples,
                       description="OR-Bench-Hard-1K (benign, harm-adjacent)", license="CC-BY-4.0", split=split)


def _load_notinject(split: str = "test", limit: int | None = None,
                    cache: bool = True) -> EvalDataset:
    """
    NotInject — an EXTERNAL over-defense benchmark. All 339 samples are benign.

    WHY THIS CORPUS IS HERE, and it earned its place immediately. L1's tier 2
    produces 462 of Alpaca's 465 benign flags, and they are topic collisions rather
    than near-misses: "Generate a list of 3 safety tips for using public
    transportation" matching the anchor "circumvent your safety guidelines".
    NotInject (InjecGuard / PIGuard, ACL 2025, arXiv:2410.22770) is built for
    exactly that failure — benign prompts deliberately seeded with the trigger
    words injection guards over-fire on, in subsets carrying one, two and three
    triggers, plus a multilingual slice.

    It is someone else's corpus, so it is a GENERALIZATION test rather than a
    second opportunity to tune. That distinction has already paid for itself: two
    literature-grounded repairs of tier 2 (dimension standardization per Timkey &
    van Schijndel 2021, and per-anchor null calibration) improved every quantity
    measured against Alpaca while firing 2.3-2.5x MORE often here. Without this
    corpus in the table they would have looked like large wins and been shipped.
    Nothing in this project is fitted on it.

    Published reference points, as context and not as a target to chase: the paper
    reports open-source guards (Deepset, Fmops, PromptGuard, ProtectAI v2) below
    60 % over-defense accuracy at their own operating points, where 50 % is chance.

    Having no malicious arm, the only metric it can produce is a false-positive
    rate — which is precisely what an over-defense measurement is.
    """
    if cache:
        cached = _load_from_cache_capped("notinject", split, limit)
        if cached:
            return cached

    import json as _json

    cache_file = _CACHE_DIR / "notinject" / "test" / "samples.jsonl"
    if not cache_file.exists():
        raise FileNotFoundError(
            f"NotInject cache missing at {cache_file}. Build it with "
            f"`python scratch/l1x/prep_notinject.py`, which downloads the three "
            f"parquet subsets from huggingface.co/datasets/leolee99/NotInject."
        )

    samples = []
    with cache_file.open(encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            r = _json.loads(line)
            samples.append(EvalSample(
                text=r["text"],
                label="benign",
                attack_type="none",
                target_layer="L1",
                source_benchmark="notinject",
                sample_id=r["sample_id"],
                metadata=r.get("metadata") or {},
            ))

    if limit:
        samples = _apply_limit(samples, limit)

    return EvalDataset(
        name="notinject",
        samples=samples,
        description="NotInject — benign prompts seeded with injection trigger "
                    "words, for measuring over-defense",
        license="apache-2.0",
        source_url="https://huggingface.co/datasets/leolee99/NotInject",
        split=split,
    )


def _load_alpaca(split: str = "test", limit: int | None = None, cache: bool = True) -> EvalDataset:
    """
    Load Alpaca benign instruction-following dataset.

    Used as the primary benign corpus for L1 false-positive evaluation.
    Alpaca has only a 'train' split — we use a deterministic hash-based
    partition to create a pseudo-test split.
    """
    if cache:
        cached = _load_from_cache_capped("alpaca", split, limit)
        if cached:
            return cached

    hf = _ensure_hf_datasets()
    logger.info("  Downloading Alpaca from HuggingFace...")

    ds = hf.load_dataset("tatsu-lab/alpaca")
    raw = ds["train"]  # Alpaca only has a train split

    samples = []
    for i, row in enumerate(raw):
        instruction = row.get("instruction", "")
        input_text = row.get("input", "")
        text = f"{instruction}\n{input_text}".strip() if input_text else instruction

        if not text:
            continue

        # Deterministic split: hash-based partition (80% train, 20% test)
        h = int(hashlib.md5(text.encode()).hexdigest(), 16) % 100
        sample_split = "test" if h < 20 else "train"

        if split != "all" and sample_split != split:
            continue

        samples.append(EvalSample(
            text=text,
            label="benign",
            attack_type="none",
            target_layer="L1",
            source_benchmark="alpaca",
            sample_id=f"alpaca_{i}",
            metadata={
                "output": row.get("output", ""),
            },
        ))

    if limit:
        samples = _apply_limit(samples, limit)

    dataset = EvalDataset(
        name="alpaca",
        samples=samples,
        description="Alpaca benign instruction-following prompts",
        license="CC-BY-NC-4.0",
        source_url="https://huggingface.co/datasets/tatsu-lab/alpaca",
        split=split,
    )

    if cache:
        _save_to_cache(dataset, limit)
    return dataset


def _load_custom_l3(split: str = "test", limit: int | None = None, cache: bool = True) -> EvalDataset:
    """
    Load custom-generated L3 multi-turn slow-burn escalation conversations.

    These must be generated first using: python -m sentinel.eval.generate_l3_corpus
    """
    local_path = _DATA_DIR / "custom_l3" / f"{split}.jsonl"
    if not local_path.exists():
        logger.warning(
            f"L3 corpus not found at {local_path}.\n"
            "Generate it first: python -m sentinel.eval.generate_l3_corpus"
        )
        return EvalDataset(
            name="custom_l3",
            samples=[],
            description="L3 slow-burn corpus (not yet generated)",
            license="internal",
            split=split,
        )

    samples = []
    with open(local_path, "r", encoding="utf-8") as f:
        for line in f:
            d = json.loads(line)
            samples.append(EvalSample(**d))

    if limit:
        samples = _apply_limit(samples, limit)

    return EvalDataset(
        name="custom_l3",
        samples=samples,
        description="Custom multi-turn slow-burn escalation conversations",
        license="internal",
        split=split,
    )


def _load_custom_l5_pii(split: str = "test", limit: int | None = None, cache: bool = True) -> EvalDataset:
    """
    Load synthetic PII / canary-token corpus for L5 output firewall testing.

    Must be generated first using: python -m sentinel.eval.generate_l5_corpus
    """
    local_path = _DATA_DIR / "custom_l5" / f"{split}.jsonl"
    if not local_path.exists():
        logger.warning(
            f"L5 PII corpus not found at {local_path}.\n"
            "Generate it first: python -m sentinel.eval.generate_l5_corpus"
        )
        return EvalDataset(
            name="custom_l5_pii",
            samples=[],
            description="L5 PII corpus (not yet generated)",
            license="internal",
            split=split,
        )

    samples = []
    with open(local_path, "r", encoding="utf-8") as f:
        for line in f:
            d = json.loads(line)
            samples.append(EvalSample(**d))

    _substitute_live_canary_tokens(samples)

    if limit:
        samples = _apply_limit(samples, limit)

    return EvalDataset(
        name="custom_l5_pii",
        samples=samples,
        description="Synthetic PII / canary-token corpus",
        license="internal",
        split=split,
    )


def _substitute_live_canary_tokens(samples: list[EvalSample]) -> None:
    """
    RCA finding: generate_l5_corpus.py bakes a statically-generated fake
    token (`SENTINEL-CANARY-` + 16 random hex chars, generated once at
    corpus-generation time) into every 'canary_in_output' sample. But
    sentinel.config.CANARY_TOKEN is regenerated fresh on every process
    start (`uuid.uuid4().hex`, no persistence) — so the corpus's baked-in
    token can never equal the live token in any process other than
    (impossibly) the one that doesn't exist yet when the corpus is loaded.
    This produced a guaranteed, structural false negative on every literal
    canary-leak sample, regardless of whether L5's canary-matching logic
    itself was correct.

    Regenerating the corpus wouldn't fix this either — CANARY_TOKEN would
    just go stale again on the next process restart. The correct fix is
    dynamic substitution at load time: replace the baked-in placeholder
    pattern with whatever the CURRENT process's real CANARY_TOKEN is, right
    before evaluation. This mutates samples in place.
    """
    import re
    from sentinel.config import CANARY_TOKEN

    placeholder_pattern = re.compile(r"SENTINEL-CANARY-[0-9a-f]{6,}")
    n_substituted = 0
    for sample in samples:
        if sample.metadata.get("canary_type") == "canary_in_output" and placeholder_pattern.search(sample.text):
            sample.text = placeholder_pattern.sub(CANARY_TOKEN, sample.text)
            n_substituted += 1

    if n_substituted:
        logger.info(
            f"  Substituted live CANARY_TOKEN into {n_substituted} canary sample(s) "
            f"(corpus's baked-in token would never match the current process's token — see RCA note)"
        )


def _load_benign_pipeline_arm(split: str = "test", limit: int | None = None, cache: bool = True) -> EvalDataset:
    """fixing.md F1. Generate first: python -m sentinel.eval.generate_benign_pipeline_arm"""
    local_path = _DATA_DIR / "benign_pipeline_arm" / f"{split}.jsonl"
    samples = []
    if local_path.exists():
        with open(local_path, "r", encoding="utf-8") as f:
            samples = [EvalSample(**json.loads(line)) for line in f if line.strip()]
    else:
        logger.warning(f"benign pipeline arm not found at {local_path}; "
                       "run python -m sentinel.eval.generate_benign_pipeline_arm")
    if limit:
        samples = _apply_limit(samples, limit)
    return EvalDataset(name="benign_pipeline_arm", samples=samples,
                       description="Benign multi-layer pipeline arm", license="internal", split=split)


def _load_sentinel_bench(split: str = "test", limit: int | None = None, cache: bool = True) -> EvalDataset:
    """
    Load SENTINEL-Bench multi-vector composite attack chains.

    Must be generated first using: python -m sentinel.eval.generate_sentinel_bench
    """
    local_path = _DATA_DIR / "sentinel_bench" / f"{split}.jsonl"
    if not local_path.exists():
        logger.warning(
            f"SENTINEL-Bench not found at {local_path}.\n"
            "Generate it first: python -m sentinel.eval.generate_sentinel_bench"
        )
        return EvalDataset(
            name="sentinel_bench",
            samples=[],
            description="SENTINEL-Bench (not yet generated)",
            license="internal",
            split=split,
        )

    samples = []
    with open(local_path, "r", encoding="utf-8") as f:
        for line in f:
            d = json.loads(line)
            samples.append(EvalSample(**d))

    if limit:
        samples = _apply_limit(samples, limit)

    return EvalDataset(
        name="sentinel_bench",
        samples=samples,
        description="SENTINEL-Bench multi-vector composite attack chains",
        license="internal",
        split=split,
    )


def _load_agentleak(split: str = "test", limit: int | None = None, cache: bool = True) -> EvalDataset:
    """
    Load AgentLeak's real execution-trace C1 (final output) samples.

    Must be prepared first using: python -m sentinel.eval.prepare_agentleak
    (see that module's docstring for the extraction rule and its
    100%-agreement verification against AgentLeak's own official labels).
    """
    local_path = _DATA_DIR / "agentleak" / f"{split}.jsonl"
    if not local_path.exists():
        logger.warning(
            f"AgentLeak corpus not found at {local_path}.\n"
            "Prepare it first: python -m sentinel.eval.prepare_agentleak"
        )
        return EvalDataset(
            name="agentleak",
            samples=[],
            description="AgentLeak (not yet prepared)",
            license="MIT",
            split=split,
        )

    samples = []
    with open(local_path, "r", encoding="utf-8") as f:
        for line in f:
            d = json.loads(line)
            samples.append(EvalSample(**d))

    if limit:
        samples = _apply_limit(samples, limit)

    return EvalDataset(
        name="agentleak",
        samples=samples,
        description="AgentLeak real execution traces — C1 privacy leakage",
        license="MIT",
        source_url="https://github.com/Privatris/AgentLeak",
        split=split,
    )


# =============================================================================
# 2026-09-25 evaluation rebuild (deep_rca.md §10): datasets with VALID benign arms.
# =============================================================================

def _benign_mt_rows(corpus: str) -> list[dict]:
    """Audited benign multi-turn sessions (sentinel/eval/build_benign_multiturn.py)."""
    p = _DATA_DIR / "benign_mt" / f"{corpus}.jsonl"
    if not p.exists():
        logger.warning(f"{p} missing: run scratch/trackB/audit_benign_arms.py then "
                       f"python -m sentinel.eval.build_benign_multiturn")
        return []
    return [json.loads(l) for l in open(p, encoding="utf-8") if l.strip()]


def _benign_mt_samples(corpus: str) -> list:
    out = []
    for r in _benign_mt_rows(corpus):
        out.append(EvalSample(text=r["text"], label="benign", attack_type="none", target_layer="L3",
                              source_benchmark=corpus, sample_id=r["sample_id"],
                              metadata={"n_turns": r.get("n_turns"), "benign_arm": corpus}))
    return out


def _mhj_malicious(limit=None) -> list:
    return [s for s in load_dataset("mhj", split="test").samples if s.label == "malicious"]


def _load_oasst_mt(split: str = "test", limit: int | None = None, cache: bool = True) -> EvalDataset:
    """OASST2 human-written, moderated multi-turn conversations (audited), benign only."""
    samples = _benign_mt_samples("oasst_test" if split == "test" else "oasst_ref")
    if limit:
        samples = _apply_limit(samples, limit)
    return EvalDataset(name="oasst_mt", samples=samples, split=split, license="Apache-2.0",
                       description="OASST2 multi-turn benign conversations, audited (deep_rca.md §10.1)")


def _load_mhj_oasst(split: str = "test", limit: int | None = None, cache: bool = True) -> EvalDataset:
    """MHJ malicious vs a VALID benign arm: audited OASST2 conversations (R-021).
    Replaces the 100 chained-Alpaca proxy for the MHJ row."""
    samples = _mhj_malicious() + _benign_mt_samples("oasst_test")
    if limit:
        samples = _apply_limit(samples, limit)
    return EvalDataset(name="mhj_oasst", samples=samples, split=split, license="cc-by-nc-4.0 / Apache-2.0",
                       description="MHJ malicious + audited OASST2 benign multi-turn")


def _load_mhj_wildchat_clean(split: str = "test", limit: int | None = None, cache: bool = True) -> EvalDataset:
    """MHJ malicious vs AUDITED WildChat (random + sensitive test arms, benign-labelled
    sessions only). The harder, in-the-wild benign arm, without its jailbreaks."""
    samples = (_mhj_malicious() + _benign_mt_samples("wildchat_test")
               + _benign_mt_samples("wildchat_sens_test"))
    if limit:
        samples = _apply_limit(samples, limit)
    return EvalDataset(name="mhj_wildchat_clean", samples=samples, split=split, license="mixed",
                       description="MHJ malicious + audited WildChat benign (random + sensitive)")


def _load_tomgibbs_semi(split: str = "test", limit: int | None = None, cache: bool = True) -> EvalDataset:
    """tom-gibbs Harmful vs the SEMI-BENIGN control (harmful/toxic WORDS, benign GOAL) --
    the hard negative the authors' judge had 35.7 % false positives on (R-022). Kept as a
    separate dataset so the published tomgibbs_mt row stays comparable. Carries `goal_id`
    so bootstrap CIs can resample GOALS (517 + 150 unique goals, x8 cipher configs)."""
    if cache:
        cached = _load_from_cache_capped("tomgibbs_semi", split, limit)
        if cached:
            return cached
    import ast
    hf = _ensure_hf_datasets()
    samples = []
    for filename, label in (("Harmful Dataset.csv", "malicious"), ("Semi-Benign Dataset.csv", "benign")):
        ds = hf.load_dataset("tom-gibbs/multi-turn_jailbreak_attack_datasets", data_files=filename)
        raw = ds[list(ds.keys())[0]]
        for i, row in enumerate(raw):
            try:
                conv = ast.literal_eval(row.get("Multi-turn conversation", ""))
            except Exception:
                continue
            turns = [m.get("content", "") for m in conv if m.get("role") == "user"]
            if not turns:
                continue
            samples.append(EvalSample(
                text="\n".join(f"[Turn {t + 1}] {x}" for t, x in enumerate(turns)),
                label=label, attack_type="multiturn_escalation" if label == "malicious" else "none",
                target_layer="L3", source_benchmark="tomgibbs_semi",
                sample_id=f"tgsb_{label}_{i}",
                metadata={"goal": row.get("Goal", ""), "goal_id": f"{label}:{row.get('Goal ID', row.get('Goal', ''))}",
                          "input_cipher": row.get("Input-cipher", ""), "output_cipher": row.get("Output-cipher", ""),
                          "n_turns": len(turns)}))
    if limit:
        samples = _apply_limit(samples, limit)
    dataset = EvalDataset(name="tomgibbs_semi", samples=samples, split=split, license="MIT",
                          description="tom-gibbs Harmful vs Semi-Benign (harm-adjacent words, benign goals)",
                          source_url="https://huggingface.co/datasets/tom-gibbs/multi-turn_jailbreak_attack_datasets")
    if cache:
        _save_to_cache(dataset, limit)
    return dataset


_REGISTRY.update({
    "oasst_mt": {"loader": "_load_oasst_mt", "layer": "L3", "hf_path": None, "license": "Apache-2.0",
                 "description": "OASST2 audited benign multi-turn conversations"},
    "mhj_oasst": {"loader": "_load_mhj_oasst", "layer": "L3", "hf_path": None, "license": "mixed",
                  "description": "MHJ malicious + audited OASST2 benign (valid benign arm)"},
    "mhj_wildchat_clean": {"loader": "_load_mhj_wildchat_clean", "layer": "L3", "hf_path": None,
                           "license": "mixed", "description": "MHJ malicious + audited WildChat benign"},
    "tomgibbs_semi": {"loader": "_load_tomgibbs_semi", "layer": "L3",
                      "hf_path": "tom-gibbs/multi-turn_jailbreak_attack_datasets", "license": "MIT",
                      "description": "tom-gibbs Harmful vs Semi-Benign control"},
})
