"""
Append-only results ledger — one line per real evaluation run.

WHY THIS EXISTS
------------------
No git repo exists in this project, so "which commit produced this number"
isn't answerable the normal way. This gives an honest substitute: hash the
exact source files whose logic affects a run, plus the exact dataset cache
file used, so any cited number can be traced back to precisely what code
and data produced it — without pretending a VCS exists.

Usage: call `append_entry(...)` at the end of any real eval run. Every
field is required except `notes` and `seed`.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

_LEDGER_PATH = Path(__file__).parent / "results" / "LEDGER.jsonl"


def hash_file(path: str | Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()[:16]


def append_entry(
    experiment_id: str,
    phase: str,
    code_files: list[str],
    dataset_cache_file: str,
    split: str,
    thresholds_used: dict,
    metrics: dict,
    result_file: str,
    runtime_seconds: float,
    model_versions: dict | None = None,
    seed: int | None = None,
    notes: str = "",
) -> None:
    entry = {
        "experiment_id": experiment_id,
        "phase": phase,
        "code_files_hash": {f: hash_file(f) for f in code_files},
        # `Path("").exists()` is TRUE — it resolves to the current
        # directory — so an empty dataset path used to send `hash_file`
        # off to read a directory and raise PermissionError. Caught in
        # practice the first time the runner self-logged a mode that does
        # not name a cache file. The emptiness check has to come first.
        "dataset_cache_hash": (
            hash_file(dataset_cache_file)
            if dataset_cache_file and Path(dataset_cache_file).is_file()
            else None
        ),
        "split": split,
        "thresholds_used": thresholds_used,
        "model_versions": model_versions or {},
        "seed": seed,
        "metrics": metrics,
        "runtime_seconds": runtime_seconds,
        "result_file": result_file,
        "notes": notes,
        "logged_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    _LEDGER_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(_LEDGER_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def safe_append_entry(**kwargs) -> bool:
    """
    `append_entry` that cannot destroy the run it is recording.

    Ledger writes happen at the END of an evaluation, after minutes of real
    layer inference. A raised exception there — a non-serialisable metric, a
    missing code file after a rename, a locked file — would discard the
    entire run's work for the sake of its bookkeeping. That trade is never
    worth taking, so failures are logged loudly and swallowed.

    Returns True if the entry was written.

    The failure IS visible: the caller prints the warning, and a run whose
    result JSON exists with no matching ledger line is detectable by
    comparing the two. Silent-but-detectable beats loud-and-destructive.
    """
    try:
        append_entry(**kwargs)
        return True
    except Exception as exc:  # noqa: BLE001 - deliberately broad, see docstring
        import logging

        logging.getLogger(__name__).warning(
            "results-ledger write FAILED for experiment_id=%r (%s: %s). "
            "The run's own result file is unaffected; re-log it manually.",
            kwargs.get("experiment_id"), type(exc).__name__, exc,
        )
        return False


def code_files_for(*paths: str) -> list[str]:
    """
    Keep only paths that currently exist.

    `append_entry` hashes every file it is given, so one stale path after a
    rename turns every subsequent run's logging into a hard failure. The
    dropped paths are the caller's problem to notice, not a reason to lose
    a run.
    """
    return [p for p in paths if Path(p).exists()]
