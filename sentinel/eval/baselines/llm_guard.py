"""
Baseline: LLM Guard (Protect AI).

Open-source multi-scanner LLM security toolkit — the closest
architectural comparison to SENTINEL since it's also a multi-scanner
pipeline rather than a single classifier.

GitHub: https://github.com/protectai/llm-guard
Docs:   https://llm-guard.com

NOTE: LLM Guard must be installed separately:
    pip install llm-guard

Usage:
    from sentinel.eval.baselines.llm_guard import LLMGuardBaseline
    baseline = LLMGuardBaseline()
    result = baseline.predict("ignore previous instructions...")
"""

from __future__ import annotations

import logging
import time

from sentinel.eval.baselines.prompt_guard import BaselineResult

logger = logging.getLogger(__name__)


class LLMGuardBaseline:
    """
    Wrapper around Protect AI's LLM Guard toolkit.

    LLM Guard runs multiple input/output scanners (injection, toxicity,
    PII, etc.) and returns a combined result. We use their input scanners
    to compare against SENTINEL's input-side layers (L1, L2).
    """

    def __init__(self, threshold: float = 0.5, scanners: list[str] | None = None):
        """
        Args:
            threshold: Score threshold for binary classification.
            scanners:  List of scanner names to enable. None = all defaults.
        """
        self.threshold = threshold
        self.scanner_names = scanners
        self._input_scanners = None
        self._vault = None

    def _load(self):
        """Lazy-load LLM Guard scanners."""
        if self._input_scanners is not None:
            return

        try:
            from llm_guard.input_scanners import (
                PromptInjection,
                TokenLimit,
                Toxicity,
            )
            from llm_guard.vault import Vault
        except ImportError:
            raise ImportError(
                "LLM Guard is required for this baseline.\n"
                "Install: pip install llm-guard\n"
                "See: https://llm-guard.com/get_started/installation/"
            )

        logger.info("Loading LLM Guard scanners...")
        self._vault = Vault()

        # Default scanner set — these are the most comparable to SENTINEL
        self._input_scanners = []

        try:
            self._input_scanners.append(PromptInjection(threshold=0.5))
            logger.info("  ✓ PromptInjection scanner loaded")
        except Exception as e:
            logger.warning(f"  ✗ PromptInjection scanner failed: {e}")

        try:
            self._input_scanners.append(Toxicity(threshold=0.5))
            logger.info("  ✓ Toxicity scanner loaded")
        except Exception as e:
            logger.warning(f"  ✗ Toxicity scanner failed: {e}")

        if not self._input_scanners:
            raise RuntimeError("No LLM Guard scanners could be loaded")

        logger.info(f"  Loaded {len(self._input_scanners)} scanners")

    def predict(self, text: str) -> BaselineResult:
        """
        Run LLM Guard input scanners on a single text.

        Returns the highest threat score across all scanners.
        """
        self._load()

        from llm_guard import scan_prompt

        start = time.perf_counter()

        sanitized, results_valid, results_score = scan_prompt(
            self._input_scanners,
            text,
        )

        elapsed_ms = (time.perf_counter() - start) * 1000

        # Aggregate scanner scores. NOTE: this installed version of LLM
        # Guard does NOT return a continuous 0-1 safety score for these
        # scanners the way older docs describe — empirically it returns
        # -1.0 whenever is_valid=True (safe/no risk) and a real value
        # (e.g. 1.0) only when is_valid=False (flagged). Confirmed via
        # live logs: `1.0 - (-1.0) = 2.0` was being produced for every
        # single safe verdict, pushing every benign sample's threat_score
        # miles above threshold -> FPR=1.0 on the full sentinel_bench run
        # (every one of 53 benign samples incorrectly flagged). Use
        # is_valid as the primary signal; only trust `score` as a
        # graded value when it falls in the normal [0, 1] range.
       # Confirmed empirically (see check_llm_guard3.py output): scan_prompt's
        # `score` is NOT a continuous safety probability — it is a fixed
        # +1.0/-1.0 restating `valid` (valid=True -> -1.0, valid=False -> 1.0),
        # for both PromptInjection and Toxicity. The docstring's original
        # assumption ("1.0 = safe, 0.0 = unsafe", a continuous scale) does
        # not match reality, and using `1.0 - score` inverted the signal:
        # a real injection (valid=False, score=1.0) computed threat_score=0.0
        # (looks perfectly safe), producing 0 recall across an entire run.
        # Derive threat_score from `valid` directly instead — it is the only
        # field carrying real signal here.
        scanner_scores = {}
        max_score = 0.0
        for scanner in self._input_scanners:
            scanner_name = type(scanner).__name__
            is_valid = results_valid.get(scanner_name)
            if is_valid is None:
                continue
            threat_score = 0.0 if is_valid else 1.0
            scanner_scores[scanner_name] = {
                "valid": is_valid,
                "raw_score": results_score.get(scanner_name),
                "threat_score": threat_score,
            }
            max_score = max(max_score, threat_score)

        if max_score >= 0.85:
            decision = "BLOCK"
        elif max_score >= 0.5:
            decision = "WARN"
        else:
            decision = "ALLOW"

        return BaselineResult(
            score=max_score,
            label="malicious" if max_score >= self.threshold else "benign",
            decision=decision,
            latency_ms=elapsed_ms,
            system="llm_guard",
            details={
                "scanner_scores": scanner_scores,
                "sanitized_text": sanitized[:200] if sanitized != text else "(unchanged)",
            },
        )
