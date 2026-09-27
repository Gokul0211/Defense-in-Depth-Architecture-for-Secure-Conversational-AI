"""
Baseline: Meta Prompt Guard.

Meta's dedicated prompt-injection / jailbreak classifier.
Most directly comparable to SENTINEL's L1 — both target the same
threat (injection in user input) with a classifier approach.

Model: meta-llama/Prompt-Guard-86M (86M params, fits easily on any GPU)
HuggingFace: https://huggingface.co/meta-llama/Prompt-Guard-86M

Usage:
    from sentinel.eval.baselines.prompt_guard import PromptGuardBaseline
    baseline = PromptGuardBaseline()
    score, label = baseline.predict("ignore previous instructions...")
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class BaselineResult:
    """Standard result from a baseline system."""
    score: float        # 0-1 threat score
    label: str          # "malicious" or "benign"
    decision: str       # "BLOCK", "WARN", "ALLOW"
    latency_ms: float
    system: str
    details: dict = None

    def __post_init__(self):
        if self.details is None:
            self.details = {}


class PromptGuardBaseline:
    """
    Wrapper around Meta's Prompt-Guard-86M model.

    This is a DeBERTa-based classifier fine-tuned specifically for
    detecting prompt injection and jailbreak attempts.
    """

    MODEL_NAME = "meta-llama/Prompt-Guard-86M"

    def __init__(self, device: str = "auto", threshold: float = 0.5):
        self.device = device
        self.threshold = threshold
        self._model = None
        self._tokenizer = None

    def _load(self):
        """Lazy-load the model and tokenizer."""
        if self._model is not None:
            return

        try:
            from transformers import AutoTokenizer, AutoModelForSequenceClassification
            import torch
        except ImportError:
            raise ImportError(
                "Prompt Guard requires 'transformers' and 'torch'.\n"
                "Install: pip install transformers torch"
            )

        logger.info(f"Loading Prompt Guard from {self.MODEL_NAME}...")
        self._tokenizer = AutoTokenizer.from_pretrained(self.MODEL_NAME)
        self._model = AutoModelForSequenceClassification.from_pretrained(self.MODEL_NAME)

        if self.device == "auto":
            import torch
            from sentinel.core.guard_device import classifier_cuda_ok
            self.device = "cuda" if classifier_cuda_ok("promptguard") else "cpu"

        self._model = self._model.to(self.device)
        self._model.eval()
        logger.info(f"  Loaded on {self.device}")

    def predict(self, text: str) -> BaselineResult:
        """
        Run Prompt Guard on a single text input.

        Returns a BaselineResult with:
          - score: probability of injection/jailbreak (0-1)
          - label: "malicious" if score >= threshold, else "benign"
          - decision: "BLOCK"/"WARN"/"ALLOW" based on score
        """
        self._load()
        import torch

        start = time.perf_counter()

        # Share the memo with probs_batch. L2's ingest path scores the same
        # document through layer1_check() (which lands here) and then through
        # document_threat.py (which lands in probs_batch); without a shared cache
        # that is two forward passes over identical text, and Prompt Guard is the
        # most expensive operation in the pipeline.
        cached = self._cached_probs(text)
        if cached is not None and "jailbreak_prob" in cached:
            score = cached["jailbreak_prob"]
            return BaselineResult(
                score=score,
                label="malicious" if score >= self.threshold else "benign",
                decision=("BLOCK" if score >= 0.85
                          else "WARN" if score >= 0.5 else "ALLOW"),
                latency_ms=0.0,
                system="prompt_guard",
                details={k: v for k, v in cached.items() if k != "latency_ms"},
            )

        inputs = self._tokenizer(
            text,
            return_tensors="pt",
            truncation=True,
            max_length=512,
            padding=True,
        ).to(self.device)

        with torch.no_grad():
            outputs = self._model(**inputs)
            probs = torch.softmax(outputs.logits, dim=-1)

        elapsed_ms = (time.perf_counter() - start) * 1000

        # Prompt Guard outputs: [benign, injection, jailbreak]
        #
        # RCA (2026-09-11): the "injection" class is unusable as a threat
        # signal for this kind of standalone-text classification — measured
        # directly against real sentinel_bench samples (n=40, 20/20
        # malicious/benign): injection_prob alone scores AUROC 0.185,
        # *worse than chance* and actively anti-correlated (it fires near
        # 1.0 on plain benign questions like "What is a good recipe for
        # chocolate chip cookies?" and near 0.0 on real injection attempts —
        # inverted, not just noisy). jailbreak_prob alone, by contrast,
        # scores AUROC 0.7825 and cleanly separated every hand-checked
        # example (10/10: 1.000 on real attacks, 0.000 on real benign
        # text). The original `max(injection_prob, jailbreak_prob)`
        # formula diluted the real jailbreak_prob signal down to AUROC
        # 0.6375 by including the broken class in the max. Likely cause:
        # this model's "injection" class was trained/calibrated for
        # detecting instructions embedded within longer retrieved/
        # third-party documents, not for classifying short standalone
        # conversational turns — out of that distribution, it's
        # unreliable. Use jailbreak_prob as the real score; keep
        # injection_prob available in `details` for anyone scanning
        # longer retrieved-document content where it may behave
        # differently, but don't let it dominate the primary score.
        if probs.shape[-1] >= 3:
            injection_prob = float(probs[0, 1])
            jailbreak_prob = float(probs[0, 2])
            score = jailbreak_prob
            details = {
                "injection_prob": injection_prob,
                "jailbreak_prob": jailbreak_prob,
                "benign_prob": float(probs[0, 0]),
            }
        else:
            # Binary output
            score = float(probs[0, 1]) if probs.shape[-1] == 2 else float(probs[0, 0])
            details = {"raw_probs": probs[0].tolist()}

        self._store_probs(text, dict(details, latency_ms=elapsed_ms))

        if score >= 0.85:
            decision = "BLOCK"
        elif score >= 0.5:
            decision = "WARN"
        else:
            decision = "ALLOW"

        return BaselineResult(
            score=score,
            label="malicious" if score >= self.threshold else "benign",
            decision=decision,
            latency_ms=elapsed_ms,
            system="prompt_guard",
            details=details,
        )

    def predict_batch(self, texts: list[str], batch_size: int = 32) -> list[BaselineResult]:
        """Run Prompt Guard on a batch of texts for efficiency."""
        return [
            BaselineResult(
                score=p["jailbreak_prob"] if "jailbreak_prob" in p else p["score"],
                label=("malicious"
                       if (p.get("jailbreak_prob", p.get("score", 0.0)) >= self.threshold)
                       else "benign"),
                decision=("BLOCK" if p.get("jailbreak_prob", p.get("score", 0.0)) >= 0.85
                          else "WARN" if p.get("jailbreak_prob", p.get("score", 0.0)) >= 0.5
                          else "ALLOW"),
                latency_ms=p["latency_ms"],
                system="prompt_guard",
                details={k: v for k, v in p.items()
                         if k not in ("latency_ms", "score")},
            )
            for p in self.probs_batch(texts, batch_size=batch_size)
        ]

    # Bounded memo of whole-text -> class probabilities.
    #
    # WHY. L2's ingest path calls layer1_check(), which runs Prompt Guard on the
    # document, and then scores the SAME document again through
    # document_threat.py. That is two forward passes over identical text -- and
    # Prompt Guard is the single most expensive operation in the pipeline (71 % of
    # L2 ingest wall-clock, profiled). Memoising removes the duplicate outright.
    #
    # Keyed on the exact text, bounded so a long evaluation cannot grow it without
    # limit, and holding only floats.
    _PROBS_CACHE_MAX = 4096

    def _cached_probs(self, text: str):
        cache = getattr(self, "_probs_cache", None)
        if cache is None:
            cache = self._probs_cache = {}
        return cache.get(text)

    def _store_probs(self, text: str, row: dict) -> None:
        cache = getattr(self, "_probs_cache", None)
        if cache is None:
            cache = self._probs_cache = {}
        if len(cache) >= self._PROBS_CACHE_MAX:
            for k in list(cache)[: self._PROBS_CACHE_MAX // 4]:
                cache.pop(k, None)
        cache[text] = row

    def probs_batch(self, texts: list[str], batch_size: int = 32) -> list[dict]:
        """
        All class probabilities for many texts, in ONE forward pass per batch.

        WHY THIS EXISTS. `predict_batch` used to be a batch method in name only --
        it chunked the input and then called `predict()` on each text
        individually, so every call was still a separate tokenisation and a
        separate forward pass. Measured consequence: scoring 28,934 document
        windows was projected at several hours, which made per-window Prompt Guard
        untestable and therefore untested.

        WHY IT RETURNS EVERY CLASS, not just the headline score. `predict()`
        collapses the model's three outputs to `jailbreak_prob`, for a documented
        reason: on SHORT standalone conversational turns the `injection` class
        scores AUROC 0.185 -- inverted, not merely noisy. But that same note says
        the injection class was trained for "instructions embedded within longer
        retrieved/third-party documents" and may behave differently there, which is
        exactly L2's input distribution. Collapsing to one number at the API
        boundary made that hypothesis impossible to test without re-running the
        model. Callers that want the shipped behaviour keep using `predict()`;
        this is for callers that need the full head.
        """
        self._load()
        import torch

        out: list[dict] = []
        pending_idx = [i for i, t in enumerate(texts) if self._cached_probs(t) is None]
        results: dict[int, dict] = {
            i: self._cached_probs(t) for i, t in enumerate(texts)
            if self._cached_probs(t) is not None
        }
        todo = [texts[i] for i in pending_idx]
        for i in range(0, len(todo), batch_size):
            batch = todo[i:i + batch_size]
            start = time.perf_counter()
            inputs = self._tokenizer(
                batch,
                return_tensors="pt",
                truncation=True,
                max_length=512,
                padding=True,
            ).to(self.device)
            with torch.no_grad():
                probs = torch.softmax(self._model(**inputs).logits, dim=-1)
            per_item_ms = (time.perf_counter() - start) * 1000 / max(len(batch), 1)
            p = probs.cpu().numpy()
            batch_out: list[dict] = []
            for row in p:
                if len(row) >= 3:
                    batch_out.append({
                        "benign_prob": float(row[0]),
                        "injection_prob": float(row[1]),
                        "jailbreak_prob": float(row[2]),
                        "latency_ms": per_item_ms,
                    })
                else:
                    batch_out.append({
                        "score": float(row[1]) if len(row) == 2 else float(row[0]),
                        "raw_probs": [float(x) for x in row],
                        "latency_ms": per_item_ms,
                    })
            for text, row_out in zip(batch, batch_out):
                self._store_probs(text, row_out)
            out.extend(batch_out)

        # splice cached and freshly-computed results back into input order
        for slot, row_out in zip(pending_idx, out):
            results[slot] = row_out
        return [results[i] for i in range(len(texts))]
