"""
Two external prompt-injection guards, as Tier-3 candidates and as baselines.

WHY THESE TWO, AND WHY NOW. L1's Tier 3 is Prompt-Guard-86M. Measured on NotInject
(`scratch/l1x/LEDGER.md` EXP-006), the benign samples L1 cannot stop flagging no
matter how high the threshold goes are **8 of 339, every one of them Tier 3** --
Prompt Guard saturating at ~1.000 on benign text that merely *mentions* attack
vocabulary ("When writing secure CODE, what rules MUST never be Disregarded?").
Raising `L1_WARN_THRESHOLD` cannot fix that; only changing Tier 3 can.

  PIGuard (formerly InjecGuard) -- Li et al., ACL 2025, arXiv:2410.22770. Trained
      with "Mitigating Over-defense for Free", a strategy aimed precisely at the
      trigger-word bias above. MIT licensed.
  ProtectAI deberta-v3-base-prompt-injection-v2 -- the most widely deployed open
      injection classifier (800k+ monthly downloads), included as the incumbent
      practitioners actually reach for. Apache-2.0.

A FAIRNESS CAVEAT THAT MUST TRAVEL WITH ANY NOTINJECT NUMBER. NotInject was built
by PIGuard's own authors, as the benchmark their training strategy targets. PIGuard
scoring well on it is close to an in-distribution result and must not be read as
independent validation. Their relative standing on **our** corpora -- bipia_local,
sentinel_bench, TensorTrust, WildJailbreak -- carries the evidential weight, and the
InjecGuard paper's own numbers are reported separately in results.md as third-party
claims rather than as measurements taken here.

NO REMOTE CODE IS EXECUTED. PIGuard ships `modeling_piguard.py` and its config sets
`auto_map`, so `AutoModelForSequenceClassification` demands
`trust_remote_code=True` -- i.e. running arbitrary Python from a model repo. The
file was READ rather than run: it imports only transformers/torch and performs no
I/O, network, subprocess or eval. Its architecture is reimplemented below from that
source, and the custom module is never fetched or imported.

THE DETAIL THAT MATTERS, and it was caught by disbelieving a plausible number.
Loading PIGuard's weights into the stock `DebertaV2ForSequenceClassification`
"succeeds" -- every key maps, nothing is missing or unexpected -- and produces
probabilities compressed into 0.46-0.60 on inputs that should be trivially
separable. The cause is that PIGuard's forward **bypasses the pooler**:

    pooled = outputs.last_hidden_state[:, 0, :]     # raw CLS hidden state
    logits = self.classifier(pooled)

while the stock class inserts `ContextPooler` (dense + activation) and dropout
before the classifier. The checkpoint carries `pooler.dense.*` weights that
inference never uses, so a clean-looking state-dict load silently runs the wrong
graph. `_HEAD_CLS_DIRECT` below reproduces the real forward; a comparison built on
the stock path would have reported a fabricated baseline.
"""

from __future__ import annotations

import logging
import time

from sentinel.eval.baselines.prompt_guard import BaselineResult

logger = logging.getLogger(__name__)


# How a checkpoint gets from encoder output to logits. These are not
# interchangeable -- see the module docstring.
_HEAD_STOCK = "stock"          # ContextPooler -> dropout -> classifier
_HEAD_CLS_DIRECT = "cls"       # last_hidden_state[:, 0, :] -> classifier


class _DebertaGuard:
    """Shared loader/scorer for single-logit-pair DeBERTa injection classifiers."""

    model_id: str = ""
    system: str = ""
    #: index of the logit meaning "this is an injection"
    injection_index: int = 1
    head: str = _HEAD_STOCK

    def __init__(self, device: str = "auto", threshold: float = 0.5):
        self.device = device
        self.threshold = threshold
        self._model = None
        self._tokenizer = None
        self._head = None

    def _load(self):
        if self._model is not None:
            return
        import torch
        from transformers import (AutoTokenizer, DebertaV2Config,
                                  DebertaV2ForSequenceClassification)

        logger.info(f"Loading {self.system} from {self.model_id}...")
        self._tokenizer = AutoTokenizer.from_pretrained(self.model_id)

        cfg = DebertaV2Config.from_pretrained(self.model_id)
        # Drop the pointer to the repo's custom module so nothing can route back
        # to it; the architecture below is the stock one.
        for attr in ("auto_map", "architectures"):
            if hasattr(cfg, attr):
                setattr(cfg, attr, None)
        cfg.model_type = "deberta-v2"

        from huggingface_hub import hf_hub_download
        from safetensors.torch import load_file
        sd = load_file(hf_hub_download(self.model_id, "model.safetensors"))

        if self.head == _HEAD_CLS_DIRECT:
            # PIGuard's real graph: base encoder, take the CLS hidden state, one
            # linear layer. No pooler, no dropout. Reimplemented from the repo's
            # `modeling_piguard.py`, which was read and not executed.
            from transformers import DebertaV2Model
            base = DebertaV2Model(cfg)
            enc_sd = {k[len("deberta."):]: v for k, v in sd.items()
                      if k.startswith("deberta.")}
            missing, unexpected = base.load_state_dict(enc_sd, strict=False)
            blocking = [k for k in missing if not k.endswith("position_ids")]
            if blocking or unexpected:
                raise RuntimeError(
                    f"{self.system}: encoder weights do not map. "
                    f"missing={blocking[:6]} unexpected={list(unexpected)[:6]}")
            head = torch.nn.Linear(cfg.hidden_size, cfg.num_labels)
            head.load_state_dict({"weight": sd["classifier.weight"],
                                  "bias": sd["classifier.bias"]})
            base.eval(); head.eval()
            self._head = head
            model = base
        else:
            model = DebertaV2ForSequenceClassification(cfg)
            missing, unexpected = model.load_state_dict(sd, strict=False)
            # A silent mismatch here would produce a randomly-initialised head
            # and a plausible-looking but meaningless AUROC -- refuse instead.
            blocking = [k for k in missing
                        if not k.endswith(("position_ids",
                                           "position_embeddings.weight"))]
            if blocking or unexpected:
                raise RuntimeError(
                    f"{self.system}: weights do not map onto the stock DeBERTa "
                    f"classifier. missing={blocking[:6]} "
                    f"unexpected={list(unexpected)[:6]}. "
                    f"Refusing to score with a partially-initialised model.")
            self._head = None
            model.eval()
        from sentinel.core.guard_device import classifier_cuda_ok
        if self.device != "cpu" and classifier_cuda_ok(self.system):
            model = model.cuda()
            # PIGuard's CLS head is a SEPARATE nn.Linear (not part of `model`): move it too.
            # Bug 2026-09-26: only the encoder moved, every GPU inference raised a device
            # mismatch, and callers silently fell back ("PIGuard unavailable") -- S7/S9/G8.
            if self._head is not None:
                self._head = self._head.cuda()
        self._model = model
        logger.info(f"  {self.system} loaded on "
                    f"{'cuda' if next(model.parameters()).is_cuda else 'cpu'}")

    def injection_probs(self, texts: list[str], batch_size: int = 32) -> list[float]:
        """P(injection) per text, in one forward pass per batch."""
        self._load()
        import torch

        out: list[float] = []
        for i in range(0, len(texts), batch_size):
            batch = texts[i:i + batch_size]
            enc = self._tokenizer(batch, return_tensors="pt", truncation=True,
                                  max_length=512, padding=True)
            enc = {k: v.to(next(self._model.parameters()).device)
                   for k, v in enc.items()}
            with torch.no_grad():
                if self._head is not None:
                    hs = self._model(**enc).last_hidden_state[:, 0, :]
                    logits = self._head(hs)
                else:
                    logits = self._model(**enc).logits
            p = torch.softmax(logits, dim=-1)[:, self.injection_index]
            out.extend(p.tolist())
        return out

    def predict(self, text: str) -> BaselineResult:
        t0 = time.perf_counter()
        score = self.injection_probs([text])[0]
        return BaselineResult(
            score=float(score),
            label="malicious" if score >= self.threshold else "benign",
            decision=("BLOCK" if score >= 0.85
                      else "WARN" if score >= self.threshold else "ALLOW"),
            latency_ms=(time.perf_counter() - t0) * 1000.0,
            system=self.system,
            details={"model_id": self.model_id},
        )

    def predict_batch(self, texts: list[str],
                      batch_size: int = 32) -> list[BaselineResult]:
        t0 = time.perf_counter()
        probs = self.injection_probs(texts, batch_size=batch_size)
        per = (time.perf_counter() - t0) * 1000.0 / max(len(texts), 1)
        return [
            BaselineResult(
                score=float(p),
                label="malicious" if p >= self.threshold else "benign",
                decision=("BLOCK" if p >= 0.85
                          else "WARN" if p >= self.threshold else "ALLOW"),
                latency_ms=per,
                system=self.system,
                details={"model_id": self.model_id},
            )
            for p in probs
        ]


class PIGuardBaseline(_DebertaGuard):
    """PIGuard / InjecGuard (ACL 2025). id2label = {0: benign, 1: injection}."""
    model_id = "leolee99/PIGuard"
    system = "PIGuard"
    injection_index = 1
    head = _HEAD_CLS_DIRECT


class ProtectAIv2Baseline(_DebertaGuard):
    """ProtectAI deberta-v3-base-prompt-injection-v2.
    id2label = {0: SAFE, 1: INJECTION}."""
    model_id = "protectai/deberta-v3-base-prompt-injection-v2"
    system = "ProtectAI-v2"
    injection_index = 1
