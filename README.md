<div align="center">

# DIDA
### Defense-in-Depth Architecture for Secure Conversational AI

**A five-layer runtime security proxy for LLM applications, and a measurement-first study of
whether layered guardrails actually compose.**

![python](https://img.shields.io/badge/python-3.10%2B-blue)
![layers](https://img.shields.io/badge/defense%20layers-5-6f42c1)
![live agent](https://img.shields.io/badge/AgentDojo%20live%20attack%20success-0.59%E2%86%920.04-brightgreen)
![harm AUROC](https://img.shields.io/badge/WildJailbreak%20AUROC-0.952-brightgreen)
![multi-turn](https://img.shields.io/badge/cipher%20jailbreak%20AUROC-0.996-brightgreen)

</div>

---

## Why DIDA exists

Production LLM apps now read retrieved documents, call tools and hold long conversations. That
gives an attacker four doors: the user prompt, a poisoned document, a hijacked tool output and a
slow multi-turn escalation. The industry answer is to **stack guardrails**: an input classifier,
a retrieval sanitizer, a tool monitor, an output filter. The premise is that layers catch what any
single layer misses.

DIDA builds that stack properly, with five layers, calibrated thresholds, a shared per-session
evidence bus and cross-layer correlation. It then tests the premise instead of assuming it.

> **The headline finding.** The individual layers can be made strong. But no detector that
> reads threshold crossings can catch an attacker who keeps every layer just below its threshold.
> And no statistically valid way of fusing layer scores beats the best single layer unless it
> assumes the layers are independent. We prove both, build certified benchmarks that test them,
> and show they hold on DIDA **and** on a second stack assembled from third-party components
> (LLM Guard + Llama Guard 3).

Every number below comes from **[`results.md`](results.md)**, the complete lab log of this project.
It records every run, every bug found and fixed, and every figure that was superseded and why.

---

## Results at a glance

### Defending a live AI agent (AgentDojo)
A real Gemini agent doing real tasks (e-mail, banking, travel, Slack) while attackers plant
instructions in its tool outputs. 68 attack scenarios and 34 benign tasks; every pipeline ran every
episode.

| Pipeline | Attack success ↓ | Task success under attack ↑ | Task success, no attack ↑ |
|---|:---:|:---:|:---:|
| No defense | 0.588 | 0.529 | 0.853 |
| AgentDojo's built-in detector | 0.015 | 0.206 | 0.471 |
| **DIDA, tool-call check only** | **0.103** | **0.574** | **0.853** |
| **DIDA, full** | **0.044** | 0.309 | 0.794 |

- **DIDA's tool-call check alone cuts attacks 6× with zero loss of benign utility.**
- The full defense stopped 37 attacks and enabled none (p < 10⁻⁶).
- AgentDojo's own detector breaks **13 of 34** benign tasks to reach its number.

### Per-layer, shipped configuration

| Layer | What it stops | Benchmark | Result |
|---|---|---|---|
| **L1** injection | prompt injection | TensorTrust (570 attacks) | recall **0.875** |
| | | NotInject / Alpaca (benign) | false positives **3.5% / 0.5%** |
| **L1H** harm intent | jailbreaks behind roleplay | WildJailbreak (2,210) | AUROC **0.952**, recall 0.738 @ 4.3% FPR |
| **L2** documents | poisoned retrieval | BIPIA | AUROC **0.93**; held-out recall **0.636** @ **1.3%** FPR |
| **L3** multi-turn | slow-burn and cipher jailbreaks | tom-gibbs (5,336) | AUROC **0.996**, recall 0.984, **0 false positives** |
| **L4** tool calls | agent hijacking | InjecAgent | recall **1.000**, **0 false positives** |
| **L5** output | data leakage | AgentLeak (5,006) | AUROC **0.888** |
| **Pipeline** | multi-vector attacks | DIDA-Bench | **91.5%** blocked, **0** false positives |

### What the engineering bought: before → after

Each row is a measured root cause and a repair, not a threshold tweak (details in `results.md`).

| Problem found | Before | After |
|---|:---:|:---:|
| Harmful intent hidden in roleplay (WildJailbreak AUROC) | 0.574 | **0.952** |
| Cipher-encoded multi-turn jailbreaks (tom-gibbs AUROC / FPR) | 0.755 / 10.2% | **0.996 / 0%** |
| Poisoned documents (BIPIA AUROC) | 0.719 | **0.934** |
| Poisoned documents (BIPIA held-out recall @ FPR) | 0.148 @ 4.0% | **0.636 @ 1.3%** |
| Agent hijacking, trace replay (attack execution per suite) | 0.59 / 1.00 / 0.45 / 0.41 | **0.00 / 0.20 / 0.02 / 0.00** |
| Tool-call false alarms on benign agent traffic | 56% of calls | **2–20%** by suite |
| Injection false positives on trigger-word prompts (NotInject) | 11.5% | **3.2%** (judge off) |
| Full-pipeline blocking on DIDA-Bench (0 false positives) | 69.5% | **91.5%** |

### Against third-party guards

| | Llama Guard 3 (1B) | ProtectAI DeBERTa v2 | DIDA |
|---|:---:|:---:|:---:|
| WildJailbreak AUROC | 0.814 | 0.653 | **0.952** |
| Multi-turn attacks (MHJ vs. real chats), AUROC | 0.682 | 0.566 | 0.682 (L3); 0.954 (probe, not shipped) |
| Certified sub-threshold sessions caught (SPLIT-Bench v1) | 1 / 340 | 0 / 340 | **265 / 340** (L3) |
| TensorTrust recall | 0.588 | **0.970** | 0.875 |
| False positives on NotInject | 7.4% | 43.4% | **3.5%** |

ProtectAI wins TensorTrust at its default threshold but flags 43% of benign trigger-word prompts.
Held to DIDA's false-positive rate, its recall falls to 0.779.

---

## The research: do layered defenses compose?

| Finding | Evidence |
|---|---|
| **Threshold fusion is provably blind** to an attacker who keeps every layer sub-threshold | Correlation engine fired **0 times** on SPLIT-Bench v1 (680) and v2 (510), whose sessions carry machine-checked sub-threshold certificates |
| **Apparent cross-layer wins are single layers in disguise** | The only detecting mechanism, a pattern miner (\|U\| 0.7794 / 0.6706), equals one layer's zero-false-positive ceiling *to the session* |
| **Valid fusion cannot beat the best layer** without assuming independence | An anytime-valid e-process detects a set **identical** to one layer (Jaccard 1.0000); a learned alarm ranks attacks at AUROC 0.974 but cannot operate within a 2% false-alarm budget |
| **Pipelines destroy evidence at their interfaces** | A four-check audit found **7** such points in DIDA; Llama Guard's safe/unsafe verdict turns an AUROC-0.714 ranking into one bit (0.500) |
| **It is not just our system** | Replicated on LLM Guard + Llama Guard 3 with a corpus certified against *that* stack: deployed rule catches **0/107**; dependence-robust fusion **0**; independence-assuming fusion **10**, exactly as predicted |
| **More layers can mean more places to hide** | 66.7–85.2% of DIDA's headroom is undefended against a distributed attacker (37.4% on the third-party stack) |

The theory is classical: decision fusion, and Vovk and Wang's e-merging. The contribution is turning
it into checks an engineer can run on a real guardrail stack, and measuring two stacks against it.

---

## Architecture

```
                         ┌──────────────── Threat Intelligence Bus (per session) ───────────────┐
                         │   correlation rules · taint graph · e-value fusion · live dashboard   │
                         └───▲──────────────▲──────────────▲──────────────▲──────────────▲───────┘
                             │              │              │              │              │
user prompt ──► [ L1 ] injection tiers + separate harm head (Qwen3Guard)   │              │
retrieved docs / tool output ──► [ L2 ] document scorer, per-content-type conformal anchors
conversation ─────────────────────────► [ L3 ] drift + velocity + decoded-goal cipher channel
tool call ───────────────────────────────────────► [ L4 ] action authorisation + ADDRESSEE check
model output ─────────────────────────────────────────────────────────► [ L5 ] PII / exfil / leak
```

| Layer | How it works |
|---|---|
| **L1** | Regex → semantic templates → Prompt Guard × PIGuard (an AND, which kills trigger-word false positives) → an optional policy judge (gpt-oss-safeguard-20b). Plus a **separate** harm-intent head: fusing it with `max()` measurably hurt both signals. |
| **L2** | Prompt Guard's *injection* head over overlapping segments and a dangerous-code indicator, with Mondrian split-conformal anchors per content type (news, code answers, tool outputs). Short text is scored by PIGuard. |
| **L3** | Alignment, cumulative drift and velocity over sentence windows. For substitution-cipher jailbreaks it reverse-substitutes the decoded goal and scores that **instead of** the encoding features. |
| **L4** | Every tool has a capability class. The user must have requested the action, and each argument is traced to where it came from. The addressee check asks whether the text around a copied value is **talking to the AI**; e-mails and chats instruct humans, injections instruct the model. |
| **L5** | PII and exfiltration regexes, canary tokens (including base64), and a provenance leak check that reuses L4's tracing on the output. |

Thresholds are **split-conformal on benign data only**, so the false-positive rate is guaranteed on
traffic like the calibration set. We also report where that guarantee breaks across corpora.

---

## Engineering highlights

- **Certified benchmarks.** SPLIT-Bench samples are accepted only if a machine-checked certificate
  proves every layer is sub-threshold while ≥ k layers carry signal. The certificates are re-verified
  at import.
- **Honest harnesses.** Seven harness defects were caught by treating plausible numbers as suspicious.
  Examples: a leak benchmark sharing one session across samples (AUROC 0.53 → 0.89 once fixed), and
  an agent framework that scores an overloaded API as a *successful attack*.
- **Pre-registered gates.** Candidate improvements were adopted only if they passed a gate written
  before the held-out data was scored. Several failed and are reported as failures.
- **Runs on a laptop.** Qwen3Guard and Llama Guard run on a 4 GB GPU via split-device placement,
  matching CPU scores to within 5×10⁻⁶. The whole defense can run fully locally with the judge off.
- **Every run is recorded.** Each evaluation writes its full configuration snapshot, and
  `sentinel/eval/results/LEDGER.jsonl` indexes them.

---

## Quick start

```bash
pip install -r requirements.txt           # the proxy
cp .env.example .env                      # optional API keys (see below)
python main.py                            # proxy + live dashboard → http://localhost:8080
```

- **Python 3.10+.** A GPU is optional.
- **Gated models:** Prompt Guard and Llama Guard 3 require accepting their Hugging Face licences
  (`huggingface-cli login`).
- **Optional keys:**
  - `GROQ_API_KEYS` enables L1's policy judge. Set `L1_LLM_JUDGE_ENABLED=false` for a fully local
    defense.
  - `GEMINI_API_KEYS` is used only by the live AgentDojo harness and the benign-data audit.

**Core endpoints:**
- `POST /sentinel/chat` for user input;
- `POST /sentinel/rag/ingest` for documents;
- `POST /sentinel/agent/tool_call` to authorise a tool call before it runs;
- `POST /sentinel/agent/tool_response` to scan a tool output;
- `POST /sentinel/output/scan` for model responses;
- `WS /ws/events` for the live event stream.

## Reproducing the results

```bash
pip install -r requirements-eval.txt
python -m sentinel.eval.runner --layer L1 --dataset tensortrust       # any layer × dataset
python -m sentinel.eval.runner --pipeline                             # full pipeline, DIDA-Bench
python -m sentinel.eval.split_bench                                   # generate certified SPLIT-Bench
python -m sentinel.eval.eprocess_eval                                 # anytime-valid fusion
python -m sentinel.eval.agentdojo_l4 --attacks --max-pairs 60         # L4, trace replay
python -m sentinel.eval.agentdojo_live --pairs 20 --benign 10         # live agent (resumable)
python -m sentinel.eval.guard_baseline --backend llama-guard-3-1b     # third-party baselines
python -m sentinel.eval.second_stack build && python -m sentinel.eval.second_stack analyze
```

## Repository layout

```
main.py                    entry point
sentinel/                  the DIDA package (directory keeps the project's original name)
├── app.py                 FastAPI proxy and WebSocket
├── config.py              every threshold and feature flag, shipped defaults documented inline
├── core/                  threat bus, correlation, taint graph, e-value fusion, conformal calibration,
│                          addressee cues, split-device GPU placement
├── layers/                L1 · L2 (layer2_rag/) · L3 · L4 (layer4_agentic/) · L5 (layer5_output/)
└── eval/                  harness, dataset loaders, SPLIT-Bench generator + certificates,
    └── data/              live AgentDojo, guard baselines, second-stack audit; our benchmarks
dashboard/static/          real-time monitoring dashboard
results.md                 the complete lab log
```

Third-party corpora (AgentDojo, InjecAgent, BIPIA, AgentLeak, WildJailbreak, MHJ, tom-gibbs,
OR-Bench, WildChat, OpenAssistant) are fetched from their sources by
`sentinel/eval/dataset_loaders.py` and are not redistributed. Neither is any corpus containing real
users' conversation text.

---

<div align="center">

**Built by Gokul Iyer**

</div>
