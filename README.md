# DIDA — Defense-in-Depth Architecture for Secure Conversational AI

DIDA is a five-layer runtime security proxy for LLM applications: it sits between users, retrieved
content, tools and the model, and scores every request, document, tool call and response. It is
also the research system behind the paper **"Why Layered LLM Defenses Fail to Compose: Evidence
Interfaces and the Price of Valid Cross-Layer Fusion"**, which asks a question most guardrail
stacks never test: *does stacking layers actually catch what no single layer catches?*

The short answer we measured: the individual layers can be made strong, but threshold-based
cross-layer correlation cannot detect an attacker who keeps every layer below its threshold, and
statistically valid score fusion cannot either unless it assumes the layers are independent. We
proved both statements, built benchmarks that test them, and showed they hold on DIDA **and** on a
second stack built from third-party components (LLM Guard + Llama Guard 3).

> **Every number in this README is taken from [`results.md`](results.md)**, the project's full lab
> log: every run, every bug found, every superseded figure and why it changed. The current
> results are in its §12 (DIDA v2) and §13 (live agent, baselines, second stack).

---

## Architecture

```
user input ──► L1  injection score (regex → semantic templates → Prompt Guard × PIGuard → policy judge)
               └── L1H harm-intent head (Qwen3Guard-0.6B, separate output, own conformal anchor)
retrieved docs / tool outputs ──► L2  document scorer (Prompt Guard injection head + dangerous-code
                                       indicator; Mondrian conformal anchors per content type;
                                       PIGuard bin for short third-party text)
conversation ──► L3  multi-turn scoring (alignment, drift, velocity) + decoded-goal channel for
                     turn-by-turn substitution ciphers
tool call ──► L4  action authorisation: capability classes, requested-action check, data-flow
                  provenance of every argument, and an ADDRESSEE check (does the text around a
                  copied value speak to the model or to a human?)
model output ──► L5  PII / exfiltration / canary screening + provenance-based free-text leak check

all layers ──► Threat Intelligence Bus ──► correlation rules, taint graph, e-value fusion (research)
```

Thresholds are split-conformal on benign data only (a guaranteed false-positive budget on
exchangeable traffic), and every layer emits a continuous score onto a per-session event bus.

## Results

### Per-layer (shipped configuration)

| Layer | Benchmark | Result |
|---|---|---|
| L1 injection | TensorTrust (570 attacks) | recall **0.875** |
| L1 injection | NotInject (339 benign, trigger words) / Alpaca (10,376 benign) | FPR **0.035** / **0.005** |
| L1H harm head | WildJailbreak (2,000 / 210) | AUROC **0.952** (injection score alone: 0.574), recall 0.738 @ FPR 0.043 |
| L2 documents | BIPIA held-out | recall **0.636** @ FPR 0.013 |
| L3 multi-turn | tom-gibbs cipher jailbreaks (4,136 / 1,200) | AUROC **0.996**, recall 0.984, **FPR 0.000** (was 0.755) |
| L4 actions | InjecAgent, direct harm and data stealing | recall **1.000**, FPR 0.000 |
| L5 output | AgentLeak (5,006) | AUROC **0.888** |
| Full pipeline | DIDA-Bench (59 / 53) | block rate **0.915** at FPR 0.000 |

### Live agent (AgentDojo, Gemini 3.1 Flash-Lite, 68 attack pairs + 34 benign tasks)

| Pipeline | Attack success | Utility under attack | Benign utility |
|---|---|---|---|
| no defense | 0.588 | 0.529 | 0.853 |
| AgentDojo's built-in detector | 0.015 | 0.206 | 0.471 |
| **DIDA, L4 only** | **0.103** | **0.574** | **0.853** |
| **DIDA, full** | **0.044** | 0.309 | 0.794 |

DIDA stopped 37 attacks and enabled none (exact McNemar p < 1e-6). Its L4 check alone cuts attack
success six-fold with benign utility unchanged, while AgentDojo's detector breaks 13 of 34 benign
tasks.

### Cross-layer findings (the paper's core)

- **Threshold fusion is blind to distributed attacks.** On SPLIT-Bench (v1: 680, v2: 510 sessions,
  each with a machine-checked certificate that every layer is sub-threshold) the correlation
  engine fired **0** times. The one mechanism that detected anything (a pattern miner) was reading a
  lower cut of a single layer and matched that layer's zero-false-positive ceiling exactly.
- **Valid fusion cannot beat the best layer without an independence assumption.** An anytime-valid
  e-process detected a set identical to one layer alone (**Jaccard 1.0000** on both corpora), and a
  learned fusion alarm ranking attacks at AUROC 0.974 could not work within a 2% false-alarm budget.
- **Evidence is destroyed at interfaces.** A four-check audit found 7 places in DIDA where continuous
  evidence becomes a bare decision, including a multi-turn term that could never reach its own
  threshold and a layer whose accuracy silently depended on an external API.
- **It replicates on a stack we did not build.** On LLM Guard's scanner + Llama Guard 3, with a
  corpus certified against *that* stack: its rule blocks **0/107** attacks, Llama Guard's verdict
  reduces a ranking with AUROC 0.714 to one bit (0.500), the dependence-robust mean merge detects **0**
  and the independence-assuming product merge **10**, exactly as the theory predicts.
- **Effective capacity:** 66.7–85.2% of DIDA's headroom is undefended against a distributed attacker
  (37.4% on the third-party stack), so adding a layer can enlarge what an attacker can hide.

### Baselines

Llama Guard 3 (1B) and ProtectAI's DeBERTa injection classifier were run on every corpus.
- **Llama Guard 3** is at chance on SPLIT-Bench (at most 1 attack detected at zero false positives,
  against 265/340 for L3 alone).
- **L1H** beats Llama Guard on WildJailbreak (AUROC 0.952 vs 0.814).
- **ProtectAI** beats L1 on TensorTrust at its own threshold (0.970 vs 0.875) but flags 43% of
  NotInject. At L1's false-positive rate it drops to 0.779.

The full tables, the root-cause analyses behind every repaired layer, and the honest failures (MHJ
multi-turn intent, over-refusal on OR-Bench-Hard, the utility cost of withholding tool outputs) are
in [`results.md`](results.md).

---

## Repository layout

```
main.py                     entry point (uvicorn)
sentinel/                   the DIDA package (the directory keeps the project's original name)
  app.py                    FastAPI proxy: chat, RAG, agent tool-call / tool-response, output scan, WebSocket
  config.py                 every threshold and feature flag (shipped defaults documented inline)
  core/                     threat bus, correlation engine, taint graph, e-value fusion, conformal
                            calibration, addressee cues, guard device placement, pattern mining
  layers/                   L1 (layer1.py, judge), L2 (layer2_rag/), L3 (layer3.py), L4 (layer4_agentic/),
                            L5 (layer5_output/)
  eval/                     evaluation harness: dataset loaders, runner, SPLIT-Bench generator and
                            certificates, e-process / fusion evaluation, live AgentDojo harness
                            (agentdojo_live.py), guard baselines (guard_baseline.py), second-stack
                            audit (second_stack.py)
  eval/data/                our benchmarks: DIDA-Bench (sentinel_bench), Phase-4, SPLIT-Bench v1/v2
dashboard/static/           real-time monitoring dashboard (served at /)
sentinel_policy.yaml        L5 output policy
results.md                  the lab log of record
```

Third-party corpora (AgentDojo, InjecAgent, BIPIA, AgentLeak, WildJailbreak, MHJ, tom-gibbs,
OR-Bench, WildChat, OpenAssistant) are downloaded from their sources by `sentinel/eval/dataset_loaders.py`
and are not redistributed here. Nor is any corpus containing real users' conversation text, which
includes SPLIT-S2. Its builder is `python -m sentinel.eval.second_stack build`.

## Setup

```bash
pip install -r requirements.txt            # the proxy
pip install -r requirements-eval.txt       # the evaluation harness
cp .env.example .env                       # API keys (optional; see below)
python main.py                             # proxy + dashboard on http://localhost:8080
```

- Python 3.10+. A GPU is optional: Qwen3Guard and Llama Guard fit a 4 GB card, and they run on the CPU otherwise.
- Some models are gated on Hugging Face (Prompt Guard, Llama Guard 3). Accept their licences and
  log in with `huggingface-cli login`.
- **API keys (optional):**
  - `GROQ_API_KEYS` enables L1's policy judge (gpt-oss-safeguard-20b). DIDA runs fully locally with
    `L1_LLM_JUDGE_ENABLED=false`.
  - `GEMINI_API_KEYS` is used only by the benign-arm audit and the live AgentDojo harness.

## Reproducing the evaluation

```bash
python -m sentinel.eval.runner --layer L1 --dataset tensortrust       # any layer x dataset
python -m sentinel.eval.runner --pipeline                             # full pipeline on DIDA-Bench
python -m sentinel.eval.split_bench                                   # generate SPLIT-Bench (certified)
python -m sentinel.eval.eprocess_eval                                 # e-process fusion on SPLIT-Bench
python -m sentinel.eval.agentdojo_l4 --attacks --max-pairs 60         # L4 trace replay
python -m sentinel.eval.agentdojo_live --pairs 20 --benign 10         # live agent (resumable)
python -m sentinel.eval.guard_baseline --backend llama-guard-3-1b     # third-party baselines
python -m sentinel.eval.second_stack build && python -m sentinel.eval.second_stack analyze
```

Every run writes a JSON artifact with its full configuration snapshot to `sentinel/eval/results/`.
It also appends a line to `sentinel/eval/results/LEDGER.jsonl`, which is committed and records
every reported run.

## Authors

Gokul Iyer, Parth Choutapelly, Ishita Sharma, Neha Kadam and Preet Kaur (supervisor). Department of
Computer Engineering, Ramrao Adik Institute of Technology, D. Y. Patil Deemed to be University,
Navi Mumbai.
