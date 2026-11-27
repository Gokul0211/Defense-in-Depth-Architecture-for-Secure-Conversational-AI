<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/logo/dida-logo-dark.svg">
  <img alt="DIDA: Defense-in-Depth Architecture" src="assets/logo/dida-logo-light.svg" width="520">
</picture>

### Defense-in-Depth Architecture for Secure Conversational AI

**Five security layers in front of your LLM app, plus a hard look at whether stacking them actually works.**

![python](https://img.shields.io/badge/python-3.10%2B-blue)
![layers](https://img.shields.io/badge/defense%20layers-5-6f42c1)
![live agent](https://img.shields.io/badge/AgentDojo%20live%20attack%20success-0.59%E2%86%920.04-brightgreen)
![harm AUROC](https://img.shields.io/badge/WildJailbreak%20AUROC-0.952-brightgreen)
![multi-turn](https://img.shields.io/badge/cipher%20jailbreak%20AUROC-0.996-brightgreen)
![runs local](https://img.shields.io/badge/runs%20on-a%204%20GB%20laptop%20GPU-orange)

[Since the paper](#since-the-paper) ·
[What it does](#what-it-does) ·
[Results](#results) ·
[The research](#research) ·
[Contributions A–M](#contributions) ·
[Architecture](#architecture) ·
[Quick start](#quick-start) ·
[Reproduce](#reproduce)

</div>

---

## ⚡ TL;DR

- 🧱 **A runtime proxy** that screens every prompt, retrieved document, conversation, tool call and model output, with calibrated thresholds and a shared per-session evidence bus.
- 🤖 **On a live Gemini agent** (AgentDojo), DIDA's tool-call check alone cuts attack success from **58.8% to 10.3%** with **zero loss** of benign task success. The full defense gets it to **4.4%**.
- 🔬 **A research result:** layered guardrails don't compose the way people assume. No detector that reads threshold crossings can catch an attacker who keeps every layer just under its threshold. And no statistically valid fusion beats the best single layer unless it assumes the layers are independent. We prove both, then show they hold on DIDA **and** on a second stack built from third-party parts (LLM Guard + Llama Guard 3).
- 🖥️ **Since the paper, fully local:** the final whole-system run (one read, 2026-11-19) blocks **96.6%** of DIDA-Bench attacks, blocks **0%** of 582 re-used and **0.19%** of 529 fresh benign requests, at **0.77 s** per request on a 4 GB laptop GPU with no hosted model call ([details](#since-the-paper)).
- 📒 **Nothing hand-waved:** every number below comes from [`results.md`](results.md), the full lab log of every run, bug, fix and superseded figure.

---

<a id="since-the-paper"></a>

## 🆕 Since the paper (October–November 2026)

The results tables further down are the paper's measurements (September 2026). The work since then ran in rounds
with pre-registered DEV / VAL / one-time TEST protocols on fresh, untouched test draws; everything is logged in
[`results.md`](results.md) §18–§34 (every metric of every row: §21.5 and each round's own section; metrics policy and 95 % intervals: §21.1; the final whole-system run: §27.3).

| Layer | What changed | Shipped by default? | Measured (fresh test draws) |
|---|---|---|---|
| **L2** documents | A **local document detector**: a 4-bit Qwen3-4B reads the document under a document policy and a linear probe on its residual stream decides, with split-conformal thresholds per content type. Code and prose go to separate probes; non-English prose segments get one more reading translated to English (opus-mt-mul-en); long documents are read in windows, hidden-character text unhidden. | **Yes**, since 2026-11-03 (`L2_LOCAL_DETECTOR=authoritative`, `L2_LOCAL_PROBE_ROUTING`, `L2_LOCAL_TRANSLATE_VIEW`). Without the local model it falls back to the earlier scorer. | BIPIA **0.969**; injection in the middle of a document **0.926** (long documents 0.930); injections translated into German / French / Spanish / Italian / Russian / Dutch **0.94–1.00**, Chinese 0.916; DIDA **1.0**. False positives: pasted passages 1.8 %, code 0.7 %, e-mail and translated benign text 0. **v8 (default since 2026-11-07):** foreign script runs inside lines translated, Chinese through opus-mt-zh-en plus a mood-keeping translation by the local model, canonical whitespace, recalibrated thresholds, and two speed-ups with identical decisions (early exit after the probe layer; the soft scorers skipped once the detector answered: ingest 2.5 s -> **0.6 s**). Eleventh untouched draw, read once: precision **0.992**, recall **0.959**, F1 0.975, FP 1.10 %, AUROC 0.996; Chinese **0.973**, German 0.958, pasted passages **1.41 %**, whitespace flips 0. |
| **L4** tool calls | **Action authorization** at the tool boundary: an intent contract (which actions the user asked for, with which values), value lineage (where every argument came from: the user, a system of record, or document text) and a trust matrix per argument class. | **Yes**, since 2026-10-23 (`L4_AUTHZ`; the contract is written by a hosted model, with a lexicon fallback). | AgentDojo, 398 held-out attack pairs, effect-level replay: 3 attacks with an effect when the user declines unexpected confirmations (0.8 %). |
| | A **fully local profile**: the contract and a per-call alignment check written by the local Qwen3-4B (nothing leaves the machine), copied-argument guards, and a named-source rule for actions the user did not ask for. | No (opt-in profile). | AgentDojo held-out: 0 / 398 with a declining user, 38 / 398 when every confirmation is approved — statistically the same as the hosted candidate (paired McNemar p = 0.79); InjecAgent 100 % stopped, 0 / 34 benign held; Agent Security Bench 99.5 % stopped. **Named-source rule** (2026-11-06, `L4_NAMED_SOURCE_AUTHORITY`, in the local profile): a value from a document the user pointed at, of the kind the user asked for, needs no confirmation unless the text around it reads as an injection — benign tasks prompted 16.5 % → 8.2 %. **v10** (adds v8's necessity question, guarded so it cannot turn a block into a confirmation, and an entity anchor): **5.2 %** of benign tasks prompted, benign utility 0.41 → **0.52**, still **0 / 398** attacks with a declining user, whose utility under attack (0.46) now equals that of a user who approves everything. **v11 / v12** (2026-11-11, adopted in the local profile): an operator capability registry (Agent Security Bench legitimate prompts held 29 % -> 13 %, the two genuine write tools) and user-named alternatives -- AgentDojo benign tasks prompted **4.1 %**, still 0 / 398 attacks with a declining user. |
| **L1** prompts | A local judge and residual-probe ensemble (Qwen3-4B) plus a ProtectAI feature. | No (`L1_LOCAL_JUDGE`, `L1_LLM_PROBE`). | Untouched TensorTrust split (800 attacks): shipped **0.465** → candidate **0.805**, at a NotInject false-positive rate of 4.4 %. |
| | v8 round (2026-11-06): probe score S1 plus **AUTH**, which lets the local probe overrule soft-tier false alarms (hard pattern matches keep their verdict); v13 / v15 (2026-11-08) add trigger-word hard negatives, unsuccessful attack attempts as training positives, weighted hard negatives and AUTH2. | **v15: the code default** since 2026-11-19 (`L1_STACK_V12`, `L1_STACK_CASCADE`, `L1_STACK_EARLY_EXIT`); production reproduces the offline v15 decisions on all 800 fresh8 texts (0 mismatches, results.md §23.14). | Fourth untouched TensorTrust split (537), read once: hijacking **0.853**, extraction **0.713** (shipped 0.523 / 0.448); fifth untouched split (800), read once: **0.802 / 0.783** (shipped 0.500 / 0.450); NotInject false positives **2.65 %** (shipped 3.24 %); pooled precision 0.98–0.99. A probe adapted on the spent TensorTrust sets (v10) adds ~4 points on a sixth untouched split: **0.832 / 0.780**, NotInject 2.95 %. A **fine-tuned classifier** stage (v11, ProtectAI DeBERTa tuned on the spent sets) on a seventh untouched split: **0.846 / 0.843**, NotInject **1.77 %**, precision 0.991. **v15** on a tenth untouched split, read once: **0.927 / 0.935**, NotInject **2.06 %**, precision **0.985**, F1 0.957, AUROC 0.997, 433 ms mean -- meets the mark within the user's tolerance. |
| **L5** outputs | **Field policy**: the operator declares which record fields a task may disclose -- per session (`L5_FIELD_POLICY`) or once per task type in a **task-policy library** matched by similarity (`L5_POLICY_LIBRARY`); L5 matches the other fields' values exactly. | No (the operator supplies the policy). | AgentLeak scenario split, TEST read once: recall **1.000**, false positives **0.91 %**, precision 0.976 (shipped 0.900 / 5.3 %). On AgentLeak the check mirrors how the label is built: it shows the policy is enforced, not that L5 infers which fields are private. |
| **L6** answers | **Answer-provenance guard** v3.4: the final answer may not repeat an identifier or a 6-word run that first entered the session through third-party data (structured spans over YAML / JSON records, first-seen taint, whole-token identifiers, spotlighting-tolerant units, nothing before the first cue, an explicit closing tag ends the block). | v3.4 rules default ON since 2026-11-15 (`L6_STRUCTURED_SPAN`, `L6_TAINT_FIRST_SEEN`, `L6_BOUNDED_IDENT`, `L6_SPAN_V33`, `L6_SPAN_CLOSE_TAG`); L6 itself is opt-in. | Fresh local-agent TEST5 (the local Qwen3-4B as the AgentDojo agent, 406 answers, 179 relays), read once: recall **0.972**, FP **0.00 %** (0 / 227), precision **1.000**, F1 0.986, AUROC 0.986, 3.2 ms; ignore_previous recall 0.911 (51 / 56, accepted). v3.1 on 13 published agents (TEST2): recall 0.997, FP 0.14 %, precision 0.982. |
| **Harm** (reply side) | The local 4B reads each reply in the context of the request (a probe on its forward pass, stacked with its yes / no read-out), where harm is explicit instead of disguised. | No (`L5_HARM_LOCAL` off). v5 failed (Do-Not-Answer recall 0.062: a reply-only read cannot see question-relative harm; XSTest 0.811); v6 (reply-first two-view read) separates within every dataset (VAL recall at 4 % FP 0.85 - 0.97) but no single threshold serves the datasets' different harm policies; its VAL gate failed and the TEST stays unread (results.md §31.4 - §31.5). | Fresh human-consensus labels (all three annotators agree), read once: JailbreakBench judge set recall 0.833 / FP 6.2 % / F1 0.852; HarmBench val set 0.881 / 6.6 % / 0.892; AUROC 0.96 / 0.97; 0.4 - 0.6 s per reply. No judge stored with those sets meets the mark on the same items either (GPT-4, Llama-3-70B and HarmBench's 13B classifier all exceed 4 % FP); on majority labels (WildGuardTest, kappa 0.50) a single human annotator scores recall 0.85 / FP 7.4 % (results.md §28). |
| **Whole system** (final run) | All adopted layers in the local profile, no hosted calls. Profile final_ct: 8 CPU threads and the L1 fine-tuned tier in fp16, which stops the 4B spilling into system memory. | -- | FINAL run, read once (2026-11-19, results.md §27.3): DIDA-Bench 59 attacks blocked **0.966** [0.885, 0.991]. Benign blocked **0 / 582** (re-read) and **1 / 529** on a fresh arm (0.19 %); any alarm on benign **1.03 % / 1.32 %**. Block precision **1.000 / 0.983**, AUROC **0.9998**, **772 ms** mean per request (interim WS1: 3.6 s). Every mark is met except any-alarm precision on the fresh arm, **0.892**: 5 of its 7 benign warnings are L5 e-mail warnings with no operator policy. The run happened before the L3 v4 round because of a chain fault, so L3 v4 is not in it. |
| **L3** multi-turn (v4.2 / v4.3) | A **conversation probe** on the shared 4B reads the user-turn history at every turn (layers 16 / 20 / 24), and a **reply check** (the v6 pair read with L3's own threshold) reads each real reply. v4.3: the reply check runs on real model replies only, never on the offline harness's stand-in output. | In the paper's local profile since 2026-11-27 (`L3_MT_V4`). The code default stays off: the reply threshold is calibrated on the local 4B's replies. | L3 TEST, read once (results.md §39.1): end-to-end recall **2 / 2** (Attack_600) and **11 / 11** (MHJ), **0 / 141** benign alarms, 607 ms per turn. The evidence is thin (Wilson lower bounds 0.34 / 0.74) and judge-sensitive (at t = 0.5: 0.756 / 0.726). Probe recall 0.917 on Attack_600 at 0 / 730 benign. |
| **Whole system** (FINAL + L3 v4.3: the system of record since 2026-11-27) | The FINAL profile plus L3 v4.3. | -- | Read once on a FRESH benign arm v3s (results.md §39.6): DIDA-Bench attacks blocked **0.983** [0.910, 0.997] (58 / 59), any alarm **59 / 59**. Benign blocked **0 / 529**, any alarm **0.57 %** (3 / 529). Precision **1.000** (any alarm **0.952**), AUROC **1.000**, **904 ms** mean per request. Every mark met strictly. Against FINAL on the same items, L3 adds one blocked attack and no benign alarm, at +88 ms. |

**Every metric, every layer** (shipped configuration unless marked; 95 % Wilson intervals; AUROC / AUPRC ranked against
all benign rows of the same run; latency per item on an i5-12500H laptop with a 4 GB RTX 3050). Full tables, one row per
dataset slice, with sources: [`results.md`](results.md) §21.5.

| Layer · benchmark | n attack / benign | Recall [95 % CI] | FP rate [95 % CI] | Precision | F1 | AUROC | AUPRC | Latency mean / p95 |
|---|---|---|---|---|---|---|---|---|
| **L1** TensorTrust untouched + DIDA vs NotInject + Alpaca + DIDA benign | 859 / 892 | 0.502 (TensorTrust 0.465 [0.431, 0.500]) | 1.35 % (NotInject 3.24 % [1.82, 5.72]) | 0.973 | 0.662 | 0.854 | 0.875 | 0.2–0.5 / 0.2–1.9 s |
| L1 probe candidate (off) | 859 / 892 | 0.789 (TensorTrust 0.774 [0.744, 0.801]) | 1.57 % (NotInject 3.83 %) | 0.980 | 0.874 | 0.916 | 0.931 | 1.7–2.3 / 2.4–5.2 s |
| L1 S1 + AUTH (off; v8, fourth untouched TensorTrust split, read once) | 537 / 892 | 0.816 (hijacking 0.853 [0.814, 0.884], extraction 0.713 [0.634, 0.781]) | 1.01 % (NotInject 2.65 % [1.40, 4.97]) | 0.980 | 0.890 | 0.983 (score) | 0.978 | probe stage 1.7–2.3 s |
| L1 S1 + AUTH (off) · fifth untouched TensorTrust split, read once | 800 / 892 | 0.795 (hijacking 0.802 [0.765, 0.835], extraction 0.783 [0.733, 0.826]) | 1.01 % (NotInject 2.65 % [1.40, 4.97]) | 0.986 | 0.880 | 0.981 (score) | 0.982 | probe stage 1.7–2.3 s |
| L1 v10 = S1 + AUTH + domain-adapted probe (off) · sixth untouched TensorTrust split, read once | 800 / 892 | 0.813 (hijacking 0.832 [0.797, 0.862], extraction 0.780 [0.730, 0.823]) | 1.12 % (NotInject 2.95 % [1.61, 5.34]) | 0.985 | 0.890 | 0.987 (score) | 0.987 | probe stage 1.7–2.3 s |
| **L1 v11 = v10 + fine-tuned classifier (off) · seventh untouched TensorTrust split, read once** | 800 / 892 | **0.845** (hijacking 0.846 [0.812, 0.875], extraction 0.843 [0.798, 0.880]) | **0.67 %** (NotInject **1.77 %** [0.81, 3.81]) | **0.991** | **0.912** | 0.989 (score) | 0.989 | probe stage 1.7–2.3 s + 11 ms |
| L1 v12 = v10 + PIGuard-based fine-tuned stage (off) · eighth untouched TensorTrust split, read once | 800 / 892 | 0.834 (hijacking 0.824 [0.788, 0.855], extraction 0.850 [0.805, 0.886]) | 1.35 % (NotInject 3.54 % [2.04, 6.08]) | 0.982 | 0.902 (accuracy 0.914, balanced 0.910, MCC 0.836) | 0.988 (score) | 0.988 | real runner, whole L1: 6.4 / 8.7 s (stage alone 0.37 / 0.89 s) |
| **L1 v13 = v12 + trigger-word hard negatives (off) · ninth untouched TensorTrust split, read once** | 800 / 892 | **0.915** (hijacking **0.922** [0.895, 0.942], extraction 0.903 [0.865, 0.932]) | 1.57 % (NotInject 4.13 % [2.48, 6.81]) | 0.981 | 0.947 (accuracy 0.952, balanced 0.9497, MCC 0.904) | 0.993 (score) | 0.993 | 4B read needed for 0–2.9 % of texts; production latency not yet measured |
| **L1 v15 = v13 + unsuccessful attempts + weighted hard negatives + AUTH2 (off) · tenth untouched TensorTrust split, read once** | 500 / 892 | **0.930** (hijacking **0.927** [0.891, 0.951], extraction **0.935** [0.892, 0.962]) | 0.78 % (NotInject **2.06 %** [1.00, 4.20]) | **0.985** | **0.957** (accuracy 0.970, balanced 0.961, MCC 0.935) | 0.997 (score) | 0.995 | real runner, whole L1 (harm head off): **433 ms mean** / 1,396 ms p95 |
| **L1H** harm head · WildJailbreak | 2,000 / 210 | 0.738 [0.718, 0.757] | 4.29 % [2.27, 7.94] | 0.994 | 0.847 | 0.952 | 0.992 | 2.8 / 5.8 s |
| Harm, reply side (local 4B, off) · WildGuardTest, majority labels, read once | 284 / 1,425 | 0.563 [0.505, 0.620] | 2.18 % [1.54, 3.07] | 0.838 | 0.674 (accuracy 0.909, balanced 0.771, MCC 0.640) | 0.939 | 0.825 | 0.64 / 1.01 s |
| Harm, reply side v4 (off) · JailbreakBench judge set, consensus labels, read once | 90 / 177 | 0.833 [0.743, 0.896] | 6.21 % [3.51, 10.78] | 0.872 | 0.852 (accuracy 0.903, balanced 0.886, MCC 0.780) | 0.960 | 0.907 | 0.39 / 0.67 s |
| Harm, reply side v4 (off) · HarmBench val set, consensus labels, read once | 202 / 286 | 0.881 [0.829, 0.919] | 6.64 % [4.29, 10.14] | 0.904 | 0.892 (accuracy 0.912, balanced 0.907, MCC 0.818) | 0.966 | 0.938 | 0.64 / 1.00 s |
| Harm, reply side v5 (off) · Do-Not-Answer, 3-annotator consensus, read once | 193 / 5,441 | 0.062 [0.036, 0.106] | 0.07 % [0.03, 0.19] | 0.750 | 0.115 (accuracy 0.967, balanced 0.531, MCC 0.210) | 0.926 | 0.409 | 0.39 / 0.68 s |
| Harm, reply side v5 (off) · XSTest annotated completions, 2 annotators, read once | 132 / 1,897 | 0.811 [0.735, 0.868] | 0.00 % [0, 0.20] | 1.000 | 0.895 (accuracy 0.988, balanced 0.905, MCC 0.895) | 0.975 | 0.922 | 0.42 / 0.52 s |
| L1H v3 harm probe on the shared 4B pass (off) · pooled fresh TEST, read once | 1,297 / 2,806 | 0.931 [0.916, 0.944] (XSTest unsafe 0.720) | 11.3 % [10.2, 12.5] (JBB benign 19.0 %, PHTest 14.2 %) | 0.792 | 0.856 (accuracy 0.901, balanced 0.909, MCC 0.787) | 0.975 | 0.959 | 0.10 / 0.35 s |
| **L1H v4.1 request-harm read on the shared 4B (off; accepted by the user as near the marks, 2026-11-20) · pooled fresh TEST, read once** | 1,913 / 2,173 | **0.913** [0.900, 0.925] (StrongREJECT 0.837, SST 0.840, GPTFuzz 0.934) | **3.04 %** [2.39, 3.85] (FalseReject 4.21 %, ToxicChat 1.62 %) | **0.964** | 0.938 (accuracy 0.943, balanced 0.941, MCC 0.887) | **0.989** | 0.987 | **0.22 / 0.57 s** |
| **L2** BIPIA, middle-of-document, translated attacks vs pasted, code, e-mail, translated benign (t9 TEST) | 1,985 / 1,822 | 0.952 (lowest row: Chinese 0.916) | 0.60 % (highest row: pasted 1.76 %) | 0.994 | 0.973 | 0.996 | 0.997 | 3.1–3.8 / 6.3–9.7 s per document |
| **L2 v8 (default)** · eleventh untouched draw (t11, stratified), read once; real runner | 2,180 / 1,630 | **0.959** (lowest row: Dutch 0.919) | 1.10 % (pasted 1.41 %; translated benign Chinese 4.35 %, Dutch 2.08 %) | **0.992** | **0.975** | **0.996** | **0.997** | **0.92 / 2.87 s** per document (VAL ingest 0.62 / 1.19 s) |
| **L3** tom-gibbs multi-turn | 4,136 / 1,200 | 0.984 [0.980, 0.987] | 0 % [0, 0.32] | 1.000 | 0.992 | 0.996 | 0.998 | 0.39 / 0.48 s |
| **L3 v4.2** end-to-end · Attack_600 replay vs four benign replay arms (TEST read once, §39.1) | 2 / 141 | 1.000 [0.342, 1.000] | 0 % [0, 2.65] | 1.000 | 1.000 | 1.000 | 1.000 | 0.61 s per turn |
| L3 v4.2 end-to-end · MHJ replay vs the same benign arms | 11 / 141 | 1.000 [0.741, 1.000] | 0 % [0, 2.65] | 1.000 | 1.000 | 1.000 | 1.000 | 0.61 s per turn |
| L3 v4.2 probe · Attack_600 vs 730 benign conversations | 600 / 730 | 0.917 [0.892, 0.936] | 0 % [0, 0.52] | 1.000 | 0.957 | 0.9998 | 0.9998 | probe read 0.12 / 0.31 s |
| L3 · MHJ vs audited WildChat | 110 / 646 | 0.082 [0.044, 0.148] | 3.10 % [2.01, 4.73] | 0.310 | 0.130 | 0.682 | 0.249 | 0.56 / 1.3 s |
| **L4** InjecAgent (direct + data stealing) | 1,054 / 34 | 1.000 [0.996, 1.000] | 0 % [0, 10.2] | 1.000 | 1.000 | 1.000 | — | 0.45 / 0.58–0.66 s |
| L4 · Agent Security Bench (local profile) | 1,200 / 100 | 0.995 [0.989, 0.998] | 29 % prompted [21.0, 38.5] | 0.976 | 0.986 | 0.871 | 0.979 | not stored |
| L4 · Agent Security Bench, local profile + **operator capability registry** (v11/v12, adopted 2026-11-11) | 1,200 / 100 | 0.995 [0.989, 0.998] | **13 % prompted** [7.8, 21.0] -- the two genuine write tools, held when the task did not ask for the write | 0.989 | 0.992 | 0.941 | 0.990 | not stored |
| L4 · AgentDojo held-out (local profile, effect replay) | 398 / 97 | attack success 0 [0, 0.010] declining, 0.095 [0.070, 0.128] approve-all | 16.5 % of benign tasks prompted [10.4, 25.1] | — | — | — | — | not stored |
| L4 · AgentDojo held-out, local profile + named-source rule + guarded necessity + entity anchor (v10, adopted 2026-11-06) | 398 / 97 | attack success 0 [0, 0.010] declining, 0.096 [0.070, 0.128] approve-all | 5.2 % of benign tasks prompted [2.2, 11.5] | 0.794 (refusals, calls) | 0.672 (calls) | — | — | 3.7 s per benign task (harness, all L4 checks) |
| **L4 · AgentDojo held-out, v12 = v10 + user-named alternatives (adopted 2026-11-11)** | 398 / 97 | attack success **0** [0, 0.010] declining, 0.096 [0.070, 0.128] approve-all | **4.1 %** of benign tasks prompted [1.6, 10.1] | 0.808 (refusals, calls) | 0.677 (calls) | — | — | 6.9 s per benign task (harness, all L4 checks) |
| **L5** AgentLeak | 1,355 / 3,651 | 0.875 [0.857, 0.892] | 4.85 % [4.20, 5.59] | 0.870 | 0.873 | 0.911 | 0.795 | 0.04 / 0.10 s |
| L5 with a declared field policy (off; scenario TEST, read once) | 290 / 771 | 1.000 [0.987, 1.000] | 0.91 % [0.44, 1.86] | 0.976 | 0.988 | 0.994 | 0.976 | 0.007 / 0.021 s |
| **L5 task-policy library** (off; fresh AgentLeak TEST: a local model's outputs on unseen scenarios, read once) | 370 / 52 | **0.997** [0.985, 1.000] | **3.85 %** [1.06, 12.98] | **0.995** | **0.996** (accuracy 0.993, balanced 0.979, MCC 0.967) | 0.980 | 0.994 | 0.010 / 0.011 s |
| L5 without any policy (shipped heuristic) · same fresh TEST | 370 / 52 | 1.000 [0.990, 1.000] | 36.5 % [24.8, 50.1] | 0.951 | 0.975 | 0.818 | 0.951 | 0.012 / 0.030 s |
| L6 answer guard v2.1 (superseded) · AgentDojo published runs of 13 fresh agents (TEST2), read once | 774 / 10,007 | 0.981 [0.968, 0.988] | 12.30 % [11.67, 12.96] | 0.381 | 0.549 (accuracy 0.8844, balanced 0.9288, MCC 0.571) | 0.929 (rule) | 0.218 | 4.1 / 12.9 ms |
| **L6 v3.1 = structured span + first-seen taint (adopted 2026-11-13; L6 itself off by default) · TEST2, 13 fresh agents, read once** | 774 / 10,007 | 0.997 [0.991, 0.999] | 0.14 % [0.08, 0.23] | 0.982 | 0.990 (accuracy 0.9985, balanced 0.9980, MCC 0.989) | 0.998 (rule) | 0.925 | 4.6 / 14.9 ms |
| L6 v3.1 · TEST3: 10 further pipelines (incl. 4 defended gpt-4o), read once | 703 / 11,292 | 0.989 [0.978, 0.994] | 0.53 % [0.41, 0.68] | 0.920 | 0.953 (accuracy 0.9943, balanced 0.9917, MCC 0.951) | 0.992 (rule) | 0.774 | 5.1 / 26.7 ms; spotlighting pipeline FP 5.84 %, precision 0.369 -- fixed in v3.3 / v3.4 |
| **L6 v3.4 (default ON since 2026-11-15) · TEST5: the local Qwen3-4B as the AgentDojo agent, read once** | 179 / 227 | 0.972 [0.936, 0.988] | 0.00 % [0.00, 1.66] | 1.000 | 0.986 (accuracy 0.9877, balanced 0.9860, MCC 0.975) | 0.986 (rule) | 0.984 | 3.2 / 9.8 ms |
| **Pipeline** DIDA-Bench (Sept. 2026 configuration) | 59 / 53 | 0.915 blocked (59 / 59 blocked or warned) | 0 / 53 | — | — | — | — | 0.52 / 0.75 s |
| Pipeline · benign traffic arm (Sept. 2026) | — / 529 | — | 1.5 % blocked, **33 % warned** | — | — | — | — | 1.8 / 3.1 s |
| **Pipeline, interim WS1** (2026-11-14, adopted local profile) · DIDA-Bench + benign arm, block decision | 59 / 582 | **0.966** [0.885, 0.991] | **0 %** [0, 0.66] (any alarm 1.03 % [0.47, 2.23]) | **1.000** | 0.983 (accuracy 0.9969, balanced 0.9831, MCC 0.981) | — | — | **3.59 / 7.54 s** |
| **Pipeline, FINAL** (2026-11-19, read once; profile final_ct) · DIDA-Bench vs DIDA benign + arm v1 (re-read), block decision | 59 / 582 | **0.966** [0.885, 0.991] | **0 %** [0, 0.66] (any alarm 1.03 % [0.47, 2.23]) | **1.000** (any alarm 0.906) | 0.983 (accuracy 0.9969, balanced 0.9831, MCC 0.981) | 0.9998 | 0.998 | **0.74 / 0.87 s** per request |
| Pipeline, FINAL · DIDA-Bench vs the FRESH benign arm v2, block decision | 59 / 529 | **0.966** [0.885, 0.991] | **0.19 %** [0.03, 1.06] (any alarm 1.32 % [0.64, 2.71]) | **0.983** (any alarm **0.892**) | 0.974 (accuracy 0.9949, balanced 0.9821, MCC 0.972) | 0.9997 | 0.998 | **0.83 / 1.07 s** per request |
| **Pipeline, FINAL + L3 v4.3** (2026-11-27, read once; the system of record) · DIDA-Bench vs the FRESH benign arm v3s, block decision | 59 / 529 | **0.983** [0.910, 0.997] | **0 %** [0, 0.72] (any alarm 0.57 % [0.19, 1.65]) | **1.000** (any alarm **0.952**) | 0.992 (accuracy 0.9983, balanced 0.9915, MCC 0.991) | 1.000 | 1.000 | **0.90 / 1.18 s** per request |

**Meets the mark** (status 2026-11-27):
- **The whole system, FINAL + L3 v4.3** (§39.6, the system of record since 2026-11-27): every mark met strictly on a fresh
  benign arm (blocked 0.983, benign blocked 0 / 529, any alarm 0.57 %, any-alarm precision 0.952, 904 ms).
- **L3 v4.2 on MHJ and Attack_600** (§39.1): every pre-registered mark on its TEST, with thin evidence and a
  judge-sensitive pass (see the table).
- **The whole system's FINAL run** (§27.3): every mark is met except any-alarm precision on the fresh arm, 0.892, which is near
  the mark.
- **L1H v4.1** (pooled recall 0.913, FP 3.04 %): accepted by the user as near the marks; opt-in.
- L1 v15 on the tenth untouched TensorTrust split: recall 0.930, NotInject 2.06 %, within the user's tolerance.
- L2 v8 (default): every row of the eleventh untouched draw except Dutch recall 0.919 and translated-benign Chinese /
  Dutch 4.35 % / 2.08 %, accepted as manageable.
- L3 on tom-gibbs.
- L4's attack stopping on InjecAgent and AgentDojo (declining user; v12 benign tasks prompted 4.1 %).
- **L5 when the operator declares a field policy or a task-policy library** (fresh TEST: recall 0.997 - 1.000, FP
  3.85 %).
- L6 v3.4 (fresh local-agent TEST5: recall 0.972, FP 0 / 227, precision 1.000).

**Still below the project's mark** (recall ≥ 0.92 at ~1.7 % false positives per row, and no other weak metric), each
with its logged root cause in [`results.md`](results.md):
- **Harm**:
  - **Input side, closed:** L1H v4.1, a request-harm read on the shared 4B (§32.6), reaches pooled recall 0.913, FP
    3.04 %, precision 0.964 and AUROC 0.989 at 221 ms. StrongREJECT and SST recall are 0.837 / 0.840. The user accepted
    it as near the marks; it is opt-in (`L1_HARM_LOCAL`) and not part of the measured system.
  - **Reply side, closed at the measured frontier and not pursued further** (user decision 2026-11-20, §35; v6 /
    v6.1 / v6.2, §31.4 - §31.6): within one dataset the read
    separates harm (VAL recall at 4 % FP 0.85 - 0.97). The datasets' harm policies, though, need different thresholds,
    and no single threshold, cluster calibration or nonlinear head serves them all.
- **L3 on MHJ: the marks are met, with caveats** (§39.1, §39.6).
  - **Why it was hard:** 53 of the 110 test attacks show no harmful intent in the user's turns, so an input-only
    detector is capped near recall 0.5 (§29). v4's reply check reads the protected model's replies to close that half.
  - **Caveats:** at the judge's pre-registered t = 0.9 only 2 Attack_600 and 11 MHJ replays count as breached; at
    t = 0.5 recall is 0.756 / 0.726. In a live deployment the reply check adds 489 ms per real reply (not measured
    end to end), and protecting a model other than the local 4B needs its own reply-threshold calibration.
  - **A shortcut risk (§39.8):** outside the test split, the probe BLOCKs 4 of 60 templated synthetic benign
    DIDA-Bench conversations (2.0 % of all 200 benign; the gated rows read 0). The fix direction is a v4.4 with
    templated benign negatives and a fresh TEST.
- **L5 without any policy**: closed at the design limit (§33.6) and not pursued further (user decision 2026-11-20,
  §35).
  - AgentLeak's leak label is a per-task policy, and the same field is allowed by one task's policy and forbidden by
    another's.
  - The best design point is recall 0.929 at FP 7.1 %. With a declared policy or the task-policy library, L5 meets
    the mark.
- L4 on Agent Security Bench's legitimate prompts (13 %: the two genuine write tools, held by design); L2's
  three accepted residual rows.
- **The whole system**: FINAL + L3 v4.3 meets every mark strictly (§39.6). The earlier FINAL run (§27.3) missed only
  any-alarm precision on arm v2 (0.892); on the fresh arm v3s FINAL reads 0.951.

---

<a id="what-it-does"></a>

## 🎯 The attack it was built for

> A user asks their AI assistant to *summarize a report and email it to a colleague*.
>
> 1. The retrieved report contains one sentence that looks like formatting advice. It is really a hidden instruction to forward the summary to an outside address.
> 2. Later, the assistant makes an email call whose recipient matches nothing the user typed.
>
> Neither event alone looks bad enough to block. Together, they're data exfiltration.

LLM apps now read documents, call tools and hold long conversations. That gives an attacker four doors: **the prompt, a poisoned document, a hijacked tool output, and a slow multi-turn escalation**. The industry answer is to stack guardrails. DIDA builds that stack properly, then **tests the premise instead of assuming it**.

---

<a id="results"></a>

## 📊 Results

### 🤖 Defending a live AI agent (AgentDojo)

A real Gemini agent doing real tasks (email, banking, travel, Slack) while attackers plant instructions in its tool outputs. 68 attack scenarios and 34 benign tasks; every pipeline ran every episode.

| Pipeline | Attack success ↓ | Task success under attack ↑ | Task success, no attack ↑ |
|---|:---:|:---:|:---:|
| No defense | 0.588 | 0.529 | 0.853 |
| AgentDojo's built-in detector | 0.015 | 0.206 | 0.471 |
| **DIDA, tool-call check only** | **0.103** | **0.574** | **0.853** |
| **DIDA, full** | **0.044** | 0.309 | 0.794 |

> ✅ **The tool-call check alone cuts attacks about 6× and keeps benign task success exactly the same.**
> The full defense stopped 37 attacks and enabled none (p < 10⁻⁶). AgentDojo's own detector gets its low number by breaking **13 of 34** benign tasks.

### 🧱 Every layer, shipped configuration (paper era, September 2026)

> For the current shipped defaults and their numbers on fresh test draws, see [Since the paper](#since-the-paper). The L2 row below is the scorer that is now the fail-soft fallback.

| Layer | Stops | Benchmark | Result |
|---|---|---|---|
| **L1** injection | prompt injection | TensorTrust (570 attacks) | recall **0.875** |
| | | NotInject / Alpaca (benign) | false positives **3.5% / 0.5%** |
| **L1H** harm intent | jailbreaks hidden in roleplay | WildJailbreak (2,210) | AUROC **0.952**, recall 0.738 @ 4.3% FPR |
| **L2** documents | poisoned retrieval | BIPIA | AUROC **0.928**; held-out recall **0.636** @ **1.3%** FPR |
| **L3** multi-turn | slow-burn and cipher jailbreaks | tom-gibbs (5,336) | AUROC **0.996**, recall 0.984, **0 false positives** |
| **L4** tool calls | agent hijacking | InjecAgent | recall **1.000**, **0 false positives** |
| **L5** output | data leakage | AgentLeak (5,006) | AUROC **0.888** |
| **Pipeline** | multi-vector attacks | DIDA-Bench | **91.5%** blocked, **0** false positives |

### 🔧 What the engineering bought

Each row is a measured root cause and a repair, not a threshold tweak.

| Problem found | Before | After |
|---|:---:|:---:|
| Harmful intent hidden in roleplay (WildJailbreak AUROC) | 0.574 | **0.952** |
| Cipher-encoded multi-turn jailbreaks (tom-gibbs AUROC / FPR) | 0.755 / 10.2% | **0.996 / 0%** |
| Poisoned documents (BIPIA AUROC) | 0.719 | **0.928** |
| Poisoned documents (BIPIA held-out recall @ FPR) | 0.148 @ 4.0% | **0.636 @ 1.3%** |
| Agent hijacking, trace replay (attack execution per suite) | 0.59 / 1.00 / 0.45 / 0.41 | **0.00 / 0.20 / 0.02 / 0.00** |
| Tool-call false alarms on benign agent traffic | 56% of calls | **2–20%** by suite |
| Injection false positives on trigger-word prompts (NotInject) | 11.5% | **3.2%** (judge off) |
| Full-pipeline blocking on DIDA-Bench (0 false positives) | 69.5% | **91.5%** |

### 🥊 Against third-party guards

| | Llama Guard 3 (1B) | ProtectAI DeBERTa v2 | DIDA |
|---|:---:|:---:|:---:|
| WildJailbreak AUROC | 0.814 | 0.653 | **0.952** |
| Multi-turn attacks (MHJ vs. real chats), AUROC | 0.682 | 0.566 | 0.682 (L3); 0.954 (probe, not shipped) |
| Certified sub-threshold sessions caught (SPLIT-Bench v1) | 1 / 340 | 0 / 340 | **265 / 340** (L3) |
| TensorTrust recall | 0.588 | **0.970** | 0.875 |
| False positives on NotInject | 7.4% | 43.4% | **3.5%** |

ProtectAI wins TensorTrust at its default threshold, but it flags 43% of benign trigger-word prompts. Held to DIDA's false-positive rate, its recall falls to 0.779.

---

<a id="research"></a>

## 🔬 The research: do layered defenses compose?

Short answer: **not the way the industry assumes.**

| # | Finding | Evidence |
|:---:|---|---|
| 1 | **Threshold fusion is provably blind** to an attacker who keeps every layer under its threshold | The correlation engine fired **0 times** on SPLIT-Bench v1 (680 sessions) and v2 (510), whose sessions carry machine-checked sub-threshold certificates |
| 2 | **Apparent cross-layer wins are single layers in disguise** | The only mechanism that detected anything, a pattern miner (\|U\| 0.7794 / 0.6706), equals one layer's zero-false-positive ceiling *exactly* |
| 3 | **Valid fusion can't beat the best layer** without assuming independence | An anytime-valid e-process detects a set **identical** to one layer's (Jaccard 1.0000). A learned alarm ranks attacks at AUROC 0.974 but can't operate within a 2% false-alarm budget |
| 4 | **Pipelines destroy evidence at their interfaces** | A four-check audit found **7** such points in DIDA. Llama Guard's safe/unsafe verdict turns an AUROC-0.714 ranking into a single bit (0.500) |
| 5 | **It's not just our system** | Replicated on LLM Guard + Llama Guard 3 with a corpus certified against *that* stack: the deployed rule catches **0/107**, dependence-robust fusion **0**, independence-assuming fusion **10**, exactly as predicted |
| 6 | **More layers can mean more places to hide** | 66.7–85.2% of DIDA's headroom is undefended against a distributed attacker (37.4% on the third-party stack) |

The math is classical: decision fusion, and Vovk and Wang's e-merging. The contribution is turning it into **checks an engineer can run on a real guardrail stack**, and measuring two stacks against them.

---

<a id="contributions"></a>

## 🧬 What sets DIDA apart: contributions A–M

Most guardrail projects ship detectors. DIDA also ships the machinery to **prove what a stack of detectors can and cannot catch**, and to measure it. A–H are the paper's contributions; their letters match the code and the released artifacts. I–M came after the paper (October–November 2026) and are not in it yet; the code names them by layer and flag.

### Cross-layer mechanisms

| | Contribution | What it does | Measured |
|:---:|---|---|---|
| **A** | **Taint-propagation graph** | Turns a session into a provenance graph (turns → retrieved chunks → tool arguments) and propagates trust along it: `taint(u,v) = 1 − w·(1 − trust(u))`. Flags high-impact calls fed by low-trust content even when no single layer fired. | Fires on exactly the same 7 held-out real attack sessions as the hand-coded RAG-plus-agent rule: it generalizes the rule rather than replacing it *(earlier configuration)*. Today (FINAL + L3 v4.3, results.md §39.8): the rule fires on 150 / 375 DIDA-Bench attacks and the taint path on 75, every taint firing is also a rule firing, and rules without any layer add 0 recall |
| **B** | **Cost-aware sequential triage** | Runs layers as a Wald sequential test (SPRT) and stops as soon as the evidence is decisive, instead of always paying for all five layers. | Accuracy 0.9554, precision 1.0, recall 0.9153, 0 false positives; attacks are decided after **~3.4 of 5 layers** *(earlier configuration)*. Today (§39.8): recall 59 / 59 and 0 / 53 false positives on the test split, 2.78 of 5 layers consulted on average (attacks 1.54) |
| **C** | **Correlation-pattern mining** | Mines attack-chain patterns from labeled cross-layer event sequences (PrefixSpan-style) instead of hand-writing rules. | Recall **1.0000** on attack-chain types never seen in training (0.8841 on known types), FPR 0.0667 *(earlier configuration)*. Today (§39.8): held-out chain types 1.000, known types 0.957, benign FP 0.117 (7 / 60); the top pattern is L1 alone |
| **D** | **Conformal risk control for false positives** | Sets each threshold with split-conformal calibration on benign data, so the false-positive rate carries a distribution-free guarantee: `k = ⌈(n+1)(1−α)⌉`. | Holds on fresh same-source traffic (0/500 at α = 0.01) and is **shown to break** under shift (14.8% on WildJailbreak's benign set). The failure is reported, not hidden |

### The theory and the measurement kit

| | Contribution | What it does | Measured |
|:---:|---|---|---|
| **E** | **Detectability bound** | Proves that any detector reading only threshold crossings has **zero power** against an attacker who keeps every layer sub-threshold, and turns that into a prediction you can check (\|U\| = 0 on a certified corpus). | The correlation engine fired **0 times** on 510 certified attacks; the one detector that "beat" the bound turned out to be reading a lower threshold, exactly as the corollary says |
| **F** | **Anytime-valid e-value fusion** | Fuses layer scores across layers and turns with e-values: false alarms stay controlled under *any* dependence between layers, at any stopping time. | Recovers exactly the best single layer (Jaccard **1.0000** on both corpora), proving the price of validity. Assuming independence instead catches **10/107**, 9 of which no single layer catches. On SPLIT-Bench v3 against today's DIDA (§39.3) the mean merge detects 0 / 340 and the product 23 / 340, none of them unique |
| **G** | **SPLIT-Bench, certified sub-threshold corpora** | Generates attack sessions with a **machine-checked certificate** that every layer stays under its threshold while ≥ k layers carry real signal. Certificates are re-verified at import. | 680 sessions (v1) and 510 (v2) against DIDA, plus 447 (SPLIT-S2) against a third-party stack. Hardening DIDA made **0 of 4,080** three-layer attacks certifiable. **v3 against today's DIDA** (§39.3): k=2 certified 170 / 348, k=3 170 / 2,480. Validity limit: L1 / L3's carrier band overlaps benign text. A v3.1 rebuild with benign-relative carriers against FINAL + L3 v4.3 is in progress: calibration 190 / 200, stopped 2026-11-27 08:16 and resumable (results.md §39.9) |
| **H** | **Threshold-aware adversary and capacity sweep** | Models the attacker who knows every threshold and computes how much attack signal the stack lets them hide (*effective capacity*). | Every budget up to the capacity (3.002) fits under all thresholds; the first that doesn't is 3.040. 66.7–85.2% of that capacity is undefended. A fusion-aware variant is still certified at a 0.72 rate. On v3 (§39.5) the fusion-aware adversary is still certified at 0.227 (per-layer 0.489), and 79.2 % of the capacity is undefended |

> **Why this matters:** A–D are the cross-layer tricks people usually reach for. E–H explain where each one stops: three of the four reduce to a single layer on certified attacks, exactly as E predicts. That gives you a way to test *your own* guardrail stack before trusting it.

### Since the paper: per-layer contributions I–M

| | Contribution | What it does | Measured (fresh test draws, each read once) |
|:---:|---|---|---|
| **I** | **Action authorization at the tool boundary** | Each tool call is checked against an intent contract (which actions the user asked for, with which values), the lineage of every argument (the user, a system of record, or document text) and a trust matrix per argument class. A fully local profile writes the contract with the local Qwen3-4B. Includes a named-source rule and an operator capability registry. | AgentDojo held out, effect-level replay: **0 / 398** attacks with an effect when the user declines unexpected confirmations; benign tasks prompted **4.1%**. InjecAgent 100% stopped, 0 / 34 benign held; Agent Security Bench 99.5% stopped *(results.md §16–§17, §25)* |
| **J** | **Policy-conditioned residual probe for documents** | A 4-bit local Qwen3-4B reads each document under a written document policy. A linear probe on its residual stream decides, with split-conformal thresholds per content type, a translated view for non-English text and windowed reads for long documents. | Eleventh untouched draw: recall **0.959**, FP **1.10%**, precision **0.992**, AUROC **0.996**, 0.92 s per document; BIPIA **0.969** *(results.md §20–§22)* |
| **K** | **Answer-provenance guard (L6)** | The final answer may not repeat an identifier or a 6-word run that first entered the session through third-party data, using first-seen taint over structured spans of YAML / JSON records. It catches injected content relayed to the user, which no tool-call check sees. | The local 4B as the AgentDojo agent: recall **0.972**, FP **0 / 227**, precision **1.000**, 3.2 ms. 13 published agents: recall **0.997**, FP **0.14%**, precision **0.982** *(results.md §26)* |
| **L** | **Task-policy library for output disclosure (L5)** | L5 does not guess which record fields are private. It enforces a per-task allowed-field policy, declared by the operator or matched by similarity from a library of task types, and matches the other fields' values exactly. | Fresh AgentLeak test (a local model's outputs on unseen scenarios): recall **0.997**, FP **3.85%**, precision **0.995** *(results.md §24)* |
| **M** | **Label-agreement audit before a harm gate** | Before blaming a detector, measure the labels and score the reference judges stored with the benchmark on the same items. A gate stricter than human agreement cannot be read. | WildGuardTest labels (Fleiss kappa 0.50) put a single human annotator at recall 0.850 / FP 7.4% against the majority. On human-consensus items no stored judge (GPT-4, Llama-3-70B, HarmBench's 13B classifier) meets a 0.92 / 4% gate *(results.md §28)* |

The layer upgrades behind the final system run, the fully local L1 v15 stack and the L1H v4.1 request-harm read, are listed in [Since the paper](#since-the-paper).


<details>
<summary><b>Where each contribution lives in the code</b></summary>

| | Code |
|:---:|---|
| A | `sentinel/core/taint_graph.py` |
| B | `sentinel/core/sequential_triage.py`, `sentinel/eval/sprt_eval.py` |
| C | `sentinel/core/pattern_mining.py`, `sentinel/eval/pattern_mining_eval.py` |
| D | `sentinel/core/conformal_risk_control.py`, `sentinel/eval/conformal_l1_eval.py` |
| E | `SENTINEL_CONTRIBUTION_E_THEORY.md`, `sentinel/eval/run_phase4_ablation.py` |
| F | `sentinel/core/evidence_fusion.py`, `sentinel/eval/eprocess_eval.py` |
| G | `sentinel/eval/split_bench.py`, `sentinel/eval/second_stack.py` |
| H | `sentinel/eval/split_attack.py` |
| I | `sentinel/layers/layer4_agentic/authz/`, `sentinel/layers/layer4_agentic/action_policy.py` |
| J | `sentinel/layers/layer2_rag/local_detector.py`, `sentinel/layers/layer2_rag/translate_view.py`, `sentinel/core/local_judge.py` |
| K | `sentinel/layers/layer6_answer/answer_guard.py` |
| L | `sentinel/core/policy_library.py`, `sentinel/layers/layer5_output/layer5.py` |
| M | `results.md` §28 (the analysis and its numbers) |

</details>

---

<a id="architecture"></a>

## 🏗️ Architecture

```mermaid
flowchart LR
    P([User prompt]) --> L1["<b>L1</b> · injection tiers<br/>+ separate harm head"]
    D([Retrieved docs /<br/>tool output]) --> L2["<b>L2</b> · local document detector<br/>(scorer as fallback)"]
    C([Conversation]) --> L3["<b>L3</b> · drift + velocity<br/>+ cipher decoder"]
    T([Tool call]) --> L4["<b>L4</b> · action authorization<br/>contract + lineage + trust matrix"]
    O([Model output]) --> L5["<b>L5</b> · PII / exfil /<br/>canary / leak check"]

    L1 & L2 & L3 & L4 & L5 --> BUS[("Threat Intelligence Bus<br/>per-session evidence")]

    BUS --> CE["Correlation engine<br/>hand-coded rules + taint graph"]
    BUS --> FU["Score fusion<br/>e-process · learned alarm"]
    BUS --> DB["Live dashboard"]
```

| Layer | How it works |
|---|---|
| **L1** | Regex → semantic templates → Prompt Guard × PIGuard (an AND, which kills trigger-word false positives) → an optional policy judge (gpt-oss-safeguard-20b). Plus a **separate** harm-intent head (Qwen3Guard): fusing it in with `max()` measurably hurt both signals. |
| **L2** | **Default (since 2026-11-03):** a local document detector. A 4-bit Qwen3-4B reads each document under a document policy; a linear probe on its residual stream decides against split-conformal thresholds per content type, with code and prose routed to separate probes, an extra translated-to-English reading for non-English prose segments, windows for long documents and an unhidden reading for hidden-character text. **Fallback** (no local model, or `L2_LOCAL_DETECTOR=off`): Prompt Guard's *injection* head over overlapping segments plus a dangerous-code indicator, with Mondrian split-conformal anchors per content type; short text scored by PIGuard. |
| **L3** | Alignment, cumulative drift and velocity over sentence windows. For substitution-cipher jailbreaks it reverse-substitutes the conversation and scores the **decoded goal** instead of the encoding. |
| **L4** | Every tool has a capability class. **Action authorization** (`L4_AUTHZ`, default since 2026-10-23): an intent contract records which actions the user asked for and with which values; every argument's lineage is traced (the user, a system of record, or document text) and checked against a trust matrix per argument class, so a payee or recipient that only a document supplies needs the user's confirmation or is refused. The **addressee check** asks whether the text around a copied value is *talking to the AI*. A fully local profile writes the contract with the local model. |
| **L5** | PII and exfiltration patterns, canary tokens (including base64), and a provenance leak check that reuses L4's tracing on the output. |

🎚️ Thresholds are **split-conformal, calibrated on benign data only**, so the false-positive rate is guaranteed on traffic like the calibration set. We also report where that guarantee breaks across corpora.

---

## ✨ Engineering highlights

| | |
|---|---|
| 📜 **Certified benchmarks** | A SPLIT-Bench sample is accepted only if a machine-checked certificate proves every layer is under its threshold while at least *k* layers carry signal. Certificates are re-verified at import. |
| 🕵️ **Suspicious of good numbers** | Seven harness defects were caught by treating plausible results as suspect. Examples: a leak benchmark that shared one session across samples (AUROC 0.53 → 0.89 once fixed), and an agent framework that counted an overloaded API as a *successful attack*. |
| 🔒 **Pre-registered gates** | Candidate improvements were adopted only if they passed a gate written before the held-out data was scored. Several failed, and they're reported as failures. |
| 💻 **Runs on a laptop** | Qwen3Guard and Llama Guard run on a 4 GB GPU via split-device placement, matching CPU scores to within 5×10⁻⁶. With the judge off, the whole defense runs locally. |
| 🗂️ **Every run recorded** | Each evaluation saves its full configuration snapshot, indexed in `sentinel/eval/results/LEDGER.jsonl`. |

---

<a id="quick-start"></a>

## 🚀 Quick start

```bash
pip install -r requirements.txt           # the proxy
cp .env.example .env                      # optional API keys (see below)
python main.py                            # proxy + live dashboard → http://localhost:8080
```

- **Python 3.10+.** A GPU is optional.
- **Local models (optional, recommended):** the default L2 document detector uses `Qwen/Qwen3-4B-Instruct-2507` in 4-bit (~2.9 GB of GPU memory) and, for the translated reading, `Helsinki-NLP/opus-mt-mul-en` in `~/.cache/sentinel/mt/opus-mt-mul-en`. Without them L2 falls back to the earlier scorer (fail soft); `L2_LOCAL_DETECTOR=off` restores that path explicitly.
- **Small GPUs:** on a card under 8 GB with a local model configured, the 4B model keeps the GPU and the Qwen3Guard harm head and small classifiers run on the CPU (`SENTINEL_GUARD_DEVICE=auto`, `SENTINEL_CLASSIFIER_DEVICE=auto`; CPU and GPU scores are parity-tested, so only latency changes). Measured on a 4 GB laptop GPU: putting everything on the card spilled 1.4 GB into shared system memory and slowed the document path about 4x. Set either variable to `cuda` to override. Measured harm-head latency per prompt: ~0.1 s on the GPU, ~1.1 s mean / 1.7 s p95 on the CPU, where the guard runs on its own 8-thread worker (`SENTINEL_GUARD_THREADS`) while every other model keeps one thread (`SENTINEL_TORCH_THREADS`, default 1; torch's own pool crashed the full test suite, results.md §21.5.1).
- **Gated models:** Prompt Guard and Llama Guard 3 need their Hugging Face licences accepted (`huggingface-cli login`).
- **Optional keys:**
  - `GROQ_API_KEYS` enables L1's policy judge and L4's hosted intent contract. For a fully local defense set `L1_LLM_JUDGE_ENABLED=false` and either `L4_AUTHZ_CONTRACT=lexicon`, or the measured local L4 profile: `L4_AUTHZ_CONTRACT=local L4_ALIGNMENT_LOCAL=true L4_AUTHZ_TARGET_CRITERIA=true L4_AUTHZ_CONTENT_LINK_CONFIRM=true L4_COPIED_CONTENT_CONFIRM=true L4_AUTHZ_LOCAL_DELEGATION=true` ([`results.md`](results.md) §20.17).
  - `GEMINI_API_KEYS` is used only by the live AgentDojo harness and the benign-data audit.

### 🔌 Core endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/sentinel/chat` | screen user input |
| `POST` | `/sentinel/rag/ingest` | screen a document before retrieval |
| `POST` | `/sentinel/agent/tool_call` | authorize a tool call before it runs |
| `POST` | `/sentinel/agent/tool_response` | scan a tool output |
| `POST` | `/sentinel/output/scan` | scan a model response |
| `WS` | `/ws/events` | live event stream |

---

<a id="reproduce"></a>

## 🧪 Reproducing the results

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

## 📁 Repository layout

```
main.py                    entry point
sentinel/                  the DIDA package (directory keeps the project's original name)
├── app.py                 FastAPI proxy and WebSocket
├── config.py              every threshold and feature flag, shipped defaults documented inline
├── core/                  threat bus, correlation, taint graph, e-value fusion, conformal calibration,
│                          addressee cues, split-device GPU placement, local judge (Qwen3-4B),
│                          artifacts/ (probe artifacts for L1 / L2)
├── layers/                L1 · L2 (layer2_rag/) · L3 · L4 (layer4_agentic/) · L5 (layer5_output/)
└── eval/                  harness, dataset loaders, SPLIT-Bench generator + certificates,
    └── data/              live AgentDojo, guard baselines, second-stack audit; our benchmarks
dashboard/static/          real-time monitoring dashboard
results.md                 the complete lab log
```

Third-party corpora (AgentDojo, InjecAgent, BIPIA, AgentLeak, WildJailbreak, MHJ, tom-gibbs, OR-Bench, WildChat, OpenAssistant) are fetched from their sources by `sentinel/eval/dataset_loaders.py` and are not redistributed. Neither is any corpus containing real users' conversation text.

---

<div align="center">

**Built by Gokul Iyer**

</div>
