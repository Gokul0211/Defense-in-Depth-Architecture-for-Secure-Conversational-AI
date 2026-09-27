# SENTINEL Evaluation Datasets

This directory contains all evaluation datasets used for benchmarking SENTINEL.

## Structure

```
data/
├── cache/                    # Cached downloads from HuggingFace
│   ├── tensortrust/         # TensorTrust injection prompts (L1)
│   ├── jailbreakbench/      # JailbreakBench jailbreak behaviors (L1)
│   ├── bipia/               # BIPIA indirect injection via documents (L2)
│   ├── injecagent/          # InjecAgent tool-call hijack (L4)
│   └── alpaca/              # Alpaca benign instructions (L1 FP baseline)
├── custom_l3/               # Generated multi-turn escalation corpus (L3)
│   ├── test.jsonl
│   ├── train.jsonl
│   ├── all.jsonl
│   └── metadata.json
├── custom_l5/               # Generated PII / canary corpus (L5)
│   ├── test.jsonl
│   ├── train.jsonl
│   ├── all.jsonl
│   └── metadata.json
├── sentinel_bench/          # SENTINEL-Bench multi-vector attack chains
│   ├── test.jsonl
│   ├── train.jsonl
│   ├── all.jsonl
│   ├── held_out.jsonl       # Held-out chains for generalization test
│   ├── mining_set.jsonl     # Non-held-out chains for pattern mining
│   └── metadata.json
└── README.md                # This file
```

## Benchmark Sources

| Dataset | Layer | Source | License | How to obtain |
|---------|-------|--------|---------|---------------|
| TensorTrust | L1 | [HuggingFace](https://huggingface.co/datasets/ethz-spylab/tensor_trust_data) | MIT | Auto-downloaded by `dataset_loaders.py` |
| JailbreakBench | L1 | [HuggingFace](https://huggingface.co/datasets/JailbreakBench/JBB-Behaviors) | MIT | Auto-downloaded by `dataset_loaders.py` |
| BIPIA | L2 | [HuggingFace](https://huggingface.co/datasets/AI-Secure/BIPIA) | Apache-2.0 | Auto-downloaded by `dataset_loaders.py` |
| InjecAgent | L4 | [HuggingFace](https://huggingface.co/datasets/anonymousauthors/InjecAgent) | MIT | Auto-downloaded by `dataset_loaders.py` |
| Alpaca | Benign | [HuggingFace](https://huggingface.co/datasets/tatsu-lab/alpaca) | CC-BY-NC-4.0 | Auto-downloaded by `dataset_loaders.py` |
| Custom L3 | L3 | Generated locally | Internal | `python -m sentinel.eval.generate_l3_corpus` |
| Custom L5 | L5 | Generated locally | Internal | `python -m sentinel.eval.generate_l5_corpus` |
| SENTINEL-Bench | Cross-layer | Generated locally | Internal | `python -m sentinel.eval.generate_sentinel_bench` |

## Generation Commands

```bash
# Generate L3 slow-burn escalation corpus (requires Groq API key)
python -m sentinel.eval.generate_l3_corpus --api-key $GROQ_API_KEY --n-attack 20 --n-benign 40

# Generate L5 PII / canary corpus (no API key needed)
python -m sentinel.eval.generate_l5_corpus --n-pii 200 --n-clean 300 --n-canary 50

# Generate SENTINEL-Bench multi-vector corpus
python -m sentinel.eval.generate_sentinel_bench --n-per-chain 75 --n-benign 200
```

## Licensing Notes

- **TensorTrust, JailbreakBench, InjecAgent**: MIT — redistribution allowed.
- **BIPIA**: Apache-2.0 — redistribution allowed with notice.
- **Alpaca**: CC-BY-NC-4.0 — non-commercial use only. If targeting a
  commercial venue, use a different benign corpus.
- **Custom corpora**: Internal to this project. If releasing SENTINEL-Bench
  publicly, release the generation scripts rather than the raw data to
  avoid redistributing derived benchmark content.

## Sample Format (JSONL)

Each line in a `.jsonl` file is a JSON object with:

```json
{
  "text": "The input/output text to evaluate",
  "label": "malicious|benign",
  "attack_type": "direct_injection|rag_poisoning|tool_hijack|...|none",
  "target_layer": "L1|L2|L3|L4|L5|all",
  "source_benchmark": "tensortrust|bipia|...|sentinel_bench",
  "sample_id": "unique_identifier",
  "metadata": { "...benchmark-specific fields..." }
}
```
