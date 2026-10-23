"""
Build the training corpus for ADR, the ADDRESSEE model (scratch/rca/v3/RCA_AND_PLAN.md, Phase 2).

THE QUESTION ADR ANSWERS. Is this piece of text addressed TO AN AI SYSTEM as a request, or is it
written for a person (an e-mail asking a colleague for a file, an answer telling the reader what to
run, a news story)? An indirect prompt injection is, by definition, third-party data that addresses
the model; data written for people almost never does. Every injection classifier available to DIDA
(PIGuard, Prompt Guard, ProtectAI, the L1 stack) scores instructions for a human like instructions
for the AI (R-031: both ~0.999), which is the root cause behind five weak rows (v3 F3).

VERSION 2 (2026-10-18), AFTER A MEASURED FAILURE OF VERSION 1. v1 was trained on benign
conversations only (prompts vs replies/news). It passed its in-distribution gate (dev AUROC 0.954,
length control 0.505) and FAILED where it matters: BIPIA-train selection doc recall @1 % FPR 0.09,
and on hand-written probes (scratch/rca/v3/b02_adr_probe.py) it scored injection phrasing ~0
("Ignore everything you were told..." 0.04, "Note to the assistant: ..." 0.003, "[ADMIN NOTE: ...]"
0.000) while scoring human questions ~1 ("How do I fix ...?" 1.000). It had learned "this looks
like a ChatGPT task", not "this addresses the AI": ordinary prompts never contain the meta-
instructions, authority claims and tool directives injections are made of, and human questions
look exactly like prompts. v1's artifact is kept in scratch/rca/v3/ for the record.

v2 therefore teaches the concept directly, still WITHOUT any evaluation benchmark:
  label 1 (directs an AI system): prompts people wrote to an assistant (Alpaca `instruction`,
      WildChat user turns, WildGuardMix unharmful prompts) AND public prompt-injection / jailbreak
      ATTEMPTS that are in no paper benchmark -- Lakera gandalf_ignore_instructions (train), Lakera
      gandalf_summarization (train; injections hidden inside "text to summarise"), Lakera mosscap
      (train; authority claims, role-play, meta-instructions), deepset prompt-injections (train,
      label 1), WildGuardMix adversarial prompts (jailbreak wrappers).
  label 0 (written for a person, or plain data): the assistant's replies, WildGuardMix responses,
      Alpaca `input`, XSum news (validation) -- and the HARD NEGATIVES v1 lacked, requests addressed
      to PEOPLE: e-mails, Q&A and tables from BIPIA's TRAIN contexts (md5-even half only; the odd
      half is the selection set, BIPIA TEST is never touched) and e-mails / messages the assistant
      drafted for users (WildChat replies that open like a letter).

EXCLUSIONS, so no evaluation or calibration set leaks in:
  * Alpaca: only the md5 "train" partition (dataset_loaders._load_alpaca puts md5(text) % 100 < 20
    in "test"; L1's conformal anchor and every Alpaca FPR row are drawn from that test partition).
  * WildChat shard 0: every conversation used by the L3 benign arms (scratch/trackB/data/wildchat_*,
    wildchat_sens_*) and by the benign pipeline arm (bpa_wccode_*) is excluded by hash.
  * News: XSum VALIDATION only (L2's short-bin anchor uses XSum/NewsQA TRAIN; BIPIA's contexts are
    XSum TEST and NewsQA VALIDATION).
  * BIPIA: TRAIN contexts only, md5(context)-even half (the odd half + BIPIA's train attacks are
    fit_addressee_model's selection set); BIPIA attacks and BIPIA TEST are never trained on.
  * Lakera / deepset: TRAIN splits only (their validation / test splits are selection checks).
  * Nothing from OASST, MHJ, tom-gibbs, AgentDojo, InjecAgent, TensorTrust, NotInject,
    sentinel_bench or SPLIT-Bench.

UNIT = the window ADR scores at inference: sentence windows from core.text_windowing (20-300 chars).
Prompts longer than 300 chars are skipped rather than windowed (a long prompt is mostly pasted data,
not the request). LENGTH CONTROL (check C3): the two classes are subsampled per 25-char length bin to
identical histograms, so length alone cannot separate them (fit_addressee_model reports the control).

    python -I -m sentinel.eval.build_addressee_corpus [--per-class 24000] [--seed 20261018]
writes sentinel/eval/data/addressee/{train,dev}.jsonl (+ stats.json); dev = md5(text) % 10 == 0.
"""
from __future__ import annotations

import argparse
import collections
import glob
import hashlib
import json
import random
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "sentinel" / "eval" / "data" / "addressee"
HUB = Path.home() / ".cache" / "huggingface" / "hub"
MIN_CHARS, MAX_CHARS, BIN = 20, 300, 25

_CODEY = re.compile(r"```|^\s*(def |class |import |#include|public |function |const |let |var )|[{};]\s*$",
                    re.M)


def _md5(s: str) -> int:
    return int(hashlib.md5(s.encode("utf-8")).hexdigest(), 16)


def _parquet(pattern: str):
    import pandas as pd
    paths = glob.glob(str(HUB / pattern))
    if not paths:
        raise SystemExit(f"missing local dataset: {pattern} (expected in the Hugging Face cache)")
    return pd.read_parquet(paths[0])


def _windows(text: str) -> list[str]:
    from sentinel.core.text_windowing import split_into_windows
    return [w for w in split_into_windows(text or "") if MIN_CHARS <= len(w) <= MAX_CHARS]


def _ok_prompt(t: str) -> bool:
    t = (t or "").strip()
    return MIN_CHARS <= len(t) <= MAX_CHARS and not _CODEY.search(t)


def _excluded_wildchat() -> set[str]:
    """12-char conversation-hash prefixes of every WildChat conversation an evaluation uses."""
    used: set[str] = set()
    for f in glob.glob(str(ROOT / "scratch" / "trackB" / "data" / "wildchat*.jsonl")):
        for line in open(f, encoding="utf-8"):
            sid = json.loads(line).get("sample_id", "")
            used.add(sid.split("_", 1)[-1][:12])
    arm = ROOT / "sentinel" / "eval" / "data" / "benign_pipeline_arm" / "test.jsonl"
    if arm.exists():
        for line in open(arm, encoding="utf-8"):
            sid = json.loads(line).get("sample_id", "")
            if sid.startswith("bpa_wccode_"):
                used.add(sid[len("bpa_wccode_"):][:12])
    return used


def collect() -> list[dict]:
    rows: list[dict] = []

    def add(text, label, source):
        text = re.sub(r"\s+", " ", (text or "")).strip()
        if MIN_CHARS <= len(text) <= MAX_CHARS:
            rows.append({"text": text, "label": label, "source": source})

    # Alpaca, train partition only (see the module docstring)
    a = _parquet("datasets--tatsu-lab--alpaca/snapshots/*/data/*.parquet")
    for ins, inp, out in zip(a["instruction"], a["input"], a["output"]):
        key = f"{ins}\n{inp}".strip() if inp else ins
        if not key or _md5(key) % 100 < 20:
            continue
        if _ok_prompt(ins):
            add(ins, 1, "alpaca_instruction")
        if inp:
            for w in _windows(inp):
                add(w, 0, "alpaca_input")
        for w in _windows(out):
            add(w, 0, "alpaca_output")

    # WildChat shard 0, English, not redacted, minus every conversation an evaluation uses
    excl = _excluded_wildchat()
    w = _parquet("datasets--allenai--WildChat-1M/snapshots/*/data/train-00000-of-00014.parquet")
    w = w[(w.language == "English") & (~w.redacted)]
    for h, conv in zip(w["conversation_hash"], w["conversation"]):
        if h[:12] in excl:
            continue
        for m in conv:
            role, content = m.get("role"), (m.get("content") or "").strip()
            if role == "user":
                if _ok_prompt(content):
                    add(content, 1, "wildchat_user")
            elif role == "assistant":
                # e-mails / messages the assistant drafted FOR the user address a PERSON: their own
                # source, so the per-source cap does not dilute these hard negatives (v2)
                src = "wildchat_drafted_letter" if _LETTER.search(content[:200]) else "wildchat_assistant"
                for win in _windows(content):
                    add(win, 0, src)

    # WildGuardMix train: unharmful prompts (label 1), responses (label 0)
    g = _parquet("datasets--allenai--wildguardmix/snapshots/*/train/wildguard_train.parquet")
    for p, adv, lab, resp in zip(g["prompt"], g["adversarial"], g["prompt_harm_label"], g["response"]):
        if lab == "unharmful" and isinstance(p, str):
            t = p.strip()
            if MIN_CHARS <= len(t) <= 400 and not _CODEY.search(t):
                rows.append({"text": re.sub(r"\s+", " ", t), "label": 1,
                             "source": "wgm_adversarial" if adv else "wgm_vanilla"})
        if isinstance(resp, str):
            for win in _windows(resp):
                add(win, 0, "wgm_response")

    # XSum VALIDATION news (label 0)
    x = _parquet("datasets--EdinburghNLP--xsum/snapshots/*/data/validation-*.parquet")
    for doc in x["document"]:
        for win in _windows(doc):
            add(win, 0, "xsum_validation")

    # --- v2: requests addressed to PEOPLE (label 0) -------------------------------------------
    # BIPIA TRAIN contexts, md5-even half (e-mails, Stack-Overflow-style Q&A, tables)
    for ctx in bipia_train_contexts():
        if _md5(ctx) % 2 == 0:
            for win in _windows(ctx):
                add(win, 0, "bipia_train_context_even")
    # (drafted e-mails / messages: tagged in the WildChat loop above)

    # --- v2: attempts to direct an AI system (label 1), public, in no paper benchmark ----------
    for t in _parquet("datasets--Lakera--gandalf_ignore_instructions/snapshots/*/data/train-*.parquet")["text"]:
        add(t, 1, "lakera_gandalf_ignore")
    for t in _parquet("datasets--Lakera--gandalf_summarization/snapshots/*/data/train-*.parquet")["text"]:
        for win in _windows(t):
            add(win, 1, "lakera_gandalf_summarization")
    mos = _parquet("datasets--Lakera--mosscap_prompt_injection/snapshots/*/data/train-*.parquet")["prompt"]
    for t in mos:
        if isinstance(t, str) and _mostly_ascii(t):
            add(t, 1, "lakera_mosscap")
    dp = _parquet("datasets--deepset--prompt-injections/snapshots/*/data/train-*.parquet")
    for t, lab in zip(dp["text"], dp["label"]):
        if str(lab) == "1" and isinstance(t, str) and _mostly_ascii(t):
            add(t, 1, "deepset_injection")
    # (WildGuardMix adversarial prompts enter whole, <= 400 chars, above. Their sentence WINDOWS are
    # deliberately not used: a role-play wrapper's narrative sentences are story, not address.)
    return rows


_LETTER = re.compile(r"^\s*(subject:|dear |hi |hello |hey |good (morning|afternoon|evening))|"
                     r"\b(best regards|kind regards|sincerely|warm regards|cheers,)", re.I | re.M)


def _mostly_ascii(t: str) -> bool:
    return bool(t) and sum(ch.isascii() for ch in t) / len(t) >= 0.95


def bipia_train_contexts() -> list[str]:
    """BIPIA TRAIN contexts (email, table, code); the table scenario stores rows as a list."""
    base = ROOT / "sentinel" / "eval" / "data" / "bipia_local"
    out = []
    for scen in ("email", "table", "code"):
        p = base / scen / "train.jsonl"
        if not p.exists():
            continue
        for line in open(p, encoding="utf-8"):
            if not line.strip():
                continue
            c = json.loads(line).get("context")
            if isinstance(c, list):
                c = "\n".join(str(x) for x in c)
            if isinstance(c, str) and c.strip():
                out.append(c)
    return out


def balance(rows: list[dict], per_class: int, seed: int) -> list[dict]:
    """Dedupe, cap each source, then length-match the classes bin by bin."""
    rng = random.Random(seed)
    seen, uniq = set(), []
    for r in rows:
        k = r["text"].lower()
        if k not in seen:
            seen.add(k)
            uniq.append(r)
    by_src = collections.defaultdict(list)
    for r in uniq:
        by_src[(r["label"], r["source"])].append(r)
    # each source contributes at most an equal share of its class, so no single corpus dominates
    pooled = {0: [], 1: []}
    for (label, _src), items in by_src.items():
        rng.shuffle(items)
        n_src = sum(1 for (l, _s) in by_src if l == label)
        pooled[label].extend(items[: max(1, (2 * per_class) // n_src)])
    bins = {lab: collections.defaultdict(list) for lab in (0, 1)}
    for lab in (0, 1):
        for r in pooled[lab]:
            bins[lab][min(len(r["text"]), MAX_CHARS) // BIN].append(r)
    out = []
    for b in sorted(set(bins[0]) | set(bins[1])):
        k = min(len(bins[0][b]), len(bins[1][b]))
        for lab in (0, 1):
            rng.shuffle(bins[lab][b])
            out.extend(bins[lab][b][:k])
    # trim to per_class each, keeping the matched histograms (uniform thinning across bins)
    res = []
    for lab in (0, 1):
        cls = [r for r in out if r["label"] == lab]
        rng.shuffle(cls)
        res.extend(cls[:per_class])
    rng.shuffle(res)
    return res


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--per-class", type=int, default=24000)
    ap.add_argument("--seed", type=int, default=20261018)
    a = ap.parse_args(argv)
    rows = collect()
    data = balance(rows, a.per_class, a.seed)
    OUT.mkdir(parents=True, exist_ok=True)
    split = {"train": [], "dev": []}
    for r in data:
        split["dev" if _md5(r["text"]) % 10 == 0 else "train"].append(r)
    for name, items in split.items():
        with open(OUT / f"{name}.jsonl", "w", encoding="utf-8") as f:
            for r in items:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
    stats = {
        "seed": a.seed, "per_class": a.per_class,
        "collected": {f"{l}:{s}": n for (l, s), n in
                      collections.Counter((r["label"], r["source"]) for r in rows).items()},
        "kept": {f"{l}:{s}": n for (l, s), n in collections.Counter((r["label"], r["source"]) for r in data).items()},
        "train": len(split["train"]), "dev": len(split["dev"]),
        "version": 2,
        "exclusions": "alpaca md5 test partition; WildChat hashes of trackB arms + benign pipeline arm; "
                      "XSum validation only; BIPIA train contexts md5-even only (no BIPIA attacks, no BIPIA "
                      "test); Lakera/deepset train splits only; no OASST/MHJ/tom-gibbs/AgentDojo/InjecAgent/"
                      "TensorTrust/NotInject/sentinel_bench/SPLIT",
    }
    (OUT / "stats.json").write_text(json.dumps(stats, indent=2), encoding="utf-8")
    print(json.dumps(stats, indent=2))


if __name__ == "__main__":
    main()
