#!/usr/bin/env python3
"""
Parth's run queue (2026-11-22).

Runs every job below in order, one at a time. After each job, its results are saved in parth_results/<job>/ together
with a DONE file, so running this script again (after a crash, a closed lid or a restart) skips the finished jobs and
carries on. At the end everything is zipped into parth_results.zip: send that one file back.

    python parth_run.py           run, or resume, everything
    python parth_run.py --list    show the jobs and which are done
    python parth_run.py --redo    delete parth_results/ and start again

Nothing here needs a GPU, an API key or a downloaded dataset. The first job fetches one small public model
(sentence-transformers/all-MiniLM-L6-v2, about 90 MB) if it is not on the machine yet; every later job runs offline.
The two "regenerate" jobs rebuild a shipped benchmark, compare it byte for byte, then put the shipped files back, so the
repository is left exactly as it was.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import time
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "parth_results"
RESULTS = ROOT / "sentinel" / "eval" / "results"
PY = sys.executable
MINILM = "sentence-transformers/all-MiniLM-L6-v2"

OFFLINE_ENV = {"HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1", "TOKENIZERS_PARALLELISM": "false",
               "PYTHONUTF8": "1", "CUDA_VISIBLE_DEVICES": "", "SENTINEL_CLASSIFIER_DEVICE": "cpu"}


# --------------------------------------------------------------------------------------------- helpers
def say(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def run_cmd(cmd: list[str], log: Path, timeout_s: int, env_extra: dict | None = None) -> tuple[int | str, float]:
    """Run one command, its output to `log`. Returns (exit code or 'timeout', seconds)."""
    env = dict(os.environ, **OFFLINE_ENV, **(env_extra or {}))
    t0 = time.time()
    with log.open("w", encoding="utf-8") as fh:
        fh.write("$ " + " ".join(str(c) for c in cmd) + "\n\n")
        fh.flush()
        try:
            p = subprocess.run([str(c) for c in cmd], cwd=ROOT, env=env, stdout=fh, stderr=subprocess.STDOUT,
                               timeout=timeout_s)
            rc: int | str = p.returncode
        except subprocess.TimeoutExpired:
            rc = "timeout"
    return rc, round(time.time() - t0, 1)


def new_result_files(before: set[str], prefix: str) -> list[Path]:
    if not RESULTS.exists():
        return []
    return sorted(p for p in RESULTS.glob(f"{prefix}_*.json") if p.name not in before)


def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def hf_cached(repo_id: str) -> bool:
    try:
        from huggingface_hub import try_to_load_from_cache
        return isinstance(try_to_load_from_cache(repo_id, "config.json"), str)
    except Exception:                                                          # noqa: BLE001
        return False


# --------------------------------------------------------------------------------------------- jobs
def job_preflight(d: Path) -> dict:
    """Machine and library versions; the files this queue needs; the one public model (downloaded if missing)."""
    info = {"python": sys.version.split()[0], "platform": platform.platform(), "machine": platform.machine(),
            "cpu_count": os.cpu_count()}
    vers = {}
    for m in ("torch", "transformers", "sentence_transformers", "numpy", "sklearn", "scipy", "faker", "pytest",
              "pytest_asyncio", "fastapi", "huggingface_hub"):
        try:
            mod = __import__(m)
            vers[m] = getattr(mod, "__version__", getattr(mod, "VERSION", "?"))
        except Exception as e:                                                 # noqa: BLE001
            vers[m] = f"MISSING ({type(e).__name__})"
    info["versions"] = vers
    try:
        import torch
        info["mps_available"] = bool(getattr(torch.backends, "mps", None) and torch.backends.mps.is_available())
    except Exception:                                                          # noqa: BLE001
        info["mps_available"] = None
    need = ["tests/conftest.py", "pytest.ini", "sentinel/eval/split_bench_v3.py",
            "sentinel/eval/data/split_bench_v2/all.jsonl", "sentinel/eval/data/phase4_benchmark/all.jsonl",
            "sentinel/eval/data/custom_l5/all.jsonl"]
    info["missing_files"] = [f for f in need if not (ROOT / f).exists()]
    info["free_disk_gb"] = round(shutil.disk_usage(ROOT).free / 2 ** 30, 1)
    if not hf_cached(MINILM):
        say(f"  downloading {MINILM} (about 90 MB, once)")
        code = ("from sentence_transformers import SentenceTransformer; "
                f"SentenceTransformer('{MINILM}')")
        env = {k: v for k, v in os.environ.items() if k not in ("HF_HUB_OFFLINE", "TRANSFORMERS_OFFLINE")}
        p = subprocess.run([PY, "-c", code], cwd=ROOT, env=env, capture_output=True, text=True, timeout=1800)
        (d / "model_download.log").write_text(p.stdout + p.stderr, encoding="utf-8")
    info["minilm_cached"] = hf_cached(MINILM)
    bad = [k for k, v in vers.items() if str(v).startswith("MISSING")]
    info["ok"] = not bad and not info["missing_files"] and info["minilm_cached"]
    if not info["ok"]:
        info["problem"] = ("missing libraries: " + ", ".join(bad) if bad else "") + \
                          (" | missing files: " + ", ".join(info["missing_files"]) if info["missing_files"] else "") + \
                          ("" if info["minilm_cached"] else " | the MiniLM model could not be downloaded (internet?)")
    return info


def job_unit_tests(d: Path) -> dict:
    """The full test suite, once. A test that needs a gated model, private weights or a non-public file is SKIPPED
    with its reason (tests/_resources.py), never counted as a failure."""
    junit = d / "junit.xml"
    rc, secs = run_cmd([PY, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-rs", f"--junitxml={junit}", "tests"],
                       d / "log.txt", timeout_s=3 * 3600)
    out = {"exit": rc, "seconds": secs}
    if junit.exists():
        import xml.etree.ElementTree as ET
        tot = {"passed": 0, "failed": 0, "skipped": 0}
        failures, skips = [], {}
        for c in ET.parse(junit).getroot().iter("testcase"):
            f = c.find("failure") if c.find("failure") is not None else c.find("error")
            name = f"{c.get('classname')}::{c.get('name')}"
            if f is not None:
                tot["failed"] += 1
                failures.append({"test": name, "message": (f.get("message") or "")[:300]})
            elif c.find("skipped") is not None:
                tot["skipped"] += 1
                r = (c.find("skipped").get("message") or "")[:160]
                skips[r] = skips.get(r, 0) + 1
            else:
                tot["passed"] += 1
        out.update(tot)
        out["failures"] = failures
        out["skip_reasons"] = skips
    out["ok"] = rc == 0 or (isinstance(rc, int) and out.get("failed", 1) == 0)
    return out


def analysis_job(module: str, args: list[str], prefix: str):
    def job(d: Path) -> dict:
        before = {p.name for p in RESULTS.glob(f"{prefix}_*.json")} if RESULTS.exists() else set()
        rc, secs = run_cmd([PY, "-m", module, *args], d / "log.txt", timeout_s=3600)
        files = new_result_files(before, prefix)
        for f in files:
            shutil.copy2(f, d / f.name)
        return {"exit": rc, "seconds": secs, "result_files": [f.name for f in files], "ok": rc == 0 and bool(files)}
    return job


def regenerate_job(module: str, data_dir: str):
    """Rebuild a shipped synthetic benchmark, compare every file byte for byte, then restore the shipped files."""
    def job(d: Path) -> dict:
        src = ROOT / data_dir
        keep = d / "shipped"
        if keep.exists():
            shutil.rmtree(keep)
        shutil.copytree(src, keep)
        try:
            rc, secs = run_cmd([PY, "-m", module], d / "log.txt", timeout_s=3600)
            cmp = {}
            for f in sorted(keep.iterdir()):
                g = src / f.name
                cmp[f.name] = "identical" if g.exists() and sha(f) == sha(g) else "DIFFERENT"
            detail = {}
            a, b = keep / "all.jsonl", src / "all.jsonl"
            if a.exists() and b.exists() and cmp.get("all.jsonl") == "DIFFERENT":
                ra = [json.loads(x) for x in a.read_text(encoding="utf-8").splitlines() if x.strip()]
                rb = [json.loads(x) for x in b.read_text(encoding="utf-8").splitlines() if x.strip()]
                detail = {"rows_shipped": len(ra), "rows_rebuilt": len(rb),
                          "same_text": sum(x.get("text") == y.get("text") for x, y in zip(ra, rb)),
                          "same_label": sum(x.get("label") == y.get("label") for x, y in zip(ra, rb))}
                shutil.copy2(b, d / "rebuilt_all.jsonl")
        finally:
            for f in keep.iterdir():                                   # leave the repository as it was
                shutil.copy2(f, src / f.name)
        return {"exit": rc, "seconds": secs, "files": cmp, "detail": detail,
                "ok": rc == 0 and all(v == "identical" for v in cmp.values())}
    return job


# Fingerprints of the FIXED L5 generator's output on the developer machine (Windows, 2026-11-23). The shipped corpus came
# from an older state of the generator and cannot be rebuilt, so this job checks the rebuild across machines instead.
L5_EXPECTED = {"all.jsonl": "2cc18aa340b286ae2c6b731948282c672ac017173757365332366c75e6dc9ede",
               "metadata.json": "b9680976acc1ad623fd99be3a625035f4233e17f91f444ea8407b47ccea9fe9c",
               "test.jsonl": "ad88c45eec46ca0783b32b10100a7abf564611aed0a55d2046d806c1d1ff073c",
               "train.jsonl": "0df49ef439bcf1849a68aecfb29202cf449fc29a26a15a4c69cb36056adb2303"}


def l5_reproducibility_job():
    """Rebuild the L5 corpus twice into this job's folder (never over the shipped files) and compare both rebuilds with
    each other (same machine) and with L5_EXPECTED (the developer machine)."""
    def job(d: Path) -> dict:
        code = ("import sys, pathlib; import sentinel.eval.generate_l5_corpus as g; "
                "g._DATA_DIR = pathlib.Path(sys.argv[1]); g._DATA_DIR.mkdir(parents=True, exist_ok=True); "
                "g.generate_l5_corpus()")
        out, total = {}, 0.0
        for run in ("run1", "run2"):
            rd = d / run
            if rd.exists():
                shutil.rmtree(rd)
            rc, secs = run_cmd([PY, "-c", code, str(rd)], d / f"log_{run}.txt", timeout_s=1800)
            total += secs
            out[run] = {"exit": rc, "sha256": {f.name: sha(f) for f in sorted(rd.iterdir())} if rd.exists() else {}}
        same_machine = out["run1"]["sha256"] == out["run2"]["sha256"] and bool(out["run1"]["sha256"])
        cross = {n: ("identical" if out["run1"]["sha256"].get(n) == h else "DIFFERENT") for n, h in L5_EXPECTED.items()}
        return {"seconds": round(total, 1), "runs": out, "same_machine_identical": same_machine,
                "files": cross, "ok": same_machine and all(v == "identical" for v in cross.values())}
    return job


JOBS = [
    ("00_preflight", job_preflight, "check the machine, libraries and files; fetch the one public model"),
    ("01_unit_tests", job_unit_tests, "the full test suite (about 2,170 tests)"),
    ("02_crosslayer_score_fusion_v2", analysis_job("sentinel.eval.split_bench_eval",
                                                   ["--data-dir", "sentinel/eval/data/split_bench_v2"], "eval_split_bench"),
     "cross-layer: score fusion vs threshold fusion on SPLIT-Bench v2 (contribution E)"),
    ("03_crosslayer_score_fusion_v1", analysis_job("sentinel.eval.split_bench_eval",
                                                   ["--data-dir", "sentinel/eval/data/split_bench"], "eval_split_bench"),
     "cross-layer: the same on SPLIT-Bench v1"),
    ("04_crosslayer_evalue_fusion", analysis_job("sentinel.eval.evidence_fusion_eval", [], "eval_evidence_fusion"),
     "cross-layer: e-value fusion (contribution F)"),
    ("05_crosslayer_eprocess", analysis_job("sentinel.eval.eprocess_eval", [], "eval_eprocess"),
     "cross-layer: per-turn e-process (contribution F, sequential)"),
    ("06_rebuild_phase4_benchmark", regenerate_job("sentinel.eval.generate_phase4_benchmark",
                                                   "sentinel/eval/data/phase4_benchmark"),
     "reproducibility: rebuild the phase-4 benchmark and compare"),
    ("07_rebuild_l5_corpus", l5_reproducibility_job(),
     "reproducibility: rebuild the L5 corpus twice, compare with each other and with the developer machine"),
]


# --------------------------------------------------------------------------------------------- queue
def state(name: str) -> str:
    d = OUT / name
    if (d / "DONE").exists():
        r = json.loads((d / "result.json").read_text(encoding="utf-8"))
        return "done (ok)" if r.get("ok") else "done (with problems)"
    return "running or stopped" if d.exists() else "waiting"


def write_summary(total_s: float) -> Path:
    lines = ["# Parth's results", "", f"- Written: {time.strftime('%Y-%m-%d %H:%M')}",
             f"- Machine: {platform.platform()} ({platform.machine()}), Python {sys.version.split()[0]}",
             f"- Time for this pass: {round(total_s / 60, 1)} min", "", "| job | state | time | notes |",
             "|---|---|---|---|"]
    for name, _, what in JOBS:
        d = OUT / name
        r = json.loads((d / "result.json").read_text(encoding="utf-8")) if (d / "result.json").exists() else {}
        note = ""
        if name == "00_preflight" and r:
            note = "ok" if r.get("ok") else r.get("problem", "")
        elif name == "01_unit_tests" and r:
            note = f"{r.get('passed', '?')} passed, {r.get('failed', '?')} failed, {r.get('skipped', '?')} skipped"
        elif "files" in r:
            diff = [k for k, v in r["files"].items() if v != "identical"]
            note = "all files identical" if not diff else "different: " + ", ".join(diff)
        elif r:
            note = ", ".join(r.get("result_files", [])) or f"exit {r.get('exit')}"
        lines.append(f"| {name} | {state(name)} | {r.get('seconds', '')} s | {note} |")
    p = OUT / "SUMMARY.md"
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return p


def make_zip() -> Path:
    z = ROOT / "parth_results.zip"
    with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in OUT.rglob("*"):
            if f.is_file():
                zf.write(f, f.relative_to(ROOT))
    return z


def main() -> int:
    if "--list" in sys.argv:
        for name, _, what in JOBS:
            print(f"{name:34} {state(name):22} {what}")
        return 0
    if "--redo" in sys.argv and OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(exist_ok=True)
    t_all = time.time()
    say(f"{len(JOBS)} jobs; results go to {OUT}")
    for i, (name, fn, what) in enumerate(JOBS, 1):
        d = OUT / name
        if (d / "DONE").exists():
            say(f"[{i}/{len(JOBS)}] {name}: already done, skipped")
            continue
        d.mkdir(parents=True, exist_ok=True)
        say(f"[{i}/{len(JOBS)}] {name}: {what} ...")
        t0 = time.time()
        try:
            res = fn(d)
        except KeyboardInterrupt:
            say("stopped by hand; run `python parth_run.py` again to continue from this job")
            return 130
        except Exception as e:                                                 # noqa: BLE001
            res = {"ok": False, "error": f"{type(e).__name__}: {e}"}
        res.setdefault("seconds", round(time.time() - t0, 1))
        (d / "result.json").write_text(json.dumps(res, indent=1, default=str), encoding="utf-8")
        (d / "DONE").write_text(time.strftime("%Y-%m-%d %H:%M:%S"), encoding="utf-8")
        say(f"[{i}/{len(JOBS)}] {name}: {'ok' if res.get('ok') else 'finished WITH PROBLEMS (kept going)'} "
            f"in {res['seconds']} s")
        if name == "00_preflight" and not res.get("ok"):
            say("preflight problem: " + res.get("problem", "") + " -- the other jobs still run; send the zip anyway")
    summary = write_summary(time.time() - t_all)
    z = make_zip()
    say(f"all done. Summary: {summary}")
    say(f"SEND THIS FILE BACK: {z}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
