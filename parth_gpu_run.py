"""
Parth's GPU runs on an Apple-silicon Mac (2026-11-23, results.md §38): the L3 v4.2 TEST (resumed from the PC's save
point), the whole-system re-run, and SPLIT-Bench v3. One command, safe to re-run: every step leaves a DONE marker and
the long steps resume where they stopped.

    python parth_gpu_run.py            run everything that is not done yet
    python parth_gpu_run.py status     show which steps are done

What it does, in order (details: results.md §38):
  setup      find parth_gpu_pack.zip, check every file's sha256, unpack it (models -> ~/.cache, data + scripts -> this
             folder; files already here are kept, scripts are updated), convert the two 4-bit models to fp16
  preflight  the Mac: chip, memory, disk, PyTorch's Apple GPU (MPS) and a small numeric check
  parity     the Mac's models against values the NVIDIA PC stored (scratch/rca/mac/parity_gate.py, rules fixed there);
             if it fails, NOTHING else runs and the results zip is made for the developer
  l3_*       the L3 v4.2 TEST exactly as the PC's chain (scratch/rca/l3/chain_l3_v42.sh test), then the sensitivity read
  baseline   the FINAL whole-system arms on this Mac with L3 off (the platform's own reference)
  reread     only if the L3 TEST passed: the same arms with L3 v4 on
  split_*    SPLIT-Bench v3: build, analysis, fusion-aware variant
  results    parth_gpu_results.zip -> send it back
Stdlib only here; every model step runs in its own process (one model in memory at a time).

Since 2026-11-23 evening (results.md §38.8, after the first run on Parth's M5):
  - the preflight's matmul check moves the GPU result to the CPU BEFORE widening it to float64 (Apple's GPU has no
    float64: the old order crashed), and checks every library the steps import, at this PC's versions
  - code fixes to the scratch scripts (not in git) arrive as parth_gpu_patch.zip with `git pull`; applied once per
    version before the next step, every file's sha256 checked
  - an unexpected error inside a step stops the run the same way a failed step does (results zip, SEND THIS FILE BACK),
    and every stop prints the end of the step's log
  - the pack may also be a re-compressed zip (one top folder, as macOS makes) or an unzipped parth_gpu_pack folder
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import time
import traceback
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RES = ROOT / "parth_gpu_results"
STATE = RES / "state"
LOGS = RES / "logs"
ZIP_OUT = ROOT / "parth_gpu_results.zip"
PACK_NAME = "parth_gpu_pack.zip"
PATCH_NAME = "parth_gpu_patch.zip"
RUNNER_VERSION = "2026-11-23b"
CACHE = Path.home() / ".cache"
L3 = "scratch/rca/l3"
PY = sys.executable
CODE_SUFFIXES = {".py", ".sh", ".env", ".md"}
MODELS = [("sentinel/qwen3-4b-instruct-2507-nf4", "sentinel/qwen3-4b-instruct-2507-fp16"),
          ("sentinel/granite-guardian-3.1-2b-nf4", "sentinel/granite-guardian-3.1-2b-fp16")]
HOUR = 3600


# ------------------------------------------------------------------------------------------------------------ helpers
def now() -> str:
    return _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def stamp() -> str:
    return _dt.datetime.now().strftime("%Y%m%d_%H%M%S")


def note(msg: str) -> None:
    RES.mkdir(parents=True, exist_ok=True)
    with open(RES / "STATUS.txt", "a", encoding="utf-8") as f:
        f.write(f"{now()} {msg}\n")


def say(msg: str) -> None:
    print(msg, flush=True)


def done(name: str) -> bool:
    return (STATE / f"{name}.done").exists()


def mark(name: str, info: str = "") -> None:
    STATE.mkdir(parents=True, exist_ok=True)
    (STATE / f"{name}.done").write_text(f"{now()} {info}\n", encoding="utf-8")


def base_env() -> dict:
    e = dict(os.environ)
    e.update({"HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1", "TOKENIZERS_PARALLELISM": "false",
              "PYTORCH_ENABLE_MPS_FALLBACK": "1", "PYTHONUTF8": "1"})
    e.pop("SENTINEL_DEVICE", None)
    return e


def final_env(extra: dict | None = None) -> dict:
    """The FINAL profile (scratch/rca/sys/final_profile.env), as the PC's jobs source it."""
    e = base_env()
    for line in (ROOT / "scratch/rca/sys/final_profile.env").read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            e[k.strip()] = v.strip()
    e.update(extra or {})
    return e


def cpu_env(e: dict | None = None) -> dict:
    e = dict(e or base_env())
    e.update({"SENTINEL_DEVICE": "cpu", "CUDA_VISIBLE_DEVICES": ""})
    return e


LAST_LOG: list = []                                   # the log of the step that ran last (its tail is shown on a stop)

# The defense's model parts FAIL SOFT: a model that cannot load or run logs one warning and the layer goes on without it
# (e.g. "Prompt Guard inference failed, using Tier 2 score only"). On this PC none of these lines appear under the FINAL
# profile (the guarded runs of results.md §38.8); the logs of earlier runs that had them were renamed *.bad_pig_device.
# On the Mac one of them would mean the numbers are not the system's, so every step's log is watched while it runs and
# the step stops at the first such line. The messages are the ones in sentinel/ (logger.warning ... unavailable /
# unreadable / failed), plus any sentinel warning with those words.
FALLBACK_TEXT = (
    "signal absent", "ADR encoding failed", "attack bank unavailable", "data minimizer failed",
    "local injection judge unavailable", "local injection judge failed", "multilingual model unavailable",
    "perplexity model unavailable", "pipeline fusion unavailable", "policy library unreadable",
    "local request-harm read failed", "FAILED its promotion gate", "safety head unavailable", "safety guard unavailable",
    "safety guard inference failed", "safety guard response inference failed", "safety guard category inference failed",
    "local jailbreak judge failed", "L1 will run Tier 2-only", "tier-fusion model unavailable",
    "harm-content tier unavailable", "harm probe unavailable", "harm probe tier unavailable",
    "new-tier anchors unavailable", "Prompt Guard inference failed", "LLM judge unavailable", "OCR unavailable",
    "OCR failed", "calibrated on another ENS3 probe", "stack artifact unreadable", "fine-tuned stage unavailable",
    "ProtectAI v2 unavailable", "PIGuard unavailable", "Prompt Guard 1 unavailable", "Prompt Guard unavailable for L2",
    "L2 LLM check unavailable", "l2_thresholds_v8.json is missing", "local document detector failed",
    "hidden-text scan failed", "no translation from it", "L3 multi-turn probe failed", "L3 multi-turn reply signal failed",
    "rank fusion off", "response-side harm check failed", "L6 relay judge failed")


def is_fallback(line: str) -> bool:
    if any(t in line for t in FALLBACK_TEXT):
        return True
    return ("[WARNING] sentinel." in line or "[ERROR] sentinel." in line) and any(
        w in line for w in ("unavailable", "unreadable", "failed"))


def fallback_lines(log: Path, start: int) -> tuple[list, int]:
    """Fallback lines in the whole lines written to `log` since byte `start`; the new start."""
    try:
        with open(log, "rb") as fh:
            fh.seek(start)
            chunk = fh.read()
    except OSError:
        return [], start
    cut = chunk.rfind(b"\n") + 1
    hits = [s.strip()[:240] for s in chunk[:cut].decode("utf-8", "replace").splitlines() if is_fallback(s)]
    return hits, start + cut


def tail(p: Path, n: int = 14) -> str:
    try:
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    return "\n".join("    " + s[:200] for s in lines[-n:])


def run(name: str, args: list, timeout_s: int, env: dict | None = None) -> int:
    """One process; output to logs/<name>.log; a short 'still running' line every 10 minutes."""
    LOGS.mkdir(parents=True, exist_ok=True)
    log = LOGS / f"{name}.log"
    LAST_LOG[:] = [log]
    note(f"{name} START")
    t0 = time.time()
    hits: list = []
    with open(log, "a", encoding="utf-8") as f:
        shown = [str(a) if len(str(a)) <= 160 else f"<{len(str(a))} characters>" for a in args]   # not the -c code
        f.write(f"\n===== {now()} {' '.join(shown)}\n")
        f.flush()
        pos = log.stat().st_size                          # this run's lines only
        p = subprocess.Popen([str(a) for a in args], cwd=ROOT, env=env or base_env(), stdout=f, stderr=subprocess.STDOUT)
        last = t0

        def stop_child():
            p.terminate()
            try:
                p.wait(timeout=60)
            except subprocess.TimeoutExpired:
                p.kill()
        try:
            while True:
                try:
                    rc = p.wait(timeout=30)
                    break
                except subprocess.TimeoutExpired:
                    new, pos = fallback_lines(log, pos)
                    hits += new
                    if hits:
                        stop_child()
                        rc = 125
                        break
                    if time.time() - t0 > timeout_s:
                        stop_child()
                        rc = 124
                        break
                    if time.time() - last >= 600:
                        last = time.time()
                        say(f"      still running ({(time.time() - t0) / 60:.0f} min) ...")
        except KeyboardInterrupt:
            p.terminate()
            note(f"{name} STOPPED by Ctrl+C")
            raise
    hits += fallback_lines(log, pos)[0] if rc != 125 else []
    note(f"{name} END rc={rc} ({(time.time() - t0) / 60:.1f} min)" + (f", {len(hits)} fallback line(s)" if hits else ""))
    if hits:
        raise Stop(f"{name}: a model part stopped working and the code went on without it (the numbers would not be "
                   "the system's), so the step was stopped:\n    " + "\n    ".join(hits[:5]))
    return rc


def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def keep_awake():
    """macOS: no sleep while this script runs (the lid must stay open)."""
    if sys.platform == "darwin" and shutil.which("caffeinate"):
        try:
            subprocess.Popen(["caffeinate", "-dimsu", "-w", str(os.getpid())], stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
        except OSError:
            pass


class Stop(Exception):
    """A step failed: stop, make the results zip, tell Parth to send it (send=False: something Parth fixes himself, e.g.
    a missing library, with the command to paste)."""

    def __init__(self, msg: str, send: bool = True):
        super().__init__(msg)
        self.send = send


# -------------------------------------------------------------------------------------------------------------- steps
class _Pack:
    """The pack as built (a zip with MANIFEST.json at its root), as macOS re-compresses it (every entry under one top
    folder, plus __MACOSX/ entries), or as Safari leaves it (unzipped into a parth_gpu_pack folder). Every file is
    checked against its sha256 in MANIFEST.json either way."""

    def __init__(self, path: Path):
        self.path, self.z, self.pre = path, None, ""
        if path.is_dir():
            if not (path / "MANIFEST.json").exists():
                raise Stop(f"{path} has no MANIFEST.json: download {PACK_NAME} again and leave it zipped")
            return
        self.z = zipfile.ZipFile(path)
        names = [n for n in self.z.namelist() if not n.startswith("__MACOSX/")]
        if "MANIFEST.json" not in names:
            tops = [n[:-len("MANIFEST.json")] for n in names if n.endswith("/MANIFEST.json") and n.count("/") == 1]
            if len(tops) != 1:
                self.z.close()
                raise Stop(f"{path.name} is not the data pack (no MANIFEST.json inside): download {PACK_NAME} again "
                           "and leave it zipped")
            self.pre = tops[0]

    def read(self, a: str) -> bytes:
        return (self.path / a).read_bytes() if self.z is None else self.z.read(self.pre + a)

    def open(self, a: str):
        return open(self.path / a, "rb") if self.z is None else self.z.open(self.pre + a)

    def close(self) -> None:
        if self.z is not None:
            self.z.close()


def find_pack() -> Path:
    for d in (ROOT, Path.home() / "Downloads", Path.home() / "Desktop"):
        for p in (d / PACK_NAME, d / PACK_NAME[:-len(".zip")]):    # the zip, or the folder Safari unzips it into
            if p.exists():
                return p
    raise Stop(f"{PACK_NAME} not found. Put it in your Downloads folder (or in {ROOT}) and run again.")


def step_setup_pack():
    pack = find_pack()
    say(f"      using {pack}")
    z = _Pack(pack)
    try:
        man = json.loads(z.read("MANIFEST.json"))
        need = sum(f["bytes"] for f in man["files"])
        free = shutil.disk_usage(ROOT).free
        if free < need + 16e9:
            raise Stop(f"not enough free disk: {free / 1e9:.0f} GB free, about {(need + 16e9) / 1e9:.0f} GB needed")
        n_new = n_kept = n_code = 0
        for i, f in enumerate(man["files"], 1):
            a = f["path"]
            if a.startswith("/") or ".." in a.split("/"):
                raise Stop(f"bad path in the pack: {a}")
            if a.startswith("cache/"):
                dst = CACHE / a[len("cache/"):]
            elif a.startswith("repo/"):
                dst = ROOT / a[len("repo/"):]
            else:
                continue
            is_code = dst.suffix in CODE_SUFFIXES and a.startswith("repo/")
            if dst.exists() and not is_code:
                if dst.stat().st_size == f["bytes"] or a.startswith("repo/"):
                    n_kept += 1                       # data already here (run progress is never overwritten)
                    continue
            dst.parent.mkdir(parents=True, exist_ok=True)
            tmp = dst.with_name(dst.name + ".unpacking")
            with z.open(a) as src, open(tmp, "wb") as out:
                shutil.copyfileobj(src, out, 1 << 20)
            if sha256(tmp) != f["sha256"]:
                tmp.unlink()
                raise Stop(f"the pack is damaged ({a}); download {PACK_NAME} again")
            os.replace(tmp, dst)
            n_code += is_code
            n_new += 1
            if i % 300 == 0:
                say(f"      {i}/{len(man['files'])} files")
    finally:
        z.close()
    note(f"pack {man['version']} built {man['built']}: {n_new} written ({n_code} scripts), {n_kept} kept")
    (RES / "pack_version.txt").write_text(man["version"] + "\n", encoding="utf-8")
    (RES / "patch_version.txt").unlink(missing_ok=True)      # the pack rewrote the scripts: re-apply any code update


def step_setup_convert():
    for src, dst in MODELS:
        s, d = CACHE / src, CACHE / dst
        if (d / "nf4_converted.json").exists():
            continue
        say(f"      converting {s.name} -> {d.name} (a few minutes)")
        rc = run("convert_" + d.name, [PY, "-B", "-X", "utf8", "-m", "sentinel.core.nf4_to_fp16", s, d], HOUR)
        if rc != 0 or not (d / "nf4_converted.json").exists():
            raise Stop(f"model conversion failed ({d.name})")


# Every library the steps import, at this PC's version (scratch/rca/mac/dep_scan.json: every import statement of the code
# the steps run, plus the modules the guarded runs on the PC actually loaded -- transformers loads accelerate only for
# device_map, so no import statement shows it). (distribution, version, import name, numbers depend on it). A missing
# library, or a different version of one the numbers depend on, stops at the preflight with one pip line to paste.
LIBS = [("torch", "2.12.1", "torch", True), ("transformers", "5.12.1", "transformers", True),
        ("tokenizers", "0.22.2", "tokenizers", True), ("safetensors", "0.8.0", "safetensors", True),
        ("accelerate", "1.14.0", "accelerate", True), ("huggingface_hub", "1.17.0", "huggingface_hub", True),
        ("sentencepiece", "0.2.2", "sentencepiece", True), ("protobuf", "5.29.6", "google.protobuf", True),
        ("sentence-transformers", "5.6.0", "sentence_transformers", True), ("numpy", "2.4.4", "numpy", True),
        ("scikit-learn", "1.9.0", "sklearn", True), ("scipy", "1.18.0", "scipy", True),
        ("PyYAML", "6.0.3", "yaml", False), ("pandas", "3.0.2", "pandas", False), ("datasets", "5.0.0", "datasets", False),
        ("pyarrow", "25.0.0", "pyarrow", False), ("Faker", "40.31.0", "faker", False),
        ("python-dotenv", "1.2.2", "dotenv", False), ("pillow", "12.2.0", "PIL", False), ("pypdf", "6.14.2", "pypdf", False),
        ("httpx", "0.28.1", "httpx", False), ("regex", "2026.5.9", "regex", False), ("tqdm", "4.67.3", "tqdm", False),
        ("psutil", "7.2.2", "psutil", False), ("Jinja2", "3.1.6", "jinja2", False)]

PREFLIGHT = r"""
import importlib, importlib.metadata as md, json, platform, subprocess, sys, shutil
r = {"python": platform.python_version(), "system": platform.platform(), "machine": platform.machine(),
     "libraries": {}, "pip_fix": [], "other_versions": []}
for dist, want, mod, core in json.loads(sys.argv[1]):
    try:
        importlib.import_module(mod)
        have = md.version(dist)
    except Exception as e:
        r["libraries"][dist] = None
        r["pip_fix"].append(f"{dist}=={want}")
        continue
    r["libraries"][dist] = have
    if have.split("+")[0] != want:
        r["pip_fix" if core else "other_versions"].append(f"{dist}=={want}")
r["installed"] = {d.metadata["Name"]: d.version for d in md.distributions()}
r["free_disk_gb"] = round(shutil.disk_usage(".").free / 1e9, 1)
try:
    r["chip"] = subprocess.run(["sysctl", "-n", "machdep.cpu.brand_string"], capture_output=True, text=True).stdout.strip()
    r["ram_gb"] = round(int(subprocess.run(["sysctl", "-n", "hw.memsize"], capture_output=True, text=True).stdout) / 2**30, 1)
    r["macos"] = platform.mac_ver()[0]
except Exception as e:
    r["sysctl_error"] = str(e)
def done(code):
    json.dump(r, open("parth_gpu_results/preflight.json", "w"), indent=1)
    print({k: v for k, v in r.items() if k != "installed"})
    sys.exit(code)
if r["pip_fix"]:
    done(4)
import torch
from sentinel.core.accel import device
r.update({"torch": torch.__version__, "device": device(), "mps": bool(torch.backends.mps.is_available())})
if r["mps"]:
    # Apple's GPU has no float64: the GPU result goes to the CPU first, then widens to float64 there
    g = torch.Generator().manual_seed(0)
    a = torch.randn(512, 512, generator=g); b = torch.randn(512, 512, generator=g)
    ref = a.double() @ b.double()
    r["mps_fp16_matmul_rel_err"] = float(((a.half().to("mps") @ b.half().to("mps")).cpu().double() - ref).abs().max() / ref.abs().max())
    r["mps_bf16_matmul_rel_err"] = float(((a.bfloat16().to("mps") @ b.bfloat16().to("mps")).cpu().double() - ref).abs().max() / ref.abs().max())
    r["mps_recommended_max_gb"] = round(torch.mps.recommended_max_memory() / 2**30, 1)
ok = (r["mps"] and r.get("ram_gb", 0) >= 15 and r.get("mps_fp16_matmul_rel_err", 1) < 0.01
      and r.get("mps_bf16_matmul_rel_err", 1) < 0.05)
done(0 if ok else 3)
"""


def step_preflight():
    rc = run("preflight", [PY, "-B", "-X", "utf8", "-c", PREFLIGHT, json.dumps(LIBS)], 900)
    if rc == 0:
        return
    pf = RES / "preflight.json"
    r = json.loads(pf.read_text(encoding="utf-8")) if pf.exists() else {}
    if rc == 4:
        raise Stop("some libraries are missing, or at a different version than on the developer's PC. Paste these two "
                   "lines, then run python parth_gpu_run.py again:\n\n    source .venv/bin/activate\n    pip install "
                   + " ".join(r.get("pip_fix", [])), send=False)
    if rc == 3:
        raise Stop("this Mac cannot run the GPU steps (see parth_gpu_results/preflight.json): an Apple GPU, >= 16 GB "
                   "memory and a passing numeric check are needed")
    raise Stop(f"the preflight check itself crashed (exit code {rc}); the end of its log is above")


def gate(part):
    def f():
        rc = run("parity_" + part, [PY, "-B", "-X", "utf8", "scratch/rca/mac/parity_gate.py", part], 3 * HOUR)
        if rc != 0:
            raise Stop(f"parity check '{part}' did not finish" if rc != 3 else
                       "the Mac's numbers do not match the PC's closely enough (parity gate FAIL); nothing else was run")
    return f


def l3(name, script, timeout_s, cpu=False, extra=None, isolated=False, skip_if=None):
    def f():
        if skip_if and (ROOT / L3 / skip_if).exists():
            return "skipped (" + skip_if + " exists)"
        env = base_env()
        env.update(extra or {})
        if cpu:
            env = cpu_env(env)
        args = [PY] + (["-I"] if isolated else []) + ["-B", "-X", "utf8", f"{L3}/{script[0]}"] + script[1:]
        if run(name, args, timeout_s, env) != 0:
            raise Stop(f"{name} failed")
    return f


def step_l3_val_stop():
    cal = json.loads((ROOT / L3 / "l3v42_cal.json").read_text(encoding="utf-8"))
    if not cal.get("val_stop", {}).get("pass"):
        raise Stop("the v4.2 VAL stop did not pass: the TEST stays unread")


def new_results(before: set) -> list:
    d = ROOT / "sentinel/eval/results"
    return sorted(p for p in d.iterdir() if p.name not in before and p.name.startswith("eval_pipeline_"))


def arms(tag: str, extra: dict, metrics_out: str):
    def f():
        d = ROOT / "sentinel/eval/results"
        before = {p.name for p in d.iterdir()}
        st = stamp()
        files = {}
        for ds, key in (("sentinel_bench", "dida"), ("benign_pipeline_arm", "v1"), ("benign_pipeline_arm_v2", "v2")):
            b2 = {p.name for p in d.iterdir()}
            rc = run(f"{tag}_{ds}", [PY, "-B", "-X", "utf8", "-m", "sentinel.eval.runner", "--pipeline", "--dataset", ds],
                     4 * HOUR, final_env(extra))
            new = new_results(b2)
            if rc != 0 or not new:
                raise Stop(f"{tag} {ds} failed")
            files[key] = new[-1]
        args = [PY, "-B", "-X", "utf8", "scratch/rca/sys/sys06_final_metrics.py", "--after", st, "--out", metrics_out]
        for k, v in files.items():
            args += [f"--{k}", str(v)]
        if run(f"{tag}_metrics", args, HOUR, cpu_env()) != 0:
            raise Stop(f"{tag} metrics failed")
        (RES / f"{tag}_files.json").write_text(json.dumps({k: v.name for k, v in files.items()}, indent=1), encoding="utf-8")
        _ = before
    return f


def l3_passed() -> bool:
    p = ROOT / L3 / "l3v4_test.json"
    try:
        return bool(json.loads(p.read_text(encoding="utf-8")).get("pass"))
    except (OSError, ValueError):
        return False


def step_reread():
    if not l3_passed():
        return "skipped: the L3 TEST did not pass (l3v4_test.json)"
    rc = run("reread_export", [PY, "-I", "-B", "-X", "utf8", f"{L3}/l3v4_11_export.py"], HOUR, cpu_env())
    art = ROOT / "sentinel/core/artifacts"
    if rc != 0 or not (art / "l3_mt_probe.npz").exists() or not (art / "l3_mt_reply.npz").exists():
        raise Stop("L3 export failed")
    arms("reread", {"L3_MT_V4": "true"}, "scratch/rca/mac/sys08_l3v4_reread_metrics_mac.json")()


def split(name, cmd, timeout_s, env_fn):
    def f():
        if run(name, cmd, timeout_s, env_fn()) != 0:
            raise Stop(f"{name} failed or ran out of time; run the same command again to continue")
    return f


def step_split_analyze():
    e = cpu_env()
    rc = run("split_analyze", [PY, "-B", "-X", "utf8", "-m", "sentinel.eval.split_bench_v3", "analyze"], 2 * HOUR, e)
    rc2 = run("second_stack_analyze", [PY, "-B", "-X", "utf8", "-m", "sentinel.eval.second_stack", "analyze"], HOUR, e)
    if rc != 0 or rc2 != 0:
        raise Stop("SPLIT-Bench v3 analysis failed")


def step_compare():
    rc = run("platform_compare", [PY, "-B", "-X", "utf8", "scratch/rca/mac/platform_compare.py"], HOUR, cpu_env())
    if rc != 0:
        raise Stop("platform comparison failed")


STEPS = [
    ("setup_pack", "Unpack the data and models (10-20 min)", step_setup_pack),
    ("setup_convert", "Convert the two 4-bit models for the Apple GPU (5-15 min)", step_setup_convert),
    ("preflight", "Check this Mac", step_preflight),
    ("parity_probe_reply", "Compare with the PC: L3 probe and reply signal", gate("probe_reply")),
    ("parity_judge", "Compare with the PC: the L3 judge (5-15 min)", gate("judge")),
    ("parity_replay", "Compare with the PC: reply generation", gate("replay")),
    ("parity_verdict", "Parity verdict", gate("verdict")),
    ("l3_val_stop", "L3: confirm the VAL stop passed", step_l3_val_stop),
    ("l3_feat_test", "L3 TEST: probe features (already done on the PC)", l3("l3_feat_test", ["l3v4_02_feat.py", "test"], 8 * HOUR)),
    ("l3_test_replay", "L3 TEST: replay the conversations (the long one: hours)", l3("l3_test_replay", ["l3v4_05_replay.py"], 20 * HOUR)),
    ("l3_test_labels", "L3 TEST: judge labels", l3("l3_test_labels", ["l3v4_04_judge.py", "label"], 4 * HOUR, skip_if="l3v4_labels.json")),
    ("l3_reply_signal", "L3 TEST: reply signal", l3("l3_reply_signal", ["l3v4_09_reply_l3.py"], 8 * HOUR)),
    ("l3_calibrate", "L3 TEST: calibration scores", l3("l3_calibrate", ["l3v42_10_calibrate.py"], HOUR, isolated=True)),
    ("l3_test_read", "L3 TEST: the one TEST read", l3("l3_test_read", ["l3v4_07_test.py"], HOUR, cpu=True,
                                                     extra={"L3_ROUND": "v42"}, skip_if="L3V4_TEST.done")),
    ("l3_sensitivity", "L3 TEST: judge sensitivity", l3("l3_sensitivity", ["l3v42_12_sensitivity.py"], HOUR, isolated=True)),
    ("baseline", "Whole system on this Mac, L3 off (30-90 min)", arms("baseline", {}, "scratch/rca/mac/mac_final_baseline_metrics.json")),
    ("platform_compare", "Compare this Mac's whole-system run with the PC's", step_compare),
    ("reread", "Whole system with L3 v4 on (only if the L3 TEST passed; 30-90 min)", step_reread),
    ("split_build", "SPLIT-Bench v3: build (hours; continues if stopped)",
     split("split_build", [PY, "-B", "-X", "utf8", "-m", "sentinel.eval.split_bench_v3", "build"], 16 * HOUR, final_env)),
    ("split_analyze", "SPLIT-Bench v3: analysis", step_split_analyze),
    ("split_fusion_aware", "SPLIT-Bench v3: fusion-aware variant (hours)",
     split("split_fusion_aware", [PY, "-B", "-X", "utf8", "-m", "sentinel.eval.split_bench_v3", "build-fusion-aware"],
           10 * HOUR, final_env)),
]


# ------------------------------------------------------------------------------------------------------------ results
RESULT_GLOBS = ["parth_gpu_results/**/*", "scratch/rca/mac/parity_*.json", "scratch/rca/mac/mac_*.json",
                "scratch/rca/mac/sys08_*.json", "scratch/rca/mac/platform_compare*.json",
                f"{L3}/l3v4_replay.jsonl", f"{L3}/l3v4_replay.partial.json", f"{L3}/l3v4_labels.json",
                f"{L3}/l3v4_reply_l3.json", f"{L3}/l3v42_cal.json", f"{L3}/l3v4_reply_scores.json", f"{L3}/l3v4_test.json",
                f"{L3}/L3V4_TEST.done", f"{L3}/l3v42_test_sensitivity.json", f"{L3}/STATUS",
                "sentinel/eval/data/split_bench_v3/*", "sentinel/eval/data/split_bench_v3_fusion_aware/*",
                "sentinel/eval/results/LEDGER.jsonl", "sentinel/core/artifacts/l3_mt_*.npz"]


def make_zip() -> Path:
    since = (STATE / "setup_pack.done").stat().st_mtime if (STATE / "setup_pack.done").exists() else 0
    files = set()
    for g in RESULT_GLOBS:
        files |= {p for p in ROOT.glob(g) if p.is_file()}
    d = ROOT / "sentinel/eval/results"
    files |= {p for p in d.glob("*.json") if p.stat().st_mtime >= since and since}
    tmp = ZIP_OUT.with_suffix(".zip.partial")
    with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as z:
        for p in sorted(files):
            if p.name.startswith(".env") or p.suffix in (".partial",):
                continue
            z.write(p, p.relative_to(ROOT).as_posix())
    os.replace(tmp, ZIP_OUT)
    return ZIP_OUT


def apply_patch() -> None:
    """Code fixes made after the pack: the scratch scripts are not in git, so their corrected versions come in
    parth_gpu_patch.zip, which `git pull` brings (same layout as the pack: MANIFEST.json + repo/...). Applied once per
    version, every file's sha256 checked; the pack's unpacking clears the record, so the fixes are re-applied after it."""
    p = ROOT / PATCH_NAME
    if not p.exists():
        return
    vf = RES / "patch_version.txt"
    with zipfile.ZipFile(p) as z:
        man = json.loads(z.read("MANIFEST.json"))
        if vf.exists() and vf.read_text(encoding="utf-8").strip() == man["version"]:
            return
        for f in man["files"]:
            a = f["path"]
            if not a.startswith("repo/") or ".." in a.split("/"):
                raise Stop(f"bad path in {PATCH_NAME}: {a}")
            data = z.read(a)
            if hashlib.sha256(data).hexdigest() != f["sha256"]:
                raise Stop(f"{PATCH_NAME} is damaged ({a}): run git pull again")
            dst = ROOT / a[len("repo/"):]
            dst.parent.mkdir(parents=True, exist_ok=True)
            tmp = dst.with_name(dst.name + ".patching")
            tmp.write_bytes(data)
            os.replace(tmp, dst)
    RES.mkdir(parents=True, exist_ok=True)
    vf.write_text(man["version"] + "\n", encoding="utf-8")
    note(f"code update {man['version']} applied: {len(man['files'])} files")
    say(f"Code update {man['version']} applied ({len(man['files'])} files).\n")


# --------------------------------------------------------------------------------------------------------------- main
def status():
    for i, (name, desc, _) in enumerate(STEPS, 1):
        mark_ = "done" if done(name) else "    "
        say(f"  [{mark_}] {i:2d}. {desc}")


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "status":
        status()
        return
    if sys.prefix == sys.base_prefix:
        say("Please activate the environment first:  source .venv/bin/activate")
        sys.exit(1)
    keep_awake()
    RES.mkdir(parents=True, exist_ok=True)
    note(f"RUN START runner {RUNNER_VERSION} python {platform.python_version()} on {platform.platform()}")
    say(f"Parth's GPU runs (runner {RUNNER_VERSION}). Keep the MacBook plugged in with the lid open. Ctrl+C stops; "
        "run again to continue.\n")
    try:
        for i, (name, desc, fn) in enumerate(STEPS, 1):
            if done(name):
                say(f"[{i:2d}/{len(STEPS)}] {desc}: already done")
                continue
            t0 = time.time()
            LAST_LOG[:] = []
            say(f"[{i:2d}/{len(STEPS)}] {desc} (started {_dt.datetime.now().strftime('%H:%M')})")
            try:
                if name != "setup_pack":
                    apply_patch()
                info = fn() or ""
            except (Stop, KeyboardInterrupt):
                raise
            except Exception as e:                    # a bug in a step itself: the same stop path, traceback kept
                LOGS.mkdir(parents=True, exist_ok=True)
                err = LOGS / f"{name}.error.log"
                err.write_text(traceback.format_exc(), encoding="utf-8")
                LAST_LOG[:] = [err]
                raise Stop(f"step '{name}' hit an unexpected error ({type(e).__name__}: {e})") from e
            mark(name, info)
            say(f"      done in {(time.time() - t0) / 60:.0f} min{' -- ' + info if info else ''}")
    except Stop as e:
        note(f"STOPPED: {e}")
        if LAST_LOG and LAST_LOG[0].exists():
            say(f"\nThe end of {LAST_LOG[0].relative_to(ROOT)}:\n{tail(LAST_LOG[0])}")
        if not e.send:
            say(f"\nSTOPPED: {e}\n")
            sys.exit(2)
        z = make_zip()
        say(f"\nSTOPPED: {e}\n\nSEND THIS FILE BACK: {z}\n")
        sys.exit(2)
    except KeyboardInterrupt:
        say("\nStopped by Ctrl+C. Run the same command again to continue.")
        sys.exit(130)
    note("RUN COMPLETE")
    z = make_zip()
    say(f"\nALL DONE.\n\nSEND THIS FILE BACK: {z}\n")


if __name__ == "__main__":
    main()
