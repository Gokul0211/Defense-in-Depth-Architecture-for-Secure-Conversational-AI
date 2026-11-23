"""
Which accelerator this machine has, in one place (2026-11-23: the Apple-silicon port for the hand-off runs).

  cuda:0  an NVIDIA GPU -- the measured platform: every number in results.md up to §37 comes from it
  mps     Apple silicon (PyTorch's Metal backend). The 4-bit models run there as their exact fp16 dequantisation
          (sentinel/core/nf4_to_fp16.py): the same weights the 4-bit kernels compute with on the NVIDIA GPU
  cpu     neither

SENTINEL_DEVICE forces one (cuda:0 | mps | cpu). An EMPTY CUDA_VISIBLE_DEVICES -- how the GPU queue marks a step as
CPU-only -- hides the Apple GPU too, so a step that is CPU-only on the PC stays CPU-only on a Mac.

Memory helpers with one meaning on both GPUs: mem_info() -> (free, total) bytes, in_use(), set_fraction(f) (a hard cap,
f x total), reset_peak() / peak() (MPS keeps no peak counter: peak() is the memory in use when read), is_oom(exc).
"""
from __future__ import annotations

import os


def device() -> str:
    import torch
    forced = os.environ.get("SENTINEL_DEVICE", "").strip().lower()
    if forced:
        return "cuda:0" if forced.startswith("cuda") else forced
    if torch.cuda.is_available():
        return "cuda:0"
    if os.environ.get("CUDA_VISIBLE_DEVICES") == "":
        return "cpu"
    mps = getattr(torch.backends, "mps", None)
    if mps is not None and mps.is_available():
        return "mps"
    return "cpu"


def is_cuda(dev=None) -> bool:
    return str(dev or device()).startswith("cuda")


def is_mps(dev=None) -> bool:
    return str(dev or device()).startswith("mps")


def empty_cache() -> None:
    import torch
    try:
        if torch.cuda.is_available():
            torch.cuda.empty_cache()
        elif getattr(torch.backends, "mps", None) is not None and torch.backends.mps.is_available():
            torch.mps.empty_cache()
    except Exception:                                       # noqa: BLE001 -- best effort
        pass


def synchronize(dev: str | None = None) -> None:
    import torch
    dev = dev or device()
    if is_cuda(dev):
        torch.cuda.synchronize()
    elif dev == "mps":
        torch.mps.synchronize()


def is_oom(exc: BaseException) -> bool:
    """An out-of-memory failure on either GPU (CUDA raises OutOfMemoryError; MPS a RuntimeError 'MPS backend out of
    memory ...')."""
    import torch
    oom = getattr(torch, "OutOfMemoryError", None) or getattr(torch.cuda, "OutOfMemoryError", None)
    if oom is not None and isinstance(exc, oom):
        return True
    return isinstance(exc, RuntimeError) and "out of memory" in str(exc).lower()


def mem_info(dev: str | None = None) -> tuple[int, int]:
    """(free, total) bytes. MPS: total = the Metal recommended working-set size, free = total - what this process's
    Metal allocator holds."""
    import torch
    dev = dev or device()
    if is_cuda(dev):
        return torch.cuda.mem_get_info()
    if dev == "mps":
        total = int(torch.mps.recommended_max_memory())
        return max(0, total - int(torch.mps.driver_allocated_memory())), total
    return 0, 0


def in_use(dev: str | None = None) -> int:
    import torch
    dev = dev or device()
    if is_cuda(dev):
        return int(torch.cuda.memory_reserved())
    if dev == "mps":
        return int(torch.mps.driver_allocated_memory())
    return 0


def set_fraction(f: float, dev: str | None = None) -> None:
    """Hard cap at f x total (CUDA: of the device memory; MPS: of the recommended working set). An allocation beyond it
    raises an out-of-memory error instead of spilling (Windows) or swapping (macOS)."""
    import torch
    dev = dev or device()
    if is_cuda(dev):
        torch.cuda.set_per_process_memory_fraction(f)
    elif dev == "mps":
        torch.mps.set_per_process_memory_fraction(f)


def reset_peak(dev: str | None = None) -> None:
    import torch
    if is_cuda(dev or device()):
        torch.cuda.reset_peak_memory_stats()


def peak(dev: str | None = None) -> int:
    import torch
    dev = dev or device()
    if is_cuda(dev):
        return int(torch.cuda.max_memory_allocated())
    if dev == "mps":
        return int(torch.mps.current_allocated_memory())
    return 0


# ---- Apple GPU: driver memory per distinct tensor shape, never returned (results.md §38.9) -------------------------
# On MPS (torch 2.12.1, macOS 27.0.1) every new tensor shape a process runs costs driver memory ("other allocations")
# that empty_cache() does not return (ultralytics/ultralytics#26742: same versions, same 20.13 GiB limit on a 16 GB Mac).
# A loop over inputs of varying length therefore runs out of memory: the Granite judge did on Parth's M5 at 14 GiB of
# "other allocations". Two answers, both only on Apple's GPU unless forced:
#   shape buckets  pad sequence lengths to 64, 96, 128, 192, 256, ... (powers of two and 1.5x them) and batch sizes to
#                  powers of two, so a run meets a few shapes instead of one per input
#   recycling      a resumable loop saves its progress and exits with RECYCLE_EXIT when the driver memory passes a limit;
#                  parth_gpu_run.py starts it again at once in a fresh process
RECYCLE_EXIT = 75


def shape_buckets(dev=None) -> bool:
    """Pad shapes to buckets? Default: only on Apple's GPU. SENTINEL_SHAPE_BUCKETS=1 forces it anywhere (the equivalence
    tests on CUDA), 0 turns it off."""
    v = os.environ.get("SENTINEL_SHAPE_BUCKETS", "").strip()
    if v in ("0", "1"):
        return v == "1"
    return is_mps(dev)


def bucket_len(n: int) -> int:
    """The smallest of 64, 96, 128, 192, 256, 384, 512, ... (powers of two and 1.5x them) that is >= n."""
    b = 64
    while b < n:
        b = b * 3 // 2 if b & (b - 1) == 0 else b * 4 // 3
    return b


def bucket_batch(b: int) -> int:
    """The smallest power of two >= b."""
    return 1 << max(0, b - 1).bit_length()


def driver_memory(dev=None) -> int:
    """Bytes this process holds on the GPU as the driver counts them (MPS: tensors + the per-shape driver memory)."""
    import torch
    dev = dev or device()
    if is_mps(dev):
        return int(torch.mps.driver_allocated_memory())
    if is_cuda(dev):
        return int(torch.cuda.memory_reserved())
    return 0


def recycle_limit(dev=None) -> int:
    """Bytes of driver memory above which a resumable loop hands over to a fresh process: SENTINEL_RECYCLE_GB if set;
    on Apple's GPU SENTINEL_RECYCLE_FRAC (default 0.85) x the recommended working set (11.84 GiB on a 16 GB M5 -> 10.1
    GiB, under both the 16 GB of RAM and PyTorch's 1.7x limit); elsewhere 0 = never."""
    gb = os.environ.get("SENTINEL_RECYCLE_GB", "").strip()
    if gb:
        return int(float(gb) * 2 ** 30)
    if is_mps(dev):
        import torch
        return int(float(os.environ.get("SENTINEL_RECYCLE_FRAC", "0.85")) * torch.mps.recommended_max_memory())
    return 0


def recycle_due(dev=None, n: int | None = None) -> bool:
    """True when the caller should save and recycle. n = units done in this process: SENTINEL_RECYCLE_EVERY=k (tests
    only) also says yes every k units, so the restart path can be tested on any machine."""
    every = int(os.environ.get("SENTINEL_RECYCLE_EVERY", "0") or 0)
    if every and n and n % every == 0:
        return True
    lim = recycle_limit(dev)
    return bool(lim) and driver_memory(dev) > lim


def recycle_exit(what: str, dev=None) -> None:
    """Say why, then exit with RECYCLE_EXIT. The caller has saved its progress; the runner starts the same command again
    in a fresh process, which resumes from it."""
    import sys
    print(f"RECYCLE: GPU driver memory {driver_memory(dev) / 2 ** 30:.2f} GiB, limit {recycle_limit(dev) / 2 ** 30:.2f} "
          f"GiB, after {what}: exiting {RECYCLE_EXIT} for a fresh process", flush=True)
    sys.exit(RECYCLE_EXIT)


def fp16_dir(nf4_dir: str) -> str:
    """Where the Apple-silicon copy of a 4-bit checkpoint lives: the same path with '-nf4' replaced by '-fp16'."""
    d = os.path.expanduser(nf4_dir).rstrip("/\\")
    return d[:-4] + "-fp16" if d.endswith("-nf4") else d + "-fp16"
