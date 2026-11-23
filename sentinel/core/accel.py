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


def is_cuda(dev: str | None = None) -> bool:
    return (dev or device()).startswith("cuda")


def is_mps(dev: str | None = None) -> bool:
    return (dev or device()) == "mps"


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


def fp16_dir(nf4_dir: str) -> str:
    """Where the Apple-silicon copy of a 4-bit checkpoint lives: the same path with '-nf4' replaced by '-fp16'."""
    d = os.path.expanduser(nf4_dir).rstrip("/\\")
    return d[:-4] + "-fp16" if d.endswith("-nf4") else d + "-fp16"
