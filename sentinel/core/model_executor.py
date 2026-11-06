"""
Long-lived worker threads for blocking model work (2026-11-04 RCA; results.md §21.5).

WHY. On this torch build every OS thread that runs a CPU op big enough to go parallel gets its OWN OpenMP worker team,
and the team outlives the thread (scratch/rca/l2/l2p/omp_teams_check.py): 100 short-lived Python threads that each ran
one matmul left 1,100-1,500 OS threads behind; the same 200 ops on a reused 4-worker pool added about 11.
`asyncio.to_thread` uses the RUNNING LOOP's default executor, and every `asyncio.run()` creates and tears down its own
(the evaluation runner calls it once per sample; the test suite once per test) -- so each sample that reached a model
through `to_thread` leaked a team. A module-level pool is shared by every loop: its threads, and so their teams, are
reused. In the app (one long-lived loop) the old path was bounded; this makes the bound hold everywhere.

The OpenMP team size is PER THREAD on this build (scratch/rca/l2/l2p/omp_local_check.py: a worker that sets 8 threads
runs a 1024 x 1024 matmul in 7.3 ms while the main thread, still at 1, takes 18.6 ms). `cpu_compute` uses that: a CPU
model gets one dedicated worker with its own team size, and the rest of the process keeps SENTINEL_TORCH_THREADS
(default 1, which the full test suite needs: results.md §21.5).

  run_model(fn, *args, **kwargs)        async; same semantics as asyncio.to_thread (contextvars copied), shared pool
  cpu_compute(fn, *args, threads=k)     sync; runs fn on a dedicated worker whose torch team has k threads; blocks
"""
from __future__ import annotations

import asyncio
import contextvars
import functools
import os
import threading
from concurrent.futures import ThreadPoolExecutor

_lock = threading.Lock()
_pool: ThreadPoolExecutor | None = None
_cpu_pools: dict[int, ThreadPoolExecutor] = {}


def model_workers() -> int:
    """Size of the shared pool (SENTINEL_MODEL_WORKERS; default min(8, cpu count))."""
    try:
        n = int(os.getenv("SENTINEL_MODEL_WORKERS", "0"))
    except ValueError:
        n = 0
    return n if n > 0 else max(1, min(8, os.cpu_count() or 1))


def _shared_pool() -> ThreadPoolExecutor:
    global _pool
    if _pool is None:
        with _lock:
            if _pool is None:
                _pool = ThreadPoolExecutor(max_workers=model_workers(), thread_name_prefix="sentinel-model")
    return _pool


async def run_model(fn, /, *args, **kwargs):
    """`await asyncio.to_thread(fn, ...)`, on the shared long-lived pool instead of the loop's own executor."""
    loop = asyncio.get_running_loop()
    ctx = contextvars.copy_context()
    return await loop.run_in_executor(_shared_pool(), functools.partial(ctx.run, fn, *args, **kwargs))


def _init_threads(n: int) -> None:
    try:
        import torch
        torch.set_num_threads(n)           # thread-local team size on this build (module docstring)
    except Exception:                      # noqa: BLE001 - no torch: the worker still runs fn
        pass


def cpu_compute(fn, /, *args, threads: int, **kwargs):
    """Run fn(*args, **kwargs) on a dedicated long-lived worker whose torch team has `threads` threads; block for the
    result (exceptions propagate). threads <= 1 or a call already on such a worker -> run inline."""
    if threads <= 1 or threading.current_thread().name.startswith("sentinel-cpu"):
        return fn(*args, **kwargs)
    ex = _cpu_pools.get(threads)
    if ex is None:
        with _lock:
            ex = _cpu_pools.get(threads)
            if ex is None:
                ex = ThreadPoolExecutor(max_workers=1, thread_name_prefix=f"sentinel-cpu{threads}",
                                        initializer=_init_threads, initargs=(threads,))
                _cpu_pools[threads] = ex
    ctx = contextvars.copy_context()
    return ex.submit(ctx.run, fn, *args, **kwargs).result()


def guard_cpu_threads() -> int:
    """Team size for the CPU safety guard's forward passes (SENTINEL_GUARD_THREADS, default 8: the setting the
    evaluation chains ran for hours; 1,071 ms mean per prompt vs 2,473 ms at one thread, results.md §21.2)."""
    try:
        return max(1, int(os.getenv("SENTINEL_GUARD_THREADS", "8")))
    except ValueError:
        return 8
