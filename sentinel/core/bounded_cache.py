"""
Bounded LRU dict used to cap the size of the per-session state stores across
the codebase: Layer 3's embedding history (`session_embeddings`), the Threat
Bus's session table (`ThreatBus.sessions`), and the correlation engine's
fired-rule tracker (`_fired_rules`).

Each of these previously grew without bound for the lifetime of the process —
every session_id that ever appeared stayed in memory forever, with no
eviction except a full manual reset (the demo "Reset" button). In a
long-running deployment this is an unbounded memory leak, and it also makes
`ThreatBus.stats["active_sessions"]` misleading over time: it reports the
total number of sessions ever seen, not sessions that are actually active.

This is intentionally a bounded-size LRU (via OrderedDict), not a TTL cache —
sessions are evicted by "least recently touched" once the configured cap is
hit. That's enough to bound memory deterministically without needing a
background sweep task, at the cost of a hard cap on concurrently tracked
sessions rather than a time-based expiry. If sub-cap TTL expiry is needed
later (e.g. to keep `active_sessions` accurate on a short time window), track
a `last_seen` timestamp alongside each value and sweep on read.
"""

from collections import OrderedDict
from typing import Generic, Iterator, TypeVar

K = TypeVar("K")
V = TypeVar("V")


class BoundedLRUDict(Generic[K, V]):
    """A dict-like store that evicts the least-recently-used entry once it
    exceeds `max_size`. Supports the subset of dict operations used
    elsewhere in this codebase."""

    def __init__(self, max_size: int = 10_000):
        if max_size < 1:
            raise ValueError("max_size must be >= 1")
        self._max_size = max_size
        self._data: "OrderedDict[K, V]" = OrderedDict()

    def __contains__(self, key: K) -> bool:
        return key in self._data

    def __getitem__(self, key: K) -> V:
        value = self._data[key]
        self._data.move_to_end(key)
        return value

    def __setitem__(self, key: K, value: V) -> None:
        self._data[key] = value
        self._data.move_to_end(key)
        self._evict_if_needed()

    def __len__(self) -> int:
        return len(self._data)

    def __iter__(self) -> Iterator[K]:
        return iter(self._data)

    def get(self, key: K, default: V | None = None):
        if key in self._data:
            self._data.move_to_end(key)
            return self._data[key]
        return default

    def setdefault(self, key: K, default: V) -> V:
        if key not in self._data:
            self._data[key] = default
        self._data.move_to_end(key)
        self._evict_if_needed()
        return self._data[key]

    def pop(self, key: K, default: V | None = None):
        return self._data.pop(key, default)

    def clear(self) -> None:
        self._data.clear()

    def values(self):
        return self._data.values()

    def keys(self):
        return self._data.keys()

    def items(self):
        return self._data.items()

    def _evict_if_needed(self) -> None:
        while len(self._data) > self._max_size:
            self._data.popitem(last=False)  # evict least-recently-used
