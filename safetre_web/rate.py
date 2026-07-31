"""Per-user token-bucket rate limiting.

Bounds request rate per identity to blunt DoS and (in real-LLM mode) cost-
amplification. In-memory and per-process; a multi-instance deployment would back
this with a shared store.
"""

from __future__ import annotations

import threading
import time


class RateLimiter:
    def __init__(self, capacity: int = 120, window_sec: float = 60.0,
                 max_keys: int = 100_000):
        self.capacity = capacity
        self.rate = capacity / window_sec      # tokens per second
        self.window_sec = window_sec
        self.max_keys = max_keys
        self._buckets: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()

    def _sweep_locked(self, now: float) -> None:
        """Bring the map back under `max_keys`. A dropped bucket resets to
        full, which is the correct state for an idle key anyway.

        Idle buckets go first. If that is not enough the least recently used
        go too, because idleness alone was never a bound: a stream of FRESH
        distinct keys has no idle buckets to drop, so the map grew without
        limit while the docstring said it could not — 50,000 entries against a
        `max_keys` of 100, measured (round 10, #77). Dropping an active
        bucket forgives that key its spent tokens, which is why it is the
        second resort and not the first, but a limiter that runs out of memory
        limits nothing.
        """
        idle_before = now - self.window_sec
        for k in [k for k, (_, last) in self._buckets.items() if last <= idle_before]:
            del self._buckets[k]
        if len(self._buckets) > self.max_keys:
            by_age = sorted(self._buckets.items(), key=lambda kv: kv[1][1])
            for k, _ in by_age[:len(self._buckets) - self.max_keys]:
                del self._buckets[k]

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            if len(self._buckets) > self.max_keys:
                self._sweep_locked(now)
            tokens, last = self._buckets.get(key, (float(self.capacity), now))
            tokens = min(self.capacity, tokens + (now - last) * self.rate)
            if tokens < 1.0:
                self._buckets[key] = (tokens, now)
                return False
            self._buckets[key] = (tokens - 1.0, now)
            return True
