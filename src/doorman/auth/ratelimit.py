"""In-memory sliding-window rate limiter (single process, resets on restart)."""

from __future__ import annotations

import threading
import time
from collections import OrderedDict, deque


class RateLimiter:
    def __init__(self, limit: int, window_s: float, max_keys: int = 10000) -> None:
        self.limit = limit
        self.window_s = window_s
        self.max_keys = max_keys
        self._hits: OrderedDict[str, deque[float]] = OrderedDict()
        self._lock = threading.Lock()

    def hit(self, key: str, now: float | None = None) -> bool:
        """Record an attempt. Returns False when the key is over its limit."""
        now = time.monotonic() if now is None else now
        with self._lock:
            q = self._hits.get(key)
            if q is None:
                q = self._hits[key] = deque()
            self._hits.move_to_end(key)
            while q and now - q[0] > self.window_s:
                q.popleft()
            # Bound memory under a flood by dropping the least recently used keys. Never clear
            # everything: that would hand every blocked key a fresh budget.
            while len(self._hits) > self.max_keys:
                self._hits.popitem(last=False)
            if len(q) >= self.limit:
                return False
            q.append(now)
            return True

    def reset(self, key: str) -> None:
        with self._lock:
            self._hits.pop(key, None)
