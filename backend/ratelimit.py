import threading
import time
from collections import defaultdict, deque
from typing import Callable


class SlidingWindowLimiter:
    """Allow at most `limit` calls per `window_seconds` for each key.

    Thread-safe: FastAPI runs plain `def` dependencies in a thread pool, so
    several requests may call allow() at the same time.

    # shortcut: _hits keys are never removed; fine for a small fixed sensor set.
    # If this ever hits the public internet, add periodic cleanup of idle keys.
    """

    def __init__(
        self,
        limit: int,
        window_seconds: int,
        clock: Callable[[], float] = time.monotonic,
    ):
        if limit < 1 or window_seconds < 1:
            raise ValueError("limit and window_seconds must be positive")
        self.limit = limit
        self.window = window_seconds
        self._clock = clock
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = self._clock()
        with self._lock:
            hits = self._hits[key]
            while hits and now - hits[0] > self.window:
                hits.popleft()
            if len(hits) >= self.limit:
                return False
            hits.append(now)
            return True
