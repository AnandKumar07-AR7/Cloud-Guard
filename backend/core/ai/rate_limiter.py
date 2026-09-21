"""
CloudGuard — Process-Local AI Rate Limiter (Phase 8)

Enforces per-user rate limiting for AI analysis requests to prevent resource abuse.
NOTE: This rate limiter is single-instance and thread-safe for the current application process only.
It is NOT a distributed or multi-worker production-grade rate limiter.
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict
from typing import Dict, List
from fastapi import HTTPException, status


class AIRateLimiter:
    """
    Process-local sliding window rate limiter for AI operations.
    Thread-safe via threading.Lock().
    """

    def __init__(self, max_requests: int = 10, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._lock = threading.Lock()
        self._requests: Dict[str, List[float]] = defaultdict(list)

    def check_rate_limit(self, user_id: str) -> None:
        """
        Records an attempt and raises HTTPException(429) if limit exceeded.
        """
        now = time.monotonic()
        with self._lock:
            timestamps = self._requests[user_id]
            # Prune timestamps older than window
            cutoff = now - self.window_seconds
            valid_timestamps = [ts for ts in timestamps if ts > cutoff]
            self._requests[user_id] = valid_timestamps

            if len(valid_timestamps) >= self.max_requests:
                retry_after = int(self.window_seconds - (now - valid_timestamps[0])) + 1
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"AI analysis rate limit exceeded. Max {self.max_requests} requests per minute.",
                    headers={"Retry-After": str(max(1, retry_after))},
                )

            self._requests[user_id].append(now)

    def reset(self) -> None:
        """Clears all stored rate limit history (primarily for tests)."""
        with self._lock:
            self._requests.clear()


# Global singleton instance for the process
ai_rate_limiter = AIRateLimiter(max_requests=10, window_seconds=60)
