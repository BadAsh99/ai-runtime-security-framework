"""
In-memory rate limiter — per-app and per-IP quota management.
Production would use Redis; this in-memory version is sufficient for single-instance lab use.
"""

import time
from collections import defaultdict, deque
from dataclasses import dataclass


@dataclass
class RateLimitResult:
    allowed: bool
    requests_remaining: int
    reset_in_seconds: int
    limit: int


# Per-app limits (requests per window)
APP_LIMITS = {
    "app_a_content":  {"requests": 30, "window_seconds": 60},
    "app_b_finance":  {"requests": 20, "window_seconds": 60},
    "app_c_support":  {"requests": 50, "window_seconds": 60},
    "scanner":        {"requests": 100, "window_seconds": 60},
    "default":        {"requests": 20, "window_seconds": 60},
}


class RateLimiter:
    def __init__(self):
        # {key: deque of timestamps}
        self._windows: dict[str, deque] = defaultdict(deque)

    def check(self, app_id: str, client_ip: str = "unknown") -> RateLimitResult:
        """
        Check rate limit for app_id + client_ip combination.
        Uses sliding window algorithm.
        """
        config = APP_LIMITS.get(app_id, APP_LIMITS["default"])
        limit = config["requests"]
        window = config["window_seconds"]
        key = f"{app_id}:{client_ip}"
        now = time.time()
        cutoff = now - window

        q = self._windows[key]

        # Drop timestamps outside the window
        while q and q[0] < cutoff:
            q.popleft()

        remaining = limit - len(q)
        allowed = remaining > 0

        if allowed:
            q.append(now)
            remaining -= 1

        # Estimate reset time (when oldest request falls out of window)
        reset_in = int(q[0] + window - now) if q else 0

        return RateLimitResult(
            allowed=allowed,
            requests_remaining=max(remaining, 0),
            reset_in_seconds=max(reset_in, 0),
            limit=limit,
        )

    def get_stats(self, app_id: str) -> dict:
        """Return current usage stats for all IPs on an app."""
        prefix = f"{app_id}:"
        stats = {}
        now = time.time()
        config = APP_LIMITS.get(app_id, APP_LIMITS["default"])
        window = config["window_seconds"]
        cutoff = now - window

        for key, q in self._windows.items():
            if key.startswith(prefix):
                ip = key.split(":", 1)[1]
                active = sum(1 for ts in q if ts > cutoff)
                stats[ip] = active

        return stats


# Singleton instance shared across gateway
limiter = RateLimiter()
