"""
Rate Limiter — Sliding-window rate limiting for HexStrike API endpoints.

Applied as Flask middleware via @app.before_request. Uses an in-memory
sliding window (same pattern as core/cache.py) — no external dependencies.

Design notes (senior-engineering/clean-code):
  - Lives at the Flask API layer, not MCP layer (the API on port 8888 is
    directly accessible, so MCP-layer limits would be bypassable)
  - Periodic cleanup of stale entries to prevent memory growth
  - Thread-safe via GIL for single-process Flask (adequate for HexStrike)
"""

import logging
import time
from collections import defaultdict
from typing import Dict, List

logger = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────────
DEFAULT_WINDOW_SECONDS = 60
DEFAULT_MAX_CALLS = 30
SCAN_INTEL_MAX_CALLS = 10  # Tighter limit for expensive scan endpoints
CLEANUP_INTERVAL_SECONDS = 300
MAX_IDENTIFIERS = 10000  # Prevent unbounded growth


class RateLimiter:
    """In-memory sliding-window rate limiter for Flask request throttling."""

    def __init__(self):
        self._windows: Dict[str, List[float]] = defaultdict(list)
        self._last_cleanup = time.time()

    def check_limit(
        self,
        identifier: str,
        window_seconds: int = DEFAULT_WINDOW_SECONDS,
        max_calls: int = DEFAULT_MAX_CALLS,
    ) -> bool:
        """Check if a request is within the rate limit.

        Args:
            identifier: Unique key for the rate limit bucket (e.g. IP + endpoint).
            window_seconds: Sliding window duration.
            max_calls: Maximum calls allowed within the window.

        Returns:
            True if allowed, False if rate limited.
        """
        now = time.time()
        cutoff = now - window_seconds

        # Periodic cleanup
        if now - self._last_cleanup > CLEANUP_INTERVAL_SECONDS:
            self._cleanup(now)

        # Filter to recent timestamps only
        recent = [ts for ts in self._windows[identifier] if ts > cutoff]

        if len(recent) >= max_calls:
            logger.warning(f"Rate limit hit: {identifier} ({len(recent)}/{max_calls} in {window_seconds}s)")
            self._windows[identifier] = recent
            return False

        recent.append(now)
        self._windows[identifier] = recent
        return True

    def get_remaining(
        self,
        identifier: str,
        window_seconds: int = DEFAULT_WINDOW_SECONDS,
        max_calls: int = DEFAULT_MAX_CALLS,
    ) -> int:
        """Get the number of remaining calls for an identifier."""
        now = time.time()
        cutoff = now - window_seconds
        recent = [ts for ts in self._windows[identifier] if ts > cutoff]
        return max(0, max_calls - len(recent))

    def reset(self, identifier: str) -> None:
        """Clear rate limit state for an identifier."""
        self._windows.pop(identifier, None)

    def _cleanup(self, now: float) -> None:
        """Remove stale entries to prevent unbounded memory growth."""
        stale_keys = []
        for key, timestamps in self._windows.items():
            # Keep only timestamps within the largest reasonable window (5 min)
            fresh = [ts for ts in timestamps if now - ts < DEFAULT_WINDOW_SECONDS * 5]
            if not fresh:
                stale_keys.append(key)
            else:
                self._windows[key] = fresh

        for key in stale_keys:
            del self._windows[key]

        # Hard cap on total identifiers
        if len(self._windows) > MAX_IDENTIFIERS:
            excess = len(self._windows) - MAX_IDENTIFIERS
            for key in list(self._windows.keys())[:excess]:
                del self._windows[key]

        self._last_cleanup = now
        if stale_keys:
            logger.debug(f"Rate limiter cleanup: removed {len(stale_keys)} stale entries")
