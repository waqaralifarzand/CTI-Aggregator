import asyncio
import time


class RateLimiter:
    """Token-bucket rate limiter for async HTTP clients."""

    def __init__(self, max_requests: int, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.tokens = float(max_requests)
        self.last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self):
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_refill
            self.tokens = min(
                float(self.max_requests),
                self.tokens + (elapsed / self.window_seconds) * self.max_requests,
            )
            self.last_refill = now

            if self.tokens < 1.0:
                wait = (1.0 - self.tokens) / (self.max_requests / self.window_seconds)
                await asyncio.sleep(wait)
                self.tokens = 0.0
            else:
                self.tokens -= 1.0
