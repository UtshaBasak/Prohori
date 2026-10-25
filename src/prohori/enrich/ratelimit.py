"""Rate limiting for external providers: a token bucket, a daily budget and bounded retries.

Clocks and sleep functions are injected so tests never wait. Nothing here retries forever: waits
are capped, attempts are counted, and a provider that asks for a longer pause is reported as
rate limited for the rest of the run.
"""

import time
from collections.abc import Callable
from dataclasses import dataclass

from prohori.enrich.cache import EnrichmentCache
from prohori.enrich.provider import BudgetExhaustedError, RateLimitedError

Monotonic = Callable[[], float]
Sleep = Callable[[float], None]


class TokenBucket:
    """Allows ``capacity`` requests at once, refilled at ``rate`` requests per second."""

    def __init__(
        self,
        rate: float,
        capacity: float,
        *,
        max_wait: float = 60.0,
        monotonic: Monotonic = time.monotonic,
        sleep: Sleep = time.sleep,
    ) -> None:
        if rate <= 0 or capacity < 1:
            raise ValueError("rate must be positive and capacity at least 1")
        self.rate = rate
        self.capacity = capacity
        self.max_wait = max_wait
        self._monotonic = monotonic
        self._sleep = sleep
        self._tokens = capacity
        self._updated = monotonic()

    @classmethod
    def per_minute(
        cls,
        requests: int,
        *,
        max_wait: float = 60.0,
        monotonic: Monotonic = time.monotonic,
        sleep: Sleep = time.sleep,
    ) -> "TokenBucket":
        """Allow ``requests`` per minute, all of which may be used in a burst."""
        return cls(
            requests / 60.0, float(requests), max_wait=max_wait, monotonic=monotonic, sleep=sleep
        )

    def _refill(self) -> None:
        now = self._monotonic()
        self._tokens = min(self.capacity, self._tokens + (now - self._updated) * self.rate)
        self._updated = now

    def acquire(self) -> None:
        """Take one token, sleeping until one is available.

        Raises:
            RateLimitedError: if the wait would exceed ``max_wait`` seconds.
        """
        self._refill()
        if self._tokens < 1:
            wait = (1 - self._tokens) / self.rate
            if wait > self.max_wait:
                raise RateLimitedError(f"local rate limit needs a {wait:.0f}s wait")
            self._sleep(wait)
            self._refill()
        self._tokens -= 1


class DailyBudget:
    """At most ``limit`` requests per provider per UTC day, counted in the persistent cache."""

    def __init__(self, provider: str, limit: int, cache: EnrichmentCache) -> None:
        self.provider = provider
        self.limit = limit
        self._cache = cache

    def remaining(self) -> int:
        return max(0, self.limit - self._cache.requests_today(self.provider))

    def spend(self) -> None:
        """Record one request.

        Raises:
            BudgetExhaustedError: if today's budget is already used up (nothing is recorded).
        """
        if self.remaining() <= 0:
            raise BudgetExhaustedError(f"daily budget of {self.limit} requests used up")
        self._cache.count_request(self.provider)


@dataclass(frozen=True)
class RetryPolicy:
    """Bounded retries with exponential backoff and a cap on any single wait."""

    max_attempts: int = 3
    base_delay: float = 1.0
    max_delay: float = 60.0

    def delay(self, attempt: int, retry_after: float | None = None) -> float:
        """Return the wait before retry number ``attempt`` (1-based).

        Raises:
            RateLimitedError: if the server asks for a longer wait than ``max_delay``.
        """
        if retry_after is not None:
            if retry_after > self.max_delay:
                raise RateLimitedError(f"provider asked to wait {retry_after:.0f}s")
            return max(0.0, retry_after)
        backoff: float = self.base_delay * 2 ** (attempt - 1)
        return min(self.max_delay, backoff)
