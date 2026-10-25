"""Shared HTTP behaviour for external providers: limits, retries, timeouts and safe errors.

Endpoints are fixed in code (never read from configuration), keys travel only in headers,
redirects are not followed, responses are size-capped, and error messages never include headers.
"""

import json
import time
from datetime import timedelta
from typing import Any, ClassVar

import httpx

from prohori.enrich.provider import (
    Provider,
    ProviderAuthError,
    ProviderError,
    ProviderUnavailableError,
    RateLimitedError,
)
from prohori.enrich.ratelimit import DailyBudget, RetryPolicy, Sleep, TokenBucket
from prohori.version import __version__

#: Largest response body read from a provider.
MAX_RESPONSE_BYTES = 1024 * 1024
DEFAULT_TIMEOUT = httpx.Timeout(10.0, connect=5.0)


def make_client(timeout: float | None = None) -> httpx.Client:
    """Create the HTTP client providers use: no redirects, explicit timeouts."""
    return httpx.Client(
        timeout=DEFAULT_TIMEOUT if timeout is None else httpx.Timeout(timeout),
        follow_redirects=False,
        headers={"User-Agent": f"prohori/{__version__}"},
    )


def _retry_after(response: httpx.Response) -> float | None:
    value = response.headers.get("Retry-After", "").strip()
    return float(value) if value.isdigit() else None


class HttpProvider(Provider):
    """A provider reached over HTTPS with an API key."""

    external: ClassVar[bool] = True

    def __init__(
        self,
        api_key: str,
        *,
        ttl: timedelta,
        budget: DailyBudget,
        bucket: TokenBucket | None = None,
        retry: RetryPolicy | None = None,
        client: httpx.Client | None = None,
        timeout: float | None = None,
        sleep: Sleep = time.sleep,
    ) -> None:
        super().__init__(ttl)
        if not api_key:
            raise ValueError(f"{self.name}: an API key is required")
        self._api_key = api_key
        self._budget = budget
        self._bucket = bucket
        self._retry = retry or RetryPolicy()
        self._owns_client = client is None
        self._client = client or make_client(timeout)
        self._sleep = sleep

    def __repr__(self) -> str:  # never show the key
        return f"{type(self).__name__}(ttl={self.ttl!r})"

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def auth_headers(self) -> dict[str, str]:
        """Headers carrying the API key."""
        raise NotImplementedError  # pragma: no cover - every provider overrides it

    def exhausted(self, response: httpx.Response) -> bool:
        """Whether a 429 response says the quota is gone for the day (no point retrying)."""
        return False

    def get_json(self, url: str, params: dict[str, str] | None = None) -> dict[str, Any] | None:
        """GET ``url`` and return the JSON object, or ``None`` for 404.

        Raises:
            ProviderError: on authentication failure, rate limiting, exhausted budget, an
                unexpected status or a transient failure that outlasted the retries.
        """
        policy = self._retry
        for attempt in range(1, policy.max_attempts + 1):
            last = attempt == policy.max_attempts
            if self._bucket is not None:
                self._bucket.acquire()
            self._budget.spend()  # every attempt counts, retries included
            try:
                status, body, response = self._fetch(url, params)
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                if last:
                    raise ProviderUnavailableError(
                        f"{type(exc).__name__} after {attempt} attempts"
                    ) from None
                self._sleep(policy.delay(attempt))
                continue
            if status == 200:
                return self._decode(body)
            if status == 404:
                return None
            if status in (401, 403):
                raise ProviderAuthError(f"HTTP {status}: API key rejected")
            if status == 429:
                if self.exhausted(response):
                    raise RateLimitedError("HTTP 429: provider quota used up")
                if last:
                    raise RateLimitedError(f"HTTP 429 after {attempt} attempts")
                self._sleep(policy.delay(attempt, _retry_after(response)))
                continue
            if status >= 500:
                if last:
                    raise ProviderUnavailableError(f"HTTP {status} after {attempt} attempts")
                self._sleep(policy.delay(attempt))
                continue
            raise ProviderError(f"unexpected HTTP {status}")
        raise AssertionError("unreachable")  # pragma: no cover

    def _fetch(self, url: str, params: dict[str, str] | None) -> tuple[int, bytes, httpx.Response]:
        headers = {"Accept": "application/json", **self.auth_headers()}
        with self._client.stream("GET", url, params=params, headers=headers) as response:
            chunks: list[bytes] = []
            size = 0
            for chunk in response.iter_bytes():
                size += len(chunk)
                if size > MAX_RESPONSE_BYTES:
                    raise ProviderUnavailableError(
                        f"response larger than {MAX_RESPONSE_BYTES} bytes"
                    )
                chunks.append(chunk)
        return response.status_code, b"".join(chunks), response

    def _decode(self, body: bytes) -> dict[str, Any]:
        try:
            value = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise ProviderError("response is not valid JSON") from None
        if not isinstance(value, dict):
            raise ProviderError("response is not a JSON object")
        return value
