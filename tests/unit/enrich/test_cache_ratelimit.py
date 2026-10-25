"""Tests for the SQLite cache, the token bucket, the daily budget and the retry policy."""

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from prohori.enrich.cache import EnrichmentCache, default_cache_path
from prohori.enrich.provider import BudgetExhaustedError, RateLimitedError
from prohori.enrich.ratelimit import DailyBudget, RetryPolicy, TokenBucket


class Clock:
    def __init__(self, start: datetime = datetime(2026, 10, 26, 12, 0, tzinfo=UTC)) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **kwargs: float) -> None:
        self.now += timedelta(**kwargs)


class FakeTime:
    """A monotonic clock whose sleep advances time instantly."""

    def __init__(self) -> None:
        self.t = 0.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.t

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.t += seconds


def make_cache(tmp_path: Path, clock: Clock) -> EnrichmentCache:
    return EnrichmentCache(tmp_path / "sub" / "cache.sqlite3", clock=clock)


class TestCache:
    def test_hit_and_expiry(self, tmp_path: Path) -> None:
        clock = Clock()
        cache = make_cache(tmp_path, clock)
        assert cache.get("abuseipdb", "8.8.8.8") is None
        retrieved = cache.put("abuseipdb", "8.8.8.8", {"abuse_score": 0}, timedelta(hours=1))
        clock.advance(minutes=59)
        hit = cache.get("abuseipdb", "8.8.8.8")
        assert hit is not None
        assert hit.data == {"abuse_score": 0}
        assert hit.retrieved_at == retrieved
        clock.advance(minutes=1)
        assert cache.get("abuseipdb", "8.8.8.8") is None
        assert cache.purge_expired() == 1

    def test_no_data_answers_are_cached(self, tmp_path: Path) -> None:
        cache = make_cache(tmp_path, Clock())
        cache.put("virustotal", "8.8.4.4", None, timedelta(hours=1))
        hit = cache.get("virustotal", "8.8.4.4")
        assert hit is not None
        assert hit.data is None

    def test_entries_are_per_provider(self, tmp_path: Path) -> None:
        cache = make_cache(tmp_path, Clock())
        cache.put("abuseipdb", "1.1.1.1", {"a": 1}, timedelta(hours=1))
        assert cache.get("virustotal", "1.1.1.1") is None

    def test_cache_survives_reopening(self, tmp_path: Path) -> None:
        clock = Clock()
        make_cache(tmp_path, clock).put("abuseipdb", "1.1.1.1", {"a": 1}, timedelta(hours=1))
        assert make_cache(tmp_path, clock).get("abuseipdb", "1.1.1.1") is not None

    @pytest.mark.parametrize("value", ["not json", "[1, 2]"])
    def test_corrupted_entries_are_misses(self, tmp_path: Path, value: str) -> None:
        clock = Clock()
        cache = make_cache(tmp_path, clock)
        cache.put("abuseipdb", "1.1.1.1", {"a": 1}, timedelta(hours=1))
        db = sqlite3.connect(cache.path)
        with db:
            db.execute("UPDATE lookups SET value = ?", (value,))
        db.close()
        assert cache.get("abuseipdb", "1.1.1.1") is None

    def test_file_is_not_held_open(self, tmp_path: Path) -> None:
        cache = make_cache(tmp_path, Clock())
        cache.put("abuseipdb", "1.1.1.1", {"a": 1}, timedelta(hours=1))
        cache.path.unlink()  # fails on Windows if a connection were still open

    def test_daily_usage_resets_at_utc_midnight(self, tmp_path: Path) -> None:
        clock = Clock(datetime(2026, 10, 26, 23, 59, tzinfo=UTC))
        cache = make_cache(tmp_path, clock)
        assert cache.count_request("virustotal") == 1
        assert cache.count_request("virustotal") == 2
        assert cache.requests_today("abuseipdb") == 0
        clock.advance(minutes=1)
        assert cache.requests_today("virustotal") == 0

    def test_default_path(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
        assert default_cache_path() == tmp_path / "prohori" / "enrich.sqlite3"


class TestTokenBucket:
    def test_burst_then_wait(self) -> None:
        fake = FakeTime()
        bucket = TokenBucket.per_minute(4, monotonic=fake.monotonic, sleep=fake.sleep)
        for _ in range(4):
            bucket.acquire()
        assert fake.sleeps == []
        bucket.acquire()
        assert fake.sleeps == [pytest.approx(15.0)]

    def test_refills_over_time(self) -> None:
        fake = FakeTime()
        bucket = TokenBucket(1.0, 2, monotonic=fake.monotonic, sleep=fake.sleep)
        bucket.acquire()
        bucket.acquire()
        fake.t += 5
        bucket.acquire()
        bucket.acquire()
        assert fake.sleeps == []

    def test_refuses_long_waits(self) -> None:
        fake = FakeTime()
        bucket = TokenBucket(1 / 600, 1, max_wait=60, monotonic=fake.monotonic, sleep=fake.sleep)
        bucket.acquire()
        with pytest.raises(RateLimitedError):
            bucket.acquire()
        assert fake.sleeps == []

    @pytest.mark.parametrize(("rate", "capacity"), [(0, 1), (1, 0.5)])
    def test_invalid(self, rate: float, capacity: float) -> None:
        with pytest.raises(ValueError, match="rate must be positive"):
            TokenBucket(rate, capacity)


class TestDailyBudget:
    def test_spend_until_exhausted(self, tmp_path: Path) -> None:
        cache = make_cache(tmp_path, Clock())
        budget = DailyBudget("abuseipdb", 2, cache)
        budget.spend()
        budget.spend()
        assert budget.remaining() == 0
        with pytest.raises(BudgetExhaustedError):
            budget.spend()
        assert cache.requests_today("abuseipdb") == 2

    def test_budget_is_shared_across_runs(self, tmp_path: Path) -> None:
        clock = Clock()
        DailyBudget("abuseipdb", 2, make_cache(tmp_path, clock)).spend()
        assert DailyBudget("abuseipdb", 2, make_cache(tmp_path, clock)).remaining() == 1


class TestRetryPolicy:
    def test_exponential_backoff_is_capped(self) -> None:
        policy = RetryPolicy(base_delay=1, max_delay=5)
        assert [policy.delay(n) for n in (1, 2, 3, 4)] == [1, 2, 4, 5]

    def test_retry_after_is_honoured_up_to_the_cap(self) -> None:
        policy = RetryPolicy(max_delay=60)
        assert policy.delay(1, retry_after=7) == 7
        with pytest.raises(RateLimitedError):
            policy.delay(1, retry_after=3600)
