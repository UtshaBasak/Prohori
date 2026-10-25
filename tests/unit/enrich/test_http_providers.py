"""Tests for the AbuseIPDB and VirusTotal providers with mocked HTTP (respx)."""

import socket
from collections.abc import Iterator
from datetime import timedelta
from ipaddress import ip_address
from pathlib import Path

import httpx
import pytest
import respx

from prohori.enrich.abuseipdb import CHECK_URL, AbuseIPDBProvider
from prohori.enrich.cache import EnrichmentCache
from prohori.enrich.http import MAX_RESPONSE_BYTES
from prohori.enrich.provider import (
    BudgetExhaustedError,
    ProviderAuthError,
    ProviderError,
    ProviderUnavailableError,
    RateLimitedError,
)
from prohori.enrich.ratelimit import DailyBudget, RetryPolicy, TokenBucket
from prohori.enrich.virustotal import IP_URL, VirusTotalProvider
from tests.unit.enrich.conftest import NetworkAccessError

KEY = "test-key-not-real"
IP = ip_address("8.8.8.8")
VT_URL = IP_URL.format(ip=IP)

ABUSE_BODY = {
    "data": {
        "ipAddress": "8.8.8.8",
        "isPublic": True,
        "isWhitelisted": False,
        "abuseConfidenceScore": 87,
        "countryCode": "US",
        "usageType": "Data Center/Web Hosting/Transit",
        "isp": "Example ISP\x1b[31m",
        "domain": "example.net",
        "isTor": False,
        "totalReports": 41,
        "numDistinctUsers": 12,
        "lastReportedAt": "2026-10-25T10:00:00+00:00",
    }
}

VT_BODY = {
    "data": {
        "id": "8.8.8.8",
        "type": "ip_address",
        "attributes": {
            "last_analysis_stats": {
                "harmless": 60,
                "malicious": 3,
                "suspicious": 1,
                "undetected": 30,
                "timeout": 0,
            },
            "reputation": -5,
            "country": "US",
            "asn": 15169,
            "as_owner": "Example LLC",
            "network": "8.8.8.0/24",
            "last_analysis_date": 1793000000,
            "whois": "x" * 5000,
        },
    }
}


class Sleeps(list[float]):
    def __call__(self, seconds: float) -> None:
        self.append(seconds)


@pytest.fixture
def router() -> Iterator[respx.MockRouter]:
    with respx.mock(assert_all_mocked=True, assert_all_called=False) as mock:
        yield mock


@pytest.fixture
def cache(tmp_path: Path) -> EnrichmentCache:
    return EnrichmentCache(tmp_path / "cache.sqlite3")


def abuse(cache: EnrichmentCache, sleeps: Sleeps, limit: int = 100) -> AbuseIPDBProvider:
    return AbuseIPDBProvider(
        KEY,
        ttl=timedelta(hours=1),
        budget=DailyBudget("abuseipdb", limit, cache),
        retry=RetryPolicy(max_attempts=3, base_delay=1, max_delay=60),
        sleep=sleeps,
    )


def virustotal(cache: EnrichmentCache, sleeps: Sleeps) -> VirusTotalProvider:
    return VirusTotalProvider(
        KEY,
        ttl=timedelta(hours=1),
        budget=DailyBudget("virustotal", 100, cache),
        bucket=TokenBucket.per_minute(4, sleep=sleeps),
        sleep=sleeps,
    )


def test_network_guard_is_active() -> None:
    with pytest.raises(NetworkAccessError):
        socket.create_connection(("example.com", 443))
    with pytest.raises(NetworkAccessError):
        socket.getaddrinfo("example.com", 443)
    with pytest.raises(NetworkAccessError), socket.socket() as sock:
        sock.connect(("192.0.2.1", 443))


def test_abuseipdb_lookup(cache: EnrichmentCache, router: respx.MockRouter) -> None:
    route = router.get(CHECK_URL).mock(return_value=httpx.Response(200, json=ABUSE_BODY))
    data = abuse(cache, Sleeps()).lookup(IP)
    assert data == {
        "abuse_score": 87,
        "reports": 41,
        "distinct_reporters": 12,
        "country": "US",
        "as_org": "Example ISP",  # control sequences stripped
        "domain": "example.net",
        "usage_type": "Data Center/Web Hosting/Transit",
        "is_tor": False,
        "is_whitelisted": False,
        "last_reported_at": "2026-10-25T10:00:00+00:00",
    }
    request = route.calls.last.request
    assert request.headers["Key"] == KEY
    assert request.url.params["ipAddress"] == "8.8.8.8"
    assert KEY not in str(request.url)


def test_virustotal_lookup(cache: EnrichmentCache, router: respx.MockRouter) -> None:
    route = router.get(VT_URL).mock(return_value=httpx.Response(200, json=VT_BODY))
    data = virustotal(cache, Sleeps()).lookup(IP)
    assert data == {
        "malicious": 3,
        "suspicious": 1,
        "harmless": 60,
        "undetected": 30,
        "reputation": -5,
        "country": "US",
        "asn": 15169,
        "as_org": "Example LLC",
        "network": "8.8.8.0/24",
        "last_analysis_at": "2026-10-26T07:33:20+00:00",
    }
    assert route.calls.last.request.headers["x-apikey"] == KEY


def test_not_found_is_no_data(cache: EnrichmentCache, router: respx.MockRouter) -> None:
    router.get(VT_URL).mock(return_value=httpx.Response(404, json={"error": {}}))
    assert virustotal(cache, Sleeps()).lookup(IP) is None


def test_429_then_success_waits_for_retry_after(
    cache: EnrichmentCache, router: respx.MockRouter
) -> None:
    route = router.get(CHECK_URL).mock(
        side_effect=[
            httpx.Response(429, headers={"Retry-After": "7"}),
            httpx.Response(200, json=ABUSE_BODY),
        ]
    )
    sleeps = Sleeps()
    assert abuse(cache, sleeps).lookup(IP) is not None
    assert sleeps == [7.0]
    assert route.call_count == 2
    assert cache.requests_today("abuseipdb") == 2  # retries count against the budget


def test_repeated_429_gives_up_after_bounded_attempts(
    cache: EnrichmentCache, router: respx.MockRouter
) -> None:
    route = router.get(CHECK_URL).mock(return_value=httpx.Response(429))
    sleeps = Sleeps()
    with pytest.raises(RateLimitedError, match="after 3 attempts"):
        abuse(cache, sleeps).lookup(IP)
    assert route.call_count == 3
    assert sleeps == [1.0, 2.0]


def test_long_retry_after_is_not_waited_for(
    cache: EnrichmentCache, router: respx.MockRouter
) -> None:
    router.get(CHECK_URL).mock(return_value=httpx.Response(429, headers={"Retry-After": "86400"}))
    sleeps = Sleeps()
    with pytest.raises(RateLimitedError, match="86400"):
        abuse(cache, sleeps).lookup(IP)
    assert sleeps == []


def test_abuseipdb_daily_quota_used_up(cache: EnrichmentCache, router: respx.MockRouter) -> None:
    route = router.get(CHECK_URL).mock(
        return_value=httpx.Response(429, headers={"Retry-After": "5", "X-RateLimit-Remaining": "0"})
    )
    with pytest.raises(RateLimitedError, match="quota"):
        abuse(cache, Sleeps()).lookup(IP)
    assert route.call_count == 1


def test_budget_exhausted_sends_nothing(cache: EnrichmentCache, router: respx.MockRouter) -> None:
    route = router.get(CHECK_URL).mock(return_value=httpx.Response(200, json=ABUSE_BODY))
    provider = abuse(cache, Sleeps(), limit=1)
    provider.lookup(IP)
    with pytest.raises(BudgetExhaustedError):
        provider.lookup(IP)
    assert route.call_count == 1


@pytest.mark.parametrize("status", [401, 403])
def test_auth_errors_are_not_retried(
    cache: EnrichmentCache, status: int, router: respx.MockRouter
) -> None:
    route = router.get(CHECK_URL).mock(return_value=httpx.Response(status))
    with pytest.raises(ProviderAuthError) as info:
        abuse(cache, Sleeps()).lookup(IP)
    assert route.call_count == 1
    assert KEY not in str(info.value)


def test_server_errors_are_retried_then_reported(
    cache: EnrichmentCache, router: respx.MockRouter
) -> None:
    route = router.get(CHECK_URL).mock(
        side_effect=[httpx.Response(503), httpx.Response(200, json=ABUSE_BODY)]
    )
    assert abuse(cache, Sleeps()).lookup(IP) is not None
    assert route.call_count == 2
    router.get(CHECK_URL).mock(return_value=httpx.Response(500))
    with pytest.raises(ProviderUnavailableError, match="HTTP 500 after 3 attempts"):
        abuse(cache, Sleeps()).lookup(IP)


def test_timeouts_are_retried_then_reported(
    cache: EnrichmentCache, router: respx.MockRouter
) -> None:
    route = router.get(CHECK_URL).mock(side_effect=httpx.ConnectTimeout("slow"))
    sleeps = Sleeps()
    with pytest.raises(ProviderUnavailableError, match="ConnectTimeout after 3 attempts"):
        abuse(cache, sleeps).lookup(IP)
    assert route.call_count == 3
    assert sleeps == [1.0, 2.0]


def test_unexpected_status(cache: EnrichmentCache, router: respx.MockRouter) -> None:
    router.get(CHECK_URL).mock(return_value=httpx.Response(418))
    with pytest.raises(ProviderError, match="unexpected HTTP 418"):
        abuse(cache, Sleeps()).lookup(IP)


def test_redirects_are_not_followed(cache: EnrichmentCache, router: respx.MockRouter) -> None:
    router.get(CHECK_URL).mock(
        return_value=httpx.Response(302, headers={"Location": "https://attacker.invalid/"})
    )
    with pytest.raises(ProviderError, match="unexpected HTTP 302"):
        abuse(cache, Sleeps()).lookup(IP)


@pytest.mark.parametrize(
    ("body", "message"),
    [
        (b"not json", "not valid JSON"),
        (b"[1, 2]", "not a JSON object"),
        (b'{"errors": []}', "no 'data' object"),
    ],
)
def test_malformed_abuseipdb_responses(
    cache: EnrichmentCache, body: bytes, message: str, router: respx.MockRouter
) -> None:
    router.get(CHECK_URL).mock(return_value=httpx.Response(200, content=body))
    with pytest.raises(ProviderError, match=message):
        abuse(cache, Sleeps()).lookup(IP)


def test_malformed_virustotal_response(cache: EnrichmentCache, router: respx.MockRouter) -> None:
    router.get(VT_URL).mock(return_value=httpx.Response(200, json={"data": "x"}))
    with pytest.raises(ProviderError, match=r"data\.attributes"):
        virustotal(cache, Sleeps()).lookup(IP)


def test_virustotal_ignores_bad_field_types(
    cache: EnrichmentCache, router: respx.MockRouter
) -> None:
    body = {"data": {"attributes": {"last_analysis_stats": "x", "asn": "15169", "country": None}}}
    router.get(VT_URL).mock(return_value=httpx.Response(200, json=body))
    assert virustotal(cache, Sleeps()).lookup(IP) == {}


def test_oversized_responses_are_rejected(cache: EnrichmentCache, router: respx.MockRouter) -> None:
    router.get(CHECK_URL).mock(
        return_value=httpx.Response(200, content=b"x" * (MAX_RESPONSE_BYTES + 1))
    )
    with pytest.raises(ProviderUnavailableError, match="larger than"):
        abuse(cache, Sleeps()).lookup(IP)


def test_key_is_required_and_hidden(cache: EnrichmentCache) -> None:
    with pytest.raises(ValueError, match="API key"):
        AbuseIPDBProvider("", ttl=timedelta(hours=1), budget=DailyBudget("abuseipdb", 1, cache))
    provider = abuse(cache, Sleeps())
    assert KEY not in repr(provider)
    provider.close()


def test_supplied_client_is_not_closed(cache: EnrichmentCache) -> None:
    client = httpx.Client()
    provider = AbuseIPDBProvider(
        KEY, ttl=timedelta(hours=1), budget=DailyBudget("abuseipdb", 1, cache), client=client
    )
    provider.close()
    assert not client.is_closed
    client.close()
