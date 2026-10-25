"""Tests for the enricher: privacy short-circuit, caching, offline mode and failure handling."""

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from pathlib import Path
from typing import ClassVar

import httpx
import pytest
import respx

from prohori.enrich import EnrichSettings, build_enricher
from prohori.enrich.abuseipdb import CHECK_URL
from prohori.enrich.addresses import IPAddress
from prohori.enrich.cache import EnrichmentCache
from prohori.enrich.enricher import NOT_PUBLIC_NOTE, Enricher
from prohori.enrich.provider import (
    BudgetExhaustedError,
    Provider,
    ProviderAuthError,
    ProviderData,
    ProviderError,
    ProviderUnavailableError,
    RateLimitedError,
)
from prohori.enrich.virustotal import IP_URL

ABUSE = {"data": {"abuseConfidenceScore": 50, "totalReports": 3, "countryCode": "US"}}
VT = {"data": {"attributes": {"last_analysis_stats": {"malicious": 2}, "asn": 15169}}}


class Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 10, 26, 12, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now


class ScriptedProvider(Provider):
    """A provider whose answers (or errors) are given in advance."""

    name: ClassVar[str] = "scripted"
    external: ClassVar[bool] = True
    note: ClassVar[str] = "scripted"

    def __init__(self, *answers: ProviderData | Exception | None) -> None:
        super().__init__(ttl=timedelta(hours=1))
        self.answers = list(answers)
        self.calls: list[str] = []
        self.closed = False

    def lookup(self, address: IPAddress) -> ProviderData | None:
        self.calls.append(str(address))
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer

    def close(self) -> None:
        self.closed = True


@pytest.fixture
def router() -> Iterator[respx.MockRouter]:
    with respx.mock(assert_all_mocked=True, assert_all_called=False) as mock:
        yield mock


def settings(tmp_path: Path, **keys: str) -> EnrichSettings:
    return EnrichSettings.load(
        environ={"PROHORI_CACHE_PATH": str(tmp_path / "c.sqlite3"), **keys}, env_file=None
    )


def no_sleep(seconds: float) -> None:
    raise AssertionError(f"unexpected sleep of {seconds}s")


def test_private_and_documentation_addresses_never_reach_external_providers(
    tmp_path: Path, router: respx.MockRouter
) -> None:
    abuse = router.get(CHECK_URL).mock(return_value=httpx.Response(200, json=ABUSE))
    vt = router.get(url__startswith=IP_URL.format(ip="")).mock(
        return_value=httpx.Response(200, json=VT)
    )
    config = settings(tmp_path, ABUSEIPDB_API_KEY="k1", VIRUSTOTAL_API_KEY="k2")
    with build_enricher(config, sleep=no_sleep) as enricher:
        for address in ("10.0.0.1", "203.0.113.7", "::ffff:192.168.0.1", "fe80::1", "2001:db8::1"):
            report = enricher.enrich_ip(address)
            assert not report.public
            assert report.indicator.enrichment == ()
            assert NOT_PUBLIC_NOTE in report.notes
    assert abuse.call_count == 0
    assert vt.call_count == 0


def test_public_address_uses_every_provider_and_then_the_cache(
    tmp_path: Path, router: respx.MockRouter
) -> None:
    abuse = router.get(CHECK_URL).mock(return_value=httpx.Response(200, json=ABUSE))
    vt = router.get(IP_URL.format(ip="8.8.8.8")).mock(return_value=httpx.Response(200, json=VT))
    config = settings(tmp_path, ABUSEIPDB_API_KEY="k1", VIRUSTOTAL_API_KEY="k2")
    with build_enricher(config, sleep=no_sleep) as enricher:
        first = enricher.enrich_ip("8.8.8.8")
        second = enricher.enrich_ip("8.8.8.8")
    assert [r.provider for r in first.indicator.enrichment] == ["abuseipdb", "virustotal"]
    assert first.indicator.enrichment[0].data["abuse_score"] == 50
    assert first.cached == ()
    assert second.cached == ("abuseipdb", "virustotal")
    assert second.indicator.enrichment == first.indicator.enrichment
    assert abuse.call_count == 1
    assert vt.call_count == 1
    cache = EnrichmentCache(config.cache_path)
    assert cache.requests_today("abuseipdb") == 1  # cache hits do not spend the budget


def test_cache_expiry_triggers_a_new_lookup(tmp_path: Path) -> None:
    clock = Clock()
    provider = ScriptedProvider({"abuse_score": 1}, {"abuse_score": 2})
    enricher = Enricher(
        [provider], EnrichmentCache(tmp_path / "c.sqlite3", clock=clock), clock=clock
    )
    assert enricher.enrich_ip("8.8.8.8").indicator.enrichment[0].data["abuse_score"] == 1
    clock.now += timedelta(minutes=59)
    assert enricher.enrich_ip("8.8.8.8").cached == ("scripted",)
    clock.now += timedelta(minutes=2)
    report = enricher.enrich_ip("8.8.8.8")
    assert report.indicator.enrichment[0].data["abuse_score"] == 2
    assert report.indicator.enrichment[0].retrieved_at == clock.now
    assert provider.calls == ["8.8.8.8", "8.8.8.8"]


def test_no_data_answers_are_cached(tmp_path: Path) -> None:
    provider = ScriptedProvider(None)
    enricher = Enricher([provider], EnrichmentCache(tmp_path / "c.sqlite3"))
    assert enricher.enrich_ip("8.8.8.8").indicator.enrichment == ()
    assert enricher.enrich_ip("8.8.8.8").indicator.enrichment == ()
    assert provider.calls == ["8.8.8.8"]


def test_no_cache_flag_skips_reads_but_still_writes(tmp_path: Path) -> None:
    cache = EnrichmentCache(tmp_path / "c.sqlite3")
    provider = ScriptedProvider({"a": 1}, {"a": 2})
    enricher = Enricher([provider], cache, read_cache=False)
    enricher.enrich_ip("8.8.8.8")
    enricher.enrich_ip("8.8.8.8")
    assert len(provider.calls) == 2
    hit = cache.get("scripted", "8.8.8.8")
    assert hit is not None
    assert hit.data == {"a": 2}


@pytest.mark.parametrize(
    "error",
    [RateLimitedError("HTTP 429"), BudgetExhaustedError("budget"), ProviderAuthError("HTTP 401")],
)
def test_run_level_failures_disable_the_provider(tmp_path: Path, error: ProviderError) -> None:
    provider = ScriptedProvider(error)
    enricher = Enricher([provider], EnrichmentCache(tmp_path / "c.sqlite3"))
    first = enricher.enrich_ip("8.8.8.8")
    second = enricher.enrich_ip("1.1.1.1")
    assert provider.calls == ["8.8.8.8"]
    assert "skipped for the rest of this run" in first.notes[0]
    assert second.notes[0].startswith("scripted: skipped")


def test_failures_are_reported_and_not_cached(tmp_path: Path) -> None:
    provider = ScriptedProvider(ProviderUnavailableError("HTTP 503 after 3 attempts"), {"a": 1})
    enricher = Enricher([provider], EnrichmentCache(tmp_path / "c.sqlite3"))
    failed = enricher.enrich_ip("8.8.8.8")
    assert failed.notes == ("scripted: HTTP 503 after 3 attempts",)
    assert enricher.enrich_ip("8.8.8.8").indicator.enrichment[0].data == {"a": 1}
    assert provider.calls == ["8.8.8.8", "8.8.8.8"]


def test_offline_uses_fixture_and_cache_but_never_the_network(
    tmp_path: Path, router: respx.MockRouter
) -> None:
    route = router.get(CHECK_URL).mock(return_value=httpx.Response(200, json=ABUSE))
    config = settings(tmp_path, ABUSEIPDB_API_KEY="k1")
    EnrichmentCache(config.cache_path).put(
        "abuseipdb", "1.1.1.1", {"abuse_score": 0}, timedelta(hours=1)
    )
    with build_enricher(config, offline=True, sleep=no_sleep) as enricher:
        demo = enricher.enrich_ip("203.0.113.7")
        cached = enricher.enrich_ip("1.1.1.1")
        missing = enricher.enrich_ip("8.8.8.8")
    assert [r.provider for r in demo.indicator.enrichment] == ["offline"]
    assert demo.indicator.enrichment[0].retrieved_at == datetime(2026, 10, 1, tzinfo=UTC)
    assert cached.cached == ("abuseipdb",)
    assert missing.indicator.enrichment == ()
    assert "abuseipdb: not in the cache (offline)" in missing.notes
    assert route.call_count == 0


def test_setup_notes(tmp_path: Path) -> None:
    with build_enricher(settings(tmp_path)) as enricher:
        assert "no providers configured" in enricher.setup_notes[0]
    config = settings(tmp_path, GEOLITE2_CITY_DB=str(tmp_path / "missing.mmdb"))
    with build_enricher(config, offline=True) as enricher:
        assert enricher.setup_notes == (
            f"geolite2: GeoLite2 database not found: {tmp_path / 'missing.mmdb'}",
        )


def test_close_closes_providers(tmp_path: Path) -> None:
    provider = ScriptedProvider()
    with Enricher([provider], None):
        pass
    assert provider.closed


def test_local_providers_answer_for_private_addresses(tmp_path: Path) -> None:
    class Local(ScriptedProvider):
        name: ClassVar[str] = "local"
        external: ClassVar[bool] = False

    provider = Local({"country": "BD"})
    report = Enricher([provider], None).enrich_ip(ip_address("10.1.2.3"))
    assert report.indicator.enrichment[0].data == {"country": "BD"}
    assert report.notes == ()


def test_invalid_address() -> None:
    with pytest.raises(ValueError, match="not-an-ip"):
        Enricher([], None).enrich_ip("not-an-ip")
