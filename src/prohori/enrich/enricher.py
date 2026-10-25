"""Run IP addresses through the configured providers, with caching and safe failure handling.

* External providers only ever see public addresses (:func:`prohori.enrich.addresses.is_public`).
* Offline mode never touches the network: local providers answer, and external providers answer
  only from the cache.
* A provider that is rate limited, out of budget or rejects its key is skipped for the rest of
  the run; other failures are reported for the one address. Failures are never cached.
"""

import time
from collections.abc import Sequence
from datetime import datetime
from types import TracebackType
from typing import Self

from pydantic import BaseModel, ConfigDict

from prohori.enrich.abuseipdb import AbuseIPDBProvider
from prohori.enrich.addresses import IPAddress, canonical, is_public, parse_ip
from prohori.enrich.cache import Clock, EnrichmentCache, utc_now
from prohori.enrich.config import EnrichSettings
from prohori.enrich.geolite import GeoLiteProvider
from prohori.enrich.offline import OfflineProvider
from prohori.enrich.provider import (
    BudgetExhaustedError,
    Provider,
    ProviderAuthError,
    ProviderData,
    ProviderError,
    RateLimitedError,
)
from prohori.enrich.ratelimit import DailyBudget, Sleep, TokenBucket
from prohori.enrich.virustotal import VirusTotalProvider
from prohori.schema import EnrichmentResult, Indicator, IndicatorType
from prohori.schema.types import Text

NOT_PUBLIC_NOTE = "not sent to external providers: private, reserved or documentation address"


class EnrichmentReport(BaseModel):
    """Enrichment of one indicator: provider results plus notes on what was skipped or failed."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    indicator: Indicator
    public: bool
    cached: tuple[str, ...] = ()
    notes: tuple[Text, ...] = ()


class Enricher:
    """Looks up IP addresses with a fixed list of providers."""

    def __init__(
        self,
        providers: Sequence[Provider],
        cache: EnrichmentCache | None = None,
        *,
        offline: bool = False,
        read_cache: bool = True,
        clock: Clock = utc_now,
        setup_notes: Sequence[str] = (),
    ) -> None:
        self.providers = list(providers)
        self.cache = cache
        self.offline = offline
        self.read_cache = read_cache
        self.setup_notes = tuple(setup_notes)
        self._clock = clock
        self._disabled: dict[str, str] = {}

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        for provider in self.providers:
            provider.close()

    def enrich_ip(self, value: str | IPAddress) -> EnrichmentReport:
        """Enrich one IP address.

        Raises:
            ValueError: if ``value`` is not a valid IP address.
        """
        address = canonical(parse_ip(value) if isinstance(value, str) else value)
        public = is_public(address)
        results: list[EnrichmentResult] = []
        cached: list[str] = []
        notes: list[str] = []
        if not public and any(p.external for p in self.providers):
            notes.append(NOT_PUBLIC_NOTE)
        for provider in self.providers:
            if provider.external and not public:
                continue
            outcome = self._lookup(provider, address, notes)
            if outcome is None:
                continue
            result, from_cache = outcome
            results.append(result)
            if from_cache:
                cached.append(provider.name)
        indicator = Indicator(type=IndicatorType.IP, value=str(address), enrichment=tuple(results))
        return EnrichmentReport(
            indicator=indicator, public=public, cached=tuple(cached), notes=tuple(notes)
        )

    def _lookup(
        self, provider: Provider, address: IPAddress, notes: list[str]
    ) -> tuple[EnrichmentResult, bool] | None:
        name = provider.name
        if name in self._disabled:
            notes.append(f"{name}: skipped ({self._disabled[name]})")
            return None
        key = str(address)
        cache = self.cache if provider.ttl.total_seconds() > 0 else None
        if cache is not None and self.read_cache:
            hit = cache.get(name, key)
            if hit is not None:
                if hit.data is None:
                    return None
                return self._result(provider, hit.data, hit.retrieved_at), True
        if provider.external and self.offline:
            notes.append(f"{name}: not in the cache (offline)")
            return None
        try:
            data = provider.lookup(address)
        except (RateLimitedError, BudgetExhaustedError, ProviderAuthError) as exc:
            self._disabled[name] = str(exc)
            notes.append(f"{name}: {exc}; skipped for the rest of this run")
            return None
        except ProviderError as exc:
            notes.append(f"{name}: {exc}")
            return None
        retrieved_at = provider.retrieved_at(self._clock())
        if cache is not None:
            retrieved_at = cache.put(name, key, data, provider.ttl)
        if data is None:
            return None
        return self._result(provider, data, retrieved_at), False

    @staticmethod
    def _result(provider: Provider, data: ProviderData, at: datetime) -> EnrichmentResult:
        return EnrichmentResult.model_validate(
            {"provider": provider.name, "retrieved_at": at, "data": data, "note": provider.note}
        )


def build_enricher(
    settings: EnrichSettings,
    *,
    offline: bool = False,
    read_cache: bool = True,
    clock: Clock = utc_now,
    sleep: Sleep = time.sleep,
) -> Enricher:
    """Create an enricher with every provider the settings enable.

    Offline runs add the bundled fixture and never open a network connection. Problems with a
    single provider (such as a missing GeoLite2 file) become setup notes instead of errors.
    """
    providers: list[Provider] = []
    notes: list[str] = []
    if offline:
        providers.append(OfflineProvider())
    if settings.geolite2_city_db or settings.geolite2_asn_db:
        try:
            providers.append(GeoLiteProvider(settings.geolite2_city_db, settings.geolite2_asn_db))
        except ProviderError as exc:
            notes.append(f"geolite2: {exc}")
    cache = EnrichmentCache(settings.cache_path, clock=clock)
    if settings.abuseipdb_api_key:
        providers.append(
            AbuseIPDBProvider(
                settings.abuseipdb_api_key,
                ttl=settings.cache_ttl,
                budget=DailyBudget("abuseipdb", settings.abuseipdb_daily_limit, cache),
                timeout=settings.http_timeout,
                sleep=sleep,
            )
        )
    if settings.virustotal_api_key:
        providers.append(
            VirusTotalProvider(
                settings.virustotal_api_key,
                ttl=settings.cache_ttl,
                budget=DailyBudget("virustotal", settings.virustotal_daily_limit, cache),
                bucket=TokenBucket.per_minute(settings.virustotal_per_minute, sleep=sleep),
                timeout=settings.http_timeout,
                sleep=sleep,
            )
        )
    if not providers:
        notes.append(
            "no providers configured: set ABUSEIPDB_API_KEY, VIRUSTOTAL_API_KEY or "
            "GEOLITE2_CITY_DB (see docs/ENRICHMENT.md), or use --offline for demo data"
        )
    return Enricher(
        providers, cache, offline=offline, read_cache=read_cache, clock=clock, setup_notes=notes
    )
