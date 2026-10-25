"""The interface every enrichment provider implements, and the errors providers raise.

Providers return their findings as a flat mapping using the shared keys in :data:`RESULT_KEYS`
(where they apply), so later steps can score reputation without knowing which provider answered.
"""

from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import ClassVar

from prohori.enrich.addresses import IPAddress
from prohori.parsers import sanitize
from prohori.schema import JsonScalar

#: Shared result keys and their meaning. Providers may add their own keys as well.
RESULT_KEYS: dict[str, str] = {
    "country": "ISO 3166-1 alpha-2 country code",
    "city": "City name (GeoLite2 City)",
    "asn": "Autonomous system number",
    "as_org": "Organisation owning the autonomous system, or the ISP",
    "network": "Network range the address belongs to",
    "abuse_score": "Abuse confidence score from 0 to 100 (AbuseIPDB)",
    "reports": "Number of abuse reports (AbuseIPDB)",
    "malicious": "Number of security vendors flagging the address as malicious (VirusTotal)",
    "suspicious": "Number of security vendors flagging the address as suspicious (VirusTotal)",
    "is_tor": "Known Tor exit node (AbuseIPDB)",
    "usage_type": "Kind of network, such as Data Center or ISP (AbuseIPDB)",
}

ProviderData = dict[str, JsonScalar]

#: Longest string kept from a provider response; longer values are cut.
MAX_VALUE_LENGTH = 256


class ProviderError(Exception):
    """A lookup failed. The message is safe to show: it never contains keys or headers."""


class ProviderUnavailableError(ProviderError):
    """A transient failure (timeout, server error); a later run may succeed."""


class RateLimitedError(ProviderError):
    """The provider asked us to slow down for longer than this run will wait."""


class BudgetExhaustedError(ProviderError):
    """The configured daily request budget for this provider is used up."""


class ProviderAuthError(ProviderError):
    """The provider rejected the API key."""


class Provider(ABC):
    """An enrichment source for IP addresses."""

    #: Short identifier used in results and the cache, such as ``abuseipdb``.
    name: ClassVar[str]
    #: Whether lookups leave this machine. External providers only see public addresses.
    external: ClassVar[bool]
    #: Shown with every result to say how far the data can be trusted.
    note: ClassVar[str]

    def __init__(self, ttl: timedelta) -> None:
        self.ttl = ttl

    @abstractmethod
    def lookup(self, address: IPAddress) -> ProviderData | None:
        """Return what the provider knows about ``address``, or ``None`` if it knows nothing.

        Raises:
            ProviderError: if the lookup failed; the failure is reported, never cached.
        """

    def retrieved_at(self, now: datetime) -> datetime:
        """When the data returned by :meth:`lookup` was retrieved (``now`` for live lookups)."""
        return now

    def close(self) -> None:  # noqa: B027 - optional hook, most providers hold nothing
        """Release files or connections the provider holds."""


def clean_text(value: object) -> str | None:
    """Turn an untrusted provider value into short, printable text (``None`` if empty)."""
    if value is None:
        return None
    text = sanitize(str(value)).strip()
    return text[:MAX_VALUE_LENGTH] or None


def clean_int(value: object) -> int | None:
    """Return ``value`` as an int if it is one (booleans excluded), else ``None``."""
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value
