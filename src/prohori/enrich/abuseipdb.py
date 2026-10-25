"""AbuseIPDB reputation lookups (API v2 ``check`` endpoint).

Docs: https://docs.abuseipdb.com/ (checked 2026-10-26). The free (Standard) plan allows 1,000
checks per day and is for non-commercial use; see ``docs/LICENSES.md``.
"""

from typing import ClassVar

import httpx

from prohori.enrich.addresses import IPAddress
from prohori.enrich.http import HttpProvider
from prohori.enrich.provider import ProviderData, ProviderError, clean_int, clean_text

CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
#: Reports older than this many days are ignored by AbuseIPDB when scoring.
MAX_AGE_DAYS = 90


class AbuseIPDBProvider(HttpProvider):
    """Abuse confidence score and report counts from AbuseIPDB."""

    name: ClassVar[str] = "abuseipdb"
    note: ClassVar[str] = (
        f"AbuseIPDB community reports from the last {MAX_AGE_DAYS} days; "
        "the score reflects reports, not proof of abuse."
    )

    def auth_headers(self) -> dict[str, str]:
        return {"Key": self._api_key}

    def exhausted(self, response: httpx.Response) -> bool:
        remaining: str = response.headers.get("X-RateLimit-Remaining", "")
        return remaining.strip() == "0"

    def lookup(self, address: IPAddress) -> ProviderData | None:
        body = self.get_json(
            CHECK_URL, {"ipAddress": str(address), "maxAgeInDays": str(MAX_AGE_DAYS)}
        )
        if body is None:
            return None
        data = body.get("data")
        if not isinstance(data, dict):
            raise ProviderError("unexpected response: no 'data' object")
        result: ProviderData = {
            "abuse_score": clean_int(data.get("abuseConfidenceScore")),
            "reports": clean_int(data.get("totalReports")),
            "distinct_reporters": clean_int(data.get("numDistinctUsers")),
            "country": clean_text(data.get("countryCode")),
            "as_org": clean_text(data.get("isp")),
            "domain": clean_text(data.get("domain")),
            "usage_type": clean_text(data.get("usageType")),
            "is_tor": data.get("isTor") if isinstance(data.get("isTor"), bool) else None,
            "is_whitelisted": (
                data.get("isWhitelisted") if isinstance(data.get("isWhitelisted"), bool) else None
            ),
            "last_reported_at": clean_text(data.get("lastReportedAt")),
        }
        return {key: value for key, value in result.items() if value is not None}
