"""VirusTotal IP address reports (API v3).

Docs: https://docs.virustotal.com/reference/ip-info (checked 2026-10-26). The public API allows 4
requests per minute and 500 per day and must not be used in commercial products or services.
Queried indicators are added to the VirusTotal dataset; see ``docs/ENRICHMENT.md``.
"""

from datetime import UTC, datetime
from typing import ClassVar

from prohori.enrich.addresses import IPAddress
from prohori.enrich.http import HttpProvider
from prohori.enrich.provider import ProviderData, ProviderError, clean_int, clean_text

IP_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"


class VirusTotalProvider(HttpProvider):
    """Security-vendor verdicts and network ownership from VirusTotal."""

    name: ClassVar[str] = "virustotal"
    note: ClassVar[str] = (
        "VirusTotal vendor verdicts from the last analysis; a few detections are common for "
        "shared hosting and may be stale."
    )

    def auth_headers(self) -> dict[str, str]:
        return {"x-apikey": self._api_key}

    def lookup(self, address: IPAddress) -> ProviderData | None:
        # The address is a parsed ipaddress object, so its text form is safe in the URL path.
        body = self.get_json(IP_URL.format(ip=address))
        if body is None:
            return None
        data = body.get("data")
        attributes = data.get("attributes") if isinstance(data, dict) else None
        if not isinstance(attributes, dict):
            raise ProviderError("unexpected response: no 'data.attributes' object")
        stats = attributes.get("last_analysis_stats")
        stats = stats if isinstance(stats, dict) else {}
        analysed = clean_int(attributes.get("last_analysis_date"))
        result: ProviderData = {
            "malicious": clean_int(stats.get("malicious")),
            "suspicious": clean_int(stats.get("suspicious")),
            "harmless": clean_int(stats.get("harmless")),
            "undetected": clean_int(stats.get("undetected")),
            "reputation": clean_int(attributes.get("reputation")),
            "country": clean_text(attributes.get("country")),
            "asn": clean_int(attributes.get("asn")),
            "as_org": clean_text(attributes.get("as_owner")),
            "network": clean_text(attributes.get("network")),
            "last_analysis_at": (
                datetime.fromtimestamp(analysed, tz=UTC).isoformat()
                if analysed is not None and 0 <= analysed < 2**33
                else None
            ),
        }
        return {key: value for key, value in result.items() if value is not None}
