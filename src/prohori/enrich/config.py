"""Enrichment settings from environment variables and an optional ``.env`` file.

Environment variables win over ``.env``. Only the variables listed in :data:`ENV_VARS` are read
(provider endpoints are fixed in code and cannot be configured). API keys are kept out of
``repr`` and error messages.
"""

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path

from prohori.enrich.cache import default_cache_path

#: Every variable Prohori's enrichment reads, with its meaning.
ENV_VARS: dict[str, str] = {
    "ABUSEIPDB_API_KEY": "AbuseIPDB API key (enables the abuseipdb provider)",
    "VIRUSTOTAL_API_KEY": "VirusTotal API key (enables the virustotal provider)",
    "GEOLITE2_CITY_DB": "Path to GeoLite2-City.mmdb or GeoLite2-Country.mmdb",
    "GEOLITE2_ASN_DB": "Path to GeoLite2-ASN.mmdb",
    "PROHORI_CACHE_PATH": "SQLite cache file (default: the per-user cache directory)",
    "PROHORI_CACHE_TTL_HOURS": "How long cached answers stay valid, in hours (default 24)",
    "ABUSEIPDB_DAILY_LIMIT": "AbuseIPDB requests per UTC day (default 1000)",
    "VIRUSTOTAL_DAILY_LIMIT": "VirusTotal requests per UTC day (default 500)",
    "VIRUSTOTAL_PER_MINUTE": "VirusTotal requests per minute (default 4)",
    "PROHORI_HTTP_TIMEOUT": "Timeout for each HTTP request, in seconds (default 10)",
}

#: Largest ``.env`` file read.
MAX_ENV_FILE_BYTES = 64 * 1024


class ConfigError(ValueError):
    """A setting has an invalid value."""


def read_env_file(path: Path) -> dict[str, str]:
    """Read ``KEY=VALUE`` lines from ``path``; only known variables are returned."""
    if not path.is_file() or path.stat().st_size > MAX_ENV_FILE_BYTES:
        return {}
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.removeprefix("export ").partition("=")
        key, value = key.strip(), value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if key in ENV_VARS:
            values[key] = value
    return values


def _positive(values: Mapping[str, str], key: str, default: float) -> float:
    raw = values.get(key, "").strip()
    if not raw:
        return default
    try:
        number = float(raw)
    except ValueError:
        raise ConfigError(f"{key} must be a number, not {raw!r}") from None
    if not number > 0:
        raise ConfigError(f"{key} must be greater than zero")
    return number


def _count(values: Mapping[str, str], key: str, default: int) -> int:
    number = _positive(values, key, default)
    if number != int(number):
        raise ConfigError(f"{key} must be a whole number")
    return int(number)


def _path(values: Mapping[str, str], key: str) -> Path | None:
    raw = values.get(key, "").strip()
    return Path(raw).expanduser() if raw else None


@dataclass(frozen=True)
class EnrichSettings:
    """Resolved enrichment configuration."""

    abuseipdb_api_key: str = field(default="", repr=False)
    virustotal_api_key: str = field(default="", repr=False)
    geolite2_city_db: Path | None = None
    geolite2_asn_db: Path | None = None
    cache_path: Path = field(default_factory=default_cache_path)
    cache_ttl: timedelta = timedelta(hours=24)
    abuseipdb_daily_limit: int = 1000
    virustotal_daily_limit: int = 500
    virustotal_per_minute: int = 4
    http_timeout: float = 10.0

    @classmethod
    def load(
        cls, environ: Mapping[str, str] | None = None, env_file: Path | None = Path(".env")
    ) -> "EnrichSettings":
        """Build settings from ``environ`` (default ``os.environ``) over ``env_file``.

        Raises:
            ConfigError: if a numeric setting is invalid.
        """
        values = read_env_file(env_file) if env_file is not None else {}
        values.update({k: v for k, v in (environ or os.environ).items() if k in ENV_VARS})
        return cls(
            abuseipdb_api_key=values.get("ABUSEIPDB_API_KEY", "").strip(),
            virustotal_api_key=values.get("VIRUSTOTAL_API_KEY", "").strip(),
            geolite2_city_db=_path(values, "GEOLITE2_CITY_DB"),
            geolite2_asn_db=_path(values, "GEOLITE2_ASN_DB"),
            cache_path=_path(values, "PROHORI_CACHE_PATH") or default_cache_path(),
            cache_ttl=timedelta(hours=_positive(values, "PROHORI_CACHE_TTL_HOURS", 24)),
            abuseipdb_daily_limit=_count(values, "ABUSEIPDB_DAILY_LIMIT", 1000),
            virustotal_daily_limit=_count(values, "VIRUSTOTAL_DAILY_LIMIT", 500),
            virustotal_per_minute=_count(values, "VIRUSTOTAL_PER_MINUTE", 4),
            http_timeout=_positive(values, "PROHORI_HTTP_TIMEOUT", 10),
        )
