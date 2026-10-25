"""Enrichment tests never touch the network or the developer's real cache."""

import socket
from pathlib import Path
from typing import Any

import pytest


class NetworkAccessError(AssertionError):
    """Raised when a test tries to open a real network connection."""


def _blocked(*args: Any, **kwargs: Any) -> Any:
    raise NetworkAccessError("tests must not open network connections; mock HTTP with respx")


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket.socket, "connect", _blocked)
    monkeypatch.setattr(socket.socket, "connect_ex", _blocked)
    monkeypatch.setattr(socket, "create_connection", _blocked)
    monkeypatch.setattr(socket, "getaddrinfo", _blocked)


@pytest.fixture(autouse=True)
def isolated_settings(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Point the cache at a temporary file and hide any real keys or .env file."""
    for name in (
        "ABUSEIPDB_API_KEY",
        "VIRUSTOTAL_API_KEY",
        "GEOLITE2_CITY_DB",
        "GEOLITE2_ASN_DB",
        "PROHORI_CACHE_TTL_HOURS",
        "ABUSEIPDB_DAILY_LIMIT",
        "VIRUSTOTAL_DAILY_LIMIT",
        "VIRUSTOTAL_PER_MINUTE",
        "PROHORI_HTTP_TIMEOUT",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("PROHORI_CACHE_PATH", str(tmp_path / "cache" / "enrich.sqlite3"))
    monkeypatch.chdir(tmp_path)  # no stray .env from the working directory
