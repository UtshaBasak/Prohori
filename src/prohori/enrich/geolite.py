"""Geolocation and network ownership from local MaxMind GeoLite2 databases.

Lookups never leave the machine, so this provider also answers for private and documentation
addresses (the databases simply have no data for them). Prohori never downloads or bundles the
databases: GeoLite2 needs a free MaxMind account, and its licence forbids redistribution and
requires replacing old copies within 30 days of an update (see ``docs/LICENSES.md``). Requires
the ``geoip`` extra: ``pip install "prohori[geoip]"``.
"""

from collections.abc import Callable
from datetime import timedelta
from pathlib import Path
from typing import Any, ClassVar

from prohori.enrich.addresses import IPAddress
from prohori.enrich.provider import Provider, ProviderData, ProviderError, clean_int, clean_text

ReaderFactory = Callable[[str], Any]


def _default_reader(path: str) -> Any:  # noqa: ANN401 - geoip2 is optional
    try:
        from geoip2.database import Reader
    except ImportError:
        raise ProviderError(
            'GeoLite2 needs the geoip extra: pip install "prohori[geoip]"'
        ) from None
    return Reader(path)


def _not_found(exc: Exception) -> bool:
    return type(exc).__name__ == "AddressNotFoundError"


class GeoLiteProvider(Provider):
    """Country, city and autonomous system from GeoLite2 City/Country and ASN databases."""

    name: ClassVar[str] = "geolite2"
    external: ClassVar[bool] = False
    note: ClassVar[str] = (
        "This product includes GeoLite Data created by MaxMind, available from "
        "https://www.maxmind.com. Locations are approximate and must not be used to locate "
        "a person."
    )

    def __init__(
        self,
        city_db: Path | None = None,
        asn_db: Path | None = None,
        *,
        reader_factory: ReaderFactory = _default_reader,
    ) -> None:
        super().__init__(ttl=timedelta(0))
        if city_db is None and asn_db is None:
            raise ValueError("geolite2: give a City/Country database, an ASN database or both")
        self._readers: list[tuple[str, Any]] = []
        try:
            for kind, path in (("geo", city_db), ("asn", asn_db)):
                if path is None:
                    continue
                if not path.is_file():
                    raise ProviderError(f"GeoLite2 database not found: {path}")
                self._readers.append((kind, reader_factory(str(path))))
        except Exception:
            self.close()
            raise

    def close(self) -> None:
        for _, reader in self._readers:
            reader.close()  # releases the memory-mapped file (needed on Windows)
        self._readers = []

    def lookup(self, address: IPAddress) -> ProviderData | None:
        result: ProviderData = {}
        for kind, reader in self._readers:
            try:
                if kind == "asn":
                    asn = reader.asn(str(address))
                    result["asn"] = clean_int(asn.autonomous_system_number)
                    result["as_org"] = clean_text(asn.autonomous_system_organization)
                    result["network"] = clean_text(asn.network)
                elif "City" in reader.metadata().database_type:
                    city = reader.city(str(address))
                    result["country"] = clean_text(city.country.iso_code)
                    result["city"] = clean_text(city.city.name)
                else:
                    result["country"] = clean_text(reader.country(str(address)).country.iso_code)
            except Exception as exc:
                if not _not_found(exc):
                    raise ProviderError(f"GeoLite2 lookup failed: {type(exc).__name__}") from None
        cleaned: ProviderData = {k: v for k, v in result.items() if v is not None}
        return cleaned or None
