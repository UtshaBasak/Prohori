"""Tests for the GeoLite2 provider (with a fake reader), the offline fixture and settings."""

import json
from datetime import timedelta
from importlib.resources import files
from ipaddress import ip_address
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from prohori.enrich import geolite
from prohori.enrich.addresses import is_public
from prohori.enrich.config import ENV_VARS, ConfigError, EnrichSettings, read_env_file
from prohori.enrich.geolite import GeoLiteProvider
from prohori.enrich.offline import OfflineProvider
from prohori.enrich.provider import RESULT_KEYS, ProviderError


class AddressNotFoundError(Exception):
    """Same name as geoip2's error, which the provider recognises."""


class FakeReader:
    def __init__(self, path: str, kind: str = "GeoLite2-City") -> None:
        self.path = path
        self.kind = "GeoLite2-ASN" if "asn" in Path(path).name.lower() else kind
        self.closed = False

    def metadata(self) -> Any:
        return SimpleNamespace(database_type=self.kind)

    def _check(self, ip: str) -> None:
        if ip.startswith(("10.", "203.")):
            raise AddressNotFoundError(ip)
        if ip == "1.2.3.4":
            raise OSError("corrupt database")

    def city(self, ip: str) -> Any:
        self._check(ip)
        return SimpleNamespace(
            country=SimpleNamespace(iso_code="BD"), city=SimpleNamespace(name="Dhaka")
        )

    def country(self, ip: str) -> Any:
        self._check(ip)
        return SimpleNamespace(country=SimpleNamespace(iso_code="BD"))

    def asn(self, ip: str) -> Any:
        self._check(ip)
        return SimpleNamespace(
            autonomous_system_number=64500,
            autonomous_system_organization="Example Net",
            network="8.8.8.0/24",
        )

    def close(self) -> None:
        self.closed = True


@pytest.fixture
def dbs(tmp_path: Path) -> tuple[Path, Path]:
    city, asn = tmp_path / "GeoLite2-City.mmdb", tmp_path / "GeoLite2-ASN.mmdb"
    city.write_bytes(b"fake")
    asn.write_bytes(b"fake")
    return city, asn


class TestGeoLite:
    def test_city_and_asn(self, dbs: tuple[Path, Path]) -> None:
        readers: list[FakeReader] = []

        def factory(path: str) -> FakeReader:
            readers.append(FakeReader(path))
            return readers[-1]

        provider = GeoLiteProvider(*dbs, reader_factory=factory)
        assert provider.lookup(ip_address("8.8.8.8")) == {
            "country": "BD",
            "city": "Dhaka",
            "asn": 64500,
            "as_org": "Example Net",
            "network": "8.8.8.0/24",
        }
        assert provider.lookup(ip_address("10.0.0.1")) is None
        provider.close()
        assert all(r.closed for r in readers)

    def test_country_database(self, dbs: tuple[Path, Path]) -> None:
        provider = GeoLiteProvider(
            dbs[0], reader_factory=lambda p: FakeReader(p, kind="GeoLite2-Country")
        )
        assert provider.lookup(ip_address("8.8.8.8")) == {"country": "BD"}

    def test_lookup_failure(self, dbs: tuple[Path, Path]) -> None:
        provider = GeoLiteProvider(dbs[0], reader_factory=FakeReader)
        with pytest.raises(ProviderError, match="OSError"):
            provider.lookup(ip_address("1.2.3.4"))

    def test_missing_database(self, tmp_path: Path, dbs: tuple[Path, Path]) -> None:
        opened: list[FakeReader] = []

        def factory(path: str) -> FakeReader:
            opened.append(FakeReader(path))
            return opened[-1]

        with pytest.raises(ProviderError, match="not found"):
            GeoLiteProvider(dbs[0], tmp_path / "missing.mmdb", reader_factory=factory)
        assert opened
        assert all(r.closed for r in opened)  # nothing left open

    def test_needs_a_database(self) -> None:
        with pytest.raises(ValueError, match="give a City"):
            GeoLiteProvider()

    def test_real_reader_opens_the_file(self, dbs: tuple[Path, Path]) -> None:
        with pytest.raises(Exception, match=r"(?i)metadata|database|invalid"):
            GeoLiteProvider(dbs[0])  # the fake file is not a MaxMind database

    def test_missing_extra(self, monkeypatch: pytest.MonkeyPatch, dbs: tuple[Path, Path]) -> None:
        import builtins

        real_import = builtins.__import__

        def no_geoip2(name: str, *args: Any, **kwargs: Any) -> Any:
            if name.startswith("geoip2"):
                raise ImportError(name)
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", no_geoip2)
        with pytest.raises(ProviderError, match=r"prohori\[geoip\]"):
            geolite._default_reader(str(dbs[0]))


class TestOffline:
    def test_fixture_data(self) -> None:
        provider = OfflineProvider()
        data = provider.lookup(ip_address("203.0.113.7"))
        assert data is not None
        assert data["abuse_score"] == 97
        assert provider.lookup(ip_address("8.8.8.8")) is None
        assert provider.retrieved_at(provider.retrieved_at_fixed).isoformat().startswith("2026")

    def test_fixture_only_holds_documentation_addresses_and_shared_keys(self) -> None:
        provider = OfflineProvider()
        for address in provider.addresses():
            assert not is_public(ip_address(address)), address
            data = provider.lookup(ip_address(address))
            assert data is not None
            assert set(data) <= set(RESULT_KEYS), address

    def test_fixture_is_packaged(self) -> None:
        raw = json.loads(files("prohori.enrich").joinpath("data/offline.json").read_text("utf-8"))
        assert raw["addresses"]


class TestSettings:
    def test_defaults(self, tmp_path: Path) -> None:
        settings = EnrichSettings.load(environ={}, env_file=None)
        assert settings.abuseipdb_api_key == ""
        assert settings.cache_ttl == timedelta(hours=24)
        assert settings.abuseipdb_daily_limit == 1000
        assert settings.virustotal_daily_limit == 500
        assert settings.virustotal_per_minute == 4

    def test_environment_wins_over_env_file(self, tmp_path: Path) -> None:
        env = tmp_path / ".env"
        env.write_text(
            "# comment\n"
            "export ABUSEIPDB_API_KEY='from-file'\n"
            'VIRUSTOTAL_API_KEY="vt-file"\n'
            "PROHORI_CACHE_TTL_HOURS=2\n"
            "ABUSEIPDB_URL=https://attacker.invalid\n"
            "not a setting\n",
            encoding="utf-8",
        )
        settings = EnrichSettings.load(
            environ={"ABUSEIPDB_API_KEY": "from-env", "GEOLITE2_CITY_DB": "~/geo.mmdb"},
            env_file=env,
        )
        assert settings.abuseipdb_api_key == "from-env"
        assert settings.virustotal_api_key == "vt-file"
        assert settings.cache_ttl == timedelta(hours=2)
        assert settings.geolite2_city_db == Path("~/geo.mmdb").expanduser()
        assert "ABUSEIPDB_URL" not in read_env_file(env)

    def test_keys_are_not_in_repr(self) -> None:
        settings = EnrichSettings.load(
            environ={"ABUSEIPDB_API_KEY": "secret-1", "VIRUSTOTAL_API_KEY": "secret-2"},
            env_file=None,
        )
        assert "secret" not in repr(settings)

    @pytest.mark.parametrize(
        ("key", "value"),
        [
            ("PROHORI_CACHE_TTL_HOURS", "soon"),
            ("PROHORI_CACHE_TTL_HOURS", "0"),
            ("VIRUSTOTAL_PER_MINUTE", "2.5"),
            ("ABUSEIPDB_DAILY_LIMIT", "-1"),
        ],
    )
    def test_invalid_numbers(self, key: str, value: str) -> None:
        with pytest.raises(ConfigError, match=key):
            EnrichSettings.load(environ={key: value}, env_file=None)

    def test_oversized_env_file_is_ignored(self, tmp_path: Path) -> None:
        env = tmp_path / ".env"
        env.write_text("ABUSEIPDB_API_KEY=x\n" + "#" * 70000, encoding="utf-8")
        assert read_env_file(env) == {}

    def test_every_variable_is_documented(self) -> None:
        example = Path(__file__).resolve().parents[3] / ".env.example"
        text = example.read_text(encoding="utf-8")
        for name in ENV_VARS:
            assert f"{name}=" in text, name
