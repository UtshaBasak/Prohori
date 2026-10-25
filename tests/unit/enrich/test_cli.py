"""Tests for ``prohori enrich`` (run under the enrichment network guard)."""

import json
import re
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest
import respx
from typer.testing import CliRunner

from prohori.cli import app
from prohori.cli.exit_codes import ExitCode
from prohori.enrich.abuseipdb import CHECK_URL

runner = CliRunner(env={"COLUMNS": "200", "NO_COLOR": "1"})
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def run(*args: str) -> tuple[int, str, str]:
    result = runner.invoke(app, ["enrich", *args])
    return result.exit_code, _ANSI.sub("", result.stdout), _ANSI.sub("", result.stderr)


@pytest.fixture
def router() -> Iterator[respx.MockRouter]:
    with respx.mock(assert_all_mocked=True, assert_all_called=False) as mock:
        yield mock


def test_offline_json_returns_fixture_data() -> None:
    code, out, _ = run("203.0.113.7", "--offline", "--format", "json")
    assert code == ExitCode.OK
    (report,) = [json.loads(line) for line in out.splitlines()]
    assert report["indicator"]["value"] == "203.0.113.7"
    (result,) = report["indicator"]["enrichment"]
    assert result["provider"] == "offline"
    assert result["data"]["abuse_score"] == 97
    assert "not real" in result["note"]


def test_offline_table() -> None:
    code, out, _ = run("203.0.113.7", "2001:db8:abcd::17", "10.0.0.1", "--offline")
    assert code == ExitCode.OK
    assert "203.0.113.7 (not public)" in out
    assert "abuse_score: 97" in out
    assert "2001:db8:abcd::17" in out
    assert "no data" in out


def test_no_providers_configured() -> None:
    code, out, err = run("8.8.8.8")
    assert code == ExitCode.OK
    assert "no providers configured" in err
    assert "8.8.8.8 (public)" in out


@pytest.mark.parametrize("value", ["example.com", "8.8.8.8/24", "fe80::1%eth0", "1.2.3"])
def test_invalid_addresses_are_rejected_before_any_lookup(
    value: str, router: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "k")
    route = router.get(CHECK_URL).mock(return_value=httpx.Response(200, json={"data": {}}))
    code, _, err = run("8.8.8.8", value)
    assert code == ExitCode.USAGE
    assert "not an IP address" in err
    assert route.call_count == 0


def test_too_many_addresses() -> None:
    code, _, err = run(*(["8.8.8.8"] * 1001))
    assert code == ExitCode.USAGE
    assert "at most 1000" in err


def test_invalid_setting(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PROHORI_CACHE_TTL_HOURS", "soon")
    code, _, err = run("8.8.8.8")
    assert code == ExitCode.USAGE
    assert "PROHORI_CACHE_TTL_HOURS" in err


def test_live_lookup_and_cache(router: respx.MockRouter, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "k")
    body = {"data": {"abuseConfidenceScore": 42, "isp": "[bold]Example[/bold]"}}
    route = router.get(CHECK_URL).mock(return_value=httpx.Response(200, json=body))
    code, out, _ = run("8.8.8.8")
    assert code == ExitCode.OK
    assert "abuse_score: 42" in out
    assert "[bold]Example[/bold]" in out  # provider text is never rendered as markup
    code, out, _ = run("8.8.8.8")
    assert "(cached)" in out
    code, out, _ = run("8.8.8.8", "--no-cache")
    assert route.call_count == 2


def test_rate_limit_note(router: respx.MockRouter, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "k")
    router.get(CHECK_URL).mock(
        return_value=httpx.Response(429, headers={"X-RateLimit-Remaining": "0"})
    )
    code, out, _ = run("8.8.8.8", "1.1.1.1", "--format", "json")
    assert code == ExitCode.OK
    first, second = (json.loads(line) for line in out.splitlines())
    assert "quota used up" in first["notes"][0]
    assert second["notes"][0].startswith("abuseipdb: skipped")


def test_env_file_option(tmp_path: Path, router: respx.MockRouter) -> None:
    env = tmp_path / "settings.env"
    env.write_text("ABUSEIPDB_API_KEY=from-file\n", encoding="utf-8")
    route = router.get(CHECK_URL).mock(
        return_value=httpx.Response(200, json={"data": {"abuseConfidenceScore": 1}})
    )
    code, _, _ = run("8.8.8.8", "--env-file", str(env))
    assert code == ExitCode.OK
    assert route.calls.last.request.headers["Key"] == "from-file"
