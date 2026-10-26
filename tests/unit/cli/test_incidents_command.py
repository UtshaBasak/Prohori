"""``prohori incidents``: golden files for the samples, options and exit codes."""

import hashlib
import json
import os
import socket
from pathlib import Path

import pytest
from typer.testing import CliRunner

from prohori.cli import app
from prohori.cli.exit_codes import ExitCode
from prohori.schema import Incident
from prohori.version import __version__
from tests.unit.enrich.conftest import NetworkAccessError, isolated_settings, no_network

__all__ = ["isolated_settings", "no_network"]  # autouse: no network, no real cache or keys

ROOT = Path(__file__).resolve().parents[3]
SAMPLES = ROOT / "samples" / "logs"
GOLDEN = ROOT / "tests" / "golden" / "incidents"
runner = CliRunner(env={"COLUMNS": "200", "NO_COLOR": "1"})

#: Set PROHORI_UPDATE_GOLDEN=1 to rewrite the golden files after an intended output change.
UPDATE_GOLDEN = os.environ.get("PROHORI_UPDATE_GOLDEN") == "1"


def normalise_version(text: str) -> str:
    """Golden files hold a placeholder, so a version bump does not change them."""
    return text.replace(f'"tool_version":"{__version__}"', '"tool_version":"<version>"')


@pytest.mark.parametrize(
    ("sample", "golden", "extra"),
    [
        ("auth.log", "auth-log.jsonl", ["--year", "2026"]),
        ("access.log", "access-log.jsonl", []),
        ("app-security.jsonl", "app-security.jsonl", []),
        ("account-takeover.jsonl", "account-takeover.jsonl", []),
    ],
)
def test_json_output_matches_golden_file(sample: str, golden: str, extra: list[str]) -> None:
    result = runner.invoke(app, ["incidents", str(SAMPLES / sample), "-f", "json", *extra])
    assert result.exit_code == ExitCode.ALERTS_FOUND, result.output
    path = GOLDEN / golden
    output = normalise_version(result.stdout)
    if UPDATE_GOLDEN:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(output, encoding="utf-8", newline="\n")
    assert output == path.read_text(encoding="utf-8")
    for line in result.stdout.splitlines():
        Incident.model_validate_json(line)  # every line is a valid incident


def test_summary_goes_to_stderr() -> None:
    result = runner.invoke(
        app, ["incidents", str(SAMPLES / "account-takeover.jsonl"), "-f", "json"]
    )
    summary = json.loads(result.stderr.strip().splitlines()[-1])
    assert summary == {
        "input": "account-takeover.jsonl",
        "events": 17,
        "parse_errors": 0,
        "alerts": 3,
        "incidents": 1,
    }


def test_table_output() -> None:
    result = runner.invoke(app, ["incidents", str(SAMPLES / "account-takeover.jsonl")])
    assert result.exit_code == ExitCode.ALERTS_FOUND
    assert "critical  score 100" in result.stdout
    assert "Capped at 100" in result.stdout
    assert "1 incident(s) from 3 alert(s) in account-takeover.jsonl." in result.stdout


def test_no_enrich_and_exit_zero() -> None:
    result = runner.invoke(
        app,
        ["incidents", str(SAMPLES / "account-takeover.jsonl"), "-f", "json", "--no-enrich"],
    )
    incident = Incident.model_validate_json(result.stdout.splitlines()[0])
    assert incident.limitations[0].startswith("Enrichment not run")
    zero = runner.invoke(app, ["incidents", str(SAMPLES / "access.log"), "--exit-zero"])
    assert zero.exit_code == 0


def test_online_without_keys_sends_nothing() -> None:
    result = runner.invoke(
        app, ["incidents", str(SAMPLES / "account-takeover.jsonl"), "-f", "json", "--online"]
    )
    assert result.exit_code == ExitCode.ALERTS_FOUND, result.output
    incident = Incident.model_validate_json(result.stdout.splitlines()[0])
    assert incident.limitations[0].startswith("Enrichment: no providers configured")
    assert incident.indicators[0].enrichment == ()


def test_no_incidents(tmp_path: Path) -> None:
    quiet = tmp_path / "quiet.log"
    quiet.write_text(
        "Oct 24 13:50:01 web01 CRON[2110]: pam_unix(cron:session): session opened for user "
        "root(uid=0) by (uid=0)\n",
        encoding="utf-8",
    )
    result = runner.invoke(app, ["incidents", str(quiet)])
    assert result.exit_code == 0
    assert "No incidents in quiet.log (0 alerts)." in result.stdout


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (["--gap", "soon"], "invalid duration"),
        (["--lateness", "x"], "invalid duration"),
    ],
)
def test_usage_errors(args: list[str], message: str) -> None:
    result = runner.invoke(app, ["incidents", str(SAMPLES / "access.log"), *args])
    assert result.exit_code == ExitCode.USAGE
    assert message in result.output


def test_invalid_env_file_setting(tmp_path: Path) -> None:
    env = tmp_path / "bad.env"
    env.write_text("PROHORI_CACHE_TTL_HOURS=-1\n", encoding="utf-8")
    result = runner.invoke(app, ["incidents", str(SAMPLES / "access.log"), "--env-file", str(env)])
    assert result.exit_code == ExitCode.USAGE


def test_unparseable_input(tmp_path: Path) -> None:
    junk = tmp_path / "junk.jsonl"
    junk.write_text('{"time": "nope"}\n', encoding="utf-8")
    result = runner.invoke(app, ["incidents", str(junk), "--parser", "app_json"])
    assert result.exit_code == ExitCode.NO_EVENTS


def test_log_text_is_not_rendered_as_markup(tmp_path: Path) -> None:
    line = (
        '{"time": "2026-10-24T14:01:00Z", "log_type": "security", "event": {"action": '
        '"admin.role.granted", "category": "admin", "outcome": "success"}, "source": '
        '{"ip": "192.0.2.10"}, "user": {"id": "[red]evil[/red]"}}\n'
    )
    path = tmp_path / "admin.jsonl"
    path.write_text(line, encoding="utf-8")
    result = runner.invoke(app, ["incidents", str(path)])
    assert result.exit_code == ExitCode.ALERTS_FOUND
    assert "[red]evil[/red]" in result.stdout


def test_suite_is_isolated_from_the_network_and_the_real_cache(tmp_path: Path) -> None:
    assert Path(os.environ["PROHORI_CACHE_PATH"]).is_relative_to(tmp_path)
    with pytest.raises(NetworkAccessError):
        socket.create_connection(("example.com", 443))


def test_provenance_records_the_input_hash_and_rules() -> None:
    sample = SAMPLES / "account-takeover.jsonl"
    result = runner.invoke(app, ["incidents", str(sample), "-f", "json"])
    incident = Incident.model_validate_json(result.stdout.splitlines()[0])
    provenance = incident.provenance
    assert provenance is not None
    assert provenance.tool_version == __version__
    assert provenance.enrichment == "offline"
    (source,) = provenance.inputs
    assert source.sha256 == hashlib.sha256(sample.read_bytes()).hexdigest()
    assert (source.bytes, source.events, source.parser) == (sample.stat().st_size, 17, "app_json")
    assert [r.id for r in provenance.rules] == ["PRH-ACCT-001", "PRH-AUTH-001", "PRH-AUTH-003"]
    assert all(r.sha256 for r in provenance.rules)


def test_provenance_from_stdin_and_without_enrichment() -> None:
    data = (SAMPLES / "account-takeover.jsonl").read_bytes()
    result = runner.invoke(app, ["incidents", "-", "-f", "json", "--no-enrich"], input=data)
    incident = Incident.model_validate_json(result.stdout.splitlines()[0])
    assert incident.provenance is not None
    assert incident.provenance.enrichment == "none"
    assert incident.provenance.inputs[0].name == "<stdin>"
    assert incident.provenance.inputs[0].sha256 == hashlib.sha256(data).hexdigest()


def test_sample_incident_file_is_current() -> None:
    """samples/incidents/ is the report sample; it must match what the builder produces now."""
    (path,) = (ROOT / "samples" / "incidents").glob("INC-*.json")
    result = runner.invoke(
        app, ["incidents", str(SAMPLES / "account-takeover.jsonl"), "-f", "json"]
    )
    current = Incident.model_validate_json(result.stdout.splitlines()[0])
    stored = Incident.model_validate_json(path.read_text(encoding="utf-8"))
    assert path.stem == current.id
    version = {"provenance": {"tool_version"}}
    assert stored.model_dump(exclude=version) == current.model_dump(exclude=version)
