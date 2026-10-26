"""``prohori triage``, ``prohori demo`` and ``prohori version``."""

import json
import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from prohori.cli import app
from prohori.cli.exit_codes import ExitCode
from prohori.reports import make as make_module
from prohori.schema import Incident
from prohori.version import __version__
from tests.unit.enrich.conftest import isolated_settings, no_network

__all__ = ["isolated_settings", "no_network"]  # autouse: no network, no real cache or keys

ROOT = Path(__file__).resolve().parents[3]
SAMPLES = ROOT / "samples" / "logs"
runner = CliRunner(env={"COLUMNS": "120", "NO_COLOR": "1"})
_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_BOX = re.compile(r"[─-╿|+]")


def _plain(output: str) -> str:
    return " ".join(_BOX.sub(" ", _ANSI.sub("", output)).split())


def _all_text(directory: Path) -> str:
    return "\n".join(
        p.read_text(encoding="utf-8") for p in sorted(directory.rglob("*")) if p.is_file()
    )


# ------------------------------------------------------------------ triage


def test_triage_writes_incidents_reports_and_summary(tmp_path: Path) -> None:
    out = tmp_path / "t"
    result = runner.invoke(app, ["triage", str(SAMPLES / "account-takeover.jsonl"), "-o", str(out)])
    assert result.exit_code == ExitCode.ALERTS_FOUND, result.output
    (line,) = (out / "incidents.jsonl").read_text(encoding="utf-8").splitlines()
    incident = Incident.model_validate_json(line)
    report = out / f"{incident.id}.html"
    assert report.read_text(encoding="utf-8").startswith("<!DOCTYPE html>")
    summary = (out / "summary.md").read_text(encoding="utf-8")
    assert f"[{report.name}]({report.name})" in summary
    assert "| critical | 100 | high |" in summary
    assert incident.id in result.stdout
    assert "Summary:" in result.stdout


@pytest.mark.parametrize("fmt", ["md", "json", "csv"])
def test_triage_formats(tmp_path: Path, fmt: str) -> None:
    out = tmp_path / fmt
    args = ["triage", str(SAMPLES / "auth.log"), "--year", "2026", "-o", str(out), "-f", fmt]
    assert runner.invoke(app, args).exit_code == ExitCode.ALERTS_FOUND
    assert len(list(out.glob(f"INC-*.{fmt}"))) == 1


def test_triage_redacts_every_file(tmp_path: Path) -> None:
    out = tmp_path / "r"
    args = ["triage", str(SAMPLES / "account-takeover.jsonl"), "-o", str(out), "--redact-ips"]
    assert runner.invoke(app, args).exit_code == ExitCode.ALERTS_FOUND
    text = _all_text(out)
    for value in ("u-2001", "203.0.113.7", "0cc175b9c0f1b6a831c399e269772661", "192.0.2.44"):
        assert value not in text
    pseudonyms = set(re.findall(r"\[user:[0-9a-f]{10}\]", text))
    assert len(pseudonyms) == 2  # the user id and the email hash, the same in every file
    assert "(redacted)" in (out / "summary.md").read_text(encoding="utf-8")


def test_triage_redaction_failure_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from prohori.cli import triage as triage_module

    monkeypatch.setattr(triage_module, "find_leaks", lambda text, values: ["u-2001"])
    monkeypatch.setattr(make_module, "find_leaks", lambda text, values: ["u-2001"])
    out = tmp_path / "nothing"
    result = runner.invoke(
        app, ["triage", str(SAMPLES / "account-takeover.jsonl"), "-o", str(out), "--redact"]
    )
    assert result.exit_code == ExitCode.REDACTION_FAILED
    assert "nothing was written" in result.stderr
    assert not out.exists()


def test_triage_stdin_no_enrich_and_exit_zero(tmp_path: Path) -> None:
    data = (SAMPLES / "access.log").read_bytes()
    result = runner.invoke(
        app, ["triage", "-", "-o", str(tmp_path), "--no-enrich", "--exit-zero"], input=data
    )
    assert result.exit_code == 0, result.output
    incidents = [
        Incident.model_validate_json(line)
        for line in (tmp_path / "incidents.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert len(incidents) == 2
    assert all(i.provenance and i.provenance.enrichment == "none" for i in incidents)


def test_triage_without_incidents_and_errors(tmp_path: Path) -> None:
    quiet = tmp_path / "quiet.log"
    quiet.write_text(
        "Oct 24 13:50:01 web01 CRON[2110]: pam_unix(cron:session): session opened for user "
        "root(uid=0) by (uid=0)\n",
        encoding="utf-8",
    )
    result = runner.invoke(app, ["triage", str(quiet), "-o", str(tmp_path / "q")])
    assert result.exit_code == 0
    assert "No incidents." in (tmp_path / "q" / "summary.md").read_text(encoding="utf-8")
    bad = runner.invoke(app, ["triage", str(quiet), "--gap", "later"])
    assert bad.exit_code == ExitCode.USAGE
    assert "invalid duration" in _plain(bad.output)


# ------------------------------------------------------------------ demo


def test_demo_runs_offline_and_finds_every_expected_rule(tmp_path: Path) -> None:
    out = tmp_path / "demo"
    result = runner.invoke(app, ["demo", "-o", str(out)])
    assert result.exit_code == 0, result.output
    text = _plain(result.stdout)
    assert "Expected rules that did not fire" not in text
    for name in ("account-takeover", "ssh-bruteforce", "web-scanning"):
        assert (out / name / "summary.md").is_file()
        assert (out / "logs" / name / "manifest.json").is_file()
    assert "critical, score 100" in text
    assert (out / ".cache" / "enrich.sqlite3").is_file()  # its own cache, not the user's
    assert "nothing was sent over the network" in text


def test_demo_options(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["demo", "-o", str(tmp_path), "-s", "injection", "-f", "md", "--seed", "4"]
    )
    assert result.exit_code == 0, result.output
    assert list((tmp_path / "injection").glob("INC-*.md"))
    bad = runner.invoke(app, ["demo", "-o", str(tmp_path), "-s", "nope"])
    assert bad.exit_code == ExitCode.USAGE
    assert "unknown scenario(s) nope" in _plain(bad.output)


def test_demo_reports_missed_rules(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A held-out style parameter change: a slow takeover stays under PRH-AUTH-001's threshold.
    from prohori.cli import demo as demo_module
    from prohori.simulate import Simulation, simulate

    def slow(name: str, *, seed: int) -> Simulation:
        return simulate(name, seed=seed, overrides={"rate": "1"})

    monkeypatch.setattr(demo_module, "simulate", slow)
    result = runner.invoke(app, ["demo", "-o", str(tmp_path), "-s", "account-takeover"])
    assert result.exit_code == 0
    text = _plain(result.stdout)
    assert "Expected rules that did not fire: account-takeover: PRH-AUTH-001" in text


# ------------------------------------------------------------------ version and help


def test_version_shows_attack_and_rules() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert result.stdout.startswith(f"prohori {__version__}\n")
    assert "ATT&CK Enterprise v20.0" in result.stdout
    assert re.search(r"built-in rules: 15 \(rule set [0-9a-f]{12}\)", result.stdout)
    short = runner.invoke(app, ["--version"])
    assert short.stdout == f"prohori {__version__}\n"


def _commands() -> list[list[str]]:
    commands = [[c.name or ""] for c in app.registered_commands]
    for group in app.registered_groups:
        sub = group.typer_instance
        assert sub is not None
        name = group.name or str(sub.info.name)
        commands += [[name, c.name or ""] for c in sub.registered_commands]
    return commands


@pytest.mark.parametrize("command", _commands(), ids=" ".join)
def test_every_command_has_help(command: list[str]) -> None:
    result = runner.invoke(app, [*command, "--help"])
    assert result.exit_code == 0, command
    assert "Usage:" in _plain(result.stdout)
    assert len(_plain(result.stdout)) > 80


def test_all_planned_commands_exist() -> None:
    names = {" ".join(c) for c in _commands()}
    expected = {"parse", "detect", "enrich", "incidents", "report", "simulate", "triage", "demo"}
    assert expected <= names
    assert {"rules list", "rules validate", "rules test", "version"} <= names


def test_demo_json_reports(tmp_path: Path) -> None:
    runner.invoke(app, ["demo", "-o", str(tmp_path), "-s", "token-reuse", "-f", "json"])
    reports = sorted((tmp_path / "token-reuse").glob("INC-*.json"))
    assert reports
    assert json.loads(reports[0].read_text(encoding="utf-8"))["format"] == "prohori.report/1"
