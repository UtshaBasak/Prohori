"""Tests for ``prohori detect``."""

import json
import os
import re
import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from prohori.cli import app
from prohori.cli.exit_codes import ExitCode

ROOT = Path(__file__).resolve().parents[3]
SAMPLES = ROOT / "samples" / "logs"
GOLDEN = ROOT / "tests" / "golden" / "detect"
RULE_FIXTURES = ROOT / "tests" / "fixtures" / "rules"

runner = CliRunner(env={"COLUMNS": "200", "NO_COLOR": "1"})
_ANSI = re.compile(r"\x1b\[[0-9;]*m")

#: Set PROHORI_UPDATE_GOLDEN=1 to rewrite the golden files after an intended output change.
UPDATE_GOLDEN = os.environ.get("PROHORI_UPDATE_GOLDEN") == "1"


def run(*args: str, stdin: bytes | None = None) -> tuple[int, str, str]:
    result = runner.invoke(app, ["detect", *args], input=stdin)
    return result.exit_code, _ANSI.sub("", result.stdout), _ANSI.sub("", result.stderr)


@pytest.mark.parametrize(
    ("sample", "golden"),
    [
        ("auth.log", "auth-log.jsonl"),
        ("access.log", "access-log.jsonl"),
        ("app-security.jsonl", "app-security.jsonl"),
    ],
)
def test_json_output_matches_golden_file(sample: str, golden: str) -> None:
    code, out, _ = run(str(SAMPLES / sample), "--format", "json")
    assert code == ExitCode.ALERTS_FOUND
    path = GOLDEN / golden
    if UPDATE_GOLDEN:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(out, encoding="utf-8", newline="\n")
    assert out.splitlines() == path.read_text(encoding="utf-8").splitlines()


def test_auth_log_reports_the_brute_force_alert() -> None:
    code, out, _ = run(str(SAMPLES / "auth.log"))
    assert code == ExitCode.ALERTS_FOUND
    assert "PRH-AUTH-001" in out
    assert "source.ip=203.0.113.7" in out
    assert "Detection summary" in out


def test_json_alerts_and_summary() -> None:
    code, out, err = run(str(SAMPLES / "app-security.jsonl"), "--format", "json")
    assert code == ExitCode.ALERTS_FOUND
    alerts = [json.loads(line) for line in out.splitlines()]
    assert {a["detector_id"] for a in alerts} == {"PRH-ACCT-001", "PRH-SESS-001", "PRH-ADMIN-001"}
    summary = json.loads(err.strip().splitlines()[-1])
    assert summary["parser"] == "app_json"
    assert summary["events"] == 10
    assert summary["alerts"] == 3
    assert summary["rules"] >= 14
    assert summary["engine"]["late_events"] == 0


def test_exit_zero() -> None:
    code, out, _ = run(str(SAMPLES / "auth.log"), "--exit-zero")
    assert code == ExitCode.OK
    assert "PRH-AUTH-001" in out


def test_no_alerts() -> None:
    code, out, _ = run(str(SAMPLES / "auth-iso.log"))
    assert code == ExitCode.OK
    assert "No alerts." in out


def test_stdin() -> None:
    code, out, _ = run("-", "--format", "json", stdin=(SAMPLES / "auth.log").read_bytes())
    assert code == ExitCode.ALERTS_FOUND
    assert '"PRH-AUTH-001"' in out


def test_custom_rules_only() -> None:
    code, out, _ = run(
        str(SAMPLES / "auth.log"), "--no-builtin", "--rules", str(RULE_FIXTURES / "valid")
    )
    assert code == ExitCode.ALERTS_FOUND
    assert "TST-AUTH-001" in out
    assert "PRH-AUTH-001" not in out


def test_custom_rules_are_added_to_builtin(tmp_path: Path) -> None:
    shutil.copy(RULE_FIXTURES / "valid" / "brute-force.yml", tmp_path / "custom.yml")
    code, out, err = run(str(SAMPLES / "auth.log"), "--rules", str(tmp_path), "--format", "json")
    assert code == ExitCode.ALERTS_FOUND
    assert {json.loads(line)["detector_id"] for line in out.splitlines()} == {
        "PRH-AUTH-001",
        "TST-AUTH-001",
    }
    assert json.loads(err.strip().splitlines()[-1])["rules"] >= 15


def test_invalid_rules_stop_the_run() -> None:
    code, out, err = run(str(SAMPLES / "auth.log"), "--rules", str(RULE_FIXTURES / "invalid"))
    assert code == ExitCode.INVALID_RULES
    assert out == ""
    assert "INVALID" in err
    assert "prohori rules validate" in err


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (["{auth}", "--no-builtin"], "no rules to run"),
        (["{auth}", "--rules", "nowhere"], "not found: nowhere"),
        (["{auth}", "--lateness", "soon"], "invalid duration"),
        (["missing.log"], "file not found"),
        (["{auth}", "--parser", "nope"], "unknown parser"),
    ],
)
def test_usage_errors(args: list[str], message: str) -> None:
    code, _, err = run(*(a.replace("{auth}", str(SAMPLES / "auth.log")) for a in args))
    assert code == ExitCode.USAGE
    assert message in err


def test_empty_rules_directory(tmp_path: Path) -> None:
    code, _, err = run(str(SAMPLES / "auth.log"), "--no-builtin", "--rules", str(tmp_path))
    assert code == ExitCode.USAGE
    assert "no rule files found" in err


def test_unparseable_input(tmp_path: Path) -> None:
    bad = tmp_path / "bad.log"
    bad.write_text("not a log line\nnor this\n", encoding="utf-8")
    code, _, _ = run(str(bad), "--parser", "auth_log", "--format", "json")
    assert code == ExitCode.NO_EVENTS


def test_late_events_are_reported(tmp_path: Path) -> None:
    lines = (SAMPLES / "auth.log").read_text(encoding="utf-8").splitlines()
    shuffled = tmp_path / "late.log"
    shuffled.write_text("\n".join([*lines[5:], *lines[:5]]) + "\n", encoding="utf-8")
    code, out, _ = run(str(shuffled), "--lateness", "0s", "--parser", "auth_log", "--year", "2026")
    assert code in {ExitCode.OK, ExitCode.ALERTS_FOUND}
    assert re.search(r"late events\W+5\b", out), out


def test_lateness_tolerates_out_of_order_lines(tmp_path: Path) -> None:
    lines = (SAMPLES / "auth.log").read_text(encoding="utf-8").splitlines()
    swapped = tmp_path / "swapped.log"
    swapped.write_text("\n".join([lines[3], lines[2], *lines[4:]]) + "\n", encoding="utf-8")
    code, out, _ = run(str(swapped), "--parser", "auth_log", "--year", "2026")
    assert code == ExitCode.ALERTS_FOUND
    assert "late events" not in out


def test_rule_text_is_not_rendered_as_markup(tmp_path: Path) -> None:
    rule = (RULE_FIXTURES / "valid" / "brute-force.yml").read_text(encoding="utf-8")
    rule = rule.replace(
        "title: Brute-force sign-in attempts from one IP", "title: '[bold red]Injected[/bold red]'"
    )
    (tmp_path / "rule.yml").write_text(rule, encoding="utf-8")
    code, out, _ = run(str(SAMPLES / "auth.log"), "--no-builtin", "--rules", str(tmp_path))
    assert code == ExitCode.ALERTS_FOUND
    assert "[bold red]Injected[/bold red]" in out
