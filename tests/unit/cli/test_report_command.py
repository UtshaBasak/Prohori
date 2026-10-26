"""``prohori report``: formats, input handling, incident selection and redaction."""

import hashlib
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from prohori.cli import app
from prohori.cli import report as report_module
from prohori.cli.exit_codes import ExitCode

ROOT = Path(__file__).resolve().parents[3]
(SAMPLE,) = (ROOT / "samples" / "incidents").glob("INC-*.json")
GOLDEN_JSONL = ROOT / "tests" / "golden" / "incidents" / "app-security.jsonl"
runner = CliRunner(env={"COLUMNS": "200", "NO_COLOR": "1"})


@pytest.mark.parametrize(
    ("fmt", "marker"),
    [
        ("md", "## Score breakdown"),
        ("html", "<!DOCTYPE html>"),
        ("json", '"format": "prohori.report/1"'),
        ("csv", "timestamp,kind,description"),
    ],
)
def test_every_format_to_stdout(fmt: str, marker: str) -> None:
    result = runner.invoke(app, ["report", str(SAMPLE), "-f", fmt])
    assert result.exit_code == 0, result.output
    assert marker in result.stdout


def test_default_is_markdown_with_the_source_hash() -> None:
    result = runner.invoke(app, ["report", str(SAMPLE)])
    assert result.stdout.startswith("# Successful sign-in")
    assert hashlib.sha256(SAMPLE.read_bytes()).hexdigest() in result.stdout


def test_output_file_is_utf8(tmp_path: Path) -> None:
    out = tmp_path / "report.html"
    result = runner.invoke(app, ["report", str(SAMPLE), "-f", "html", "-o", str(out)])
    assert result.exit_code == 0
    assert f"wrote {out}" in result.stderr
    text = out.read_bytes().decode("utf-8")
    assert text.startswith("<!DOCTYPE html>")
    assert "<script" not in text


def test_json_lines_need_an_incident_choice() -> None:
    result = runner.invoke(app, ["report", str(GOLDEN_JSONL)])
    assert result.exit_code == ExitCode.USAGE
    assert "has 3 incidents; choose one with --incident" in result.output
    first = json.loads(GOLDEN_JSONL.read_text(encoding="utf-8").splitlines()[1])["id"]
    chosen = runner.invoke(app, ["report", str(GOLDEN_JSONL), "--incident", first, "-f", "json"])
    assert chosen.exit_code == 0, chosen.output
    assert json.loads(chosen.stdout)["incident"]["id"] == first
    missing = runner.invoke(app, ["report", str(GOLDEN_JSONL), "--incident", "INC-nope"])
    assert missing.exit_code == ExitCode.USAGE
    assert "no incident 'INC-nope'" in missing.output


def test_single_line_and_array_and_stdin(tmp_path: Path) -> None:
    incident = json.loads(SAMPLE.read_text(encoding="utf-8"))
    one_line = tmp_path / "one.jsonl"
    one_line.write_text(json.dumps(incident) + "\n", encoding="utf-8")
    assert runner.invoke(app, ["report", str(one_line)]).exit_code == 0
    array = tmp_path / "array.json"
    array.write_text(json.dumps([incident]), encoding="utf-8")
    assert runner.invoke(app, ["report", str(array)]).exit_code == 0
    piped = runner.invoke(app, ["report", "-"], input=SAMPLE.read_bytes())
    assert piped.exit_code == 0
    assert "`<stdin>`" in piped.stdout


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("", "no incident in the file"),
        ("not json\n", "incident 1"),
        ('{"id": "INC-1"}', "incident 1"),
        ("[" * 100_000 + "]" * 100_000, "nested too deeply"),
    ],
    ids=["empty", "not-json", "invalid-incident", "deeply-nested"],
)
def test_invalid_input(tmp_path: Path, content: str, message: str) -> None:
    path = tmp_path / "bad.json"
    path.write_text(content, encoding="utf-8")
    result = runner.invoke(app, ["report", str(path)])
    assert result.exit_code == ExitCode.USAGE
    assert message in result.output


def test_missing_and_oversized_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    missing = runner.invoke(app, ["report", str(tmp_path / "none.json")])
    assert missing.exit_code == ExitCode.USAGE
    assert "file not found" in missing.output
    monkeypatch.setattr(report_module, "MAX_INPUT_BYTES", 100)
    big = runner.invoke(app, ["report", str(SAMPLE)])
    assert big.exit_code == ExitCode.USAGE
    assert "larger than" in big.output


def test_redact_and_redact_ips() -> None:
    redacted = runner.invoke(app, ["report", str(SAMPLE), "--redact"])
    assert redacted.exit_code == 0, redacted.output
    assert "u-2001" not in redacted.stdout
    assert "0cc175b9c0f1b6a831c399e269772661" not in redacted.stdout
    assert "203.0.113.7" in redacted.stdout
    assert "Redacted: account names" in redacted.stdout
    both = runner.invoke(app, ["report", str(SAMPLE), "--redact-ips", "-f", "html"])
    assert both.exit_code == 0
    assert "203.0.113.7" not in both.stdout
    assert "u-2001" not in both.stdout
    again = runner.invoke(app, ["report", str(SAMPLE), "--redact"])
    assert again.stdout != redacted.stdout  # a fresh key per run: pseudonyms cannot be linked


def test_a_leaking_redaction_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(report_module, "find_leaks", lambda text, values: ["u-2001"])
    out = tmp_path / "r.md"
    result = runner.invoke(app, ["report", str(SAMPLE), "--redact", "-o", str(out)])
    assert result.exit_code == ExitCode.REDACTION_FAILED
    assert "could not be redacted; no report was written" in result.stderr
    assert not out.exists()
