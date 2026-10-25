"""Tests for ``prohori parse``."""

import json
import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from prohori.cli import app
from prohori.cli.exit_codes import ExitCode

ROOT = Path(__file__).resolve().parents[3]
SAMPLES = ROOT / "samples" / "logs"
MAPPING = ROOT / "samples" / "mappings" / "payments.yaml"

runner = CliRunner(env={"COLUMNS": "200", "NO_COLOR": "1"})

# Typer's error panels may still be coloured when CI forces colour output.
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def run(*args: str, stdin: bytes | None = None) -> tuple[int, str, str]:
    result = runner.invoke(app, ["parse", *args], input=stdin)
    return result.exit_code, _ANSI.sub("", result.stdout), _ANSI.sub("", result.stderr)


@pytest.mark.parametrize(
    ("file", "parser", "events"),
    [
        ("auth.log", "auth_log", 32),
        ("access.log", "access_log", 14),
        ("app-security.jsonl", "app_json", 10),
    ],
)
def test_auto_detect_table(file: str, parser: str, events: int) -> None:
    code, out, _ = run(str(SAMPLES / file))
    assert code == ExitCode.OK
    assert "Parse summary" in out
    assert parser in out
    assert re.search(rf"\bevents\W+{events}\b", out)


@pytest.mark.parametrize(
    ("file", "events"), [("auth.log", 32), ("access.log", 14), ("app-security.jsonl", 10)]
)
def test_json_output(file: str, events: int) -> None:
    code, out, err = run(str(SAMPLES / file), "--format", "json")
    assert code == ExitCode.OK
    lines = out.splitlines()
    assert len(lines) == events
    first = json.loads(lines[0])
    assert {"id", "timestamp", "event", "raw"} <= first.keys()
    summary = json.loads(err)
    assert summary["events"] == events
    assert summary["errors"] == 0


def test_stdin() -> None:
    data = (SAMPLES / "auth.log").read_bytes()
    code, out, err = run("-", "--format", "json", "--year", "2026", stdin=data)
    assert code == ExitCode.OK
    assert json.loads(err)["input"] == "<stdin>"
    assert len(out.splitlines()) == 32


def test_stdin_crlf() -> None:
    data = (SAMPLES / "access.log").read_bytes().replace(b"\n", b"\r\n")
    code, out, _ = run("-", "--format", "json", stdin=data)
    assert code == ExitCode.OK
    assert len(out.splitlines()) == 14


def test_generic_json_with_mapping() -> None:
    code, out, _ = run(
        str(SAMPLES / "payments.jsonl"),
        "--parser",
        "generic_json",
        "--mapping",
        str(MAPPING),
        "--format",
        "json",
    )
    assert code == ExitCode.OK
    assert json.loads(out.splitlines()[0])["log_source"] == "payments-api"


def test_unknown_json_layout_needs_mapping() -> None:
    code, _, err = run(str(SAMPLES / "payments.jsonl"))
    assert code == ExitCode.USAGE
    assert "mapping" in err


def test_generic_json_without_mapping() -> None:
    code, _, err = run(str(SAMPLES / "payments.jsonl"), "--parser", "generic_json")
    assert code == ExitCode.USAGE
    assert "--mapping" in err


def test_all_lines_fail_gives_exit_code_1(tmp_path: Path) -> None:
    bad = tmp_path / "bad.log"
    bad.write_text("garbage one\ngarbage two\n", encoding="utf-8")
    code, out, _ = run(str(bad), "--parser", "auth_log")
    assert code == ExitCode.NO_EVENTS
    assert "Parse errors" in out


def test_some_errors_still_succeed(tmp_path: Path) -> None:
    mixed = tmp_path / "mixed.log"
    good = (SAMPLES / "auth.log").read_text(encoding="utf-8").splitlines()[2]
    mixed.write_text(f"garbage\n{good}\n", encoding="utf-8")
    code, _, err = run(str(mixed), "--parser", "auth_log", "--format", "json")
    assert code == ExitCode.OK
    assert json.loads(err)["errors"] == 1


def test_empty_file_succeeds(tmp_path: Path) -> None:
    empty = tmp_path / "empty.log"
    empty.write_bytes(b"")
    code, _, err = run(str(empty), "--parser", "auth_log", "--format", "json")
    assert code == ExitCode.OK
    assert json.loads(err)["lines"] == 0


def test_undetectable_format(tmp_path: Path) -> None:
    unknown = tmp_path / "unknown.txt"
    unknown.write_text("hello\nworld\n", encoding="utf-8")
    code, _, err = run(str(unknown))
    assert code == ExitCode.USAGE
    assert "--parser" in err


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (["missing.log"], "file not found"),
        (["{file}", "--parser", "nope"], "unknown parser"),
        (["{file}", "--parser", "auth_log", "--timezone", "Mars/Base"], "unknown timezone"),
        (["{file}", "--parser", "access_log", "--year", "2026"], "--year"),
        (["{file}", "--parser", "access_log", "--pattern", "(oops"], "invalid access log pattern"),
        (["{file}", "--format", "xml"], "xml"),
    ],
)
def test_usage_errors(args: list[str], message: str) -> None:
    resolved = [a.replace("{file}", str(SAMPLES / "auth.log")) for a in args]
    code, _, err = run(*resolved)
    assert code == ExitCode.USAGE
    assert message in err


def test_table_limit_zero_shows_only_summary() -> None:
    code, out, _ = run(str(SAMPLES / "auth.log"), "--limit", "0")
    assert code == ExitCode.OK
    assert "Events from" not in out
    assert "Parse summary" in out


def test_table_escapes_rich_markup(tmp_path: Path) -> None:
    log = tmp_path / "markup.log"
    log.write_text(
        "Oct 24 13:50:02 h sshd[1]: Invalid user [bold red]x[/bold red] from 192.0.2.1 port 1\n",
        encoding="utf-8",
    )
    code, out, _ = run(str(log), "--year", "2026")
    assert code == ExitCode.OK
    assert "[bold red]x[/bold red]" in out


def test_keep_query_option() -> None:
    code, out, _ = run(str(SAMPLES / "access.log"), "--keep-query", "--format", "json")
    assert code == ExitCode.OK
    paths = [json.loads(line)["http"]["path"] for line in out.splitlines()]
    assert any(p and "?" in p for p in paths)


def test_help_lists_parsers() -> None:
    result = runner.invoke(app, ["parse", "--help"])
    assert result.exit_code == 0
    for name in ("access_log", "app_json", "auth_log", "generic_json"):
        assert name in result.stdout
