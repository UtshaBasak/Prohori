"""Tests for ``prohori rules list`` and ``prohori rules validate``."""

import json
import re
from pathlib import Path

from typer.testing import CliRunner

from prohori.cli import app
from prohori.cli.exit_codes import ExitCode

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "rules"
runner = CliRunner(env={"COLUMNS": "200", "NO_COLOR": "1"})
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def run(*args: str) -> tuple[int, str, str]:
    result = runner.invoke(app, ["rules", *args])
    return result.exit_code, _ANSI.sub("", result.stdout), _ANSI.sub("", result.stderr)


def test_validate_mixed_directory_fails() -> None:
    code, out, _ = run("validate", str(FIXTURES))
    assert code == ExitCode.INVALID_RULES
    assert "5 valid, 9 invalid" in out
    assert re.search(r"INVALID\s+\S*unsafe-regex\.yml", out)
    assert re.search(
        r"unsafe-regex\.yml:7: detection\.selection\.http\.path\|re: invalid regular expression: "
        r"backreferences are not supported",
        out,
    )


def test_validate_valid_directory_succeeds() -> None:
    code, out, _ = run("validate", str(FIXTURES / "valid"))
    assert code == ExitCode.OK
    assert "5 valid, 0 invalid" in out


def test_validate_json() -> None:
    code, out, _ = run(
        "validate", str(FIXTURES / "invalid" / "unknown-field.yml"), "--format", "json"
    )
    assert code == ExitCode.INVALID_RULES
    (row,) = json.loads(out)
    assert row["valid"] is False
    assert row["errors"][0]["line"] == 7
    assert row["errors"][0]["path"] == "detection.selection.event.actoin"


def test_validate_default_builtin_directory() -> None:
    code, _, _ = run("validate")
    assert code == ExitCode.OK


def test_validate_missing_path() -> None:
    code, _, err = run("validate", "does-not-exist")
    assert code == ExitCode.USAGE
    assert "not found" in err


def test_list_table_sorted_by_id() -> None:
    code, out, _ = run("list", str(FIXTURES / "valid"))
    assert code == ExitCode.OK
    ids = re.findall(r"TST-[A-Z]+-\d{3}", out)
    assert ids == sorted(ids)
    assert len(ids) == 5


def test_list_json() -> None:
    code, out, _ = run("list", str(FIXTURES / "valid"), "--format", "json")
    assert code == ExitCode.OK
    rows = json.loads(out)
    assert {r["id"] for r in rows} == {
        "TST-AUTH-001",
        "TST-AUTH-002",
        "TST-AUTH-003",
        "TST-WEB-001",
        "TST-WEB-002",
    }
    assert next(r for r in rows if r["id"] == "TST-WEB-001")["stateful"] is False


def test_list_reports_invalid_rules() -> None:
    code, _, err = run("list", str(FIXTURES))
    assert code == ExitCode.INVALID_RULES
    assert "9 invalid rule file(s)" in err


def test_list_default_builtin_directory() -> None:
    code, out, _ = run("list")
    assert code == ExitCode.OK
    assert "PRH-AUTH-001" in out
    assert "PRH-AUTHZ-001" in out


def test_rule_text_is_not_rendered_as_markup(tmp_path: Path) -> None:
    rule = (FIXTURES / "valid" / "brute-force.yml").read_text(encoding="utf-8")
    rule = rule.replace(
        "title: Brute-force sign-in attempts from one IP", "title: '[bold red]Injected[/bold red]'"
    )
    (tmp_path / "rule.yml").write_text(rule, encoding="utf-8")
    code, out, _ = run("list", str(tmp_path))
    assert code == ExitCode.OK
    assert "[bold red]Injected[/bold red]" in out


def test_validate_strips_control_characters(tmp_path: Path) -> None:
    rule = (FIXTURES / "valid" / "brute-force.yml").read_text(encoding="utf-8")
    rule = rule.replace(
        "    event.action: [auth.signin.failure, ssh.login.failure]",
        r'    "event.action\e]0;pwned\a": x',
    )
    (tmp_path / "rule.yml").write_text(rule, encoding="utf-8")
    code, out, _ = run("validate", str(tmp_path))
    assert code == ExitCode.INVALID_RULES
    assert "\x1b" not in out
    assert "\x07" not in out
    assert "unknown field" in out


def test_rules_test_valid_fixtures_pass() -> None:
    code, out, _ = run("test", str(FIXTURES / "valid"))
    assert code == ExitCode.OK
    assert "5 passed, 0 failed" in out
    assert "PASS  TST-AUTH-001" in out


def test_rules_test_fails_without_fixtures(tmp_path: Path) -> None:
    rule = (FIXTURES / "valid" / "brute-force.yml").read_text(encoding="utf-8")
    (tmp_path / "rule.yml").write_text(rule, encoding="utf-8")
    code, out, _ = run("test", str(tmp_path))
    assert code == ExitCode.INVALID_RULES
    assert "no test fixtures" in out


def test_rules_test_json() -> None:
    code, out, _ = run("test", str(FIXTURES / "valid"), "--format", "json")
    assert code == ExitCode.OK
    rows = json.loads(out)
    assert len(rows) == 5
    assert all(r["passed"] for r in rows)
    assert rows[0]["cases"][0]["alerts"] >= 1


def test_rules_test_default_builtin_directory() -> None:
    code, out, _ = run("test")
    assert code == ExitCode.OK
    assert "0 failed" in out


def test_rules_test_missing_path() -> None:
    code, _, err = run("test", "nowhere")
    assert code == ExitCode.USAGE
    assert "not found" in err
