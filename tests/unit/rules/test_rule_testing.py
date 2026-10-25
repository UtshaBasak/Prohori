"""Tests for the rule test harness (``<rule>.tests.yml`` fixtures)."""

import shutil
from datetime import UTC, datetime
from pathlib import Path

import pytest

from prohori.rules import load_rules
from prohori.rules.loader import discover
from prohori.rules.testing import (
    Case,
    _log_events,
    fixture_file_for,
    parse_offset,
    run_rule_tests,
)

VALID = Path(__file__).resolve().parents[2] / "fixtures" / "rules" / "valid"

RULE = """\
id: TST-H-001
title: Harness rule
status: test
severity: low
detection:
  failure:
    event.action: auth.signin.failure
  aggregate:
    group_by: [source.ip]
    window: 1m
    count_gte: 3
  condition: failure and aggregate
"""

GOOD_TESTS = """\
rule: TST-H-001
defaults: {event.category: authentication, source.ip: 192.0.2.1}
cases:
  - name: three failures alert
    expect: {alerts: 1, entities: [{source.ip: 192.0.2.1}]}
    events:
      - {event.action: auth.signin.failure, repeat: 3}
  - name: two failures do not
    expect: {alerts: 0}
    events:
      - {event.action: auth.signin.failure, repeat: 2}
"""


def make(tmp_path: Path, tests: str | None, rule: str = RULE) -> Path:
    (tmp_path / "rule.yml").write_text(rule, encoding="utf-8")
    if tests is not None:
        (tmp_path / "rule.tests.yml").write_text(tests, encoding="utf-8")
    return tmp_path


def single(tmp_path: Path) -> object:
    (report,) = run_rule_tests([tmp_path])
    return report


def test_valid_fixture_directory_passes() -> None:
    reports = run_rule_tests([VALID])
    assert len(reports) == 5
    assert all(r.passed for r in reports), [(r.rule_id, r.errors, r.cases) for r in reports]


def test_passing_rule(tmp_path: Path) -> None:
    (report,) = run_rule_tests([make(tmp_path, GOOD_TESTS)])
    assert report.passed
    assert [c.alerts for c in report.cases] == [1, 0]


def test_missing_fixture_fails(tmp_path: Path) -> None:
    (report,) = run_rule_tests([make(tmp_path, None)])
    assert not report.passed
    assert "no test fixtures" in report.errors[0]


def test_wrong_expectation_fails(tmp_path: Path) -> None:
    (report,) = run_rule_tests([make(tmp_path, GOOD_TESTS.replace("alerts: 1", "alerts: 2"))])
    assert not report.passed
    assert "expected 2 alert(s), got 1" in report.cases[0].message


def test_entity_expectation(tmp_path: Path) -> None:
    tests = GOOD_TESTS.replace("{source.ip: 192.0.2.1}]", "{source.ip: 192.0.2.99}]")
    (report,) = run_rule_tests([make(tmp_path, tests)])
    assert "no alert with entities" in report.cases[0].message


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (("rule: TST-H-001", "rule: TST-OTHER-001"), "not 'TST-H-001'"),
        (("expect: {alerts: 0}", "expect: {alerts: 1}"), "negative case"),
        (
            ("expect: {alerts: 1, entities: [{source.ip: 192.0.2.1}]}", "expect: {alerts: 0}"),
            "positive case",
        ),
    ],
)
def test_fixture_rules(tmp_path: Path, change: tuple[str, str], message: str) -> None:
    (report,) = run_rule_tests([make(tmp_path, GOOD_TESTS.replace(*change))])
    assert not report.passed
    assert any(message in e for e in report.errors), report.errors


@pytest.mark.parametrize(
    ("tests", "message"),
    [
        ("rule: TST-H-001\ncases: []\n", "cases"),
        ("rule: TST-H-001\ncases:\n  - {name: x, expect: {alerts: 0}}\n", "exactly one of"),
        (
            "rule: TST-H-001\nsurprise: 1\n"
            "cases:\n  - {name: x, expect: {alerts: 0}, events: [{}]}\n",
            "Extra inputs",
        ),
        ("a: &x 1\nb: *x\n", "aliases"),
        ("cases: [unclosed\n", "invalid YAML"),
    ],
)
def test_invalid_fixture_files(tmp_path: Path, tests: str, message: str) -> None:
    (report,) = run_rule_tests([make(tmp_path, tests)])
    assert not report.passed
    assert any(message in e for e in report.errors), report.errors


def test_fixture_errors_carry_line_numbers(tmp_path: Path) -> None:
    tests = GOOD_TESTS.replace("expect: {alerts: 0}", "expect: {alerts: -1}")
    (report,) = run_rule_tests([make(tmp_path, tests)])
    assert any(e.startswith("rule.tests.yml:9:") for e in report.errors), report.errors


@pytest.mark.parametrize(
    ("event", "message"),
    [
        ("{event.colour: red}", "unknown field"),
        ("{event.action: auth.signin.failure, timestamp: x}", "'at'/'after'"),
        ("{event.action: auth.signin.failure, repeat: 0}", "'repeat'"),
        ("{event.action: auth.signin.failure, every: soon}", "invalid duration"),
        ("{event.action: auth.signin.failure, at: yesterday}", "invalid 'at'"),
        ("{event.action: auth.signin.failure, at: '2026-10-24T13:50:00'}", "timezone"),
        ("{event.action: Not Valid}", "pattern"),
    ],
)
def test_bad_event_specs_fail_the_case(tmp_path: Path, event: str, message: str) -> None:
    tests = GOOD_TESTS.replace("{event.action: auth.signin.failure, repeat: 3}", event)
    (report,) = run_rule_tests([make(tmp_path, tests)])
    assert not report.cases[0].passed
    assert message in report.cases[0].message


def test_log_cases_use_parsers(tmp_path: Path) -> None:
    tests = """\
rule: TST-H-001
cases:
  - name: auth.log lines
    expect: {alerts: 0}
    log:
      parser: auth_log
      options: {year: 2026}
      lines:
        - "Oct 24 13:50:01 h sshd[1]: Failed password for root from 192.0.2.1 port 1 ssh2"
  - name: positive
    expect: {alerts: 1}
    events:
      - event.action: auth.signin.failure
        event.category: authentication
        source.ip: 192.0.2.1
        repeat: 3
"""
    (report,) = run_rule_tests([make(tmp_path, tests)])
    assert report.passed, report.cases


@pytest.mark.parametrize(
    ("log", "message"),
    [
        ("{parser: nope, lines: [x]}", "cannot create parser"),
        ("{parser: auth_log, options: {colour: red}, lines: [x]}", "cannot create parser"),
        ("{parser: auth_log, options: {year: 2026}, lines: [garbage]}", "failed to parse"),
    ],
)
def test_bad_log_cases(tmp_path: Path, log: str, message: str) -> None:
    tests = GOOD_TESTS.replace(
        "    events:\n      - {event.action: auth.signin.failure, repeat: 2}", f"    log: {log}"
    )
    (report,) = run_rule_tests([make(tmp_path, tests)])
    assert message in report.cases[1].message


def test_invalid_rule_is_reported(tmp_path: Path) -> None:
    (report,) = run_rule_tests(
        [make(tmp_path, GOOD_TESTS, rule=RULE.replace("severity: low", "severity: huge"))]
    )
    assert not report.passed
    assert "severity" in report.errors[0]


def test_fixture_files_are_not_treated_as_rules(tmp_path: Path) -> None:
    for name in ("brute-force.yml", "brute-force.tests.yml"):
        shutil.copy(VALID / name, tmp_path / name)
    shutil.copy(VALID / "brute-force.tests.yml", tmp_path / "other.tests.yaml")
    assert [p.name for p in discover([tmp_path])] == ["brute-force.yml"]
    assert all(r.ok for r in load_rules([tmp_path]))


def test_fixture_file_for(tmp_path: Path) -> None:
    rule_file = make(tmp_path, GOOD_TESTS) / "rule.yml"
    assert fixture_file_for(rule_file) == tmp_path / "rule.tests.yml"
    assert fixture_file_for(tmp_path / "missing.yml") is None


@pytest.mark.parametrize(("text", "seconds"), [("0s", 0), ("20s", 20), ("5m", 300), ("1d", 86400)])
def test_parse_offset(text: str, seconds: int) -> None:
    assert parse_offset(text).total_seconds() == seconds


def test_auth_log_cases_default_year_to_start() -> None:
    case = Case.model_validate(
        {
            "name": "no year option",
            "expect": {"alerts": 0},
            "log": {
                "parser": "auth_log",
                "lines": ["Oct 24 13:50:01 h sshd[1]: Invalid user a from 192.0.2.1 port 1"],
            },
        }
    )
    (event,) = _log_events(case, 0, datetime(2020, 3, 1, tzinfo=UTC))
    assert event.timestamp.year == 2020
