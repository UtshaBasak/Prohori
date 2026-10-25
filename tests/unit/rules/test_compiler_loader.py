"""Tests for rule compilation and loading (validation, line numbers, YAML safety)."""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from prohori.rules import builtin_rules_dir, compile_rule, load_rule, load_rules, parse_duration
from prohori.rules.loader import MAX_DEPTH, MAX_RULE_BYTES, discover
from prohori.schema import Event

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "rules"

BASE: dict[str, Any] = {
    "id": "TST-X-001",
    "title": "Test rule",
    "status": "test",
    "severity": "medium",
    "detection": {
        "selection": {"event.action": "auth.signin.failure"},
        "condition": "selection",
    },
}


def rule(**overrides: Any) -> dict[str, Any]:
    document = {**BASE, **overrides}
    return document


def detection(**blocks: Any) -> dict[str, Any]:
    return rule(detection=blocks)


def errors_of(document: object) -> list[str]:
    result = compile_rule(document)
    assert result.rule is None
    return [f"{'.'.join(map(str, e.path))}: {e.message}" for e in result.errors]


def event(action: str, category: str = "authentication", log_source: str = "app") -> Event:
    return Event.model_validate(
        {
            "timestamp": datetime(2026, 10, 24, tzinfo=UTC),
            "log_source": log_source,
            "event": {"action": action, "category": category},
            "raw": action,
        }
    )


class TestCompile:
    def test_minimal_rule(self) -> None:
        result = compile_rule(rule())
        assert result.errors == []
        assert result.rule is not None
        assert result.rule.id == "TST-X-001"
        assert not result.rule.is_stateful
        assert result.rule.matches_filter(event("auth.signin.failure"))
        assert not result.rule.matches_filter(event("auth.signin.success"))

    def test_logsource_filter(self) -> None:
        compiled = compile_rule(rule(logsource={"category": "web", "log_source": "NGINX"})).rule
        assert compiled is not None
        assert not compiled.matches_filter(event("auth.signin.failure"))
        assert compiled.matches_filter(event("auth.signin.failure", "web", "nginx"))

    def test_aggregate_rule(self) -> None:
        compiled = compile_rule(
            detection(
                failure={"event.action": "auth.signin.failure"},
                aggregate={"group_by": ["source.ip"], "window": "5m", "count_gte": 10},
                condition="failure and aggregate",
            )
        ).rule
        assert compiled is not None
        assert compiled.aggregate is not None
        assert compiled.is_stateful
        assert compiled.aggregate.window == timedelta(minutes=5)
        assert compiled.matches_filter(event("auth.signin.failure"))

    def test_sequence_rule_filter_is_any_step(self) -> None:
        compiled = compile_rule(
            detection(
                fail={"event.action": "auth.signin.failure"},
                ok={"event.action": "auth.signin.success"},
                sequence={
                    "by": ["source.ip"],
                    "within": "10m",
                    "steps": [{"selection": "fail", "count_gte": 3}, {"selection": "ok"}],
                },
                condition="sequence",
            )
        ).rule
        assert compiled is not None
        assert compiled.sequence is not None
        assert compiled.filter is None
        assert compiled.matches_filter(event("auth.signin.success"))
        assert not compiled.matches_filter(event("auth.lockout"))

    @pytest.mark.parametrize(
        ("document", "message"),
        [
            ("just a string", "must be a YAML mapping"),
            (rule(detection="selection"), "detection"),
            (detection(condition="selection"), "unknown selection 'selection'"),
            (detection(selection={"event.action": "x"}), "missing condition"),
            (detection(selection={"event.action": "x"}, condition="selection or nope"), "nope"),
            (
                detection(
                    selection={"event.action": "x"},
                    unused={"event.action": "y"},
                    condition="selection",
                ),
                "never used",
            ),
            (
                detection(**{"bad-name": {"event.action": "x"}}, condition="selection"),
                "invalid selection name",
            ),
            (
                detection(selection={"event.action": "x"}, condition="aggregate and selection"),
                "not defined",
            ),
            (
                detection(
                    selection={"event.action": "x"},
                    aggregate={"group_by": ["source.ip"], "window": "5m", "count_gte": 2},
                    condition="aggregate",
                ),
                "needs a selection",
            ),
            (
                detection(
                    selection={"event.action": "x"},
                    aggregate={"group_by": ["source.ip"], "window": "5m", "count_gte": 2},
                    condition="selection",
                ),
                "not in the condition",
            ),
            (
                detection(
                    selection={"event.action": "x"},
                    aggregate={"group_by": ["source.ip"], "window": "5m"},
                    condition="selection and aggregate",
                ),
                "exactly one of",
            ),
            (
                detection(
                    selection={"event.action": "x"},
                    aggregate={
                        "group_by": ["source.ip"],
                        "window": "5m",
                        "ratio": {"selection": "ghost", "gte": 0.5},
                    },
                    condition="selection and aggregate",
                ),
                "unknown selection 'ghost'",
            ),
            (
                detection(
                    a={"event.action": "x"},
                    sequence={
                        "by": ["source.ip"],
                        "within": "1m",
                        "steps": [{"selection": "a"}, {"selection": "b"}],
                    },
                    condition="sequence",
                ),
                "unknown selection 'b'",
            ),
            (
                detection(
                    a={"event.action": "x"},
                    sequence={
                        "by": ["source.ip"],
                        "within": "1m",
                        "steps": [{"selection": "a"}, {"selection": "a"}],
                    },
                    condition="a and sequence",
                ),
                "just 'sequence'",
            ),
            (
                detection(
                    a={"event.action": "x"},
                    aggregate={"group_by": ["source.ip"], "window": "5m", "count_gte": 2},
                    sequence={
                        "by": ["source.ip"],
                        "within": "1m",
                        "steps": [{"selection": "a"}, {"selection": "a"}],
                    },
                    condition="a and aggregate and sequence",
                ),
                "either aggregate or sequence",
            ),
            (rule(tags=["attack.T1110"]), "tags.0"),
            (rule(tags=["attack.t111"]), "invalid ATT&CK tag"),
            (rule(response="/etc/passwd.md"), "relative path"),
            (rule(response="runbooks/../../x.md"), "relative path"),
            (rule(response="C:/x.md"), "relative path"),
            (rule(references=["ftp://x"]), "references.0"),
            (rule(unknown_key=1), "Extra inputs"),
            ({**rule(), "id": None}, "id"),
        ],
    )
    def test_invalid(self, document: object, message: str) -> None:
        errors = errors_of(document)
        assert any(message in e for e in errors), errors

    def test_attack_tags_property(self) -> None:
        compiled = compile_rule(rule(tags=["attack.t1110", "custom.tag"])).rule
        assert compiled is not None
        assert compiled.meta.attack_tags == ("attack.t1110",)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("1s", timedelta(seconds=1)),
        ("5m", timedelta(minutes=5)),
        ("2h", timedelta(hours=2)),
        ("7d", timedelta(days=7)),
    ],
)
def test_parse_duration(text: str, expected: timedelta) -> None:
    assert parse_duration(text) == expected


@pytest.mark.parametrize(
    ("text", "message"),
    [("0s", "between"), ("8d", "between"), ("5 minutes", "invalid"), (5, "string")],
)
def test_parse_duration_errors(text: object, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        parse_duration(text)


def write(tmp_path: Path, text: str, name: str = "rule.yml") -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


VALID_YAML = """\
id: TST-Y-001
title: YAML rule
status: test
severity: low
detection:
  selection:
    event.action: auth.signin.failure
  condition: selection
"""


class TestLoader:
    def test_valid_file(self, tmp_path: Path) -> None:
        report = load_rule(write(tmp_path, VALID_YAML))
        assert report.ok
        assert report.rule is not None
        assert report.rule.id == "TST-Y-001"

    def test_error_line_three_levels_deep(self, tmp_path: Path) -> None:
        text = VALID_YAML.replace(
            "    event.action: auth.signin.failure",
            "    event.action: x\n    http.status|gte: lots",
        )
        report = load_rule(write(tmp_path, text))
        assert not report.ok
        (error,) = report.errors
        assert error.line == 8
        assert error.path == "detection.selection.http.status|gte"
        assert "needs a number" in error.message

    def test_error_line_for_list_item(self, tmp_path: Path) -> None:
        text = VALID_YAML.replace(
            "    event.action: auth.signin.failure",
            "    source.ip|cidr:\n      - 10.0.0.0/8\n      - not-a-network",
        )
        (error,) = load_rule(write(tmp_path, text)).errors
        assert error.line == 9
        assert error.path == "detection.selection.source.ip|cidr[1]"

    def test_error_line_for_metadata(self, tmp_path: Path) -> None:
        (error,) = load_rule(
            write(tmp_path, VALID_YAML.replace("severity: low", "severity: huge"))
        ).errors
        assert error.line == 4
        assert error.path == "severity"

    def test_condition_error_line(self, tmp_path: Path) -> None:
        text = VALID_YAML.replace("condition: selection", "condition: selection and nope")
        (error,) = load_rule(write(tmp_path, text)).errors
        assert error.line == 8

    def test_format(self, tmp_path: Path) -> None:
        (error,) = load_rule(
            write(tmp_path, VALID_YAML.replace("severity: low", "severity: huge"))
        ).errors
        assert error.format("rule.yml").startswith("rule.yml:4: severity: ")

    @pytest.mark.parametrize(
        ("text", "message"),
        [
            ("", "empty"),
            ("key: [unclosed\n", "invalid YAML"),
            ("a: 1\n---\nb: 2\n", "invalid YAML"),
            ("detection: !!python/object/apply:os.system ['echo x']\n", "invalid YAML"),
            ("a: !!binary aGk=\nb: !!set {x}\n", None),
            ("a: &x [1, 2]\nb: *x\n", "aliases are not allowed"),
            ("a: " + "[" * (MAX_DEPTH + 5) + "]" * (MAX_DEPTH + 5) + "\n", "deeper than"),
        ],
    )
    def test_unsafe_or_broken_yaml(self, tmp_path: Path, text: str, message: str | None) -> None:
        report = load_rule(write(tmp_path, text))
        assert not report.ok
        if message is not None:
            assert any(message in e.message for e in report.errors), report.errors

    def test_too_large(self, tmp_path: Path) -> None:
        report = load_rule(write(tmp_path, "# " + "x" * MAX_RULE_BYTES))
        assert "larger than" in report.errors[0].message

    def test_not_utf8(self, tmp_path: Path) -> None:
        path = tmp_path / "rule.yml"
        path.write_bytes(b"title: caf\xe9\n")
        assert "UTF-8" in load_rule(path).errors[0].message

    def test_unreadable(self, tmp_path: Path) -> None:
        assert "cannot read" in load_rule(tmp_path / "missing.yml").errors[0].message

    def test_duplicate_ids(self, tmp_path: Path) -> None:
        write(tmp_path, VALID_YAML, "a.yml")
        write(tmp_path, VALID_YAML, "b.yaml")
        reports = load_rules([tmp_path])
        assert [r.ok for r in reports] == [True, False]
        assert "duplicate rule id" in reports[1].errors[0].message

    def test_discover_recursive_sorted_and_files(self, tmp_path: Path) -> None:
        (tmp_path / "sub").mkdir()
        b = write(tmp_path, VALID_YAML, "b.yml")
        a = write(tmp_path / "sub", VALID_YAML, "a.YAML")
        write(tmp_path, "ignored", "notes.txt")
        assert list(discover([tmp_path])) == sorted([b, a])
        assert list(discover([b])) == [b]


class TestFixtures:
    def test_valid_fixtures(self) -> None:
        reports = load_rules([FIXTURES / "valid"])
        assert reports
        assert all(r.ok for r in reports), [(r.file, r.errors) for r in reports if not r.ok]

    def test_invalid_fixtures(self) -> None:
        reports = load_rules([FIXTURES / "invalid"])
        assert reports
        for report in reports:
            assert not report.ok, report.file
            assert all(e.line is not None for e in report.errors), (report.file, report.errors)

    def test_builtin_dir_exists(self) -> None:
        assert builtin_rules_dir().is_dir()
        assert all(r.ok for r in load_rules([builtin_rules_dir()]))


def test_extremely_deep_yaml_is_reported_not_raised(tmp_path: Path) -> None:
    path = tmp_path / "deep.yml"
    path.write_text("a: " + "[" * 2000 + "]" * 2000 + "\n", encoding="utf-8")
    report = load_rule(path)
    assert not report.ok
    assert "nested deeper" in report.errors[0].message
