"""Tests for stateless selection matching."""

import fnmatch
from datetime import UTC, datetime
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from prohori.rules import wildcard_match
from prohori.rules.matching import RuleError, Selection, compile_selection, has_wildcards
from prohori.schema import Event


def event(**overrides: Any) -> Event:
    data: dict[str, Any] = {
        "timestamp": datetime(2026, 10, 24, 13, 50, tzinfo=UTC),
        "log_source": "nginx",
        "event": {"action": "web.request", "category": "web", "outcome": "failure"},
        "source": {"ip": "203.0.113.7"},
        "http": {"method": "GET", "path": "/WP-Login.php", "status": 404, "bytes": 153},
        "user_agent": "sqlmap/1.8",
        "raw": "line",
        "extra": {"query": "id=1' OR '1'='1", "attempts": "7"},
    }
    data.update(overrides)
    return Event.model_validate(data)


def compile_ok(raw: object) -> Selection:
    errors: list[RuleError] = []
    selection = compile_selection("sel", raw, ("detection", "sel"), errors)
    assert errors == []
    assert selection is not None
    return selection


def compile_errors(raw: object) -> list[RuleError]:
    errors: list[RuleError] = []
    assert compile_selection("sel", raw, ("detection", "sel"), errors) is None
    return errors


EVENT = event()


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        # exact, case-insensitive by default
        ({"http.method": "get"}, True),
        ({"http.method|cased": "get"}, False),
        ({"http.method|cased": "GET"}, True),
        # any-of lists
        ({"http.method": ["POST", "GET"]}, True),
        ({"http.method": ["POST", "PUT"]}, False),
        # all keys of a mapping must match
        ({"http.method": "GET", "http.status": 404}, True),
        ({"http.method": "GET", "http.status": 200}, False),
        # list of mappings: any mapping
        ([{"http.status": 200}, {"http.status": 404}], True),
        # numbers match numbers and numeric strings
        ({"http.status": 404}, True),
        ({"http.status": "404"}, True),
        ({"extra.attempts": 7}, True),
        ({"http.status": 404.0}, True),
        # wildcards
        ({"http.path": "/wp-*"}, True),
        ({"http.path": "*login?php"}, True),
        ({"http.path": "/wp-login"}, False),
        ({"http.path|cased": "/wp-*"}, False),
        # escaped wildcard is literal
        ({"user_agent": "sqlmap\\*"}, False),
        # null means missing
        ({"user.name": None}, True),
        ({"http.method": None}, False),
        # operators
        ({"http.path|contains": "login"}, True),
        ({"http.path|startswith": "/wp"}, True),
        ({"http.path|endswith": ".PHP"}, True),
        ({"http.path|endswith|cased": ".PHP"}, False),
        ({"extra.query|re": r"'\s+or\s+'"}, True),
        ({"extra.query|re|cased": r"'\s+or\s+'"}, False),
        ({"source.ip|cidr": "203.0.113.0/24"}, True),
        ({"source.ip|cidr": ["10.0.0.0/8", "192.168.0.0/16"]}, False),
        ({"http.status|gte": 400}, True),
        ({"http.status|gt": 404}, False),
        ({"http.status|lt": 500, "http.status|gte": 400}, True),
        ({"http.bytes|lte": "153"}, True),
        ({"http.method|gt": 1}, False),
        ({"user.name|exists": False}, True),
        ({"http.path|exists": True}, True),
        # all
        ({"http.path|contains|all": ["wp", "login"]}, True),
        ({"http.path|contains|all": ["wp", "admin"]}, False),
        # missing fields never match a value
        ({"user.name|contains": "a"}, False),
        ({"user.name|cidr": "10.0.0.0/8"}, False),
        # extra fields
        ({"extra.missing": None}, True),
    ],
)
def test_matching(raw: object, expected: bool) -> None:
    assert compile_ok(raw).matches(EVENT) is expected


def test_cidr_ignores_non_ip_values() -> None:
    selection = compile_ok({"user_agent|cidr": "10.0.0.0/8"})
    assert not selection.matches(EVENT)


def test_bool_values() -> None:
    selection = compile_ok({"extra.flag": True})
    assert selection.matches(event(extra={"flag": True}))
    assert selection.matches(event(extra={"flag": "true"}))
    assert not selection.matches(event(extra={"flag": False}))


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        ("not a mapping", "mapping or a non-empty list"),
        ([], "mapping or a non-empty list"),
        ([{}], "non-empty mapping"),
        ({"event.colour": "x"}, "unknown field"),
        ({"http.path|shout": "x"}, "unknown modifier"),
        ({"http.path|contains|startswith": "x"}, "at most one operator"),
        ({"http.path|cased|cased": "x"}, "at most one operator"),
        ({"http.path": []}, "empty list"),
        ({"http.path": [{"nested": 1}]}, "values must be"),
        ({"http.path": ["x"] * 513}, "more than 512"),
        ({"http.path|contains|all": ["x"]}, "at least two"),
        ({"http.status|gte": "lots"}, "needs a number"),
        ({"source.ip|cidr": "300.1.1.0/24"}, "invalid CIDR"),
        ({"http.path|re": 5}, "string pattern"),
        ({"http.path|re": "(a+)+"}, "unsafe regex"),
        ({"http.path|exists": "yes"}, "true or false"),
        ({"http.path|contains": None}, "null cannot"),
        ({"http.path": "x" * 1025}, "longer than"),
        ({5: "x"}, "must be strings"),
    ],
)
def test_invalid_selections(raw: object, message: str) -> None:
    errors = compile_errors(raw)
    assert any(message in e.message for e in errors), errors


def test_error_paths_point_at_values() -> None:
    errors = compile_errors({"http.status|gte": [400, "lots"]})
    assert errors[0].path == ("detection", "sel", "http.status|gte", 1)


class TestWildcard:
    @pytest.mark.parametrize(
        ("pattern", "text", "expected"),
        [
            ("*", "", True),
            ("", "", True),
            ("", "a", False),
            ("a*b", "ab", True),
            ("a*b", "axxxb", True),
            ("a*b", "axxxc", False),
            ("a?c", "abc", True),
            ("a?c", "ac", False),
            ("*.env", "/.env", True),
            ("\\*", "*", True),
            ("\\*", "a", False),
            ("a\\?", "a?", True),
            ("\\\\*", "\\abc", True),
            ("*a*a*a*b", "a" * 5000, False),
        ],
    )
    def test_cases(self, pattern: str, text: str, expected: bool) -> None:
        assert wildcard_match(pattern, text) is expected

    @given(
        st.text(alphabet="ab*?", max_size=8),
        st.text(alphabet="ab", max_size=12),
    )
    def test_agrees_with_fnmatch(self, pattern: str, text: str) -> None:
        assert wildcard_match(pattern, text) == fnmatch.fnmatchcase(text, pattern)

    def test_has_wildcards(self) -> None:
        assert has_wildcards("a*")
        assert has_wildcards("a?")
        assert has_wildcards("a\\\\*")
        assert not has_wildcards("a\\*")
        assert not has_wildcards("plain")
