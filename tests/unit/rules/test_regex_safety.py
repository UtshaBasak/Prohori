"""Tests for rule regular expressions (RE2, linear-time matching)."""

import time

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from prohori.rules import UnsafeRegexError, check_regex
from prohori.rules.regex_safety import MAX_PATTERN_LENGTH, compile_regex


@pytest.mark.parametrize(
    ("pattern", "reason"),
    [
        (r"(a)\1", "backreferences are not supported"),
        (r"(?=admin)\w", "look-ahead is not supported"),
        (r"(?!admin)\w", "look-ahead is not supported"),
        (r"(?<!a)b", "look-behind is not supported"),
        (r"(?>a+)b", "atomic groups are not supported"),
        (r"a++b", "possessive quantifiers are not supported"),
        (r"a{1001}", "invalid repetition size"),
        ("(", "missing )"),
        ("a" * (MAX_PATTERN_LENGTH + 1), "longer than"),
    ],
)
def test_rejected(pattern: str, reason: str) -> None:
    with pytest.raises(UnsafeRegexError, match=reason.replace("(", r"\(").replace(")", r"\)")):
        check_regex(pattern)


@pytest.mark.parametrize(
    "pattern",
    [
        r"\.env$",
        r"union\s+select",
        r"(\d{1,3}\.){3}\d{1,3}",
        r"^/(wp-login\.php|phpmyadmin)",
        r"(?i)<script",
        r"\.\./",
        r"[a-z0-9]+@[a-z0-9.]+",
        r"(GET|POST)+",
        r"\pL+",
    ],
)
def test_accepted(pattern: str) -> None:
    check_regex(pattern)


@pytest.mark.parametrize(
    ("pattern", "cased", "text", "expected"),
    [
        (r"union\s+select", False, "x UNION  SELECT y", True),
        (r"union\s+select", True, "x UNION  SELECT y", False),
        (r"\.env$", False, "/.env", True),
        (r"^/admin", False, "/x/admin", False),
        (r"\pL+ü", False, "grün", True),
    ],
)
def test_search(pattern: str, cased: bool, text: str, expected: bool) -> None:
    assert compile_regex(pattern, cased=cased)(text) is expected


def test_hostile_patterns_run_in_linear_time() -> None:
    """Patterns that make a backtracking engine hang finish quickly on an 8 KiB field."""
    hostile = [
        r".*.*x",
        r"\w*\w*\w*x",
        r"[a-z]+[a-z]+[a-z]+!",
        r"(a+)+$",
        r"(a|ab)*c",
        r"(\w+\s?)+$",
    ]
    text = "a" * 8192
    started = time.perf_counter()
    for pattern in hostile:
        compile_regex(pattern, cased=False)(text)
    assert time.perf_counter() - started < 0.5


@settings(max_examples=300)
@given(st.text(max_size=40), st.text(max_size=200))
def test_arbitrary_patterns_compile_or_raise(pattern: str, text: str) -> None:
    try:
        search = compile_regex(pattern, cased=False)
    except UnsafeRegexError:
        return
    search(text)
