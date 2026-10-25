"""Tests for the static regular-expression safety check."""

import pytest

from prohori.rules import UnsafeRegexError, check_regex
from prohori.rules.regex_safety import MAX_PATTERN_LENGTH


@pytest.mark.parametrize(
    ("pattern", "reason"),
    [
        (r"(a+)+$", "inside an unbounded repeat"),
        (r"(a*)*", "inside an unbounded repeat"),
        (r"(\w+\s?)+$", "inside an unbounded repeat"),
        (r"(x+x+)+y", "inside an unbounded repeat"),
        (r"(a|ab)*c", "alternation inside a repeat"),
        (r"(GET|POST){2,3}", "alternation inside a repeat"),
        (r".*.*.*x", "repeats of '.'"),
        (r"a+b+c+d+e+f+g+", "more than 6 unbounded"),
        (r"(a)\1", "backreferences"),
        (r"(?P<x>a)(?(x)b|c)", "conditional backreferences"),
        (r"(?=admin)\w", "look-around"),
        (r"(?<!a)b", "look-around"),
        (r"a{1000}", "repeat counts above"),
        (r"a{,500}", "repeat counts above"),
        (r"(a{1,50}){50}", "combinations"),
        ("(", "invalid regular expression"),
        ("a" * (MAX_PATTERN_LENGTH + 1), "longer than"),
    ],
)
def test_rejected(pattern: str, reason: str) -> None:
    with pytest.raises(UnsafeRegexError, match=reason):
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
        r".*admin.*",
        r"(?:ab)+c",
        r"^sqlmap/\d+\.\d+",
        r"(?>a+)b",
        r"a++b",
    ],
)
def test_accepted(pattern: str) -> None:
    check_regex(pattern)
