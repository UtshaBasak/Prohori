"""Regular expressions for detection rules, evaluated with RE2 in linear time.

Rule patterns run against attacker-controlled log fields. Python's ``re`` module backtracks and
has no timeout, so a pattern such as ``.*.*x`` or ``(a+)+$`` can take minutes on one 8 KiB field.
Rules therefore use `RE2 <https://github.com/google/re2>`_ (the ``google-re2`` package, imported
as ``re2``), whose matching time is linear in the input length by construction.

RE2 rejects constructs that cannot run in linear time (backreferences, look-around, atomic groups,
possessive quantifiers) at compile time, and caps repetition counts and program size. On top of
that, patterns are limited to :data:`MAX_PATTERN_LENGTH` characters.
"""

from collections.abc import Callable
from typing import Any

import re2

MAX_PATTERN_LENGTH = 256

#: Upper bound for the compiled program, in bytes (RE2's own default is 8 MiB).
MAX_PROGRAM_MEMORY = 1 << 20

_FRIENDLY = (
    ("invalid escape sequence: \\1", "backreferences are not supported"),
    ("invalid escape sequence: \\2", "backreferences are not supported"),
    ("invalid perl operator: (?=", "look-ahead is not supported"),
    ("invalid perl operator: (?!", "look-ahead is not supported"),
    ("invalid perl operator: (?<", "look-behind is not supported"),
    ("invalid perl operator: (?>", "atomic groups are not supported"),
    ("bad repetition operator: ++", "possessive quantifiers are not supported"),
    ("bad repetition operator: *+", "possessive quantifiers are not supported"),
    ("bad repetition operator: ?+", "possessive quantifiers are not supported"),
)


class UnsafeRegexError(ValueError):
    """Raised for a pattern that is too long or that RE2 cannot compile."""


def _compile(pattern: str, cased: bool) -> Any:  # noqa: ANN401 - re2 ships no type hints
    if len(pattern) > MAX_PATTERN_LENGTH:
        msg = f"pattern longer than {MAX_PATTERN_LENGTH} characters"
        raise UnsafeRegexError(msg)
    options = re2.Options()
    options.case_sensitive = cased
    options.log_errors = False
    options.max_mem = MAX_PROGRAM_MEMORY
    try:
        return re2.compile(pattern, options)
    except re2.error as exc:
        detail = exc.args[0] if exc.args else exc
        text = detail.decode("utf-8", "replace") if isinstance(detail, bytes) else str(detail)
        for raw, friendly in _FRIENDLY:
            if text.startswith(raw):
                text = friendly
                break
        msg = f"invalid regular expression: {text}"
        raise UnsafeRegexError(msg) from None


def check_regex(pattern: str) -> None:
    """Raise :class:`UnsafeRegexError` if ``pattern`` cannot be used in a rule."""
    _compile(pattern, cased=True)


def compile_regex(pattern: str, *, cased: bool) -> Callable[[str], bool]:
    """Compile ``pattern`` and return a predicate that searches a string in linear time.

    Raises:
        UnsafeRegexError: if the pattern is too long or RE2 cannot compile it.
    """
    regex = _compile(pattern, cased)

    def search(text: str) -> bool:
        return regex.search(text) is not None

    return search
