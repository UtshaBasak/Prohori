"""Static safety checks for regular expressions in detection rules.

Python's ``re`` module has no timeout, so a rule regex that backtracks catastrophically on a hostile
log line would hang the whole run. Patterns are therefore checked when a rule is validated, and
unsafe constructs are rejected:

* patterns longer than :data:`MAX_PATTERN_LENGTH`;
* backreferences and look-around assertions;
* repeat counts above :data:`MAX_REPEAT_COUNT`;
* an unbounded repeat (``*``, ``+``, ``{n,}``) around anything that itself repeats, such as
  ``(a+)+`` or ``(\\w+\\s?)+``;
* alternation inside any repeat, such as ``(a|ab)*``;
* bounded repeats nested so deeply that the combined count exceeds :data:`MAX_NESTED_PRODUCT`;
* more than :data:`MAX_UNBOUNDED_REPEATS` unbounded repeats in total, or more than
  :data:`MAX_UNBOUNDED_ANY` unbounded repeats of ``.`` (``.*.*.*x`` is cubic in the input length).

Together with the bounded length of every event field this keeps matching time polynomial and
small. It is a static check only: there is no runtime timeout.
"""

import re
from collections.abc import Iterable

# ``re._parser`` is private but stable across the supported Python versions (3.11-3.14);
# the public ``sre_parse`` alias is deprecated and emits a warning on import.
from re import _constants as sre_constants  # type: ignore[attr-defined]
from re import _parser as sre_parser  # type: ignore[attr-defined]
from typing import Any

MAX_PATTERN_LENGTH = 256
MAX_REPEAT_COUNT = 100
MAX_NESTED_PRODUCT = 1_000
MAX_UNBOUNDED_REPEATS = 6
MAX_UNBOUNDED_ANY = 2

_MAXREPEAT = sre_constants.MAXREPEAT
_REPEATS = {sre_constants.MAX_REPEAT, sre_constants.MIN_REPEAT, sre_constants.POSSESSIVE_REPEAT}
_FORBIDDEN = {
    sre_constants.GROUPREF: "backreferences are not allowed",
    sre_constants.GROUPREF_EXISTS: "conditional backreferences are not allowed",
    sre_constants.ASSERT: "look-around assertions are not allowed",
    sre_constants.ASSERT_NOT: "look-around assertions are not allowed",
}


class UnsafeRegexError(ValueError):
    """Raised for a regular expression that is invalid or could backtrack catastrophically."""


class _Counts:
    def __init__(self) -> None:
        self.unbounded = 0
        self.unbounded_any = 0


def check_regex(pattern: str) -> None:
    """Raise :class:`UnsafeRegexError` if ``pattern`` is invalid or unsafe; return otherwise."""
    if len(pattern) > MAX_PATTERN_LENGTH:
        msg = f"pattern longer than {MAX_PATTERN_LENGTH} characters"
        raise UnsafeRegexError(msg)
    try:
        re.compile(pattern)
        parsed = sre_parser.parse(pattern)
    except (re.error, OverflowError, RecursionError) as exc:
        msg = f"invalid regular expression: {exc}"
        raise UnsafeRegexError(msg) from None
    counts = _Counts()
    _walk(list(parsed), counts, product=1, inside_unbounded=False, inside_repeat=False)
    if counts.unbounded > MAX_UNBOUNDED_REPEATS:
        msg = f"more than {MAX_UNBOUNDED_REPEATS} unbounded repeats"
        raise UnsafeRegexError(msg)
    if counts.unbounded_any > MAX_UNBOUNDED_ANY:
        msg = f"more than {MAX_UNBOUNDED_ANY} unbounded repeats of '.'"
        raise UnsafeRegexError(msg)


def _walk(
    items: list[tuple[Any, Any]],
    counts: _Counts,
    *,
    product: int,
    inside_unbounded: bool,
    inside_repeat: bool,
) -> None:
    for op, arg in items:
        if op in _FORBIDDEN:
            raise UnsafeRegexError(_FORBIDDEN[op])
        if op in _REPEATS:
            low, high, body = arg
            _check_repeat(low, high, body, counts, product, inside_unbounded, inside_repeat)
        elif op == sre_constants.BRANCH:
            if inside_repeat:
                msg = "alternation inside a repeat (for example '(a|ab)*') is not allowed"
                raise UnsafeRegexError(msg)
            for branch in arg[1]:
                _walk(
                    list(branch),
                    counts,
                    product=product,
                    inside_unbounded=inside_unbounded,
                    inside_repeat=inside_repeat,
                )
        elif op == sre_constants.SUBPATTERN:
            body = arg[-1]
            _walk(
                list(body),
                counts,
                product=product,
                inside_unbounded=inside_unbounded,
                inside_repeat=inside_repeat,
            )
        elif op == sre_constants.ATOMIC_GROUP:
            _walk(
                list(arg),
                counts,
                product=product,
                inside_unbounded=inside_unbounded,
                inside_repeat=inside_repeat,
            )


def _check_repeat(
    low: int,
    high: int,
    body: Iterable[tuple[Any, Any]],
    counts: _Counts,
    product: int,
    inside_unbounded: bool,
    inside_repeat: bool,
) -> None:
    unbounded = high == _MAXREPEAT
    if (not unbounded and high > MAX_REPEAT_COUNT) or low > MAX_REPEAT_COUNT:
        msg = f"repeat counts above {MAX_REPEAT_COUNT} are not allowed"
        raise UnsafeRegexError(msg)
    repeats = unbounded or high > 1
    if repeats and inside_unbounded:
        msg = "a repeat inside an unbounded repeat (for example '(a+)+') is not allowed"
        raise UnsafeRegexError(msg)
    if unbounded:
        counts.unbounded += 1
        if _is_any(body):
            counts.unbounded_any += 1
    new_product = product * (high if not unbounded else 1)
    if new_product > MAX_NESTED_PRODUCT:
        msg = f"nested repeats allow more than {MAX_NESTED_PRODUCT} combinations"
        raise UnsafeRegexError(msg)
    _walk(
        list(body),
        counts,
        product=new_product,
        inside_unbounded=inside_unbounded or unbounded,
        inside_repeat=inside_repeat or repeats,
    )


def _is_any(body: Iterable[tuple[Any, Any]]) -> bool:
    items = list(body)
    return len(items) == 1 and items[0][0] == sre_constants.ANY
