"""Stateless field matching for rule selections.

A selection is a mapping of ``field[|modifier...]`` keys to expected values, or a list of such
mappings. Matching rules (see ``docs/RULES.md``):

* keys within one mapping must **all** match; a list of mappings matches if **any** mapping does;
* a list of values matches if **any** value matches (``|all`` requires every value to match);
* string comparison is case-insensitive unless the ``|cased`` modifier is used;
* ``*`` and ``?`` in plain values are wildcards; ``\\*``, ``\\?`` and ``\\\\`` match a literal
  ``*``, ``?`` and ``\\``, and any other backslash is literal (``C:\\Windows``);
* a YAML number equals a numeric field or a numeric string with the same value;
* ``null`` matches a missing (unset) field;
* ``|urldecode`` percent-decodes the field value (repeatedly, for double encoding) before matching.
"""

import ipaddress
import math
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, tzinfo
from urllib.parse import unquote_plus

from prohori.rules.regex_safety import UnsafeRegexError, compile_regex
from prohori.schema import Event, JsonScalar, get_field, is_valid_path

#: Operator modifiers; at most one per key.
OPERATORS = frozenset(
    {"contains", "startswith", "endswith", "re", "cidr", "gt", "gte", "lt", "lte", "exists"}
)
#: Flag modifiers that combine with an operator.
FLAGS = frozenset({"all", "cased", "urldecode"})
#: Operators that compare text, the only ones ``urldecode`` combines with.
TEXT_OPERATORS = frozenset({None, "contains", "startswith", "endswith", "re"})
#: Decoding rounds for ``urldecode``: enough for double and triple encoding.
URLDECODE_ROUNDS = 3
MAX_VALUES = 512
#: Virtual fields computed from ``timestamp`` in the rule's ``timezone``: the hour (0-23), the
#: weekday (0 = Monday ... 6 = Sunday) and the minute of the day (0-1439).
TIME_FIELDS = frozenset({"time.hour", "time.weekday", "time.minute_of_day"})
MAX_VALUE_LENGTH = 1024

Path = tuple[str | int, ...]


@dataclass(frozen=True, slots=True)
class RuleError:
    """A problem found while validating a rule, located by its path in the rule document."""

    path: Path
    message: str


Predicate = Callable[[JsonScalar], bool]


@dataclass(frozen=True, slots=True)
class FieldMatcher:
    """Matches one event field against a set of expected values."""

    field: str
    predicates: tuple[Predicate, ...]
    require_all: bool
    urldecode: bool = False
    tz: tzinfo = UTC

    def matches(self, event: Event) -> bool:
        value = (
            time_field(event, self.field, self.tz)
            if self.field in TIME_FIELDS
            else get_field(event, self.field)
        )
        if self.urldecode and isinstance(value, str):
            value = url_decode(value)
        if self.require_all:
            return all(predicate(value) for predicate in self.predicates)
        return any(predicate(value) for predicate in self.predicates)


@dataclass(frozen=True, slots=True)
class Selection:
    """A named selection: any of several groups, each a conjunction of field matchers."""

    name: str
    groups: tuple[tuple[FieldMatcher, ...], ...]

    def matches(self, event: Event) -> bool:
        return any(all(m.matches(event) for m in group) for group in self.groups)


# ---------------------------------------------------------------- value semantics


def _text(value: JsonScalar, cased: bool) -> str | None:
    if value is None:
        return None
    if isinstance(value, bool):
        text = "true" if value else "false"
    elif isinstance(value, float) and value.is_integer():
        text = str(int(value))
    else:
        text = str(value)
    return text if cased else text.casefold()


def url_decode(text: str) -> str:
    """Percent-decode ``text`` (``+`` as a space) until it stops changing, at most 3 rounds."""
    for _ in range(URLDECODE_ROUNDS):
        decoded = unquote_plus(text)
        if decoded == text:
            break
        text = decoded
    return text


def _number(value: JsonScalar) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int | float):
        return float(value)
    try:
        number = float(value)
    except ValueError:
        return None
    return number if math.isfinite(number) else None


def wildcard_match(pattern: str, text: str) -> bool:
    """Match ``text`` against a glob with ``*`` and ``?`` in O(len(pattern) * len(text)) time.

    ``\\`` escapes a following ``*``, ``?`` or ``\\``; other backslashes are literal. Uses the
    classic two-pointer algorithm, never regular expressions, so hostile input cannot cause
    catastrophic backtracking.
    """
    tokens = _glob_tokens(pattern)
    t = p = 0
    star_p, star_t = -1, 0
    while t < len(text):
        if (
            p < len(tokens)
            and tokens[p] is not _STAR
            and (tokens[p] is _ANY_CHAR or tokens[p] == text[t])
        ):
            t += 1
            p += 1
        elif p < len(tokens) and tokens[p] is _STAR:
            star_p, star_t = p, t
            p += 1
        elif star_p >= 0:
            p = star_p + 1
            star_t += 1
            t = star_t
        else:
            return False
    while p < len(tokens) and tokens[p] is _STAR:
        p += 1
    return p == len(tokens)


class _Wildcard:
    """Marker token for an unescaped wildcard character."""

    def __init__(self, symbol: str) -> None:
        self.symbol = symbol

    def __repr__(self) -> str:
        return self.symbol


_STAR = _Wildcard("*")
#: Characters a backslash escapes; any other backslash is literal (as in Sigma).
_ESCAPABLE = frozenset("*?\\")
_ANY_CHAR = _Wildcard("?")


def _glob_tokens(pattern: str) -> list[str | _Wildcard]:
    tokens: list[str | _Wildcard] = []
    i = 0
    while i < len(pattern):
        char = pattern[i]
        if char == "\\" and i + 1 < len(pattern) and pattern[i + 1] in _ESCAPABLE:
            tokens.append(pattern[i + 1])
            i += 2
            continue
        tokens.append(_STAR if char == "*" else _ANY_CHAR if char == "?" else char)
        i += 1
    return tokens


_WILDCARD_RE = re.compile(r"(?<!\\)(?:\\\\)*[*?]")


def has_wildcards(value: str) -> bool:
    """Return whether ``value`` contains an unescaped ``*`` or ``?``."""
    return _WILDCARD_RE.search(value) is not None


def _unescape(value: str) -> str:
    return re.sub(r"\\([*?\\])", r"\1", value)


# ---------------------------------------------------------------- compilation


def _predicate(
    operator: str | None, expected: JsonScalar, cased: bool, path: Path, errors: list[RuleError]
) -> Predicate | None:
    if operator == "exists":
        if not isinstance(expected, bool):
            errors.append(RuleError(path, "'exists' needs true or false"))
            return None
        return lambda value: (value is not None) == expected
    if expected is None:
        if operator is not None:
            errors.append(RuleError(path, f"null cannot be used with '{operator}'"))
            return None
        return lambda value: value is None
    if isinstance(expected, str) and len(expected) > MAX_VALUE_LENGTH:
        errors.append(RuleError(path, f"value longer than {MAX_VALUE_LENGTH} characters"))
        return None
    if operator in {"gt", "gte", "lt", "lte"}:
        limit = _number(expected)
        if limit is None:
            errors.append(RuleError(path, f"'{operator}' needs a number"))
            return None
        compare = _COMPARISONS[operator]
        return lambda value: (n := _number(value)) is not None and compare(n, limit)
    if operator == "cidr":
        try:
            network = ipaddress.ip_network(str(expected), strict=False)
        except ValueError:
            errors.append(RuleError(path, f"invalid CIDR network {expected!r}"))
            return None
        return lambda value: _in_network(value, network)
    if operator == "re":
        if not isinstance(expected, str):
            errors.append(RuleError(path, "'re' needs a string pattern"))
            return None
        try:
            search = compile_regex(expected, cased=cased)
        except UnsafeRegexError as exc:
            errors.append(RuleError(path, str(exc)))
            return None
        return lambda value: (text := _text(value, cased=True)) is not None and search(text)
    needle = _text(expected, cased) or ""
    if operator == "contains":
        return lambda value: (text := _text(value, cased)) is not None and needle in text
    if operator == "startswith":
        return lambda value: (text := _text(value, cased)) is not None and text.startswith(needle)
    if operator == "endswith":
        return lambda value: (text := _text(value, cased)) is not None and text.endswith(needle)
    # Plain value: numeric equality, wildcard match or string equality.
    number = None if isinstance(expected, str) else _number(expected)
    if number is not None:
        return lambda value: _number(value) == number or _text(value, cased) == needle
    if isinstance(expected, str) and has_wildcards(expected):
        glob = expected if cased else expected.casefold()
        return lambda value: (
            (text := _text(value, cased)) is not None and wildcard_match(glob, text)
        )
    literal = _unescape(needle) if isinstance(expected, str) else needle
    return lambda value: _text(value, cased) == literal


_COMPARISONS: dict[str, Callable[[float, float], bool]] = {
    "gt": lambda a, b: a > b,
    "gte": lambda a, b: a >= b,
    "lt": lambda a, b: a < b,
    "lte": lambda a, b: a <= b,
}


def _in_network(value: JsonScalar, network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return ipaddress.ip_address(value) in network
    except ValueError:
        return False


def time_field(event: Event, field: str, tz: tzinfo) -> int:
    """Value of a :data:`TIME_FIELDS` field for ``event``, in timezone ``tz``."""
    local = event.timestamp.astimezone(tz)
    if field == "time.hour":
        return local.hour
    if field == "time.weekday":
        return local.weekday()
    return local.hour * 60 + local.minute


def compile_field(
    key: object, raw: object, path: Path, errors: list[RuleError], tz: tzinfo = UTC
) -> FieldMatcher | None:
    """Compile one ``field|modifiers: value(s)`` entry; append problems to ``errors``."""
    if not isinstance(key, str):
        errors.append(RuleError(path, "field names must be strings"))
        return None
    field, *modifiers = key.split("|")
    if not is_valid_path(field) and field not in TIME_FIELDS:
        errors.append(RuleError(path, f"unknown field {field!r}"))
        return None
    operators = [m for m in modifiers if m in OPERATORS]
    unknown = [m for m in modifiers if m not in OPERATORS and m not in FLAGS]
    if unknown:
        errors.append(RuleError(path, f"unknown modifier(s): {', '.join(unknown)}"))
        return None
    if len(operators) > 1 or len(set(modifiers)) != len(modifiers):
        errors.append(RuleError(path, "use at most one operator modifier and no duplicates"))
        return None
    operator = operators[0] if operators else None
    cased = "cased" in modifiers
    require_all = "all" in modifiers
    urldecode = "urldecode" in modifiers
    if urldecode and operator not in TEXT_OPERATORS:
        errors.append(RuleError(path, f"'urldecode' cannot be combined with '{operator}'"))
        return None
    values: Sequence[object] = raw if isinstance(raw, list) else [raw]
    if not values:
        errors.append(RuleError(path, "empty list of values"))
        return None
    if len(values) > MAX_VALUES:
        errors.append(RuleError(path, f"more than {MAX_VALUES} values"))
        return None
    if require_all and len(values) < 2:
        errors.append(RuleError(path, "'all' needs a list of at least two values"))
        return None
    predicates: list[Predicate] = []
    before = len(errors)
    for index, value in enumerate(values):
        item_path = (*path, index) if isinstance(raw, list) else path
        if not (value is None or isinstance(value, str | int | float | bool)):
            errors.append(RuleError(item_path, "values must be strings, numbers, booleans or null"))
            continue
        predicate = _predicate(operator, value, cased, item_path, errors)
        if predicate is not None:
            predicates.append(predicate)
    if len(errors) > before:
        return None
    return FieldMatcher(field, tuple(predicates), require_all, urldecode, tz)


def compile_selection(
    name: str, raw: object, path: Path, errors: list[RuleError], tz: tzinfo = UTC
) -> Selection | None:
    """Compile a selection (a mapping, or a list of mappings); append problems to ``errors``."""
    groups_raw: list[tuple[Path, object]]
    if isinstance(raw, Mapping):
        groups_raw = [(path, raw)]
    elif isinstance(raw, list) and raw:
        groups_raw = [((*path, i), item) for i, item in enumerate(raw)]
    else:
        errors.append(
            RuleError(path, "a selection must be a mapping or a non-empty list of mappings")
        )
        return None
    before = len(errors)
    groups: list[tuple[FieldMatcher, ...]] = []
    for group_path, group in groups_raw:
        if not isinstance(group, Mapping) or not group:
            errors.append(RuleError(group_path, "expected a non-empty mapping of field: value"))
            continue
        matchers = [
            compile_field(key, value, (*group_path, str(key)), errors, tz)
            for key, value in group.items()
        ]
        groups.append(tuple(m for m in matchers if m is not None))
    if len(errors) > before:
        return None
    return Selection(name, tuple(groups))
