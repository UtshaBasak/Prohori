"""Rule test harness: run each rule against its positive and negative fixtures.

Every rule ``<name>.yml`` must have a fixture file ``<name>.tests.yml`` next to it::

    rule: PRH-AUTH-001                  # must match the rule's id
    start: 2026-10-24T13:50:00Z         # optional; first event time (default 2026-01-01T00:00:00Z)
    defaults:                           # merged into every event (dotted schema fields)
      log_source: app-security
      event.category: authentication
    cases:
      - name: ten failures in five minutes alert
        expect: {alerts: 1, entities: [{source.ip: 203.0.113.7}]}
        events:
          - {event.action: auth.signin.failure, source.ip: 203.0.113.7, repeat: 10, every: 20s}
      - name: real log lines through a parser
        expect: {alerts: 0}
        log:
          parser: auth_log
          options: {year: 2026}
          lines:
            - "Oct 24 13:50:02 web01 sshd[1]: Invalid user admin from 203.0.113.7 port 1"

Event specs place events on a timeline: ``at`` sets an absolute time, otherwise ``after``
(default ``1s``) advances from the previous event; ``repeat`` (default 1) emits copies ``every``
(default ``1s``) apart. ``auth_log`` cases without a ``year`` option use the year of ``start``.
Each fixture needs at least one positive case (``alerts`` >= 1) and one negative case
(``alerts: 0``).
"""

import json
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any, Self

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, ValidationError, model_validator

from prohori.parsers import ParseStats, get_parser, iter_text_lines
from prohori.rules.compiler import CompiledRule
from prohori.rules.engine import RuleEngine
from prohori.rules.loader import (
    TEST_SUFFIXES,
    RuleLoadError,
    format_path,
    line_for,
    load_rules,
    read_yaml_file,
)
from prohori.schema import Alert, Event, event_id, is_valid_path

MAX_REPEAT = 10_000
MAX_EVENTS_PER_CASE = 50_000
DEFAULT_START = datetime(2026, 1, 1, tzinfo=UTC)
_TIMING_KEYS = frozenset({"at", "after", "repeat", "every"})
_OFFSET_RE = re.compile(r"^(?P<amount>\d{1,6})(?P<unit>[smhd])$")
_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}
_CONFIG = ConfigDict(extra="forbid", frozen=True)


def parse_offset(value: object) -> timedelta:
    """Parse ``0s``, ``20s``, ``5m``, ``2h`` or ``1d`` (zero allowed, unlike rule windows)."""
    match = _OFFSET_RE.match(str(value).strip())
    if match is None:
        msg = f"invalid duration {value!r}; use a number followed by s, m, h or d"
        raise ValueError(msg)
    return timedelta(seconds=int(match["amount"]) * _UNITS[match["unit"]])


class LogSpec(BaseModel):
    """Raw log lines run through a named parser."""

    model_config = _CONFIG

    parser: Annotated[str, Field(min_length=1, max_length=64)]
    options: dict[str, Any] = {}
    lines: Annotated[list[str], Field(min_length=1, max_length=10_000)]


class Expectation(BaseModel):
    """What a case must produce."""

    model_config = _CONFIG

    alerts: Annotated[int, Field(ge=0, le=MAX_EVENTS_PER_CASE)]
    entities: list[dict[str, str]] = []


class Case(BaseModel):
    """One scenario: events (or log lines) and the expected alerts."""

    model_config = _CONFIG

    name: Annotated[str, Field(min_length=1, max_length=200)]
    expect: Expectation
    events: Annotated[list[dict[str, Any]], Field(min_length=1)] | None = None
    log: LogSpec | None = None

    @model_validator(mode="after")
    def _one_source(self) -> Self:
        if (self.events is None) == (self.log is None):
            msg = "give exactly one of 'events' or 'log'"
            raise ValueError(msg)
        return self


class RuleTestFile(BaseModel):
    """A validated fixture file."""

    model_config = _CONFIG

    rule: Annotated[str, Field(min_length=1, max_length=64)]
    start: AwareDatetime = DEFAULT_START
    defaults: dict[str, Any] = {}
    cases: Annotated[list[Case], Field(min_length=1, max_length=100)]


@dataclass
class CaseResult:
    """Outcome of one case."""

    name: str
    passed: bool
    alerts: int
    message: str = ""


@dataclass
class RuleTestReport:
    """Outcome of testing one rule file."""

    rule_file: Path
    rule_id: str | None
    test_file: Path | None
    errors: list[str] = field(default_factory=list)
    cases: list[CaseResult] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not self.errors and bool(self.cases) and all(c.passed for c in self.cases)


def fixture_file_for(rule_file: Path) -> Path | None:
    """Return the fixture file for ``rule_file`` if one exists."""
    stem = rule_file.name.rsplit(".", 1)[0]
    for suffix in TEST_SUFFIXES:
        candidate = rule_file.with_name(stem + suffix)
        if candidate.is_file():
            return candidate
    return None


def _nested(flat: dict[str, Any], where: str) -> dict[str, Any]:
    document: dict[str, Any] = {"event": {}, "source": {}, "user": {}, "http": {}, "extra": {}}
    for key, value in flat.items():
        if key in {"log_source", "raw", "timestamp", "id"}:
            if key in {"timestamp", "id"}:
                msg = f"{where}: set times with 'at'/'after', not '{key}'"
                raise ValueError(msg)
            document[key] = value
            continue
        if not is_valid_path(key):
            msg = f"{where}: unknown field {key!r}"
            raise ValueError(msg)
        head, _, tail = key.partition(".")
        if tail:
            document[head][tail] = value
        else:
            document[head] = value
    return document


def build_events(spec: RuleTestFile, case: Case, case_index: int) -> Iterator[Event]:
    """Expand a case's event specs into events on a timeline."""
    cursor = spec.start
    count = 0
    first = True
    for index, raw_spec in enumerate(case.events or []):
        where = f"case {case.name!r}, event {index + 1}"
        if "at" in raw_spec:
            try:
                cursor = datetime.fromisoformat(str(raw_spec["at"]))
            except ValueError:
                msg = f"{where}: invalid 'at' timestamp {raw_spec['at']!r}"
                raise ValueError(msg) from None
            if cursor.tzinfo is None:
                msg = f"{where}: 'at' needs a timezone, for example 2026-10-24T13:50:00Z"
                raise ValueError(msg)
        elif not first:
            cursor += parse_offset(raw_spec.get("after", "1s"))
        first = False
        repeat = raw_spec.get("repeat", 1)
        if not isinstance(repeat, int) or isinstance(repeat, bool) or not 1 <= repeat <= MAX_REPEAT:
            msg = f"{where}: 'repeat' must be an integer from 1 to {MAX_REPEAT}"
            raise ValueError(msg)
        every = parse_offset(raw_spec.get("every", "1s"))
        fields = {**spec.defaults, **{k: v for k, v in raw_spec.items() if k not in _TIMING_KEYS}}
        document = _nested(fields, where)
        document.setdefault("log_source", "test")
        for n in range(repeat):
            if n:
                cursor += every
            count += 1
            if count > MAX_EVENTS_PER_CASE:
                msg = f"case {case.name!r}: more than {MAX_EVENTS_PER_CASE} events"
                raise ValueError(msg)
            raw = document.get("raw") or json.dumps(fields, sort_keys=True, default=str)
            yield Event.model_validate(
                {
                    **document,
                    "id": event_id(
                        str(document["log_source"]), cursor, raw, f"{case_index}:{count}"
                    ),
                    "timestamp": cursor,
                    "raw": raw,
                }
            )


def _log_events(case: Case, case_index: int, start: datetime) -> list[Event]:
    if case.log is None:  # pragma: no cover - guarded by the caller
        return []
    options = dict(case.log.options)
    if case.log.parser == "auth_log" and "year" not in options and "reference_time" not in options:
        # Syslog lines carry no year; never let a fixture depend on today's date.
        options["year"] = start.year
    try:
        parser = get_parser(case.log.parser, **options)
    except (KeyError, TypeError, ValueError) as exc:
        msg = f"case {case.name!r}: cannot create parser: {exc}"
        raise ValueError(msg) from None
    stats = ParseStats()
    events = list(
        parser.parse(iter_text_lines(case.log.lines), source=f"case{case_index}", stats=stats)
    )
    if stats.errors:
        first = stats.error_examples[0]
        msg = (
            f"case {case.name!r}: {stats.errors} fixture line(s) failed to parse "
            f"(line {first.line}: {first.reason})"
        )
        raise ValueError(msg)
    return events


def _check(case: Case, alerts: list[Alert]) -> str:
    problems: list[str] = []
    if len(alerts) != case.expect.alerts:
        problems.append(f"expected {case.expect.alerts} alert(s), got {len(alerts)}")
    for wanted in case.expect.entities:
        if not any(wanted.items() <= alert.entities.items() for alert in alerts):
            problems.append(f"no alert with entities {wanted}")
    return "; ".join(problems)


def run_cases(rule: CompiledRule, spec: RuleTestFile) -> list[CaseResult]:
    """Run every case of ``spec`` against ``rule`` with a fresh engine per case."""
    results: list[CaseResult] = []
    for index, case in enumerate(spec.cases):
        try:
            events = (
                _log_events(case, index, spec.start)
                if case.log is not None
                else list(build_events(spec, case, index))
            )
            engine = RuleEngine([rule])
            alerts = list(engine.run(events))
        except ValidationError as exc:
            first = exc.errors()[0]
            where = ".".join(str(part) for part in first["loc"]) or "event"
            message = f"case {case.name!r}: invalid {where}: {first['msg']}"
            results.append(CaseResult(case.name, False, 0, message))
            continue
        except ValueError as exc:
            results.append(CaseResult(case.name, False, 0, str(exc).splitlines()[0]))
            continue
        message = _check(case, alerts)
        dropped = engine.stats.late_events + engine.stats.future_events
        if dropped:
            message = "; ".join(filter(None, [message, f"{dropped} event(s) dropped as late"]))
        results.append(CaseResult(case.name, not message, len(alerts), message))
    return results


def _load_spec(test_file: Path) -> tuple[RuleTestFile | None, list[str]]:
    try:
        document, lines = read_yaml_file(test_file)
    except RuleLoadError as exc:
        location = f"{test_file.name}:{exc.line}" if exc.line else test_file.name
        return None, [f"{location}: {exc}"]
    try:
        return RuleTestFile.model_validate(document), []
    except ValidationError as exc:
        errors = []
        for error in exc.errors():
            path = tuple(error["loc"])
            line = line_for(path, lines)
            location = f"{test_file.name}:{line}" if line else test_file.name
            errors.append(f"{location}: {format_path(path)}: {error['msg']}")
        return None, errors


def run_rule_tests(paths: list[Path]) -> list[RuleTestReport]:
    """Test every rule under ``paths`` against its fixture file."""
    reports: list[RuleTestReport] = []
    for loaded in load_rules(paths):
        rule = loaded.rule
        report = RuleTestReport(
            loaded.file, rule.id if rule else None, fixture_file_for(loaded.file)
        )
        reports.append(report)
        if not loaded.ok or rule is None:
            report.errors.extend(e.format(loaded.file.name) for e in loaded.errors)
            continue
        if report.test_file is None:
            report.errors.append(f"no test fixtures: create {loaded.file.stem}.tests.yml")
            continue
        spec, errors = _load_spec(report.test_file)
        if spec is None:
            report.errors.extend(errors)
            continue
        if spec.rule != rule.id:
            report.errors.append(f"fixture is for rule {spec.rule!r}, not {rule.id!r}")
            continue
        if not any(c.expect.alerts > 0 for c in spec.cases):
            report.errors.append("fixtures need at least one positive case (alerts >= 1)")
        if not any(c.expect.alerts == 0 for c in spec.cases):
            report.errors.append("fixtures need at least one negative case (alerts: 0)")
        report.cases = run_cases(rule, spec)
    return reports
