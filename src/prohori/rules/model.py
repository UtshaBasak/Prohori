"""Pydantic models for the rule document (everything except selection contents).

Selections and the condition are compiled by :mod:`prohori.rules.compiler`, which reports errors
with their exact location in the document.
"""

import re
from datetime import timedelta
from enum import StrEnum
from typing import Annotated, Any, Self
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from prohori.schema import ATTACK_TAG_PATTERN, EventCategory, Severity, is_valid_path

RULE_ID_PATTERN = r"^[A-Z][A-Z0-9]*(-[A-Z0-9]+)+$"
TAG_PATTERN = r"^[a-z0-9][a-z0-9_.-]*$"
MIN_WINDOW = timedelta(seconds=1)
MAX_WINDOW = timedelta(days=7)

_DURATION_RE = re.compile(r"^(?P<amount>\d{1,6})(?P<unit>[smhd])$")
_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}

_CONFIG = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


def parse_duration(value: object) -> timedelta:
    """Parse ``30s``, ``5m``, ``2h`` or ``1d`` into a ``timedelta`` between 1 second and 7 days."""
    if not isinstance(value, str):
        msg = "duration must be a string such as '5m'"
        raise ValueError(msg)
    match = _DURATION_RE.match(value.strip())
    if match is None:
        msg = f"invalid duration {value!r}; use a number followed by s, m, h or d"
        raise ValueError(msg)
    duration = timedelta(seconds=int(match["amount"]) * _UNITS[match["unit"]])
    if not MIN_WINDOW <= duration <= MAX_WINDOW:
        msg = "duration must be between 1s and 7d"
        raise ValueError(msg)
    return duration


def _field_path(value: str) -> str:
    if not is_valid_path(value):
        msg = f"unknown field {value!r}"
        raise ValueError(msg)
    return value


def _tag(value: str) -> str:
    if value.startswith("attack.") and not re.match(ATTACK_TAG_PATTERN, value):
        msg = f"invalid ATT&CK tag {value!r}; use attack.tNNNN, attack.tNNNN.NNN or attack.tactic"
        raise ValueError(msg)
    return value


def _runbook_path(value: str) -> str:
    parts = value.replace("\\", "/").split("/")
    if (
        value.startswith(("/", "\\"))
        or ":" in value
        or ".." in parts
        or not value.endswith(".md")
        or not re.fullmatch(r"[\w./-]+", value)
    ):
        msg = "response must be a relative path to a Markdown runbook, such as runbooks/x.md"
        raise ValueError(msg)
    return value


def _timezone(value: str) -> str:
    try:
        ZoneInfo(value)
    except (ZoneInfoNotFoundError, ValueError):
        msg = f"unknown timezone {value!r}; use an IANA name such as UTC or Asia/Dhaka"
        raise ValueError(msg) from None
    return value


FieldPath = Annotated[str, AfterValidator(_field_path)]
Duration = Annotated[timedelta, Field(json_schema_extra={"format": "duration"})]
Tag = Annotated[str, Field(pattern=TAG_PATTERN, max_length=64), AfterValidator(_tag)]
RunbookPath = Annotated[str, Field(max_length=200), AfterValidator(_runbook_path)]
SelectionName = Annotated[str, Field(pattern=r"^[A-Za-z_][A-Za-z0-9_]*$", max_length=64)]


class RuleStatus(StrEnum):
    """Maturity of a rule."""

    STABLE = "stable"
    TEST = "test"
    EXPERIMENTAL = "experimental"
    DEPRECATED = "deprecated"


class WindowMode(StrEnum):
    """How aggregation windows advance."""

    SLIDING = "sliding"
    TUMBLING = "tumbling"


class LogSource(BaseModel):
    """Optional pre-filter on the event source; every given key must match."""

    model_config = _CONFIG

    category: EventCategory | None = None
    log_source: Annotated[str, Field(min_length=1, max_length=64)] | None = None


class DistinctThreshold(BaseModel):
    """Alert when a field takes at least ``gte`` distinct values in one group and window."""

    model_config = _CONFIG

    field: FieldPath
    gte: Annotated[int, Field(ge=2, le=100_000)]


class RatioThreshold(BaseModel):
    """Alert when the share of events matching ``selection`` reaches ``gte``."""

    model_config = _CONFIG

    selection: SelectionName
    gte: Annotated[float, Field(gt=0.0, le=1.0)]
    min_count: Annotated[int, Field(ge=1, le=100_000)] = 10


class AggregateSpec(BaseModel):
    """Threshold over the events that pass the condition, per group and time window.

    Evaluated by the stateful engine; exactly one threshold must be given.
    """

    model_config = _CONFIG

    group_by: Annotated[list[FieldPath], Field(min_length=1, max_length=5)]
    window: Duration
    mode: WindowMode = WindowMode.SLIDING
    count_gte: Annotated[int, Field(ge=1, le=100_000)] | None = None
    distinct: DistinctThreshold | None = None
    ratio: RatioThreshold | None = None

    @field_validator("window", mode="before")
    @classmethod
    def _window(cls, value: object) -> timedelta:
        return parse_duration(value)

    @model_validator(mode="after")
    def _one_threshold(self) -> Self:
        given = [n for n in ("count_gte", "distinct", "ratio") if getattr(self, n) is not None]
        if len(given) != 1:
            msg = "give exactly one of count_gte, distinct or ratio"
            raise ValueError(msg)
        return self


class SequenceStep(BaseModel):
    """One step of a sequence: ``count_gte`` events matching ``selection``."""

    model_config = _CONFIG

    selection: SelectionName
    count_gte: Annotated[int, Field(ge=1, le=10_000)] = 1


class SequenceSpec(BaseModel):
    """Ordered steps for the same entity (``by``) within a time limit."""

    model_config = _CONFIG

    by: Annotated[list[FieldPath], Field(min_length=1, max_length=5)]
    within: Duration
    steps: Annotated[list[SequenceStep], Field(min_length=2, max_length=5)]

    @field_validator("within", mode="before")
    @classmethod
    def _within(cls, value: object) -> timedelta:
        return parse_duration(value)


class RuleMeta(BaseModel):
    """Rule metadata. ``detection`` is kept raw here and compiled separately."""

    model_config = _CONFIG

    id: Annotated[str, Field(pattern=RULE_ID_PATTERN, max_length=64)]
    title: Annotated[str, Field(min_length=3, max_length=200)]
    status: RuleStatus
    severity: Severity
    description: Annotated[str, Field(max_length=4_000)] = ""
    author: Annotated[str, Field(max_length=200)] | None = None
    tags: Annotated[list[Tag], Field(max_length=32)] = []
    logsource: LogSource = LogSource()
    detection: dict[str, Any]
    falsepositives: Annotated[
        list[Annotated[str, Field(max_length=500)]], Field(max_length=32)
    ] = []
    response: RunbookPath | None = None
    #: IANA timezone for the ``time.*`` fields (``time.hour`` and so on).
    timezone: Annotated[str, Field(max_length=64), AfterValidator(_timezone)] = "UTC"
    references: Annotated[
        list[Annotated[str, Field(pattern=r"^https?://\S+$", max_length=500)]],
        Field(max_length=32),
    ] = []

    @property
    def attack_tags(self) -> tuple[str, ...]:
        """The ATT&CK tags among ``tags``."""
        return tuple(tag for tag in self.tags if tag.startswith("attack."))
