"""Incidents: groups of related alerts with scoring, enrichment and recommendations."""

import math
from enum import StrEnum
from typing import Annotated, Self

from pydantic import BaseModel, Field, model_validator

from prohori.schema.alert import Alert, AttackTag
from prohori.schema.types import (
    MODEL_CONFIG,
    BoundedScalar,
    Severity,
    ShortText,
    Text,
    UtcDatetime,
)


class IncidentStatus(StrEnum):
    """Lifecycle state of an incident."""

    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class Confidence(StrEnum):
    """How much the evidence supports the incident's conclusion."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class IndicatorType(StrEnum):
    """Kinds of observable recorded on an incident."""

    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"
    USER = "user"
    USER_AGENT = "user_agent"


class EnrichmentResult(BaseModel):
    """One provider's answer about an indicator."""

    model_config = MODEL_CONFIG

    provider: Annotated[str, Field(min_length=1, max_length=64)]
    retrieved_at: UtcDatetime
    data: dict[ShortText, BoundedScalar] = {}
    note: Text | None = None


class Indicator(BaseModel):
    """An observable (IP address, domain, hash, ...) with any enrichment attached."""

    model_config = MODEL_CONFIG

    type: IndicatorType
    value: Text
    enrichment: tuple[EnrichmentResult, ...] = ()


class TimelineEntry(BaseModel):
    """One line of the incident timeline, pointing at the event or alert it came from."""

    model_config = MODEL_CONFIG

    timestamp: UtcDatetime
    description: Text
    event_id: ShortText | None = None
    alert_id: ShortText | None = None


class ScoreComponent(BaseModel):
    """One contribution to the incident score, so the total can be explained."""

    model_config = MODEL_CONFIG

    reason: Text
    points: Annotated[float, Field(allow_inf_nan=False)]


class Incident(BaseModel):
    """Related alerts grouped by shared entities within a time gap.

    When ``score_breakdown`` is given, its points must add up to ``score``.
    """

    model_config = MODEL_CONFIG

    id: Annotated[str, Field(pattern=r"^INC-[A-Za-z0-9-]+$", max_length=64)]
    title: Text
    status: IncidentStatus = IncidentStatus.OPEN
    severity: Severity
    score: Annotated[float, Field(ge=0.0, allow_inf_nan=False)]
    score_breakdown: tuple[ScoreComponent, ...] = ()
    first_seen: UtcDatetime
    last_seen: UtcDatetime
    entities: dict[ShortText, tuple[ShortText, ...]] = {}
    alerts: Annotated[tuple[Alert, ...], Field(min_length=1)]
    timeline: tuple[TimelineEntry, ...] = ()
    indicators: tuple[Indicator, ...] = ()
    attack: tuple[AttackTag, ...] = ()
    attack_version: Annotated[str, Field(max_length=16)] | None = None
    recommended_actions: tuple[Text, ...] = ()
    confidence: Confidence = Confidence.MEDIUM
    limitations: tuple[Text, ...] = ()

    @model_validator(mode="after")
    def _check(self) -> Self:
        if self.last_seen < self.first_seen:
            msg = "last_seen must not be earlier than first_seen"
            raise ValueError(msg)
        if self.score_breakdown:
            total = math.fsum(c.points for c in self.score_breakdown)
            if not math.isclose(total, self.score, rel_tol=1e-9, abs_tol=1e-6):
                msg = f"score_breakdown sums to {total}, but score is {self.score}"
                raise ValueError(msg)
        return self
