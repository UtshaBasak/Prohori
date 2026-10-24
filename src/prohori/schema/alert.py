"""Alerts raised by detection rules and machine-learning models."""

from enum import StrEnum
from typing import Annotated, Self

from pydantic import BaseModel, Field, model_validator

from prohori.schema.ids import alert_id
from prohori.schema.types import MODEL_CONFIG, Severity, ShortText, Text, UtcDatetime

#: ATT&CK tags in rule style: ``attack.t1110``, ``attack.t1110.003``, ``attack.credential_access``.
ATTACK_TAG_PATTERN = r"^attack\.(t\d{4}(\.\d{3})?|[a-z][a-z_]*)$"

AttackTag = Annotated[str, Field(pattern=ATTACK_TAG_PATTERN, max_length=64)]


class DetectorKind(StrEnum):
    """What produced an alert."""

    RULE = "rule"
    MODEL = "model"


class Alert(BaseModel):
    """A detection over one or more events.

    ``entities`` maps the grouping fields to their values, for example
    ``{"source.ip": "203.0.113.7"}``. ``id`` is derived from the detector and matched events
    when not given.
    """

    model_config = MODEL_CONFIG

    id: Annotated[str, Field(max_length=64)] = ""
    detector_id: Annotated[str, Field(min_length=1, max_length=64)]
    detector_kind: DetectorKind = DetectorKind.RULE
    title: Text
    severity: Severity
    score: Annotated[float, Field(ge=0.0, le=100.0, allow_inf_nan=False)] = 0.0
    event_ids: Annotated[tuple[str, ...], Field(min_length=1)]
    entities: dict[ShortText, ShortText] = {}
    first_seen: UtcDatetime
    last_seen: UtcDatetime
    attack: tuple[AttackTag, ...] = ()
    explanation: Text = ""

    @model_validator(mode="after")
    def _check(self) -> Self:
        if self.last_seen < self.first_seen:
            msg = "last_seen must not be earlier than first_seen"
            raise ValueError(msg)
        if not self.id:
            # The model is frozen; this is the one place the id is set after validation.
            object.__setattr__(self, "id", alert_id(self.detector_id, self.event_ids))
        return self
