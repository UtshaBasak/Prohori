"""The common event schema ("ECS-lite") that every parser produces."""

from typing import Annotated, Self

from pydantic import BaseModel, Field, IPvAnyAddress, field_validator, model_validator

from prohori.schema.ids import event_id
from prohori.schema.types import (
    MAX_EXTRA_KEYS,
    MODEL_CONFIG,
    EventCategory,
    JsonScalar,
    Outcome,
    RawText,
    Severity,
    ShortText,
    Text,
    UtcDatetime,
)

#: Dotted, lower-case action names such as ``auth.signin.failure``.
ACTION_PATTERN = r"^[a-z0-9_]+(\.[a-z0-9_]+)*$"


class EventInfo(BaseModel):
    """What happened (`event.*`)."""

    model_config = MODEL_CONFIG

    action: Annotated[str, Field(pattern=ACTION_PATTERN, max_length=128)]
    category: EventCategory
    outcome: Outcome = Outcome.UNKNOWN
    severity: Severity | None = None
    reason: ShortText | None = None


class SourceInfo(BaseModel):
    """Where the activity came from (`source.*`)."""

    model_config = MODEL_CONFIG

    ip: IPvAnyAddress | None = None


class UserInfo(BaseModel):
    """Who the activity concerns (`user.*`). Usernames are attacker-controlled."""

    model_config = MODEL_CONFIG

    name: ShortText | None = None
    id: ShortText | None = None
    email_hash: ShortText | None = None


class HttpInfo(BaseModel):
    """HTTP request details (`http.*`). Paths are stored without the query string by default."""

    model_config = MODEL_CONFIG

    method: Annotated[str, Field(max_length=16)] | None = None
    path: Text | None = None
    status: Annotated[int, Field(ge=100, le=599)] | None = None
    bytes: Annotated[int, Field(ge=0)] | None = None

    @field_validator("method")
    @classmethod
    def _upper_method(cls, value: str | None) -> str | None:
        return value.upper() if value is not None else None


class Event(BaseModel):
    """One normalised log event. All timestamps are UTC.

    ``id`` is derived from the content when not given (see :func:`prohori.schema.ids.event_id`).
    """

    model_config = MODEL_CONFIG

    id: Annotated[str, Field(max_length=64)] = ""
    timestamp: UtcDatetime
    log_source: Annotated[str, Field(min_length=1, max_length=64)]
    event: EventInfo
    source: SourceInfo = SourceInfo()
    user: UserInfo = UserInfo()
    http: HttpInfo = HttpInfo()
    user_agent: Text | None = None
    client: ShortText | None = None
    host: ShortText | None = None
    request_id: ShortText | None = None
    raw: RawText
    extra: Annotated[dict[ShortText, JsonScalar], Field(max_length=MAX_EXTRA_KEYS)] = {}

    @model_validator(mode="after")
    def _fill_id(self) -> Self:
        if not self.id:
            # The model is frozen; this is the one place the id is set after validation.
            object.__setattr__(self, "id", event_id(self.log_source, self.timestamp, self.raw))
        return self
