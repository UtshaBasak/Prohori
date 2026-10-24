"""Shared enums and constrained types for the common schema.

Log content is attacker-controlled, so free-text fields are truncated to fixed maximum lengths
instead of being rejected: a hostile user agent must not be able to make an event disappear.
"""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated

from pydantic import AfterValidator, AwareDatetime, BeforeValidator, ConfigDict

# Maximum stored lengths (characters) for untrusted text fields.
MAX_RAW_LENGTH = 8192
MAX_TEXT_LENGTH = 1024
MAX_SHORT_TEXT_LENGTH = 256
MAX_EXTRA_KEYS = 64

#: Model configuration shared by every schema model: immutable, strict about unknown fields.
MODEL_CONFIG = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=False)


class EventCategory(StrEnum):
    """High-level category of an event (`event.category`)."""

    AUTHENTICATION = "authentication"
    WEB = "web"
    SESSION = "session"
    ACCOUNT = "account"
    AUTHORIZATION = "authorization"
    ABUSE = "abuse"
    ADMIN = "admin"
    NETWORK = "network"


class Outcome(StrEnum):
    """Result of the action an event describes (`event.outcome`)."""

    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"


class Severity(StrEnum):
    """Ordered severity scale shared by events, alerts and incidents.

    Source events use ``low``, ``medium`` and ``high``; ``critical`` is reserved for alerts and
    incidents produced by Prohori.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """Numeric rank for ordering (``low`` = 1 ... ``critical`` = 4)."""
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}


def _to_utc(value: datetime) -> datetime:
    return value.astimezone(UTC)


def _truncator(limit: int) -> BeforeValidator:
    def truncate(value: object) -> object:
        if isinstance(value, str) and len(value) > limit:
            return value[:limit]
        return value

    return BeforeValidator(truncate)


#: Timezone-aware datetime normalised to UTC. Naive datetimes are rejected: parsers must decide
#: the timezone explicitly rather than have the schema guess.
UtcDatetime = Annotated[AwareDatetime, AfterValidator(_to_utc)]

#: Untrusted free text (user agents, paths, descriptions).
Text = Annotated[str, _truncator(MAX_TEXT_LENGTH)]

#: Untrusted short text (usernames, hosts, identifiers).
ShortText = Annotated[str, _truncator(MAX_SHORT_TEXT_LENGTH)]

#: The original log line, truncated at a safe maximum length.
RawText = Annotated[str, _truncator(MAX_RAW_LENGTH)]

#: Values allowed in free-form ``extra`` and enrichment mappings.
JsonScalar = str | int | float | bool | None
