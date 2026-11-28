# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
# Copyright (c) 2026 Utsha Basak
"""The common event schema ("ECS-lite") that every parser produces."""

from typing import Annotated, Self

from pydantic import BaseModel, Field, IPvAnyAddress, field_validator, model_validator

from prohori.schema.ids import event_id
from prohori.schema.types import (
    MAX_EXTRA_KEYS,
    MODEL_CONFIG,
    BoundedScalar,
    EventCategory,
    Outcome,
    RawText,
    Severity,
    ShortText,
    Text,
    UtcDatetime,
)

#: Dotted, lower-case action names such as ``auth.signin.failure``.
ACTION_PATTERN = r"^[a-z0-9_]+(\.[a-z0-9_]+)*$"
#: A fully qualified host name in lower case, without the trailing dot (at least two labels).
HOSTNAME_PATTERN = (
    r"^(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)


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
    #: The remote host's name when the log has a name instead of an address (sshd with
    #: ``UseDNS yes``). Attacker-influenced: whoever controls the address's reverse DNS picks it.
    host: Annotated[str, Field(pattern=HOSTNAME_PATTERN, max_length=253)] | None = None


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


#: SHA-256 as 64 lower-case hex digits.
SHA256_PATTERN = r"^[0-9a-f]{64}$"
#: A host name as :data:`HOSTNAME_PATTERN`, length-limited.
HostName = Annotated[str, Field(pattern=HOSTNAME_PATTERN, max_length=253)]


class ParentProcessInfo(BaseModel):
    """The process that started :class:`ProcessInfo` (`process.parent.*`)."""

    model_config = MODEL_CONFIG

    pid: Annotated[int, Field(ge=0)] | None = None
    name: ShortText | None = None
    executable: Text | None = None
    command_line: Text | None = None


class ProcessInfo(BaseModel):
    """The process that did something (`process.*`, since 1.2). Command lines are untrusted."""

    model_config = MODEL_CONFIG

    pid: Annotated[int, Field(ge=0)] | None = None
    name: ShortText | None = None
    executable: Text | None = None
    command_line: Text | None = None
    #: SHA-256 of the executable.
    hash: Annotated[str, Field(pattern=SHA256_PATTERN)] | None = None
    #: Who signed the executable, as the source reports it.
    signer: ShortText | None = None
    #: Windows integrity level: ``low``, ``medium``, ``high`` or ``system``.
    integrity_level: ShortText | None = None
    parent: ParentProcessInfo | None = None


class FileInfo(BaseModel):
    """A file that was created, deleted or loaded (`file.*`, since 1.2)."""

    model_config = MODEL_CONFIG

    path: Text | None = None
    name: ShortText | None = None
    #: Lower case, without the dot (``exe``).
    extension: ShortText | None = None
    size: Annotated[int, Field(ge=0)] | None = None
    #: Mark-of-the-web zone of a downloaded file (3 is the internet), when the source has it.
    zone: Annotated[int, Field(ge=0, le=4)] | None = None


class RegistryInfo(BaseModel):
    """A Windows registry change (`registry.*`, since 1.2)."""

    model_config = MODEL_CONFIG

    #: The full key or value path, as the source writes it (``HKLM`` or ``\REGISTRY\MACHINE``).
    path: Text | None = None
    #: The value's name (the last part of ``path`` for a value).
    value: ShortText | None = None
    #: The data written, as the source logs it.
    data: Text | None = None


class DestinationInfo(BaseModel):
    """Where a connection went (`destination.*`, since 1.2)."""

    model_config = MODEL_CONFIG

    ip: IPvAnyAddress | None = None
    port: Annotated[int, Field(ge=0, le=65535)] | None = None
    #: The destination's name (TLS SNI, HTTP host, a resolved host name); attacker-influenced.
    domain: HostName | None = None


class DnsInfo(BaseModel):
    """A name lookup (`dns.*`, since 1.2)."""

    model_config = MODEL_CONFIG

    #: The name asked for, as logged (not normalised: lookups for odd names are the point).
    question: ShortText | None = None


class CloudInfo(BaseModel):
    """Where a cloud API call was made (`cloud.*`, since 1.2)."""

    model_config = MODEL_CONFIG

    #: The cloud provider, in lower case (``aws``).
    provider: ShortText | None = None
    #: The account the call was made in (AWS: the 12-digit account id).
    account_id: ShortText | None = None
    region: ShortText | None = None
    #: The service whose API was called, as the provider names it (``iam.amazonaws.com``).
    service: ShortText | None = None


#: Event fields added in 1.2, left out of the JSON when unset so older events are unchanged.
OPTIONAL_GROUPS = ("process", "file", "registry", "destination", "dns", "cloud")


def _unset(value: object) -> bool:
    return value is None


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
    # Groups added in 1.2, left out of the JSON when unset so older events are unchanged.
    process: Annotated[ProcessInfo | None, Field(exclude_if=_unset)] = None
    file: Annotated[FileInfo | None, Field(exclude_if=_unset)] = None
    registry: Annotated[RegistryInfo | None, Field(exclude_if=_unset)] = None
    destination: Annotated[DestinationInfo | None, Field(exclude_if=_unset)] = None
    dns: Annotated[DnsInfo | None, Field(exclude_if=_unset)] = None
    cloud: Annotated[CloudInfo | None, Field(exclude_if=_unset)] = None
    raw: RawText
    extra: Annotated[dict[ShortText, BoundedScalar], Field(max_length=MAX_EXTRA_KEYS)] = {}

    @model_validator(mode="after")
    def _fill_id(self) -> Self:
        if not self.id:
            # The model is frozen; this is the one place the id is set after validation.
            object.__setattr__(self, "id", event_id(self.log_source, self.timestamp, self.raw))
        return self
