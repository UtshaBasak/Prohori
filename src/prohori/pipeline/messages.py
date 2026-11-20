# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
# Copyright (c) 2026 Utsha Basak
"""Topics, message payloads and keys.

Every message is a JSON object with a key. ``events``, ``alerts`` and ``incidents`` carry the
schema models unchanged (:class:`~prohori.schema.Event`, :class:`~prohori.schema.Alert`,
:class:`~prohori.schema.Incident`); ``raw-logs`` and ``dead-letter`` have their own payloads,
defined here. Payloads carry a schema version ``v`` so a later change can be told apart.

Keys: a raw line is keyed by its source name, so the lines of one file stay in order on one
partition; events, alerts and incidents are keyed by their id. The rule engine needs the events
in time order, so the ``events`` topic has one partition.

**Control markers** (:class:`Control`) record a stateful stage's wall-clock decisions in the
stream: the detector writes one into ``events`` before it releases its reorder buffer, and the
incident stage writes one into ``alerts`` before it closes every open incident. The stage acts on
its marker only when it reads it back, live and on a rebuild alike, so both see the decision at
the same position. Every other reader skips markers (:func:`is_control`).
"""

import hashlib
import uuid
from collections.abc import Mapping
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, Field

from prohori.parsers import MAX_LINE_LENGTH
from prohori.schema.types import MODEL_CONFIG, ShortText, UtcDatetime

#: Version of the ``raw-logs``, ``dead-letter`` and control payloads.
SCHEMA_VERSION: Literal[1] = 1

#: Longest payload kept in a dead letter, in characters.
MAX_DEAD_LETTER_PAYLOAD = 4096


class Topic(StrEnum):
    """The pipeline's topics, in processing order."""

    RAW_LOGS = "raw-logs"
    EVENTS = "events"
    ALERTS = "alerts"
    INCIDENTS = "incidents"
    DEAD_LETTER = "dead-letter"


class RawLog(BaseModel):
    """One line read from a log file, before parsing.

    ``line`` numbers the lines of the file from 1. It is part of the event id, so a line that is
    read again (a replay, or a restart before a checkpoint) gets the same id and is written once.
    ``read_at`` is when the producer read the file (its modification time for a replay); the
    ``auth_log`` parser uses it to infer the year of timestamps that have none.
    """

    model_config = MODEL_CONFIG

    v: Literal[1] = SCHEMA_VERSION
    source: ShortText
    line: Annotated[int, Field(ge=1)]
    text: Annotated[str, Field(max_length=MAX_LINE_LENGTH)]
    parser: Annotated[str, Field(min_length=1, max_length=64)]
    read_at: UtcDatetime
    too_long: bool = False
    decode_error: bool = False


class DeadLetter(BaseModel):
    """A message a stage could not use, with the reason. Its id is a hash of its content."""

    model_config = MODEL_CONFIG

    v: Literal[1] = SCHEMA_VERSION
    id: Annotated[str, Field(pattern=r"^dlq-[0-9a-f]{24}$")]
    stage: Annotated[str, Field(max_length=32)]
    topic: Annotated[str, Field(max_length=32)]
    key: ShortText | None = None
    reason: Annotated[str, Field(max_length=200)]
    payload: Annotated[str, Field(max_length=MAX_DEAD_LETTER_PAYLOAD)]


def dead_letter(stage: str, topic: str, key: str | None, reason: str, payload: str) -> DeadLetter:
    """Build a dead letter, truncating the reason and payload to their limits."""
    payload = payload[:MAX_DEAD_LETTER_PAYLOAD]
    reason = reason[:200]
    digest = hashlib.sha256("\x1f".join((stage, topic, key or "", payload)).encode()).hexdigest()
    return DeadLetter(
        id=f"dlq-{digest[:24]}",
        stage=stage,
        topic=topic,
        key=key[:256] if key is not None else None,
        reason=reason,
        payload=payload,
    )


class Control(BaseModel):
    """A stateful stage's decision, recorded at its position in the stage's own input topic.

    ``action`` is ``flush`` (the detector releases the events it holds for reordering) or
    ``close`` (the incident stage writes every open incident); ``reason`` says why: the input was
    quiet (``idle``) or the run ended (``finish``). ``id`` is random; a marker written twice
    after a crash is harmless, because the second one finds nothing left to release.
    """

    model_config = MODEL_CONFIG

    v: Literal[1] = SCHEMA_VERSION
    control: Literal["flush", "close"]
    stage: Annotated[str, Field(min_length=1, max_length=32)]
    reason: Literal["idle", "finish"]
    id: Annotated[str, Field(pattern=r"^ctl-[0-9a-f]{32}$")]


def control(
    stage: str, action: Literal["flush", "close"], reason: Literal["idle", "finish"]
) -> Control:
    """Build a new marker with a random id."""
    return Control(control=action, stage=stage, reason=reason, id=f"ctl-{uuid.uuid4().hex}")


def is_control(value: Mapping[str, Any]) -> bool:
    """Whether a message is a control marker (no event, alert or incident has ``control``)."""
    return "control" in value
