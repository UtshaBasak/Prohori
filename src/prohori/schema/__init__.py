"""Pydantic models for the common event schema: Event, Alert and Incident."""

from prohori.schema.alert import ATTACK_TAG_PATTERN, Alert, AttackTag, DetectorKind
from prohori.schema.event import ACTION_PATTERN, Event, EventInfo, HttpInfo, SourceInfo, UserInfo
from prohori.schema.fields import FIELD_PATHS, get_field, is_valid_path
from prohori.schema.ids import alert_id, event_id, incident_id
from prohori.schema.incident import (
    Confidence,
    EnrichmentResult,
    Incident,
    IncidentStatus,
    Indicator,
    IndicatorType,
    InputFile,
    Provenance,
    RuleRef,
    ScoreComponent,
    TimelineEntry,
)
from prohori.schema.serialization import from_json, read_jsonl, to_json, write_jsonl
from prohori.schema.types import (
    MAX_RAW_LENGTH,
    MAX_SHORT_TEXT_LENGTH,
    MAX_TEXT_LENGTH,
    EventCategory,
    JsonScalar,
    Outcome,
    Severity,
)

__all__ = [
    "ACTION_PATTERN",
    "ATTACK_TAG_PATTERN",
    "FIELD_PATHS",
    "MAX_RAW_LENGTH",
    "MAX_SHORT_TEXT_LENGTH",
    "MAX_TEXT_LENGTH",
    "Alert",
    "AttackTag",
    "Confidence",
    "DetectorKind",
    "EnrichmentResult",
    "Event",
    "EventCategory",
    "EventInfo",
    "HttpInfo",
    "Incident",
    "IncidentStatus",
    "Indicator",
    "IndicatorType",
    "InputFile",
    "JsonScalar",
    "Outcome",
    "Provenance",
    "RuleRef",
    "ScoreComponent",
    "Severity",
    "SourceInfo",
    "TimelineEntry",
    "UserInfo",
    "alert_id",
    "event_id",
    "from_json",
    "get_field",
    "incident_id",
    "is_valid_path",
    "read_jsonl",
    "to_json",
    "write_jsonl",
]
