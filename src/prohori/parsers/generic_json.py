"""Parser for arbitrary JSON Lines logs, driven by a YAML field-mapping file.

Example mapping::

    log_source: payments-api
    timestamp:
      field: ts                 # dotted path into each record
      format: iso8601           # iso8601, epoch, epoch_ms or a strptime pattern
      timezone: UTC             # used when the timestamp has no offset
    fields:                     # schema field -> dotted path in the record
      event.action: kind
      source.ip: client.addr
      user.name: actor
    constants:                  # schema field -> fixed value
      event.category: authentication
    values:                     # optional value translation per schema field
      event.outcome: {ok: success, denied: failure}
    extra:                      # extra key -> dotted path in the record
      merchant: merchant.id

``event.action`` and ``event.category`` must come from ``fields`` or ``constants``.
"""

from datetime import UTC, datetime, tzinfo
from pathlib import Path
from typing import Annotated, Any, Self
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from prohori.parsers.base import LineParser, ParseError
from prohori.parsers.registry import register
from prohori.parsers.util import as_text, get_path, load_json_object, normalise_ip
from prohori.schema import FIELD_PATHS, Event, event_id

#: Largest mapping file accepted, in bytes.
MAX_MAPPING_BYTES = 64 * 1024

#: Schema fields a mapping may set (the rest are derived by the parser).
MAPPABLE_FIELDS = frozenset(FIELD_PATHS - {"id", "timestamp", "log_source", "raw"})

_DottedPath = Annotated[str, Field(pattern=r"^[^.\s]+(\.[^.\s]+)*$", max_length=200)]


class TimestampSpec(BaseModel):
    """Where and how to read the event time."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    field: _DottedPath
    format: Annotated[str, Field(min_length=1, max_length=100)] = "iso8601"
    timezone: str = "UTC"

    @field_validator("timezone")
    @classmethod
    def _known_timezone(cls, value: str) -> str:
        _zone(value)
        return value


class FieldMapping(BaseModel):
    """A validated mapping file."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    log_source: Annotated[str, Field(min_length=1, max_length=64)]
    timestamp: TimestampSpec
    fields: dict[str, _DottedPath] = {}
    constants: dict[str, str | int | bool] = {}
    values: dict[str, dict[str, str]] = {}
    extra: Annotated[dict[str, _DottedPath], Field(max_length=32)] = {}

    @model_validator(mode="after")
    def _check_targets(self) -> Self:
        for section in ("fields", "constants", "values"):
            unknown = set(getattr(self, section)) - MAPPABLE_FIELDS
            if unknown:
                msg = f"unknown schema field(s) in '{section}': {', '.join(sorted(unknown))}"
                raise ValueError(msg)
        both = set(self.fields) & set(self.constants)
        if both:
            msg = f"field(s) set in both 'fields' and 'constants': {', '.join(sorted(both))}"
            raise ValueError(msg)
        for required in ("event.action", "event.category"):
            if required not in self.fields and required not in self.constants:
                msg = f"'{required}' must be mapped in 'fields' or set in 'constants'"
                raise ValueError(msg)
        return self


def load_mapping(path: Path) -> FieldMapping:
    """Read and validate a YAML mapping file (safe loading only).

    Raises:
        ValueError: if the file is too large, not valid YAML or not a valid mapping.
    """
    data = path.read_bytes()
    if len(data) > MAX_MAPPING_BYTES:
        msg = f"mapping file larger than {MAX_MAPPING_BYTES} bytes"
        raise ValueError(msg)
    try:
        document = yaml.safe_load(data)
    except yaml.YAMLError as exc:
        msg = f"invalid YAML in mapping file: {exc}"
        raise ValueError(msg) from exc
    if not isinstance(document, dict):
        msg = "mapping file must contain a YAML mapping"
        raise ValueError(msg)
    try:
        return FieldMapping.model_validate(document)
    except ValidationError as exc:
        msg = f"invalid mapping file: {exc}"
        raise ValueError(msg) from exc


@register
class GenericJsonParser(LineParser):
    """Parse JSON Lines using a :class:`FieldMapping` (or a path to a YAML mapping file)."""

    name = "generic_json"

    def __init__(self, *, mapping: FieldMapping | Path | str | None = None) -> None:
        if mapping is None:
            msg = "the generic_json parser needs a field-mapping file"
            raise ValueError(msg)
        if not isinstance(mapping, FieldMapping):
            mapping = load_mapping(Path(mapping))
        self.mapping = mapping
        self._timezone = _zone(mapping.timestamp.timezone)

    def parse_line(self, line: str, number: int, source: str) -> Event:
        record = load_json_object(line)
        spec = self.mapping.timestamp
        timestamp = _parse_time(get_path(record, spec.field), spec.format, self._timezone)
        nested: dict[str, Any] = {"event": {}, "source": {}, "user": {}, "http": {}}
        values: dict[str, object] = dict(self.mapping.constants)
        for target, path in self.mapping.fields.items():
            values[target] = get_path(record, path)
        for target, raw_value in values.items():
            if raw_value is None:
                continue  # absent in this record: leave the schema default
            value: object = as_text(raw_value) if target not in _NUMERIC else raw_value
            translation = self.mapping.values.get(target)
            if translation is not None and value is not None:
                value = translation.get(str(value), value)
            head, _, tail = target.partition(".")
            if tail:
                nested[head][tail] = value
            else:
                nested[head] = value
        extra: dict[str, object] = {}
        ip_value = nested["source"].get("ip")
        if ip_value is not None:
            ip = normalise_ip(str(ip_value))
            if ip is None:
                extra["source_host"] = str(ip_value)
            nested["source"]["ip"] = ip
        for key, path in self.mapping.extra.items():
            value = get_path(record, path)
            if isinstance(value, str | int | float | bool) or value is None:
                extra[key] = value
        log_source = self.mapping.log_source
        return Event.model_validate(
            {
                **nested,
                "id": event_id(log_source, timestamp, line, f"{source}:{number}"),
                "timestamp": timestamp,
                "log_source": log_source,
                "raw": line,
                "extra": extra,
            }
        )


_NUMERIC = frozenset({"http.status", "http.bytes"})


def _zone(name: str) -> tzinfo:
    if name.upper() == "UTC":
        return UTC
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        msg = f"unknown timezone {name!r}"
        raise ValueError(msg) from exc


def _parse_time(value: object, fmt: str, zone: tzinfo) -> datetime:
    if value is None or value == "":
        raise ParseError("missing timestamp")
    try:
        if fmt in {"epoch", "epoch_ms"}:
            if isinstance(value, bool) or not isinstance(value, int | float | str):
                raise ParseError("epoch timestamp must be a number")
            seconds = float(value) / (1000 if fmt == "epoch_ms" else 1)
            return datetime.fromtimestamp(seconds, tz=UTC)
        if not isinstance(value, str):
            raise ParseError("timestamp must be a string")
        parsed = (
            datetime.fromisoformat(value.strip())
            if fmt == "iso8601"
            else datetime.strptime(value.strip(), fmt)  # noqa: DTZ007 - timezone applied below
        )
    except (ValueError, OverflowError, OSError) as exc:
        raise ParseError(f"invalid timestamp: {exc}") from None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=zone)
    return parsed.astimezone(UTC)
