# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
# Copyright (c) 2026 Utsha Basak
"""Parser for exported Windows Security events: JSON Lines or event XML.

Each input line is recognised on its own, so a file may mix the layouts:

* **Winlogbeat / Elastic Agent** (ECS JSON): ``winlog.event_id``, ``winlog.provider_name``,
  ``winlog.event_data`` (``winlog.user_data`` for 1102), ``@timestamp``.
* **NXLog** (``xm_json``): ``EventID``, ``SourceName`` or ``ProviderName``, ``Hostname``,
  ``EventTime``, with the event data as top-level keys.
* **PowerShell**: ``Get-WinEvent ... | ForEach-Object { $_ | ConvertTo-Json -Compress }``:
  ``Id``, ``ProviderName``, ``MachineName``, ``TimeCreated`` (``/Date(ms)/`` from Windows
  PowerShell 5.1 or ISO 8601 from PowerShell 7) and the values by position in ``Properties``,
  named by the event's documented template.
* **evtx_dump** JSON (``{"Event": {"System": ..., "EventData": ...}}``), the layout of the
  ``evtx`` library, which reads ``.evtx`` files when the ``evtx`` extra is installed.
* **Event XML** (``<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">``), as
  ``Get-WinEvent | ForEach-Object { $_.ToXml() }`` writes it (one event per line) or as saved
  from Event Viewer (one event over several lines; ``<?xml ...?>`` and ``<Events>`` lines are
  skipped). XML with a ``DOCTYPE`` or entity declaration is refused before it is parsed.

Times without an offset (NXLog's default ``EventTime``) are read in the ``timezone`` option.
The mapping from a record to an event is :mod:`prohori.parsers.windows`.
"""

import re
import xml.etree.ElementTree as ET  # DOCTYPE and entity declarations are refused before parsing
from datetime import UTC, datetime, tzinfo
from typing import Any

from prohori.parsers.auth_log import _resolve_timezone
from prohori.parsers.base import LineParser, ParseError
from prohori.parsers.network import parse_iso
from prohori.parsers.registry import register
from prohori.parsers.util import load_json_object
from prohori.parsers.windows import (
    SUPPORTED_EVENT_IDS,
    WindowsRecord,
    positional,
    scalar_text,
    to_event,
)
from prohori.schema import Event

#: Most characters one XML event may span when it is written over several lines.
MAX_XML_EVENT = 65_536
#: Most event data values read from one record.
MAX_VALUES = 128

_DATE_RE = re.compile(r"^/Date\((-?\d{1,15})\)/$")
_FRACTION_RE = re.compile(r"(\.\d{6})\d+")
_NAIVE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?$")
_FORBIDDEN_XML = ("<!DOCTYPE", "<!ENTITY")


@register
class WindowsSecurityParser(LineParser):
    """Parse exported Windows Security events (JSON Lines or XML) into events.

    Args:
        timezone: IANA timezone for times written without an offset (NXLog's default).
        log_source: Value for ``log_source``.
    """

    name = "windows_security"

    def __init__(
        self, *, timezone: str | tzinfo = "UTC", log_source: str = "windows-security"
    ) -> None:
        self.timezone = _resolve_timezone(timezone)
        self.log_source = log_source
        self.reset()

    def reset(self) -> None:
        self._xml: list[str] | None = None
        self._xml_size = 0

    def parse_line(self, line: str, number: int, source: str) -> Event | None:
        stripped = line.strip()
        if self._xml is not None or stripped.startswith("<"):
            return self._xml_line(stripped, number, source)
        record = load_json_object(stripped)
        parsed = self._from_json(record)
        if parsed is None:
            return None
        return to_event(parsed, raw=line, position=f"{source}:{number}", log_source=self.log_source)

    # ------------------------------------------------------------------ XML

    def _xml_line(self, line: str, number: int, source: str) -> Event | None:
        if self._xml is None:
            if line.startswith(("<?xml", "<Events", "</Events")):
                return None
            if not line.startswith("<Event"):
                raise ParseError("not an <Event> element")
            self._xml, self._xml_size = [], 0
        self._xml.append(line)
        self._xml_size += len(line)
        if self._xml_size > MAX_XML_EVENT:
            self._xml = None
            raise ParseError(f"XML event longer than {MAX_XML_EVENT} characters")
        if "</Event>" not in line:
            return None  # the event continues on the next line
        text = "".join(self._xml)
        self._xml = None
        if text.count("</Event>") > 1:
            raise ParseError("more than one event on a line; write one event per line")
        record = self._from_xml(text)
        if record is None:
            return None
        return to_event(record, raw=text, position=f"{source}:{number}", log_source=self.log_source)

    def _from_xml(self, text: str) -> WindowsRecord | None:
        upper = text.upper()
        if any(marker in upper for marker in _FORBIDDEN_XML):
            raise ParseError("XML with a DOCTYPE or entity declaration is refused")
        try:
            root = ET.fromstring(text)  # noqa: S314 - DOCTYPE and entities refused above
        except ET.ParseError as exc:
            raise ParseError(f"invalid XML: {exc}"[:200]) from None
        if _local(root.tag) != "Event":
            raise ParseError("not an <Event> element")
        system = data_element = user_data = None
        for child in root:
            name = _local(child.tag)
            if name == "System":
                system = child
            elif name == "EventData":
                data_element = child
            elif name == "UserData":
                user_data = child
        if system is None:
            raise ParseError("event without <System>")
        fields: dict[str, Any] = {}
        for child in system:
            name = _local(child.tag)
            if name == "Provider":
                fields["provider"] = child.get("Name")
            elif name == "TimeCreated":
                fields["time"] = child.get("SystemTime")
            elif name in {"EventID", "EventRecordID", "Channel", "Computer"}:
                fields[name] = (child.text or "").strip()
        data: dict[str, str] = {}
        if data_element is not None:
            for item in list(data_element)[:MAX_VALUES]:
                key = item.get("Name")
                if key is not None:
                    data[key] = (item.text or "").strip()
        if user_data is not None:
            for wrapper in list(user_data)[:1]:
                for item in list(wrapper)[:MAX_VALUES]:
                    data[_local(item.tag)] = (item.text or "").strip()
        return self._record(
            fields.get("EventID"),
            fields.get("provider"),
            fields.get("time"),
            fields.get("Computer"),
            fields.get("EventRecordID"),
            fields.get("Channel"),
            {key: value for key, value in ((k, scalar_text(v)) for k, v in data.items()) if value},
        )

    # ------------------------------------------------------------------ JSON

    def _from_json(self, record: dict[str, Any]) -> WindowsRecord | None:
        winlog = record.get("winlog")
        if isinstance(winlog, dict):  # Winlogbeat / Elastic Agent
            data = _named(winlog.get("event_data"))
            data.update(_named(winlog.get("user_data")))
            return self._record(
                winlog.get("event_id"),
                winlog.get("provider_name"),
                record.get("@timestamp"),
                winlog.get("computer_name"),
                winlog.get("record_id"),
                winlog.get("channel"),
                data,
            )
        event = record.get("Event")
        if isinstance(event, dict) and isinstance(event.get("System"), dict):  # evtx_dump
            return self._from_evtx(event)
        if "Id" in record and "TimeCreated" in record:  # Get-WinEvent | ConvertTo-Json
            event_id = _event_id(record.get("Id"))
            properties = record.get("Properties")
            values = [
                p.get("Value") if isinstance(p, dict) else p
                for p in (properties if isinstance(properties, list) else [])[:MAX_VALUES]
            ]
            return self._record(
                event_id,
                record.get("ProviderName"),
                record.get("TimeCreated"),
                record.get("MachineName"),
                record.get("RecordId"),
                record.get("LogName"),
                positional(event_id, values) if event_id is not None else {},
            )
        if "EventID" in record:  # NXLog: event data as top-level keys
            return self._record(
                record.get("EventID"),
                record.get("SourceName") or record.get("ProviderName"),
                record.get("EventTime"),
                record.get("Hostname"),
                record.get("RecordNumber"),
                record.get("Channel"),
                _named(record),
            )
        if "evtx_error" in record:
            raise ParseError(f"evtx: {record['evtx_error']}"[:200])
        raise ParseError("not a Windows event record")

    def _from_evtx(self, event: dict[str, Any]) -> WindowsRecord | None:
        system = event["System"]
        provider = system.get("Provider")
        time = system.get("TimeCreated")
        data = _named(event.get("EventData"))
        user_data = event.get("UserData")
        if isinstance(user_data, dict):
            for child in list(user_data.values())[:1]:
                data.update(_named(child))
        return self._record(
            _text_of(system.get("EventID")),
            _attribute(provider, "Name"),
            _attribute(time, "SystemTime"),
            system.get("Computer"),
            system.get("EventRecordID"),
            system.get("Channel"),
            data,
        )

    def _record(
        self,
        event_id: object,
        provider: object,
        timestamp: object,
        computer: object,
        record_id: object,
        channel: object,
        data: dict[str, str],
    ) -> WindowsRecord | None:
        number = _event_id(event_id)
        if number is None:
            raise ParseError("missing or invalid event id")
        if number not in SUPPORTED_EVENT_IDS:
            return None
        return WindowsRecord(
            provider=scalar_text(provider),
            event_id=number,
            timestamp=self._time(timestamp),
            computer=scalar_text(computer),
            record_id=_event_id(record_id, maximum=2**63 - 1),
            channel=scalar_text(channel),
            data=data,
        )

    def _time(self, value: object) -> datetime:
        if not isinstance(value, str):
            raise ParseError("missing or non-string time")
        text = value.strip()
        if match := _DATE_RE.match(text):
            try:
                return datetime.fromtimestamp(int(match[1]) / 1000, tz=UTC)
            except (OverflowError, OSError, ValueError):
                raise ParseError(f"time out of range: {text[:40]!r}") from None
        text = _FRACTION_RE.sub(r"\1", text)
        if _NAIVE_RE.match(text):
            try:
                naive = datetime.fromisoformat(text.replace(" ", "T"))
            except ValueError:
                raise ParseError(f"invalid time {text[:40]!r}") from None
            return naive.replace(tzinfo=self.timezone).astimezone(UTC)
        return parse_iso(text, "time")


def _event_id(value: object, maximum: int = 65_535) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        number = value
    elif isinstance(value, str) and value.strip().isascii() and value.strip().isdigit():
        number = int(value.strip()[:20])
    else:
        return None
    return number if 0 <= number <= maximum else None


def _named(value: object) -> dict[str, str]:
    """String values of a name -> value mapping (nested objects and lists are left out)."""
    if not isinstance(value, dict):
        return {}
    named: dict[str, str] = {}
    for key, item in list(value.items())[:MAX_VALUES]:
        text = scalar_text(item)
        if text is not None and isinstance(key, str):
            named[key] = text
    return named


def _attribute(element: object, name: str) -> object:
    """``element["#attributes"][name]`` in evtx_dump JSON."""
    if isinstance(element, dict):
        attributes = element.get("#attributes")
        if isinstance(attributes, dict):
            return attributes.get(name)
    return None


def _text_of(value: object) -> object:
    """An element's text in evtx_dump JSON: the value itself, or ``{"#text": ...}``."""
    if isinstance(value, dict):
        return value.get("#text")
    return value


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]
