# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
# Copyright (c) 2026 Utsha Basak
"""Parser for Zeek ``conn.log``: tab-separated with a ``#fields`` header, or Zeek JSON.

The layout follows the ``Conn::Info`` record of Zeek 6 and 7 (``ip_proto`` was added in 7.1).
Columns are taken from the ``#fields`` header, so their order, extra columns from policy scripts
and missing optional columns all work. Header lines (``#...``) are counted as skipped.

Data lines before any ``#fields`` header (for example when following a file from the middle) are
read with the default Zeek 7.1 column order if they have 21 or 22 columns, and are errors
otherwise. A log whose ``#path`` is not ``conn`` (``dns.log`` passed by mistake) is skipped line
by line. JSON records use Zeek's flat dotted keys (``"id.orig_h"``) or nested ``id`` objects;
``ts`` may be epoch seconds or an ISO 8601 string. A JSON record with a ``_path`` other than
``conn`` is skipped.

Every connection becomes a ``network.flow`` event in category ``network``. The event is dated at
the connection's **last** packet (``ts + duration``): Zeek writes a line when the connection
ends, so a long connection's line arrives after hours of later lines and would be dropped as late
if it carried its start time. The start is kept in ``extra.start_time``.
"""

import re
from typing import Any

from prohori.parsers.base import LineParser, ParseError, sanitize
from prohori.parsers.network import (
    address,
    as_count,
    as_float,
    as_port,
    checked_duration,
    compact,
    end_of,
    iso_utc,
    parse_epoch,
    parse_iso,
    transport,
)
from prohori.parsers.registry import register
from prohori.parsers.util import as_text, load_json_object
from prohori.schema import Event, event_id

#: Columns of conn.log in Zeek 7.1 without policy scripts (``ip_proto`` is new in 7.1).
DEFAULT_FIELDS = (
    "ts",
    "uid",
    "id.orig_h",
    "id.orig_p",
    "id.resp_h",
    "id.resp_p",
    "proto",
    "service",
    "duration",
    "orig_bytes",
    "resp_bytes",
    "conn_state",
    "local_orig",
    "local_resp",
    "missed_bytes",
    "history",
    "orig_pkts",
    "orig_ip_bytes",
    "resp_pkts",
    "resp_ip_bytes",
    "tunnel_parents",
    "ip_proto",
)
#: Most columns a ``#fields`` header may declare.
MAX_FIELDS = 64
#: Columns every header must declare.
REQUIRED_FIELDS = ("ts", "id.orig_h", "id.resp_h")

#: Connection state -> outcome. Established connections succeed; attempts that were never
#: answered or were rejected fail; midstream (``OTH``) and unknown states stay unknown.
OUTCOME_BY_STATE = {
    "SF": "success",
    "S1": "success",
    "S2": "success",
    "S3": "success",
    "RSTO": "success",
    "RSTR": "success",
    "S0": "failure",
    "REJ": "failure",
    "RSTOS0": "failure",
    "RSTRH": "failure",
    "SH": "failure",
    "SHR": "failure",
}
#: (local_orig, local_resp) -> direction, when Zeek knows its local networks.
DIRECTION = {
    (True, False): "outbound",
    (False, True): "inbound",
    (True, True): "internal",
    (False, False): "external",
}

_ESCAPE_RE = re.compile(r"\\x([0-9a-fA-F]{2})")
_FIELD_NAME_RE = re.compile(r"^[A-Za-z0-9_.]{1,64}$")


def _unescape(text: str) -> str:
    """Decode Zeek's ``\\xNN`` escapes; callers sanitise the result again."""
    return _ESCAPE_RE.sub(lambda m: chr(int(m.group(1), 16)), text)


def _flag(value: object, what: str) -> bool | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return value
    if value in {"T", "F"}:
        return value == "T"
    raise ParseError(f"{what} is not T or F: {str(value)[:20]!r}")


@register
class ZeekConnParser(LineParser):
    """Parse Zeek ``conn.log`` (TSV or JSON) into events.

    Args:
        log_source: Value for ``log_source``.
    """

    name = "zeek_conn"
    keep_tabs = True

    def __init__(self, *, log_source: str = "zeek") -> None:
        self.log_source = log_source
        self.reset()

    def reset(self) -> None:
        self._fields: tuple[str, ...] | None = None
        self._bad_header = False  # the last #fields header was invalid
        self._separator = "\t"
        self._unset = "-"
        self._empty = "(empty)"
        self._path: str | None = None

    def parse_line(self, line: str, number: int, source: str) -> Event | None:
        stripped = line.strip()
        if stripped.startswith("{"):
            record = load_json_object(stripped)
            path = record.get("_path")
            if path is not None and path != "conn":
                return None
            values = _flatten(record)
        elif line.startswith("#"):
            self._header(line)
            return None
        else:
            if self._path is not None and self._path != "conn":
                return None
            values = self._columns(line)
        raw = line.replace("\t", " ")
        return self._event(values, raw, f"{source}:{number}")

    # ------------------------------------------------------------------ TSV

    def _header(self, line: str) -> None:
        if line.startswith("#separator"):
            value = _unescape(line[len("#separator") :].strip(" \t"))
            if len(value) != 1:
                raise ParseError("#separator must be one character")
            self._separator = value
            return
        name, _, rest = line[1:].partition(self._separator)
        if name == "fields":
            fields = tuple(rest.split(self._separator))
            self._fields, self._bad_header = None, True
            if len(fields) > MAX_FIELDS:
                raise ParseError(f"#fields declares more than {MAX_FIELDS} columns")
            missing = [f for f in REQUIRED_FIELDS if f not in fields]
            bad = [f for f in fields if not _FIELD_NAME_RE.fullmatch(f)]
            if missing or bad or len(set(fields)) != len(fields):
                raise ParseError("invalid #fields header")
            self._fields, self._bad_header = fields, False
        elif name == "path":
            self._path = rest.strip()
        elif name == "unset_field":
            self._unset = rest
        elif name == "empty_field":
            self._empty = rest

    def _columns(self, line: str) -> dict[str, Any]:
        cells = line.split(self._separator)
        fields = self._fields
        if fields is None:
            if self._bad_header:
                raise ParseError("data line after an invalid #fields header")
            if len(cells) not in {len(DEFAULT_FIELDS) - 1, len(DEFAULT_FIELDS)}:
                raise ParseError("data line before a #fields header")
            fields = DEFAULT_FIELDS
        elif len(cells) != len(fields):
            raise ParseError(f"expected {len(fields)} columns, found {len(cells)}")
        values: dict[str, Any] = {}
        for field, cell in zip(fields, cells, strict=False):
            if cell == self._unset:
                continue
            values[field] = "" if cell == self._empty else sanitize(_unescape(cell))
        return values

    # ------------------------------------------------------------------ both layouts

    def _event(self, values: dict[str, Any], raw: str, position: str) -> Event:
        ts = values.get("ts")
        start = parse_iso(ts, "ts") if isinstance(ts, str) and "T" in ts else parse_epoch(ts, "ts")
        duration = checked_duration(as_float(values.get("duration"), "duration"))
        end = end_of(start, duration)
        state = as_text(values.get("conn_state"))
        local_orig = _flag(values.get("local_orig"), "local_orig")
        local_resp = _flag(values.get("local_resp"), "local_resp")
        direction = (
            DIRECTION[(local_orig, local_resp)]
            if local_orig is not None and local_resp is not None
            else None
        )
        extra = {
            "destination_ip": address(values.get("id.resp_h"), "id.resp_h"),
            "destination_port": as_port(values.get("id.resp_p"), "id.resp_p"),
            "source_port": as_port(values.get("id.orig_p"), "id.orig_p"),
            "transport": transport(values.get("proto")),
            "app_protocol": as_text(values.get("service")),
            "bytes_out": as_count(values.get("orig_bytes"), "orig_bytes"),
            "bytes_in": as_count(values.get("resp_bytes"), "resp_bytes"),
            "packets_out": as_count(values.get("orig_pkts"), "orig_pkts"),
            "packets_in": as_count(values.get("resp_pkts"), "resp_pkts"),
            "duration": duration,
            "start_time": iso_utc(start),
            "direction": direction,
            "conn_state": state,
            "history": as_text(values.get("history")),
            "uid": as_text(values.get("uid")),
            "community_id": as_text(values.get("community_id")),
        }
        return Event.model_validate(
            {
                "id": event_id(self.log_source, end, raw, position),
                "timestamp": end,
                "log_source": self.log_source,
                "event": {
                    "action": "network.flow",
                    "category": "network",
                    "outcome": OUTCOME_BY_STATE.get(state or "", "unknown"),
                },
                "source": {"ip": address(values.get("id.orig_h"), "id.orig_h")},
                "destination": {
                    "ip": extra.pop("destination_ip"),
                    "port": extra.pop("destination_port"),
                },
                "raw": raw,
                "extra": compact(extra),
            }
        )


def _flatten(record: dict[str, Any]) -> dict[str, Any]:
    """Zeek JSON with nested ``id`` objects -> the flat dotted keys of the default layout."""
    nested = record.get("id")
    if not isinstance(nested, dict):
        return record
    flat = {key: value for key, value in record.items() if key != "id"}
    for key, value in nested.items():
        flat.setdefault(f"id.{key}", value)
    return flat
