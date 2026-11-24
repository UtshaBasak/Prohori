# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
# Copyright (c) 2026 Utsha Basak
"""Best-effort detection of a log format from its first lines.

Rules, applied to up to :data:`SAMPLE_LINES` non-blank lines; the format matching most lines wins
and ties go to the earlier entry in this list:

1. ``suricata_eve``: a JSON object with an ``event_type`` and a ``timestamp`` string.
2. ``zeek_conn``: a JSON object with ``uid``, the originator address (``id.orig_h`` or a nested
   ``id``) and a ``conn_state``; a Zeek header line (``#separator``, ``#path conn``, ``#fields``
   starting with ``ts``); or a tab-separated line starting with epoch seconds and a ``C`` uid.
3. ``windows_security``: a JSON object from Winlogbeat (``winlog``), NXLog (``EventID`` with
   ``SourceName``, ``ProviderName`` or ``Channel``), ``Get-WinEvent`` (``Id``, ``TimeCreated``,
   ``ProviderName``) or evtx_dump (``Event.System``), or a line starting ``<Event`` (also
   ``<Events>``) or ``<?xml``.
4. ``journald``: a JSON object with ``__REALTIME_TIMESTAMP`` and ``MESSAGE``.
5. ``app_json``: a JSON object with a ``time`` string and an ``event`` object with an ``action``.
6. ``generic_json``: any other JSON object (needs a mapping file, so it is reported, not used).
7. ``auth_log``: a syslog line (RFC 3164 or RFC 3339 timestamp, host, program).
8. ``access_log``: a combined or common log format line.

Detection is a convenience; pass ``--parser`` when it matters.
"""

import json
import re
from collections.abc import Iterable

from prohori.parsers.access_log import COMBINED_PATTERN
from prohori.parsers.base import RawLine, sanitize

SAMPLE_LINES = 20

_SYSLOG_RE = re.compile(
    r"^(?:[A-Z][a-z]{2} {1,2}\d{1,2} \d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\S*)"
    r" \S+ [^\s\[:]+(?:\[\d+\])?:"
)
_ACCESS_RE = re.compile(COMBINED_PATTERN)
_ZEEK_HEADER_RE = re.compile(r"^#(?:separator |path[ \t]+conn$|fields[ \t]+ts[ \t])")
_ZEEK_LINE_RE = re.compile(r"^\d{9,10}(?:\.\d+)?\tC[A-Za-z0-9]{5,}\t")
_ORDER = (
    "suricata_eve",
    "zeek_conn",
    "windows_security",
    "journald",
    "app_json",
    "generic_json",
    "auth_log",
    "access_log",
)


def classify_line(line: str) -> str | None:
    """Return the format a single line looks like, or ``None``.

    ``line`` is sanitised but may still contain tabs (Zeek's separator).
    """
    if _ZEEK_HEADER_RE.match(line) or _ZEEK_LINE_RE.match(line):
        return "zeek_conn"
    line = line.replace("\t", " ")
    stripped = line.strip()
    if stripped.startswith(("<Event", "<?xml")):
        return "windows_security"
    if stripped.startswith("{"):
        try:
            record = json.loads(stripped)
        except (ValueError, RecursionError):
            return None
        if not isinstance(record, dict):
            return None
        if isinstance(record.get("event_type"), str) and isinstance(record.get("timestamp"), str):
            return "suricata_eve"
        if "uid" in record and "conn_state" in record and _has_originator(record):
            return "zeek_conn"
        if _is_windows(record):
            return "windows_security"
        if "__REALTIME_TIMESTAMP" in record and "MESSAGE" in record:
            return "journald"
        event = record.get("event")
        if isinstance(record.get("time"), str) and isinstance(event, dict) and "action" in event:
            return "app_json"
        return "generic_json"
    if _SYSLOG_RE.match(stripped):
        return "auth_log"
    if _ACCESS_RE.match(stripped):
        return "access_log"
    return None


def detect_format(lines: Iterable[RawLine]) -> str | None:
    """Return the most likely parser name for ``lines``, or ``None`` if nothing matches."""
    votes = dict.fromkeys(_ORDER, 0)
    seen = 0
    for raw in lines:
        if raw.too_long:
            continue
        text = sanitize(raw.text, keep_tabs=True)
        if not text.strip():
            continue
        kind = classify_line(text)
        if kind is not None:
            votes[kind] += 1
        seen += 1
        if seen >= SAMPLE_LINES:
            break
    best = max(_ORDER, key=lambda name: (votes[name], -_ORDER.index(name)))
    return best if votes[best] > 0 else None


def _has_originator(record: dict[str, object]) -> bool:
    nested = record.get("id")
    return "id.orig_h" in record or (isinstance(nested, dict) and "orig_h" in nested)


def _is_windows(record: dict[str, object]) -> bool:
    winlog, event = record.get("winlog"), record.get("Event")
    if isinstance(winlog, dict) and "event_id" in winlog:
        return True
    if isinstance(event, dict) and isinstance(event.get("System"), dict):
        return True
    if {"Id", "TimeCreated", "ProviderName"} <= record.keys():
        return True
    return "EventID" in record and bool({"SourceName", "ProviderName", "Channel"} & record.keys())
