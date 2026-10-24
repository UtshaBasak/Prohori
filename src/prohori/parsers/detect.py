"""Best-effort detection of a log format from its first lines.

Rules, applied to up to :data:`SAMPLE_LINES` non-blank lines; the format matching most lines wins
and ties go to the earlier entry in this list:

1. ``app_json``: a JSON object with a ``time`` string and an ``event`` object with an ``action``.
2. ``generic_json``: any other JSON object (needs a mapping file, so it is reported, not used).
3. ``auth_log``: a syslog line (RFC 3164 or RFC 3339 timestamp, host, program).
4. ``access_log``: a combined or common log format line.

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
_ORDER = ("app_json", "generic_json", "auth_log", "access_log")


def classify_line(line: str) -> str | None:
    """Return the format a single line looks like, or ``None``."""
    stripped = line.strip()
    if stripped.startswith("{"):
        try:
            record = json.loads(stripped)
        except (ValueError, RecursionError):
            return None
        if not isinstance(record, dict):
            return None
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
        text = sanitize(raw.text)
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
