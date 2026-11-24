# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
# Copyright (c) 2026 Utsha Basak
"""Parser for the systemd journal exported as JSON (``journalctl -o json``), one entry per line.

sshd, sudo and PAM messages go through the same message parsers as ``auth_log``
(:func:`prohori.parsers.auth_log.parse_auth_message`), so the same sshd message gives the same
event whether it was read from ``auth.log`` or from the journal; only the event id differs.
Entries of other programs are counted as skipped.

========================  ===================================================================
Journal field             Use
========================  ===================================================================
``__REALTIME_TIMESTAMP``  the time: microseconds since the Unix epoch, always UTC
``SYSLOG_IDENTIFIER``     the program (``sshd``, ``sshd-session``, ``sudo``); ``_COMM`` if absent
``SYSLOG_PID``            the process id; ``_PID`` if absent
``_HOSTNAME``             ``host``
``MESSAGE``               the message; a list of byte values (journalctl's form for messages
                          that are not valid UTF-8) is decoded with replacement characters
========================  ===================================================================

The Linux sensors of step 68 read the journal live and reuse this mapping.
"""

from datetime import UTC, datetime, timedelta

from prohori.parsers.auth_log import parse_auth_message
from prohori.parsers.base import LineParser, ParseError, sanitize
from prohori.parsers.registry import register
from prohori.parsers.util import as_text, load_json_object
from prohori.schema import Event

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
#: Longest message read from a list of byte values.
MAX_MESSAGE_BYTES = 16_384


def _message(value: object) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        if len(value) > MAX_MESSAGE_BYTES or not all(
            isinstance(b, int) and not isinstance(b, bool) and 0 <= b <= 255 for b in value
        ):
            raise ParseError("MESSAGE is not a list of byte values")
        return sanitize(bytes(value).decode("utf-8", errors="replace"))
    raise ParseError("missing MESSAGE")


def _pid(value: object) -> str | None:
    text = as_text(value)
    if text is None:
        return None
    if not (text.isascii() and text.isdigit() and len(text) <= 10):
        raise ParseError(f"invalid process id {text[:20]!r}")
    return text


@register
class JournaldParser(LineParser):
    """Parse ``journalctl -o json`` entries (sshd, sudo and PAM messages) into events."""

    name = "journald"

    def parse_line(self, line: str, number: int, source: str) -> Event | None:
        record = load_json_object(line)
        stamp = as_text(record.get("__REALTIME_TIMESTAMP"))
        if stamp is None or not (stamp.isascii() and stamp.isdigit() and len(stamp) <= 17):
            raise ParseError("missing or invalid __REALTIME_TIMESTAMP")
        try:
            timestamp = _EPOCH + timedelta(microseconds=int(stamp))
        except OverflowError:
            raise ParseError(f"__REALTIME_TIMESTAMP out of range: {stamp}") from None
        program = as_text(record.get("SYSLOG_IDENTIFIER")) or as_text(record.get("_COMM"))
        if program is None:
            return None
        pid = _pid(record.get("SYSLOG_PID")) or _pid(record.get("_PID"))
        return parse_auth_message(
            timestamp=timestamp,
            host=as_text(record.get("_HOSTNAME")),
            program=program,
            pid=pid,
            message=_message(record.get("MESSAGE")).lstrip(),
            raw=line,
            discriminator=f"{source}:{number}",
        )
