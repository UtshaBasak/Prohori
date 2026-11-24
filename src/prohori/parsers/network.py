# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
# Copyright (c) 2026 Utsha Basak
"""Helpers shared by the network sensor parsers (``suricata_eve`` and ``zeek_conn``).

Both parsers put the responder in ``destination.ip`` and ``destination.port`` (since step 34b;
``extra.destination_ip`` and ``extra.destination_port`` before) and describe the rest of a
connection with the same ``extra`` keys, so one rule works on either sensor's output:

======================  =====================================================================
``source_port``         originator port (int)
``transport``           ``tcp``, ``udp``, ``icmp``, ... (lower case)
``app_protocol``        application protocol the sensor recognised (``http``, ``dns``, ...)
``bytes_out``           bytes the originator sent (int)
``bytes_in``            bytes the responder sent (int)
``packets_out``         packets the originator sent (int)
``packets_in``          packets the responder sent (int)
``duration``            seconds from the first to the last packet (float)
``start_time``          first packet, ISO 8601 UTC (the event timestamp is the last packet)
``direction``           ``outbound``, ``inbound``, ``internal`` or ``external`` (Zeek only)
======================  =====================================================================
"""

import math
import re
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta

from prohori.parsers.base import ParseError
from prohori.parsers.util import normalise_ip

#: Longest connection accepted: anything longer is a corrupt duration, not a real flow.
MAX_DURATION_SECONDS = 366 * 24 * 3600.0

_BASIC_OFFSET_RE = re.compile(r"([+-]\d{2})(\d{2})$")
_TRANSPORT_RE = re.compile(r"^[a-z0-9_-]{1,16}$")


def parse_iso(value: object, what: str = "timestamp") -> datetime:
    """Parse ISO 8601 with an offset; ``+0000`` (no colon, as Suricata writes it) is accepted."""
    if not isinstance(value, str):
        raise ParseError(f"missing or non-string {what}")
    text = _BASIC_OFFSET_RE.sub(r"\1:\2", value.strip())
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        raise ParseError(f"invalid {what} {value[:40]!r}") from None
    if parsed.tzinfo is None:
        raise ParseError(f"{what} has no timezone")
    return parsed.astimezone(UTC)


def parse_epoch(value: object, what: str = "timestamp") -> datetime:
    """Parse seconds since the Unix epoch (a number or numeric text) as UTC."""
    seconds = as_float(value, what)
    if seconds is None:
        raise ParseError(f"missing {what}")
    try:
        return datetime.fromtimestamp(seconds, tz=UTC)
    except (OverflowError, OSError, ValueError):
        raise ParseError(f"{what} out of range: {seconds}") from None


def as_float(value: object, what: str) -> float | None:
    """A finite, non-negative number from a JSON number or text; ``None`` when absent."""
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        raise ParseError(f"{what} is not a number")
    if isinstance(value, int | float):
        number = float(value)
    elif isinstance(value, str):
        try:
            number = float(value)
        except ValueError:
            raise ParseError(f"{what} is not a number: {value[:40]!r}") from None
    else:
        raise ParseError(f"{what} is not a number")
    if not math.isfinite(number) or number < 0:
        raise ParseError(f"{what} out of range: {value!r}"[:200])
    return number


def as_count(value: object, what: str, maximum: int = 2**63 - 1) -> int | None:
    """A non-negative integer from a JSON number or text; ``None`` when absent."""
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        raise ParseError(f"{what} is not a count")
    if isinstance(value, int):
        number = value
    elif isinstance(value, str) and value.isascii() and value.isdigit() and len(value) <= 20:
        number = int(value)
    else:
        raise ParseError(f"{what} is not a count: {str(value)[:40]!r}")
    if not 0 <= number <= maximum:
        raise ParseError(f"{what} out of range: {number}")
    return number


def as_port(value: object, what: str) -> int | None:
    """A port number 0-65535 (ICMP type and code are logged in the port fields too)."""
    return as_count(value, what, maximum=65535)


def address(value: object, what: str) -> str:
    """A required IP address, normalised (IPv4-mapped IPv6 becomes IPv4)."""
    text = value if isinstance(value, str) else None
    ip = normalise_ip(text)
    if ip is None:
        raise ParseError(f"missing or invalid {what}")
    return str(ip)


def transport(value: object) -> str | None:
    """A transport protocol name in lower case (``TCP`` -> ``tcp``); ``None`` when unknown."""
    if not isinstance(value, str):
        return None
    name = value.strip().lower()
    return name if _TRANSPORT_RE.fullmatch(name) else None


def checked_duration(seconds: float | None) -> float | None:
    """Reject durations no real connection has (more than a year)."""
    if seconds is not None and seconds > MAX_DURATION_SECONDS:
        raise ParseError(f"duration out of range: {seconds}")
    return seconds


def end_of(start: datetime, duration: float | None) -> datetime:
    """The time of a connection's last packet: its start plus its duration."""
    if not duration:
        return start
    try:
        return start + timedelta(seconds=duration)
    except OverflowError:
        raise ParseError("connection end out of range") from None


def iso_utc(moment: datetime) -> str:
    """ISO 8601 in UTC with a ``Z`` suffix, as the schema writes timestamps."""
    return moment.astimezone(UTC).isoformat().replace("+00:00", "Z")


def compact(values: Mapping[str, object]) -> dict[str, object]:
    """Drop keys whose value is ``None``."""
    return {key: value for key, value in values.items() if value is not None}
