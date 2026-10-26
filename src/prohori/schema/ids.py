"""Deterministic identifiers.

Ids are content hashes so that re-processing the same input yields the same ids, which makes
pipeline writes idempotent and reports reproducible.
"""

import hashlib
from collections.abc import Iterable
from datetime import datetime

_SEP = "\x1f"  # ASCII unit separator: cannot appear in a parsed log line after sanitising


def _digest(parts: Iterable[str], length: int) -> str:
    data = _SEP.join(parts).encode("utf-8", errors="surrogatepass")
    return hashlib.sha256(data).hexdigest()[:length]


def event_id(log_source: str, timestamp: datetime, raw: str, discriminator: str = "") -> str:
    """Return the id of an event.

    Two identical lines with the same timestamp from the same source get the same id. Parsers
    that must keep such duplicates apart pass a ``discriminator`` such as ``"auth.log:1042"``.
    """
    return "evt-" + _digest((log_source, timestamp.isoformat(), raw, discriminator), 24)


def alert_id(detector_id: str, event_ids: Iterable[str]) -> str:
    """Return the id of an alert raised by ``detector_id`` over a set of events."""
    return "alr-" + _digest((detector_id, *sorted(event_ids)), 24)


def incident_id(alert_ids: Iterable[str]) -> str:
    """Return the id of the incident grouping ``alert_ids`` (order does not matter)."""
    return "INC-" + _digest(sorted(alert_ids), 16)
