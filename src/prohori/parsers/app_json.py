"""Parser for application security events written as JSON Lines.

Expected record (one per line)::

    {"time": "2026-10-24T13:50:12.345Z", "log_type": "security",
     "event": {"action": "auth.signin.failure", "category": "authentication",
               "outcome": "failure", "severity": "low", "reason": "bad_password"},
     "request_id": "9f3c0a", "source": {"ip": "203.0.113.7"}, "user_agent": "Mozilla/5.0",
     "client": "web", "http": {"method": "POST", "route": "/api/auth/signin"},
     "user": {"id": "665f1c", "email_hash": "3a91d0"}}

Records whose ``log_type`` is present and not ``security`` are skipped. A missing or unknown
``event.category`` is derived from the action prefix (``auth.`` -> ``authentication``, ...).
"""

from datetime import UTC, datetime
from typing import Any

from prohori.parsers.base import LineParser, ParseError
from prohori.parsers.registry import register
from prohori.parsers.util import as_text, get_path, load_json_object, normalise_ip
from prohori.schema import Event, EventCategory, event_id

#: Action prefix -> category, used when the record has no valid category.
CATEGORY_BY_PREFIX: dict[str, EventCategory] = {
    "auth": EventCategory.AUTHENTICATION,
    "session": EventCategory.SESSION,
    "account": EventCategory.ACCOUNT,
    "authz": EventCategory.AUTHORIZATION,
    "ratelimit": EventCategory.ABUSE,
    "turnstile": EventCategory.ABUSE,
    "upload": EventCategory.ABUSE,
    "admin": EventCategory.ADMIN,
}

_CATEGORIES = {category.value for category in EventCategory}


def parse_iso_time(value: object) -> datetime:
    """Parse an ISO-8601 timestamp that must carry a timezone (``Z`` or an offset)."""
    if not isinstance(value, str):
        raise ParseError("missing or non-string timestamp")
    text = value.strip()
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        raise ParseError(f"invalid timestamp {text[:40]!r}") from None
    if parsed.tzinfo is None:
        raise ParseError("timestamp has no timezone")
    return parsed.astimezone(UTC)


@register
class AppJsonParser(LineParser):
    """Parse application security events (JSON Lines) into events.

    Args:
        log_source: Value for ``log_source``.
    """

    name = "app_json"

    def __init__(self, *, log_source: str = "app-security") -> None:
        self.log_source = log_source

    def parse_line(self, line: str, number: int, source: str) -> Event | None:
        record = load_json_object(line)
        log_type = record.get("log_type")
        if log_type is not None and log_type != "security":
            return None
        timestamp = parse_iso_time(record.get("time"))
        event = record.get("event")
        if not isinstance(event, dict):
            raise ParseError("missing 'event' object")
        action = as_text(event.get("action"))
        if action is None:
            raise ParseError("missing event.action")
        http: dict[str, Any] = {
            "method": as_text(get_path(record, "http.method")),
            "path": as_text(get_path(record, "http.route") or get_path(record, "http.path")),
            "status": get_path(record, "http.status"),
        }
        ip_text = as_text(get_path(record, "source.ip"))
        extra: dict[str, str | None] = {}
        ip = normalise_ip(ip_text)
        if ip_text and ip is None:
            extra["source_host"] = ip_text
        return Event.model_validate(
            {
                "id": event_id(self.log_source, timestamp, line, f"{source}:{number}"),
                "timestamp": timestamp,
                "log_source": self.log_source,
                "event": {
                    "action": action,
                    "category": _category(event.get("category"), action),
                    "outcome": as_text(event.get("outcome")) or "unknown",
                    "severity": as_text(event.get("severity")),
                    "reason": as_text(event.get("reason")),
                },
                "source": {"ip": ip},
                "user": {
                    "name": as_text(get_path(record, "user.name")),
                    "id": as_text(get_path(record, "user.id")),
                    "email_hash": as_text(get_path(record, "user.email_hash")),
                },
                "http": http,
                "user_agent": as_text(record.get("user_agent")),
                "client": as_text(record.get("client")),
                "host": as_text(record.get("host")),
                "request_id": as_text(record.get("request_id")),
                "raw": line,
                "extra": extra,
            }
        )


def _category(value: object, action: str) -> str:
    if isinstance(value, str) and value in _CATEGORIES:
        return value
    prefix = action.split(".", 1)[0]
    if prefix in CATEGORY_BY_PREFIX:
        return CATEGORY_BY_PREFIX[prefix].value
    raise ParseError(f"unknown event category {value!r} for action {action!r}")
