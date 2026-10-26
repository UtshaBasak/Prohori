"""Small builders for events and alerts used by the incident tests."""

from datetime import UTC, datetime, timedelta
from typing import Any

from prohori.schema import Alert, Event, Severity

T0 = datetime(2026, 10, 24, 21, 0, tzinfo=UTC)


def at(minutes: float = 0, seconds: float = 0) -> datetime:
    return T0 + timedelta(minutes=minutes, seconds=seconds)


def event(
    when: datetime,
    action: str = "auth.signin.failure",
    *,
    ip: str | None = "203.0.113.7",
    user_id: str | None = None,
    user_name: str | None = None,
    client: str | None = None,
    log_source: str = "app-security",
    request_id: str | None = None,
    extra: dict[str, Any] | None = None,
    user_agent: str | None = None,
    **http: Any,
) -> Event:
    category = {
        "auth": "authentication",
        "ssh": "authentication",
        "account": "account",
        "admin": "admin",
        "web": "web",
        "session": "session",
    }[action.split(".", 1)[0]]
    outcome = (
        "success"
        if action.endswith("success") or category in {"account", "admin"}
        else ("failure" if action.endswith("failure") else "unknown")
    )
    return Event.model_validate(
        {
            "timestamp": when,
            "log_source": log_source,
            "event": {"action": action, "category": category, "outcome": outcome},
            "source": {"ip": ip},
            "user": {"id": user_id, "name": user_name},
            "client": client,
            "request_id": request_id,
            "user_agent": user_agent,
            "http": http,
            "raw": f"{when.isoformat()} {action} {ip} {user_id} {user_name} {request_id}",
            "extra": extra or {},
        }
    )


def alert(
    rule: str,
    events: list[Event] | None = None,
    *,
    start: datetime | None = None,
    end: datetime | None = None,
    severity: Severity = Severity.HIGH,
    entities: dict[str, str] | None = None,
    tags: tuple[str, ...] = (),
    title: str | None = None,
) -> Alert:
    events = events or []
    first = start or (min(e.timestamp for e in events) if events else T0)
    last = end or (max(e.timestamp for e in events) if events else first)
    ids = tuple(e.id for e in events) or (f"evt-{rule}-{first.isoformat()}",)
    return Alert(
        detector_id=rule,
        title=title or f"{rule} fired",
        severity=severity,
        event_ids=ids,
        entities=entities or {},
        first_seen=first,
        last_seen=last,
        attack=tags,
    )
