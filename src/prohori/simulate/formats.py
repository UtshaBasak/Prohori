"""Render simulated activity in the log formats Prohori's parsers read."""

import hashlib
import json
from datetime import datetime

_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
HOST = "web01"


def syslog(timestamp: datetime, program: str, pid: int | None, message: str) -> str:
    """An RFC 3164 ``auth.log`` line, without a year as syslog writes it."""
    stamp = f"{_MONTHS[timestamp.month - 1]} {timestamp.day:>2} {timestamp:%H:%M:%S}"
    tag = f"{program}[{pid}]" if pid is not None else program
    return f"{stamp} {HOST} {tag}: {message}"


def access(
    timestamp: datetime,
    ip: str,
    method: str,
    target: str,
    status: int,
    size: int,
    user_agent: str,
    referer: str = "-",
) -> str:
    """An nginx/Apache combined log line."""
    # Month names from a fixed table, not strftime("%b"), which follows the process locale.
    stamp = f"{timestamp.day:02d}/{_MONTHS[timestamp.month - 1]}/{timestamp:%Y:%H:%M:%S} +0000"
    return (
        f'{ip} - - [{stamp}] "{method} {target} HTTP/1.1" {status} {size} '
        f'"{referer}" "{user_agent}"'
    )


def app(
    timestamp: datetime,
    action: str,
    category: str,
    outcome: str,
    *,
    ip: str,
    request_id: str,
    client: str = "web",
    user_agent: str | None = None,
    method: str = "POST",
    route: str = "/api/auth/signin",
    user: dict[str, str] | None = None,
    severity: str = "low",
    reason: str | None = None,
) -> str:
    """An application security event as one JSON line (the ``app_json`` layout)."""
    event: dict[str, str] = {
        "action": action,
        "category": category,
        "outcome": outcome,
        "severity": severity,
    }
    if reason:
        event["reason"] = reason
    record: dict[str, object] = {
        "time": timestamp.strftime("%Y-%m-%dT%H:%M:%S.") + f"{timestamp.microsecond // 1000:03d}Z",
        "log_type": "security",
        "event": event,
        "request_id": request_id,
        "source": {"ip": ip},
    }
    if user_agent:
        record["user_agent"] = user_agent
    record["client"] = client
    record["http"] = {"method": method, "route": route}
    record["user"] = user or {}
    return json.dumps(record, ensure_ascii=False)


def email_hash(account: str) -> str:
    """A stand-in for the app's email hash: 32 hex digits derived from a synthetic address."""
    return hashlib.sha256(f"{account}@example.com".encode()).hexdigest()[:32]
