"""Parser for Linux ``auth.log`` / ``secure`` files (sshd, sudo and PAM lines).

Two syslog header formats are supported:

* RFC 3164 (``Oct 24 13:50:12 host sshd[123]: ...``) has **no year and no timezone**. The year
  comes from the ``year`` option (the year of the first line) or, failing that, from a reference
  time such as the file's modification time; the timezone comes from the ``timezone`` option.
  A month that goes backwards by six or more (December -> January) is a New Year rollover.
* RFC 3339 / ISO 8601 (``2026-10-24T13:50:12.345678+06:00 host sshd[123]: ...``), the default on
  recent distributions, carries both. ``timezone`` is only used if the offset is missing.
"""

import re
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta, tzinfo
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from prohori.parsers.base import LineParser, ParseError, ParseStats
from prohori.parsers.registry import register
from prohori.parsers.util import normalise_ip
from prohori.schema import Event, EventCategory, EventInfo, Outcome, event_id

_MONTHS = {
    name: number
    for number, name in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"),
        start=1,
    )
}

_RFC3164_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2}) {1,2}(?P<day>\d{1,2}) "
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2}) (?P<rest>.*)$"
)
_ISO_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})?) "
    r"(?P<rest>.*)$"
)
_TAG_RE = re.compile(
    r"^(?P<host>\S+) (?P<program>[^\s\[:]+)(?:\[(?P<pid>\d{1,10})\])?: ?(?P<msg>.*)$"
)

# sshd messages. Usernames are attacker-controlled and may contain spaces or even text that looks
# like " from <ip> port <n>"; greedy user groups anchored at the end of the line make the address
# sshd appends last the one that is used.
_ADDR = r"(?P<addr>\S+) port (?P<port>\d{1,5})"
_TAIL = r"(?: \S+)?(?::.*)?$"  # protocol and key details: " ssh2: RSA SHA256:..."
_PREAUTH = r"(?: \[preauth\])?$"
_SSH_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = tuple(
    (re.compile(pattern), kind)
    for pattern, kind in (
        (
            rf"^Failed (?P<method>\S+) for invalid user (?P<user>.*) from {_ADDR}{_TAIL}",
            "failed_invalid",
        ),
        (rf"^Failed (?P<method>\S+) for (?P<user>.*) from {_ADDR}{_TAIL}", "failed"),
        (rf"^Accepted (?P<method>\S+) for (?P<user>.*) from {_ADDR}{_TAIL}", "accepted"),
        (rf"^Invalid user (?P<user>.*) from {_ADDR}$", "invalid_user"),
        (r"^Invalid user (?P<user>.*) from (?P<addr>\S+)$", "invalid_user"),
        (
            rf"^error: maximum authentication attempts exceeded for invalid user (?P<user>.*) "
            rf"from {_ADDR}(?: \S+)?(?: \[preauth\])?$",
            "too_many_invalid",
        ),
        (
            rf"^error: maximum authentication attempts exceeded for (?P<user>.*) "
            rf"from {_ADDR}(?: \S+)?(?: \[preauth\])?$",
            "too_many",
        ),
        (
            rf"^Disconnecting invalid user (?P<user>.*) {_ADDR}: "
            r"Too many authentication failures(?: \[preauth\])?$",
            "too_many_invalid",
        ),
        (
            rf"^Disconnecting authenticating user (?P<user>.*) {_ADDR}: "
            r"Too many authentication failures(?: \[preauth\])?$",
            "too_many",
        ),
        (
            rf"^Disconnected from invalid user (?P<user>.*) {_ADDR}{_PREAUTH}",
            "disconnect_invalid",
        ),
        (
            rf"^Disconnected from (?:authenticating )?user (?P<user>.*) {_ADDR}{_PREAUTH}",
            "disconnect",
        ),
        (rf"^Disconnected from {_ADDR}{_PREAUTH}", "disconnect"),
        (rf"^Received disconnect from {_ADDR}:\d+: .*$", "disconnect"),
        (
            rf"^Connection closed by invalid user (?P<user>.*) {_ADDR}{_PREAUTH}",
            "disconnect_invalid",
        ),
        (
            rf"^Connection closed by (?:authenticating )?user (?P<user>.*) {_ADDR}{_PREAUTH}",
            "disconnect",
        ),
        (rf"^Connection closed by {_ADDR}{_PREAUTH}", "disconnect"),
    )
)

_PAM_AUTH_FAILURE_RE = re.compile(
    r"^pam_unix\((?P<service>[^:)]+):auth\): authentication failure;(?P<fields>.*)$"
)
_PAM_SESSION_RE = re.compile(
    r"^pam_unix\((?P<service>[^:)]+):session\): session (?P<state>opened|closed) "
    r"for user (?P<user>[^(\s]+)(?:\(uid=\d+\))?(?: by (?P<by>\S*?)(?:\(uid=\d+\))?)?$"
)
_PAM_FIELD_RE = re.compile(r"(\w+)=(\S*)")

# sudo: "alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id"
_SUDO_RE = re.compile(r"^(?P<user>\S+) : (?P<fields>.*)$")


def _resolve_timezone(value: str | tzinfo) -> tzinfo:
    if isinstance(value, tzinfo):
        return value
    if value.upper() == "UTC":
        return UTC
    try:
        return ZoneInfo(value)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        msg = f"unknown timezone {value!r}"
        raise ValueError(msg) from exc


@register
class AuthLogParser(LineParser):
    """Parse sshd, sudo and PAM lines from ``auth.log`` / ``secure``.

    Args:
        year: Year of the **first** line of RFC 3164 input. Later lines advance it on rollover.
        timezone: IANA timezone name (or ``tzinfo``) for timestamps that carry no offset.
        reference_time: Used when ``year`` is not given: the first line is assumed to be no later
            than this moment (for example the file's modification time). Defaults to now.
    """

    name = "auth_log"

    def __init__(
        self,
        *,
        year: int | None = None,
        timezone: str | tzinfo = "UTC",
        reference_time: datetime | None = None,
    ) -> None:
        if year is not None and not 1970 <= year <= 9998:
            msg = f"year out of range: {year}"
            raise ValueError(msg)
        self.year = year
        self.timezone = _resolve_timezone(timezone)
        self.reference_time = reference_time
        self.reset()

    def reset(self) -> None:
        self._current_year: int | None = None
        self._previous_month: int | None = None

    def parse_file(self, path: Path, *, stats: ParseStats | None = None) -> Iterator[Event]:
        """Parse a file, using its modification time as the reference time if no year is set."""
        if self.year is None and self.reference_time is None:
            mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=UTC)
            parser = AuthLogParser(timezone=self.timezone, reference_time=mtime)
            return parser.parse_file(path, stats=stats)
        return super().parse_file(path, stats=stats)

    # ------------------------------------------------------------------ timestamps

    def _rfc3164_timestamp(self, match: re.Match[str]) -> datetime:
        month = _MONTHS.get(match["month"])
        if month is None:
            raise ParseError(f"unknown month {match['month']!r}")
        day = int(match["day"])
        hour, minute, second = int(match["hour"]), int(match["minute"]), int(match["second"])
        year = self._year_for(month, day)
        try:
            local = datetime(year, month, day, hour, minute, second, tzinfo=self.timezone)
        except ValueError as exc:  # e.g. Feb 30, or Feb 29 in a non-leap year
            raise ParseError(f"invalid date: {exc}") from None
        return local.astimezone(UTC)

    def _year_for(self, month: int, day: int) -> int:
        if self._current_year is None or self._previous_month is None:
            self._current_year = (
                self.year if self.year is not None else self._initial_year(month, day)
            )
            self._previous_month = month
            return self._current_year
        if self._previous_month - month >= 6:  # December -> January
            self._current_year += 1
            self._previous_month = month
            return self._current_year
        if month - self._previous_month >= 6:  # a late line from the previous year
            return self._current_year - 1
        self._previous_month = month
        return self._current_year

    def _initial_year(self, month: int, day: int) -> int:
        reference = (self.reference_time or datetime.now(tz=UTC)).astimezone(self.timezone)
        # Allow a day of slack for clock skew and timezone differences.
        limit = reference + timedelta(days=1)
        year = reference.year
        if (month, day) > (limit.month, limit.day) and limit.year == year:
            year -= 1
        return year

    def _iso_timestamp(self, text: str) -> datetime:
        try:
            value = datetime.fromisoformat(_trim_fraction(text))
        except ValueError as exc:
            raise ParseError(f"invalid timestamp: {exc}") from None
        if value.tzinfo is None:
            value = value.replace(tzinfo=self.timezone)
        return value.astimezone(UTC)

    # ------------------------------------------------------------------ lines

    def parse_line(self, line: str, number: int, source: str) -> Event | None:
        if match := _ISO_RE.match(line):
            timestamp = self._iso_timestamp(match["ts"])
        elif match := _RFC3164_RE.match(line):
            timestamp = self._rfc3164_timestamp(match)
        else:
            raise ParseError("no syslog timestamp")
        tag = _TAG_RE.match(match["rest"])
        if tag is None:
            raise ParseError("no syslog host/program tag")
        program, message = tag["program"], tag["msg"].lstrip()
        builder = _EventBuilder(
            timestamp=timestamp,
            host=tag["host"],
            program=program,
            pid=tag["pid"],
            raw=line,
            discriminator=f"{source}:{number}",
        )
        if message.startswith("pam_unix("):
            return _parse_pam(message, builder)
        if program == "sshd" or program.startswith("sshd-"):
            return _parse_sshd(message, builder)
        if program == "sudo":
            return _parse_sudo(message, builder)
        return None


class _EventBuilder:
    """Collects the header fields shared by every event from one line."""

    def __init__(
        self,
        *,
        timestamp: datetime,
        host: str,
        program: str,
        pid: str | None,
        raw: str,
        discriminator: str,
    ) -> None:
        self.timestamp = timestamp
        self.host = host
        self.program = program
        self.pid = pid
        self.raw = raw
        self.discriminator = discriminator

    def build(
        self,
        action: str,
        category: EventCategory,
        outcome: Outcome,
        *,
        reason: str | None = None,
        user: str | None = None,
        addr: str | None = None,
        extra: dict[str, str | int | bool | None] | None = None,
    ) -> Event:
        log_source = "sshd" if self.program.startswith("sshd") else self.program
        fields: dict[str, str | int | bool | None] = {}
        if self.pid is not None:
            fields["pid"] = int(self.pid)
        ip = None
        if addr is not None:
            ip = normalise_ip(addr)
            if ip is None:  # sshd with UseDNS logs host names instead of addresses
                fields["source_host"] = addr
        fields.update(extra or {})
        return Event.model_validate(
            {
                "id": event_id(log_source, self.timestamp, self.raw, self.discriminator),
                "timestamp": self.timestamp,
                "log_source": log_source[:64],
                "event": EventInfo(
                    action=action, category=category, outcome=outcome, reason=reason
                ),
                "source": {"ip": ip},
                "user": {"name": user},
                "host": self.host,
                "raw": self.raw,
                "extra": fields,
            }
        )


def _parse_sshd(message: str, b: _EventBuilder) -> Event | None:
    for pattern, kind in _SSH_PATTERNS:
        match = pattern.match(message)
        if match is None:
            continue
        groups = match.groupdict()
        user, addr = groups.get("user"), groups["addr"]
        extra: dict[str, str | int | bool | None] = {}
        if groups.get("port") is not None:
            extra["source_port"] = int(groups["port"])
        if groups.get("method") is not None:
            extra["auth_method"] = groups["method"]
        auth = EventCategory.AUTHENTICATION
        match kind:
            case "failed" | "failed_invalid":
                invalid = kind == "failed_invalid"
                reason = "unknown_user" if invalid else _failure_reason(groups["method"])
                return b.build(
                    "ssh.login.failure",
                    auth,
                    Outcome.FAILURE,
                    reason=reason,
                    user=user,
                    addr=addr,
                    extra=extra,
                )
            case "accepted":
                return b.build(
                    "ssh.login.success", auth, Outcome.SUCCESS, user=user, addr=addr, extra=extra
                )
            case "invalid_user":
                return b.build(
                    "ssh.invalid_user",
                    auth,
                    Outcome.FAILURE,
                    reason="unknown_user",
                    user=user,
                    addr=addr,
                    extra=extra,
                )
            case "too_many" | "too_many_invalid":
                reason = "unknown_user" if kind == "too_many_invalid" else "too_many_failures"
                return b.build(
                    "ssh.auth.too_many_failures",
                    auth,
                    Outcome.FAILURE,
                    reason=reason,
                    user=user,
                    addr=addr,
                    extra=extra,
                )
            case _:  # disconnects and closed connections
                if kind == "disconnect_invalid":
                    extra["invalid_user"] = True
                return b.build(
                    "ssh.disconnect",
                    EventCategory.NETWORK,
                    Outcome.UNKNOWN,
                    user=user,
                    addr=addr,
                    extra=extra,
                )
    return None


def _failure_reason(method: str) -> str:
    if method == "publickey":
        return "bad_key"
    if method in {"password", "keyboard-interactive/pam"}:
        return "bad_password"
    return "auth_failed"


def _parse_pam(message: str, b: _EventBuilder) -> Event | None:
    if match := _PAM_AUTH_FAILURE_RE.match(message):
        fields = dict(_PAM_FIELD_RE.findall(match["fields"]))
        rhost = fields.get("rhost") or None
        extra: dict[str, str | int | bool | None] = {"pam_service": match["service"]}
        if ruser := fields.get("ruser"):
            extra["remote_user"] = ruser
        return b.build(
            "pam.auth.failure",
            EventCategory.AUTHENTICATION,
            Outcome.FAILURE,
            reason="auth_failed",
            user=fields.get("user") or None,
            addr=rhost,
            extra=extra,
        )
    if match := _PAM_SESSION_RE.match(message):
        extra = {"pam_service": match["service"]}
        if match["by"]:
            extra["by_user"] = match["by"]
        return b.build(
            f"session.{match['state']}",
            EventCategory.SESSION,
            Outcome.SUCCESS,
            user=match["user"],
            extra=extra,
        )
    return None


def _parse_sudo(message: str, b: _EventBuilder) -> Event | None:
    match = _SUDO_RE.match(message)
    if match is None:
        return None
    user = match["user"]
    parts = [part.strip() for part in match["fields"].split(" ; ")]
    keyed: dict[str, str] = {}
    notes: list[str] = []
    for part in parts:
        key, sep, value = part.partition("=")
        if sep and key.isupper() and key.isalpha():
            keyed[key] = value
        else:
            notes.append(part)
    if "COMMAND" not in keyed:
        return None
    extra: dict[str, str | int | bool | None] = {
        "target_user": keyed.get("USER"),
        "command": keyed["COMMAND"],
        "tty": keyed.get("TTY"),
        "cwd": keyed.get("PWD"),
    }
    note = notes[0] if notes else ""
    if "incorrect password attempt" in note:
        attempts = re.match(r"^(\d+) incorrect password attempts?$", note)
        extra["attempts"] = int(attempts[1]) if attempts else None
        return b.build(
            "sudo.auth.failure",
            EventCategory.AUTHENTICATION,
            Outcome.FAILURE,
            reason="bad_password",
            user=user,
            extra=extra,
        )
    if "NOT in sudoers" in note or "not allowed to execute" in note:
        return b.build(
            "sudo.denied",
            EventCategory.AUTHORIZATION,
            Outcome.FAILURE,
            reason="not_permitted",
            user=user,
            extra=extra,
        )
    if note:
        extra["note"] = note
        return b.build("sudo.command", EventCategory.ADMIN, Outcome.UNKNOWN, user=user, extra=extra)
    return b.build("sudo.command", EventCategory.ADMIN, Outcome.SUCCESS, user=user, extra=extra)


def _trim_fraction(text: str) -> str:
    """Shorten fractional seconds to microseconds (``fromisoformat`` accepts at most six digits)."""
    return re.sub(r"(\.\d{6})\d+", r"\1", text)
