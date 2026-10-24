"""Parser for nginx and Apache access logs (combined and common log formats).

The default pattern accepts both::

    203.0.113.7 - alice [24/Oct/2026:13:50:12 +0000] "GET /a?b=1 HTTP/1.1" 404 153 "-" "curl/8.5"
    203.0.113.7 - - [24/Oct/2026:13:50:12 +0000] "GET / HTTP/1.1" 200 512

A custom regular expression can be supplied for other ``log_format`` settings. It must define the
named groups ``ip``, ``time`` and ``status``, and either ``request`` or ``method`` and ``path``;
``user``, ``bytes``, ``referer``, ``agent``, ``host`` and ``protocol`` are optional.
"""

import re
from datetime import UTC, datetime, timedelta, timezone

from prohori.parsers.base import LineParser, ParseError
from prohori.parsers.registry import register
from prohori.parsers.util import normalise_ip
from prohori.schema import Event, EventCategory, EventInfo, Outcome, event_id

_QUOTED = r'"(?P<{name}>(?:[^"\\]|\\.)*)"'

#: Combined log format, with referer and user agent optional (common log format).
COMBINED_PATTERN = (
    r"^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]{1,40})\] "
    + _QUOTED.format(name="request")
    + r" (?P<status>\d{3}) (?P<bytes>\d+|-)"
    + r"(?: "
    + _QUOTED.format(name="referer")
    + r" "
    + _QUOTED.format(name="agent")
    + r")?(?: .*)?$"
)

_REQUEST_RE = re.compile(
    r"^(?P<method>[A-Za-z]{1,16}) (?P<target>\S+)(?: (?P<protocol>[A-Z]+/[\d.]+))?$"
)
_TIME_RE = re.compile(
    r"^(?P<day>\d{2})/(?P<month>[A-Z][a-z]{2})/(?P<year>\d{4}):"
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2}) (?P<sign>[+-])(?P<oh>\d{2})(?P<om>\d{2})$"
)
_MONTHS = {
    name: number
    for number, name in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"),
        start=1,
    )
}
_ESCAPE_RE = re.compile(r"\\x([0-9a-fA-F]{2})|\\(.)")
_REQUIRED_GROUPS = {"ip", "time", "status"}


def parse_clf_time(text: str) -> datetime:
    """Parse ``24/Oct/2026:13:50:12 +0600`` (locale-independent) and return it in UTC."""
    match = _TIME_RE.match(text)
    if match is None or match["month"] not in _MONTHS:
        raise ParseError(f"invalid timestamp {text[:40]!r}")
    offset = timedelta(hours=int(match["oh"]), minutes=int(match["om"]))
    if match["sign"] == "-":
        offset = -offset
    try:
        local = datetime(
            int(match["year"]),
            _MONTHS[match["month"]],
            int(match["day"]),
            int(match["hour"]),
            int(match["minute"]),
            int(match["second"]),
            tzinfo=timezone(offset),
        )
    except ValueError as exc:
        raise ParseError(f"invalid timestamp: {exc}") from None
    return local.astimezone(UTC)


def unescape(text: str) -> str:
    """Undo nginx (``\\x22``) and Apache (``\\"``) escaping inside quoted fields."""

    def replace(match: re.Match[str]) -> str:
        if match[1] is not None:
            return chr(int(match[1], 16))
        return match[2]

    return _ESCAPE_RE.sub(replace, text)


@register
class AccessLogParser(LineParser):
    """Parse web-server access logs into ``web.request`` events.

    Args:
        pattern: Custom regular expression (see module documentation). Defaults to the combined
            log format, which also accepts the common log format.
        keep_query: Keep the query string in ``http.path``. By default the path is stored without
            it and the query string goes to ``extra.query``, so rules can still inspect it.
        log_source: Value for ``log_source`` (for example ``nginx`` or ``apache``).
    """

    name = "access_log"

    def __init__(
        self,
        *,
        pattern: str | None = None,
        keep_query: bool = False,
        log_source: str = "access_log",
    ) -> None:
        try:
            self._regex = re.compile(pattern or COMBINED_PATTERN)
        except re.error as exc:
            msg = f"invalid access log pattern: {exc}"
            raise ValueError(msg) from exc
        groups = set(self._regex.groupindex)
        missing = _REQUIRED_GROUPS - groups
        if "request" not in groups and not {"method", "path"} <= groups:
            missing.add("request (or method and path)")
        if missing:
            msg = f"access log pattern is missing named groups: {', '.join(sorted(missing))}"
            raise ValueError(msg)
        self.keep_query = keep_query
        self.log_source = log_source

    def parse_line(self, line: str, number: int, source: str) -> Event:
        match = self._regex.match(line)
        if match is None:
            raise ParseError("line does not match the access log pattern")
        groups = match.groupdict()
        timestamp = parse_clf_time(groups["time"])
        method, target, protocol = self._request(groups)
        path, query = target, None
        if target is not None and "?" in target and not self.keep_query:
            path, query = target.split("?", 1)
        status = int(groups["status"])
        size = groups.get("bytes")
        extra: dict[str, str | int | None] = {}
        if protocol:
            extra["protocol"] = protocol
        if query:
            extra["query"] = query
        if method is None and groups.get("request"):
            extra["request"] = unescape(groups["request"])  # unparseable, e.g. TLS on port 80
        referer = _optional(groups.get("referer"))
        if referer:
            extra["referer"] = unescape(referer)
        if groups.get("host"):
            extra["vhost"] = groups["host"]
        ip = normalise_ip(groups["ip"])
        if ip is None:
            extra["source_host"] = groups["ip"]
        return Event.model_validate(
            {
                "id": event_id(self.log_source, timestamp, line, f"{source}:{number}"),
                "timestamp": timestamp,
                "log_source": self.log_source,
                "event": EventInfo(
                    action="web.request",
                    category=EventCategory.WEB,
                    outcome=Outcome.FAILURE if status >= 400 else Outcome.SUCCESS,
                ),
                "source": {"ip": ip},
                "user": {"name": _optional(groups.get("user"))},
                "http": {
                    "method": method,
                    "path": path,
                    "status": status,
                    "bytes": int(size) if size and size != "-" else None,
                },
                "user_agent": _optional_unescaped(groups.get("agent")),
                "raw": line,
                "extra": extra,
            }
        )

    @staticmethod
    def _request(groups: dict[str, str | None]) -> tuple[str | None, str | None, str | None]:
        if groups.get("method") is not None or groups.get("path") is not None:
            return groups.get("method"), groups.get("path"), groups.get("protocol")
        request = unescape(groups.get("request") or "")
        match = _REQUEST_RE.match(request)
        if match is None:
            return None, None, None
        return match["method"], match["target"], match["protocol"]


def _optional(value: str | None) -> str | None:
    return None if value in (None, "", "-") else value


def _optional_unescaped(value: str | None) -> str | None:
    value = _optional(value)
    return unescape(value) if value is not None else None
