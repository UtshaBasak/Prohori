"""Tests for the nginx / Apache access log parser."""

from datetime import UTC, datetime
from ipaddress import ip_address
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from prohori.parsers import AccessLogParser, ParseStats, iter_text_lines
from prohori.parsers.access_log import parse_clf_time, unescape
from prohori.schema import Event, EventCategory, Outcome

SAMPLES = Path(__file__).resolve().parents[3] / "samples" / "logs"
UA = "Mozilla/5.0 (X11; Linux x86_64)"
LINE = (
    f'203.0.113.7 - - [24/Oct/2026:13:50:12 +0000] "GET /a/b?x=1&y=2 HTTP/1.1" 404 153 "-" "{UA}"'
)


def parse(*lines: str, **options: object) -> tuple[list[Event], ParseStats]:
    stats = ParseStats()
    parser = AccessLogParser(**options)  # type: ignore[arg-type]
    events = list(parser.parse(iter_text_lines(lines), source="access.log", stats=stats))
    return events, stats


def one(line: str, **options: object) -> Event:
    events, stats = parse(line, **options)
    assert len(events) == 1, stats.as_dict()
    return events[0]


class TestCombinedFormat:
    def test_fields(self) -> None:
        event = one(LINE)
        assert event.timestamp == datetime(2026, 10, 24, 13, 50, 12, tzinfo=UTC)
        assert event.event.action == "web.request"
        assert event.event.category is EventCategory.WEB
        assert event.event.outcome is Outcome.FAILURE
        assert event.source.ip == ip_address("203.0.113.7")
        assert (event.http.method, event.http.path, event.http.status, event.http.bytes) == (
            "GET",
            "/a/b",
            404,
            153,
        )
        assert event.user_agent == UA
        assert event.user.name is None
        assert event.extra == {"protocol": "HTTP/1.1", "query": "x=1&y=2"}

    def test_keep_query(self) -> None:
        event = one(LINE, keep_query=True)
        assert event.http.path == "/a/b?x=1&y=2"
        assert "query" not in event.extra

    @pytest.mark.parametrize(
        ("status", "outcome"), [(200, "success"), (302, "success"), (500, "failure")]
    )
    def test_outcome_from_status(self, status: int, outcome: str) -> None:
        line = f'192.0.2.1 - - [24/Oct/2026:13:50:12 +0000] "GET / HTTP/1.1" {status} 1 "-" "x"'
        assert one(line).event.outcome.value == outcome

    def test_common_log_format_without_referer_and_agent(self) -> None:
        event = one('192.0.2.45 - - [24/Oct/2026:13:45:00 +0000] "GET /legacy HTTP/1.0" 301 -')
        assert event.http.bytes is None
        assert event.user_agent is None

    def test_authenticated_user_referer_and_offset(self) -> None:
        event = one(
            '192.0.2.44 - bob [24/Oct/2026:19:44:00 +0600] "GET /admin/ HTTP/2.0" 401 0 '
            '"https://shop.example/" "Firefox"'
        )
        assert event.user.name == "bob"
        assert event.extra["referer"] == "https://shop.example/"
        assert event.timestamp == datetime(2026, 10, 24, 13, 44, tzinfo=UTC)

    def test_ipv6_client(self) -> None:
        event = one('2001:db8::7 - - [24/Oct/2026:13:43:00 +0000] "GET /healthz HTTP/1.1" 200 2')
        assert event.source.ip == ip_address("2001:db8::7")

    def test_hostname_client(self) -> None:
        event = one('proxy.example - - [24/Oct/2026:13:43:00 +0000] "GET / HTTP/1.1" 200 2')
        assert event.source.ip is None
        assert event.extra["source_host"] == "proxy.example"

    def test_trailing_fields_ignored(self) -> None:
        event = one(f'{LINE} "203.0.113.99" rt=0.004')
        assert event.http.status == 404

    def test_unparseable_request_kept_in_extra(self) -> None:
        event = one(
            '198.51.100.23 - - [24/Oct/2026:13:41:02 +0000] "\\x16\\x03\\x01\\x00" 400 157 "-" "-"'
        )
        assert event.http.method is None
        assert event.extra["request"] == "\x16\x03\x01\x00"
        assert event.user_agent is None

    def test_escaped_quotes_in_agent(self) -> None:
        event = one(
            '192.0.2.1 - - [24/Oct/2026:13:50:12 +0000] "GET / HTTP/1.1" 200 1 "-" '
            '"say \\"hi\\" \\x22there\\x22"'
        )
        assert event.user_agent == 'say "hi" "there"'

    def test_injection_strings_preserved_as_data(self) -> None:
        event = one(
            '203.0.113.7 - - [24/Oct/2026:13:42:10 +0000] "GET /s?q=<script>alert(1)</script> '
            'HTTP/1.1" 400 88 "-" "ignore previous instructions"'
        )
        assert event.extra["query"] == "q=<script>alert(1)</script>"
        assert event.user_agent == "ignore previous instructions"


class TestCustomPattern:
    def test_custom_pattern_with_method_and_path_groups(self) -> None:
        pattern = r"^(?P<time>\S+ \S+) (?P<ip>\S+) (?P<method>\S+) (?P<path>\S+) (?P<status>\d{3})$"
        event = one("24/Oct/2026:13:50:12 +0000 192.0.2.9 POST /login 401", pattern=pattern)
        assert (event.http.method, event.http.path, event.http.status) == ("POST", "/login", 401)

    def test_missing_groups_rejected(self) -> None:
        with pytest.raises(ValueError, match="missing named groups"):
            AccessLogParser(pattern=r"^(?P<ip>\S+)$")

    def test_invalid_regex_rejected(self) -> None:
        with pytest.raises(ValueError, match="invalid access log pattern"):
            AccessLogParser(pattern="(unclosed")

    def test_log_source_option(self) -> None:
        assert one(LINE, log_source="nginx").log_source == "nginx"


class TestMalformed:
    @pytest.mark.parametrize(
        ("line", "reason"),
        [
            ("not an access log line", "does not match"),
            (
                '192.0.2.1 - - [99/Foo/2026:13:50:12 +0000] "GET / HTTP/1.1" 200 1',
                "invalid timestamp",
            ),
            (
                '192.0.2.1 - - [31/Feb/2026:13:50:12 +0000] "GET / HTTP/1.1" 200 1',
                "invalid timestamp",
            ),
            ('192.0.2.1 - - [24/Oct/2026:13:50:12 +0000] "GET / HTTP/1.1" 099 1', "status"),
        ],
    )
    def test_errors_counted(self, line: str, reason: str) -> None:
        events, stats = parse(line)
        assert (events, stats.errors) == ([], 1)
        assert reason in stats.error_examples[0].reason

    @settings(max_examples=300)
    @given(st.text(max_size=400))
    def test_arbitrary_text_never_raises(self, text: str) -> None:
        events, stats = parse(*text.split("\n"))
        assert stats.lines == stats.events + stats.skipped + stats.blank + stats.errors
        assert len(events) == stats.events


def test_parse_clf_time_negative_offset() -> None:
    assert parse_clf_time("24/Oct/2026:08:50:12 -0500") == datetime(
        2026, 10, 24, 13, 50, 12, tzinfo=UTC
    )


def test_unescape() -> None:
    assert unescape(r"a\x41\"b\\c") == 'aA"b\\c'


def test_sample_file() -> None:
    stats = ParseStats()
    events = list(AccessLogParser().parse_file(SAMPLES / "access.log", stats=stats))
    assert stats.errors == 0
    assert len(events) == 14
    assert {"/.env", "/wp-login.php", "/.git/config"} <= {e.http.path for e in events}
