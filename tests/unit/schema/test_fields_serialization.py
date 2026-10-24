"""Tests for dotted field access and JSON Lines helpers."""

import io
from datetime import UTC, datetime

import pytest
from hypothesis import given

from prohori.schema import (
    FIELD_PATHS,
    Event,
    from_json,
    get_field,
    is_valid_path,
    read_jsonl,
    to_json,
    write_jsonl,
)
from tests.unit.schema.strategies import events

EVENT = Event.model_validate(
    {
        "timestamp": datetime(2026, 10, 24, 13, 50, tzinfo=UTC),
        "log_source": "nginx",
        "event": {"action": "web.request", "category": "web", "outcome": "failure"},
        "source": {"ip": "198.51.100.23"},
        "http": {"method": "GET", "path": "/.env", "status": 404, "bytes": 0},
        "raw": "GET /.env",
        "extra": {"vhost": "shop.example", "upstream_ms": 12},
    }
)


class TestFieldPaths:
    def test_documented_paths_present(self) -> None:
        expected = {
            "timestamp",
            "log_source",
            "event.action",
            "event.category",
            "event.outcome",
            "event.severity",
            "event.reason",
            "source.ip",
            "user.name",
            "user.id",
            "user.email_hash",
            "http.method",
            "http.path",
            "http.status",
            "http.bytes",
            "user_agent",
            "client",
            "host",
            "request_id",
            "raw",
        }
        assert expected <= FIELD_PATHS

    @pytest.mark.parametrize(
        ("path", "valid"),
        [("event.action", True), ("extra.vhost", True), ("extra.", False), ("event", False)],
    )
    def test_is_valid_path(self, path: str, valid: bool) -> None:
        assert is_valid_path(path) is valid


class TestGetField:
    @pytest.mark.parametrize(
        ("path", "value"),
        [
            ("event.action", "web.request"),
            ("event.category", "web"),
            ("event.outcome", "failure"),
            ("event.severity", None),
            ("source.ip", "198.51.100.23"),
            ("http.status", 404),
            ("http.bytes", 0),
            ("user.name", None),
            ("timestamp", "2026-10-24T13:50:00+00:00"),
            ("extra.vhost", "shop.example"),
            ("extra.upstream_ms", 12),
            ("extra.missing", None),
        ],
    )
    def test_values(self, path: str, value: object) -> None:
        assert get_field(EVENT, path) == value

    @pytest.mark.parametrize("path", ["nope", "event.nope", "event"])
    def test_unknown_path_raises(self, path: str) -> None:
        with pytest.raises(KeyError):
            get_field(EVENT, path)

    @given(events)
    def test_every_path_readable(self, event: Event) -> None:
        for path in FIELD_PATHS:
            get_field(event, path)


class TestSerialization:
    def test_to_and_from_json(self) -> None:
        assert from_json(Event, to_json(EVENT, indent=2)) == EVENT

    def test_jsonl_round_trip(self) -> None:
        other = EVENT.model_copy(update={"id": "evt-other"})
        buffer = io.StringIO()
        assert write_jsonl([EVENT, other], buffer) == 2
        lines = buffer.getvalue().splitlines(keepends=True)
        assert len(lines) == 2
        assert list(read_jsonl(Event, ["\n", *lines, "   \n"])) == [EVENT, other]

    def test_jsonl_handles_crlf(self) -> None:
        line = to_json(EVENT) + "\r\n"
        assert list(read_jsonl(Event, [line])) == [EVENT]
