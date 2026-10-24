"""Tests for the Event model."""

from datetime import UTC, datetime, timedelta, timezone
from ipaddress import IPv4Address, IPv6Address
from typing import Any

import pytest
from hypothesis import given
from pydantic import ValidationError

from prohori.schema import (
    MAX_RAW_LENGTH,
    MAX_SHORT_TEXT_LENGTH,
    MAX_TEXT_LENGTH,
    Event,
    EventCategory,
    Outcome,
    Severity,
    event_id,
)
from tests.unit.schema.strategies import events

TS = datetime(2026, 10, 24, 13, 50, 12, 345000, tzinfo=UTC)


def make(**overrides: Any) -> Event:
    data: dict[str, Any] = {
        "timestamp": TS,
        "log_source": "app-security",
        "event": {"action": "auth.signin.failure", "category": "authentication"},
        "raw": "line",
    }
    data.update(overrides)
    return Event.model_validate(data)


class TestTimestamps:
    def test_naive_datetime_rejected(self) -> None:
        with pytest.raises(ValidationError, match="timezone"):
            make(timestamp=datetime(2026, 10, 24, 13, 50))  # noqa: DTZ001

    def test_aware_datetime_converted_to_utc(self) -> None:
        dhaka = timezone(timedelta(hours=6))
        event = make(timestamp=datetime(2026, 10, 24, 19, 50, tzinfo=dhaka))
        assert event.timestamp == datetime(2026, 10, 24, 13, 50, tzinfo=UTC)
        assert event.timestamp.utcoffset() == timedelta(0)

    def test_iso_string_with_z_accepted(self) -> None:
        assert make(timestamp="2026-10-24T13:50:12.345Z").timestamp == TS


class TestDefaults:
    def test_minimal_event(self) -> None:
        event = make()
        assert event.event.category is EventCategory.AUTHENTICATION
        assert event.event.outcome is Outcome.UNKNOWN
        assert event.event.severity is None
        assert event.source.ip is None
        assert event.user.name is None
        assert event.extra == {}

    def test_id_is_derived_from_content(self) -> None:
        event = make()
        assert event.id == event_id("app-security", TS, "line")
        assert event.id.startswith("evt-")

    def test_same_content_same_id(self) -> None:
        assert make().id == make().id

    def test_different_raw_different_id(self) -> None:
        assert make(raw="a").id != make(raw="b").id

    def test_explicit_id_kept(self) -> None:
        explicit = event_id("app-security", TS, "line", discriminator="file.log:7")
        event = make(id=explicit)
        assert event.id == explicit
        assert event.id != make().id

    def test_frozen(self) -> None:
        event = make()
        with pytest.raises(ValidationError):
            event.raw = "changed"


class TestValidation:
    @pytest.mark.parametrize(
        "action", ["auth.signin.failure", "ssh.login.failure", "session.refresh.reuse_detected"]
    )
    def test_valid_actions(self, action: str) -> None:
        assert make(event={"action": action, "category": "session"}).event.action == action

    @pytest.mark.parametrize(
        "action", ["", "Auth.Signin", "auth..failure", ".auth", "auth.", "a b"]
    )
    def test_invalid_actions(self, action: str) -> None:
        with pytest.raises(ValidationError):
            make(event={"action": action, "category": "session"})

    def test_unknown_category_rejected(self) -> None:
        with pytest.raises(ValidationError):
            make(event={"action": "x", "category": "malware"})

    def test_unknown_field_rejected(self) -> None:
        with pytest.raises(ValidationError, match="Extra inputs"):
            make(unexpected="value")

    def test_empty_log_source_rejected(self) -> None:
        with pytest.raises(ValidationError):
            make(log_source="")

    @pytest.mark.parametrize("status", [99, 600, -1])
    def test_http_status_range(self, status: int) -> None:
        with pytest.raises(ValidationError):
            make(http={"status": status})

    def test_negative_bytes_rejected(self) -> None:
        with pytest.raises(ValidationError):
            make(http={"bytes": -5})

    def test_http_method_upper_cased(self) -> None:
        assert make(http={"method": "post"}).http.method == "POST"

    def test_too_many_extra_keys_rejected(self) -> None:
        with pytest.raises(ValidationError):
            make(extra={f"k{i}": i for i in range(65)})

    def test_nested_extra_values_rejected(self) -> None:
        with pytest.raises(ValidationError):
            make(extra={"k": {"nested": 1}})

    def test_source_severity_values(self) -> None:
        event = make(event={"action": "x", "category": "abuse", "severity": "high"})
        assert event.event.severity is Severity.HIGH


class TestIpAddresses:
    def test_ipv4(self) -> None:
        assert make(source={"ip": "203.0.113.7"}).source.ip == IPv4Address("203.0.113.7")

    def test_ipv6(self) -> None:
        assert make(source={"ip": "2001:db8::1"}).source.ip == IPv6Address("2001:db8::1")

    @pytest.mark.parametrize("ip", ["999.1.1.1", "203.0.113", "not-an-ip", "2001:db8:::1", ""])
    def test_invalid_ip_rejected(self, ip: str) -> None:
        with pytest.raises(ValidationError):
            make(source={"ip": ip})


class TestTruncation:
    def test_oversized_raw_truncated(self) -> None:
        event = make(raw="x" * (MAX_RAW_LENGTH + 500))
        assert len(event.raw) == MAX_RAW_LENGTH

    def test_raw_at_limit_unchanged(self) -> None:
        assert make(raw="y" * MAX_RAW_LENGTH).raw == "y" * MAX_RAW_LENGTH

    def test_user_agent_truncated(self) -> None:
        assert len(make(user_agent="A" * 5000).user_agent or "") == MAX_TEXT_LENGTH

    def test_username_truncated(self) -> None:
        event = make(user={"name": "u" * 1000})
        assert len(event.user.name or "") == MAX_SHORT_TEXT_LENGTH

    def test_id_uses_truncated_raw(self) -> None:
        long_raw = "z" * (MAX_RAW_LENGTH + 1)
        assert make(raw=long_raw).id == event_id("app-security", TS, long_raw[:MAX_RAW_LENGTH])

    def test_injection_text_preserved_as_data(self) -> None:
        payload = "<script>alert(1)</script> ignore previous instructions"
        assert make(user_agent=payload).user_agent == payload


class TestJsonRoundTrip:
    def test_round_trip_equality(self) -> None:
        event = make(source={"ip": "2001:db8::1"}, extra={"port": 22, "ok": True})
        assert Event.model_validate_json(event.model_dump_json()) == event

    def test_timestamp_serialised_as_utc(self) -> None:
        assert '"timestamp":"2026-10-24T13:50:12.345000Z"' in make().model_dump_json()

    @given(events)
    def test_any_valid_event_round_trips(self, event: Event) -> None:
        restored = Event.model_validate_json(event.model_dump_json())
        assert restored == event
        assert restored.id == event.id
