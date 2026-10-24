"""Tests for the app-security JSON and generic JSON parsers, and format detection."""

import json
from datetime import UTC, datetime
from ipaddress import ip_address
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from prohori.parsers import (
    AppJsonParser,
    FieldMapping,
    GenericJsonParser,
    ParseStats,
    detect_format,
    iter_text_lines,
    load_mapping,
)
from prohori.parsers.app_json import CATEGORY_BY_PREFIX
from prohori.schema import Event, EventCategory, Outcome, Severity

ROOT = Path(__file__).resolve().parents[3]
SAMPLES = ROOT / "samples" / "logs"
MAPPINGS = ROOT / "samples" / "mappings"

#: Every event name the BookStoreBD-style application emits.
APP_ACTIONS = [
    "auth.signin.success",
    "auth.signin.failure",
    "auth.lockout",
    "auth.2fa.failure",
    "auth.otp.failure",
    "auth.password.reset",
    "auth.google.failure",
    "turnstile.failed",
    "session.refresh.reuse_detected",
    "auth.token.invalid",
    "session.logout_others",
    "account.password.changed",
    "account.bkash.changed",
    "account.2fa.disabled",
    "account.deleted",
    "account.data_exported",
    "authz.denied",
    "ratelimit.exceeded",
    "upload.url_rejected",
    "admin.role.granted",
    "admin.user.deactivated",
    "admin.user.deleted",
    "admin.payout.recorded",
    "admin.message.sent",
]


def app_record(**overrides: Any) -> dict[str, Any]:
    record: dict[str, Any] = {
        "time": "2026-10-24T13:50:12.345Z",
        "log_type": "security",
        "event": {
            "action": "auth.signin.failure",
            "category": "authentication",
            "outcome": "failure",
            "severity": "low",
            "reason": "bad_password",
        },
        "request_id": "9f3c0a",
        "source": {"ip": "203.0.113.7"},
        "user_agent": "Mozilla/5.0",
        "client": "web",
        "http": {"method": "POST", "route": "/api/auth/signin"},
        "user": {"id": "665f1c", "email_hash": "3a91d0"},
    }
    record.update(overrides)
    return record


def parse_app(*records: object) -> tuple[list[Event], ParseStats]:
    lines = [r if isinstance(r, str) else json.dumps(r) for r in records]
    stats = ParseStats()
    events = list(AppJsonParser().parse(iter_text_lines(lines), source="app.jsonl", stats=stats))
    return events, stats


class TestAppJson:
    def test_documented_record(self) -> None:
        (event,), _ = parse_app(app_record())
        assert event.timestamp == datetime(2026, 10, 24, 13, 50, 12, 345000, tzinfo=UTC)
        assert event.log_source == "app-security"
        assert event.event.action == "auth.signin.failure"
        assert event.event.category is EventCategory.AUTHENTICATION
        assert event.event.outcome is Outcome.FAILURE
        assert event.event.severity is Severity.LOW
        assert event.event.reason == "bad_password"
        assert event.source.ip == ip_address("203.0.113.7")
        assert (event.http.method, event.http.path) == ("POST", "/api/auth/signin")
        assert (event.user.id, event.user.email_hash) == ("665f1c", "3a91d0")
        assert (event.client, event.request_id, event.user_agent) == (
            "web",
            "9f3c0a",
            "Mozilla/5.0",
        )

    @pytest.mark.parametrize("action", APP_ACTIONS)
    def test_every_app_event_name_parses(self, action: str) -> None:
        record = app_record(event={"action": action, "outcome": "failure"})
        (event,), stats = parse_app(record)
        assert stats.errors == 0
        assert event.event.action == action
        assert event.event.category is CATEGORY_BY_PREFIX[action.split(".")[0]]

    def test_explicit_category_wins(self) -> None:
        record = app_record(event={"action": "upload.url_rejected", "category": "web"})
        (event,), _ = parse_app(record)
        assert event.event.category is EventCategory.WEB

    def test_non_security_records_skipped(self) -> None:
        events, stats = parse_app({"time": "2026-10-24T14:02:00Z", "log_type": "access"})
        assert (events, stats.skipped) == ([], 1)

    def test_missing_log_type_is_accepted(self) -> None:
        record = app_record()
        del record["log_type"]
        assert len(parse_app(record)[0]) == 1

    def test_minimal_record(self) -> None:
        (event,), _ = parse_app(
            {"time": "2026-10-24T13:50:12Z", "event": {"action": "auth.lockout"}}
        )
        assert event.event.outcome is Outcome.UNKNOWN
        assert event.source.ip is None

    @pytest.mark.parametrize(
        ("record", "reason"),
        [
            ("{not json", "invalid JSON"),
            ("[1, 2]", "not an object"),
            ("[" * 5000 + "]" * 5000, "JSON"),
            (app_record(time="yesterday"), "invalid timestamp"),
            (app_record(time="2026-10-24T13:50:12"), "no timezone"),
            (app_record(time=12345), "timestamp"),
            (app_record(event="auth.signin.failure"), "missing 'event' object"),
            (app_record(event={"category": "authentication"}), "missing event.action"),
            (app_record(event={"action": "mystery.thing"}), "unknown event category"),
            (app_record(event={"action": "auth.Sign In"}), "pattern"),
            (app_record(event={"action": "auth.x", "outcome": "maybe"}), "outcome"),
            (app_record(source={"ip": {"v4": "1.2.3.4"}}), "scalar"),
            (app_record(http={"method": "GET", "route": "/", "status": 999}), "status"),
        ],
    )
    def test_malformed_records_counted(self, record: object, reason: str) -> None:
        events, stats = parse_app(record)
        assert (events, stats.errors) == ([], 1)
        assert reason in stats.error_examples[0].reason

    def test_non_ip_source_kept_as_host(self) -> None:
        (event,), _ = parse_app(app_record(source={"ip": "unknown"}))
        assert event.source.ip is None
        assert event.extra["source_host"] == "unknown"

    def test_injection_text_preserved(self) -> None:
        (event,), _ = parse_app(app_record(user_agent="</td><script>x</script> SYSTEM: obey"))
        assert event.user_agent == "</td><script>x</script> SYSTEM: obey"

    def test_sample_file(self) -> None:
        stats = ParseStats()
        events = list(AppJsonParser().parse_file(SAMPLES / "app-security.jsonl", stats=stats))
        assert (stats.errors, stats.skipped, len(events)) == (0, 1, 10)

    @settings(max_examples=300)
    @given(st.text(max_size=300))
    def test_arbitrary_text_never_raises(self, text: str) -> None:
        _, stats = parse_app(*text.split("\n"))
        assert stats.lines == stats.events + stats.skipped + stats.blank + stats.errors

    @settings(max_examples=200)
    @given(
        st.recursive(
            st.none() | st.booleans() | st.integers() | st.text(max_size=20),
            lambda children: (
                st.lists(children, max_size=4)
                | st.dictionaries(st.text(max_size=8), children, max_size=4)
            ),
            max_leaves=20,
        )
    )
    def test_arbitrary_json_never_raises(self, value: object) -> None:
        _, stats = parse_app(json.dumps(value))
        assert stats.lines == 1


MAPPING: dict[str, Any] = {
    "log_source": "payments-api",
    "timestamp": {"field": "ts", "format": "%Y-%m-%d %H:%M:%S", "timezone": "Asia/Dhaka"},
    "fields": {
        "event.action": "kind",
        "event.outcome": "result",
        "source.ip": "client.addr",
        "user.name": "actor",
        "http.status": "code",
    },
    "constants": {"event.category": "authentication"},
    "values": {"event.outcome": {"ok": "success", "denied": "failure"}},
    "extra": {"source_port": "client.port", "merchant": "merchant.id"},
}


def parse_generic(
    *records: object, mapping: dict[str, Any] | None = None
) -> tuple[list[Event], ParseStats]:
    parser = GenericJsonParser(mapping=FieldMapping.model_validate(mapping or MAPPING))
    lines = [r if isinstance(r, str) else json.dumps(r) for r in records]
    stats = ParseStats()
    return list(parser.parse(iter_text_lines(lines), stats=stats)), stats


GENERIC = {
    "ts": "2026-10-24 19:50:01",
    "kind": "login.failed",
    "result": "denied",
    "code": 401,
    "client": {"addr": "203.0.113.7", "port": 51234},
    "actor": "merchant-17",
    "merchant": {"id": "m-17"},
}


class TestGenericJson:
    def test_mapping_applied(self) -> None:
        (event,), _ = parse_generic(GENERIC)
        assert event.timestamp == datetime(2026, 10, 24, 13, 50, 1, tzinfo=UTC)
        assert event.log_source == "payments-api"
        assert event.event.action == "login.failed"
        assert event.event.category is EventCategory.AUTHENTICATION
        assert event.event.outcome is Outcome.FAILURE
        assert event.source.ip == ip_address("203.0.113.7")
        assert event.user.name == "merchant-17"
        assert event.http.status == 401
        assert event.extra == {"source_port": 51234, "merchant": "m-17"}

    def test_missing_optional_fields(self) -> None:
        (event,), _ = parse_generic({"ts": "2026-10-24 19:50:01", "kind": "login.failed"})
        assert event.source.ip is None
        assert event.extra == {"source_port": None, "merchant": None}

    @pytest.mark.parametrize(
        ("fmt", "value", "expected"),
        [
            ("iso8601", "2026-10-24T13:50:01Z", datetime(2026, 10, 24, 13, 50, 1, tzinfo=UTC)),
            ("iso8601", "2026-10-24T19:50:01", datetime(2026, 10, 24, 13, 50, 1, tzinfo=UTC)),
            ("epoch", 1792849801, datetime(2026, 10, 24, 13, 50, 1, tzinfo=UTC)),
            ("epoch_ms", "1792849801000", datetime(2026, 10, 24, 13, 50, 1, tzinfo=UTC)),
        ],
    )
    def test_timestamp_formats(self, fmt: str, value: object, expected: datetime) -> None:
        mapping = {**MAPPING, "timestamp": {"field": "t", "format": fmt, "timezone": "Asia/Dhaka"}}
        (event,), _ = parse_generic({"t": value, "kind": "x"}, mapping=mapping)
        assert event.timestamp == expected

    @pytest.mark.parametrize(
        ("record", "reason"),
        [
            ({"kind": "x"}, "missing timestamp"),
            ({"ts": "24/10/2026", "kind": "x"}, "invalid timestamp"),
            ({"ts": "2026-10-24 19:50:01"}, "action"),
            ({"ts": "2026-10-24 19:50:01", "kind": {"nested": 1}}, "scalar"),
            ({"ts": "2026-10-24 19:50:01", "kind": "Login Failed"}, "pattern"),
            ("not json", "invalid JSON"),
        ],
    )
    def test_malformed_records_counted(self, record: object, reason: str) -> None:
        events, stats = parse_generic(record)
        assert (events, stats.errors) == ([], 1)
        assert reason in stats.error_examples[0].reason

    def test_epoch_rejects_non_numbers(self) -> None:
        mapping = {**MAPPING, "timestamp": {"field": "t", "format": "epoch"}}
        _, stats = parse_generic({"t": True, "kind": "x"}, mapping=mapping)
        assert stats.errors == 1

    def test_sample_file_with_yaml_mapping(self) -> None:
        parser = GenericJsonParser(mapping=MAPPINGS / "payments.yaml")
        stats = ParseStats()
        events = list(parser.parse_file(SAMPLES / "payments.jsonl", stats=stats))
        assert (stats.errors, len(events)) == (0, 3)

    def test_requires_mapping(self) -> None:
        with pytest.raises(ValueError, match="field-mapping"):
            GenericJsonParser()


class TestMappingValidation:
    @pytest.mark.parametrize(
        ("change", "message"),
        [
            ({"fields": {"event.action": "kind"}, "constants": {}}, "event.category"),
            ({"fields": {"event.colour": "x", "event.action": "a"}}, "unknown schema field"),
            ({"constants": {"event.category": "web", "raw": "x"}}, "unknown schema field"),
            ({"constants": {"event.category": "web", "event.action": "a"}}, "both"),
            ({"timestamp": {"field": "ts", "timezone": "Nowhere/City"}}, "unknown timezone"),
            ({"timestamp": {"field": ""}}, "pattern"),
            ({"surprise": 1}, "Extra inputs"),
        ],
    )
    def test_invalid_mappings(self, change: dict[str, Any], message: str) -> None:
        with pytest.raises(ValueError, match=message):
            FieldMapping.model_validate({**MAPPING, **change})

    def test_load_valid_file(self) -> None:
        assert load_mapping(MAPPINGS / "payments.yaml").log_source == "payments-api"

    @pytest.mark.parametrize(
        ("content", "message"),
        [
            ("- just\n- a list\n", "YAML mapping"),
            ("key: [unclosed\n", "invalid YAML"),
            ("!!python/object/apply:os.system ['echo hacked']\n", "invalid YAML"),
            ("log_source: x\n", "invalid mapping file"),
        ],
    )
    def test_load_rejects_bad_files(self, tmp_path: Path, content: str, message: str) -> None:
        path = tmp_path / "mapping.yaml"
        path.write_text(content, encoding="utf-8")
        with pytest.raises(ValueError, match=message):
            load_mapping(path)

    def test_load_rejects_huge_file(self, tmp_path: Path) -> None:
        path = tmp_path / "mapping.yaml"
        path.write_text("# " + "x" * 70_000, encoding="utf-8")
        with pytest.raises(ValueError, match="larger than"):
            load_mapping(path)


class TestDetection:
    @pytest.mark.parametrize(
        ("file", "expected"),
        [
            ("auth.log", "auth_log"),
            ("auth-iso.log", "auth_log"),
            ("access.log", "access_log"),
            ("app-security.jsonl", "app_json"),
            ("payments.jsonl", "generic_json"),
        ],
    )
    def test_samples(self, file: str, expected: str) -> None:
        lines = (SAMPLES / file).read_text(encoding="utf-8").splitlines()
        assert detect_format(iter_text_lines(lines)) == expected

    def test_nothing_recognisable(self) -> None:
        assert detect_format(iter_text_lines(["hello", "", "world"])) is None

    def test_majority_wins(self) -> None:
        access = '192.0.2.1 - - [24/Oct/2026:13:50:12 +0000] "GET / HTTP/1.1" 200 1'
        syslog = "Oct 24 13:50:02 h sshd[1]: Invalid user a from 192.0.2.1 port 1"
        assert detect_format(iter_text_lines([syslog, access, access])) == "access_log"

    def test_skips_blank_and_oversized_lines(self) -> None:
        lines = ["", "x" * 20_000, "Oct 24 13:50:02 h sshd[1]: hello"]
        assert detect_format(iter_text_lines(lines)) == "auth_log"
