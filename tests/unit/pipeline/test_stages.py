"""Stages: dead letters, duplicates, incident closing and the at-least-once stage loop."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from prohori.incidents import IncidentSettings
from prohori.pipeline.messages import RawLog, Topic, dead_letter
from prohori.pipeline.stages import (
    Detector,
    IncidentStage,
    Normaliser,
    ParserSettings,
    StageMetrics,
    hold_time,
)
from prohori.pipeline.transport import MemoryTransport
from prohori.rules import builtin_rules_dir, load_rules
from prohori.schema import Alert, Event

T0 = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)
RULES = [r.rule for r in load_rules([builtin_rules_dir()]) if r.rule is not None]


def _raw(
    text: str, line: int = 1, parser: str = "app_json", source: str = "app.jsonl"
) -> dict[str, Any]:
    return RawLog(source=source, line=line, text=text, parser=parser, read_at=T0).model_dump(
        mode="json"
    )


def _signin(user: str, minute: int, outcome: str = "failure", ip: str = "203.0.113.9") -> str:
    when = (T0 + timedelta(minutes=minute)).isoformat().replace("+00:00", "Z")
    return json.dumps(
        {
            "time": when,
            "event": {
                "action": f"auth.signin.{outcome}",
                "category": "authentication",
                "outcome": outcome,
            },
            "source": {"ip": ip},
            "user": {"name": user},
        }
    )


def _messages(transport: MemoryTransport, topic: Topic) -> list[dict[str, Any]]:
    return [r.value for r in transport.poll(topic, "check", 100_000) if r.value is not None]


def test_metrics_as_dict_includes_extras() -> None:
    metrics = StageMetrics(consumed=2, extra={"late": 1})
    assert metrics.as_dict() == {
        "consumed": 2,
        "produced": 0,
        "dead_letters": 0,
        "duplicates": 0,
        "late": 1,
    }


def test_dead_letter_is_bounded_and_content_addressed() -> None:
    first = dead_letter("normalise", "raw-logs", "k" * 300, "r" * 300, "p" * 10_000)
    second = dead_letter("normalise", "raw-logs", "k" * 300, "r" * 300, "p" * 10_000)
    assert first == second
    assert len(first.payload) == 4096
    assert len(first.reason) == 200
    assert first.key is not None
    assert len(first.key) == 256


class TestNormaliser:
    def test_parses_lines_and_dead_letters_malformed_ones(self) -> None:
        transport = MemoryTransport()
        transport.publish(Topic.RAW_LOGS, "app.jsonl", _raw(_signin("alice", 0), line=1))
        transport.publish(Topic.RAW_LOGS, "app.jsonl", _raw("{not json", line=2))
        transport.publish(Topic.RAW_LOGS, "app.jsonl", _raw("   ", line=3))
        stage = Normaliser(transport)
        assert stage.step(100) == 3
        events = _messages(transport, Topic.EVENTS)
        letters = _messages(transport, Topic.DEAD_LETTER)
        assert len(events) == 1
        assert Event.model_validate(events[0]).user.name == "alice"
        assert [(d["key"], d["payload"]) for d in letters] == [("app.jsonl:2", "{not json")]
        assert stage.metrics.as_dict()["dead_letters"] == 1
        assert stage.parse_counts()["blank"] == 1
        # The batch is committed only after its output was published.
        assert transport.committed[("normalise", Topic.RAW_LOGS)] == 3

    def test_same_line_gives_the_same_event_id(self) -> None:
        transport = MemoryTransport()
        for _ in range(2):
            transport.publish(Topic.RAW_LOGS, "app.jsonl", _raw(_signin("alice", 0)))
        Normaliser(transport).step(100)
        ids = {e["id"] for e in _messages(transport, Topic.EVENTS)}
        assert len(ids) == 1

    def test_too_long_line_is_a_dead_letter(self) -> None:
        transport = MemoryTransport()
        message = RawLog(
            source="app.jsonl", line=1, text="x", parser="app_json", read_at=T0, too_long=True
        )
        transport.publish(Topic.RAW_LOGS, "app.jsonl", message.model_dump(mode="json"))
        Normaliser(transport).step(10)
        assert "longer than" in _messages(transport, Topic.DEAD_LETTER)[0]["reason"]

    def test_invalid_message_and_unknown_parser_are_dead_letters(self) -> None:
        transport = MemoryTransport()
        transport.publish(Topic.RAW_LOGS, "k", {"source": "a", "line": 0})
        transport.publish(Topic.RAW_LOGS, "k", _raw("x", parser="nope"))
        transport.append_raw(Topic.RAW_LOGS, b"garbage")
        stage = Normaliser(transport)
        stage.step(10)
        reasons = [d["reason"] for d in _messages(transport, Topic.DEAD_LETTER)]
        assert reasons[0].startswith("invalid line:")
        assert reasons[1] == "processing failed: KeyError"
        assert reasons[2] == "not valid JSON"
        assert stage.metrics.dead_letters == 3

    def test_parser_settings_create_each_parser(self) -> None:
        settings = ParserSettings(year=2026, keep_query=True)
        assert settings.create("auth_log", T0).name == "auth_log"
        assert settings.create("access_log", T0).name == "access_log"
        assert settings.create("app_json", T0).name == "app_json"
        with pytest.raises(ValueError, match="mapping"):
            settings.create("generic_json", T0)
        mapping = Path(__file__).resolve().parents[3] / "samples" / "mappings" / "payments.yaml"
        parser = ParserSettings(mapping=mapping).create("generic_json", T0)
        assert parser.name == "generic_json"


def _events(transport: MemoryTransport, lines: list[str]) -> list[Event]:
    for number, line in enumerate(lines, start=1):
        transport.publish(Topic.RAW_LOGS, "app.jsonl", _raw(line, line=number))
    Normaliser(transport).step(10_000)
    return [Event.model_validate(e) for e in _messages(transport, Topic.EVENTS)]


class TestDetector:
    def test_duplicates_are_dropped_before_the_engine(self) -> None:
        transport = MemoryTransport()
        events = _events(transport, [_signin("alice", m // 2) for m in range(12)])
        for event in events:  # every event delivered a second time
            transport.publish(Topic.EVENTS, event.id, event.model_dump(mode="json"))
        detector = Detector(transport, RULES, lateness=timedelta(minutes=5))
        detector.start()
        detector.step(10_000)
        detector.finish()
        assert detector.metrics.duplicates == len(events)
        assert detector.engine_counts["events_in"] == len(events)
        alerts = [Alert.model_validate(a) for a in _messages(transport, Topic.ALERTS)]
        assert alerts
        assert len({a.id for a in alerts}) == len(alerts)

    def test_a_live_detector_keeps_evaluating_after_a_day(self) -> None:
        transport = MemoryTransport()
        events = _events(transport, [_signin("alice", 0)])
        clock = [T0]
        detector = Detector(
            transport, RULES, lateness=timedelta(0), live=True, now=lambda: clock[0]
        )
        detector.start()
        detector.step(10)
        assert detector.engine_counts["future_events"] == 0
        # Two days later the stage is still running and a new event arrives.
        clock[0] = T0 + timedelta(days=2)
        later = events[0].model_copy(update={"timestamp": clock[0], "id": "evt-later"})
        transport.publish(Topic.EVENTS, later.id, later.model_dump(mode="json"))
        detector.step(10)
        assert detector.engine_counts["future_events"] == 0
        assert detector.engine_counts["events_in"] == 2

    def test_late_events_are_logged(self, caplog: pytest.LogCaptureFixture) -> None:
        transport = MemoryTransport()
        _events(transport, [_signin("alice", 60), _signin("bob", 0)])
        detector = Detector(transport, RULES, lateness=timedelta(0))
        detector.idle()  # nothing held yet
        detector.step(1)
        detector.idle()  # alice's event is released: the watermark is minute 60
        with caplog.at_level("WARNING"):
            detector.step(10)
        assert detector.engine_counts["late_events"] == 1
        assert "1 event(s) arrived too late" in caplog.text

    def test_idle_releases_the_reorder_buffer(self) -> None:
        transport = MemoryTransport()
        _events(transport, [_signin("alice", m // 2) for m in range(12)])
        detector = Detector(transport, RULES, lateness=timedelta(minutes=5))
        detector.step(10_000)
        held = detector.engine.state_size()["buffered_events"]
        assert held > 0
        detector.idle()
        assert detector.engine.state_size()["buffered_events"] == 0


class TestIncidentStage:
    def test_hold_time_covers_gap_windows_and_lateness(self) -> None:
        hold = hold_time(RULES, timedelta(minutes=30), timedelta(minutes=5))
        longest = max(
            [r.aggregate.window for r in RULES if r.aggregate is not None]
            + [r.sequence.within for r in RULES if r.sequence is not None]
        )
        assert hold == timedelta(minutes=35) + longest
        assert hold_time([], timedelta(minutes=30), timedelta(0)) == timedelta(minutes=30)

    def _alerts(self, transport: MemoryTransport, lines: list[str]) -> list[Alert]:
        _events(transport, lines)
        detector = Detector(transport, RULES, lateness=timedelta(0))
        detector.step(10_000)
        detector.finish()
        return [Alert.model_validate(a) for a in _messages(transport, Topic.ALERTS)]

    def test_groups_close_once_the_stream_has_moved_on(self) -> None:
        transport = MemoryTransport()
        early = [_signin("alice", m // 3) for m in range(15)]
        late = [_signin("bob", 600 + m // 3, ip="198.51.100.7") for m in range(15)]
        alerts = self._alerts(transport, early + late)
        assert {a.entities.get("source.ip") for a in alerts} >= {"203.0.113.9", "198.51.100.7"}
        stage = IncidentStage(transport, RULES, lateness=timedelta(0))
        stage.start()
        stage.step(10_000)
        # Alice's group ended hours before Bob's alerts: it is final. Bob's may still grow.
        published = _messages(transport, Topic.INCIDENTS)
        assert len(published) == 1
        assert "203.0.113.9" in published[0]["entities"]["source.ip"]
        assert stage.pending
        stage.finish()
        assert not stage.pending
        assert len(_messages(transport, Topic.INCIDENTS)) == 1  # the check group has read one
        assert stage.metrics.produced == 2

    def test_replayed_alerts_do_not_make_a_second_incident(self) -> None:
        transport = MemoryTransport()
        alerts = self._alerts(transport, [_signin("alice", m // 3) for m in range(15)])
        stage = IncidentStage(transport, RULES, lateness=timedelta(0))
        stage.step(10_000)
        stage.finish()
        for alert in alerts:
            transport.publish(Topic.ALERTS, alert.id, alert.model_dump(mode="json"))
        stage.step(10_000)
        stage.finish()
        assert stage.metrics.produced == 1
        assert stage.metrics.duplicates == len(alerts)

    def test_idle_close_uses_the_clock(self) -> None:
        transport = MemoryTransport()
        self._alerts(transport, [_signin("alice", m // 3) for m in range(15)])
        now = [0.0]
        stage = IncidentStage(
            transport,
            RULES,
            settings=IncidentSettings(),
            lateness=timedelta(0),
            clock=lambda: now[0],
            idle_close=30.0,
        )
        stage.step(10_000)
        assert stage.pending
        now[0] += 30.0
        stage.step(10_000)
        assert not stage.pending
        assert stage.metrics.produced == 1

    def test_invalid_alert_is_a_dead_letter(self) -> None:
        transport = MemoryTransport()
        transport.publish(Topic.ALERTS, "a", {"id": "nope"})
        stage = IncidentStage(transport, RULES, lateness=timedelta(0))
        stage.step(10)
        assert stage.metrics.dead_letters == 1
        stage.tick()  # nothing pending: no work
