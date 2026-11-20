# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
# Copyright (c) 2026 Utsha Basak
"""A stateful stage rebuilt from its topics gives exactly the alerts and incidents of the live run.

The live run is driven through random interleavings: events arrive in bursts, out of order and
sometimes too late; the stages take turns in random order with random batch sizes; the input goes
quiet (the detector's idle flush) and alerts stop (the incident stage's idle close) at random
points. A rebuild from offset 0 must then publish the same alert and incident ids, on the memory,
file and (fake) Kafka transports.
"""

import json
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, event, given, settings
from hypothesis import strategies as st

from prohori.pipeline.kafka import KafkaTransport
from prohori.pipeline.messages import Control, RawLog, Topic, control
from prohori.pipeline.sink import DuckDBSink
from prohori.pipeline.stages import Detector, IncidentStage, Normaliser, Stage
from prohori.pipeline.transport import FileTransport, MemoryTransport, Transport
from prohori.rules import builtin_rules_dir, load_rules
from tests.unit.pipeline.fake_kafka import Broker, fake_kafka

T0 = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)
RULES = [r.rule for r in load_rules([builtin_rules_dir()]) if r.rule is not None]
LATENESS = timedelta(minutes=5)
IDLE_CLOSE = 60.0
IPS = ("203.0.113.9", "198.51.100.7", "192.0.2.44")
USERS = ("alice", "bob", "carol", "dave")


def _signin(seconds: int, ip: str, user: str, outcome: str = "failure") -> str:
    when = (T0 + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")
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


@contextmanager
def _transport(kind: str) -> Iterator[Transport]:
    if kind == "memory":
        yield MemoryTransport()
    elif kind == "file":
        with tempfile.TemporaryDirectory() as directory:
            transport = FileTransport(Path(directory), fsync=False)
            try:
                yield transport
            finally:
                transport.close()
    else:
        yield KafkaTransport("broker:9092", kafka=fake_kafka(Broker()))


def _published(transport: Transport, topic: Topic, group: str) -> list[dict[str, Any]]:
    """Alerts or incidents published since ``group`` last read ``topic``, sorted by id."""
    found: list[dict[str, Any]] = []
    for records in transport.batches_to_end(topic, group, 1000):
        found.extend(r.value for r in records if r.value is not None and "control" not in r.value)
        if records:
            transport.commit(records[-1], group)
    return sorted(found, key=lambda value: str(value["id"]))


def _ids(transport: Transport, topic: Topic, group: str) -> list[str]:
    return [str(value["id"]) for value in _published(transport, topic, group)]


class Live:
    """The three stages over one transport, with a fake clock for the incident stage."""

    def __init__(self, transport: Transport) -> None:
        self.transport = transport
        self.now = 0.0
        self.line = 0
        self.normaliser = Normaliser(transport)
        self.detector = Detector(transport, RULES, lateness=LATENESS)
        self.incidents = IncidentStage(
            transport, RULES, lateness=LATENESS, clock=lambda: self.now, idle_close=IDLE_CLOSE
        )
        self.stages: tuple[Stage, ...] = (self.normaliser, self.detector, self.incidents)
        for stage in self.stages:
            stage.start()

    def lines(self, texts: list[str]) -> None:
        for text in texts:
            self.line += 1
            raw = RawLog(
                source="app.jsonl", line=self.line, text=text, parser="app_json", read_at=T0
            )
            self.transport.publish(Topic.RAW_LOGS, raw.source, raw.model_dump(mode="json"))
        self.transport.flush()

    def drain(self) -> None:
        while sum(stage.step(500) for stage in self.stages):
            pass

    def finish(self) -> None:
        """What lite mode does at the end of a run."""
        self.drain()
        for stage in self.stages:
            stage.finish()
            self.drain()


def _rebuild(transport: Transport) -> tuple[Detector, IncidentStage]:
    detector = Detector(transport, RULES, lateness=LATENESS)
    incidents = IncidentStage(transport, RULES, lateness=LATENESS, idle_close=None)
    for stage in (detector, incidents):
        stage.start()
    while detector.step(500) + incidents.step(500):
        pass
    detector.finish()
    incidents.finish()
    return detector, incidents


bursts = st.lists(
    st.tuples(
        st.integers(min_value=-420, max_value=30),  # seconds relative to the stream's front
        st.sampled_from((IPS[0], IPS[0], IPS[0], IPS[1], IPS[2])),
        st.sampled_from(USERS),
        st.sampled_from(("failure", "failure", "failure", "success")),
    ),
    min_size=1,
    max_size=25,
)
actions = st.one_of(
    st.tuples(st.just("lines"), bursts),
    # A brute-force run: failures from one IP every few seconds, starting before the front.
    st.tuples(st.just("attack"), st.integers(4, 14), st.integers(-360, 0), st.sampled_from(IPS)),
    st.tuples(st.just("step"), st.integers(0, 2), st.integers(1, 40)),
    st.tuples(st.just("idle"), st.none()),
    st.tuples(st.just("quiet"), st.none()),
    st.tuples(st.just("advance"), st.integers(60, 7200)),
)


def _play(live: Live, script: list[tuple[Any, ...]]) -> None:
    front = 0
    for action in script:
        if action[0] == "lines":
            texts = []
            for offset, ip, user, outcome in action[1]:
                texts.append(_signin(max(0, front + offset), ip, user, outcome))
                front = max(front, front + offset)
            live.lines(texts)
        elif action[0] == "attack":
            _, count, start, ip = action
            first = max(0, front + start)
            live.lines([_signin(first + 4 * i, ip, USERS[i % 4]) for i in range(count)])
            front = max(front, first + 4 * (count - 1))
        elif action[0] == "step":  # one stage takes a turn with a random batch size
            live.stages[action[1]].step(action[2])
        elif action[0] == "idle":  # the input went quiet: the detector asks for a flush
            live.drain()
            live.detector.idle()
        elif action[0] == "quiet":  # no alert for a while: the incident stage asks to close
            live.now += IDLE_CLOSE
            live.incidents.step(500)
        else:  # the stream's front moves on (hours may pass between bursts)
            front += action[1]


@pytest.mark.parametrize("kind", ["memory", "file", "kafka"])
@settings(
    max_examples=200,
    deadline=None,
    derandomize=True,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large],
)
@given(script=st.lists(actions, min_size=1, max_size=25))
def test_rebuild_from_offset_zero_matches_the_live_run(
    kind: str, script: list[tuple[Any, ...]]
) -> None:
    with _transport(kind) as transport:
        live = Live(transport)
        _play(live, script)
        live.finish()
        live_alerts = _published(transport, Topic.ALERTS, "check")
        live_incidents = _published(transport, Topic.INCIDENTS, "check")
        event(f"alerts: {'yes' if live_alerts else 'no'}")
        event(f"incidents: {min(len(live_incidents), 3)}")
        event(f"late events: {'yes' if live.detector.engine_counts['late_events'] else 'no'}")

        _rebuild(transport)
        # The whole messages, not only the ids: an incident's timeline, score and provenance too.
        assert _published(transport, Topic.ALERTS, "check") == live_alerts
        assert _published(transport, Topic.INCIDENTS, "check") == live_incidents


# ------------------------------------------------------------------ the audit repro


def _audit(transport: Transport) -> Live:
    """Nine failures from one IP, the input goes quiet, then three older failures arrive.

    PRH-AUTH-001 needs ten failures within five minutes. The live detector released the nine on
    the idle flush, so the three older ones are too late and no alert is raised.
    """
    live = Live(transport)
    live.lines([_signin(120 + 5 * i, IPS[0], "alice") for i in range(9)])
    live.drain()
    live.detector.idle()
    live.drain()
    live.lines([_signin(s, IPS[0], "alice") for s in (90, 100, 110)])
    live.finish()
    return live


def test_audit_repro_gives_the_same_result_live_and_rebuilt() -> None:
    transport = MemoryTransport()
    live = _audit(transport)
    assert live.detector.engine_counts["late_events"] == 3
    assert _ids(transport, Topic.ALERTS, "check") == []
    detector, _ = _rebuild(transport)
    assert detector.engine_counts["late_events"] == 3
    assert _ids(transport, Topic.ALERTS, "check") == []


def test_topics_without_markers_replay_as_in_1_0() -> None:
    """Topics written by 1.0 have no markers: a rebuild sees no flush, as before this change."""
    recorded = MemoryTransport()
    _audit(recorded)
    old = MemoryTransport()
    for topic in (Topic.RAW_LOGS, Topic.EVENTS):
        for records in recorded.batches_to_end(topic, "copy", 1000):
            for record in records:
                if record.value is not None and "control" not in record.value:
                    old.publish(topic, record.key or "", record.value)
    old.flush()
    detector, _ = _rebuild(old)
    assert detector.engine_counts["late_events"] == 0
    alerts = [r.value for r in old.poll(Topic.ALERTS, "check", 100) if r.value is not None]
    assert [a["detector_id"] for a in alerts if "control" not in a] == ["PRH-AUTH-001"]


# ------------------------------------------------------------------ markers and other readers


def _marker(stage: str, action: str = "flush") -> dict[str, Any]:
    return control(stage, action, "idle").model_dump(mode="json")  # type: ignore[arg-type]


def test_other_stages_skip_markers_without_dead_letters(tmp_path: Path) -> None:
    transport = MemoryTransport()
    transport.publish(Topic.EVENTS, "m1", _marker("detect"))
    transport.publish(Topic.ALERTS, "m2", _marker("incidents", "close"))
    transport.publish(Topic.EVENTS, "m3", _marker("someone-else"))
    transport.flush()
    sink = DuckDBSink(transport, tmp_path / "db.duckdb")
    incidents = IncidentStage(transport, RULES, lateness=LATENESS)
    detector = Detector(transport, RULES, lateness=LATENESS)
    try:
        for stage in (sink, incidents, detector):
            stage.step(100)
            assert stage.metrics.dead_letters == 0
        assert sink.counts()["events"] == 0
        assert sink.counts()["alerts"] == 0
        assert not incidents.pending
    finally:
        sink.close()


def test_invalid_marker_is_a_dead_letter() -> None:
    transport = MemoryTransport()
    transport.publish(Topic.EVENTS, "bad", {"control": "explode", "stage": "detect"})
    detector = Detector(transport, RULES, lateness=LATENESS)
    detector.step(10)
    assert detector.metrics.dead_letters == 1
    (letter,) = [r.value for r in transport.poll(Topic.DEAD_LETTER, "check", 10)]
    assert letter is not None
    assert letter["reason"] == "invalid control marker"


def test_finish_writes_a_marker_only_when_something_is_held() -> None:
    transport = MemoryTransport()
    detector = Detector(transport, RULES, lateness=LATENESS)
    incidents = IncidentStage(transport, RULES, lateness=LATENESS)
    detector.finish()
    incidents.finish()
    assert transport.poll(Topic.EVENTS, "check", 10) == []
    assert transport.poll(Topic.ALERTS, "check", 10) == []


def test_marker_model_round_trips() -> None:
    marker = control("detect", "flush", "finish")
    assert Control.model_validate(marker.model_dump(mode="json")) == marker
    assert marker.id.startswith("ctl-")
    ids = {control("detect", "flush", "idle").id for _ in range(3)}
    assert len(ids) == 3  # every marker gets its own id
