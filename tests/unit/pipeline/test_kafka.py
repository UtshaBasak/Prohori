"""Kafka transport over an in-memory fake client: the same contract as the lite transports."""

import json
import sys
import threading
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from prohori.pipeline import kafka as kafka_module
from prohori.pipeline.kafka import TOPIC_CONFIG, KafkaTransport, TransportError, decode_message
from prohori.pipeline.messages import Topic
from prohori.pipeline.producers import replay
from prohori.pipeline.runner import LiteSettings, make_stage, serve
from prohori.rules import builtin_rules_dir, load_rules
from prohori.simulate import simulate, write
from tests.unit.pipeline.fake_kafka import Broker, FakeKafkaError, FakeMessage, fake_kafka

RULES = [r.rule for r in load_rules([builtin_rules_dir()]) if r.rule is not None]


@pytest.fixture
def broker() -> Broker:
    return Broker()


@pytest.fixture
def transport(broker: Broker) -> KafkaTransport:
    return KafkaTransport("broker:9092", kafka=fake_kafka(broker))


def test_topics_are_created_once_with_unlimited_retention(broker: Broker) -> None:
    KafkaTransport("broker:9092", kafka=fake_kafka(broker))
    assert set(broker.topics) == {t.value for t in Topic}
    assert broker.configs["events"] == TOPIC_CONFIG
    KafkaTransport("broker:9092", kafka=fake_kafka(broker))  # already there: fine


def test_topics_are_awaited_until_they_have_a_leader(
    broker: Broker, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("prohori.pipeline.kafka.time.sleep", lambda seconds: None)
    broker.leaderless_lookups = 3
    KafkaTransport("broker:9092", kafka=fake_kafka(broker))
    assert broker.leaderless_lookups < 0
    broker.leaderless_lookups = 10**9
    monkeypatch.setattr("prohori.pipeline.kafka.BROKER_TIMEOUT", 0.0)
    with pytest.raises(TransportError, match="have no leader"):
        KafkaTransport("broker:9092", kafka=fake_kafka(broker))
    assert not kafka_module._has_leader(None)
    assert not kafka_module._has_leader(SimpleNamespace(error="unknown", partitions={}))


def test_unreachable_broker_and_refused_topics_are_errors(broker: Broker) -> None:
    broker.unreachable = True
    with pytest.raises(TransportError, match="cannot reach the Kafka broker"):
        KafkaTransport("broker:9092", kafka=fake_kafka(broker))
    broker.unreachable = False
    broker.create_error = 29
    with pytest.raises(TransportError, match="cannot create topic"):
        KafkaTransport("broker:9092", kafka=fake_kafka(broker))


def test_publish_poll_commit_and_redelivery(broker: Broker, transport: KafkaTransport) -> None:
    for number in range(5):
        transport.publish(Topic.EVENTS, f"k{number}", {"n": number})
    transport.flush()
    assert broker.topics["events"][0] == (b"k0", b'{"n":0}')
    first = transport.poll(Topic.EVENTS, "g", 2)
    assert [(r.key, r.value, r.position) for r in first] == [
        ("k0", {"n": 0}, 1),
        ("k1", {"n": 1}, 2),
    ]
    transport.commit(first[-1], "g")
    assert broker.committed[("prohori-g", "events")] == 2
    transport.poll(Topic.EVENTS, "g", 2)  # read, not committed: the process "crashes"
    transport.close()

    again = KafkaTransport("broker:9092", kafka=fake_kafka(broker))
    assert [r.value for r in again.poll(Topic.EVENTS, "g", 10)] == [{"n": n} for n in (2, 3, 4)]


def test_batches_to_end_read_everything_published_before_the_call(
    transport: KafkaTransport,
) -> None:
    for number in range(7):
        transport.publish(Topic.EVENTS, "k", {"n": number})
    transport.flush()
    assert sum(map(len, transport.batches_to_end(Topic.EVENTS, "g", 3))) == 7
    assert list(transport.batches_to_end(Topic.EVENTS, "g", 3)) == []
    other = transport.poll(Topic.EVENTS, "h", 2)
    transport.commit(other[-1], "h")
    fresh = KafkaTransport("broker:9092", kafka=transport.kafka)
    assert (
        sum(map(len, fresh.batches_to_end(Topic.EVENTS, "h", 3))) == 5
    )  # from the committed offset


def test_rewind_reads_from_the_start_and_commits(broker: Broker, transport: KafkaTransport) -> None:
    transport.publish(Topic.ALERTS, "a", {"n": 1})
    transport.flush()
    records = transport.poll(Topic.ALERTS, "g", 10)
    transport.commit(records[-1], "g")
    transport.rewind(Topic.ALERTS, "g")
    assert broker.committed[("prohori-g", "alerts")] == 0
    assert sum(map(len, transport.batches_to_end(Topic.ALERTS, "g", 10))) == 1


def test_failed_delivery_makes_flush_raise(broker: Broker, transport: KafkaTransport) -> None:
    broker.fail_delivery = True
    transport.publish(Topic.EVENTS, "k", {"n": 1})
    with pytest.raises(TransportError, match="not delivered: broker down"):
        transport.flush()
    broker.fail_delivery = False
    broker.undelivered = 2
    with pytest.raises(TransportError, match="2 message"):
        transport.flush()


def test_a_full_local_queue_is_retried(transport: KafkaTransport) -> None:
    transport.producer.full_once = True
    transport.publish(Topic.EVENTS, "k", {"n": 1})
    transport.flush()
    assert len(transport.poll(Topic.EVENTS, "g", 10)) == 1


def test_missing_topic_reads_as_empty(broker: Broker) -> None:
    transport = KafkaTransport("broker:9092", kafka=fake_kafka(broker), create_topics=False)
    assert transport.poll(Topic.EVENTS, "g", 10) == []


def test_read_errors_are_raised(broker: Broker, transport: KafkaTransport) -> None:
    consumer = transport._consumer("g", Topic.EVENTS)
    consumer.consume = lambda **_: [FakeMessage(0, None, None, FakeKafkaError(5, "no leader"))]  # type: ignore[method-assign]
    with pytest.raises(TransportError, match="no leader"):
        transport.poll(Topic.EVENTS, "g", 10)


@pytest.mark.parametrize(
    ("key", "value", "error"),
    [
        (b"k", b"not json", "not valid JSON"),
        (b"k", b"[1]", "not a keyed message"),
        (None, b"{}", "not a keyed message"),
        (b"k", None, "not valid JSON"),
    ],
)
def test_decode_message_never_raises(key: bytes | None, value: bytes | None, error: str) -> None:
    record = decode_message(Topic.EVENTS, 3, key, value)
    assert (record.value, record.error, record.position) == (None, error, 3)


def test_client_needs_the_extra(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "confluent_kafka", None)
    with pytest.raises(ImportError, match="pipeline' extra"):
        kafka_module.client()


def test_client_returns_the_real_library() -> None:
    import confluent_kafka

    real = kafka_module.client()
    assert real.Producer is confluent_kafka.Producer
    assert real.KafkaError.TOPIC_ALREADY_EXISTS == confluent_kafka.KafkaError.TOPIC_ALREADY_EXISTS


def test_every_stage_over_kafka_matches_lite_mode(broker: Broker, tmp_path: Path) -> None:
    """Separate stages over the (fake) broker, as in the Docker stack, give the same rows."""
    write(simulate("web-scanning", seed=1), tmp_path / "logs")
    log = tmp_path / "logs" / "web-scanning.log"
    settings = LiteSettings(
        rules=RULES, database=tmp_path / "k.duckdb", lateness=timedelta(minutes=5), idle_close=0.0
    )
    producer = KafkaTransport("broker:9092", kafka=fake_kafka(broker))
    replay(log, producer, parser="access_log")
    stages = [
        make_stage(name, KafkaTransport("broker:9092", kafka=fake_kafka(broker)), settings)
        for name in ("normalise", "detect", "incidents", "sink")
    ]
    heartbeat = tmp_path / "heartbeat"
    rounds = serve(
        stages, threading.Event(), poll_interval=0, idle_after=0, heartbeat=heartbeat, max_rounds=12
    )
    assert rounds == 12
    assert heartbeat.is_file()
    sink = stages[-1]
    counts = sink.counts()  # type: ignore[attr-defined]
    lines = log.read_bytes().count(b"\n")
    assert counts["events"] == lines
    assert counts["incidents"] == 1
    assert counts["alerts"] == 22
    sink.close()  # type: ignore[attr-defined]
    incidents = [json.loads(v) for _, v in broker.topics["incidents"] if v is not None]
    assert len({i["id"] for i in incidents}) == 1
