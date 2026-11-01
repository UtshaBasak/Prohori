"""DuckDB sink: idempotent writes, one transaction per batch, dead letters stored."""

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import duckdb
import pytest

from prohori.pipeline.messages import Topic, dead_letter
from prohori.pipeline.sink import DuckDBSink, connect
from prohori.pipeline.transport import MemoryTransport
from prohori.schema import Alert, Event, Severity

T0 = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)


def _event(n: int) -> Event:
    return Event.model_validate(
        {
            "timestamp": T0,
            "log_source": "app",
            "event": {"action": "auth.signin.failure", "category": "authentication"},
            "source": {"ip": "203.0.113.9"},
            "user": {"name": f"user{n}"},
            "http": {"status": 401},
            "raw": f"line {n}",
        }
    )


@pytest.fixture
def sink(tmp_path: Path) -> Iterator[tuple[MemoryTransport, DuckDBSink]]:
    transport = MemoryTransport()
    stage = DuckDBSink(transport, tmp_path / "db" / "p.duckdb")
    yield transport, stage
    stage.close()


def test_same_id_twice_in_one_batch_and_across_batches_is_stored_once(
    sink: tuple[MemoryTransport, DuckDBSink],
) -> None:
    transport, stage = sink
    event = _event(1)
    for _ in range(2):
        transport.publish(Topic.EVENTS, event.id, event.model_dump(mode="json"))
    transport.publish(Topic.EVENTS, "e2", _event(2).model_dump(mode="json"))
    stage.step(100)
    transport.publish(Topic.EVENTS, event.id, event.model_dump(mode="json"))
    stage.step(100)
    assert stage.counts()["events"] == 2
    row = stage.connection.execute(
        "SELECT action, source_ip, user_name, http_status, record->>'$.raw' FROM events "
        "WHERE id = ?",
        [event.id],
    ).fetchone()
    assert row == ("auth.signin.failure", "203.0.113.9", "user1", 401, "line 1")


def test_alerts_and_dead_letters_are_written(sink: tuple[MemoryTransport, DuckDBSink]) -> None:
    transport, stage = sink
    alert = Alert(
        id="alr-1",
        detector_id="PRH-TEST-001",
        title="test",
        severity=Severity.HIGH,
        first_seen=T0,
        last_seen=T0,
        event_ids=("evt-1",),
    )
    transport.publish(Topic.ALERTS, alert.id, alert.model_dump(mode="json"))
    letter = dead_letter("normalise", "raw-logs", "f:1", "bad", "{x")
    transport.publish(Topic.DEAD_LETTER, letter.id, letter.model_dump(mode="json"))
    transport.publish(Topic.DEAD_LETTER, "broken", {"id": "nope"})  # cannot be stored or resent
    stage.step(100)
    assert stage.counts() == {"events": 0, "alerts": 1, "incidents": 0, "dead_letters": 1}
    assert stage.metrics.dead_letters == 1
    assert transport.size(Topic.DEAD_LETTER) == 2  # nothing was sent back to the topic


def test_invalid_event_goes_to_the_dead_letter_topic(
    sink: tuple[MemoryTransport, DuckDBSink],
) -> None:
    transport, stage = sink
    transport.publish(Topic.EVENTS, "e", {"id": "x", "timestamp": "yesterday"})
    stage.step(100)
    letters = [r.value for r in transport.poll(Topic.DEAD_LETTER, "check", 10)]
    assert letters[0] is not None
    assert letters[0]["stage"] == "sink"
    assert json.loads(letters[0]["payload"])["id"] == "x"
    stage.step(100)  # the sink stores its own dead letter
    assert stage.counts()["dead_letters"] == 1


def test_failed_write_is_not_committed(
    sink: tuple[MemoryTransport, DuckDBSink], monkeypatch: pytest.MonkeyPatch
) -> None:
    transport, stage = sink
    transport.publish(Topic.EVENTS, "e1", _event(1).model_dump(mode="json"))

    def disk_full() -> None:
        raise RuntimeError("disk full")

    monkeypatch.setattr(stage, "tick", disk_full)
    with pytest.raises(RuntimeError):
        stage.step(100)
    assert ("sink", Topic.EVENTS) not in transport.committed  # redelivered after a restart


def test_rollback_on_database_error(sink: tuple[MemoryTransport, DuckDBSink]) -> None:
    _, stage = sink
    stage._rows = {"events": [("only-one-column",)]}
    with pytest.raises(duckdb.Error):
        stage.tick()
    assert stage.counts()["events"] == 0


def test_connect_reopens_an_existing_database(tmp_path: Path) -> None:
    path = tmp_path / "x.duckdb"
    connect(path).close()
    connection = connect(path)
    tables = {row[0] for row in connection.execute("SHOW TABLES").fetchall()}
    connection.close()
    assert tables == {"events", "alerts", "incidents", "dead_letters"}
