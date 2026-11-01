"""PostgreSQL sink over a fake psycopg connection (the Docker smoke test uses a real server)."""

from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any

import psycopg
import pytest

from prohori.pipeline import postgres
from prohori.pipeline.messages import Topic, dead_letter
from prohori.pipeline.postgres import SCHEMA, PostgresSink
from prohori.pipeline.transport import MemoryTransport
from prohori.schema import Event

T0 = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)


class FakeCursor:
    def __init__(self, connection: "FakeConnection") -> None:
        self.connection = connection

    def __enter__(self) -> "FakeCursor":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def executemany(self, sql: str, rows: Sequence[tuple[Any, ...]]) -> None:
        for row in rows:
            if any(isinstance(v, str) and "\x00" in v for v in row):
                raise psycopg.DataError("PostgreSQL text fields cannot contain NUL (0x00) bytes")
            if any(v == "reject-me" for v in row):
                raise psycopg.DataError("rejected")
        table = sql.split()[2]
        stored = self.connection.tables.setdefault(table, {})
        for row in rows:
            stored.setdefault(row[0], row)
        self.connection.statements.append(sql)


class FakeResult:
    def __init__(self, value: int) -> None:
        self.value = value

    def fetchone(self) -> tuple[int]:
        return (self.value,)


class FakeConnection:
    def __init__(self) -> None:
        self.tables: dict[str, dict[str, tuple[Any, ...]]] = {}
        self.statements: list[str] = []
        self.closed = False
        self.transactions = 0

    @contextmanager
    def transaction(self) -> Iterator[None]:
        self.transactions += 1
        yield

    def cursor(self) -> FakeCursor:
        return FakeCursor(self)

    def execute(self, sql: str) -> FakeResult:
        self.statements.append(sql)
        if sql.startswith("SELECT count(*) FROM "):
            return FakeResult(len(self.tables.get(sql.split()[-1], {})))
        return FakeResult(0)

    def close(self) -> None:
        self.closed = True


@pytest.fixture
def connection(monkeypatch: pytest.MonkeyPatch) -> FakeConnection:
    fake = FakeConnection()
    seen: dict[str, Any] = {}

    def connect(dsn: str, **options: Any) -> FakeConnection:
        seen.update(options, dsn=dsn)
        return fake

    monkeypatch.setattr(psycopg, "connect", connect)
    fake.options = seen  # type: ignore[attr-defined]
    return fake


def _event(n: int, name: str | None = None) -> Event:
    return Event.model_validate(
        {
            "timestamp": T0,
            "log_source": "app",
            "event": {"action": "auth.signin.failure", "category": "authentication"},
            "user": {"name": name or f"user{n}"},
            "raw": f"line {n}",
        }
    )


def test_connect_creates_the_raw_schema(connection: FakeConnection) -> None:
    sink = PostgresSink(MemoryTransport(), "postgresql://u@h/db")
    assert connection.statements[0] == SCHEMA
    assert connection.options["autocommit"] is True  # type: ignore[attr-defined]
    assert "CREATE SCHEMA IF NOT EXISTS raw" in SCHEMA
    sink.close()
    assert connection.closed


def test_rows_are_inserted_once_with_on_conflict(connection: FakeConnection) -> None:
    transport = MemoryTransport()
    sink = PostgresSink(transport, "postgresql://u@h/db")
    event = _event(1)
    for _ in range(2):
        transport.publish(Topic.EVENTS, event.id, event.model_dump(mode="json"))
    letter = dead_letter("normalise", "raw-logs", "f:1", "bad", "x")
    transport.publish(Topic.DEAD_LETTER, letter.id, letter.model_dump(mode="json"))
    sink.step(100)
    assert sink.counts() == {"events": 1, "alerts": 0, "incidents": 0, "dead_letters": 1}
    insert = next(s for s in connection.statements if s.startswith("INSERT INTO raw.events"))
    assert insert.endswith("%s::jsonb) ON CONFLICT (id) DO NOTHING")
    dead = next(s for s in connection.statements if s.startswith("INSERT INTO raw.dead_letters"))
    assert "jsonb" not in dead


def test_nul_never_reaches_the_database(connection: FakeConnection) -> None:
    transport = MemoryTransport()
    sink = PostgresSink(transport, "postgresql://u@h/db")
    letter = dead_letter("normalise", "raw-logs", "f:1", "bad", "a\x00b")
    transport.publish(Topic.DEAD_LETTER, letter.id, letter.model_dump(mode="json"))
    event = _event(1, name="eve\x00")
    transport.publish(Topic.EVENTS, event.id, event.model_dump(mode="json"))
    sink.step(100)
    assert sink.counts()["dead_letters"] == 1
    assert sink.counts()["events"] == 1
    assert sink.metrics.dead_letters == 0


def test_a_rejected_row_becomes_a_dead_letter(connection: FakeConnection) -> None:
    transport = MemoryTransport()
    sink = PostgresSink(transport, "postgresql://u@h/db")
    for event in (_event(1), _event(2, name="reject-me")):
        transport.publish(Topic.EVENTS, event.id, event.model_dump(mode="json"))
    sink.step(100)
    assert sink.counts()["events"] == 1
    assert sink.metrics.dead_letters == 1


def test_missing_extra(monkeypatch: pytest.MonkeyPatch) -> None:
    import sys

    monkeypatch.setitem(sys.modules, "psycopg", None)
    with pytest.raises(ImportError, match="pipeline' extra"):
        postgres.connect("postgresql://u@h/db")
