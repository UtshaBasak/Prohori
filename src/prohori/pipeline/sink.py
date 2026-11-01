"""DuckDB sink: events, alerts, incidents and dead letters in one local database file.

Every table has the message id as its primary key and rows are written with ``INSERT OR IGNORE``,
so a message delivered twice (a replay, a redelivery after a crash) is stored once. Each row keeps
a few columns for querying and the whole message as JSON in ``record``.
"""

import json
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel

from prohori.pipeline import MissingExtraError
from prohori.pipeline.messages import DeadLetter, Topic
from prohori.pipeline.stages import Stage
from prohori.pipeline.transport import Record, Transport
from prohori.schema import Alert, Event, Incident

if TYPE_CHECKING:
    import duckdb

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id VARCHAR PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    log_source VARCHAR NOT NULL,
    action VARCHAR NOT NULL,
    category VARCHAR NOT NULL,
    outcome VARCHAR NOT NULL,
    source_ip VARCHAR,
    user_name VARCHAR,
    http_status INTEGER,
    record JSON NOT NULL
);
CREATE TABLE IF NOT EXISTS alerts (
    id VARCHAR PRIMARY KEY,
    detector_id VARCHAR NOT NULL,
    detector_kind VARCHAR NOT NULL,
    severity VARCHAR NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    title VARCHAR NOT NULL,
    event_count INTEGER NOT NULL,
    record JSON NOT NULL
);
CREATE TABLE IF NOT EXISTS incidents (
    id VARCHAR PRIMARY KEY,
    severity VARCHAR NOT NULL,
    score DOUBLE NOT NULL,
    confidence VARCHAR NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    title VARCHAR NOT NULL,
    alert_count INTEGER NOT NULL,
    record JSON NOT NULL
);
CREATE TABLE IF NOT EXISTS dead_letters (
    id VARCHAR PRIMARY KEY,
    stage VARCHAR NOT NULL,
    topic VARCHAR NOT NULL,
    key VARCHAR,
    reason VARCHAR NOT NULL,
    payload VARCHAR NOT NULL
);
"""

TABLES = ("events", "alerts", "incidents", "dead_letters")


def connect(path: Path) -> "duckdb.DuckDBPyConnection":
    """Open (or create) the database at ``path`` with the tables in place."""
    try:
        import duckdb
    except ImportError as exc:
        raise MissingExtraError("the DuckDB sink") from exc
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = duckdb.connect(str(path))
    connection.execute(SCHEMA)
    return connection


def _event_row(event: Event, record: str) -> tuple[Any, ...]:
    return (
        event.id,
        event.timestamp,
        event.log_source,
        event.event.action,
        event.event.category.value,
        event.event.outcome.value,
        str(event.source.ip) if event.source.ip is not None else None,
        event.user.name,
        event.http.status,
        record,
    )


def _alert_row(alert: Alert, record: str) -> tuple[Any, ...]:
    return (
        alert.id,
        alert.detector_id,
        alert.detector_kind.value,
        alert.severity.value,
        alert.first_seen,
        alert.last_seen,
        alert.title,
        len(alert.event_ids),
        record,
    )


def _incident_row(incident: Incident, record: str) -> tuple[Any, ...]:
    return (
        incident.id,
        incident.severity.value,
        incident.score,
        incident.confidence.value,
        incident.first_seen,
        incident.last_seen,
        incident.title,
        len(incident.alerts),
        record,
    )


def _dead_letter_row(letter: DeadLetter, record: str) -> tuple[Any, ...]:
    del record  # every field is a column already
    return (letter.id, letter.stage, letter.topic, letter.key, letter.reason, letter.payload)


_ROWS: dict[Topic, tuple[str, type[BaseModel], Callable[[Any, str], tuple[Any, ...]]]] = {
    Topic.EVENTS: ("events", Event, _event_row),
    Topic.ALERTS: ("alerts", Alert, _alert_row),
    Topic.INCIDENTS: ("incidents", Incident, _incident_row),
    Topic.DEAD_LETTER: ("dead_letters", DeadLetter, _dead_letter_row),
}


class DuckDBSink(Stage):
    """Writes every ``events``, ``alerts``, ``incidents`` and ``dead-letter`` message to DuckDB.

    A batch is written in one transaction, committed to the database before the transport
    positions are committed.
    """

    name = "sink"
    inputs = (Topic.EVENTS, Topic.ALERTS, Topic.INCIDENTS, Topic.DEAD_LETTER)

    def __init__(self, transport: Transport, path: Path) -> None:
        super().__init__(transport)
        self.path = path
        self.connection = connect(path)
        self._rows: dict[str, list[tuple[Any, ...]]] = {}

    def _process(self, batches: Sequence[tuple[Topic, list[Record]]]) -> int:
        self._rows = {}
        return super()._process(batches)

    def handle(self, topic: Topic, value: Mapping[str, Any]) -> None:
        table, model, row = _ROWS[topic]
        item = model.model_validate(value)
        record = json.dumps(value, separators=(",", ":"))
        self._rows.setdefault(table, []).append(row(item, record))

    def reject(self, record: Record, reason: str, payload: str) -> None:
        if record.topic is Topic.DEAD_LETTER:
            # A broken dead letter cannot go back to the dead-letter topic; count and skip it.
            self.metrics.dead_letters += 1
            return
        super().reject(record, reason, payload)

    def tick(self) -> None:
        if not self._rows:
            return
        self.connection.execute("BEGIN TRANSACTION")
        try:
            for table, rows in self._rows.items():
                # One statement per table and batch, each column bound as one list parameter
                # (executemany would run one statement per row, which is far slower).
                columns = [list(column) for column in zip(*rows, strict=True)]
                unnest = ", ".join(["unnest(?)"] * len(columns))
                self.connection.execute(
                    f"INSERT OR IGNORE INTO {table} SELECT {unnest}",
                    columns,
                )
            self.connection.execute("COMMIT")
        except Exception:
            self.connection.execute("ROLLBACK")
            raise
        self.metrics.produced += sum(len(rows) for rows in self._rows.values())
        self._rows = {}

    def counts(self) -> dict[str, int]:
        """Rows in each table."""
        result: dict[str, int] = {}
        for table in TABLES:
            row = self.connection.execute(f"SELECT count(*) FROM {table}").fetchone()  # noqa: S608
            result[table] = int(row[0]) if row is not None else 0
        return result

    def close(self) -> None:
        self.connection.close()
