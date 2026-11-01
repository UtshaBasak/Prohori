"""Sinks: events, alerts, incidents and dead letters in a database.

:class:`Sink` holds what every database sink shares; :class:`DuckDBSink` writes a local DuckDB
file (lite mode) and :class:`~prohori.pipeline.postgres.PostgresSink` a PostgreSQL warehouse (the
Docker stack). Every table has the message id as its primary key and rows that already exist are
ignored, so a message delivered twice (a replay, a redelivery after a crash) is stored once. Each
row keeps a few columns for querying and the whole message as JSON in ``record``.

A batch is written in one transaction before the transport positions are committed. If the
database rejects a batch because of its data, the rows are written one at a time and each row it
still rejects becomes a dead letter; any other database error stops the stage, and the batch is
delivered again after a restart.
"""

import json
import logging
from abc import abstractmethod
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from pydantic import BaseModel

from prohori.pipeline import MissingExtraError
from prohori.pipeline.messages import DeadLetter, Topic, dead_letter
from prohori.pipeline.stages import Stage
from prohori.pipeline.tables import STREAM_TABLES, column_names, ddl
from prohori.pipeline.transport import Record, Transport
from prohori.schema import Alert, Event, Incident

if TYPE_CHECKING:
    import duckdb

logger = logging.getLogger(__name__)

SCHEMA = ddl("duckdb")

TABLES = STREAM_TABLES


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


def strip_nul(value: object) -> object:
    """Replace NUL characters in every string of ``value``: PostgreSQL text cannot hold them."""
    if isinstance(value, str):
        return value.replace("\x00", "\ufffd")
    if isinstance(value, dict):
        return {strip_nul(k): strip_nul(v) for k, v in value.items()}
    if isinstance(value, list):
        return [strip_nul(v) for v in value]
    return value


@dataclass(frozen=True)
class _Row:
    topic: Topic
    key: str | None
    values: tuple[Any, ...]
    record: str


class Sink(Stage):
    """Writes every ``events``, ``alerts``, ``incidents`` and ``dead-letter`` message.

    Subclasses implement :meth:`write` (one transaction, rolled back and re-raised on error),
    :meth:`counts` and :meth:`close`, and set :attr:`data_errors` to the database errors caused
    by a row's content.
    """

    name = "sink"
    inputs = (Topic.EVENTS, Topic.ALERTS, Topic.INCIDENTS, Topic.DEAD_LETTER)
    data_errors: tuple[type[Exception], ...] = ()

    def __init__(self, transport: Transport) -> None:
        super().__init__(transport)
        self._rows: dict[str, list[_Row]] = {}

    def _process(self, batches: Sequence[tuple[Topic, list[Record]]]) -> int:
        self._rows = {}
        return super()._process(batches)

    def handle(self, topic: Topic, value: Mapping[str, Any]) -> None:
        table, model, row = _ROWS[topic]
        clean = cast(dict[str, Any], strip_nul(dict(value)))
        item = model.model_validate(clean)
        record = json.dumps(clean, separators=(",", ":"))
        key = clean.get("id") if isinstance(clean.get("id"), str) else None
        self._rows.setdefault(table, []).append(_Row(topic, key, row(item, record), record))

    def reject(self, record: Record, reason: str, payload: str) -> None:
        if record.topic is Topic.DEAD_LETTER:
            # A broken dead letter cannot go back to the dead-letter topic; count and skip it.
            self.metrics.dead_letters += 1
            return
        super().reject(record, reason, payload)

    def tick(self) -> None:
        if not self._rows:
            return
        try:
            self.write({table: [r.values for r in rows] for table, rows in self._rows.items()})
        except self.data_errors as exc:
            logger.warning("the database rejected a batch (%s); writing it row by row", exc)
            self._write_rows()
        self.metrics.produced += sum(len(rows) for rows in self._rows.values())
        self._rows = {}

    def _write_rows(self) -> None:
        for table, rows in self._rows.items():
            for row in rows:
                try:
                    self.write({table: [row.values]})
                except self.data_errors as exc:
                    reason = f"database rejected the row: {type(exc).__name__}"
                    if row.topic is Topic.DEAD_LETTER:
                        self.metrics.dead_letters += 1
                        continue
                    letter = dead_letter(self.name, row.topic, row.key, reason, row.record)
                    self.publish_dead_letter(letter)

    @abstractmethod
    def write(self, rows: Mapping[str, Sequence[tuple[Any, ...]]]) -> None:
        """Insert ``rows`` (by table), ignoring existing ids, in one transaction."""

    @abstractmethod
    def counts(self) -> dict[str, int]:
        """Rows in each table."""

    @abstractmethod
    def close(self) -> None:
        """Close the database connection."""


class DuckDBSink(Sink):
    """Writes to a local DuckDB file (lite mode)."""

    def __init__(self, transport: Transport, path: Path) -> None:
        super().__init__(transport)
        self.path = path
        self.connection = connect(path)
        import duckdb

        self.data_errors = (duckdb.DataError, duckdb.IntegrityError)

    def write(self, rows: Mapping[str, Sequence[tuple[Any, ...]]]) -> None:
        self.connection.execute("BEGIN TRANSACTION")
        try:
            for table, table_rows in rows.items():
                # One statement per table and batch, each column bound as one list parameter
                # (executemany would run one statement per row, which is far slower).
                columns = [list(column) for column in zip(*table_rows, strict=True)]
                names = ", ".join(column_names(table))
                unnest = ", ".join(["unnest(?)"] * len(columns))
                self.connection.execute(
                    f"INSERT OR IGNORE INTO {table} ({names}) SELECT {unnest}", columns
                )
            self.connection.execute("COMMIT")
        except Exception:
            self.connection.execute("ROLLBACK")
            raise

    def counts(self) -> dict[str, int]:
        result: dict[str, int] = {}
        for table in TABLES:
            row = self.connection.execute(f"SELECT count(*) FROM {table}").fetchone()  # noqa: S608
            result[table] = int(row[0]) if row is not None else 0
        return result

    def close(self) -> None:
        self.connection.close()
