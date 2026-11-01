"""PostgreSQL sink: the warehouse of the Docker stack.

Tables live in the ``raw`` schema (the dbt models of a later step build on it) and match the DuckDB
tables, with ``JSONB`` for the whole message. Rows are inserted with ``ON CONFLICT (id) DO
NOTHING``, so redelivered messages are stored once.
"""

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Any

from prohori.pipeline import MissingExtraError
from prohori.pipeline.sink import TABLES, Sink
from prohori.pipeline.transport import Transport

if TYPE_CHECKING:
    import psycopg

SCHEMA = """
CREATE SCHEMA IF NOT EXISTS raw;
CREATE TABLE IF NOT EXISTS raw.events (
    id TEXT PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    log_source TEXT NOT NULL,
    action TEXT NOT NULL,
    category TEXT NOT NULL,
    outcome TEXT NOT NULL,
    source_ip TEXT,
    user_name TEXT,
    http_status INTEGER,
    record JSONB NOT NULL
);
CREATE TABLE IF NOT EXISTS raw.alerts (
    id TEXT PRIMARY KEY,
    detector_id TEXT NOT NULL,
    detector_kind TEXT NOT NULL,
    severity TEXT NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    title TEXT NOT NULL,
    event_count INTEGER NOT NULL,
    record JSONB NOT NULL
);
CREATE TABLE IF NOT EXISTS raw.incidents (
    id TEXT PRIMARY KEY,
    severity TEXT NOT NULL,
    score DOUBLE PRECISION NOT NULL,
    confidence TEXT NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    title TEXT NOT NULL,
    alert_count INTEGER NOT NULL,
    record JSONB NOT NULL
);
CREATE TABLE IF NOT EXISTS raw.dead_letters (
    id TEXT PRIMARY KEY,
    stage TEXT NOT NULL,
    topic TEXT NOT NULL,
    key TEXT,
    reason TEXT NOT NULL,
    payload TEXT NOT NULL
);
"""

#: Placeholders per table; ``record`` is cast to JSONB.
_COLUMNS = {
    "events": 9,
    "alerts": 8,
    "incidents": 8,
    "dead_letters": 6,
}


def _insert(table: str) -> str:
    plain = ", ".join(["%s"] * _COLUMNS[table])
    values = plain if table == "dead_letters" else f"{plain}, %s::jsonb"
    return f"INSERT INTO raw.{table} VALUES ({values}) ON CONFLICT (id) DO NOTHING"  # noqa: S608


def connect(dsn: str) -> "psycopg.Connection[Any]":
    """Connect to PostgreSQL and create the ``raw`` schema and tables if needed."""
    try:
        import psycopg
    except ImportError as exc:
        raise MissingExtraError("the PostgreSQL sink") from exc
    connection = psycopg.connect(dsn, autocommit=True, connect_timeout=10)
    with connection.transaction():
        connection.execute(SCHEMA)
    return connection


class PostgresSink(Sink):
    """Writes to the ``raw`` schema of a PostgreSQL database.

    Args:
        dsn: A libpq connection string, such as ``postgresql://user:password@host:5432/db``.
    """

    def __init__(self, transport: Transport, dsn: str) -> None:
        super().__init__(transport)
        self.connection = connect(dsn)
        import psycopg

        self.data_errors = (psycopg.DataError, psycopg.IntegrityError)

    def write(self, rows: Mapping[str, Sequence[tuple[Any, ...]]]) -> None:
        with self.connection.transaction(), self.connection.cursor() as cursor:
            for table, table_rows in rows.items():
                cursor.executemany(_insert(table), table_rows)  # pipelined by psycopg

    def counts(self) -> dict[str, int]:
        result: dict[str, int] = {}
        with self.connection.transaction():
            for table in TABLES:
                row = self.connection.execute(f"SELECT count(*) FROM raw.{table}").fetchone()  # noqa: S608
                result[table] = int(row[0]) if row is not None else 0
        return result

    def close(self) -> None:
        self.connection.close()
