"""The warehouse tables, defined once for DuckDB (lite mode) and PostgreSQL (the Docker stack).

The stream tables (``events``, ``alerts``, ``incidents``, ``dead_letters``) are written by the
sinks; ``labels`` (the simulator's ground truth) and ``model_evaluations`` (flow-model results)
by the loaders in :mod:`prohori.pipeline.warehouse`. Every table has an ``id`` primary key and a
``stored_at`` column the database fills when a row is first written, which the dbt freshness
checks and the pipeline-latency model use.
"""

from dataclasses import dataclass
from typing import Literal

Dialect = Literal["duckdb", "postgres"]
Kind = Literal["text", "timestamp", "integer", "double", "json"]

_TYPES: dict[Dialect, dict[Kind, str]] = {
    "duckdb": {
        "text": "VARCHAR",
        "timestamp": "TIMESTAMPTZ",
        "integer": "INTEGER",
        "double": "DOUBLE",
        "json": "JSON",
    },
    "postgres": {
        "text": "TEXT",
        "timestamp": "TIMESTAMPTZ",
        "integer": "INTEGER",
        "double": "DOUBLE PRECISION",
        "json": "JSONB",
    },
}


@dataclass(frozen=True)
class Column:
    name: str
    kind: Kind
    nullable: bool = False


def _columns(*specs: str) -> tuple[Column, ...]:
    """``"name kind"`` or ``"name kind?"`` (nullable) to columns."""
    result = []
    for spec in specs:
        name, kind = spec.split()
        nullable = kind.endswith("?")
        result.append(Column(name, kind.rstrip("?"), nullable))  # type: ignore[arg-type]
    return tuple(result)


TABLES: dict[str, tuple[Column, ...]] = {
    "events": _columns(
        "id text",
        "timestamp timestamp",
        "log_source text",
        "action text",
        "category text",
        "outcome text",
        "source_ip text?",
        "user_name text?",
        "http_status integer?",
        "record json",
    ),
    "alerts": _columns(
        "id text",
        "detector_id text",
        "detector_kind text",
        "severity text",
        "first_seen timestamp",
        "last_seen timestamp",
        "title text",
        "event_count integer",
        "record json",
    ),
    "incidents": _columns(
        "id text",
        "severity text",
        "score double",
        "confidence text",
        "first_seen timestamp",
        "last_seen timestamp",
        "title text",
        "alert_count integer",
        "record json",
    ),
    "dead_letters": _columns(
        "id text",
        "stage text",
        "topic text",
        "key text?",
        "reason text",
        "payload text",
    ),
    # One row per event of a simulated log; id is the event id, attack_id is null for benign.
    "labels": _columns(
        "id text",
        "source text",
        "line integer",
        "scenario text?",
        "attack_id text?",
    ),
    # One row per flow model, seed, variant and operating point of an evaluation run.
    "model_evaluations": _columns(
        "id text",
        "evaluated_at timestamp",
        "dataset text",
        "variant text",
        "model text",
        "seed integer",
        "operating_point text",
        "threshold double?",
        "flows integer",
        "attacks integer",
        "alerts integer",
        "recall double",
        "precision double?",
        "fpr double",
        "false_alerts_per_10k double",
        "pr_auc double",
        "roc_auc double",
        "prohori_version text?",
    ),
}

#: The tables the sinks write.
STREAM_TABLES = ("events", "alerts", "incidents", "dead_letters")


def column_names(table: str) -> tuple[str, ...]:
    """The columns a writer supplies, in row order (``stored_at`` is filled by the database)."""
    return tuple(c.name for c in TABLES[table])


def json_columns(table: str) -> frozenset[str]:
    return frozenset(c.name for c in TABLES[table] if c.kind == "json")


def ddl(dialect: Dialect, prefix: str = "") -> str:
    """``CREATE TABLE IF NOT EXISTS`` for every table, and ``stored_at`` for older tables."""
    types = _TYPES[dialect]
    now = "current_timestamp" if dialect == "duckdb" else "now()"
    statements = []
    for table, columns in TABLES.items():
        lines = [
            f"    {c.name} {types[c.kind]}"
            + ("" if c.nullable else " NOT NULL")
            + (" PRIMARY KEY" if c.name == "id" else "")
            for c in columns
        ]
        lines.append(f"    stored_at TIMESTAMPTZ NOT NULL DEFAULT {now}")
        body = ",\n".join(lines)
        statements.append(f"CREATE TABLE IF NOT EXISTS {prefix}{table} (\n{body}\n);")
        statements.append(
            f"ALTER TABLE {prefix}{table} ADD COLUMN IF NOT EXISTS stored_at TIMESTAMPTZ "
            f"DEFAULT {now};"
        )
    return "\n".join(statements) + "\n"
