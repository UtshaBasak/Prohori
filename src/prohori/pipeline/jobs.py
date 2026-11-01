"""Scheduled jobs: the incident digest, the flow-model recall gate and the enrichment refresh.

The orchestrator (``pipeline/airflow/``) runs these through ``prohori pipeline digest``,
``check-recall`` and ``refresh-enrichment``; they work the same on the lite-mode DuckDB file.
"""

import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from ipaddress import ip_address
from pathlib import Path
from statistics import fmean
from typing import Any

from prohori.enrich import Enricher
from prohori.enrich.addresses import is_public
from prohori.pipeline.sink import DuckDBSink, Sink
from prohori.pipeline.tables import column_names
from prohori.pipeline.warehouse import evaluation_rows

#: Severities from the most to the least severe, as the digest lists them.
SEVERITIES = ("critical", "high", "medium", "low")


# ---------------------------------------------------------------------- queries


def _query(sink: Sink, sql: str, params: Sequence[Any] = ()) -> list[tuple[Any, ...]]:
    """Run ``sql`` on the sink's database; ``{t}`` prefixes tables and ``?`` marks parameters."""
    duckdb = isinstance(sink, DuckDBSink)
    text = sql.replace("{t}", "" if duckdb else "raw.")
    if not duckdb:
        text = text.replace("?", "%s")
    connection: Any = getattr(sink, "connection")  # noqa: B009 - both sinks have one
    return [tuple(row) for row in connection.execute(text, list(params)).fetchall()]


# ---------------------------------------------------------------------- digest


@dataclass(frozen=True)
class DigestIncident:
    id: str
    severity: str
    score: float
    confidence: str
    first_seen: datetime
    last_seen: datetime
    alert_count: int
    title: str


@dataclass(frozen=True)
class Digest:
    """What the pipeline stored between ``since`` and ``until`` (by ``stored_at``)."""

    since: datetime
    until: datetime
    events: int
    alerts: int
    dead_letters: int
    incidents: list[DigestIncident]
    severities: dict[str, int] = field(default_factory=dict)
    rules: list[tuple[str, int]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": "prohori.digest/1",
            "since": self.since.isoformat(),
            "until": self.until.isoformat(),
            "events": self.events,
            "alerts": self.alerts,
            "dead_letters": self.dead_letters,
            "incidents_by_severity": self.severities,
            "alerts_by_rule": dict(self.rules),
            "incidents": [
                {
                    "id": i.id,
                    "severity": i.severity,
                    "score": i.score,
                    "confidence": i.confidence,
                    "first_seen": i.first_seen.isoformat(),
                    "last_seen": i.last_seen.isoformat(),
                    "alert_count": i.alert_count,
                    "title": i.title,
                }
                for i in self.incidents
            ],
        }


def _utc(epoch: object) -> datetime:
    return datetime.fromtimestamp(float(str(epoch)), tz=UTC)


def build_digest(sink: Sink, since: datetime, until: datetime, *, limit: int = 20) -> Digest:
    """Summarise the rows stored in ``[since, until)``: counts, rules and the top incidents."""
    window = (since, until)
    where = "WHERE stored_at >= ? AND stored_at < ?"

    def count(table: str) -> int:
        return int(_query(sink, f"SELECT count(*) FROM {{t}}{table} {where}", window)[0][0])  # noqa: S608

    severities = dict(
        _query(sink, f"SELECT severity, count(*) FROM {{t}}incidents {where} GROUP BY 1", window)  # noqa: S608
    )
    rules = _query(
        sink,
        f"SELECT detector_id, count(*) FROM {{t}}alerts {where} GROUP BY 1 ORDER BY 2 DESC, 1",  # noqa: S608
        window,
    )
    rows = _query(
        sink,
        # Times as epoch seconds: DuckDB needs pytz to return TIMESTAMPTZ values to Python.
        "SELECT id, severity, score, confidence, extract(epoch FROM first_seen), "  # noqa: S608
        "extract(epoch FROM last_seen), alert_count, title "
        f"FROM {{t}}incidents {where} ORDER BY score DESC, first_seen, id LIMIT {int(limit)}",
        window,
    )
    return Digest(
        since=since,
        until=until,
        events=count("events"),
        alerts=count("alerts"),
        dead_letters=count("dead_letters"),
        incidents=[
            DigestIncident(r[0], r[1], float(r[2]), r[3], _utc(r[4]), _utc(r[5]), int(r[6]), r[7])
            for r in rows
        ],
        severities={s: int(severities[s]) for s in SEVERITIES if s in severities},
        rules=[(str(r[0]), int(r[1])) for r in rules],
    )


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def render_digest(digest: Digest) -> str:
    """The digest as Markdown."""
    total = sum(digest.severities.values())
    lines = [
        "# Prohori incident digest",
        "",
        f"Stored from {digest.since:%Y-%m-%d %H:%M} to {digest.until:%Y-%m-%d %H:%M} UTC.",
        "",
        f"- **Incidents:** {total:,}"
        + (
            " (" + ", ".join(f"{n:,} {s}" for s, n in digest.severities.items()) + ")"
            if total
            else ""
        ),
        f"- **Alerts:** {digest.alerts:,}",
        f"- **Events:** {digest.events:,}",
        f"- **Dead letters:** {digest.dead_letters:,}",
        "",
    ]
    if digest.incidents:
        lines += [
            "## Top incidents",
            "",
            "| Score | Severity | Confidence | First seen (UTC) | Alerts | Title | Id |",
            "|------:|----------|------------|------------------|-------:|-------|----|",
        ]
        lines += [
            f"| {i.score:.0f} | {i.severity} | {i.confidence} | {i.first_seen:%Y-%m-%d %H:%M} "
            f"| {i.alert_count} | {_cell(i.title)} | `{i.id}` |"
            for i in digest.incidents
        ]
        lines.append("")
    if digest.rules:
        lines += ["## Alerts by rule", "", "| Rule | Alerts |", "|------|-------:|"]
        lines += [f"| {rule} | {n:,} |" for rule, n in digest.rules]
        lines.append("")
    if not digest.incidents and not digest.alerts:
        lines += ["Nothing was detected in this period.", ""]
    return "\n".join(lines)


def digest_json(digest: Digest) -> str:
    return json.dumps(digest.to_dict(), indent=2) + "\n"


# ---------------------------------------------------------------------- recall gate


@dataclass(frozen=True)
class RecallCheck:
    """Mean test-split recall of one model, variant and operating point over its seeds."""

    dataset: str
    model: str
    variant: str
    operating_point: str
    recalls: list[float]
    minimum: float

    @property
    def mean(self) -> float:
        return fmean(self.recalls)

    @property
    def passed(self) -> bool:
        return self.mean >= self.minimum


def check_recall(
    results: Path, *, minimum: float, model: str, variant: str, operating_point: str
) -> RecallCheck:
    """Read a flow-model results file and compare one model's recall with ``minimum``.

    Raises :class:`prohori.pipeline.warehouse.LoadError` if the file cannot be read and
    :class:`ValueError` if it has no run of that model, variant and operating point.
    """
    columns = column_names("model_evaluations")
    rows = [dict(zip(columns, row, strict=True)) for row in evaluation_rows(results)]
    recalls = [
        float(r["recall"])
        for r in rows
        if r["model"] == model
        and r["variant"] == variant
        and r["operating_point"] == operating_point
    ]
    if not recalls:
        available = sorted({f"{r['model']}/{r['variant']}/{r['operating_point']}" for r in rows})
        msg = (
            f"{results} has no {model}/{variant}/{operating_point} runs "
            f"(it has: {', '.join(available) or 'none'})"
        )
        raise ValueError(msg)
    return RecallCheck(
        dataset=str(rows[0]["dataset"]),
        model=model,
        variant=variant,
        operating_point=operating_point,
        recalls=recalls,
        minimum=minimum,
    )


# ---------------------------------------------------------------------- enrichment refresh


def recent_addresses(sink: Sink, since: datetime, *, limit: int = 500) -> list[str]:
    """Public source addresses of events stored since ``since``, the most active first."""
    rows = _query(
        sink,
        "SELECT source_ip, count(*) FROM {t}events "
        "WHERE stored_at >= ? AND source_ip IS NOT NULL GROUP BY 1 ORDER BY 2 DESC, 1",
        (since,),
    )
    found = []
    for value, _ in rows:
        try:
            address = ip_address(str(value))
        except ValueError:
            continue
        if is_public(address):
            found.append(str(address))
        if len(found) >= limit:
            break
    return found


@dataclass(frozen=True)
class RefreshResult:
    addresses: int
    looked_up: int
    purged: int
    providers: list[str]


def refresh_enrichment(enricher: Enricher, addresses: Sequence[str]) -> RefreshResult:
    """Drop expired cache entries, then look up ``addresses`` so fresh answers are cached.

    Offline enrichers never open a connection: they only purge, and the lookups read the cache.
    """
    purged = enricher.cache.purge_expired() if enricher.cache is not None else 0
    looked_up = 0
    for address in addresses:
        enricher.enrich_ip(address)
        looked_up += 1
    return RefreshResult(
        addresses=len(addresses),
        looked_up=looked_up,
        purged=purged,
        providers=[p.name for p in enricher.providers],
    )
