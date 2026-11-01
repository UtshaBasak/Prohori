"""Loaders for the warehouse tables the stream does not fill.

- :func:`label_rows`: the simulator's per-line ground truth, keyed by the id of the event each
  line becomes, so the dbt models can measure rule precision and time to detection.
- :func:`evaluation_rows`: flow-model results (``results/ml_*.json``), one row per model, seed,
  variant and operating point, so the dbt models can follow model performance over time.

Both are written with the sinks' idempotent ``write``: loading the same file twice adds nothing.
"""

import hashlib
import json
from collections.abc import Iterator, Sequence
from datetime import UTC, datetime
from itertools import chain, islice
from pathlib import Path
from typing import Any

from prohori.parsers import ParseError, ParseStats, RawLine, read_lines
from prohori.pipeline.producers import DETECT_LINES, choose_parser
from prohori.pipeline.sink import DuckDBSink, Sink
from prohori.pipeline.stages import ParserSettings
from prohori.pipeline.transport import MemoryTransport

#: The results format :func:`evaluation_rows` reads (written by ``python -m prohori.ml.train``).
EVALUATION_FORMAT = "prohori.ml-eval/1"


class LoadError(ValueError):
    """A labels or results file cannot be loaded."""


def labels_path(log: Path) -> Path:
    """Where the simulator writes the labels of ``log``: ``NAME.labels.jsonl`` next to it."""
    return log.with_name(log.name.rsplit(".", 1)[0] + ".labels.jsonl")


def _scenario(log: Path) -> str | None:
    manifest = log.with_name("manifest.json")
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    files = data.get("files", {}) if isinstance(data, dict) else {}
    if files.get("log", {}).get("name") != log.name:
        return None
    scenario = data.get("scenario")
    return str(scenario) if scenario else None


def _event_ids(log: Path, parser: str, settings: ParserSettings) -> Iterator[tuple[int, str]]:
    """(line number, event id) for every line of ``log`` that becomes an event.

    Uses the same parser, source name and read time as a replay of the file, so the ids are the
    ids the pipeline stored.
    """
    read_at = datetime.fromtimestamp(log.stat().st_mtime, tz=UTC)
    with log.open("rb") as stream:
        lines: Iterator[RawLine] = read_lines(stream)
        head = list(islice(lines, DETECT_LINES))
        name = choose_parser(head, parser, has_mapping=settings.mapping is not None)
        line_parser = settings.create(name, read_at)
        stats = ParseStats()
        for raw in chain(head, lines):
            try:
                event = line_parser.parse_raw(raw, source=log.name, stats=stats)
            except ParseError:
                continue
            if event is not None:
                yield raw.number, event.id


def label_rows(
    log: Path,
    labels: Path | None = None,
    *,
    parser: str = "auto",
    settings: ParserSettings | None = None,
    scenario: str | None = None,
) -> list[tuple[Any, ...]]:
    """Rows for the ``labels`` table: (event id, source, line, scenario, attack id or None)."""
    labels = labels if labels is not None else labels_path(log)
    attacks: dict[int, str | None] = {}
    current = 0
    try:
        with labels.open(encoding="utf-8") as handle:
            for text in handle:
                current += 1
                if not text.strip():
                    continue
                item = json.loads(text)
                line, attack = item["line"], item.get("attack")
                if not isinstance(line, int) or not (attack is None or isinstance(attack, str)):
                    raise TypeError
                attacks[line] = attack
    except OSError as exc:
        msg = f"cannot read labels {labels}: {exc.strerror or exc}"
        raise LoadError(msg) from exc
    except (ValueError, KeyError, TypeError) as exc:
        msg = f'{labels} line {current}: expected {{"line": N, "attack": ID or null}}'
        raise LoadError(msg) from exc
    scenario = scenario or _scenario(log)
    settings = settings or ParserSettings()
    return [
        (event_id, log.name, line, scenario, attacks.get(line))
        for line, event_id in _event_ids(log, parser, settings)
    ]


def evaluation_rows(results: Path, evaluated_at: datetime | None = None) -> list[tuple[Any, ...]]:
    """Rows for ``model_evaluations`` from a flow-model results file (test split only).

    ``evaluated_at`` defaults to the file's modification time.
    """
    try:
        data = json.loads(results.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        msg = f"cannot read {results}: {exc}"
        raise LoadError(msg) from exc
    if not isinstance(data, dict) or data.get("format") != EVALUATION_FORMAT:
        msg = f"{results} is not a flow-model evaluation ({EVALUATION_FORMAT})"
        raise LoadError(msg)
    when = evaluated_at or datetime.fromtimestamp(results.stat().st_mtime, tz=UTC)
    when = when.astimezone(UTC).replace(microsecond=0)
    dataset = str(data["dataset"])
    version = data.get("prohori_version")
    rows: list[tuple[Any, ...]] = []
    for variant, details in data["variants"].items():
        for model, model_results in details["models"].items():
            for run in model_results["runs"]:
                test = run["test"]
                for point, values in test["operating_points"].items():
                    key = "\x1f".join(
                        (dataset, variant, model, str(run["seed"]), point, when.isoformat())
                    )
                    rows.append(
                        (
                            "eval-" + hashlib.sha256(key.encode()).hexdigest()[:24],
                            when,
                            dataset,
                            variant,
                            model,
                            int(run["seed"]),
                            point,
                            values.get("threshold"),
                            int(test["flows"]),
                            int(test["attacks"]),
                            int(values["alerts"]),
                            float(values["recall"]),
                            values.get("precision"),
                            float(values["fpr"]),
                            float(values["false_alerts_per_10k"]),
                            float(test["pr_auc"]),
                            float(test["roc_auc"]),
                            version,
                        )
                    )
    return rows


def open_warehouse(*, database: Path, postgres: str | None = None) -> Sink:
    """A sink to write loader rows with: PostgreSQL when ``postgres`` is given, else DuckDB."""
    if postgres:
        from prohori.pipeline.postgres import PostgresSink

        return PostgresSink(MemoryTransport(), postgres)
    return DuckDBSink(MemoryTransport(), database)


def load(sink: Sink, table: str, rows: Sequence[tuple[Any, ...]], *, chunk: int = 5000) -> int:
    """Write ``rows`` to ``table`` in chunks; return how many rows were offered."""
    for start in range(0, len(rows), chunk):
        sink.write({table: rows[start : start + chunk]})
    return len(rows)
