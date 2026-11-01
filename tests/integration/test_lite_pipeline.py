"""Lite mode end to end: simulated logs in, incidents in DuckDB.

The streaming pipeline must produce exactly the incidents of the batch command, store each event,
alert and incident once when the input is replayed, survive a crash mid-run, and send malformed
messages to the dead-letter table.
"""

from datetime import timedelta
from pathlib import Path
from typing import Any

import duckdb
import pytest

from prohori.cli.incidents import ParseOptions, run_incidents
from prohori.incidents import IncidentSettings
from prohori.pipeline.messages import Topic
from prohori.pipeline.producers import replay
from prohori.pipeline.runner import LitePipeline, LiteSettings
from prohori.pipeline.stages import ParserSettings
from prohori.pipeline.transport import FileTransport
from prohori.rules import builtin_rules_dir, load_rules
from prohori.schema import Incident
from prohori.simulate import SCENARIOS, simulate, write

pytestmark = pytest.mark.integration

RULES = [r.rule for r in load_rules([builtin_rules_dir()]) if r.rule is not None]
LATENESS = timedelta(minutes=5)


def _scenario(name: str, out: Path) -> tuple[Path, str, int | None]:
    simulation = simulate(name, seed=1)
    write(simulation, out)
    scenario = simulation.scenario
    year = simulation.year if scenario.parser == "auth_log" else None
    return out / scenario.filename, scenario.parser, year


def _batch(log: Path, parser: str, year: int | None) -> list[Incident]:
    run = run_incidents(
        str(log),
        rules=RULES,
        enricher=None,
        enrichment="none",
        settings=IncidentSettings(),
        lateness=LATENESS,
        parse=ParseOptions(parser, year),
    )
    return run.incidents


def _lite(state: Path, database: Path, year: int | None) -> LitePipeline:
    settings = LiteSettings(
        rules=RULES, database=database, parsers=ParserSettings(year=year), lateness=LATENESS
    )
    return LitePipeline(FileTransport(state, fsync=False), settings, batch_size=200)


def _stored(database: Path) -> list[Incident]:
    connection = duckdb.connect(str(database), read_only=True)
    try:
        rows = connection.execute("SELECT record FROM incidents ORDER BY id").fetchall()
    finally:
        connection.close()
    return [Incident.model_validate_json(row[0]) for row in rows]


def _comparable(incidents: list[Incident]) -> list[dict[str, Any]]:
    return sorted(
        (i.model_dump(mode="json", exclude={"provenance"}) for i in incidents),
        key=lambda i: i["id"],
    )


@pytest.fixture
def lite_paths(tmp_path: Path) -> tuple[Path, Path]:
    return tmp_path / "state", tmp_path / "prohori.duckdb"


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_replayed_twice_matches_the_batch_command_without_duplicate_rows(
    name: str, tmp_path: Path, lite_paths: tuple[Path, Path]
) -> None:
    log, parser, year = _scenario(name, tmp_path / "logs")
    expected = _batch(log, parser, year)
    state, database = lite_paths
    pipeline = _lite(state, database, year)
    for _ in range(2):
        replay(log, pipeline.transport, parser=parser)
    metrics = pipeline.run()
    pipeline.close()

    lines = log.read_bytes().count(b"\n")
    assert metrics["stages"]["normalise"]["consumed"] == 2 * lines
    assert metrics["stages"]["detect"]["duplicates"] == metrics["tables"]["events"]
    assert metrics["tables"]["incidents"] == len(expected)
    assert metrics["tables"]["alerts"] == len({a.id for i in expected for a in i.alerts})
    assert _comparable(_stored(database)) == _comparable(expected)
    assert all(i.provenance is not None for i in _stored(database))


def test_crash_mid_run_then_restart_stores_everything_once(
    tmp_path: Path, lite_paths: tuple[Path, Path]
) -> None:
    log, parser, year = _scenario("password-spraying", tmp_path / "logs")
    expected = _batch(log, parser, year)
    state, database = lite_paths
    crashed = _lite(state, database, year)
    replay(log, crashed.transport, parser=parser)
    crashed.start()
    for _ in range(3):  # part of the input processed, then the process dies without finishing
        crashed.round()
    crashed.sink.close()
    crashed.transport.close()

    restarted = _lite(state, database, year)
    metrics = restarted.run()
    restarted.close()
    assert metrics["tables"]["events"] == log.read_bytes().count(b"\n")
    assert _comparable(_stored(database)) == _comparable(expected)


def test_malformed_messages_land_in_the_dead_letter_table(
    tmp_path: Path, lite_paths: tuple[Path, Path]
) -> None:
    log, parser, year = _scenario("web-scanning", tmp_path / "logs")
    state, database = lite_paths
    pipeline = _lite(state, database, year)
    replay(log, pipeline.transport, parser=parser)
    transport = pipeline.transport
    assert isinstance(transport, FileTransport)
    # A line the access_log parser rejects, plus garbage written straight into two topics.
    transport.publish(
        Topic.RAW_LOGS,
        log.name,
        {
            "v": 1,
            "source": log.name,
            "line": 99_999,
            "text": "this is not an access log line",
            "parser": parser,
            "read_at": "2026-10-01T00:00:00Z",
        },
    )
    transport.append_raw(Topic.EVENTS, b"{this is not json\n")
    transport.publish(Topic.EVENTS, "bad", {"id": "evt-x", "timestamp": "not a time"})
    transport.flush()
    metrics = pipeline.run()
    pipeline.close()

    assert metrics["stages"]["normalise"]["dead_letters"] == 1
    # The detector and the incident stage both read the events topic, and the sink stores events.
    assert metrics["stages"]["detect"]["dead_letters"] == 2
    assert metrics["tables"]["dead_letters"] == 1 + 2 + 2 + 2
    assert metrics["tables"]["events"] == log.read_bytes().count(b"\n")
    connection = duckdb.connect(str(database), read_only=True)
    try:
        reasons = {
            (stage, reason)
            for stage, reason in connection.execute(
                "SELECT stage, reason FROM dead_letters"
            ).fetchall()
        }
    finally:
        connection.close()
    assert ("detect", "not valid JSON") in reasons
    assert any(stage == "normalise" for stage, _ in reasons)
    assert any(stage == "sink" and reason.startswith("invalid") for stage, reason in reasons)
