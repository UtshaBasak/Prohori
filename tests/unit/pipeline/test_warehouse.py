"""Warehouse tables and loaders: labels and flow-model results."""

import json
from datetime import UTC, datetime
from pathlib import Path

import duckdb
import pytest
from typer.testing import CliRunner

from prohori.cli import app
from prohori.cli.exit_codes import ExitCode
from prohori.pipeline.producers import replay
from prohori.pipeline.runner import LitePipeline, LiteSettings
from prohori.pipeline.tables import TABLES, column_names, ddl, json_columns
from prohori.pipeline.transport import MemoryTransport
from prohori.pipeline.warehouse import (
    LoadError,
    evaluation_rows,
    label_rows,
    labels_path,
    load,
    open_warehouse,
)
from prohori.rules import builtin_rules_dir, load_rules
from prohori.simulate import simulate, write
from tests.unit.enrich.conftest import isolated_settings, no_network

__all__ = ["isolated_settings", "no_network"]  # autouse: no network, no real cache or keys

ROOT = Path(__file__).resolve().parents[3]
RESULTS = ROOT / "results" / "ml_unsw-nb15.json"
RULES = [r.rule for r in load_rules([builtin_rules_dir()]) if r.rule is not None]
runner = CliRunner(env={"COLUMNS": "200", "NO_COLOR": "1"})


@pytest.fixture(scope="module")
def simulated(tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("sim")
    write(simulate("password-spraying", seed=1), out)
    return out / "password-spraying.jsonl"


def test_ddl_for_both_databases() -> None:
    duck = ddl("duckdb")
    postgres = ddl("postgres", prefix="raw.")
    for table in TABLES:
        assert f"CREATE TABLE IF NOT EXISTS {table} (" in duck
        assert f"CREATE TABLE IF NOT EXISTS raw.{table} (" in postgres
    assert "record JSON NOT NULL" in duck
    assert "record JSONB NOT NULL" in postgres
    assert "stored_at TIMESTAMPTZ NOT NULL DEFAULT current_timestamp" in duck
    assert "DEFAULT now()" in postgres
    assert column_names("labels") == ("id", "source", "line", "scenario", "attack_id")
    assert json_columns("events") == {"record"}
    assert json_columns("labels") == frozenset()


def test_tables_from_step_18_get_stored_at(tmp_path: Path) -> None:
    path = tmp_path / "old.duckdb"
    connection = duckdb.connect(str(path))
    connection.execute(
        "CREATE TABLE dead_letters (id VARCHAR PRIMARY KEY, stage VARCHAR NOT NULL,"
        " topic VARCHAR NOT NULL, key VARCHAR, reason VARCHAR NOT NULL,"
        " payload VARCHAR NOT NULL)"
    )
    connection.close()
    sink = open_warehouse(database=path)
    columns = {r[0] for r in sink.connection.execute("DESCRIBE dead_letters").fetchall()}  # type: ignore[attr-defined]
    sink.close()
    assert "stored_at" in columns


def test_labels_match_the_events_a_replay_stores(simulated: Path, tmp_path: Path) -> None:
    database = tmp_path / "w.duckdb"
    pipeline = LitePipeline(MemoryTransport(), LiteSettings(rules=RULES, database=database))
    replay(simulated, pipeline.transport, parser="app_json")
    pipeline.run()
    pipeline.close()
    rows = label_rows(simulated)
    assert labels_path(simulated).name == "password-spraying.labels.jsonl"
    assert len(rows) == 622
    assert {r[3] for r in rows} == {"password-spraying"}  # from manifest.json
    assert sum(1 for r in rows if r[4] is not None) == 30
    sink = open_warehouse(database=database)
    assert load(sink, "labels", rows, chunk=100) == 622
    load(sink, "labels", rows)  # again: nothing new
    joined = sink.connection.execute(  # type: ignore[attr-defined]
        "SELECT count(*) FROM labels JOIN events USING (id)"
    ).fetchone()
    sink.close()
    assert joined == (622,)


def test_label_errors(simulated: Path, tmp_path: Path) -> None:
    with pytest.raises(LoadError, match="cannot read labels"):
        label_rows(simulated, tmp_path / "missing.jsonl")
    bad = tmp_path / "bad.jsonl"
    bad.write_text('{"line": 1, "attack": null}\n\n{"line": "x"}\n', encoding="utf-8")
    with pytest.raises(LoadError, match="line 3"):
        label_rows(simulated, bad)
    lone = tmp_path / "lone.jsonl"
    lone.write_bytes(simulated.read_bytes())
    rows = label_rows(lone, labels_path(simulated), scenario="mine")
    assert {r[3] for r in rows} == {"mine"}
    assert label_rows(lone, labels_path(simulated))[0][3] is None  # no manifest for this name


def test_evaluation_rows(tmp_path: Path) -> None:
    when = datetime(2026, 10, 31, tzinfo=UTC)
    rows = evaluation_rows(RESULTS, when)
    data = json.loads(RESULTS.read_text(encoding="utf-8"))
    runs = sum(
        len(m["runs"]) * len(m["runs"][0]["test"]["operating_points"])
        for v in data["variants"].values()
        for m in v["models"].values()
    )
    assert len(rows) == runs
    assert len({r[0] for r in rows}) == len(rows)
    assert {r[1] for r in rows} == {when}
    assert rows == evaluation_rows(RESULTS, when)  # same ids again
    mtime = datetime.fromtimestamp(RESULTS.stat().st_mtime, tz=UTC).replace(microsecond=0)
    assert evaluation_rows(RESULTS)[0][1] == mtime  # the file's time by default
    other = tmp_path / "x.json"
    other.write_text('{"format": "something/1"}', encoding="utf-8")
    with pytest.raises(LoadError, match="not a flow-model evaluation"):
        evaluation_rows(other)
    with pytest.raises(LoadError, match="cannot read"):
        evaluation_rows(tmp_path / "missing.json")


def test_load_commands(simulated: Path, tmp_path: Path) -> None:
    state = ["--state", str(tmp_path)]
    labels = runner.invoke(app, ["pipeline", "load-labels", str(simulated), *state])
    assert labels.exit_code == 0, labels.output
    assert "Loaded labels for 622 event(s) (30 attack) from 1 log(s)." in labels.stdout
    results = runner.invoke(
        app, ["pipeline", "load-results", str(RESULTS), "--evaluated-at", "2026-10-31", *state]
    )
    assert results.exit_code == 0, results.output
    assert "evaluation row(s) from 1 file(s)" in results.stdout
    connection = duckdb.connect(str(tmp_path / "prohori.duckdb"), read_only=True)
    try:
        when = connection.execute(
            "SELECT DISTINCT CAST(evaluated_at AT TIME ZONE 'UTC' AS DATE) FROM model_evaluations"
        ).fetchall()
    finally:
        connection.close()
    assert [str(w[0]) for w in when] == ["2026-10-31"]


def test_load_command_errors(simulated: Path, tmp_path: Path) -> None:
    two = runner.invoke(
        app,
        ["pipeline", "load-labels", str(simulated), str(simulated), "--labels", str(simulated)],
    )
    assert two.exit_code == ExitCode.USAGE
    missing = runner.invoke(app, ["pipeline", "load-labels", str(tmp_path / "nope.log")])
    assert missing.exit_code == ExitCode.USAGE
    bad = runner.invoke(
        app, ["pipeline", "load-labels", str(simulated), "--labels", str(tmp_path / "x.jsonl")]
    )
    assert bad.exit_code == ExitCode.NO_EVENTS
    assert "cannot read labels" in bad.stderr
    wrong = runner.invoke(
        app, ["pipeline", "load-results", str(simulated), "--state", str(tmp_path)]
    )
    assert wrong.exit_code == ExitCode.NO_EVENTS
    unreachable = runner.invoke(
        app,
        ["pipeline", "load-results", str(RESULTS), "--postgres", "postgresql://u@127.0.0.1:1/db"],
    )
    assert unreachable.exit_code == ExitCode.NO_EVENTS
    assert "cannot open the warehouse" in unreachable.stderr
