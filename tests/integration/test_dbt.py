"""dbt models over a lite-mode warehouse built from the simulator.

Needs the dbt dependency group (``uv sync --group dbt``); skipped otherwise. CI runs it in the
``dbt (DuckDB)`` job. The rule precision the models compute must equal the simulator's own rule
evaluation for the same runs.
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import duckdb
import pytest

from prohori.rules import builtin_rules_dir, load_rules
from prohori.simulate.evaluate import evaluate
from scripts.build_lite_warehouse import build

ROOT = Path(__file__).resolve().parents[2]
PROJECT = ROOT / "pipeline" / "dbt"


def _dbt() -> str | None:
    beside = Path(sys.executable).parent / ("dbt.exe" if os.name == "nt" else "dbt")
    return str(beside) if beside.is_file() else shutil.which("dbt")


pytestmark = [
    pytest.mark.integration,
    pytest.mark.slow,
    pytest.mark.skipif(_dbt() is None, reason="needs the dbt group: uv sync --group dbt"),
]


def _run(*args: str, database: Path, tmp_path: Path) -> "subprocess.CompletedProcess[str]":
    dbt = _dbt()
    assert dbt is not None
    env = {
        **os.environ,
        "PROHORI_DUCKDB": str(database),
        "DBT_TARGET_PATH": str(tmp_path / "target"),
    }
    paths = ["--project-dir", str(PROJECT), "--profiles-dir", str(PROJECT)]
    return subprocess.run(  # noqa: S603 - fixed arguments
        [dbt, *args, *paths, "--log-path", str(tmp_path / "logs")],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.fixture(scope="module")
def warehouse(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    work = tmp_path_factory.mktemp("warehouse")
    database = work / "prohori.duckdb"
    build(database, work / "simulated")
    return database, work


def test_dbt_build_and_freshness_pass(warehouse: tuple[Path, Path]) -> None:
    database, work = warehouse
    built = _run("build", database=database, tmp_path=work)
    assert built.returncode == 0, built.stdout[-4000:]
    assert "ERROR=0" in built.stdout
    fresh = _run("source", "freshness", database=database, tmp_path=work)
    assert fresh.returncode == 0, fresh.stdout[-4000:]


def test_rule_precision_matches_the_simulator_evaluation(warehouse: tuple[Path, Path]) -> None:
    database, work = warehouse
    if not (work / "target").exists():
        assert _run("build", database=database, tmp_path=work).returncode == 0
    rules = [r.rule for r in load_rules([builtin_rules_dir()]) if r.rule is not None]
    expected = evaluate(rules, seeds=[1])["variants"]["default"]["rules"]  # type: ignore[index]
    connection = duckdb.connect(str(database), read_only=True)
    try:
        rows = connection.execute(
            "SELECT detector_id, alerts, true_positives, false_positives FROM marts.rule_precision"
        ).fetchall()
        attacks = connection.execute(
            "SELECT count(*), count(*) FILTER (WHERE detected) FROM marts.attack_detection"
        ).fetchone()
        days = connection.execute("SELECT sum(events) FROM marts.daily_attack_counts").fetchone()
        events = connection.execute("SELECT count(*) FROM main.events").fetchone()
    finally:
        connection.close()
    stored = {rule: (alerts, tp, fp) for rule, alerts, tp, fp in rows}
    wanted = {
        rule: (s["alerts"], s["true_positives"], s["false_positives"])
        for rule, s in expected.items()
        if s["alerts"]
    }
    assert stored == wanted
    assert attacks is not None
    assert attacks[0] == 8  # one attack per scenario
    assert attacks[1] == 8  # all caught in the default variants
    assert days == events
