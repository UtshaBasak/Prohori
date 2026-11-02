"""Docker smoke test for the orchestration profile: every DAG runs in the stack with Airflow.

Skipped unless ``PROHORI_DOCKER_TESTS=1`` and Docker is running. It builds two images, starts
about 6 GB of containers and **deletes the stack's data volumes** before and after. The
``Docker stack`` workflow runs it on Linux, where data/ holds no dataset, so the nightly
evaluation is skipped (its gate is tested in tests/unit/pipeline/test_jobs.py).

    PROHORI_DOCKER_TESTS=1 uv run pytest tests/integration/test_airflow_stack.py -v
"""

import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from prohori.cli import app
from prohori.pipeline import stack


def _docker_running() -> bool:
    if shutil.which("docker") is None:
        return False
    info = subprocess.run(["docker", "info"], capture_output=True, check=False)  # noqa: S607
    return info.returncode == 0


pytestmark = [
    pytest.mark.slow,
    pytest.mark.docker,
    pytest.mark.skipif(
        os.environ.get("PROHORI_DOCKER_TESTS") != "1" or not _docker_running(),
        reason="set PROHORI_DOCKER_TESTS=1 with Docker running to test the Docker stack",
    ),
]

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ROOT / "pipeline" / "docker-compose.yml"
runner = CliRunner(env={"COLUMNS": "200", "NO_COLOR": "1"})


def _airflow(*args: str) -> str:
    """Run the airflow CLI in the container; return its output (warnings stripped)."""
    done = stack.compose(
        ["--profile", stack.ORCHESTRATION, "exec", "-T", "airflow", "airflow", *args],
        COMPOSE,
        capture=True,
    )
    assert done.returncode == 0, done.stdout[-2000:] + done.stderr[-2000:]
    return done.stdout


def _json(text: str) -> Any:
    return json.loads(next(line for line in text.splitlines() if line[:1] in "[{"))


def _run(dag_id: str, conf: str = "{}", timeout: float = 1200) -> dict[str, str]:
    """Trigger a DAG, wait for the run to finish and return its task states."""
    run_id = _json(_airflow("dags", "trigger", dag_id, "--conf", conf, "-o", "json"))[0][
        "dag_run_id"
    ]
    deadline = time.monotonic() + timeout
    state = ""
    while time.monotonic() < deadline:
        runs = _json(_airflow("dags", "list-runs", dag_id, "-o", "json"))
        state = next(r["state"] for r in runs if r["run_id"] == run_id)
        if state in {"success", "failed"}:
            break
        time.sleep(10)
    tasks = _json(_airflow("tasks", "states-for-dag-run", dag_id, run_id, "-o", "json"))
    states = {t["task_id"]: t["state"] for t in tasks}
    assert state == "success", (dag_id, states)
    return states


def _rows(dsn: str, table: str) -> int:
    import psycopg

    with psycopg.connect(dsn, connect_timeout=5) as connection:
        row = connection.execute(f"SELECT count(*) FROM {table}").fetchone()  # noqa: S608
        return int(row[0]) if row else 0


def test_every_dag_runs_in_the_stack(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(ROOT)
    stack.down(COMPOSE, volumes=True)
    try:
        up = runner.invoke(app, ["pipeline", "up", "--orchestration", "--timeout", "900"])
        assert up.exit_code == 0, up.output
        assert "Airflow: http://127.0.0.1:18080" in up.stdout
        assert _json(_airflow("dags", "list-import-errors", "-o", "json")) == []

        # Backfill all eight scenarios into the empty stack, then build the marts.
        states = _run("prohori_backfill", '{"start": "2026-10-20T06:00:00Z"}', timeout=2400)
        assert set(states.values()) == {"success"}
        dsn = stack.default_dsn()
        assert _rows(dsn, "raw.labels") == _rows(dsn, "raw.events") > 7000
        assert _rows(dsn, "marts.attack_detection") == 8

        quality = _run("prohori_data_quality")
        assert quality == {"dbt_build": "success", "source_freshness": "success"}
        assert _run("prohori_incident_digest") == {"write_digest": "success"}
        digests = stack.compose(
            [
                "--profile",
                stack.ORCHESTRATION,
                "exec",
                "-T",
                "airflow",
                "sh",
                "-c",
                "cat /opt/prohori-output/digests/*.json",
            ],
            COMPOSE,
            capture=True,
        )
        assert json.loads(digests.stdout)["events"] == _rows(dsn, "raw.events")
        assert _run("prohori_enrichment_refresh") == {"refresh_cache": "success"}
        # No dataset in data/ on CI: training is skipped and so are the steps after it.
        nightly = _run("prohori_nightly_evaluation")
        if not (ROOT / "data" / "raw" / "unsw-nb15").is_dir():
            assert set(nightly.values()) == {"skipped"}
    finally:
        down = runner.invoke(app, ["pipeline", "down", "--volumes"])
        assert down.exit_code == 0, down.output
    assert stack.services(COMPOSE) == []
