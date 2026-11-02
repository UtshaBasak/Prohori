"""Docker smoke test: the real stack (Redpanda, PostgreSQL, one container per stage, Grafana).

Skipped unless ``PROHORI_DOCKER_TESTS=1`` and Docker is running, because it builds an image,
starts about 3 GB of containers and **deletes the stack's data volumes** before and after. The
``Docker stack`` workflow runs it on Linux.

    PROHORI_DOCKER_TESTS=1 uv run pytest tests/integration/test_docker_stack.py -v
"""

import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from prohori.cli import app
from prohori.cli.incidents import ParseOptions, run_incidents
from prohori.incidents import IncidentSettings
from prohori.pipeline import stack
from prohori.rules import builtin_rules_dir, load_rules
from prohori.simulate import simulate, write


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
DBT_PATHS = [
    "--project-dir",
    str(ROOT / "pipeline" / "dbt"),
    "--profiles-dir",
    str(ROOT / "pipeline" / "dbt"),
]
DASHBOARDS = ROOT / "pipeline" / "grafana" / "dashboards"
RULES = [r.rule for r in load_rules([builtin_rules_dir()]) if r.rule is not None]
runner = CliRunner(env={"COLUMNS": "200", "NO_COLOR": "1"})


def _rows(dsn: str) -> dict[str, int]:
    import psycopg

    with psycopg.connect(dsn, connect_timeout=5) as connection:
        tables = ("events", "alerts", "incidents", "dead_letters")
        return {
            t: connection.execute(f"SELECT count(*) FROM raw.{t}").fetchone()[0]  # type: ignore[index]  # noqa: S608
            for t in tables
        }


def _incident_ids(dsn: str) -> set[str]:
    import psycopg

    with psycopg.connect(dsn, connect_timeout=5) as connection:
        return {row[0] for row in connection.execute("SELECT id FROM raw.incidents").fetchall()}


def _dbt() -> str | None:
    beside = Path(sys.executable).parent / ("dbt.exe" if os.name == "nt" else "dbt")
    return str(beside) if beside.is_file() else shutil.which("dbt")


def _precision(dsn: str) -> dict[str, float | None]:
    import psycopg

    with psycopg.connect(dsn, connect_timeout=5) as connection:
        rows = connection.execute("SELECT detector_id, precision FROM marts.rule_precision")
        return dict(rows.fetchall())


def _grafana(path: str, body: object | None = None) -> Any:
    """A Grafana API call without credentials (the dashboards are open to anonymous viewers)."""
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(  # noqa: S310 - fixed http://127.0.0.1 URL
        stack.dashboard_url() + path, data, {"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
            return json.load(response)
    except urllib.error.HTTPError as exc:
        return json.loads(exc.read() or b"{}")


def _panel_results(board: str) -> dict[str, tuple[int, str]]:
    """Every panel of a provisioned dashboard through Grafana's query API: (rows, error)."""
    results = {}
    for panel in json.loads((DASHBOARDS / board).read_text(encoding="utf-8"))["panels"]:
        for target in panel.get("targets", []):
            query = dict(target, intervalMs=60000, maxDataPoints=1000)
            body = {"from": "now-3650d", "to": "now", "queries": [query]}
            answer = _grafana("/api/ds/query", body)
            result = answer.get("results", {}).get("A", {}) if isinstance(answer, dict) else {}
            frames = result.get("frames", [])
            rows = sum(len((f["data"].get("values") or [[]])[0]) for f in frames)
            results[panel["title"]] = (rows, result.get("error", "" if result else str(answer)))
    return results


def _memory_within_limits() -> list[str]:
    """Containers whose memory use is at or above their limit (should be none)."""
    done = subprocess.run(
        ["docker", "stats", "--no-stream", "--format", "{{.Name}} {{.MemPerc}}"],  # noqa: S607
        capture_output=True,
        text=True,
        check=True,
    )
    over = []
    for line in done.stdout.splitlines():
        name, percent = line.rsplit(" ", 1)
        if name.startswith("prohori-") and float(percent.rstrip("%")) >= 100.0:
            over.append(line)
    return over


def test_replay_reaches_postgres_once_and_matches_batch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(ROOT)
    stack.down(COMPOSE, volumes=True)  # start from empty topics and an empty warehouse
    try:
        up = runner.invoke(app, ["pipeline", "up", "--timeout", "600"])
        assert up.exit_code == 0, up.output

        simulation = simulate("password-spraying", seed=1)
        write(simulation, tmp_path)
        log = tmp_path / simulation.scenario.filename
        expected = run_incidents(
            str(log),
            rules=RULES,
            enricher=None,
            enrichment="none",
            settings=IncidentSettings(),
            lateness=timedelta(minutes=5),
            parse=ParseOptions(simulation.scenario.parser),
        ).incidents
        lines = log.read_bytes().count(b"\n")

        replay = ["pipeline", "replay", str(log), "--bootstrap", stack.default_bootstrap()]
        published = runner.invoke(app, [*replay, "--times", "2"])
        assert published.exit_code == 0, published.output

        dsn = stack.default_dsn()
        deadline = time.monotonic() + 240
        rows: dict[str, int] = {}
        while time.monotonic() < deadline:
            try:
                rows = _rows(dsn)
            except Exception:
                rows = {}
            if rows.get("incidents") == len(expected) and rows.get("events") == lines:
                break
            time.sleep(3)
        assert rows.get("events") == lines, rows  # replayed twice, stored once
        assert rows.get("dead_letters") == 0, rows
        stored, wanted = _incident_ids(dsn), {i.id for i in expected}
        assert stored == wanted, (
            f"extra {sorted(stored - wanted)}, missing {sorted(wanted - stored)}"
        )

        status = runner.invoke(app, ["pipeline", "status"])
        assert status.exit_code == 0, status.output
        assert f"incidents {len(expected)}" in status.stdout, status.stdout
        assert _memory_within_limits() == []

        # The provisioned dashboards fill without any setup: every panel on the raw tables
        # returns rows (dead letters excepted: there are none).
        assert _grafana("/api/health")["database"] == "ok"
        found = _grafana("/api/search?type=dash-db&tag=prohori")
        assert {d["uid"] for d in found} == {
            "prohori-overview",
            "prohori-detection-quality",
            "prohori-pipeline-health",
        }
        for board in ("overview.json", "pipeline-health.json"):
            for title, (count, error) in _panel_results(board).items():
                assert not error, (board, title, error)
                assert count > 0 or "Dead letters by" in title, (board, title)

        # The warehouse models build on PostgreSQL (with the dbt group installed).
        labels = runner.invoke(app, ["pipeline", "load-labels", str(log), "--postgres", dsn])
        assert labels.exit_code == 0, labels.output
        dbt = _dbt()
        if dbt is not None:
            built = subprocess.run(  # noqa: S603 - fixed arguments
                [dbt, "build", "--target", "postgres", *DBT_PATHS],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            assert built.returncode == 0, built.stdout[-4000:]
            precision = _precision(dsn)
            assert precision["PRH-AUTH-002"] == 1.0, precision
            # Grafana's read-only role can read the marts dbt just replaced.
            for title, (_, error) in _panel_results("detection-quality.json").items():
                assert not error, (title, error)

        # A stage stops gracefully on SIGTERM: it finishes and reports its counters.
        stack.compose(["stop", "detect"], COMPOSE)
        logs = stack.compose(["logs", "--no-color", "detect"], COMPOSE, capture=True)
        output = logs.stdout + logs.stderr
        assert '"stopped": ["detect"]' in output, output[-2000:]
    except BaseException:
        logs = stack.compose(
            ["--profile", stack.ORCHESTRATION, "logs", "--no-color", "--tail", "150"],
            COMPOSE,
            capture=True,
        )
        print(logs.stdout[-60000:], logs.stderr[-5000:])  # noqa: T201 - shown on failure
        raise
    finally:
        down = runner.invoke(app, ["pipeline", "down", "--volumes"])
        assert down.exit_code == 0, down.output
    assert stack.services(COMPOSE) == []
