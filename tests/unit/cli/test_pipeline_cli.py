"""``prohori pipeline``: lite mode, publishing to Kafka, ``run`` and the Docker stack commands."""

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from prohori.cli import app
from prohori.cli.exit_codes import ExitCode
from prohori.pipeline import kafka as kafka_module
from prohori.simulate import simulate, write
from tests.unit.enrich.conftest import isolated_settings, no_network
from tests.unit.pipeline.fake_kafka import Broker, fake_kafka

__all__ = ["isolated_settings", "no_network"]  # autouse: no network, no real cache or keys

ROOT = Path(__file__).resolve().parents[3]
runner = CliRunner(env={"COLUMNS": "200", "NO_COLOR": "1"})
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _plain(output: str) -> str:
    """Usage errors are drawn in a box that may wrap and colour the text; compare words only."""
    text = _ANSI.sub("", output)
    text = re.sub(r"[\u2500-\u257f|+]", " ", text)  # box-drawing characters and ASCII borders
    return " ".join(text.split())


@pytest.fixture(scope="module")
def web_log(tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("sim")
    write(simulate("web-scanning", seed=1), out)
    return out / "web-scanning.log"


def _json(output: str) -> dict[str, object]:
    return json.loads(output[output.index("{") :])  # type: ignore[no-any-return]


def test_replay_twice_writes_each_row_once(web_log: Path, tmp_path: Path) -> None:
    state = tmp_path / "state"
    args = ["pipeline", "replay", str(web_log), "--state", str(state), "--times", "2"]
    result = runner.invoke(app, args)
    assert result.exit_code == 0, result.output
    assert "Pipeline stages" in result.stdout
    assert "events 1,690" in result.stdout
    again = runner.invoke(app, [*args[:3], "--state", str(state), "-f", "json", "--no-enrich"])
    assert again.exit_code == 0, again.output
    metrics = _json(again.stdout)
    assert metrics["tables"] == {"events": 1690, "alerts": 22, "incidents": 1, "dead_letters": 0}
    assert metrics["lines_replayed"] == 1690
    assert (state / "prohori.duckdb").is_file()


def test_replay_to_a_chosen_database(web_log: Path, tmp_path: Path) -> None:
    database = tmp_path / "out" / "x.duckdb"
    result = runner.invoke(
        app,
        [
            "pipeline",
            "replay",
            str(web_log),
            "--state",
            str(tmp_path / "s"),
            "--db",
            str(database),
            "--parser",
            "access_log",
        ],
    )
    assert result.exit_code == 0, result.output
    assert database.is_file()


def test_replay_of_a_file_no_parser_accepts_exits_1(tmp_path: Path) -> None:
    log = tmp_path / "bad.log"
    log.write_text("not an access log\nstill not\n", encoding="utf-8")
    result = runner.invoke(
        app,
        ["pipeline", "replay", str(log), "--state", str(tmp_path / "s"), "--parser", "access_log"],
    )
    assert result.exit_code == ExitCode.NO_EVENTS, result.output
    assert "dead_letters 2" in result.stdout


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (["missing.log"], "not found"),
        (["{log}", "--parser", "nope"], "unknown parser"),
        (["{log}", "--gap", "soon"], "--gap"),
        (["{log}", "--lateness", "soon"], "lateness"),
    ],
)
def test_replay_usage_errors(web_log: Path, tmp_path: Path, args: list[str], message: str) -> None:
    filled = [a.replace("{log}", str(web_log)) for a in args]
    result = runner.invoke(app, ["pipeline", "replay", *filled, "--state", str(tmp_path)])
    assert result.exit_code == ExitCode.USAGE
    assert message in _plain(result.output)


def test_tail_follows_a_file_until_stopped(web_log: Path, tmp_path: Path) -> None:
    live = tmp_path / "live.log"
    live.write_bytes(web_log.read_bytes())
    state = tmp_path / "state"
    args = ["pipeline", "tail", str(live), "--state", str(state), "--poll", "0", "-f", "json"]
    result = runner.invoke(app, [*args, "--max-rounds", "2"])
    assert result.exit_code == 0, result.output
    metrics = _json(result.stdout)
    assert metrics["lines_tailed"] == 1690
    assert metrics["tables"]["events"] == 1690  # type: ignore[index]
    assert list((state / "tail").glob("*.json"))
    # Run again: the checkpoint says everything was read, so nothing is tailed twice.
    again = runner.invoke(app, [*args, "--max-rounds", "1"])
    assert _json(again.stdout)["lines_tailed"] == 0


def test_tail_with_an_unknown_parser_is_a_usage_error(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["pipeline", "tail", str(tmp_path / "x.log"), "--state", str(tmp_path), "-p", "nope"],
    )
    assert result.exit_code == ExitCode.USAGE
    assert "unknown parser" in _plain(result.output)


def test_pipeline_without_the_extra(web_log: Path, tmp_path: Path) -> None:
    """Without the extra, --help works and the commands explain how to install it."""
    code = f"""
import sys
for name in ("duckdb", "confluent_kafka", "psycopg"):
    sys.modules[name] = None
from typer.testing import CliRunner
from prohori.cli import app
runner = CliRunner()
print(runner.invoke(app, ["--help"]).exit_code)
result = runner.invoke(
    app, ["pipeline", "replay", {str(web_log)!r}, "--state", {str(tmp_path)!r}, "--no-enrich"]
)
print(result.exit_code)
print(result.stderr)
kafka = runner.invoke(app, ["pipeline", "replay", {str(web_log)!r}, "--bootstrap", "x:1"])
print(kafka.exit_code, kafka.stderr)
"""
    done = subprocess.run(  # noqa: S603 - fixed arguments
        [sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True, check=False
    )
    assert done.returncode == 0, done.stderr
    lines = done.stdout.splitlines()
    assert lines[:2] == ["0", "1"]
    assert "needs the 'pipeline' extra" in done.stdout
    assert "1 error: the Kafka transport needs the 'pipeline' extra" in done.stdout


# ---------------------------------------------------------------------- Kafka and run


@pytest.fixture
def broker(monkeypatch: pytest.MonkeyPatch) -> Broker:
    fake = Broker()
    monkeypatch.setattr(kafka_module, "client", lambda: fake_kafka(fake))
    return fake


def test_replay_and_tail_publish_to_kafka(broker: Broker, web_log: Path, tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["pipeline", "replay", str(web_log), "--bootstrap", "b:9092", "--times", "2"]
    )
    assert result.exit_code == 0, result.output
    assert "Published 3,380 line(s)" in result.stdout
    assert len(broker.topics["raw-logs"]) == 3380
    live = tmp_path / "live.log"
    live.write_bytes(web_log.read_bytes())
    args = ["pipeline", "tail", str(live), "--bootstrap", "b:9092", "--state", str(tmp_path)]
    tail = runner.invoke(app, [*args, "--poll", "0", "--max-rounds", "2"])
    assert tail.exit_code == 0, tail.output
    assert "Published 1,690 line(s)" in tail.stdout


def test_replay_to_an_unreachable_broker_exits_1(broker: Broker, web_log: Path) -> None:
    broker.unreachable = True
    result = runner.invoke(app, ["pipeline", "replay", str(web_log), "--bootstrap", "b:9092"])
    assert result.exit_code == ExitCode.NO_EVENTS
    assert "cannot reach the Kafka broker at b:9092" in result.stderr


def test_run_every_stage_over_kafka(broker: Broker, web_log: Path, tmp_path: Path) -> None:
    runner.invoke(app, ["pipeline", "replay", str(web_log), "--bootstrap", "b:9092"])
    database = tmp_path / "k.duckdb"
    args = ["pipeline", "run", "--stage", "all", "--bootstrap", "b:9092", "--db", str(database)]
    args += ["--idle-close", "0", "--poll", "0", "--max-rounds", "10", "--no-enrich"]
    result = runner.invoke(app, args, env={"PROHORI_POSTGRES_DSN": ""})
    assert result.exit_code == 0, result.output
    stopped = json.loads(result.stderr.strip().splitlines()[-1])
    assert stopped["stopped"] == ["normalise", "detect", "incidents", "sink"]
    assert stopped["stages"]["sink"]["produced"] > 1690
    assert broker.committed[("prohori-sink", "events")] == 1690


def test_run_without_a_reachable_database_exits_1(
    broker: Broker, monkeypatch: pytest.MonkeyPatch
) -> None:
    import psycopg

    def refuse(*args: object, **kwargs: object) -> None:
        raise psycopg.OperationalError("connection refused")

    monkeypatch.setattr(psycopg, "connect", refuse)
    result = runner.invoke(
        app,
        ["pipeline", "run", "--stage", "sink", "--bootstrap", "b:9092", "--no-enrich"],
        env={"PROHORI_POSTGRES_DSN": "postgresql://u@127.0.0.1:1/db"},
    )
    assert result.exit_code == ExitCode.NO_EVENTS
    assert "cannot start the sink stage: connection refused" in result.stderr


# ---------------------------------------------------------------------- the Docker stack


class Compose:
    """Records docker compose calls and answers ``ps`` with ``services``."""

    def __init__(self, services: list[dict[str, object]], returncode: int = 0) -> None:
        self.services = services
        self.returncode = returncode
        self.calls: list[list[str]] = []

    def __call__(self, command: list[str], **options: object) -> "subprocess.CompletedProcess[str]":
        self.calls.append(command)
        stdout = "\n".join(json.dumps(s) for s in self.services) if "ps" in command else ""
        return subprocess.CompletedProcess(command, self.returncode, stdout, "")


HEALTHY: list[dict[str, object]] = [
    {"Service": name, "State": "running", "Health": "healthy"}
    for name in ("detect", "incidents", "normalise", "postgres", "redpanda", "sink")
]


@pytest.fixture
def compose(monkeypatch: pytest.MonkeyPatch) -> Compose:
    recorder = Compose(HEALTHY)
    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(subprocess, "run", recorder)
    monkeypatch.chdir(ROOT)
    monkeypatch.setenv("PROHORI_POSTGRES_DSN", "postgresql://u@127.0.0.1:1/db")
    monkeypatch.delenv("PROHORI_GRAFANA_PORT", raising=False)
    return recorder


def test_up_status_and_down(compose: Compose, monkeypatch: pytest.MonkeyPatch) -> None:
    import psycopg

    def refuse(*args: object, **kwargs: object) -> None:
        raise psycopg.OperationalError("refused")

    monkeypatch.setattr(psycopg, "connect", refuse)
    up = runner.invoke(app, ["pipeline", "up", "--no-build", "--timeout", "30"])
    assert up.exit_code == 0, up.output
    assert "--wait" in compose.calls[0]
    assert "--build" not in compose.calls[0]
    assert "redpanda" in up.stdout
    assert "--bootstrap 127.0.0.1:19092" in up.stdout
    assert "Dashboards: http://127.0.0.1:13000" in up.stdout
    status = runner.invoke(app, ["pipeline", "status"])
    assert status.exit_code == 0, status.output
    assert "Warehouse: not reachable." in status.stdout
    as_json = runner.invoke(app, ["pipeline", "status", "-f", "json"])
    payload = json.loads(as_json.stdout)
    assert payload["healthy"] is True
    assert payload["rows"] is None
    assert payload["dashboards"] == "http://127.0.0.1:13000"
    assert len(payload["services"]) == 6
    down = runner.invoke(app, ["pipeline", "down", "--volumes"])
    assert down.exit_code == 0
    assert compose.calls[-1][-2:] == ["--remove-orphans", "--volumes"]
    assert "data deleted" in down.stdout


def test_status_counts_rows_in_the_warehouse(
    compose: Compose, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tests.unit.pipeline.test_postgres import FakeConnection

    fake = FakeConnection()
    fake.tables["raw.events"] = {"e1": ("e1",), "e2": ("e2",)}
    monkeypatch.setattr("psycopg.connect", lambda *a, **k: fake)
    status = runner.invoke(app, ["pipeline", "status"])
    assert "Warehouse rows: events 2, alerts 0, incidents 0, dead_letters 0." in status.stdout
    assert fake.closed


def test_unhealthy_or_stopped_stack(compose: Compose) -> None:
    compose.services = [{"Service": "sink", "State": "restarting", "Health": ""}]
    status = runner.invoke(app, ["pipeline", "status", "-f", "json"])
    assert status.exit_code == ExitCode.NO_EVENTS
    up = runner.invoke(app, ["pipeline", "up"])
    assert up.exit_code == ExitCode.NO_EVENTS
    assert "did not become healthy" in up.stderr
    compose.services = []
    stopped = runner.invoke(app, ["pipeline", "status"])
    assert stopped.exit_code == ExitCode.NO_EVENTS
    assert "not running" in stopped.stdout
    compose.returncode = 1
    assert runner.invoke(app, ["pipeline", "down"]).exit_code == ExitCode.NO_EVENTS
    assert runner.invoke(app, ["pipeline", "status"]).exit_code == ExitCode.NO_EVENTS


def test_stack_commands_need_docker_and_the_compose_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: None)
    no_docker = runner.invoke(app, ["pipeline", "status"])
    assert no_docker.exit_code == ExitCode.NO_EVENTS
    assert "Docker is not installed" in no_docker.stderr
    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.chdir(tmp_path)
    no_file = runner.invoke(app, ["pipeline", "up"])
    assert "clone of the Prohori repository" in no_file.stderr
