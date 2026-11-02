"""Docker stack helpers: command lines, ``docker compose ps`` parsing and health."""

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

from prohori.pipeline import stack

ROOT = Path(__file__).resolve().parents[3]
COMPOSE = ROOT / "pipeline" / "docker-compose.yml"


class Recorder:
    def __init__(self, stdout: str = "", returncode: int = 0) -> None:
        self.calls: list[list[str]] = []
        self.stdout = stdout
        self.returncode = returncode

    def __call__(self, command: list[str], **options: Any) -> "subprocess.CompletedProcess[str]":
        assert options["check"] is False
        assert "shell" not in options
        self.calls.append(command)
        return subprocess.CompletedProcess(command, self.returncode, self.stdout, "boom")


@pytest.fixture(autouse=True)
def docker_on_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")


def test_up_and_down_command_lines() -> None:
    run = Recorder()
    assert stack.up(COMPOSE, run=run, timeout=60) == 0
    assert stack.down(COMPOSE, volumes=True, run=run) == 0
    assert stack.up(COMPOSE, build=False, run=run) == 0
    assert stack.up(COMPOSE, orchestration=True, run=run) == 0
    base = ["/usr/bin/docker", "compose", "-p", "prohori", "-f", str(COMPOSE)]
    assert run.calls[0] == [*base, "up", "--detach", "--wait", "--wait-timeout", "60", "--build"]
    profile = ["--profile", "orchestration"]
    assert run.calls[1] == [*base, *profile, "down", "--remove-orphans", "--volumes"]
    assert "--build" not in run.calls[2]
    assert run.calls[3][len(base) : len(base) + 3] == [*profile, "up"]


def test_docker_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: None)
    with pytest.raises(stack.StackError, match="Docker is not installed"):
        stack.docker_executable()


def test_compose_file_lookup(tmp_path: Path) -> None:
    assert stack.compose_file(COMPOSE) == COMPOSE
    with pytest.raises(stack.StackError, match="clone of the Prohori repository"):
        stack.compose_file(tmp_path / "nope.yml")


@pytest.mark.parametrize("as_array", [True, False])
def test_parse_ps_formats(as_array: bool) -> None:
    items = [
        {"Service": "redpanda", "State": "running", "Health": "healthy", "ExitCode": 0},
        {"Service": "detect", "State": "running", "Health": "starting", "ExitCode": 0},
        {"Service": "warehouse-init", "State": "exited", "Health": "", "ExitCode": 0},
        {"Service": "sink", "State": "exited", "Health": "", "ExitCode": 1},
    ]
    text = json.dumps(items) if as_array else "\n".join(json.dumps(i) for i in items)
    services = {s.name: s for s in stack.parse_ps(text)}
    assert services["redpanda"].ok
    assert not services["detect"].ok
    assert services["warehouse-init"].ok
    assert not services["sink"].ok
    assert stack.parse_ps("  ") == []


def test_services_runs_ps_and_reports_failures() -> None:
    line = json.dumps({"Service": "postgres", "State": "running", "Health": "healthy"})
    assert [s.name for s in stack.services(COMPOSE, run=Recorder(line))] == ["postgres"]
    with pytest.raises(stack.StackError, match="boom"):
        stack.services(COMPOSE, run=Recorder(returncode=1))


def test_default_addresses(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("PROHORI_POSTGRES_DSN", "PROHORI_POSTGRES_PASSWORD", "PROHORI_POSTGRES_PORT"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("PROHORI_KAFKA_BOOTSTRAP", raising=False)
    monkeypatch.delenv("PROHORI_GRAFANA_PORT", raising=False)
    assert stack.default_dsn().endswith("@127.0.0.1:15432/prohori")
    assert stack.default_bootstrap() == "127.0.0.1:19092"
    assert stack.dashboard_url() == "http://127.0.0.1:13000"
    monkeypatch.delenv("PROHORI_AIRFLOW_PORT", raising=False)
    assert stack.airflow_url() == "http://127.0.0.1:18080"
    monkeypatch.setenv("PROHORI_GRAFANA_PORT", "3001")
    assert stack.dashboard_url() == "http://127.0.0.1:3001"
    monkeypatch.setenv("PROHORI_POSTGRES_PORT", "5433")
    assert stack.default_dsn().endswith(":5433/prohori")
    monkeypatch.setenv("PROHORI_POSTGRES_DSN", "postgresql://elsewhere/db")
    assert stack.default_dsn() == "postgresql://elsewhere/db"


def test_compose_file_publishes_on_localhost_only_and_pins_images() -> None:
    services = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))["services"]
    ports = [p for s in services.values() for p in s.get("ports", [])]
    assert len(ports) == 4
    assert all(p.startswith("127.0.0.1:") for p in ports)
    images = {s["image"] for s in services.values()}
    assert all("@sha256:" in i for i in images - {"prohori:local", "prohori-airflow:local"})
    limits = [s["mem_limit"] for s in services.values()]
    assert all(limits)
    for path in ("Dockerfile", "airflow/Dockerfile"):
        dockerfile = (ROOT / "pipeline" / path).read_text(encoding="utf-8")
        froms = [line for line in dockerfile.splitlines() if line.startswith("FROM ")]
        assert froms
        assert all("@sha256:" in line for line in froms)
        # The last USER is never root.
        users = [line for line in dockerfile.splitlines() if line.startswith("USER ")]
        assert users[-1] in {"USER prohori", "USER 10001:0"}
    assert services["airflow"]["profiles"] == ["orchestration"]
