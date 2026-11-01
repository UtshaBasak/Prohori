"""The Docker stack: start, stop and inspect it with ``docker compose``.

The stack (``pipeline/docker-compose.yml`` in the repository) runs Redpanda, PostgreSQL, one
container per pipeline stage and Grafana under the Compose project name ``prohori``. These helpers
only build and run ``docker compose`` command lines; they never use a shell.
"""

import json
import os
import shutil
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

#: Compose project name: containers, network and volumes are prefixed with it.
PROJECT = "prohori"
#: Where the compose file is in a clone of the repository.
DEFAULT_COMPOSE_FILE = Path("pipeline") / "docker-compose.yml"
#: Services that run once and exit (they are healthy when they exited with 0).
ONE_SHOT = frozenset({"warehouse-init"})
#: Host ports published by the compose file (all bound to 127.0.0.1 only).
KAFKA_PORT = 19092
POSTGRES_PORT = 15432
GRAFANA_PORT = 13000

Runner = Callable[..., "subprocess.CompletedProcess[str]"]


class StackError(RuntimeError):
    """Docker is missing, the compose file cannot be found or a compose command failed."""


@dataclass(frozen=True)
class Service:
    """One service of the stack as ``docker compose ps`` reports it."""

    name: str
    state: str  # running, exited, restarting, ...
    health: str  # healthy, unhealthy, starting, or "" without a health check
    exit_code: int = 0

    @property
    def ok(self) -> bool:
        if self.name in ONE_SHOT:
            return self.state == "exited" and self.exit_code == 0
        return self.state == "running" and self.health in {"", "healthy"}


def docker_executable() -> str:
    found = shutil.which("docker")
    if found is None:
        msg = "Docker is not installed or not on PATH; install Docker Desktop or Docker Engine"
        raise StackError(msg)
    return found


def compose_file(path: Path | None) -> Path:
    """The compose file to use: ``path``, or ``pipeline/docker-compose.yml`` under the cwd."""
    candidate = path if path is not None else DEFAULT_COMPOSE_FILE
    if not candidate.is_file():
        msg = (
            f"{candidate} not found: run the command from a clone of the Prohori repository "
            "or pass --file"
        )
        raise StackError(msg)
    return candidate


def compose(
    args: Sequence[str], file: Path, *, capture: bool = False, run: Runner | None = None
) -> "subprocess.CompletedProcess[str]":
    """Run ``docker compose -p prohori -f FILE ARGS...`` and return the completed process."""
    command = [docker_executable(), "compose", "-p", PROJECT, "-f", str(file), *args]
    runner = run if run is not None else subprocess.run
    return runner(command, check=False, text=True, capture_output=capture)


def up(file: Path, *, build: bool = True, timeout: int = 300, run: Runner | None = None) -> int:
    """Start the stack and wait until every service is healthy; return the exit code."""
    args = ["up", "--detach", "--wait", "--wait-timeout", str(timeout)]
    if build:
        args.append("--build")
    return compose(args, file, run=run).returncode


def down(file: Path, *, volumes: bool = False, run: Runner | None = None) -> int:
    """Stop and remove the containers and network (and the data volumes with ``volumes``)."""
    args = ["down", "--remove-orphans"]
    if volumes:
        args.append("--volumes")
    return compose(args, file, run=run).returncode


def parse_ps(text: str) -> list[Service]:
    """Parse ``docker compose ps --format json`` (a JSON array, or one object per line)."""
    text = text.strip()
    if not text:
        return []
    if text.startswith("["):
        items = json.loads(text)
    else:
        items = [json.loads(line) for line in text.splitlines() if line.strip()]
    services = [
        Service(
            name=str(item.get("Service", "")),
            state=str(item.get("State", "")),
            health=str(item.get("Health", "")),
            exit_code=int(item.get("ExitCode", 0) or 0),
        )
        for item in items
        if isinstance(item, dict)
    ]
    return sorted(services, key=lambda s: s.name)


def services(file: Path, *, run: Runner | None = None) -> list[Service]:
    """The stack's services and their state (an empty list when it is not running)."""
    done = compose(["ps", "--all", "--format", "json"], file, capture=True, run=run)
    if done.returncode != 0:
        msg = f"docker compose ps failed: {done.stderr.strip() or done.returncode}"
        raise StackError(msg)
    return parse_ps(done.stdout)


def default_dsn() -> str:
    """Connection string for the stack's PostgreSQL from the host.

    ``PROHORI_POSTGRES_DSN`` wins; otherwise it is built from ``PROHORI_POSTGRES_PASSWORD`` and
    ``PROHORI_POSTGRES_PORT``, with the compose file's local defaults.
    """
    explicit = os.environ.get("PROHORI_POSTGRES_DSN")
    if explicit:
        return explicit
    password = os.environ.get("PROHORI_POSTGRES_PASSWORD", PROJECT)
    port = os.environ.get("PROHORI_POSTGRES_PORT", str(POSTGRES_PORT))
    return f"postgresql://{PROJECT}:{password}@127.0.0.1:{port}/{PROJECT}"


def default_bootstrap() -> str:
    """The broker address from the host: ``PROHORI_KAFKA_BOOTSTRAP`` or ``127.0.0.1:19092``."""
    return os.environ.get("PROHORI_KAFKA_BOOTSTRAP", f"127.0.0.1:{KAFKA_PORT}")


def dashboard_url() -> str:
    """Grafana from the host: ``http://127.0.0.1:13000`` or the ``PROHORI_GRAFANA_PORT`` port."""
    return f"http://127.0.0.1:{os.environ.get('PROHORI_GRAFANA_PORT', str(GRAFANA_PORT))}"
