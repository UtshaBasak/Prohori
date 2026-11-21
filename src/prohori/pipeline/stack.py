# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
# Copyright (c) 2026 Utsha Basak
"""The Docker stack: start, stop and inspect it with ``docker compose``.

The stack (``pipeline/docker-compose.yml`` in the repository) runs Redpanda, PostgreSQL, one
container per pipeline stage and Grafana under the Compose project name ``prohori``. These helpers
only build and run ``docker compose`` command lines; they never use a shell.

**Secrets (since 1.1).** Grafana's admin, Airflow's user and the three Kafka users (the stages,
producers such as ``replay --bootstrap``, and the broker's administrator) get passwords generated
on the first real compose command and kept in ``pipeline/.env`` next to the compose file, which
git ignores and Docker Compose reads by itself. Existing values are never changed; delete a line
to have it generated again. Environment variables of the same name win over the file.
"""

import json
import os
import secrets
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
ONE_SHOT = frozenset({"warehouse-init", "redpanda-init"})
#: The compose profile that adds Airflow and the scheduled jobs.
ORCHESTRATION = "orchestration"
#: Host ports published by the compose file (all bound to 127.0.0.1 only).
KAFKA_PORT = 19092
POSTGRES_PORT = 15432
GRAFANA_PORT = 13000
AIRFLOW_PORT = 18080
#: The role the stages, dbt and Airflow use: it owns the warehouse schemas, nothing more. The
#: superuser (``prohori``) only initialises the database (``pipeline/postgres/warehouse-init.sql``).
APP_ROLE = "prohori_app"
#: The stack's secrets file, next to the compose file (git-ignored; read by Docker Compose).
ENV_FILE = ".env"
#: The generated secrets by the middle of their variable name (PROHORI_<NAME>_PASSWORD), with
#: what each one is for (written into the file) and the service it signs in to, if any.
_SECRETS = (
    ("GRAFANA", "Grafana's admin user (http://127.0.0.1:13000), user admin", "Grafana"),
    ("AIRFLOW", "Airflow's user (http://127.0.0.1:18080), user prohori", "Airflow"),
    ("KAFKA_STAGE", "Kafka user prohori-stage (the stage containers)", ""),
    ("KAFKA_PRODUCER", "Kafka user prohori-producer (replay, tail, Airflow jobs)", ""),
    ("KAFKA_ADMIN", "Kafka user prohori-admin (the broker's administrator)", ""),
)


def secret_variable(name: str) -> str:
    """``GRAFANA`` -> the environment variable that holds that generated secret."""
    return f"PROHORI_{name}_PASSWORD"


#: Variable -> what it is for.
GENERATED_SECRETS = {secret_variable(name): about for name, about, _ in _SECRETS}
#: Variable -> the service it signs in to; shown once when it is generated.
LOGINS = {secret_variable(name): service for name, _, service in _SECRETS if service}
#: The Kafka user that tools outside the stack publish as.
PRODUCER_USER = "prohori-producer"

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


def env_path(file: Path) -> Path:
    """``pipeline/.env``: the secrets file next to the compose file."""
    return file.parent / ENV_FILE


def read_env(path: Path) -> dict[str, str]:
    """``KEY=VALUE`` lines of an env file (comments and blank lines skipped)."""
    if not path.is_file():
        return {}
    found = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        found[key.strip()] = value.strip()
    return found


def new_secret() -> str:
    """A random password: 32 URL-safe characters, never ``$`` (Compose would interpolate it)."""
    return secrets.token_urlsafe(24)


def ensure_env(file: Path) -> dict[str, str]:
    """Add every missing generated secret to ``pipeline/.env``; return the ones just added.

    The file is created readable by its owner only (on systems with POSIX permissions).
    """
    path = env_path(file)
    existing = read_env(path)
    added = {key: new_secret() for key in GENERATED_SECRETS if key not in existing}
    if not added:
        return {}
    lines = []
    if not path.is_file():
        lines.append(
            "# Prohori stack secrets, generated by 'prohori pipeline up'. Never commit this file."
        )
    for key, value in added.items():
        lines += [f"# {GENERATED_SECRETS[key]}", f"{key}={value}"]
    text = "\n".join(lines) + "\n"
    previous = path.read_text(encoding="utf-8") if path.is_file() else ""
    if previous and not previous.endswith("\n"):
        previous += "\n"
    path.write_text(previous + text, encoding="utf-8", newline="\n")
    if os.name == "posix":
        path.chmod(0o600)
    return added


def compose(
    args: Sequence[str], file: Path, *, capture: bool = False, run: Runner | None = None
) -> "subprocess.CompletedProcess[str]":
    """Run ``docker compose -p prohori -f FILE ARGS...`` and return the completed process.

    A real run (no ``run``) first makes sure ``pipeline/.env`` holds every secret: the compose
    file requires them, for ``down`` and ``ps`` too.
    """
    if run is None:
        ensure_env(file)
    command = [docker_executable(), "compose", "-p", PROJECT, "-f", str(file), *args]
    runner = run if run is not None else subprocess.run
    return runner(command, check=False, text=True, capture_output=capture)


def up(
    file: Path,
    *,
    build: bool = True,
    timeout: int = 300,
    orchestration: bool = False,
    run: Runner | None = None,
) -> int:
    """Start the stack and wait until every service is healthy; return the exit code.

    ``orchestration`` also starts the services of the orchestration profile (Airflow).
    """
    args = ["--profile", ORCHESTRATION] if orchestration else []
    args += ["up", "--detach", "--wait", "--wait-timeout", str(timeout)]
    if build:
        args.append("--build")
    return compose(args, file, run=run).returncode


def down(file: Path, *, volumes: bool = False, run: Runner | None = None) -> int:
    """Stop and remove the containers and network (and the data volumes with ``volumes``).

    Profiled services are always included, so Airflow stops too if it was started.
    """
    args = ["--profile", ORCHESTRATION, "down", "--remove-orphans"]
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


def conninfo(**values: str) -> str:
    """A libpq keyword connection string. Every value is quoted, so any password works,
    including ``@``, ``/``, ``:``, ``#``, ``%``, spaces and quotes."""

    def quote(value: str) -> str:
        return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"

    return " ".join(f"{key}={quote(value)}" for key, value in values.items())


def default_dsn() -> str:
    """Connection string for the stack's PostgreSQL from the host, as the application role.

    ``PROHORI_POSTGRES_DSN`` wins; otherwise it is built from ``PROHORI_APP_DB_PASSWORD`` and
    ``PROHORI_POSTGRES_PORT``, with the compose file's local defaults.
    """
    explicit = os.environ.get("PROHORI_POSTGRES_DSN")
    if explicit:
        return explicit
    return conninfo(
        host="127.0.0.1",
        port=os.environ.get("PROHORI_POSTGRES_PORT", str(POSTGRES_PORT)),
        dbname=PROJECT,
        user=APP_ROLE,
        password=os.environ.get("PROHORI_APP_DB_PASSWORD", PROJECT),
    )


def default_bootstrap() -> str:
    """The broker address from the host: ``PROHORI_KAFKA_BOOTSTRAP`` or ``127.0.0.1:19092``."""
    return os.environ.get("PROHORI_KAFKA_BOOTSTRAP", f"127.0.0.1:{KAFKA_PORT}")


def kafka_credentials(bootstrap: str, file: Path | None = None) -> tuple[str, str] | None:
    """The SASL user and password a tool outside the stack should use for ``bootstrap``.

    ``PROHORI_KAFKA_USER`` and ``PROHORI_KAFKA_PASSWORD`` win. Otherwise, for the stack's own
    broker address, the producer user from ``pipeline/.env`` (found next to ``file``, or in a
    clone of the repository in the current directory). ``None``: connect without SASL.
    """
    user, password = os.environ.get("PROHORI_KAFKA_USER"), os.environ.get("PROHORI_KAFKA_PASSWORD")
    if user and password:
        return user, password
    if bootstrap != default_bootstrap():
        return None
    compose_path = file if file is not None else DEFAULT_COMPOSE_FILE
    saved = read_env(env_path(compose_path)).get(secret_variable("KAFKA_PRODUCER"))
    return (PRODUCER_USER, saved) if saved else None


def grafana_credentials(file: Path | None = None) -> tuple[str, str] | None:
    """Grafana's admin login: ``PROHORI_GRAFANA_PASSWORD`` or the one in ``pipeline/.env``."""
    variable = secret_variable("GRAFANA")
    password = os.environ.get(variable) or read_env(
        env_path(file if file is not None else DEFAULT_COMPOSE_FILE)
    ).get(variable)
    return ("admin", password) if password else None


def airflow_url() -> str:
    """Airflow from the host: ``http://127.0.0.1:18080`` or the ``PROHORI_AIRFLOW_PORT`` port."""
    return f"http://127.0.0.1:{os.environ.get('PROHORI_AIRFLOW_PORT', str(AIRFLOW_PORT))}"


def dashboard_url() -> str:
    """Grafana from the host: ``http://127.0.0.1:13000`` or the ``PROHORI_GRAFANA_PORT`` port."""
    return f"http://127.0.0.1:{os.environ.get('PROHORI_GRAFANA_PORT', str(GRAFANA_PORT))}"
