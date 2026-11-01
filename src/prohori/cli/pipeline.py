"""``prohori pipeline``: the streaming pipeline, in lite mode or as a Docker stack.

Lite mode (no Docker): ``replay`` pushes whole log files through every stage in this process and
stops when everything is written; ``tail`` follows growing log files until Ctrl+C. Both keep their
topics and positions under ``--state`` and write to a DuckDB file.

Docker stack: ``up``, ``status`` and ``down`` manage Redpanda, PostgreSQL and one container per
stage (``prohori pipeline run``); ``replay --bootstrap`` and ``tail --bootstrap`` then only
publish lines to the stack's Kafka topics. Everything here needs the ``pipeline`` extra.
"""

import json
import signal
import sys
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from types import FrameType
from typing import TYPE_CHECKING, Annotated, Any

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from prohori.cli.detect import load_detection_rules, parse_lateness
from prohori.cli.exit_codes import ExitCode
from prohori.cli.incidents import make_enricher
from prohori.cli.parse import (
    KeepQueryOption,
    MappingOption,
    OutputFormat,
    ParserOption,
    PatternOption,
    TimezoneOption,
    YearOption,
)
from prohori.incidents import IncidentSettings
from prohori.parsers import sanitize
from prohori.pipeline import stack
from prohori.pipeline.producers import FileTailer, ProducerError, follow_files, replay
from prohori.pipeline.runner import STAGES, LitePipeline, LiteSettings, make_stage, serve
from prohori.pipeline.stages import ParserSettings, Stage
from prohori.pipeline.transport import FileTransport, Transport
from prohori.rules.model import parse_duration

if TYPE_CHECKING:
    from prohori.pipeline.sink import Sink

DEFAULT_STATE = Path(".prohori") / "pipeline"

pipeline_app = typer.Typer(
    name="pipeline",
    help="Run the streaming pipeline: lite mode (no Docker, DuckDB) or the Docker stack.",
    no_args_is_help=True,
    add_completion=False,
)


class StageName(StrEnum):
    NORMALISE = "normalise"
    DETECT = "detect"
    INCIDENTS = "incidents"
    SINK = "sink"
    ALL = "all"


FilesArgument = Annotated[
    list[Path], typer.Argument(metavar="FILE...", help="Log files.", show_default=False)
]
StateOption = Annotated[
    Path, typer.Option("--state", help="Directory for topics, positions and the database.")
]
DatabaseOption = Annotated[
    Path | None,
    typer.Option(
        "--db", help="DuckDB file (default: prohori.duckdb in --state).", show_default=False
    ),
]
BootstrapOption = Annotated[
    str | None,
    typer.Option(
        "--bootstrap",
        help="Kafka broker (host:port): publish to the Docker stack instead of running lite mode.",
        show_default=False,
    ),
]
RulesOption = Annotated[
    list[Path] | None,
    typer.Option(
        "--rules",
        "-r",
        help="Extra rule file or directory (repeatable), run with the built-in rules.",
        show_default=False,
    ),
]
NoBuiltinOption = Annotated[
    bool, typer.Option("--no-builtin", help="Run only the rules given with --rules.")
]
LatenessOption = Annotated[
    str, typer.Option(help="How far out of order events may arrive and still count, such as 5m.")
]
GapOption = Annotated[
    str, typer.Option(help="Alerts sharing an entity join one incident when this close.")
]
OnlineOption = Annotated[
    bool, typer.Option("--online", help="Look up public IPs with the configured providers.")
]
NoEnrichOption = Annotated[bool, typer.Option("--no-enrich", help="Do not enrich IP addresses.")]
FormatOption = Annotated[
    OutputFormat, typer.Option("--format", "-f", help="table or json (the run's counters).")
]
EnvOption = Annotated[
    Path, typer.Option(help="Enrichment settings file read under the environment variables.")
]
ComposeOption = Annotated[
    Path | None,
    typer.Option(
        "--file",
        help="Compose file (default: pipeline/docker-compose.yml under the current directory).",
        show_default=False,
    ),
]
MaxRoundsOption = Annotated[int | None, typer.Option(hidden=True)]


def _settings(
    *,
    state: Path,
    database: Path | None,
    rules_paths: list[Path] | None,
    no_builtin: bool,
    lateness: str,
    gap: str,
    online: bool,
    no_enrich: bool,
    env_file: Path,
    parsers: ParserSettings,
    follow: bool,
    idle_close: float | None = None,
) -> LiteSettings:
    allowed_lateness = parse_lateness(lateness)
    try:
        incident_settings = IncidentSettings(gap=parse_duration(gap))
    except ValueError as exc:
        raise typer.BadParameter(str(exc), param_hint="--gap") from exc
    rules = load_detection_rules(rules_paths or [], builtin=not no_builtin)
    return LiteSettings(
        rules=rules,
        database=database or state / "prohori.duckdb",
        parsers=parsers,
        incidents=incident_settings,
        lateness=allowed_lateness,
        enricher=None if no_enrich else make_enricher(env_file, online=online),
        enrichment="none" if no_enrich else ("online" if online else "offline"),
        follow=follow,
        idle_close=idle_close,
    )


def _fail(message: str) -> typer.Exit:
    typer.echo(f"error: {sanitize(message)}", err=True)
    return typer.Exit(ExitCode.NO_EVENTS)


def _pipeline(state: Path, settings: LiteSettings) -> LitePipeline:
    transport = FileTransport(state)
    try:
        return LitePipeline(transport, settings)
    except ImportError as exc:
        transport.close()
        if settings.enricher is not None:
            settings.enricher.close()
        raise _fail(str(exc)) from None


def _kafka(bootstrap: str) -> Transport:
    """Connect to the broker, creating the topics; exit 1 with a message if that fails."""
    try:
        from prohori.pipeline.kafka import KafkaTransport, TransportError
    except ImportError as exc:  # pragma: no cover - the module itself imports nothing optional
        raise _fail(str(exc)) from None
    try:
        return KafkaTransport(bootstrap)
    except (ImportError, TransportError) as exc:
        raise _fail(str(exc)) from None


# ---------------------------------------------------------------------- replay and tail


@pipeline_app.command("replay")
def replay_command(
    files: FilesArgument,
    state: StateOption = DEFAULT_STATE,
    database: DatabaseOption = None,
    bootstrap: BootstrapOption = None,
    times: Annotated[
        int, typer.Option(min=1, help="Publish each file this many times (to test duplicates).")
    ] = 1,
    rules_paths: RulesOption = None,
    no_builtin: NoBuiltinOption = False,
    lateness: LatenessOption = "5m",
    gap: GapOption = "30m",
    online: OnlineOption = False,
    no_enrich: NoEnrichOption = False,
    env_file: EnvOption = Path(".env"),
    output: FormatOption = OutputFormat.TABLE,
    parser_name: ParserOption = "auto",
    year: YearOption = None,
    timezone: TimezoneOption = "UTC",
    mapping: MappingOption = None,
    pattern: PatternOption = None,
    keep_query: KeepQueryOption = False,
) -> None:
    """Replay log files through the pipeline.

    Lite mode (default): every stage runs here until everything is in the DuckDB file; events,
    alerts, incidents and dead letters are stored once per id, so replaying the same file again
    adds no rows. With --bootstrap the lines are only published to the Docker stack's Kafka
    topics, where its containers process them. Exit codes: 0 done, 1 the pipeline extra is
    missing, the broker is unreachable or every line was a dead letter, 2 invalid usage.
    """
    missing = [str(f) for f in files if not f.is_file()]
    if missing:
        raise typer.BadParameter(f"not found: {', '.join(missing)}", param_hint="FILE")
    if bootstrap:
        _publish(files, bootstrap, times=times, parser=parser_name, has_mapping=bool(mapping))
        return
    parsers = ParserSettings(year, timezone, mapping, pattern, keep_query)
    settings = _settings(
        state=state,
        database=database,
        rules_paths=rules_paths,
        no_builtin=no_builtin,
        lateness=lateness,
        gap=gap,
        online=online,
        no_enrich=no_enrich,
        env_file=env_file,
        parsers=parsers,
        follow=False,
    )
    pipeline = _pipeline(state, settings)
    try:
        lines = 0
        for _ in range(times):
            for file in files:
                try:
                    lines += replay(
                        file,
                        pipeline.transport,
                        parser=parser_name,
                        has_mapping=mapping is not None,
                    )
                except ProducerError as exc:
                    raise typer.BadParameter(str(exc), param_hint="FILE") from None
        metrics = pipeline.run()
        metrics["lines_replayed"] = lines
    finally:
        pipeline.close()
    _report(metrics, output, settings.database)
    normalised = metrics["stages"]["normalise"]
    if lines and normalised["produced"] == 0 and normalised["dead_letters"] > 0:
        raise typer.Exit(ExitCode.NO_EVENTS)


def _publish(
    files: list[Path], bootstrap: str, *, times: int, parser: str, has_mapping: bool
) -> None:
    transport = _kafka(bootstrap)
    lines = 0
    try:
        for _ in range(times):
            for file in files:
                try:
                    lines += replay(file, transport, parser=parser, has_mapping=has_mapping)
                except ProducerError as exc:
                    raise typer.BadParameter(str(exc), param_hint="FILE") from None
    finally:
        transport.close()
    typer.echo(f"Published {lines:,} line(s) to the raw-logs topic on {sanitize(bootstrap)}.")


@pipeline_app.command("tail")
def tail_command(
    files: FilesArgument,
    state: StateOption = DEFAULT_STATE,
    database: DatabaseOption = None,
    bootstrap: BootstrapOption = None,
    poll: Annotated[
        float, typer.Option(min=0.0, help="Seconds between checks for new lines.")
    ] = 1.0,
    rules_paths: RulesOption = None,
    no_builtin: NoBuiltinOption = False,
    lateness: LatenessOption = "5m",
    gap: GapOption = "30m",
    online: OnlineOption = False,
    no_enrich: NoEnrichOption = False,
    env_file: EnvOption = Path(".env"),
    output: FormatOption = OutputFormat.TABLE,
    parser_name: ParserOption = "auto",
    year: YearOption = None,
    timezone: TimezoneOption = "UTC",
    mapping: MappingOption = None,
    pattern: PatternOption = None,
    keep_query: KeepQueryOption = False,
    max_rounds: MaxRoundsOption = None,
) -> None:
    """Follow growing log files (like tail -F) until Ctrl+C.

    Survives log rotation by rename or truncation, and continues where it stopped when run again
    with the same --state. In lite mode (default) every stage runs here and writes to DuckDB; on
    Ctrl+C it finishes the current batch, writes the incidents still open and exits 0. With
    --bootstrap it only publishes the lines to the Docker stack. Needs the pipeline extra (exit 1
    without it, or if the broker is unreachable); 2 for invalid usage.
    """
    stop = threading.Event()
    if bootstrap:
        transport = _kafka(bootstrap)
        try:
            tailers = _tailers(files, transport, parser_name, mapping, state)
            with _stop_on_signals(stop):
                lines = follow_files(tailers, stop, poll_interval=poll, max_rounds=max_rounds)
        finally:
            transport.close()
        typer.echo(f"Published {lines:,} line(s) to the raw-logs topic on {sanitize(bootstrap)}.")
        return
    parsers = ParserSettings(year, timezone, mapping, pattern, keep_query)
    settings = _settings(
        state=state,
        database=database,
        rules_paths=rules_paths,
        no_builtin=no_builtin,
        lateness=lateness,
        gap=gap,
        online=online,
        no_enrich=no_enrich,
        env_file=env_file,
        parsers=parsers,
        follow=True,
    )
    pipeline = _pipeline(state, settings)
    try:
        tailers = _tailers(files, pipeline.transport, parser_name, mapping, state)
        with _stop_on_signals(stop):
            metrics = pipeline.follow(tailers, stop, poll_interval=poll, max_rounds=max_rounds)
    finally:
        pipeline.close()
    _report(metrics, output, settings.database)


def _tailers(
    files: list[Path], transport: Transport, parser: str, mapping: Path | None, state: Path
) -> list[FileTailer]:
    try:
        tailers = [
            FileTailer(
                file,
                transport,
                parser=parser,
                has_mapping=mapping is not None,
                state_dir=state / "tail",
            )
            for file in files
        ]
    except ProducerError as exc:
        raise typer.BadParameter(str(exc), param_hint="FILE") from None
    typer.echo(f"Following {len(tailers)} file(s); press Ctrl+C to stop.", err=True)
    return tailers


# ---------------------------------------------------------------------- one stage (containers)


@pipeline_app.command("run")
def run_command(
    stage_name: Annotated[
        StageName, typer.Option("--stage", help="The stage to run, or all of them.")
    ],
    bootstrap: Annotated[
        str,
        typer.Option(
            "--bootstrap",
            envvar="PROHORI_KAFKA_BOOTSTRAP",
            help="Kafka broker (host:port).",
            show_default=False,
        ),
    ],
    postgres: Annotated[
        str | None,
        typer.Option(
            "--postgres",
            envvar="PROHORI_POSTGRES_DSN",
            help="PostgreSQL connection string for the sink (otherwise DuckDB, see --db).",
            show_default=False,
            show_envvar=True,
        ),
    ] = None,
    state: StateOption = DEFAULT_STATE,
    database: DatabaseOption = None,
    idle_close: Annotated[
        float | None,
        typer.Option(
            min=0.0,
            help="incidents: write open incidents after this many seconds without new alerts "
            "(default: the incident hold time, 65 minutes with the built-in rules).",
            show_default=False,
        ),
    ] = None,
    heartbeat: Annotated[
        Path | None,
        typer.Option(
            help="File touched after every round, for a health check.", show_default=False
        ),
    ] = None,
    poll: Annotated[
        float, typer.Option(min=0.0, help="Seconds to wait when there is nothing to read.")
    ] = 0.5,
    rules_paths: RulesOption = None,
    no_builtin: NoBuiltinOption = False,
    lateness: LatenessOption = "5m",
    gap: GapOption = "30m",
    online: OnlineOption = False,
    no_enrich: NoEnrichOption = False,
    env_file: EnvOption = Path(".env"),
    parser_name: ParserOption = "auto",
    year: YearOption = None,
    timezone: TimezoneOption = "UTC",
    mapping: MappingOption = None,
    pattern: PatternOption = None,
    keep_query: KeepQueryOption = False,
    max_rounds: MaxRoundsOption = None,
) -> None:
    """Run one pipeline stage (or all) over Kafka until stopped: what each container runs.

    Stateful stages (detect, incidents) rebuild their state from the start of their topics when
    they start. SIGTERM or Ctrl+C finishes the current batch, releases what the stage holds and
    exits 0. Exit 1 if the pipeline extra is missing or the broker or database is unreachable.
    """
    del parser_name  # each raw line names its parser
    parsers = ParserSettings(year, timezone, mapping, pattern, keep_query)
    settings = _settings(
        state=state,
        database=database,
        rules_paths=rules_paths,
        no_builtin=no_builtin,
        lateness=lateness,
        gap=gap,
        online=online,
        no_enrich=no_enrich,
        env_file=env_file,
        parsers=parsers,
        follow=True,
        idle_close=idle_close,
    )
    names = STAGES if stage_name is StageName.ALL else (stage_name.value,)
    transport = _kafka(bootstrap)
    stages: list[Stage] = []
    try:
        try:
            stages = [make_stage(n, transport, settings, postgres=postgres) for n in names]
        except ImportError as exc:
            raise _fail(str(exc)) from None
        except Exception as exc:  # the database is not reachable
            raise _fail(f"cannot start the {', '.join(names)} stage: {exc}") from None
        typer.echo(f"Running {', '.join(names)} on {sanitize(bootstrap)}.", err=True)
        stop = threading.Event()
        with _stop_on_signals(stop):
            serve(stages, stop, poll_interval=poll, heartbeat=heartbeat, max_rounds=max_rounds)
        metrics = {stage.name: stage.metrics.as_dict() for stage in stages}
        typer.echo(json.dumps({"stopped": list(names), "stages": metrics}), err=True)
    finally:
        for stage in stages:
            close = getattr(stage, "close", None)
            if close is not None:
                close()
        transport.close()
        if settings.enricher is not None:
            settings.enricher.close()


# ---------------------------------------------------------------------- the Docker stack


def _compose(file: Path | None) -> Path:
    try:
        stack.docker_executable()
        return stack.compose_file(file)
    except stack.StackError as exc:
        raise _fail(str(exc)) from None


@pipeline_app.command("up")
def up_command(
    file: ComposeOption = None,
    build: Annotated[
        bool, typer.Option("--build/--no-build", help="Build the Prohori image first.")
    ] = True,
    timeout: Annotated[
        int, typer.Option(min=10, help="Seconds to wait for every service to be healthy.")
    ] = 300,
) -> None:
    """Start the Docker stack (Redpanda, PostgreSQL, one container per stage) and wait for it.

    Needs Docker and a clone of the repository (the compose file and the image's sources).
    Exit codes: 0 every service is healthy, 1 Docker or the compose file is missing or a service
    did not become healthy.
    """
    compose_path = _compose(file)
    code = stack.up(compose_path, build=build, timeout=timeout)
    healthy = _print_status(compose_path, counts=False)
    if code != 0 or not healthy:
        raise _fail("the stack did not become healthy; see 'docker compose -p prohori logs'")
    typer.echo(
        f"Publish logs with: prohori pipeline replay FILE --bootstrap {stack.default_bootstrap()}"
    )


@pipeline_app.command("down")
def down_command(
    file: ComposeOption = None,
    volumes: Annotated[
        bool, typer.Option("--volumes", help="Also delete the data (topics and the database).")
    ] = False,
) -> None:
    """Stop the Docker stack and remove its containers and network (data is kept)."""
    compose_path = _compose(file)
    if stack.down(compose_path, volumes=volumes) != 0:
        raise _fail("docker compose down failed")
    typer.echo("Stack stopped" + (" and its data deleted." if volumes else "; data kept."))


@pipeline_app.command("status")
def status_command(
    file: ComposeOption = None,
    dsn: Annotated[
        str | None,
        typer.Option(
            "--postgres",
            help="PostgreSQL to count rows in (default: the stack's).",
            show_default=False,
        ),
    ] = None,
    output: Annotated[OutputFormat, typer.Option("--format", "-f", help="table or json.")] = (
        OutputFormat.TABLE
    ),
) -> None:
    """Show the Docker stack's services, their health and the rows in the warehouse.

    Exit codes: 0 every service is healthy, 1 a service is missing, stopped or unhealthy (or
    Docker or the compose file is missing).
    """
    compose_path = _compose(file)
    if output is OutputFormat.JSON:
        services = _services(compose_path)
        counts = _counts(dsn or stack.default_dsn())
        healthy = bool(services) and all(s.ok for s in services)
        payload = {
            "healthy": healthy,
            "services": [s.__dict__ | {"ok": s.ok} for s in services],
            "rows": counts,
        }
        typer.echo(json.dumps(payload, indent=2))
    else:
        healthy = _print_status(compose_path, counts=True, dsn=dsn)
    if not healthy:
        raise typer.Exit(ExitCode.NO_EVENTS)


def _services(compose_path: Path) -> list[stack.Service]:
    try:
        return stack.services(compose_path)
    except stack.StackError as exc:
        raise _fail(str(exc)) from None


def _counts(dsn: str) -> dict[str, int] | None:
    """Row counts in the warehouse, or None if it cannot be reached."""
    try:
        from prohori.pipeline.postgres import connect
        from prohori.pipeline.sink import TABLES

        connection = connect(dsn)
    except Exception:  # not running, wrong password, extra missing: the table says so
        return None
    try:
        result: dict[str, int] = {}
        for table in TABLES:
            row = connection.execute(f"SELECT count(*) FROM raw.{table}").fetchone()  # noqa: S608
            result[table] = int(row[0]) if row is not None else 0
        return result
    finally:
        connection.close()


def _print_status(compose_path: Path, *, counts: bool, dsn: str | None = None) -> bool:
    services = _services(compose_path)
    console = Console(highlight=False)
    if not services:
        console.print("The stack is not running; start it with: prohori pipeline up")
        return False
    table = Table(title="Prohori stack")
    for column in ("service", "state", "health", ""):
        table.add_column(column)
    for service in services:
        mark = "ok" if service.ok else "PROBLEM"
        health = service.health or ("exit 0" if service.ok and service.state == "exited" else "-")
        table.add_row(Text(service.name), Text(service.state), Text(health), mark)
    console.print(table)
    if counts:
        rows = _counts(dsn or stack.default_dsn())
        if rows is None:
            console.print("Warehouse: not reachable.")
        else:
            console.print(
                "Warehouse rows: " + ", ".join(f"{k} {v:,}" for k, v in rows.items()) + "."
            )
    return all(s.ok for s in services)


# ---------------------------------------------------------------------- warehouse loaders

PostgresOption = Annotated[
    str | None,
    typer.Option(
        "--postgres",
        envvar="PROHORI_POSTGRES_DSN",
        help="Load into this PostgreSQL warehouse instead of the DuckDB file.",
        show_default=False,
        show_envvar=True,
    ),
]


def _warehouse(state: Path, database: Path | None, postgres: str | None) -> "Sink":
    from prohori.pipeline.warehouse import open_warehouse

    try:
        return open_warehouse(database=database or state / "prohori.duckdb", postgres=postgres)
    except ImportError as exc:
        raise _fail(str(exc)) from None
    except Exception as exc:  # the database is not reachable
        raise _fail(f"cannot open the warehouse: {exc}") from None


@pipeline_app.command("load-labels")
def load_labels_command(
    logs: Annotated[
        list[Path],
        typer.Argument(metavar="LOG...", help="Simulated log files.", show_default=False),
    ],
    labels: Annotated[
        Path | None,
        typer.Option(
            help="Labels file (default: NAME.labels.jsonl next to the log; one log only).",
            show_default=False,
        ),
    ] = None,
    scenario: Annotated[
        str | None,
        typer.Option(
            help="Scenario name (default: from manifest.json next to the log).", show_default=False
        ),
    ] = None,
    state: StateOption = DEFAULT_STATE,
    database: DatabaseOption = None,
    postgres: PostgresOption = None,
    parser_name: ParserOption = "auto",
    year: YearOption = None,
    timezone: TimezoneOption = "UTC",
    mapping: MappingOption = None,
    pattern: PatternOption = None,
    keep_query: KeepQueryOption = False,
) -> None:
    """Load the simulator's ground truth for logs that were replayed into the pipeline.

    Each line of a simulated log is matched to the event it became (same parser options as the
    replay), so the warehouse models can measure rule precision and time to detection. Loading
    the same labels again adds nothing. Exit 1 if the labels cannot be read or the warehouse
    cannot be opened, 2 for invalid usage.
    """
    from prohori.pipeline.warehouse import LoadError, label_rows, load

    if labels is not None and len(logs) > 1:
        raise typer.BadParameter("--labels needs exactly one LOG", param_hint="--labels")
    missing = [str(f) for f in logs if not f.is_file()]
    if missing:
        raise typer.BadParameter(f"not found: {', '.join(missing)}", param_hint="LOG")
    parsers = ParserSettings(year, timezone, mapping, pattern, keep_query)
    try:
        batches = [
            label_rows(log, labels, parser=parser_name, settings=parsers, scenario=scenario)
            for log in logs
        ]
    except ProducerError as exc:
        raise typer.BadParameter(str(exc), param_hint="LOG") from None
    except LoadError as exc:
        raise _fail(str(exc)) from None
    sink = _warehouse(state, database, postgres)
    try:
        total = sum(load(sink, "labels", rows) for rows in batches)
    finally:
        sink.close()
    attacks = sum(1 for rows in batches for row in rows if row[-1] is not None)
    typer.echo(
        f"Loaded labels for {total:,} event(s) ({attacks:,} attack) from {len(logs)} log(s)."
    )


@pipeline_app.command("load-results")
def load_results_command(
    results: Annotated[
        list[Path],
        typer.Argument(
            metavar="RESULTS...",
            help="Flow-model results such as results/ml_unsw-nb15.json.",
            show_default=False,
        ),
    ],
    evaluated_at: Annotated[
        datetime | None,
        typer.Option(
            formats=["%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d"],
            help="When the evaluation ran (default: each file's modification time), "
            "such as 2026-10-31.",
            show_default=False,
        ),
    ] = None,
    state: StateOption = DEFAULT_STATE,
    database: DatabaseOption = None,
    postgres: PostgresOption = None,
) -> None:
    """Load flow-model evaluation results into the warehouse, for model performance over time.

    One row per dataset, variant, model, seed and operating point (test split). Loading the same
    file with the same time again adds nothing; a later evaluation adds new rows. Exit 1 if a
    file is not a flow-model evaluation or the warehouse cannot be opened.
    """
    from prohori.pipeline.warehouse import LoadError, evaluation_rows, load

    when = None
    if evaluated_at is not None:
        when = evaluated_at if evaluated_at.tzinfo else evaluated_at.replace(tzinfo=UTC)
    try:
        batches = [evaluation_rows(path, when) for path in results]
    except LoadError as exc:
        raise _fail(str(exc)) from None
    sink = _warehouse(state, database, postgres)
    try:
        total = sum(load(sink, "model_evaluations", rows) for rows in batches)
    finally:
        sink.close()
    typer.echo(f"Loaded {total:,} evaluation row(s) from {len(results)} file(s).")


# ---------------------------------------------------------------------- helpers


@contextmanager
def _stop_on_signals(stop: threading.Event) -> Iterator[None]:
    """Set ``stop`` on Ctrl+C and termination signals instead of raising, then restore."""

    def handler(signum: int, frame: FrameType | None) -> None:
        del signum, frame
        stop.set()

    names = ["SIGINT", "SIGTERM"] + (["SIGBREAK"] if sys.platform == "win32" else [])
    previous: dict[int, Callable[[int, FrameType | None], Any] | int | None] = {}
    if threading.current_thread() is threading.main_thread():
        for name in names:
            number = getattr(signal, name)
            previous[number] = signal.signal(number, handler)
    try:
        yield
    finally:
        for number, old in previous.items():
            signal.signal(number, old)


def _report(metrics: dict[str, Any], output: OutputFormat, database: Path) -> None:
    if output is OutputFormat.JSON:
        typer.echo(json.dumps(metrics, indent=2))
        return
    console = Console(highlight=False)
    table = Table(title="Pipeline stages")
    table.add_column("stage")
    for column in ("consumed", "produced", "dead letters", "duplicates"):
        table.add_column(column, justify="right")
    for name, counts in metrics["stages"].items():
        table.add_row(
            name,
            f"{counts['consumed']:,}",
            f"{counts['produced']:,}",
            f"{counts['dead_letters']:,}",
            f"{counts['duplicates']:,}",
        )
    console.print(table)
    tables = ", ".join(f"{name} {count:,}" for name, count in metrics["tables"].items())
    console.print(f"Database {sanitize(str(database))}: {tables}.")
    late = metrics["engine"].get("late_events", 0)
    if late:
        console.print(f"{late:,} events arrived too late for the rules and were not evaluated.")
