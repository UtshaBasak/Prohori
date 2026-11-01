"""``prohori pipeline``: run the streaming pipeline in lite mode (no Docker).

``replay`` pushes whole log files through the pipeline and stops when everything is written;
``tail`` follows growing log files until Ctrl+C. Both keep their topics and positions under
``--state`` (so a later run continues) and write events, alerts, incidents and dead letters to a
DuckDB file. They need the ``pipeline`` extra.
"""

import json
import signal
import sys
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from types import FrameType
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.table import Table

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
from prohori.pipeline.producers import FileTailer, ProducerError, replay
from prohori.pipeline.runner import LitePipeline, LiteSettings
from prohori.pipeline.stages import ParserSettings
from prohori.pipeline.transport import FileTransport
from prohori.rules.model import parse_duration

DEFAULT_STATE = Path(".prohori") / "pipeline"

pipeline_app = typer.Typer(
    name="pipeline",
    help="Run the streaming pipeline in lite mode: no Docker, DuckDB storage.",
    no_args_is_help=True,
    add_completion=False,
)

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
    )


def _pipeline(state: Path, settings: LiteSettings) -> LitePipeline:
    transport = FileTransport(state)
    try:
        return LitePipeline(transport, settings)
    except ImportError as exc:
        transport.close()
        if settings.enricher is not None:
            settings.enricher.close()
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(ExitCode.NO_EVENTS) from None


@pipeline_app.command("replay")
def replay_command(
    files: FilesArgument,
    state: StateOption = DEFAULT_STATE,
    database: DatabaseOption = None,
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
    """Replay log files through the lite pipeline until everything is in the database.

    Lines go to the raw-logs topic, are parsed, run through the rules and grouped into incidents;
    events, alerts, incidents and dead letters are written to DuckDB, each id once, so replaying
    the same file again adds no rows. Exit codes: 0 done, 1 the pipeline extra is missing or
    every line was a dead letter, 2 invalid usage.
    """
    missing = [str(f) for f in files if not f.is_file()]
    if missing:
        raise typer.BadParameter(f"not found: {', '.join(missing)}", param_hint="FILE")
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


@pipeline_app.command("tail")
def tail_command(
    files: FilesArgument,
    state: StateOption = DEFAULT_STATE,
    database: DatabaseOption = None,
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
    max_rounds: Annotated[int | None, typer.Option(hidden=True)] = None,
) -> None:
    """Follow growing log files (like tail -F) until Ctrl+C, writing to DuckDB as lines arrive.

    Survives log rotation by rename or truncation, and continues where it stopped when run again
    with the same --state. On Ctrl+C it finishes the current batch, writes the incidents still
    open and exits 0. Needs the pipeline extra (exit 1 without it); 2 for invalid usage.
    """
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
    stop = threading.Event()
    try:
        tailers = [
            FileTailer(
                file,
                pipeline.transport,
                parser=parser_name,
                has_mapping=mapping is not None,
                state_dir=state / "tail",
            )
            for file in files
        ]
        typer.echo(f"Following {len(tailers)} file(s); press Ctrl+C to stop.", err=True)
        with _stop_on_signals(stop):
            metrics = pipeline.follow(tailers, stop, poll_interval=poll, max_rounds=max_rounds)
    except ProducerError as exc:
        raise typer.BadParameter(str(exc), param_hint="FILE") from None
    finally:
        pipeline.close()
    _report(metrics, output, settings.database)


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
