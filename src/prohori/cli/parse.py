"""``prohori parse``: parse and normalise a log file, print events and a parse summary."""

import contextlib
import json
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from itertools import chain, islice
from pathlib import Path
from typing import IO, Annotated

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from prohori.cli.exit_codes import ExitCode
from prohori.parsers import (
    LineParser,
    ParseStats,
    RawLine,
    available,
    detect_format,
    get_parser,
    read_lines,
)
from prohori.schema import Event

#: Raw lines buffered for format detection before parsing starts.
_DETECT_BUFFER = 50


class OutputFormat(StrEnum):
    """Output formats shared by commands."""

    TABLE = "table"
    JSON = "json"


@contextlib.contextmanager
def open_input(path: str) -> Iterator[tuple[IO[bytes], str, datetime | None]]:
    """Open ``path`` (or standard input for ``-``) as a binary stream.

    Yields the stream, a display name and the file's modification time (``None`` for stdin).
    """
    if path == "-":
        yield sys.stdin.buffer, "<stdin>", None
        return
    file = Path(path)
    if not file.is_file():
        raise typer.BadParameter(f"file not found: {path}", param_hint="FILE")
    mtime = datetime.fromtimestamp(file.stat().st_mtime, tz=UTC)
    with file.open("rb") as stream:
        yield stream, file.name, mtime


def build_parser(
    name: str,
    *,
    year: int | None,
    timezone: str,
    mtime: datetime | None,
    mapping: Path | None,
    pattern: str | None,
    keep_query: bool,
) -> LineParser:
    """Create the named parser from command-line options."""
    try:
        if name == "auth_log":
            return get_parser(name, year=year, timezone=timezone, reference_time=mtime)
        if name == "access_log":
            return get_parser(name, pattern=pattern, keep_query=keep_query)
        if name == "generic_json":
            if mapping is None:
                raise typer.BadParameter("the generic_json parser needs --mapping FILE")
            return get_parser(name, mapping=mapping)
        return get_parser(name)
    except (ValueError, OSError) as exc:
        raise typer.BadParameter(str(exc)) from exc


@dataclass
class ParsedInput:
    """Events being parsed from one input, with the parser chosen and running counts."""

    events: Iterator[Event]
    parser: str
    name: str
    stats: ParseStats


ParserOption = Annotated[
    str,
    typer.Option(
        "--parser",
        "-p",
        help="Parser to use: auto, " + ", ".join(available()) + ".",
        show_default=True,
    ),
]
YearOption = Annotated[
    int | None,
    typer.Option(help="auth_log: year of the first line (default: from the file date)."),
]
TimezoneOption = Annotated[
    str, typer.Option(help="auth_log: IANA timezone for timestamps without an offset.")
]
MappingOption = Annotated[Path | None, typer.Option(help="generic_json: YAML field-mapping file.")]
PatternOption = Annotated[
    str | None, typer.Option(help="access_log: custom regular expression for the line.")
]
KeepQueryOption = Annotated[
    bool, typer.Option(help="access_log: keep the query string in http.path.")
]


@contextlib.contextmanager
def parsed_events(
    file: str,
    parser_name: str,
    *,
    year: int | None,
    timezone: str,
    mapping: Path | None,
    pattern: str | None,
    keep_query: bool,
) -> Iterator[ParsedInput]:
    """Open ``file`` (``-`` for stdin), choose or detect the parser and yield the parsed input.

    Raises:
        typer.BadParameter: for a missing file, an unknown or undetectable format, or bad options.
    """
    if year is not None and parser_name not in {"auth_log", "auto"}:
        raise typer.BadParameter("--year applies to the auth_log parser only")
    with open_input(file) as (stream, name, mtime):
        lines: Iterator[RawLine] = read_lines(stream)
        if parser_name == "auto":
            head = list(islice(lines, _DETECT_BUFFER))
            detected = detect_format(head)
            if detected is None:
                raise typer.BadParameter(
                    "could not detect the log format; choose one with --parser", param_hint="FILE"
                )
            if detected == "generic_json" and mapping is None:
                raise typer.BadParameter(
                    "input looks like JSON Lines in an unknown layout; use --parser app_json or "
                    "--parser generic_json --mapping FILE",
                    param_hint="FILE",
                )
            parser_name = detected
            lines = chain(head, lines)
        elif parser_name not in available():
            raise typer.BadParameter(
                f"unknown parser {parser_name!r}; choose from auto, {', '.join(available())}",
                param_hint="--parser",
            )
        parser = build_parser(
            parser_name,
            year=year,
            timezone=timezone,
            mtime=mtime,
            mapping=mapping,
            pattern=pattern,
            keep_query=keep_query,
        )
        stats = ParseStats()
        yield ParsedInput(parser.parse(lines, source=name, stats=stats), parser_name, name, stats)


def parse_command(
    file: Annotated[
        str, typer.Argument(metavar="FILE", help="Log file to parse, or '-' for standard input.")
    ],
    parser_name: ParserOption = "auto",
    output: Annotated[
        OutputFormat,
        typer.Option("--format", "-f", help="table: summary and sample rows; json: JSON Lines."),
    ] = OutputFormat.TABLE,
    year: YearOption = None,
    timezone: TimezoneOption = "UTC",
    mapping: MappingOption = None,
    pattern: PatternOption = None,
    keep_query: KeepQueryOption = False,
    limit: Annotated[
        int, typer.Option(min=0, help="table: number of events to show (0 for none).")
    ] = 20,
) -> None:
    """Parse and normalise a log file; print events and a summary of counts and parse errors.

    Exit codes: 0 success, 1 every non-blank line failed to parse, 2 invalid usage or input.
    """
    with parsed_events(
        file,
        parser_name,
        year=year,
        timezone=timezone,
        mapping=mapping,
        pattern=pattern,
        keep_query=keep_query,
    ) as parsed:
        if output is OutputFormat.JSON:
            _write_json(parsed.events)
            _summary_json(parsed.parser, parsed.name, parsed.stats)
        else:
            _write_table(parsed.events, parsed.parser, parsed.name, parsed.stats, limit)
    if parsed.stats.events == 0 and parsed.stats.errors > 0:
        raise typer.Exit(ExitCode.NO_EVENTS)


def _write_json(events: Iterator[Event]) -> None:
    out = sys.stdout
    for event in events:
        out.write(event.model_dump_json())
        out.write("\n")
    out.flush()


def _summary_json(parser_name: str, name: str, stats: ParseStats) -> None:
    summary = {"input": name, "parser": parser_name, **stats.as_dict()}
    typer.echo(json.dumps(summary), err=True)


def _write_table(
    events: Iterator[Event], parser_name: str, name: str, stats: ParseStats, limit: int
) -> None:
    console = Console(highlight=False)
    table = Table(title=f"Events from {name} (first {limit})" if limit else None)
    table.add_column("time (UTC)", no_wrap=True)
    table.add_column("source", overflow="fold")
    table.add_column("action", overflow="fold")
    table.add_column("outcome", overflow="fold")
    table.add_column("source.ip", no_wrap=True)
    for column in ("user", "detail"):
        table.add_column(column, overflow="fold")
    shown = 0
    for event in events:  # always consume everything so the counts are complete
        if shown < limit:
            table.add_row(*(Text(cell) for cell in _row(event)))  # Text(): no markup injection
            shown += 1
    if shown:
        console.print(table)
    console.print(_summary_table(parser_name, name, stats))
    if stats.error_examples:
        errors = Table(title="Parse errors (first examples)")
        errors.add_column("line", justify="right")
        errors.add_column("reason", overflow="fold")
        for example in stats.error_examples:
            errors.add_row(str(example.line), Text(example.reason))
        console.print(errors)


def _row(event: Event) -> tuple[str, ...]:
    detail = ""
    if event.http.status is not None:
        detail = f"{event.http.method or '-'} {event.http.path or '-'} {event.http.status}"
    elif event.event.reason:
        detail = event.event.reason
    return (
        event.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        event.log_source,
        event.event.action,
        event.event.outcome.value,
        str(event.source.ip) if event.source.ip else "-",
        event.user.name or event.user.id or "-",
        detail,
    )


def _summary_table(parser_name: str, name: str, stats: ParseStats) -> Table:
    table = Table(title="Parse summary", show_header=False)
    table.add_column("metric")
    table.add_column("value", justify="right")
    rows = [
        ("input", name),
        ("parser", parser_name),
        ("lines", stats.lines),
        ("events", stats.events),
        ("skipped (not relevant)", stats.skipped),
        ("blank", stats.blank),
        ("errors", stats.errors),
        ("invalid UTF-8 lines", stats.decode_errors),
    ]
    for metric, value in rows:
        table.add_row(metric, Text(str(value)))
    return table
