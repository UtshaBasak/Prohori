"""``prohori incidents``: parse a log file, run the rules and group the alerts into incidents."""

import json
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from prohori.cli.detect import load_detection_rules, parse_lateness
from prohori.cli.exit_codes import ExitCode
from prohori.cli.models import ModelRun, ModelsOption
from prohori.cli.parse import (
    KeepQueryOption,
    MappingOption,
    OutputFormat,
    ParsedInput,
    ParserOption,
    PatternOption,
    TimezoneOption,
    YearOption,
    parsed_events,
)
from prohori.enrich import ConfigError, Enricher, EnrichSettings, build_enricher
from prohori.incidents import EventContext, IncidentBuilder, IncidentSettings
from prohori.incidents.provenance import with_provenance
from prohori.rules import CompiledRule, RuleEngine
from prohori.rules.model import parse_duration
from prohori.schema import Incident, InputFile


def incidents_command(
    file: Annotated[
        str, typer.Argument(metavar="FILE", help="Log file to scan, or '-' for standard input.")
    ],
    online: Annotated[
        bool,
        typer.Option(
            "--online",
            help="Look up public IPs with the configured providers (default: offline, no network).",
        ),
    ] = False,
    no_enrich: Annotated[
        bool, typer.Option("--no-enrich", help="Do not enrich IP addresses at all.")
    ] = False,
    gap: Annotated[
        str,
        typer.Option(
            help="Alerts sharing an entity join one incident when this close, such as 30m."
        ),
    ] = "30m",
    rules_paths: Annotated[
        list[Path] | None,
        typer.Option(
            "--rules",
            "-r",
            help="Extra rule file or directory (repeatable), run with the built-in rules.",
            show_default=False,
        ),
    ] = None,
    no_builtin: Annotated[
        bool, typer.Option("--no-builtin", help="Run only the rules given with --rules.")
    ] = False,
    output: Annotated[
        OutputFormat,
        typer.Option("--format", "-f", help="table: a summary per incident; json: JSON Lines."),
    ] = OutputFormat.TABLE,
    lateness: Annotated[
        str,
        typer.Option(
            help="How far out of order events may arrive and still count, such as 5m (0 for none)."
        ),
    ] = "5m",
    exit_zero: Annotated[
        bool, typer.Option("--exit-zero", help="Exit 0 even when incidents are found.")
    ] = False,
    env_file: Annotated[
        Path, typer.Option(help="Enrichment settings file read under the environment variables.")
    ] = Path(".env"),
    parser_name: ParserOption = "auto",
    year: YearOption = None,
    timezone: TimezoneOption = "UTC",
    mapping: MappingOption = None,
    pattern: PatternOption = None,
    keep_query: KeepQueryOption = False,
    models: ModelsOption = False,
) -> None:
    """Parse a log file, run the detection rules and group the alerts into scored incidents.

    Enrichment is offline by default: bundled demo data, local GeoLite2 data and cached answers,
    never the network. Exit codes: 0 no incidents, 3 incidents found (0 with --exit-zero), 1 every
    non-blank line failed to parse or a rule file is invalid, 2 invalid usage or input.
    """
    allowed_lateness = parse_lateness(lateness)
    try:
        settings = IncidentSettings(gap=parse_duration(gap))
    except ValueError as exc:
        raise typer.BadParameter(str(exc), param_hint="--gap") from exc
    rules = load_detection_rules(rules_paths or [], builtin=not no_builtin)
    enricher = None if no_enrich else make_enricher(env_file, online=online)
    mode = "none" if no_enrich else ("online" if online else "offline")
    run = run_incidents(
        file,
        rules=rules,
        enricher=enricher,
        enrichment=mode,
        settings=settings,
        lateness=allowed_lateness,
        parse=ParseOptions(parser_name, year, timezone, mapping, pattern, keep_query),
        models=models,
    )
    incidents = run.incidents
    if output is OutputFormat.JSON:
        for incident in incidents:
            typer.echo(incident.model_dump_json())
        summary = {
            "input": run.name,
            "events": run.events,
            "parse_errors": run.parse_errors,
            "alerts": run.alerts,
            "incidents": len(incidents),
        }
        typer.echo(json.dumps(summary), err=True)
    else:
        _print_tables(incidents, run.name, run.alerts)
    if run.events == 0 and run.parse_errors > 0:
        raise typer.Exit(ExitCode.NO_EVENTS)
    if incidents and not exit_zero:
        raise typer.Exit(ExitCode.ALERTS_FOUND)


@dataclass(frozen=True)
class ParseOptions:
    """Parser options shared by the commands that read log files."""

    parser: str = "auto"
    year: int | None = None
    timezone: str = "UTC"
    mapping: Path | None = None
    pattern: str | None = None
    keep_query: bool = False


@dataclass(frozen=True)
class IncidentRun:
    """The outcome of parsing one input, running the rules and building incidents."""

    incidents: list[Incident]
    name: str
    events: int
    parse_errors: int
    alerts: int


def run_incidents(
    file: str,
    *,
    rules: list[CompiledRule],
    enricher: Enricher | None,
    enrichment: str,
    settings: IncidentSettings,
    lateness: timedelta,
    parse: ParseOptions,
    models: bool = False,
) -> IncidentRun:
    """Parse ``file`` ('-' for stdin), run ``rules`` and build incidents with provenance.

    With ``models`` the anomaly detectors run over the same events and their alerts join the
    rule alerts. Closes ``enricher`` when done.
    """
    context = EventContext()
    engine = RuleEngine(rules, lateness=lateness, reference_time=datetime.now(UTC))
    try:
        with parsed_events(
            file,
            parse.parser,
            year=parse.year,
            timezone=parse.timezone,
            mapping=parse.mapping,
            pattern=parse.pattern,
            keep_query=parse.keep_query,
        ) as parsed:
            model_run = ModelRun(models)
            alerts = list(engine.run(context.observe(model_run.observe(parsed.events))))
            alerts += model_run.alerts()
            source = _input_file(parsed)  # the whole input has been read (and hashed) by now
        builder = IncidentBuilder(rules, context=context, enricher=enricher, settings=settings)
        incidents = with_provenance(
            builder.build(alerts),
            inputs=[source] if source is not None else [],
            rules=rules,
            enrichment=enrichment,
        )
    finally:
        if enricher is not None:
            enricher.close()
    return IncidentRun(
        incidents, parsed.name, parsed.stats.events, parsed.stats.errors, len(alerts)
    )


def _input_file(parsed: ParsedInput) -> InputFile | None:
    if parsed.reader is None:
        return None
    return InputFile(
        name=parsed.name,
        sha256=parsed.reader.hexdigest(),
        bytes=parsed.reader.bytes,
        events=parsed.stats.events,
        parser=parsed.parser,
    )


def make_enricher(env_file: Path, *, online: bool) -> Enricher:
    try:
        settings = EnrichSettings.load(env_file=env_file)
    except ConfigError as exc:
        raise typer.BadParameter(str(exc)) from exc
    return build_enricher(settings, offline=not online)


def _print_tables(incidents: Sequence[Incident], name: str, alerts: int) -> None:
    console = Console(highlight=False)
    if not incidents:
        console.print(f"No incidents in {name} ({alerts} alerts).")
        return
    for incident in incidents:
        table = Table(
            title=Text(f"{incident.id}  {incident.severity.value}  score {incident.score:g}"),
            title_justify="left",
            show_header=False,
        )
        table.add_column("field", no_wrap=True, style="bold")
        table.add_column("value", overflow="fold", ratio=1)
        # Text() never interprets markup, so log content cannot inject styles.
        table.add_row("title", Text(incident.title))
        table.add_row(
            "time (UTC)",
            Text(
                f"{incident.first_seen:%Y-%m-%d %H:%M:%S} - {incident.last_seen:%Y-%m-%d %H:%M:%S}"
            ),
        )
        table.add_row("confidence", Text(incident.confidence.value))
        table.add_row("rules", Text(", ".join(sorted({a.detector_id for a in incident.alerts}))))
        entities = "\n".join(f"{k}: {', '.join(v)}" for k, v in incident.entities.items())
        table.add_row("entities", Text(entities or "-"))
        table.add_row("ATT&CK", Text(", ".join(incident.attack) or "-"))
        breakdown = "\n".join(f"{c.points:+g}  {c.reason}" for c in incident.score_breakdown)
        table.add_row("score", Text(breakdown))
        table.add_row("actions", Text("\n".join(f"- {a}" for a in incident.recommended_actions)))
        table.add_row("limitations", Text("\n".join(f"- {x}" for x in incident.limitations)))
        console.print(table)
    console.print(f"{len(incidents)} incident(s) from {alerts} alert(s) in {name}.")
