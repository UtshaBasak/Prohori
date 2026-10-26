"""``prohori incidents``: parse a log file, run the rules and group the alerts into incidents."""

import json
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from prohori.cli.detect import load_detection_rules, parse_lateness
from prohori.cli.exit_codes import ExitCode
from prohori.cli.parse import (
    KeepQueryOption,
    MappingOption,
    OutputFormat,
    ParserOption,
    PatternOption,
    TimezoneOption,
    YearOption,
    parsed_events,
)
from prohori.enrich import ConfigError, Enricher, EnrichSettings, build_enricher
from prohori.incidents import EventContext, IncidentBuilder, IncidentSettings
from prohori.rules import RuleEngine
from prohori.rules.model import parse_duration
from prohori.schema import Incident


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
    enricher = None if no_enrich else _enricher(env_file, online=online)
    context = EventContext()
    engine = RuleEngine(rules, lateness=allowed_lateness, reference_time=datetime.now(UTC))
    try:
        with parsed_events(
            file,
            parser_name,
            year=year,
            timezone=timezone,
            mapping=mapping,
            pattern=pattern,
            keep_query=keep_query,
        ) as parsed:
            alerts = list(engine.run(context.observe(parsed.events)))
        builder = IncidentBuilder(rules, context=context, enricher=enricher, settings=settings)
        incidents = builder.build(alerts)
    finally:
        if enricher is not None:
            enricher.close()
    if output is OutputFormat.JSON:
        for incident in incidents:
            typer.echo(incident.model_dump_json())
        summary = {
            "input": parsed.name,
            "events": parsed.stats.events,
            "parse_errors": parsed.stats.errors,
            "alerts": len(alerts),
            "incidents": len(incidents),
        }
        typer.echo(json.dumps(summary), err=True)
    else:
        _print_tables(incidents, parsed.name, len(alerts))
    if parsed.stats.events == 0 and parsed.stats.errors > 0:
        raise typer.Exit(ExitCode.NO_EVENTS)
    if incidents and not exit_zero:
        raise typer.Exit(ExitCode.ALERTS_FOUND)


def _enricher(env_file: Path, *, online: bool) -> Enricher:
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
