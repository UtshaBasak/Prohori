"""``prohori detect``: parse a log file and run detection rules over it."""

import json
import sys
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

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
from prohori.parsers import sanitize
from prohori.rules import CompiledRule, EngineStats, RuleEngine, builtin_rules_dir, load_rules
from prohori.rules.model import parse_duration
from prohori.schema import Alert

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
#: Engine counters shown in the table summary when non-zero (the JSON summary has them all).
_DROP_COUNTERS = (
    "late_events",
    "future_events",
    "ungrouped_events",
    "groups_evicted",
    "group_events_dropped",
    "buffer_overflows",
)


def load_detection_rules(paths: list[Path], *, builtin: bool) -> list[CompiledRule]:
    """Load the built-in rules (unless ``builtin`` is false) and the rules under ``paths``.

    Invalid rules are reported on standard error and stop the command: a partial rule set would
    silently miss detections.
    """
    targets = ([builtin_rules_dir()] if builtin else []) + paths
    if not targets:
        raise typer.BadParameter("no rules to run: add --rules PATH or drop --no-builtin")
    missing = [str(p) for p in paths if not p.exists()]
    if missing:
        raise typer.BadParameter(f"not found: {', '.join(missing)}", param_hint="--rules")
    reports = load_rules(targets)
    invalid = [r for r in reports if not r.ok]
    for report in invalid:
        file = sanitize(str(report.file))
        typer.echo(f"INVALID  {file}", err=True)
        for error in report.errors:
            typer.echo(f"  {sanitize(error.format(file))}", err=True)
    if invalid:
        typer.echo(
            f"{len(invalid)} invalid rule file(s); run 'prohori rules validate' for details",
            err=True,
        )
        raise typer.Exit(ExitCode.INVALID_RULES)
    rules = [r.rule for r in reports if r.rule is not None]
    if not rules:
        raise typer.BadParameter("no rule files found", param_hint="--rules")
    return rules


def detect_command(
    file: Annotated[
        str, typer.Argument(metavar="FILE", help="Log file to scan, or '-' for standard input.")
    ],
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
        typer.Option("--format", "-f", help="table: alerts and a summary; json: JSON Lines."),
    ] = OutputFormat.TABLE,
    lateness: Annotated[
        str,
        typer.Option(
            help="How far out of order events may arrive and still count, such as 5m (0 for none)."
        ),
    ] = "5m",
    exit_zero: Annotated[
        bool, typer.Option("--exit-zero", help="Exit 0 even when alerts are found.")
    ] = False,
    parser_name: ParserOption = "auto",
    year: YearOption = None,
    timezone: TimezoneOption = "UTC",
    mapping: MappingOption = None,
    pattern: PatternOption = None,
    keep_query: KeepQueryOption = False,
    models: ModelsOption = False,
) -> None:
    """Parse a log file and run detection rules over it; print the alerts and a summary.

    Exit codes: 0 no alerts, 3 alerts found (0 with --exit-zero), 1 every non-blank line failed to
    parse or a rule file is invalid, 2 invalid usage or input.
    """
    allowed_lateness = parse_lateness(lateness)
    rules = load_detection_rules(rules_paths or [], builtin=not no_builtin)
    engine = RuleEngine(rules, lateness=allowed_lateness, reference_time=datetime.now(UTC))
    with parsed_events(
        file,
        parser_name,
        year=year,
        timezone=timezone,
        mapping=mapping,
        pattern=pattern,
        keep_query=keep_query,
    ) as parsed:
        model_run = ModelRun(models)
        alerts = model_run.chain(engine.run(model_run.observe(parsed.events)))
        if output is OutputFormat.JSON:
            count = _write_json(alerts)
            _summary_json(parsed, len(rules), count, engine.stats)
        else:
            count = _write_table(alerts, parsed, len(rules), engine.stats)
    if parsed.stats.events == 0 and parsed.stats.errors > 0:
        raise typer.Exit(ExitCode.NO_EVENTS)
    if count and not exit_zero:
        raise typer.Exit(ExitCode.ALERTS_FOUND)


def parse_lateness(text: str) -> timedelta:
    """Parse ``--lateness``: a rule duration (``30s``, ``5m``, ...) or zero (``0`` / ``0s``)."""
    if text.strip() in {"0", "0s", "0m", "0h", "0d"}:
        return timedelta(0)
    try:
        return parse_duration(text)
    except ValueError as exc:
        raise typer.BadParameter(str(exc), param_hint="--lateness") from exc


def _write_json(alerts: Iterable[Alert]) -> int:
    count = 0
    out = sys.stdout
    for alert in alerts:
        out.write(alert.model_dump_json())
        out.write("\n")
        count += 1
    out.flush()
    return count


def _summary(parsed: ParsedInput, rules: int, alerts: int) -> dict[str, str | int]:
    return {
        "input": parsed.name,
        "parser": parsed.parser,
        "events": parsed.stats.events,
        "parse_errors": parsed.stats.errors,
        "rules": rules,
        "alerts": alerts,
    }


def _engine_counters(stats: EngineStats) -> dict[str, int]:
    return {key: value for key, value in stats.as_dict().items() if key != "alerts"}


def _summary_json(parsed: ParsedInput, rules: int, alerts: int, stats: EngineStats) -> None:
    summary = {**_summary(parsed, rules, alerts), "engine": _engine_counters(stats)}
    typer.echo(json.dumps(summary), err=True)


def _sorted(alerts: Iterable[Alert]) -> list[Alert]:
    return sorted(
        alerts,
        key=lambda a: (a.first_seen, _SEVERITY_ORDER.get(a.severity.value, 9), a.detector_id),
    )


def _write_table(
    alerts: Iterable[Alert], parsed: ParsedInput, rules: int, stats: EngineStats
) -> int:
    console = Console(highlight=False)
    collected = _sorted(alerts)
    if collected:
        table = Table(title=f"Alerts in {parsed.name}")
        table.add_column("first seen (UTC)")
        table.add_column("severity", no_wrap=True)
        table.add_column("rule", no_wrap=True)
        table.add_column("entities", overflow="fold")
        table.add_column("alert", overflow="fold", ratio=1)
        for alert in collected:
            entities = "\n".join(f"{k}={v}" for k, v in sorted(alert.entities.items()))
            # Text() never interprets markup, so log content cannot inject styles.
            detail = Text(alert.title, style="bold")
            detail.append("\n" + alert.explanation, style="dim")
            table.add_row(
                Text(alert.first_seen.strftime("%Y-%m-%d %H:%M:%S")),
                Text(alert.severity.value),
                Text(alert.detector_id),
                Text(entities or "-"),
                detail,
            )
        console.print(table)
    else:
        console.print("No alerts.")
    summary = Table(title="Detection summary", show_header=False)
    summary.add_column("metric")
    summary.add_column("value", justify="right")
    engine = _engine_counters(stats)
    for key, value in _summary(parsed, rules, len(collected)).items():
        summary.add_row(key.replace("_", " "), Text(str(value)))
    for key in _DROP_COUNTERS:
        if engine[key]:  # events that were not fully evaluated; silent when zero
            summary.add_row(key.replace("_", " "), Text(str(engine[key])))
    console.print(summary)
    return len(collected)
