"""``prohori triage``: from a log file to incidents and reports in one command."""

import hashlib
import os
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from prohori.cli.detect import load_detection_rules, parse_lateness
from prohori.cli.exit_codes import ExitCode
from prohori.cli.incidents import IncidentRun, ParseOptions, make_enricher, run_incidents
from prohori.cli.parse import (
    KeepQueryOption,
    MappingOption,
    ParserOption,
    PatternOption,
    TimezoneOption,
    YearOption,
)
from prohori.enrich import Enricher
from prohori.incidents import IncidentSettings
from prohori.reports import (
    RedactionError,
    Redactor,
    ReportFormat,
    ReportSource,
    find_leaks,
    incident_strings,
    make_report,
)
from prohori.rules import CompiledRule
from prohori.rules.model import parse_duration
from prohori.schema import Incident

INCIDENTS_FILE = "incidents.jsonl"
SUMMARY_FILE = "summary.md"


@dataclass(frozen=True)
class TriageResult:
    """What a triage run wrote."""

    run: IncidentRun
    out: Path
    reports: dict[str, Path]  # incident id -> report file
    incidents: list[Incident]  # as written (redacted when asked)


def triage_file(
    file: str,
    out: Path,
    *,
    rules: list[CompiledRule],
    enricher: Enricher | None,
    enrichment: str,
    settings: IncidentSettings,
    lateness: timedelta,
    parse: ParseOptions,
    fmt: ReportFormat,
    redact: bool = False,
    redact_ips: bool = False,
) -> TriageResult:
    """Build incidents from ``file`` and write ``incidents.jsonl``, one report each and a summary.

    With redaction every file is redacted with one key, so an account keeps its pseudonym across
    all reports of the run.

    Raises:
        RedactionError: if redaction would leave a personal value; nothing is written then.
    """
    run = run_incidents(
        file,
        rules=rules,
        enricher=enricher,
        enrichment=enrichment,
        settings=settings,
        lateness=lateness,
        parse=parse,
    )
    key = os.urandom(32)
    written = [_redacted(i, key, redact_ips) if redact or redact_ips else i for i in run.incidents]
    lines = "".join(incident.model_dump_json() + "\n" for incident in written).encode("utf-8")
    source = ReportSource(name=INCIDENTS_FILE, sha256=hashlib.sha256(lines).hexdigest())
    texts = {
        incident.id: make_report(
            original, fmt, source=source, redact=redact, redact_ips=redact_ips, key=key
        )
        for incident, original in zip(written, run.incidents, strict=True)
    }
    out.mkdir(parents=True, exist_ok=True)
    (out / INCIDENTS_FILE).write_bytes(lines)
    reports: dict[str, Path] = {}
    for incident_id, text in texts.items():
        path = out / f"{incident_id}.{fmt.value}"
        path.write_bytes(text.encode("utf-8"))
        reports[incident_id] = path
    summary = _summary(run, written, reports, fmt, redacted=redact or redact_ips)
    (out / SUMMARY_FILE).write_bytes(summary.encode("utf-8"))
    return TriageResult(run, out, reports, written)


def _redacted(incident: Incident, key: bytes, ips: bool) -> Incident:
    redactor = Redactor(key, ips=ips)
    redacted = redactor.redact(incident)
    leaks = find_leaks("\n".join(incident_strings(redacted)), redactor.replaced)
    if leaks:
        raise RedactionError(len(leaks))
    return redacted


def _summary(
    run: IncidentRun,
    incidents: Sequence[Incident],
    reports: dict[str, Path],
    fmt: ReportFormat,
    *,
    redacted: bool,
) -> str:
    lines = [
        f"# Triage of `{run.name}`",
        "",
        f"{run.events} events, {run.parse_errors} parse errors, {run.alerts} alerts, "
        f"{len(incidents)} incidents.",
        "",
    ]
    if incidents:
        lines += [
            "| Incident | Severity | Score | Confidence | Title | Report |",
            "|----------|----------|------:|------------|-------|--------|",
        ]
        for incident in sorted(incidents, key=lambda i: (-i.score, i.first_seen, i.id)):
            title = incident.title.replace("|", "\\|")
            lines.append(
                f"| `{incident.id}` | {incident.severity.value} | {incident.score:g} | "
                f"{incident.confidence.value} | {title} | "
                f"[{reports[incident.id].name}]({reports[incident.id].name}) |"
            )
    else:
        lines.append("No incidents.")
    lines += [
        "",
        f"Reports are in `{fmt.value}` format; `{INCIDENTS_FILE}` holds the incidents as JSON Lines"
        + (" (redacted)." if redacted else "."),
        "",
    ]
    return "\n".join(lines)


def triage_command(
    file: Annotated[
        str, typer.Argument(metavar="FILE", help="Log file to triage, or '-' for standard input.")
    ],
    out: Annotated[
        Path, typer.Option("--out", "-o", help="Directory for incidents, reports and summary.md.")
    ] = Path("triage"),
    output_format: Annotated[
        ReportFormat,
        typer.Option("--format", "-f", help="Report format: md, html, json or csv."),
    ] = ReportFormat.HTML,
    redact: Annotated[
        bool, typer.Option("--redact", help="Replace account names, ids and emails everywhere.")
    ] = False,
    redact_ips: Annotated[
        bool, typer.Option("--redact-ips", help="Also replace IP addresses (implies --redact).")
    ] = False,
    online: Annotated[
        bool,
        typer.Option(
            "--online", help="Look up public IPs with the configured providers (default: offline)."
        ),
    ] = False,
    no_enrich: Annotated[
        bool, typer.Option("--no-enrich", help="Do not enrich IP addresses at all.")
    ] = False,
    gap: Annotated[
        str, typer.Option(help="Alerts sharing an entity join one incident when this close.")
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
    lateness: Annotated[
        str, typer.Option(help="How far out of order events may arrive, such as 5m (0 for none).")
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
    """Triage a log file: parse, detect, enrich, build incidents and write a report for each.

    Writes incidents.jsonl, one report per incident and summary.md to --out. Enrichment is
    offline unless --online is given. Exit codes: 0 no incidents, 3 incidents found (0 with
    --exit-zero), 1 nothing could be parsed, a rule file is invalid or redaction failed (nothing
    is written), 2 invalid usage.
    """
    allowed_lateness = parse_lateness(lateness)
    try:
        settings = IncidentSettings(gap=parse_duration(gap))
    except ValueError as exc:
        raise typer.BadParameter(str(exc), param_hint="--gap") from exc
    rules = load_detection_rules(rules_paths or [], builtin=not no_builtin)
    enricher = None if no_enrich else make_enricher(env_file, online=online)
    try:
        result = triage_file(
            file,
            out,
            rules=rules,
            enricher=enricher,
            enrichment="none" if no_enrich else ("online" if online else "offline"),
            settings=settings,
            lateness=allowed_lateness,
            parse=ParseOptions(parser_name, year, timezone, mapping, pattern, keep_query),
            fmt=output_format,
            redact=redact,
            redact_ips=redact_ips,
        )
    except RedactionError as exc:
        typer.echo(f"error: {exc}; nothing was written", err=True)
        raise typer.Exit(ExitCode.REDACTION_FAILED) from None
    print_result(result)
    if result.run.events == 0 and result.run.parse_errors > 0:
        raise typer.Exit(ExitCode.NO_EVENTS)
    if result.incidents and not exit_zero:
        raise typer.Exit(ExitCode.ALERTS_FOUND)


def print_result(result: TriageResult, console: Console | None = None) -> None:
    """Print the incidents of a triage run and where their reports are."""
    console = console or Console(highlight=False)
    run = result.run
    console.print(
        Text(
            f"{run.name}: {run.events} events, {run.alerts} alerts, "
            f"{len(result.incidents)} incident(s)"
        )
    )
    if result.incidents:
        table = Table(show_header=True)
        table.add_column("incident", no_wrap=True)
        table.add_column("severity", no_wrap=True)
        table.add_column("score", justify="right")
        table.add_column("title", ratio=1, overflow="fold")
        table.add_column("report", overflow="fold")
        ordered = sorted(result.incidents, key=lambda i: (-i.score, i.first_seen, i.id))
        for incident in ordered:
            table.add_row(
                Text(incident.id),
                Text(incident.severity.value),
                Text(f"{incident.score:g}"),
                Text(incident.title),
                Text(str(result.reports[incident.id])),
            )
        console.print(table)
    console.print(Text(f"Summary: {result.out / SUMMARY_FILE}"))
