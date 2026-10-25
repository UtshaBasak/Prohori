"""``prohori enrich``: look up IP addresses with the configured providers."""

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from prohori.cli.parse import OutputFormat
from prohori.enrich import ConfigError, EnrichmentReport, EnrichSettings, build_enricher, parse_ip
from prohori.enrich.addresses import IPAddress

#: Most addresses accepted in one command.
MAX_ADDRESSES = 1000


def enrich_command(
    addresses: Annotated[
        list[str], typer.Argument(metavar="IP...", help="IPv4 or IPv6 addresses to look up.")
    ],
    offline: Annotated[
        bool,
        typer.Option(
            "--offline",
            help="No network: bundled demo data, local GeoLite2 and cached answers only.",
        ),
    ] = False,
    output: Annotated[
        OutputFormat,
        typer.Option("--format", "-f", help="table: one table per address; json: JSON Lines."),
    ] = OutputFormat.TABLE,
    no_cache: Annotated[
        bool,
        typer.Option("--no-cache", help="Ignore cached answers (new answers are still cached)."),
    ] = False,
    env_file: Annotated[
        Path, typer.Option(help="Settings file read under the environment variables.")
    ] = Path(".env"),
) -> None:
    """Look up IP addresses: geolocation, network owner and reputation.

    Private, reserved and documentation addresses are never sent to external services. Exit
    codes: 0 done (failed lookups are reported per address), 2 invalid usage, address or setting.
    """
    if len(addresses) > MAX_ADDRESSES:
        raise typer.BadParameter(f"at most {MAX_ADDRESSES} addresses per run", param_hint="IP")
    parsed: list[IPAddress] = []
    for value in addresses:  # validate everything before any lookup is sent
        try:
            parsed.append(parse_ip(value))
        except ValueError:
            raise typer.BadParameter(f"not an IP address: {value!r}", param_hint="IP") from None
    try:
        settings = EnrichSettings.load(env_file=env_file)
    except ConfigError as exc:
        raise typer.BadParameter(str(exc)) from exc
    with build_enricher(settings, offline=offline, read_cache=not no_cache) as enricher:
        for note in enricher.setup_notes:
            typer.echo(f"note: {note}", err=True)
        reports = (enricher.enrich_ip(address) for address in parsed)
        if output is OutputFormat.JSON:
            for report in reports:
                typer.echo(report.model_dump_json())
        else:
            console = Console(highlight=False)
            for report in reports:
                console.print(_table(report))


def _table(report: EnrichmentReport) -> Table:
    indicator = report.indicator
    scope = "public" if report.public else "not public"
    table = Table(title=f"{indicator.value} ({scope})", title_justify="left")
    table.add_column("provider", no_wrap=True)
    table.add_column("retrieved (UTC)", no_wrap=True)
    table.add_column("data", overflow="fold", ratio=1)
    for result in indicator.enrichment:
        retrieved = result.retrieved_at.strftime("%Y-%m-%d %H:%M")
        if result.provider in report.cached:
            retrieved += " (cached)"
        data = Text("\n".join(f"{key}: {value}" for key, value in result.data.items()))
        if result.note:
            data.append("\n" + result.note, style="dim")
        table.add_row(Text(result.provider), Text(retrieved), data)  # Text(): no markup
    if not indicator.enrichment:
        table.add_row("-", "-", Text("no data"))
    for note in report.notes:
        table.add_row(Text("note"), "", Text(note, style="yellow"))
    return table
