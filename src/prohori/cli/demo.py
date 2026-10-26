"""``prohori demo``: simulate attacks, triage them and show what Prohori found, offline."""

import dataclasses
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from prohori.cli.detect import load_detection_rules
from prohori.cli.incidents import ParseOptions
from prohori.cli.triage import SUMMARY_FILE, triage_file
from prohori.enrich import EnrichSettings, build_enricher
from prohori.incidents import IncidentSettings
from prohori.reports import ReportFormat
from prohori.simulate import SCENARIOS, simulate, write
from prohori.simulate.evaluate import LATENESS

#: Scenarios the demo runs by default: one each for the app, SSH and the web server.
DEFAULT_SCENARIOS = ("account-takeover", "ssh-bruteforce", "web-scanning")


def demo_command(
    out: Annotated[
        Path, typer.Option("--out", "-o", help="Directory for the simulated logs and reports.")
    ] = Path("prohori-demo"),
    seed: Annotated[int, typer.Option(min=0, help="Random seed for the simulated attacks.")] = 1,
    scenarios: Annotated[
        list[str] | None,
        typer.Option(
            "--scenario",
            "-s",
            help="Scenario to run (repeatable; see 'prohori simulate --list').",
            show_default=False,
        ),
    ] = None,
    output_format: Annotated[
        ReportFormat, typer.Option("--format", "-f", help="Report format: md, html, json or csv.")
    ] = ReportFormat.HTML,
) -> None:
    """Simulate attacks, triage them offline and show what Prohori found.

    Needs no configuration and never uses the network: the logs are synthetic, every address is
    from a documentation range, and enrichment uses only bundled demo data, with its cache inside
    --out. Exit codes: 0 done, 2 invalid usage.
    """
    names = list(scenarios or DEFAULT_SCENARIOS)
    unknown = [n for n in names if n not in SCENARIOS]
    if unknown:
        choices = ", ".join(sorted(SCENARIOS))
        raise typer.BadParameter(f"unknown scenario(s) {', '.join(unknown)}; choose from {choices}")
    run_demo(out, seed=seed, names=names, fmt=output_format, console=Console(highlight=False))


def run_demo(
    out: Path, *, seed: int, names: list[str], fmt: ReportFormat, console: Console
) -> list[tuple[str, Path]]:
    """Run the demo and print its results; return each scenario's top report."""
    rules = load_detection_rules([], builtin=True)
    # No keys, no .env and a cache of its own: the demo cannot reach the network or touch the
    # user's enrichment cache.
    settings = dataclasses.replace(
        EnrichSettings.load(environ={}, env_file=None), cache_path=out / ".cache" / "enrich.sqlite3"
    )
    table = Table(title=f"Prohori demo (seed {seed})")
    table.add_column("scenario", no_wrap=True)
    table.add_column("alerts", justify="right")
    table.add_column("incidents", justify="right")
    table.add_column("top incident", no_wrap=True)
    table.add_column("expected rules fired", justify="right")
    reports: list[tuple[str, Path]] = []
    missed: list[str] = []
    for name in names:
        simulation = simulate(name, seed=seed)
        logs = out / "logs" / name
        write(simulation, logs)
        scenario = simulation.scenario
        result = triage_file(
            str(logs / scenario.filename),
            out / name,
            rules=rules,
            enricher=build_enricher(settings, offline=True),
            enrichment="offline",
            settings=IncidentSettings(),
            lateness=LATENESS,
            parse=ParseOptions(
                scenario.parser, year=simulation.year if scenario.parser == "auth_log" else None
            ),
            fmt=fmt,
        )
        fired = {a.detector_id for i in result.incidents for a in i.alerts}
        expected = [r for attack in simulation.attacks for r in attack.expected_rules]
        missed += [f"{name}: {r}" for r in expected if r not in fired]
        found = sum(1 for r in expected if r in fired)
        top = max(result.incidents, key=lambda i: (i.score, i.id), default=None)
        if top is not None:
            reports.append((name, result.reports[top.id]))
        table.add_row(
            Text(name),
            Text(str(result.run.alerts)),
            Text(str(len(result.incidents))),
            Text(f"{top.severity.value}, score {top.score:g}" if top else "none"),
            Text(f"{found}/{len(expected)}", style="green" if found == len(expected) else "red"),
        )
    console.print(table)
    if missed:
        console.print(Text("Expected rules that did not fire: " + ", ".join(missed), style="red"))
    console.print(Text("Highest-scoring incident of each scenario:"))
    for name, path in reports:
        console.print(Text(f"  {name}: {path.as_posix()}"))
    console.print(
        Text(
            f"Everything is in {out.as_posix()}: simulated logs with labels, incidents.jsonl, "
            f"a report per incident and a {SUMMARY_FILE} per scenario. The logs are synthetic, "
            "every address is from a documentation range, and nothing was sent over the network."
        )
    )
    return reports
