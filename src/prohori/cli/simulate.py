"""``prohori simulate``: write a labelled attack scenario as a log file."""

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from prohori.simulate import SCENARIOS, VARIANTS, SimulationError, simulate, write


def simulate_command(
    scenario: Annotated[
        str | None,
        typer.Argument(
            metavar="SCENARIO", help="Scenario to write (see --list).", show_default=False
        ),
    ] = None,
    out: Annotated[
        Path | None,
        typer.Option("--out", "-o", help="Directory for the log, its labels and manifest.json."),
    ] = None,
    seed: Annotated[
        int, typer.Option(min=0, help="Random seed; the same seed gives the same files.")
    ] = 1,
    variant: Annotated[
        str, typer.Option(help=f"Attacker behaviour: {' or '.join(VARIANTS)}.")
    ] = "default",
    settings: Annotated[
        list[str] | None,
        typer.Option(
            "--set",
            help="Override a parameter, such as --set rate=5 (repeatable; see --list).",
            show_default=False,
        ),
    ] = None,
    list_scenarios: Annotated[
        bool, typer.Option("--list", help="List the scenarios and their parameters.")
    ] = False,
) -> None:
    """Write a simulated, labelled attack scenario with benign background activity.

    Nothing is sent anywhere: the output is files, and every IP address is from a documentation
    range. Exit codes: 0 written, 2 invalid usage, scenario, variant or parameter.
    """
    if list_scenarios:
        _print_list()
        return
    if scenario is None or out is None:
        raise typer.BadParameter("give a SCENARIO and --out DIR, or use --list")
    overrides: dict[str, str] = {}
    for item in settings or []:
        name, sep, value = item.partition("=")
        if not sep or not name.strip():
            raise typer.BadParameter(f"expected NAME=VALUE, got {item!r}", param_hint="--set")
        overrides[name.strip()] = value.strip()
    try:
        simulation = simulate(scenario, seed=seed, variant=variant, overrides=overrides)
    except SimulationError as exc:
        raise typer.BadParameter(str(exc)) from exc
    manifest = write(simulation, out)
    files = manifest["files"]
    assert isinstance(files, dict)  # noqa: S101 - narrows the manifest's type for mypy
    typer.echo(
        f"wrote {out / simulation.scenario.filename} ({len(simulation.lines)} lines, "
        f"{sum(1 for _, a in simulation.lines if a)} attack), "
        f"{files['labels']['name']} and manifest.json; parse with --parser "
        f"{simulation.scenario.parser}"
        + (f" --year {simulation.year}" if simulation.scenario.parser == "auth_log" else "")
    )


def _print_list() -> None:
    console = Console(highlight=False)
    table = Table(title="Scenarios", show_lines=True)
    table.add_column("scenario", no_wrap=True)
    table.add_column("log", no_wrap=True)
    table.add_column("what it simulates", ratio=1)
    table.add_column("parameters (default / heldout)", ratio=1)
    for name, scenario in sorted(SCENARIOS.items()):
        default, heldout = scenario.defaults["default"], scenario.defaults["heldout"]
        params = "\n".join(
            f"{key}={default[key]:g}"
            + (f" / {heldout[key]:g}" if heldout[key] != default[key] else "")
            for key in sorted(default)
        )
        table.add_row(Text(name), Text(scenario.parser), Text(scenario.description), Text(params))
    console.print(table)
    console.print("Every scenario also takes --set start=<ISO time>.")
