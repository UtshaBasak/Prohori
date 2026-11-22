# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
# Copyright (c) 2026 Utsha Basak
"""``--suppressions FILE``: shared by detect, incidents, triage and the pipeline commands."""

from collections.abc import Iterable
from datetime import date
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from prohori.cli.exit_codes import ExitCode
from prohori.ml.anomaly import DETECTOR_IDS
from prohori.parsers import sanitize
from prohori.rules import CompiledRule
from prohori.suppress import (
    NO_SUPPRESSIONS,
    SuppressionFileError,
    Suppressions,
    Suppressor,
    load_suppressions,
)

SuppressionsOption = Annotated[
    Path | None,
    typer.Option(
        "--suppressions",
        help="Suppressions file (YAML, see docs/RULES.md): matching alerts are marked, counted "
        "and kept out of incidents; allow-listed addresses get no reputation points.",
        show_default=False,
    ),
]


def detector_ids(rules: Iterable[CompiledRule]) -> set[str]:
    """Every detector an entry may name: the loaded rules and the anomaly models."""
    return {r.id for r in rules} | set(DETECTOR_IDS.values())


def report_file_errors(error: SuppressionFileError) -> None:
    file = sanitize(str(error.file))
    typer.echo(f"INVALID  {file}", err=True)
    for problem in error.errors:
        typer.echo(f"  {sanitize(problem.format(file))}", err=True)


def load_option(
    path: Path | None, rules: Iterable[CompiledRule], *, today: date | None = None
) -> Suppressions:
    """Load ``--suppressions`` and print its warnings; exit 2 if the file is unusable.

    Nothing is applied from a file with any problem: half a file would silence some alerts and
    not others.
    """
    if path is None:
        return NO_SUPPRESSIONS
    if not path.is_file():
        raise typer.BadParameter(f"not found: {path}", param_hint="--suppressions")
    try:
        suppressions = load_suppressions(path)
    except SuppressionFileError as exc:
        report_file_errors(exc)
        typer.echo("the suppressions file is invalid; nothing was run", err=True)
        raise typer.Exit(ExitCode.USAGE) from None
    for warning in suppressions.warnings(detector_ids(rules), today):
        typer.echo(f"warning: {sanitize(warning)}", err=True)
    return suppressions


def print_suppressed(console: Console, suppressor: Suppressor) -> None:
    """A table of what was suppressed: entry, rule, count, reason, owner, expiry."""
    if not suppressor.total:
        return
    table = Table(title=f"Suppressed alerts ({suppressor.total:,})")
    table.add_column("entry", overflow="fold", max_width=28)
    table.add_column("rule", no_wrap=True)
    table.add_column("alerts", justify="right", no_wrap=True)
    table.add_column("expires", no_wrap=True)
    table.add_column("reason (owner)", overflow="fold", ratio=1, min_width=20)
    for entry, rule, count in suppressor.rows():
        table.add_row(
            Text(entry.id),
            Text(rule),
            Text(f"{count:,}"),
            Text(entry.expires.isoformat()),
            Text(f"{entry.reason} ({entry.owner})"),
        )
    console.print(table)
