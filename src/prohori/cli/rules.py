"""``prohori rules``: list and validate detection rules."""

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from prohori.cli.exit_codes import ExitCode
from prohori.cli.parse import OutputFormat
from prohori.rules import RuleReport, builtin_rules_dir, load_rules

rules_app = typer.Typer(
    name="rules",
    help="List and validate detection rules.",
    no_args_is_help=True,
    add_completion=False,
)

PathsArgument = Annotated[
    list[Path] | None,
    typer.Argument(
        metavar="[PATH]...",
        help="Rule files or directories (searched recursively). Default: the built-in rules.",
        show_default=False,
    ),
]
FormatOption = Annotated[OutputFormat, typer.Option("--format", "-f", help="Output format.")]


def _load(paths: list[Path] | None) -> list[RuleReport]:
    targets = paths or [builtin_rules_dir()]
    missing = [str(p) for p in targets if not p.exists()]
    if missing:
        raise typer.BadParameter(f"not found: {', '.join(missing)}", param_hint="PATH")
    return load_rules(targets)


@rules_app.command("list")
def list_command(paths: PathsArgument = None, output: FormatOption = OutputFormat.TABLE) -> None:
    """List valid rules with their severity, status and ATT&CK tags.

    Invalid rules are not listed; their number is reported and the exit code is 1.
    """
    reports = _load(paths)
    valid = sorted(
        (r for r in reports if r.ok and r.rule is not None),
        key=lambda r: r.rule.id if r.rule is not None else "",
    )
    invalid = len(reports) - len(valid)
    if output is OutputFormat.JSON:
        rows = [
            {
                "id": r.rule.id,
                "title": r.rule.meta.title,
                "severity": r.rule.meta.severity.value,
                "status": r.rule.meta.status.value,
                "tags": r.rule.meta.tags,
                "stateful": r.rule.is_stateful,
                "file": str(r.file),
            }
            for r in valid
            if r.rule is not None
        ]
        typer.echo(json.dumps(rows, indent=2))
    else:
        console = Console(highlight=False)
        if valid:
            table = Table(title=f"Rules ({len(valid)})")
            for column in ("id", "severity", "status", "title", "ATT&CK"):
                table.add_column(column, overflow="fold")
            for report in valid:
                if report.rule is None:  # pragma: no cover - filtered above
                    continue
                meta = report.rule.meta
                table.add_row(
                    Text(meta.id),
                    Text(meta.severity.value),
                    Text(meta.status.value),
                    Text(meta.title),
                    Text(", ".join(meta.attack_tags)),
                )
            console.print(table)
        else:
            console.print("No valid rules found.")
    if invalid:
        typer.echo(
            f"{invalid} invalid rule file(s); run 'prohori rules validate' for details.", err=True
        )
        raise typer.Exit(ExitCode.INVALID_RULES)


@rules_app.command("validate")
def validate_command(
    paths: PathsArgument = None, output: FormatOption = OutputFormat.TABLE
) -> None:
    """Validate rule files and report every problem with its file and line.

    Exit codes: 0 all rules valid, 1 at least one invalid rule, 2 invalid usage.
    """
    reports = _load(paths)
    invalid = [r for r in reports if not r.ok]
    if output is OutputFormat.JSON:
        rows = [
            {
                "file": str(r.file),
                "id": r.rule.id if r.rule is not None else None,
                "valid": r.ok,
                "errors": [
                    {"line": e.line, "path": e.path, "message": e.message} for e in r.errors
                ],
            }
            for r in reports
        ]
        typer.echo(json.dumps(rows, indent=2))
    else:
        # Plain lines (no Rich): one error per line, never wrapped, safe to grep.
        for report in reports:
            typer.echo(f"{'OK' if report.ok else 'INVALID':<8} {report.file}")
            for error in report.errors:
                typer.echo(f"  {error.format(str(report.file))}")
        summary = f"{len(reports) - len(invalid)} valid, {len(invalid)} invalid"
        typer.echo(summary if reports else "No rule files found.")
    if invalid:
        raise typer.Exit(ExitCode.INVALID_RULES)
