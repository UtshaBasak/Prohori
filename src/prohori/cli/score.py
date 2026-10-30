"""``prohori score``: score a CSV of network flows with a saved flow model.

The machine-learning code is imported only when the command runs, so the base install (without
the ``ml`` extra) keeps working and this command explains how to add it.
"""

import json
import sys
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Annotated

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from prohori.cli.exit_codes import ExitCode
from prohori.parsers import sanitize

if TYPE_CHECKING:
    from prohori.ml.score import ScoreResult

DEFAULT_MODELS_DIR = Path("models")
CAVEAT = (
    "Scores come from a model trained on a lab dataset; on other networks it can miss attacks "
    "and flag benign flows (see docs/MODEL_CARD.md). Treat flagged flows as leads."
)


#: Context shown in the table (JSON has every context column, including flow_id and src_port).
TABLE_CONTEXT = ("src_ip", "dst_ip", "dst_port", "protocol", "proto", "service", "timestamp")


class ScoreFormat(StrEnum):
    TABLE = "table"
    JSON = "json"


def score_command(
    file: Annotated[
        str, typer.Argument(metavar="FLOWS", help="CSV of flows, or '-' for standard input.")
    ],
    model: Annotated[
        str,
        typer.Option(
            "--model",
            "-m",
            help="Model file, or a name such as cicids2017/hgb-seed0 under --models-dir.",
            show_default=False,
        ),
    ],
    models_dir: Annotated[
        Path, typer.Option(help="Where models trained by prohori.ml.train are saved.")
    ] = DEFAULT_MODELS_DIR,
    fpr: Annotated[
        float | None,
        typer.Option(
            help="Use the model's threshold for this validation false-positive rate "
            "(default: the strictest it has).",
            show_default=False,
        ),
    ] = None,
    top: Annotated[
        int, typer.Option(min=0, help="Flagged flows to list, highest score first (0: all).")
    ] = 20,
    output: Annotated[
        ScoreFormat, typer.Option("--format", "-f", help="table or json.")
    ] = ScoreFormat.TABLE,
    exit_zero: Annotated[
        bool, typer.Option("--exit-zero", help="Exit 0 even when flows are flagged.")
    ] = False,
) -> None:
    """Score each flow in a CSV with a saved model; list the flagged flows and a summary.

    Needs the 'ml' extra. Model files are pickles: only use models you trained yourself. Exit
    codes: 0 nothing flagged, 3 flows flagged (0 with --exit-zero), 1 the ml extra is missing,
    the model cannot be loaded or the file cannot be scored, 2 invalid usage.
    """
    try:
        from prohori.ml import score as scoring
        from prohori.ml.models import UNSAFE_PICKLE_WARNING, ModelFileError
    except ImportError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(ExitCode.NO_EVENTS) from None
    try:
        model_path = scoring.resolve_model(model, models_dir)
    except FileNotFoundError as exc:
        raise typer.BadParameter(str(exc), param_hint="--model") from None
    source: Path | bytes
    if file == "-":
        source = sys.stdin.buffer.read()
    else:
        source = Path(file)
        if not source.is_file():
            raise typer.BadParameter(f"no such file: {file}", param_hint="FLOWS")
    typer.echo(f"warning: {UNSAFE_PICKLE_WARNING}", err=True)
    try:
        result = scoring.score_file(source, model_path, fpr=fpr, top=top)
    except (ModelFileError, scoring.ScoreInputError) as exc:
        typer.echo(f"error: {sanitize(str(exc))}", err=True)
        raise typer.Exit(ExitCode.NO_EVENTS) from None
    if output is ScoreFormat.JSON:
        typer.echo(json.dumps(result.to_dict(), indent=2))
    else:
        _print_table(result)
    if result.flagged and not exit_zero:
        raise typer.Exit(ExitCode.ALERTS_FOUND)


def _print_table(result: "ScoreResult") -> None:
    console = Console(highlight=False)
    if result.top:
        present = {k for f in result.top for k in f.context}
        columns = [c for c in TABLE_CONTEXT if c in present]
        table = Table(title=f"Flagged flows (top {len(result.top)} by score)")
        table.add_column("row", justify="right")
        table.add_column("score", justify="right")
        for column in columns:
            table.add_column(column)
        for flow in result.top:
            cells = [Text(sanitize(flow.context.get(c, ""))) for c in columns]
            table.add_row(str(flow.row), f"{flow.score:.4f}", *cells)
        console.print(table)
    share = result.flagged / result.flows if result.flows else 0.0
    console.print(
        f"{result.flows:,} flows scored with {result.model}; {result.flagged:,} flagged "
        f"({share:.2%}) at the {result.threshold_name.removeprefix('fpr_')} validation "
        f"false-positive threshold ({result.threshold:.6g})."
    )
    if result.non_numeric_values:
        console.print(f"{result.non_numeric_values:,} values were not numbers and were imputed.")
    console.print(CAVEAT)
