"""Root Typer application. Feature commands are registered here as they are built."""

from typing import Annotated

import typer

from prohori.version import __version__

app = typer.Typer(
    name="prohori",
    help="Prohori: from raw logs to detections, enriched incidents and analyst-ready reports.",
    no_args_is_help=True,
    add_completion=False,
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"prohori {__version__}")
        raise typer.Exit


@app.callback()
def root(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            "-V",
            help="Show the version and exit.",
            callback=_version_callback,
            is_eager=True,
        ),
    ] = False,
) -> None:
    """Prohori command-line tool."""


@app.command("version")
def version_command() -> None:
    """Show the Prohori version."""
    typer.echo(f"prohori {__version__}")


def main() -> None:
    """Console-script entry point."""
    app()
