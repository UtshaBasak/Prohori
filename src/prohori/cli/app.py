"""Root Typer application. Feature commands are registered here as they are built."""

import hashlib
import io
import platform
import sys
from typing import Annotated

import typer

from prohori.cli.demo import demo_command
from prohori.cli.detect import detect_command
from prohori.cli.enrich import enrich_command
from prohori.cli.incidents import incidents_command
from prohori.cli.parse import parse_command
from prohori.cli.report import report_command
from prohori.cli.rules import rules_app
from prohori.cli.score import score_command
from prohori.cli.simulate import simulate_command
from prohori.cli.triage import triage_command
from prohori.rules import builtin_rules_dir
from prohori.rules.attack import ATTACK_VERSION
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
    """Show the Prohori version, the ATT&CK release and the built-in rule set."""
    rules = sorted(builtin_rules_dir().glob("*.yml"))
    rule_files = [r for r in rules if not r.name.endswith(".tests.yml")]
    digest = hashlib.sha256()
    for path in rule_files:
        digest.update(path.name.encode() + b"\0" + path.read_bytes() + b"\0")
    typer.echo(f"prohori {__version__}")
    typer.echo(f"ATT&CK Enterprise v{ATTACK_VERSION}")
    typer.echo(f"built-in rules: {len(rule_files)} (rule set {digest.hexdigest()[:12]})")
    typer.echo(f"Python {platform.python_version()} on {platform.system()}")


app.command("parse")(parse_command)
app.command("detect")(detect_command)
app.command("enrich")(enrich_command)
app.command("incidents")(incidents_command)
app.command("report")(report_command)
app.command("simulate")(simulate_command)
app.command("score")(score_command)
app.command("triage")(triage_command)
app.command("demo")(demo_command)
app.add_typer(rules_app)


def main() -> None:
    """Console-script entry point."""
    # Log content can contain characters the console encoding cannot show; never crash on them.
    for stream in (sys.stdout, sys.stderr):
        if isinstance(stream, io.TextIOWrapper):
            stream.reconfigure(errors="backslashreplace")
    app()
