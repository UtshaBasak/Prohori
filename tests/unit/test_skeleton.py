"""Smoke tests for the project skeleton: the package imports and the CLI reports its version."""

import importlib
import re
import subprocess
import sys

import pytest
from typer.testing import CliRunner

import prohori
from prohori.cli import app

SUBPACKAGES = [
    "cli",
    "schema",
    "parsers",
    "rules",
    "enrich",
    "incidents",
    "reports",
    "simulate",
    "ml",
    "pipeline",
    "llm",
]

runner = CliRunner()


def test_version_is_pep440() -> None:
    assert re.fullmatch(r"\d+\.\d+\.\d+((a|b|rc)\d+)?(\.post\d+)?(\.dev\d+)?", prohori.__version__)


@pytest.mark.parametrize("name", SUBPACKAGES)
def test_subpackage_imports(name: str) -> None:
    importlib.import_module(f"prohori.{name}")


@pytest.mark.parametrize("args", [["--version"], ["-V"]])
def test_cli_prints_version(args: list[str]) -> None:
    result = runner.invoke(app, args)
    assert result.exit_code == 0
    assert result.stdout.strip() == f"prohori {prohori.__version__}"


def test_version_command_starts_with_the_version() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert result.stdout.splitlines()[0] == f"prohori {prohori.__version__}"


def test_python_m_entry_point() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "prohori", "--version"],
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    )
    assert result.stdout.strip() == f"prohori {prohori.__version__}"
