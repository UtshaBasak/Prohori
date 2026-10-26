"""Golden files for the human-readable (table) output of the main commands.

Rich draws boxes with different characters depending on the platform and terminal, so the
output is normalised to ASCII borders before comparing. Set PROHORI_UPDATE_GOLDEN=1 to rewrite
the files after an intended change.
"""

import os
import re
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from prohori.cli import app
from tests.unit.enrich.conftest import isolated_settings, no_network

__all__ = ["isolated_settings", "no_network"]  # autouse: no network, no real cache or keys

ROOT = Path(__file__).resolve().parents[3]
SAMPLES = ROOT / "samples" / "logs"
GOLDEN = ROOT / "tests" / "golden" / "cli"
UPDATE_GOLDEN = os.environ.get("PROHORI_UPDATE_GOLDEN") == "1"
#: Rich subtracts one column on Windows consoles without VT support (as under the test runner),
#: so ask for one more there: the output is 99 columns wide everywhere.
COLUMNS = "100" if sys.platform == "win32" else "99"
runner = CliRunner(env={"COLUMNS": COLUMNS, "NO_COLOR": "1", "TERM": "dumb"})

_HORIZONTAL = re.compile(r"[─━┄┅┈┉╌╍═]")
_VERTICAL = re.compile(r"[│┃┆┇┊┋╎╏║]")
_JUNCTION = re.compile(r"[┌-╋╒-╿]")
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def normalise(text: str) -> str:
    text = _ANSI.sub("", text)
    text = _HORIZONTAL.sub("-", text)
    text = _VERTICAL.sub("|", text)
    text = _JUNCTION.sub("+", text)
    return "\n".join(line.rstrip() for line in text.splitlines()) + "\n"


def _check(name: str, output: str) -> None:
    path = GOLDEN / name
    text = normalise(output)
    if UPDATE_GOLDEN:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")
    assert text == path.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("name", "args"),
    [
        ("rules-list.txt", ["rules", "list"]),
        ("detect-auth-log.txt", ["detect", str(SAMPLES / "auth.log"), "--year", "2026"]),
        ("detect-access-log.txt", ["detect", str(SAMPLES / "access.log")]),
        ("incidents-takeover.txt", ["incidents", str(SAMPLES / "account-takeover.jsonl")]),
        ("simulate-list.txt", ["simulate", "--list"]),
        ("parse-app.txt", ["parse", str(SAMPLES / "app-security.jsonl"), "--limit", "5"]),
    ],
)
def test_table_output(name: str, args: list[str]) -> None:
    result = runner.invoke(app, args)
    assert result.exit_code in {0, 3}, result.output
    _check(name, result.stdout)


def test_demo_output() -> None:
    # A relative --out (the fixture runs each test in a temporary directory) keeps the printed
    # paths short and the same on every machine.
    result = runner.invoke(app, ["demo", "-o", "prohori-demo"])
    assert result.exit_code == 0, result.output
    _check("demo.txt", result.stdout)


def test_triage_summary(tmp_path: Path) -> None:
    args = ["triage", str(SAMPLES / "auth.log"), "--year", "2026", "-o", str(tmp_path), "-f", "md"]
    assert runner.invoke(app, args).exit_code == 3
    _check("triage-auth-log-summary.md", (tmp_path / "summary.md").read_text(encoding="utf-8"))
