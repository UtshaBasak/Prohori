"""``prohori simulate``: listing, writing, parameters and errors."""

import json
import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from prohori.cli import app
from prohori.cli.exit_codes import ExitCode

runner = CliRunner(env={"COLUMNS": "200", "NO_COLOR": "1"})
_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_BOX = re.compile(r"[─-╿|+]")


def _plain(output: str) -> str:
    return " ".join(_BOX.sub(" ", _ANSI.sub("", output)).split())


def test_list() -> None:
    result = runner.invoke(app, ["simulate", "--list"])
    assert result.exit_code == 0
    for name in ("ssh-bruteforce", "account-takeover", "admin-misuse", "injection"):
        assert name in result.stdout
    assert "rate=20 / 1.5" in result.stdout


def test_definition_of_done_example(tmp_path: Path) -> None:
    out = tmp_path / "out"
    result = runner.invoke(app, ["simulate", "ssh-bruteforce", "--seed", "1", "--out", str(out)])
    assert result.exit_code == 0, result.output
    assert "parse with --parser auth_log --year 2026" in result.stdout
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["seed"] == 1
    detect = runner.invoke(
        app,
        ["detect", str(out / "ssh-bruteforce.log"), "--parser", "auth_log", "--year", "2026"],
    )
    assert detect.exit_code == ExitCode.ALERTS_FOUND
    assert "PRH-AUTH-001" in detect.stdout


def test_same_seed_same_bytes(tmp_path: Path) -> None:
    for name in ("a", "b"):
        args = ["simulate", "web-scanning", "--seed", "9", "--out", str(tmp_path / name)]
        assert runner.invoke(app, args).exit_code == 0
    for file in ("web-scanning.log", "web-scanning.labels.jsonl", "manifest.json"):
        assert (tmp_path / "a" / file).read_bytes() == (tmp_path / "b" / file).read_bytes()


def test_variant_and_settings(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "simulate", "account-takeover", "--out", str(tmp_path), "--variant", "heldout",
            "--set", "attempts=4", "--set", "start=2026-03-01T00:00:00Z",
        ],
    )  # fmt: skip
    assert result.exit_code == 0, result.output
    manifest = json.loads((tmp_path / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["variant"] == "heldout"
    assert manifest["params"]["attempts"] == 4
    assert manifest["start"] == "2026-03-01T00:00:00Z"


@pytest.mark.parametrize(
    ("args", "message"),
    [
        ([], "give a SCENARIO and --out DIR"),
        (["nope", "--out", "x"], "unknown scenario 'nope'"),
        (["injection", "--out", "x", "--variant", "sneaky"], "unknown variant"),
        (["injection", "--out", "x", "--set", "rate"], "expected NAME=VALUE"),
        (["injection", "--out", "x", "--set", "sources=2"], "has no parameter 'sources'"),
        (["injection", "--out", "x", "--set", "rate=0"], "between 0.1 and 600"),
    ],
)
def test_errors(args: list[str], message: str) -> None:
    result = runner.invoke(app, ["simulate", *args])
    assert result.exit_code == ExitCode.USAGE
    assert message in _plain(result.output)
