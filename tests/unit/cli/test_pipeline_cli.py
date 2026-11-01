"""``prohori pipeline replay`` and ``prohori pipeline tail``."""

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from prohori.cli import app
from prohori.cli.exit_codes import ExitCode
from prohori.simulate import simulate, write
from tests.unit.enrich.conftest import isolated_settings, no_network

__all__ = ["isolated_settings", "no_network"]  # autouse: no network, no real cache or keys

ROOT = Path(__file__).resolve().parents[3]
runner = CliRunner(env={"COLUMNS": "200", "NO_COLOR": "1"})
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _plain(output: str) -> str:
    """Usage errors are drawn in a box that may wrap and colour the text; compare words only."""
    text = _ANSI.sub("", output)
    text = re.sub(r"[\u2500-\u257f|+]", " ", text)  # box-drawing characters and ASCII borders
    return " ".join(text.split())


@pytest.fixture(scope="module")
def web_log(tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("sim")
    write(simulate("web-scanning", seed=1), out)
    return out / "web-scanning.log"


def _json(output: str) -> dict[str, object]:
    return json.loads(output[output.index("{") :])  # type: ignore[no-any-return]


def test_replay_twice_writes_each_row_once(web_log: Path, tmp_path: Path) -> None:
    state = tmp_path / "state"
    args = ["pipeline", "replay", str(web_log), "--state", str(state), "--times", "2"]
    result = runner.invoke(app, args)
    assert result.exit_code == 0, result.output
    assert "Pipeline stages" in result.stdout
    assert "events 1,690" in result.stdout
    again = runner.invoke(app, [*args[:3], "--state", str(state), "-f", "json", "--no-enrich"])
    assert again.exit_code == 0, again.output
    metrics = _json(again.stdout)
    assert metrics["tables"] == {"events": 1690, "alerts": 22, "incidents": 1, "dead_letters": 0}
    assert metrics["lines_replayed"] == 1690
    assert (state / "prohori.duckdb").is_file()


def test_replay_to_a_chosen_database(web_log: Path, tmp_path: Path) -> None:
    database = tmp_path / "out" / "x.duckdb"
    result = runner.invoke(
        app,
        [
            "pipeline",
            "replay",
            str(web_log),
            "--state",
            str(tmp_path / "s"),
            "--db",
            str(database),
            "--parser",
            "access_log",
        ],
    )
    assert result.exit_code == 0, result.output
    assert database.is_file()


def test_replay_of_a_file_no_parser_accepts_exits_1(tmp_path: Path) -> None:
    log = tmp_path / "bad.log"
    log.write_text("not an access log\nstill not\n", encoding="utf-8")
    result = runner.invoke(
        app,
        ["pipeline", "replay", str(log), "--state", str(tmp_path / "s"), "--parser", "access_log"],
    )
    assert result.exit_code == ExitCode.NO_EVENTS, result.output
    assert "dead_letters 2" in result.stdout


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (["missing.log"], "not found"),
        (["{log}", "--parser", "nope"], "unknown parser"),
        (["{log}", "--gap", "soon"], "--gap"),
        (["{log}", "--lateness", "soon"], "lateness"),
    ],
)
def test_replay_usage_errors(web_log: Path, tmp_path: Path, args: list[str], message: str) -> None:
    filled = [a.replace("{log}", str(web_log)) for a in args]
    result = runner.invoke(app, ["pipeline", "replay", *filled, "--state", str(tmp_path)])
    assert result.exit_code == ExitCode.USAGE
    assert message in _plain(result.output)


def test_tail_follows_a_file_until_stopped(web_log: Path, tmp_path: Path) -> None:
    live = tmp_path / "live.log"
    live.write_bytes(web_log.read_bytes())
    state = tmp_path / "state"
    args = ["pipeline", "tail", str(live), "--state", str(state), "--poll", "0", "-f", "json"]
    result = runner.invoke(app, [*args, "--max-rounds", "2"])
    assert result.exit_code == 0, result.output
    metrics = _json(result.stdout)
    assert metrics["lines_tailed"] == 1690
    assert metrics["tables"]["events"] == 1690  # type: ignore[index]
    assert list((state / "tail").glob("*.json"))
    # Run again: the checkpoint says everything was read, so nothing is tailed twice.
    again = runner.invoke(app, [*args, "--max-rounds", "1"])
    assert _json(again.stdout)["lines_tailed"] == 0


def test_tail_with_an_unknown_parser_is_a_usage_error(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["pipeline", "tail", str(tmp_path / "x.log"), "--state", str(tmp_path), "-p", "nope"],
    )
    assert result.exit_code == ExitCode.USAGE
    assert "unknown parser" in _plain(result.output)


def test_pipeline_without_the_extra(web_log: Path, tmp_path: Path) -> None:
    """Without duckdb, --help works and the commands explain how to install the extra."""
    code = f"""
import sys
sys.modules["duckdb"] = None
from typer.testing import CliRunner
from prohori.cli import app
runner = CliRunner()
print(runner.invoke(app, ["--help"]).exit_code)
result = runner.invoke(
    app, ["pipeline", "replay", {str(web_log)!r}, "--state", {str(tmp_path)!r}, "--no-enrich"]
)
print(result.exit_code)
print(result.stderr)
"""
    done = subprocess.run(  # noqa: S603 - fixed arguments
        [sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True, check=False
    )
    assert done.returncode == 0, done.stderr
    lines = done.stdout.splitlines()
    assert lines[:2] == ["0", "1"]
    assert "needs the 'pipeline' extra" in done.stdout
