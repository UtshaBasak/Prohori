"""``prohori score`` and prohori.ml.score, with models trained on the fixture datasets."""

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from prohori.cli import app
from prohori.cli.exit_codes import ExitCode
from prohori.ml import train
from prohori.ml.registry import CICIDS2017, UNSW_NB15
from prohori.ml.score import ScoreInputError, resolve_model, score_file

ROOT = Path(__file__).resolve().parents[3]
FLOWS = ROOT / "tests" / "fixtures" / "flows.csv"
runner = CliRunner(env={"COLUMNS": "200", "NO_COLOR": "1"})
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


@pytest.fixture(scope="module")
def models_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Fixture models: no model file is ever committed."""
    from tests.unit.ml.conftest import FIXTURES

    out = tmp_path_factory.mktemp("models")
    for dataset in (CICIDS2017, UNSW_NB15):
        train.run(
            dataset,
            FIXTURES,
            seeds=[0],
            variant_names=["cleaned"],
            models_dir=out,
            use_cache=False,
        )
    return out


def test_definition_of_done_example(models_dir: Path) -> None:
    args = ["score", str(FLOWS), "--model", "cicids2017/iforest-seed0"]
    result = runner.invoke(app, [*args, "--models-dir", str(models_dir), "--fpr", "0.01"])
    out = _ANSI.sub("", result.stdout)
    assert result.exit_code == ExitCode.ALERTS_FOUND, out + result.stderr
    assert "Flagged flows" in out
    assert re.search(r"25 flows scored with cicids2017/iforest-seed0; \d+ flagged", out)
    assert "lab dataset" in out
    assert "pickles" in result.stderr


def test_json_output_and_exit_zero(models_dir: Path) -> None:
    args = ["score", str(FLOWS), "-m", "cicids2017/iforest-seed0", "--fpr", "0.01"]
    args += ["--models-dir", str(models_dir), "-f", "json", "--top", "0", "--exit-zero"]
    result = runner.invoke(app, args)
    assert result.exit_code == 0
    report = json.loads(result.stdout)
    assert report["flows"] == 25
    assert report["flagged"] == len(report["flagged_flows"]) > 0
    first = report["flagged_flows"][0]
    assert {"row", "score", "src_ip", "dst_port", "timestamp"} <= set(first)
    scores = [f["score"] for f in report["flagged_flows"]]
    assert scores == sorted(scores, reverse=True)
    assert report["threshold"]["name"] == "fpr_0.01"


def test_top_keeps_the_highest_scores(models_dir: Path) -> None:
    path = models_dir / "cicids2017" / "iforest-seed0.joblib"
    every = score_file(FLOWS, path, fpr=0.01, top=0)
    three = score_file(FLOWS, path, fpr=0.01, top=3)
    assert three.flagged == every.flagged
    assert [f.row for f in three.top] == [f.row for f in every.top[:3]]
    assert every.non_numeric_values == 0  # "Infinity" is a number, empty is missing
    # The same bytes through standard input give the same result.
    again = score_file(FLOWS.read_bytes(), path, fpr=0.01, top=0)
    assert [(f.row, f.score) for f in again.top] == [(f.row, f.score) for f in every.top]


def test_default_threshold_is_the_strictest(models_dir: Path) -> None:
    path = models_dir / "cicids2017" / "hgb-seed0.joblib"
    assert score_file(FLOWS, path).threshold_name == "fpr_0.001"
    with pytest.raises(ScoreInputError, match=r"no threshold for a 0\.05"):
        score_file(FLOWS, path, fpr=0.05)


def test_wrong_layout_is_explained(models_dir: Path) -> None:
    path = models_dir / "unsw-nb15" / "hgb-seed0.joblib"
    with pytest.raises(ScoreInputError, match=r"lacks \d+ column\(s\) the model needs: dur, "):
        score_file(FLOWS, path)
    args = ["score", str(FLOWS), "-m", "unsw-nb15/hgb-seed0", "--models-dir", str(models_dir)]
    result = runner.invoke(app, args)
    assert result.exit_code == 1
    assert "the model needs" in result.stderr


def test_unreadable_input(models_dir: Path, tmp_path: Path) -> None:
    path = models_dir / "cicids2017" / "hgb-seed0.joblib"
    empty = tmp_path / "empty.csv"
    empty.write_text("", encoding="utf-8")
    with pytest.raises(ScoreInputError, match="cannot read"):
        score_file(empty, path)
    duplicated = tmp_path / "dup.csv"
    header = FLOWS.read_text(encoding="utf-8").splitlines()[0]
    duplicated.write_text(header + ",src ip\n", encoding="utf-8")
    with pytest.raises(ScoreInputError, match="duplicated"):
        score_file(duplicated, path)
    header_only = tmp_path / "header.csv"
    header_only.write_text(header + "\n", encoding="utf-8")
    assert score_file(header_only, path).flows == 0


def test_model_names_and_paths(models_dir: Path) -> None:
    path = models_dir / "cicids2017" / "hgb-seed0.joblib"
    assert resolve_model(str(path), models_dir) == path
    assert resolve_model("cicids2017/hgb-seed0", models_dir) == path
    with pytest.raises(FileNotFoundError, match="available: cicids2017/hgb-seed0"):
        resolve_model("nope", models_dir)
    with pytest.raises(FileNotFoundError, match="train one with"):
        resolve_model("nope", models_dir / "missing")
    result = runner.invoke(app, ["score", "missing.csv", "-m", str(path)])
    assert result.exit_code == ExitCode.USAGE
    tampered = models_dir / "cicids2017" / "hgb-seed1.joblib"
    tampered.write_bytes(path.read_bytes() + b"\0")
    tampered.with_suffix(".json").write_text(
        path.with_suffix(".json").read_text(encoding="utf-8"), encoding="utf-8"
    )
    result = runner.invoke(app, ["score", str(FLOWS), "-m", str(tampered)])
    assert result.exit_code == 1
    assert "refusing to load" in result.stderr


def test_score_without_the_ml_extra() -> None:
    code = """
import sys
for name in ("pandas", "sklearn", "pyarrow", "numpy", "joblib"):
    sys.modules[name] = None
from typer.testing import CliRunner
from prohori.cli import app
result = CliRunner().invoke(app, ["score", "flows.csv", "--model", "x"])
print(result.exit_code)
print(result.stderr)
"""
    done = subprocess.run(  # noqa: S603 - fixed arguments
        [sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True, check=False
    )
    assert done.returncode == 0, done.stderr
    assert done.stdout.splitlines()[0] == "1"
    assert "needs the 'ml' extra: pip install 'prohori[ml]'" in done.stdout


def test_standard_input(models_dir: Path) -> None:
    args = ["score", "-", "-m", "cicids2017/iforest-seed0", "--models-dir", str(models_dir)]
    result = runner.invoke(app, [*args, "-f", "json", "--fpr", "0.01"], input=FLOWS.read_bytes())
    assert result.exit_code == ExitCode.ALERTS_FOUND
    assert json.loads(result.stdout)["flows"] == 25
