"""Training on the fixture datasets: reproducible, frozen thresholds, saved models."""

import copy
import json
from pathlib import Path
from typing import Any

import numpy as np
import pytest
from sklearn.ensemble import IsolationForest

from prohori.ml import train
from prohori.ml.cleaning import LABEL, prepare_frames
from prohori.ml.datasets import load
from prohori.ml.models import ModelFileError, fit, load_model, save_model
from prohori.ml.registry import CICIDS2017, UNSW_NB15, get_dataset


def _without_timings(results: dict[str, Any]) -> dict[str, Any]:
    results = copy.deepcopy(results)
    del results["fit_seconds"]
    return results


def test_training_is_seed_reproducible(data_dir: Path) -> None:
    first = train.run(UNSW_NB15, data_dir, seeds=[0, 1])
    again = train.run(UNSW_NB15, data_dir, seeds=[0, 1])
    other = train.run(UNSW_NB15, data_dir, seeds=[2, 3])
    assert _without_timings(first) == _without_timings(again)
    assert _without_timings(first)["variants"] != _without_timings(other)["variants"]
    json.dumps(first)  # plain JSON


def test_results_document(data_dir: Path) -> None:
    results = train.run(CICIDS2017, data_dir, seeds=[0, 1], fprs=[0.1])
    assert results["format"] == "prohori.ml-eval/1"
    assert set(results["variants"]) == {"cleaned", "uncleaned"}
    cleaned = results["variants"]["cleaned"]
    assert [c["seed"] for c in cleaned["cleaning"]] == [0, 1]
    assert results["variants"]["uncleaned"]["cleaning"][0]["duplicates_removed"] == 0
    for name in ("hgb", "iforest"):
        entry = cleaned["models"][name]
        assert len(entry["runs"]) == 2
        run = entry["runs"][0]
        assert set(run) == {"seed", "thresholds", "validation", "test"}
        point = run["test"]["operating_points"]["fpr_0.1"]
        assert {"recall", "fpr", "false_alerts_per_10k", "per_class_recall"} <= set(point)
        assert "per_class_recall" not in run["validation"]["operating_points"]["fpr_0.1"]
        assert entry["summary"]["pr_auc"]["n"] == 2
    assert "accuracy" not in json.dumps(results)
    assert "cleaned-no-suspect" in train.variants(UNSW_NB15)


def test_thresholds_come_from_validation_only(data_dir: Path) -> None:
    frames = load(UNSW_NB15, data_dir).frames
    prepared = prepare_frames(UNSW_NB15, frames, seed=0)
    result, _, _ = train.run_model(prepared, "hgb", 0, [0.1])
    # Changing the test split changes the test metrics, never the thresholds.
    prepared.test["dur"] = prepared.test["dur"] * 1000
    prepared.test[LABEL] = 1 - prepared.test[LABEL]
    changed, _, _ = train.run_model(prepared, "hgb", 0, [0.1])
    assert changed["thresholds"] == result["thresholds"]
    assert changed["validation"] == result["validation"]
    assert changed["test"] != result["test"]


def test_isolation_forest_sees_benign_training_flows_only(
    data_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared = prepare_frames(UNSW_NB15, load(UNSW_NB15, data_dir).frames, seed=0)
    seen: list[int] = []
    original = IsolationForest.fit

    def spy(self: Any, x: Any, *args: Any, **kwargs: Any) -> Any:
        seen.append(len(x))
        return original(self, x, *args, **kwargs)

    monkeypatch.setattr(IsolationForest, "fit", spy)
    fit("iforest", prepared.x("train"), prepared.y("train"), seed=0, categorical=[])
    assert seen == [int((prepared.y("train") == 0).sum())]


def test_unknown_names_are_rejected(data_dir: Path) -> None:
    prepared = prepare_frames(UNSW_NB15, load(UNSW_NB15, data_dir).frames, seed=0)
    with pytest.raises(ValueError, match="unknown model 'svm'"):
        fit("svm", prepared.x("train"), prepared.y("train"), seed=0, categorical=[])
    with pytest.raises(ValueError, match="unknown variant"):
        train.run(CICIDS2017, data_dir, seeds=[0], variant_names=["cleaned-no-suspect"])


def test_saved_models_round_trip(data_dir: Path, tmp_path: Path) -> None:
    out = tmp_path / "models"
    train.run(UNSW_NB15, data_dir, seeds=[0], models=["hgb"], models_dir=out)
    path = out / "unsw-nb15" / "hgb-seed0.joblib"
    bundle, meta = load_model(path)
    assert meta["model"] == "hgb"
    assert meta["features"] == bundle["features"]
    assert "pickle" in meta["warning"]
    # Only the cleaned variant is saved; the saved model scores like the trained one.
    assert sorted(p.name for p in path.parent.iterdir()) == ["hgb-seed0.joblib", "hgb-seed0.json"]
    prepared = prepare_frames(UNSW_NB15, load(UNSW_NB15, data_dir).frames, seed=0)
    x = bundle["preprocessor"].transform(prepared.test[bundle["features"]]).astype("float32")
    scores = bundle["detector"].scores(x)
    assert scores.shape == (len(prepared.test),)
    assert np.all((scores >= 0) & (scores <= 1))


def test_loading_refuses_unverified_files(tmp_path: Path) -> None:
    path = save_model(tmp_path / "m.joblib", {"x": 1}, {"model": "test"})
    assert load_model(path)[0] == {"x": 1}
    path.write_bytes(path.read_bytes() + b"\0")
    with pytest.raises(ModelFileError, match="does not match"):
        load_model(path)
    path.with_suffix(".json").unlink()
    with pytest.raises(ModelFileError, match=r"no m\.json"):
        load_model(path)


def test_command_line(data_dir: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "results.json"
    args = ["--dataset", "unsw-nb15", "--seeds", "0", "--data-dir", str(data_dir)]
    args += ["--out", str(out), "--models-dir", str(tmp_path / "m"), "--models", "iforest"]
    assert train.main(args) == 0
    assert json.loads(out.read_text(encoding="utf-8"))["seeds"] == [0]
    assert (tmp_path / "m" / "unsw-nb15" / "iforest-seed0.joblib").is_file()
    assert "pickle" in capsys.readouterr().err
    assert train.main([*args, "--no-save", "--variants", "nope"]) == 1
    assert "unknown variant" in capsys.readouterr().err
    assert train.main(["--dataset", "unsw-nb15", "--data-dir", str(tmp_path), "--no-save"]) == 1
    assert "download" in capsys.readouterr().err.lower()
    with pytest.raises(SystemExit):
        train.main(["--dataset", "unsw-nb15", "--seeds", "1", "1"])


def test_tables_are_generated_from_results(data_dir: Path, tmp_path: Path) -> None:
    from scripts import generate_results_table as tables

    results = train.run(UNSW_NB15, data_dir, seeds=[0, 1])
    card = tables.render_ml(results)
    assert "| Gradient boosting (supervised) |" in card
    assert "Test FPR (1 % val.)" in card
    assert "Cleaned, without the TTL columns" in card
    assert "| Exploits |" in card
    assert " ± " in card
    summary = tables.render_ml_summary([results])
    assert summary.count("| unsw-nb15 |") == 2
    assert "0.1 % false-positive rate" in summary
    assert tables.render_ml_summary([]) == "No model results yet."
    (tmp_path / "ml_unsw-nb15.json").write_text(json.dumps(results), encoding="utf-8")
    assert [r["dataset"] for r in tables.ml_results(tmp_path)] == ["unsw-nb15"]


def test_committed_model_results_are_complete() -> None:
    root = Path(__file__).resolve().parents[3]
    for name in ("unsw-nb15", "cicids2017"):
        results = json.loads((root / "results" / f"ml_{name}.json").read_text(encoding="utf-8"))
        assert results["seeds"] == [0, 1, 2]
        assert results["sample"] is None
        assert set(results["variants"]) == set(train.variants(get_dataset(name)))
        for variant in results["variants"].values():
            for entry in variant["models"].values():
                assert [r["seed"] for r in entry["runs"]] == [0, 1, 2]
