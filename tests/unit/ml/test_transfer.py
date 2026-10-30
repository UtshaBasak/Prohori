"""The cross-dataset test: the common-feature mapping and both directions on the fixtures."""

import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from prohori.ml import transfer
from prohori.ml.cleaning import CATEGORY, LABEL, prepare
from prohori.ml.registry import UNSW_NB15


def test_unsw_mapping() -> None:
    frame = pd.DataFrame(
        {
            "dur": [0.5, 0.0],
            "spkts": [2.0, 1.0],
            "dpkts": [2.0, 0.0],
            "sbytes": [146.0, 60.0],
            "dbytes": [178.0, 0.0],
            "sinpkt": [9.0, 0.0],
            "dinpkt": [3.0, 0.0],
            "proto": ["udp", "ospf"],
            CATEGORY: ["Benign", "Generic"],
            LABEL: [0, 1],
        }
    )
    common = transfer.to_common(frame, "unsw-nb15")
    assert list(common.columns) == [*transfer.COMMON_FEATURES, CATEGORY, LABEL]
    first = common.iloc[0]
    assert first["fwd_mean_bytes"] == 73
    assert first["fwd_iat_mean_s"] == pytest.approx(0.009)
    assert first["packets_per_s"] == 8
    assert first["bytes_per_s"] == (146 + 178) / 0.5
    assert first["protocol"] == 17
    second = common.iloc[1]
    assert second["protocol"] == -1
    assert np.isnan(second["packets_per_s"])  # zero duration
    assert np.isnan(second["bwd_mean_bytes"])  # no backward packets


def test_cicids_mapping_counts_bytes_on_the_wire() -> None:
    frame = pd.DataFrame(
        {
            "flow_duration": [1_000_000.0],
            "total_fwd_packet": [2.0],
            "total_bwd_packets": [2.0],
            "total_length_of_fwd_packet": [70.0],
            "total_length_of_bwd_packet": [182.0],
            "fwd_header_length": [16.0],
            "bwd_header_length": [16.0],
            "fwd_iat_mean": [3.0],
            "bwd_iat_mean": [0.0],
            "protocol": [0.0],
            CATEGORY: ["Benign"],
            LABEL: [0],
        }
    )
    row = transfer.to_common(frame, "cicids2017").iloc[0]
    assert row["duration_s"] == 1
    assert row["fwd_bytes"] == 70 + 16 + 2 * 34  # a two-packet DNS query: 154 bytes
    assert row["fwd_iat_mean_s"] == pytest.approx(3e-6)
    assert row["protocol"] == -1
    with pytest.raises(ValueError, match="no common-feature mapping"):
        transfer.to_common(frame, "kdd99")


def test_common_splits_have_no_overlap(data_dir: Path) -> None:
    prepared = prepare(UNSW_NB15, data_dir)
    splits = {s: prepared.split(s) for s in transfer.SPLITS}
    mapped, report = transfer.common_splits(splits, "unsw-nb15", 0)
    keys = {
        s: set(pd.util.hash_pandas_object(mapped[s][list(transfer.COMMON_FEATURES)], index=False))
        for s in transfer.SPLITS
    }
    assert not keys["train"] & keys["test"]
    assert not keys["train"] & keys["validation"]
    assert not keys["validation"] & keys["test"]
    assert sum(report.rows.values()) <= sum(len(f) for f in splits.values())


def test_both_directions_are_reproducible(data_dir: Path) -> None:
    first = transfer.run(data_dir, seeds=[0, 1], fprs=[0.1])
    again = transfer.run(data_dir, seeds=[0, 1], fprs=[0.1])
    assert first == again
    assert set(first["directions"]) == {"unsw-nb15->cicids2017", "cicids2017->unsw-nb15"}
    direction = first["directions"]["unsw-nb15->cicids2017"]
    run = direction["models"]["hgb"]["runs"][0]
    assert set(run) == {"seed", "thresholds", "in_dataset", "cross_dataset"}
    # The cross-dataset score is on the target's test split, with the target's classes.
    cicids_test = first["cleaning"]["cicids2017"][0]["rows"]["test"]
    assert run["cross_dataset"]["flows"] == cicids_test
    assert "DDoS" in run["cross_dataset"]["operating_points"]["fpr_0.1"]["per_class_recall"]
    assert direction["models"]["hgb"]["summary"]["cross_dataset"]["pr_auc"]["n"] == 2
    json.dumps(first)


def test_command_line(data_dir: Path, tmp_path: Path) -> None:
    out = tmp_path / "cross.json"
    args = ["--seeds", "0", "--models", "iforest", "--data-dir", str(data_dir), "--out", str(out)]
    assert transfer.main([*args, "--no-cache"]) == 0
    results = json.loads(out.read_text(encoding="utf-8"))
    assert results["features"] == list(transfer.COMMON_FEATURES)
    assert not (data_dir / "processed").exists()
    assert transfer.main(["--data-dir", str(tmp_path / "none"), "--out", str(out)]) == 1
    with pytest.raises(SystemExit):
        transfer.main(["--seeds", "1", "1"])


def test_committed_cross_results() -> None:
    root = Path(__file__).resolve().parents[3]
    results = json.loads((root / "results" / "ml_cross.json").read_text(encoding="utf-8"))
    assert results["seeds"] == [0, 1, 2]
    assert results["sample"] is None
    for direction in results["directions"].values():
        for entry in direction["models"].values():
            assert [r["seed"] for r in entry["runs"]] == [0, 1, 2]


def test_cross_tables(data_dir: Path) -> None:
    from scripts import generate_results_table as tables

    results = transfer.run(data_dir, seeds=[0, 1], fprs=[0.1, 0.05])
    card = tables.render_cross(results, [])
    assert "| unsw-nb15 → cicids2017 | Gradient boosting (supervised) | - |" in card
    assert "Cross-dataset FPR" in card
    assert "Recall per attack class in the target, cicids2017 → unsw-nb15" in card
    summary = tables.render_cross_summary(results)
    assert summary.count(" → ") == 3  # the header and one row a direction
    assert "Chance level" in summary
    assert tables.render_cross_summary(None) == "No cross-dataset results yet."
