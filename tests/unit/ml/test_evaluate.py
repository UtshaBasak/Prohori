"""SOC metrics: thresholds from validation, operating points, PR-AUC and the seed summary."""

import numpy as np
import pytest

from prohori.ml.evaluate import evaluate, operating_point, point_name, summarise, threshold_for_fpr


def test_threshold_allows_at_most_the_target_rate() -> None:
    benign = np.arange(1000, dtype=float) / 1000  # 0.000 .. 0.999
    threshold = threshold_for_fpr(benign, 0.01)
    assert (benign >= threshold).sum() == 10
    assert (benign >= threshold_for_fpr(benign, 0.001)).sum() == 1
    # Below one allowed false alert, the threshold sits just above every benign score.
    assert (benign >= threshold_for_fpr(benign, 0.0001)).sum() == 0


def test_ties_are_never_split() -> None:
    benign = np.array([0.9] * 5 + [0.1] * 95)
    threshold = threshold_for_fpr(benign, 0.03)  # three allowed, but five tie at 0.9
    assert (benign >= threshold).sum() == 0
    assert threshold > 0.9


@pytest.mark.parametrize("fpr", [0, 1, -0.1, 1.5])
def test_threshold_rejects_bad_rates(fpr: float) -> None:
    with pytest.raises(ValueError, match="fpr must be between"):
        threshold_for_fpr(np.array([0.1, 0.2]), fpr)


def test_threshold_needs_benign_flows() -> None:
    with pytest.raises(ValueError, match="no benign flows"):
        threshold_for_fpr(np.array([]), 0.01)


def test_operating_point_counts() -> None:
    labels = np.array([0, 0, 0, 0, 1, 1, 1, 1])
    scores = np.array([0.1, 0.2, 0.3, 0.9, 0.4, 0.8, 0.95, 0.99])
    categories = np.array(["Benign"] * 4 + ["DoS", "DoS", "Worms", "Worms"], dtype=object)
    point = operating_point(labels, scores, categories, 0.5)
    assert point["alerts"] == 4
    assert point["recall"] == 0.75
    assert point["precision"] == 0.75
    assert point["fpr"] == 0.25
    assert point["false_alerts_per_10k"] == 1250
    assert point["per_class_recall"] == {
        "DoS": {"flows": 2, "recall": 0.5},
        "Worms": {"flows": 2, "recall": 1.0},
    }
    silent = operating_point(labels, scores, categories, 2.0)
    assert silent["precision"] is None
    assert silent["recall"] == 0


def test_evaluate_reports_no_accuracy() -> None:
    labels = [0, 0, 1, 1]
    result = evaluate(labels, [0.1, 0.6, 0.4, 0.9], ["Benign", "Benign", "a", "b"], {"t": 0.5})
    assert result["pr_auc"] == pytest.approx(0.8333, abs=1e-4)
    assert result["roc_auc"] == 0.75
    assert result["prevalence"] == 0.5
    assert "accuracy" not in str(result)
    one_class = evaluate([0, 0], [0.1, 0.2], ["Benign", "Benign"], {"t": 0.5})
    assert one_class["pr_auc"] is None
    assert one_class["operating_points"]["t"]["recall"] is None


def test_point_names() -> None:
    assert point_name(0.01) == "fpr_0.01"
    assert point_name(0.001) == "fpr_0.001"


def test_summary_over_seeds_with_missing_keys() -> None:
    runs = [
        {"pr_auc": 0.8, "per_class": {"Worms": {"recall": 1.0}}, "skip": None, "flag": True},
        {"pr_auc": 0.6, "per_class": {}},
        {"pr_auc": 0.7, "per_class": {"Worms": {"recall": 0.5}}},
    ]
    summary = summarise(runs)
    assert summary["pr_auc"]["mean"] == pytest.approx(0.7)
    assert summary["pr_auc"]["std"] == pytest.approx(0.1)
    assert summary["pr_auc"]["n"] == 3
    assert summary["per_class"]["Worms"]["recall"] == {
        "mean": 0.75,
        "std": pytest.approx(0.3536, abs=1e-4),
        "n": 2,
    }
    assert "skip" not in summary
    assert "flag" not in summary
    assert summarise([{"x": 2}])["x"] == {"mean": 2.0, "std": 0.0, "n": 1}
