"""The rules-versus-anomaly evaluation and its committed results."""

import json
from pathlib import Path

import pytest

from prohori.ml import anomaly, logeval
from prohori.rules import CompiledRule, builtin_rules_dir, load_rules
from prohori.simulate import simulate

ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture(scope="module")
def rules() -> list[CompiledRule]:
    return [r.rule for r in load_rules([builtin_rules_dir()]) if r.rule is not None]


def test_small_evaluation(rules: list[CompiledRule]) -> None:
    results = logeval.evaluate(rules, seeds=[1], scenarios=["web-scanning", "token-reuse"])
    assert results["format"] == "prohori.log-anomaly-eval/1"
    default = results["variants"]["default"]
    assert default["runs"] == 2
    assert set(default["detectors"]) == {"rules", "zscore", "threshold", "iforest"}
    zscore = default["detectors"]["zscore"]
    assert zscore["caught_by_scenario"]["web-scanning"] == 1
    comparison = default["versus_rules"]["zscore"]
    assert comparison["caught_by_either"] == (
        comparison["caught_by_rules"]
        + comparison["caught_by_model"]
        - (comparison["caught_by_model"] - comparison["caught_by_model_only"])
    )
    selection = results["cutoff_selection_on_default"]
    assert set(selection) == {"zscore", "iforest"}
    assert results["cutoffs"] == {
        "zscore": anomaly.Z_THRESHOLD,
        "iforest": anomaly.IFOREST_THRESHOLD,
    }


def test_credit_uses_the_majority_rule(rules: list[CompiledRule]) -> None:
    run = logeval.prepare(simulate("web-scanning", seed=1), rules)
    tp, caught = logeval.credit(run, run.detection.alerts)
    assert tp > 0
    assert caught == {a.id for a in run.simulation.attacks}
    labels = logeval.window_labels(run)
    assert len(labels) == len(run.windows)
    assert 0 < sum(labels) < len(labels)


def test_committed_results_match_the_frozen_cutoffs() -> None:
    results = json.loads((ROOT / "results" / "ml_logs.json").read_text(encoding="utf-8"))
    assert results["seeds"] == [1, 2, 3, 4, 5]
    assert results["cutoffs"] == {
        "zscore": anomaly.Z_THRESHOLD,
        "iforest": anomaly.IFOREST_THRESHOLD,
    }
    # The frozen cut-offs are the ones chosen on the default variants.
    selection = results["cutoff_selection_on_default"]
    assert selection["zscore"]["chosen"] == anomaly.Z_THRESHOLD
    assert selection["iforest"]["chosen"] == anomaly.IFOREST_THRESHOLD
    assert set(results["variants"]) == {"default", "heldout"}


def test_command_line(tmp_path: Path) -> None:
    out = tmp_path / "logs.json"
    assert logeval.main(["--seeds", "1", "--out", str(out)]) == 0
    assert json.loads(out.read_text(encoding="utf-8"))["seeds"] == [1]
    with pytest.raises(SystemExit):
        logeval.main(["--seeds", "0"])


def test_tables_are_generated(rules: list[CompiledRule]) -> None:
    from scripts import generate_results_table as tables

    results = logeval.evaluate(rules, seeds=[1], scenarios=["web-scanning", "ssh-bruteforce"])
    page = tables.render_anomaly(results)
    assert "| Robust z-score |" in page
    assert "| web-scanning | 1/1 |" in page
    assert page.count("**") == 4  # one chosen cut-off per tunable detector
    summary = tables.render_anomaly_summary(results)
    assert summary.splitlines()[2].startswith("| Detection rules (any rule) |")
    assert tables.render_anomaly_summary(None) == "No anomaly results yet."
