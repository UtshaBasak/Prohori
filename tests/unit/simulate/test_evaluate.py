"""Rule evaluation: scoring semantics, the golden seed-1 results and the documentation table."""

import json
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from prohori.parsers import ParseStats
from prohori.rules import CompiledRule, builtin_rules_dir, load_rules
from prohori.schema import Alert, Severity
from prohori.simulate import simulate
from prohori.simulate.evaluate import Detection, RuleScore, ScenarioScore, evaluate, score_run
from scripts import evaluate_rules, generate_results_table

ROOT = Path(__file__).resolve().parents[3]
GOLDEN = ROOT / "tests" / "golden" / "simulate" / "eval-seed1.json"
UPDATE_GOLDEN = os.environ.get("PROHORI_UPDATE_GOLDEN") == "1"
T = datetime(2026, 10, 24, tzinfo=UTC)


@pytest.fixture(scope="module")
def rules() -> list[CompiledRule]:
    return [r.rule for r in load_rules([builtin_rules_dir()]) if r.rule is not None]


def test_seed_one_matches_golden_results(rules: list[CompiledRule], tmp_path: Path) -> None:
    """The script's output for one seed; catches drift in scenarios, rules or scoring."""
    out = tmp_path / "eval.json"
    assert evaluate_rules.main(["--seeds", "1", "--out", str(out)]) == 0
    results = json.loads(out.read_text(encoding="utf-8"))
    if UPDATE_GOLDEN:
        GOLDEN.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8", newline="\n")
    assert results == json.loads(GOLDEN.read_text(encoding="utf-8"))
    assert results["parse_errors"] == 0
    assert results["not_evaluated"] == ["PRH-ABUSE-001", "PRH-AUTH-004", "PRH-AUTHZ-001"]


def test_committed_results_and_table_are_consistent() -> None:
    results = json.loads((ROOT / "results" / "rules_eval.json").read_text(encoding="utf-8"))
    assert results["seeds"] == [1, 2, 3, 4, 5]
    assert generate_results_table.main(["--check"]) == 0


def test_table_marks_unevaluated_rules() -> None:
    results = json.loads((ROOT / "results" / "rules_eval.json").read_text(encoding="utf-8"))
    table = generate_results_table.render(results)
    assert (
        "| PRH-AUTH-004 | not evaluated | not evaluated | not evaluated | not evaluated |" in table
    )
    assert "0%" not in table.split("PRH-AUTH-004")[1].splitlines()[0]


def _alert(rule: str, event_ids: list[str]) -> Alert:
    return Alert(
        detector_id=rule,
        title=rule,
        severity=Severity.HIGH,
        event_ids=tuple(event_ids),
        first_seen=T,
        last_seen=T,
    )


def test_scoring_semantics() -> None:
    simulation = simulate("token-reuse", seed=1)
    labels = [attack for _, attack in simulation.lines]
    attack_lines = [n for n, a in enumerate(labels, start=1) if a]
    benign_lines = [n for n, a in enumerate(labels, start=1) if not a]
    line_of = {f"e{n}": n for n in range(1, len(labels) + 1)}
    alerts = [
        _alert("PRH-SESS-001", [f"e{attack_lines[0]}"]),  # true positive
        _alert("PRH-SESS-001", [f"e{attack_lines[1]}", f"e{benign_lines[0]}"]),  # half: TP
        _alert("PRH-ACCT-001", [f"e{benign_lines[1]}", f"e{benign_lines[2]}"]),  # FP
        _alert(
            "PRH-ACCT-001", [f"e{attack_lines[2]}", f"e{benign_lines[3]}", f"e{benign_lines[4]}"]
        ),
        _alert("PRH-WEB-001", ["unknown-event"]),  # no known events: FP
    ]
    rules: dict[str, RuleScore] = {}
    scenario = ScenarioScore()
    score_run(simulation, Detection(alerts, line_of, ParseStats()), rules, scenario)
    assert (rules["PRH-SESS-001"].tp, rules["PRH-SESS-001"].fp) == (2, 0)
    assert (rules["PRH-SESS-001"].expected, rules["PRH-SESS-001"].detected) == (1, 1)
    assert (rules["PRH-ACCT-001"].tp, rules["PRH-ACCT-001"].fp) == (0, 2)
    assert rules["PRH-ACCT-001"].as_dict()["recall"] is None  # not expected: not evaluated
    assert rules["PRH-ACCT-001"].as_dict()["precision"] == 0.0
    assert rules["PRH-WEB-001"].fp == 1
    assert scenario.as_dict()["attacks_detected"] == 1
    assert scenario.as_dict()["false_positives_by_rule"] == {"PRH-ACCT-001": 2, "PRH-WEB-001": 1}


def test_a_missed_attack_counts_against_recall() -> None:
    simulation = simulate("token-reuse", seed=1)
    rules: dict[str, RuleScore] = {}
    scenario = ScenarioScore()
    score_run(simulation, Detection([], {}, ParseStats()), rules, scenario)
    assert rules["PRH-SESS-001"].as_dict()["recall"] == 0.0
    assert rules["PRH-SESS-001"].as_dict()["precision"] is None
    assert scenario.as_dict()["missed_by_rule"] == {"PRH-SESS-001": 1}


def test_evaluate_a_subset(rules: list[CompiledRule]) -> None:
    results = evaluate(rules, seeds=[2], scenarios=["injection"])
    default = results["variants"]["default"]  # type: ignore[index]
    assert default["rules"]["PRH-WEB-002"]["recall"] == 1.0
    assert results["scenarios"] == ["injection"]


def test_script_rejects_bad_seed_counts(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        evaluate_rules.main(["--seeds", "0"])
    assert "--seeds must be between 1 and 100" in capsys.readouterr().err
