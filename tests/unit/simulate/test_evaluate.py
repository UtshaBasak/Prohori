# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
# Copyright (c) 2026 Utsha Basak
"""Rule evaluation: scoring semantics, the golden seed-1 results and the documentation table."""

import json
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from prohori.parsers import ParseStats
from prohori.rules import CompiledRule, builtin_rules_dir, load_rules
from prohori.schema import Alert, Severity
from prohori.simulate import ADDRESS_MODEL, VARIANTS, simulate
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
    # The simulator writes no network sensor logs, so the network rules are not evaluated.
    assert results["not_evaluated"] == [
        "PRH-ABUSE-001",
        "PRH-AUTH-004",
        "PRH-AUTHZ-001",
        "PRH-IDS-001",
        "PRH-IDS-002",
        "PRH-IDS-003",
        "PRH-NET-001",
        "PRH-NET-002",
        "PRH-NET-003",
    ]


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


def test_generated_tables_use_the_docs_table_style() -> None:
    block = "| A | B |\n|---|--:|\n| 1 | 2 |\n|:-|"
    assert generate_results_table.compact(block) == "| A | B |\n| --- | --: |\n| 1 | 2 |\n| :- |"


def test_baselines_are_frozen_once_and_then_kept(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "eval.json"
    freeze = ["--seeds", "1", "--out", str(out), "--freeze-baseline"]
    assert evaluate_rules.main([*freeze, "old"]) == 0
    frozen = json.loads(out.read_text(encoding="utf-8"))["baselines"]["old"]
    assert frozen["label"] == "old"
    assert frozen["addresses"] == ADDRESS_MODEL
    assert set(frozen["variants"]) == set(VARIANTS)
    assert evaluate_rules.main([*freeze, "old"]) == 1  # never replaced
    assert "frozen already" in capsys.readouterr().err
    assert evaluate_rules.main(["--seeds", "1", "--out", str(out)]) == 0
    document = json.loads(out.read_text(encoding="utf-8"))
    assert document["baselines"] == {"old": frozen}
    assert document["addresses"] == ADDRESS_MODEL

    # A baseline frozen on another address model is never extended: freeze a new label.
    document["baselines"]["old"]["addresses"] = ADDRESS_MODEL - 1
    del document["baselines"]["old"]["variants"]["heldout2"]
    out.write_text(json.dumps(document), encoding="utf-8")
    assert evaluate_rules.main([*freeze, "old"]) == 1
    assert "freeze a new label instead" in capsys.readouterr().err
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    for name in ("brute-force.yml", "web-scanning.yml"):
        (rules_dir / name).write_bytes((builtin_rules_dir() / name).read_bytes())
    assert evaluate_rules.main([*freeze, "new", "--rules", str(rules_dir)]) == 0
    baselines = json.loads(out.read_text(encoding="utf-8"))["baselines"]
    assert list(baselines) == ["old", "new"]
    assert baselines["new"]["rules"] == ["PRH-AUTH-001", "PRH-WEB-001"]
    assert evaluate_rules.main([*freeze, "new"]) == 1  # the same label with other rules
    assert "another rule set" in capsys.readouterr().err


def test_committed_baselines_keep_the_first_simulator() -> None:
    results = json.loads((ROOT / "results" / "rules_eval.json").read_text(encoding="utf-8"))
    baselines = results["baselines"]
    first = baselines["1.0 rules (addresses 1)"]
    assert (first["addresses"], len(first["rules"])) == (1, 15)
    held = first["variants"]["heldout"]["scenarios"]["credential-stuffing"]
    assert held["attacks_detected"] == 0  # what the step-28b rules set out to fix
    step_28b = baselines["1.1 rules, step 28b (addresses 1)"]
    assert (step_28b["addresses"], len(step_28b["rules"])) == (1, 21)
    spraying = step_28b["variants"]["heldout2"]["scenarios"]["password-spraying"]
    assert spraying["attacks_detected"] == 0  # what step 28c set out to measure fairly
