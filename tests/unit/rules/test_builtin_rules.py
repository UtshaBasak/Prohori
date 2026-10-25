"""Checks every built-in rule ships complete: fixtures, a runbook and verified ATT&CK tags."""

import re
from pathlib import Path

import pytest
import yaml

from prohori.rules import builtin_rules_dir, builtin_runbook_path, load_rules
from prohori.rules.attack import TACTICS, TECHNIQUES, is_verified
from prohori.rules.loader import RuleReport, discover
from prohori.rules.testing import fixture_file_for, run_rule_tests

RUNBOOK_HEADINGS = [
    "## What it means",
    "## Triage",
    "## Recommended actions",
    "## False positives",
    "## ATT&CK",
]

EXPECTED_IDS = {
    "PRH-AUTH-001",
    "PRH-AUTH-002",
    "PRH-AUTH-003",
    "PRH-AUTH-004",
    "PRH-SESS-001",
    "PRH-ACCT-001",
    "PRH-AUTHZ-001",
}

REPORTS = load_rules([builtin_rules_dir()])


def _id(report: RuleReport) -> str:
    return report.file.name


def test_expected_rules_are_shipped() -> None:
    assert {r.rule.meta.id for r in REPORTS if r.rule} >= EXPECTED_IDS


@pytest.mark.parametrize("report", REPORTS, ids=_id)
def test_rule_is_valid_and_stable(report: RuleReport) -> None:
    assert report.ok, report.errors
    assert report.rule is not None
    meta = report.rule.meta
    assert meta.id.startswith("PRH-")
    assert meta.status == "stable"
    assert meta.description
    assert meta.falsepositives


@pytest.mark.parametrize("report", REPORTS, ids=_id)
def test_rule_has_fixtures(report: RuleReport) -> None:
    assert fixture_file_for(report.file) is not None


@pytest.mark.parametrize("report", REPORTS, ids=_id)
def test_rule_has_runbook_with_standard_sections(report: RuleReport) -> None:
    assert report.rule is not None
    meta = report.rule.meta
    assert meta.response is not None
    runbook = builtin_runbook_path(meta.response)
    assert runbook.is_file(), runbook
    text = runbook.read_text(encoding="utf-8")
    assert text.startswith("# ")
    assert meta.id in text.split("\n## ", 1)[0], "runbook header must name the rule"
    positions = [text.find(f"\n{heading}\n") for heading in RUNBOOK_HEADINGS]
    assert all(p >= 0 for p in positions), positions
    assert positions == sorted(positions), "sections must appear in the standard order"
    actions = text.split("\n## Recommended actions\n", 1)[1].split("\n## ", 1)[0]
    assert re.search(r"^- \S", actions, re.MULTILINE), "recommended actions must be a list"


@pytest.mark.parametrize("report", REPORTS, ids=_id)
def test_rule_attack_tags_are_verified_and_consistent(report: RuleReport) -> None:
    assert report.rule is not None
    tags = report.rule.meta.attack_tags
    techniques = [t for t in tags if t in TECHNIQUES]
    tactics = [t for t in tags if t in TACTICS]
    assert techniques, "every built-in rule needs at least one technique id"
    assert tactics, "every built-in rule needs at least one tactic"
    assert all(is_verified(t) for t in tags), [t for t in tags if not is_verified(t)]
    covered = {tactic for t in techniques for tactic in TECHNIQUES[t].tactics}
    assert set(tactics) <= covered, "each tactic must belong to one of the rule's techniques"
    for technique in techniques:
        assert set(TECHNIQUES[technique].tactics) & set(tactics), technique


def test_all_builtin_fixtures_pass() -> None:
    reports = run_rule_tests([builtin_rules_dir()])
    assert len(reports) == len(REPORTS)
    assert all(r.passed for r in reports), [(r.rule_id, r.errors, r.cases) for r in reports]


def test_every_runbook_is_used() -> None:
    used = {Path(r.rule.meta.response).name for r in REPORTS if r.rule and r.rule.meta.response}
    shipped = {p.name for p in builtin_runbook_path("runbooks").glob("*.md")} - {"README.md"}
    assert shipped == used


def test_fixture_files_are_not_discovered_as_rules() -> None:
    assert all(not p.name.endswith(".tests.yml") for p in discover([builtin_rules_dir()]))


def test_verified_list_has_no_unused_techniques() -> None:
    used = {t for r in REPORTS if r.rule for t in r.rule.meta.attack_tags}
    assert set(TECHNIQUES) <= used


@pytest.mark.parametrize("report", REPORTS, ids=_id)
def test_fixture_runs_real_log_lines_through_a_parser(report: RuleReport) -> None:
    fixture = fixture_file_for(report.file)
    assert fixture is not None
    cases = yaml.safe_load(fixture.read_text(encoding="utf-8"))["cases"]
    assert any("log" in case and case["expect"]["alerts"] > 0 for case in cases)
