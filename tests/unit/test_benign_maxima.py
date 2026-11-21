# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
# Copyright (c) 2026 Utsha Basak
"""The evasion-resistant rules' thresholds follow ADR-0036's margin rule on the default variants."""

import pytest

from prohori.rules import CompiledRule, builtin_rules_dir, load_rules
from scripts import benign_maxima


@pytest.fixture(scope="module")
def maxima() -> dict[str, int]:
    measured = benign_maxima.measure()
    assert measured["variant"] == "default"
    return {name: found["max"] for name, found in measured["measures"].items()}


@pytest.fixture(scope="module")
def rules() -> dict[str, CompiledRule]:
    loaded = [r.rule for r in load_rules([builtin_rules_dir()]) if r.rule is not None]
    return {r.id: r for r in loaded}


def _distinct(rule: CompiledRule) -> list[int]:
    assert rule.aggregate is not None
    return [d.gte for d in rule.aggregate.distincts]


def test_every_threshold_is_twice_the_benign_maximum(
    maxima: dict[str, int], rules: dict[str, CompiledRule]
) -> None:
    double = benign_maxima.threshold
    assert _distinct(rules["PRH-AUTH-005"]) == [double(maxima["addresses per existing account"])]
    aggregate = rules["PRH-AUTH-006"].aggregate
    assert aggregate is not None
    assert aggregate.count_gte == double(maxima["failures per existing account"])
    assert _distinct(rules["PRH-AUTH-007"]) == [double(maxima["existing accounts per network"])]
    assert _distinct(rules["PRH-AUTH-008"]) == [
        double(maxima["existing accounts per log"]),
        double(maxima["addresses per log"]),
    ]
    sequence = rules["PRH-AUTH-010"].sequence
    assert sequence is not None
    assert sequence.steps[0].count_gte == double(maxima["failures per account"])


def test_the_stated_exception_has_no_benign_baseline(
    maxima: dict[str, int], rules: dict[str, CompiledRule]
) -> None:
    """PRH-AUTH-009's threshold is reasoned, not measured: the background never produces it."""
    assert maxima["addresses with unknown-account failures per log"] == 0
    assert _distinct(rules["PRH-AUTH-009"]) == [10]
    assert rules["PRH-AUTH-009"].meta.status == "experimental"
