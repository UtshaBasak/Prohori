# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
# Copyright (c) 2026 Utsha Basak
"""Measure the detection rules against simulated, labelled attacks.

For every scenario, variant and seed the simulated log goes through the same path as
``prohori detect`` (the scenario's parser, the rule engine with 5 minutes of lateness). Each
alert is then compared with the line labels:

* An alert is a **true positive** when at least half of the events it lists come from attack
  lines, and it is credited to the attack most of them belong to. Otherwise it is a false
  positive. Precision is computed over alerts.
* An attack counts as **detected by a rule** when that rule raised at least one true-positive
  alert credited to it. Recall is computed over the attacks whose scenario lists the rule as
  expected.
* A rule that no scenario expects has no recall ("not evaluated"); its alerts on background
  traffic still show up as false positives.

With a suppressions file the same detections are scored twice: once with every alert (the main
results, unchanged by the file) and once without the suppressed alerts, so the file's effect on
precision **and** recall is on record: a suppression that hid an attack would show up as a lost
true positive.
"""

from collections import Counter
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from datetime import timedelta

from prohori.parsers import ParseStats, RawLine, get_parser, iter_text_lines
from prohori.rules import CompiledRule, RuleEngine
from prohori.schema import Alert, Event
from prohori.simulate.addresses import ADDRESS_MODEL
from prohori.simulate.run import Simulation, simulate
from prohori.simulate.scenarios import SCENARIOS, VARIANTS
from prohori.suppress import Suppressions, Suppressor

RESULTS_FORMAT = "prohori.rules-eval/2"
LATENESS = timedelta(minutes=5)
DEFAULT_SEEDS = (1, 2, 3, 4, 5)

CAVEAT = (
    "Synthetic results. The same author wrote the rules and the scenarios, and the default "
    "variants were written knowing the rules' thresholds, so they mostly show that the rules "
    "do what they say. The held-out variants change the attacker's behaviour (slower, spread "
    "over more addresses, obfuscated, outside a time window) and are the more honest number. "
    "Real logs are noisier; rules without a scenario are not evaluated."
)


@dataclass
class Detection:
    """The outcome of running the rules over one simulation."""

    alerts: list[Alert]
    line_of: dict[str, int]  # event id -> 1-based line number
    stats: ParseStats


class _LineTracker:
    """Passes raw lines through and remembers the number of the latest one."""

    def __init__(self, lines: Iterable[RawLine]) -> None:
        self._lines = lines
        self.current = 0

    def __iter__(self) -> Iterator[RawLine]:
        for line in self._lines:
            self.current = line.number
            yield line


def detect(
    simulation: Simulation,
    rules: Sequence[CompiledRule],
    events: list[Event] | None = None,
    suppressions: Suppressions | None = None,
) -> Detection:
    """Parse the simulated log and run ``rules`` over it, keeping each event's line number.

    Parsed events are also appended to ``events`` when it is given. With ``suppressions`` the
    alerts they cover are marked (``alert.suppression``), as ``prohori detect`` marks them.
    """
    scenario = simulation.scenario
    options = {"year": simulation.year} if scenario.parser == "auth_log" else {}
    parser = get_parser(scenario.parser, **options)
    tracker = _LineTracker(iter_text_lines(simulation.log_text().splitlines()))
    stats = ParseStats()
    line_of: dict[str, int] = {}

    def numbered() -> Iterator[Event]:
        # LineParser.parse yields at most one event per line, right after reading it.
        for event in parser.parse(tracker, source=scenario.filename, stats=stats):
            if event.id in line_of:
                msg = f"event id {event.id} maps to two lines"
                raise AssertionError(msg)
            line_of[event.id] = tracker.current
            if events is not None:
                events.append(event)
            yield event

    engine = RuleEngine(rules, lateness=LATENESS, reference_time=None)
    if suppressions is None:
        return Detection(list(engine.run(numbered())), line_of, stats)
    suppressor = Suppressor(suppressions)
    alerts = suppressor.apply_all(engine.run(suppressor.observe(numbered())))
    return Detection(list(alerts), line_of, stats)


@dataclass
class RuleScore:
    tp: int = 0
    fp: int = 0
    expected: int = 0
    detected: int = 0

    def as_dict(self) -> dict[str, object]:
        alerts = self.tp + self.fp
        return {
            "alerts": alerts,
            "true_positives": self.tp,
            "false_positives": self.fp,
            "attacks_expected": self.expected,
            "attacks_detected": self.detected,
            "precision": round(self.tp / alerts, 3) if alerts else None,
            "recall": round(self.detected / self.expected, 3) if self.expected else None,
        }


@dataclass
class ScenarioScore:
    runs: int = 0
    attacks: int = 0
    detected: int = 0  # attacks caught by at least one expected rule
    missed_rules: Counter[str] = field(default_factory=Counter)
    false_positives: Counter[str] = field(default_factory=Counter)

    def as_dict(self) -> dict[str, object]:
        return {
            "runs": self.runs,
            "attacks": self.attacks,
            "attacks_detected": self.detected,
            "missed_by_rule": dict(sorted(self.missed_rules.items())),
            "false_positives_by_rule": dict(sorted(self.false_positives.items())),
        }


def score_run(
    simulation: Simulation,
    detection: Detection,
    rules: dict[str, RuleScore],
    scenario: ScenarioScore,
    *,
    skip_suppressed: bool = False,
) -> None:
    """Add one run's alerts to the per-rule and per-scenario scores.

    With ``skip_suppressed`` the alerts a suppression marked are left out, as an analyst using
    the suppressions would never see them.
    """
    labels = [attack for _, attack in simulation.lines]
    credited: set[tuple[str, str]] = set()
    for alert in detection.alerts:
        if skip_suppressed and alert.suppression is not None:
            continue
        lines = [detection.line_of[e] for e in alert.event_ids if e in detection.line_of]
        attacks = [a for n in lines if (a := labels[n - 1]) is not None]
        score = rules.setdefault(alert.detector_id, RuleScore())
        if lines and len(attacks) * 2 >= len(lines):
            score.tp += 1
            top = max(sorted(set(attacks)), key=attacks.count)
            credited.add((alert.detector_id, top))
        else:
            score.fp += 1
            scenario.false_positives[alert.detector_id] += 1
    scenario.runs += 1
    for attack in simulation.attacks:
        scenario.attacks += 1
        caught = False
        for rule_id in attack.expected_rules:
            score = rules.setdefault(rule_id, RuleScore())
            score.expected += 1
            if (rule_id, attack.id) in credited:
                score.detected += 1
                caught = True
            else:
                scenario.missed_rules[rule_id] += 1
        scenario.detected += caught


def _totals(rules: dict[str, RuleScore], scenarios: dict[str, ScenarioScore]) -> dict[str, object]:
    alerts = sum(s.tp + s.fp for s in rules.values())
    tp = sum(s.tp for s in rules.values())
    attacks = sum(s.attacks for s in scenarios.values())
    detected = sum(s.detected for s in scenarios.values())
    return {
        "alerts": alerts,
        "true_positives": tp,
        "false_positives": alerts - tp,
        "precision": round(tp / alerts, 3) if alerts else None,
        "attacks": attacks,
        "attacks_detected": detected,
    }


def evaluate(
    rules: Sequence[CompiledRule],
    *,
    seeds: Sequence[int] = DEFAULT_SEEDS,
    scenarios: Sequence[str] | None = None,
    variants_to_run: Sequence[str] | None = None,
    suppressions: Suppressions | None = None,
    suppressions_name: str = "",
) -> dict[str, object]:
    """Evaluate ``rules`` on every scenario and variant; return the results document.

    ``variants_to_run`` limits the variants scored, so rules can be tuned on the default variants
    without seeing the held-out results. With ``suppressions`` (named ``suppressions_name`` in the
    results) the document also has a ``suppressions`` section: every variant scored again without
    the suppressed alerts, and the totals with and without them.
    """
    names = sorted(scenarios or SCENARIOS)
    variants: dict[str, object] = {}
    suppressed: dict[str, object] = {}
    parse_errors = 0
    for variant in variants_to_run or VARIANTS:
        rule_scores: dict[str, RuleScore] = {r.id: RuleScore() for r in rules}
        scenario_scores: dict[str, ScenarioScore] = {}
        kept_rules: dict[str, RuleScore] = {r.id: RuleScore() for r in rules}
        kept_scenarios: dict[str, ScenarioScore] = {}
        for name in names:
            scenario_score = scenario_scores.setdefault(name, ScenarioScore())
            kept_score = kept_scenarios.setdefault(name, ScenarioScore())
            for seed in seeds:
                simulation = simulate(name, seed=seed, variant=variant)
                detection = detect(simulation, rules, suppressions=suppressions)
                parse_errors += detection.stats.errors
                score_run(simulation, detection, rule_scores, scenario_score)
                if suppressions is not None:
                    score_run(simulation, detection, kept_rules, kept_score, skip_suppressed=True)
        variants[variant] = {
            "rules": {rid: s.as_dict() for rid, s in sorted(rule_scores.items())},
            "scenarios": {n: s.as_dict() for n, s in sorted(scenario_scores.items())},
        }
        if suppressions is not None:
            suppressed[variant] = {
                "without_suppressions": _totals(rule_scores, scenario_scores),
                "with_suppressions": _totals(kept_rules, kept_scenarios),
                "rules": {
                    rid: s.as_dict()
                    for rid, s in sorted(kept_rules.items())
                    if s.as_dict() != rule_scores[rid].as_dict()
                },
            }
    expected = {r for name in names for v in VARIANTS for r in _expected(name, v)}
    extra: dict[str, object] = {}
    if suppressions is not None:
        extra["suppressions"] = {
            "file": suppressions_name,
            "entries": [e.id for e in suppressions.entries],
            "variants": suppressed,
        }
    return {
        "format": RESULTS_FORMAT,
        "seeds": list(seeds),
        "addresses": ADDRESS_MODEL,
        "scenarios": names,
        "lateness_seconds": int(LATENESS.total_seconds()),
        "parse_errors": parse_errors,
        "not_evaluated": sorted(r.id for r in rules if r.id not in expected),
        "variants": variants,
        **extra,
        "caveat": CAVEAT,
    }


def _expected(name: str, variant: str) -> set[str]:
    simulation = simulate(name, seed=0, variant=variant)
    return {rule for attack in simulation.attacks for rule in attack.expected_rules}
