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
"""

from collections import Counter
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from datetime import timedelta

from prohori.parsers import ParseStats, RawLine, get_parser, iter_text_lines
from prohori.rules import CompiledRule, RuleEngine
from prohori.schema import Alert, Event
from prohori.simulate.run import Simulation, simulate
from prohori.simulate.scenarios import SCENARIOS, VARIANTS

RESULTS_FORMAT = "prohori.rules-eval/1"
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


def detect(simulation: Simulation, rules: Sequence[CompiledRule]) -> Detection:
    """Parse the simulated log and run ``rules`` over it, keeping each event's line number."""
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
            yield event

    engine = RuleEngine(rules, lateness=LATENESS, reference_time=None)
    return Detection(list(engine.run(numbered())), line_of, stats)


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
) -> None:
    """Add one run's alerts to the per-rule and per-scenario scores."""
    labels = [attack for _, attack in simulation.lines]
    credited: set[tuple[str, str]] = set()
    for alert in detection.alerts:
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


def evaluate(
    rules: Sequence[CompiledRule],
    *,
    seeds: Sequence[int] = DEFAULT_SEEDS,
    scenarios: Sequence[str] | None = None,
) -> dict[str, object]:
    """Evaluate ``rules`` on every scenario and variant; return the results document."""
    names = sorted(scenarios or SCENARIOS)
    variants: dict[str, object] = {}
    parse_errors = 0
    for variant in VARIANTS:
        rule_scores: dict[str, RuleScore] = {r.id: RuleScore() for r in rules}
        scenario_scores: dict[str, ScenarioScore] = {}
        for name in names:
            scenario_score = scenario_scores.setdefault(name, ScenarioScore())
            for seed in seeds:
                simulation = simulate(name, seed=seed, variant=variant)
                detection = detect(simulation, rules)
                parse_errors += detection.stats.errors
                score_run(simulation, detection, rule_scores, scenario_score)
        variants[variant] = {
            "rules": {rid: s.as_dict() for rid, s in sorted(rule_scores.items())},
            "scenarios": {n: s.as_dict() for n, s in sorted(scenario_scores.items())},
        }
    expected = {r for name in names for v in VARIANTS for r in _expected(name, v)}
    return {
        "format": RESULTS_FORMAT,
        "seeds": list(seeds),
        "scenarios": names,
        "lateness_seconds": int(LATENESS.total_seconds()),
        "parse_errors": parse_errors,
        "not_evaluated": sorted(r.id for r in rules if r.id not in expected),
        "variants": variants,
        "caveat": CAVEAT,
    }


def _expected(name: str, variant: str) -> set[str]:
    simulation = simulate(name, seed=0, variant=variant)
    return {rule for attack in simulation.attacks for rule in attack.expected_rules}
