"""Compare the anomaly detectors with the detection rules on the simulator's labelled attacks.

For every scenario, variant and seed, the simulated log is parsed once; the built-in rules run
over the events (as in ``scripts/evaluate_rules.py``) and the same events are cut into per-IP
windows for the anomaly detectors. Alerts are scored the same way for both:

* an alert is a **true positive** when at least half of the events it lists come from attack
  lines, and it is credited to the attack most of them belong to; otherwise it is a false alert;
* an attack is **caught** by a detector when at least one of its true-positive alerts is
  credited to it. For rules this counts **any** rule, not only the rules the scenario expects
  (the definition the rule evaluation in docs/SIMULATOR.md uses), so the two can be compared.

The default variants are development data: the cut-offs of the z-score and Isolation Forest
detectors are chosen on them (:func:`choose_cutoffs`) and frozen in :mod:`prohori.ml.anomaly`.
The held-out variants are the test.

    uv run python -m prohori.ml.logeval [--seeds 5]
"""

import argparse
import json
import sys
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from prohori.ml import anomaly
from prohori.ml.features import Window, extract
from prohori.rules import CompiledRule, builtin_rules_dir, load_rules
from prohori.schema import Alert, Event
from prohori.simulate import SCENARIOS, VARIANTS, simulate
from prohori.simulate.evaluate import DEFAULT_SEEDS, Detection, detect
from prohori.simulate.run import Simulation

RESULTS_FORMAT = "prohori.log-anomaly-eval/1"
RULES = "rules"
#: Detectors compared with the rules.
MODELS = ("zscore", "threshold", "iforest")
#: Candidate cut-offs tried on the default variants.
CANDIDATES = {
    "zscore": (3.0, 4.0, 5.0, 6.0, 8.0, 10.0, 12.0, 15.0, 20.0, 30.0),
    "iforest": (0.55, 0.6, 0.65, 0.7, 0.75, 0.8, 0.85, 0.9),
}
CAVEAT = (
    "Synthetic logs written by the same author as the rules and the detectors. The default "
    "variants were used to choose the anomaly cut-offs; the held-out variants were scored once "
    "with those cut-offs frozen. Every detector judges a window against the other windows of "
    "the same log, so how unusual an attack looks depends on how much background the simulated "
    "log has."
)


@dataclass
class Run:
    """One simulated log, parsed, with its rule alerts and windows."""

    simulation: Simulation
    detection: Detection
    windows: list[Window]


@dataclass
class Score:
    alerts: int = 0
    true_positives: int = 0
    attacks: int = 0
    caught: int = 0
    runs: int = 0
    by_scenario: Counter[str] = field(default_factory=Counter)  # scenario -> attacks caught

    def as_dict(self) -> dict[str, Any]:
        false = self.alerts - self.true_positives
        return {
            "alerts": self.alerts,
            "true_positives": self.true_positives,
            "false_alerts": false,
            "precision": round(self.true_positives / self.alerts, 3) if self.alerts else None,
            "attacks": self.attacks,
            "attacks_caught": self.caught,
            "false_alerts_per_run": round(false / self.runs, 2) if self.runs else None,
            "caught_by_scenario": dict(sorted(self.by_scenario.items())),
        }


@dataclass
class Comparison:
    """Which attacks the rules and a detector caught, together and apart."""

    attacks: int = 0
    rules: int = 0
    model: int = 0
    both: int = 0
    model_only: Counter[str] = field(default_factory=Counter)  # scenario -> attacks
    rules_only: Counter[str] = field(default_factory=Counter)

    def as_dict(self) -> dict[str, Any]:
        return {
            "attacks": self.attacks,
            "caught_by_rules": self.rules,
            "caught_by_model": self.model,
            "caught_by_either": self.rules + self.model - self.both,
            "caught_by_model_only": sum(self.model_only.values()),
            "caught_by_rules_only": sum(self.rules_only.values()),
            "model_only_by_scenario": dict(sorted(self.model_only.items())),
            "rules_only_by_scenario": dict(sorted(self.rules_only.items())),
        }


def prepare(simulation: Simulation, rules: Sequence[CompiledRule]) -> Run:
    events: list[Event] = []
    detection = detect(simulation, rules, events)
    return Run(simulation, detection, extract(events))


def credit(run: Run, alerts: Sequence[Alert]) -> tuple[int, set[str]]:
    """True-positive alerts and the attack ids they are credited to."""
    labels = [attack for _, attack in run.simulation.lines]
    line_of = run.detection.line_of
    true_positives = 0
    caught: set[str] = set()
    for alert in alerts:
        lines = [line_of[e] for e in alert.event_ids if e in line_of]
        attacks = [a for n in lines if (a := labels[n - 1]) is not None]
        if lines and len(attacks) * 2 >= len(lines):
            true_positives += 1
            caught.add(max(sorted(set(attacks)), key=attacks.count))
    return true_positives, caught


def window_labels(run: Run) -> list[bool]:
    """Whether each window is mostly attack events (the window-level ground truth)."""
    labels = [attack for _, attack in run.simulation.lines]
    line_of = run.detection.line_of
    found = []
    for window in run.windows:
        lines = [line_of[e] for e in window.event_ids if e in line_of]
        attack = sum(labels[n - 1] is not None for n in lines)
        found.append(bool(lines) and attack * 2 >= len(lines))
    return found


def choose_cutoffs(runs: Sequence[Run]) -> dict[str, dict[str, Any]]:
    """For each tunable detector, the candidate with the best window-level F1 on ``runs``.

    Only default-variant runs may be passed here; ties go to the higher (stricter) cut-off.
    """
    found: dict[str, dict[str, Any]] = {}
    for name, candidates in CANDIDATES.items():
        function, _ = anomaly.DETECTORS[name]
        scored: list[tuple[float, bool]] = []
        for run in runs:
            scores = function(run.windows)
            if scores:
                scored.extend(zip([s.score for s in scores], window_labels(run), strict=True))
        table = []
        for cutoff in candidates:
            tp = sum(1 for s, label in scored if s >= cutoff and label)
            fp = sum(1 for s, label in scored if s >= cutoff and not label)
            positives = sum(1 for _, label in scored if label)
            precision = tp / (tp + fp) if tp + fp else 0.0
            recall = tp / positives if positives else 0.0
            f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
            table.append(
                {
                    "cutoff": cutoff,
                    "precision": round(precision, 3),
                    "recall": round(recall, 3),
                    "f1": round(f1, 3),
                }
            )
        best = max(table, key=lambda row: (row["f1"], row["cutoff"]))
        found[name] = {"chosen": best["cutoff"], "candidates": table}
    return found


def evaluate(
    rules: Sequence[CompiledRule],
    *,
    seeds: Sequence[int] = DEFAULT_SEEDS,
    scenarios: Sequence[str] | None = None,
    models: Sequence[str] = MODELS,
) -> dict[str, Any]:
    """Every scenario, variant and seed; the results document."""
    names = sorted(scenarios or SCENARIOS)
    runs = {
        variant: [
            prepare(simulate(n, seed=s, variant=variant), rules) for n in names for s in seeds
        ]
        for variant in VARIANTS
    }
    variants: dict[str, Any] = {}
    for variant, variant_runs in runs.items():
        scores = {d: Score() for d in (RULES, *models)}
        comparisons = {m: Comparison() for m in models}
        windows = attack_windows = 0
        for run in variant_runs:
            ids = {a.id for a in run.simulation.attacks}
            scenario = run.simulation.scenario.name
            labels = window_labels(run)
            windows += len(labels)
            attack_windows += sum(labels)
            caught: dict[str, set[str]] = {}
            for name in (RULES, *models):
                alerts = (
                    run.detection.alerts if name == RULES else anomaly.detect(run.windows, [name])
                )
                tp, credited = credit(run, alerts)
                caught[name] = credited & ids
                score = scores[name]
                score.alerts += len(alerts)
                score.true_positives += tp
                score.attacks += len(ids)
                score.caught += len(caught[name])
                score.by_scenario[scenario] += len(caught[name])
                score.runs += 1
            for model in models:
                comparison = comparisons[model]
                comparison.attacks += len(ids)
                comparison.rules += len(caught[RULES])
                comparison.model += len(caught[model])
                comparison.both += len(caught[RULES] & caught[model])
                comparison.model_only[scenario] += len(caught[model] - caught[RULES])
                comparison.rules_only[scenario] += len(caught[RULES] - caught[model])
        variants[variant] = {
            "runs": len(variant_runs),
            "windows": windows,
            "attack_windows": attack_windows,
            "detectors": {name: s.as_dict() for name, s in scores.items()},
            "versus_rules": {m: c.as_dict() for m, c in comparisons.items()},
        }
    return {
        "format": RESULTS_FORMAT,
        "seeds": list(seeds),
        "scenarios": names,
        "window_minutes": 5,
        "min_windows": anomaly.MIN_WINDOWS,
        "cutoffs": {"zscore": anomaly.Z_THRESHOLD, "iforest": anomaly.IFOREST_THRESHOLD},
        "cutoff_selection_on_default": choose_cutoffs(runs["default"]),
        "variants": variants,
        "caveat": CAVEAT,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m prohori.ml.logeval", description=__doc__.splitlines()[0]
    )
    parser.add_argument("--seeds", type=int, default=5, help="seeds 1..N per scenario and variant")
    parser.add_argument("--out", type=Path, default=Path("results") / "ml_logs.json")
    args = parser.parse_args(argv)
    if not 1 <= args.seeds <= 100:
        parser.error("--seeds must be between 1 and 100")
    reports = load_rules([builtin_rules_dir()])
    rules = [r.rule for r in reports if r.rule is not None]
    results = evaluate(rules, seeds=range(1, args.seeds + 1))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8", newline="\n")
    sys.stderr.write(f"wrote {args.out}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
