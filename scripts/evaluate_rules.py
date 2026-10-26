"""Evaluate the built-in detection rules on the simulated scenarios.

Runs every scenario in both variants (default and held-out) for each seed, compares the alerts
with the line labels and writes per-rule precision and recall to ``results/rules_eval.json``.
Then run ``scripts/generate_results_table.py`` to update the table in ``docs/SIMULATOR.md``.

    uv run python scripts/evaluate_rules.py [--seeds 5] [--out results/rules_eval.json]
"""

import argparse
import json
import sys
from pathlib import Path

from prohori.rules import builtin_rules_dir, load_rules
from prohori.simulate import SCENARIOS
from prohori.simulate.evaluate import evaluate

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT = ROOT / "results" / "rules_eval.json"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--seeds", type=int, default=5, help="seeds 1..N per scenario and variant")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT, help="results file to write")
    args = parser.parse_args(argv)
    if not 1 <= args.seeds <= 100:
        parser.error("--seeds must be between 1 and 100")
    reports = load_rules([builtin_rules_dir()])
    rules = [r.rule for r in reports if r.rule is not None]
    if len(rules) != len(reports):
        print("a built-in rule is invalid; run 'prohori rules validate'", file=sys.stderr)
        return 1
    results = evaluate(rules, seeds=range(1, args.seeds + 1))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {args.out} ({len(SCENARIOS)} scenarios x 2 variants x {args.seeds} seeds)")
    if results["parse_errors"]:
        print(
            f"warning: {results['parse_errors']} simulated lines failed to parse", file=sys.stderr
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
