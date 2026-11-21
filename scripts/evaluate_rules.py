# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
# Copyright (c) 2026 Utsha Basak
"""Evaluate the built-in detection rules on the simulated scenarios.

Runs every scenario in both variants (default and held-out) for each seed, compares the alerts
with the line labels and writes per-rule precision and recall to ``results/rules_eval.json``.
Then run ``scripts/generate_results_table.py`` to update the table in ``docs/SIMULATOR.md``.

The results file keeps a frozen **baseline**: the 1.0 rules' results, recorded once with
``--freeze-baseline`` before the rules were changed, so the before-and-after comparison cannot
drift. Later runs copy it over unchanged.

    uv run python scripts/evaluate_rules.py [--seeds 5] [--out results/rules_eval.json]
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from prohori.rules import CompiledRule, builtin_rules_dir, load_rules
from prohori.simulate import SCENARIOS, VARIANTS
from prohori.simulate.evaluate import evaluate

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT = ROOT / "results" / "rules_eval.json"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--seeds", type=int, default=5, help="seeds 1..N per scenario and variant")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT, help="results file to write")
    parser.add_argument(
        "--variants",
        nargs="+",
        choices=VARIANTS,
        help="score only these variants and print a summary; the results file is not written",
    )
    parser.add_argument(
        "--freeze-baseline",
        metavar="LABEL",
        help="record this run as the baseline: once before changing the rules, and later only "
        "to add a variant the baseline does not have yet (never to replace one)",
    )
    parser.add_argument(
        "--rules",
        type=Path,
        help="evaluate the rule files in this directory instead of the built-in rules (for "
        "example the baseline's, checked out from git)",
    )
    args = parser.parse_args(argv)
    if not 1 <= args.seeds <= 100:
        parser.error("--seeds must be between 1 and 100")
    reports = load_rules([args.rules or builtin_rules_dir()])
    rules = [r.rule for r in reports if r.rule is not None]
    if len(rules) != len(reports) or not rules:
        print("a rule is invalid; run 'prohori rules validate'", file=sys.stderr)
        return 1
    if args.variants:  # tuning: look at some variants without recording anything
        partial = evaluate(rules, seeds=range(1, args.seeds + 1), variants_to_run=args.variants)
        print(json.dumps(partial["variants"], indent=2))
        return 0
    previous = json.loads(args.out.read_text(encoding="utf-8")) if args.out.exists() else {}
    if args.freeze_baseline:
        return _freeze(args.freeze_baseline, rules, args.seeds, args.out, previous)
    if args.rules:
        parser.error("--rules is only for --freeze-baseline or --variants")
    results = evaluate(rules, seeds=range(1, args.seeds + 1))
    if "baseline" in previous:
        results["baseline"] = previous["baseline"]
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(
        f"wrote {args.out} ({len(SCENARIOS)} scenarios x {len(VARIANTS)} variants x "
        f"{args.seeds} seeds)"
    )
    if results["parse_errors"]:
        print(
            f"warning: {results['parse_errors']} simulated lines failed to parse", file=sys.stderr
        )
        return 1
    return 0


def _freeze(
    label: str, rules: list[CompiledRule], seeds: int, out: Path, previous: dict[str, Any]
) -> int:
    """Record the baseline's missing variants; never change one that is already there."""
    ids = sorted(r.id for r in rules)
    baseline = previous.get("baseline")
    if baseline is not None and (baseline["label"] != label or baseline["rules"] != ids):
        print("the frozen baseline has another label or rule set", file=sys.stderr)
        return 1
    have = set(baseline["variants"]) if baseline is not None else set()
    missing = [v for v in VARIANTS if v not in have]
    if not missing:
        print(
            "every variant of the baseline is frozen already; it is never replaced", file=sys.stderr
        )
        return 1
    results = evaluate(rules, seeds=range(1, seeds + 1), variants_to_run=missing)
    if baseline is None:
        baseline = {"label": label, "rules": ids, "variants": {}}
    baseline["variants"].update(results["variants"])
    document = previous or results
    document["baseline"] = baseline
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"froze the baseline's {', '.join(missing)} results in {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
