# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
# Copyright (c) 2026 Utsha Basak
"""Evaluate the built-in detection rules on the simulated scenarios.

Runs every scenario in both variants (default and held-out) for each seed, compares the alerts
with the line labels and writes per-rule precision and recall to ``results/rules_eval.json``.
Then run ``scripts/generate_results_table.py`` to update the table in ``docs/SIMULATOR.md``.

The example suppressions (``samples/suppressions.yml``) are applied to the same detections and
scored apart: the ``suppressions`` section has precision and recall with and without them. The
main results always count every alert.

The results file keeps frozen **baselines** under their labels: earlier rule sets' results,
each recorded once with ``--freeze-baseline LABEL`` (usually with ``--rules`` pointing at that
rule set, checked out from git) and never replaced, so the before-and-after comparison cannot
drift. Each records the simulator's address model; a baseline cannot be extended on another
model, so a new simulator gets new labels and the old baselines stay for reference. Later runs
copy every baseline over unchanged.

    uv run python scripts/evaluate_rules.py [--seeds 5] [--out results/rules_eval.json]
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from prohori.rules import CompiledRule, builtin_rules_dir, load_rules
from prohori.simulate import ADDRESS_MODEL, SCENARIOS, VARIANTS
from prohori.simulate.evaluate import evaluate
from prohori.suppress import SuppressionFileError, load_suppressions

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT = ROOT / "results" / "rules_eval.json"
SUPPRESSIONS = ROOT / "samples" / "suppressions.yml"


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
        help="record this run as the baseline LABEL: once before changing the rules, and later "
        "only to add a variant that baseline does not have yet (never to replace one)",
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
    try:
        suppressions = load_suppressions(SUPPRESSIONS)
    except SuppressionFileError as exc:
        print(f"{exc}: run 'prohori rules validate --suppressions {SUPPRESSIONS}'", file=sys.stderr)
        return 1
    results = evaluate(
        rules,
        seeds=range(1, args.seeds + 1),
        suppressions=suppressions,
        suppressions_name=SUPPRESSIONS.relative_to(ROOT).as_posix(),
    )
    if "baselines" in previous:
        results["baselines"] = previous["baselines"]
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
    """Record the missing variants of baseline ``label``; never change one that is there."""
    ids = sorted(r.id for r in rules)
    baselines: dict[str, Any] = previous.get("baselines", {})
    baseline = baselines.get(label)
    if baseline is not None and baseline["rules"] != ids:
        print(f"the frozen baseline {label!r} has another rule set", file=sys.stderr)
        return 1
    if baseline is not None and baseline["addresses"] != ADDRESS_MODEL:
        print(
            f"the frozen baseline {label!r} was scored on address model {baseline['addresses']}, "
            f"not {ADDRESS_MODEL}; freeze a new label instead",
            file=sys.stderr,
        )
        return 1
    have = set(baseline["variants"]) if baseline is not None else set()
    missing = [v for v in VARIANTS if v not in have]
    if not missing:
        print(
            f"every variant of the baseline {label!r} is frozen already; it is never replaced",
            file=sys.stderr,
        )
        return 1
    results = evaluate(rules, seeds=range(1, seeds + 1), variants_to_run=missing)
    if baseline is None:
        baseline = {"label": label, "rules": ids, "addresses": ADDRESS_MODEL, "variants": {}}
    baseline["variants"].update(results["variants"])
    document = previous or results
    document["baselines"] = {**baselines, label: baseline}
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"froze the {', '.join(missing)} results of the baseline {label!r} in {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
