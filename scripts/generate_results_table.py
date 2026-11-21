# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
# Copyright (c) 2026 Utsha Basak
"""Write the evaluation results into the docs from the files in ``results/``.

* Rules (``rules_eval.json``): full tables in ``docs/SIMULATOR.md``, a summary in ``README.md``,
  between the ``<!-- results:start -->`` and ``<!-- results:end -->`` markers, and the
  before-and-after comparison with the frozen baselines in ``docs/RULES.md``, between
  ``<!-- rules-compare:start -->`` and ``<!-- rules-compare:end -->``.
* Flow models (``ml_<dataset>.json``): full tables in ``docs/MODEL_CARD.md``, a summary in
  ``README.md``, between ``<!-- ml-results:start -->`` and ``<!-- ml-results:end -->``.
* Cross-dataset test (``ml_cross.json``): the same two documents, between
  ``<!-- ml-cross:start -->`` and ``<!-- ml-cross:end -->``.
* Log anomaly detection (``ml_logs.json``): full tables in ``docs/ANOMALY.md``, a summary in
  ``README.md``, between ``<!-- anomaly:start -->`` and ``<!-- anomaly:end -->``.
* Performance (``performance.json``): full table in ``docs/PERFORMANCE.md``, a summary in
  ``README.md``, between ``<!-- performance:start -->`` and ``<!-- performance:end -->``.
* The README's worked example: from the sample incident and its log, between
  ``<!-- example:start -->`` and ``<!-- example:end -->``.
* LLM analyst (``llm_eval.json``): full tables in ``docs/LLM_ANALYST.md``, a summary in
  ``README.md``, between ``<!-- llm-eval:start -->`` and ``<!-- llm-eval:end -->``.

With ``--check`` nothing is written and the exit code is 1 when a document is out of date.

    uv run python scripts/generate_results_table.py [--check]
"""

import argparse
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results" / "rules_eval.json"
DOCUMENT = ROOT / "docs" / "SIMULATOR.md"
MODEL_CARD = ROOT / "docs" / "MODEL_CARD.md"
README = ROOT / "README.md"
RULES_DOCUMENT = ROOT / "docs" / "RULES.md"
START = "<!-- results:start -->"
END = "<!-- results:end -->"
COMPARE_START = "<!-- rules-compare:start -->"
COMPARE_END = "<!-- rules-compare:end -->"
ML_START = "<!-- ml-results:start -->"
ML_END = "<!-- ml-results:end -->"
ADAPT_START = "<!-- ml-adapt:start -->"
ADAPT_END = "<!-- ml-adapt:end -->"
CALIBRATION_START = "<!-- ml-calibration:start -->"
CALIBRATION_END = "<!-- ml-calibration:end -->"
CROSS_START = "<!-- ml-cross:start -->"
CROSS_END = "<!-- ml-cross:end -->"
ANOMALY_DOCUMENT = ROOT / "docs" / "ANOMALY.md"
ANOMALY_START = "<!-- anomaly:start -->"
ANOMALY_END = "<!-- anomaly:end -->"
EXAMPLE_INCIDENT = next((ROOT / "samples" / "incidents").glob("INC-*.json"))
EXAMPLE_LOG = ROOT / "samples" / "logs" / "account-takeover.jsonl"
EXAMPLE_START = "<!-- example:start -->"
EXAMPLE_END = "<!-- example:end -->"
PERF_DOCUMENT = ROOT / "docs" / "PERFORMANCE.md"
PERF_START = "<!-- performance:start -->"
PERF_END = "<!-- performance:end -->"
LLM_DOCUMENT = ROOT / "docs" / "LLM_ANALYST.md"
LLM_START = "<!-- llm-eval:start -->"
LLM_END = "<!-- llm-eval:end -->"
#: The LLM baselines in the order they are shown; any other system is a real model.
LLM_ORDER = ("local", "mock", "adversarial")
LLM_BASELINES = frozenset(LLM_ORDER)
DETECTOR_NAMES = {
    "rules": "Detection rules (any rule)",
    "zscore": "Robust z-score",
    "threshold": "Fixed thresholds",
    "iforest": "Isolation Forest",
}
#: Datasets in the order they appear in the docs.
ML_DATASETS = ("unsw-nb15", "cicids2017")
METHOD_NAMES = {
    "time-block": "Time blocks (validation)",
    "out-of-fold": "Out-of-fold (time-block folds)",
    "random": "Random rows (1.0)",
}
MODEL_NAMES = {"hgb": "Gradient boosting (supervised)", "iforest": "Isolation Forest (benign only)"}
VARIANT_NAMES = {
    "cleaned": "Cleaned (every leakage control)",
    "cleaned-no-suspect": "Cleaned, without the TTL columns",
    "uncleaned": "Uncleaned (no deduplication, ids and ports kept)",
}


def _pct(value: float | None) -> str:
    return "not evaluated" if value is None else f"{value * 100:.0f}%"


def _precision(score: dict[str, Any]) -> str:
    return "no alerts" if score["precision"] is None else _pct(score["precision"])


HELD_OUT = (("heldout", "Held-out"), ("heldout2", "Held-out 2"))


def _attacks_caught(scenarios: dict[str, Any]) -> tuple[int, int]:
    found = scenarios.values()
    return sum(s["attacks_detected"] for s in found), sum(s["attacks"] for s in found)


def _false_positives(scenarios: dict[str, Any]) -> int:
    return sum(sum(s["false_positives_by_rule"].values()) for s in scenarios.values())


def _missed(found: dict[str, Any]) -> str:
    return (
        ", ".join(f"{r} ({n}/{found['runs']})" for r, n in found["missed_by_rule"].items()) or "-"
    )


def render(results: dict[str, Any]) -> str:
    """The full tables for docs/SIMULATOR.md."""
    variants = results["variants"]
    names = [v for v in ("default", *(v for v, _ in HELD_OUT)) if v in variants]
    labels = {"default": "default", "heldout": "held-out", "heldout2": "held-out 2"}
    seeds = results["seeds"]
    intro = (
        f"Generated by `scripts/evaluate_rules.py`: {len(results['scenarios'])} scenarios, "
        f"seeds {seeds[0]} to {seeds[-1]} per variant. Do not edit by hand."
    )
    columns = ["Rule"]
    for name in names:
        columns += [f"Precision ({labels[name]})", f"Recall ({labels[name]})"]
    lines = [
        intro,
        "",
        "| " + " | ".join(columns) + " |",
        "|------|" + "|".join("-" * (len(c) + 1) + ":" for c in columns[1:]) + "|",
    ]
    for rule in sorted(variants["default"]["rules"]):
        scores = [variants[n]["rules"][rule] for n in names]
        if rule in results["not_evaluated"] and not any(s["alerts"] for s in scores):
            lines.append(f"| {rule} |" + " not evaluated |" * len(columns[1:]))
            continue
        cells = [
            f"{_precision(s)} ({s['true_positives']}/{s['alerts']}) | {_pct(s['recall'])}"
            for s in scores
        ]
        lines.append(f"| {rule} | " + " | ".join(cells) + " |")
    header = "| Scenario | " + " | ".join(labels[n].capitalize() for n in names)
    header += "".join(f" | Missed in {labels[n]} by" for n in names[1:]) + " |"
    lines += [
        "",
        "Attacks caught by at least one of their expected rules:",
        "",
        header,
        "|----------|" + "--------:|" * len(names) + "------|" * (len(names) - 1),
    ]
    for scenario in results["scenarios"]:
        found = [variants[n]["scenarios"][scenario] for n in names]
        caught = " | ".join(f"{f['attacks_detected']}/{f['attacks']}" for f in found)
        missed = " | ".join(_missed(f) for f in found[1:])
        lines.append(f"| {scenario} | {caught} | {missed} |")
    return "\n".join(lines)


def _compare(
    columns: list[tuple[str, dict[str, Any]]], scenarios: list[str], *, with_default: bool = True
) -> list[str]:
    """Attacks caught per scenario, one column per held-out variant and rule set."""
    held = [(v, label) for v, label in HELD_OUT if any(v in found for _, found in columns)]
    header = " | ".join(f"{label}: {title}" for _, label in held for title, _ in columns)
    lines = [
        f"| Scenario | {header} |",
        "|----------|" + "-----:|" * (len(held) * len(columns)),
    ]

    def cells(pick: Any) -> list[str]:  # noqa: ANN401 - a formatter
        return [
            pick(found[v]["scenarios"]) if v in found else "-"
            for v, _ in held
            for _, found in columns
        ]

    for scenario in scenarios:
        row = cells(lambda f, n=scenario: f"{f[n]['attacks_detected']}/{f[n]['attacks']}")
        lines.append(f"| {scenario} | " + " | ".join(row) + " |")
    totals = cells(lambda f: "**{}/{}**".format(*_attacks_caught(f)))
    lines.append("| **All attacks** | " + " | ".join(totals) + " |")
    noise = cells(lambda f: str(_false_positives(f)))
    lines.append("| False-positive alerts on benign lines | " + " | ".join(noise) + " |")
    if with_default:
        caught = [
            "{}/{} attacks caught with {} false-positive alerts ({})".format(
                *_attacks_caught(found["default"]["scenarios"]),
                _false_positives(found["default"]["scenarios"]),
                title,
            )
            for title, found in columns
            if "default" in found
        ]
        lines += ["", "Default variants: " + "; ".join(caught) + "."]
    return lines


def render_comparison(results: dict[str, Any]) -> str:
    """Before and after: the frozen baselines on today's simulator against today's rules, then
    the baselines of earlier address models for reference."""
    baselines = list(results.get("baselines", {}).values())
    if not baselines:
        return "No baseline recorded."
    model = results["addresses"]
    same = [b for b in baselines if b["addresses"] == model]
    earlier = [b for b in baselines if b["addresses"] != model]
    frozen = "; ".join(f"{b['label']}: {len(b['rules'])} rules" for b in same)
    lines = [
        f"Generated from `results/rules_eval.json`, simulator address model {model}: the frozen "
        f"baselines ({frozen}) against today's {len(results['variants']['default']['rules'])} "
        f"rules, {len(results['seeds'])} seeds per variant. Attacks caught by at least one of "
        "their expected rules. Do not edit by hand.",
        "",
        *_compare(
            [(b["label"], b["variants"]) for b in same] + [("now", results["variants"])],
            results["scenarios"],
        ),
    ]
    for old in sorted({b["addresses"] for b in earlier}):
        group = [b for b in earlier if b["addresses"] == old]
        lines += [
            "",
            f"For reference, the same comparison on address model {old} (frozen, not comparable "
            "with the table above: the simulator's background was different):",
            "",
            *_compare([(b["label"], b["variants"]) for b in group], results["scenarios"]),
        ]
    return "\n".join(lines)


def render_summary(results: dict[str, Any]) -> str:
    """The README summary: the before-and-after table and every remaining held-out miss."""
    variants = results["variants"]
    lines = [render_comparison(results), "", "Expected rules that still miss (runs missed):", ""]
    for variant, label in HELD_OUT:
        if variant not in variants:
            continue
        for name in results["scenarios"]:
            found = variants[variant]["scenarios"][name]
            missed = ", ".join(
                f"{r} {n}/{found['runs']}" for r, n in found["missed_by_rule"].items()
            )
            if missed:
                lines.append(f"- {label}, `{name}`: {missed}")
    return "\n".join(lines)


def _stat(summary: dict[str, Any], *, percent: bool = False, digits: int = 3) -> str:
    """``{"mean": .., "std": ..}`` as ``0.952 ± 0.003`` or ``82.0 ± 1.2 %``."""
    if not summary:
        return "-"
    mean, std = summary["mean"], summary["std"]
    if percent:
        return f"{mean * 100:.{digits}f} ± {std * 100:.{digits}f} %"
    return f"{mean:.{digits}f} ± {std:.{digits}f}"


def _label(fpr: float) -> str:
    return f"{fpr * 100:g} %"


def _point(summary: dict[str, Any], fpr: float) -> dict[str, Any]:
    point: dict[str, Any] = summary["operating_points"][f"fpr_{fpr:g}"]
    return point


def render_ml(results: dict[str, Any]) -> str:
    """The tables for one dataset in docs/MODEL_CARD.md."""
    fprs = results["target_fprs"]
    cleaned = results["variants"]["cleaned"]
    intro = (
        f"Seeds {', '.join(map(str, results['seeds']))}; mean ± standard deviation over the "
        "seeds. Each threshold is chosen on the validation split for a target false-positive "
        "rate (FPR) and frozen; the test split is scored once. Generated from "
        f"`results/ml_{results['dataset']}.json`; do not edit by hand."
    )
    lines = [f"### {results['dataset_title']}", "", intro, ""]
    columns = ["Model", "PR-AUC", "ROC-AUC"]
    for fpr in fprs:
        columns += [f"Test FPR ({_label(fpr)} val.)", "Recall", "False alerts / 10k"]
    lines += ["| " + " | ".join(columns) + " |", "|" + "---|" * len(columns)]
    for model, entry in cleaned["models"].items():
        summary = entry["summary"]
        row = [MODEL_NAMES.get(model, model), _stat(summary["pr_auc"]), _stat(summary["roc_auc"])]
        for fpr in fprs:
            point = _point(summary, fpr)
            row += [
                _stat(point["fpr"], percent=True, digits=2),
                _stat(point["recall"], percent=True, digits=2),
                _stat(point["false_alerts_per_10k"], digits=1),
            ]
        lines.append("| " + " | ".join(row) + " |")

    last = fprs[-1]
    effect = (
        "Effect of the leakage controls on gradient boosting. Each variant has its own test "
        "split, so this compares what the same pipeline reports about itself, not two models "
        "on the same data:"
    )
    header = (
        "| Variant | Test flows | Attack share | PR-AUC | ROC-AUC | "
        f"Recall ({_label(last)} val.) | Test FPR |"
    )
    lines += [
        "",
        effect,
        "",
        header,
        "|---------|-----------:|-------------:|-------:|--------:|------:|------:|",
    ]
    for variant, found in results["variants"].items():
        if "hgb" not in found["models"]:
            continue
        summary = found["models"]["hgb"]["summary"]
        point = _point(summary, last)
        lines.append(
            f"| {VARIANT_NAMES.get(variant, variant)} | {summary['flows']['mean']:,.0f} | "
            f"{summary['prevalence']['mean'] * 100:.1f} % | {_stat(summary['pr_auc'])} | "
            f"{_stat(summary['roc_auc'])} | {_stat(point['recall'], percent=True, digits=1)} | "
            f"{_stat(point['fpr'], percent=True, digits=2)} |"
        )

    if "hgb" in cleaned["models"]:
        summary = cleaned["models"]["hgb"]["summary"]
        points = [_point(summary, fpr) for fpr in fprs]
        header = " | ".join(f"Recall ({_label(fpr)} val.)" for fpr in fprs)
        per_class = (
            "Recall per attack class (gradient boosting, cleaned) with the class's test flows, "
            "averaged over the seeds:"
        )
        lines += [
            "",
            per_class,
            "",
            f"| Class | Test flows | {header} |",
            "|-------|-----------:|" + "------:|" * len(fprs),
        ]
        for name in sorted(points[0]["per_class_recall"]):
            flows = points[0]["per_class_recall"][name]["flows"]["mean"]
            recalls = [
                _stat(p["per_class_recall"].get(name, {}).get("recall", {}), percent=True, digits=1)
                for p in points
            ]
            lines.append(f"| {name} | {flows:,.0f} | {' | '.join(recalls)} |")
    return "\n".join(lines)


def calibration_errors(all_results: list[dict[str, Any]]) -> dict[str, float]:
    """Each method's calibration error, averaged over datasets and models (the selection rule)."""
    errors: dict[str, list[float]] = {}
    for results in all_results:
        study = results.get("calibration_study") or {}
        for method, models in study.get("methods", {}).items():
            errors.setdefault(method, []).extend(m["calibration_error"] for m in models.values())
    return {method: sum(v) / len(v) for method, v in errors.items()}


def render_calibration(all_results: list[dict[str, Any]]) -> str:
    """The calibration study for docs/MODEL_CARD.md: how each way of choosing thresholds held."""
    studied = [r for r in all_results if r.get("calibration_study")]
    if not studied:
        return "No calibration study yet."
    fprs = studied[0]["target_fprs"]
    columns = ["Dataset", "Method", "Model", "Benign val. near-duplicates"]
    for fpr in fprs:
        columns += [f"Test FPR ({_label(fpr)} target)", "Recall"]
    columns.append("Calibration error")
    lines = [
        "Seeds " + ", ".join(map(str, studied[0]["seeds"])) + "; cleaned variant; mean ± "
        "standard deviation. The same test split scores every method. Calibration error is "
        "|test FPR / target - 1| averaged over the targets (0 is perfect). Near-duplicates: the "
        "share of benign validation flows equal to a benign training flow once every number is "
        "rounded to two significant digits (out-of-fold uses the time-block split). Generated "
        "from `results/ml_*.json`; do not edit by hand.",
        "",
        "| " + " | ".join(columns) + " |",
        "|" + "---|" * len(columns),
    ]
    for results in studied:
        for method, models in results["calibration_study"]["methods"].items():
            for model, entry in models.items():
                near = [r["near_duplicate_share"] for r in entry["runs"]]
                share = sum(near) / len(near) if None not in near else None
                row = [
                    results["dataset"],
                    METHOD_NAMES.get(method, method),
                    MODEL_NAMES.get(model, model),
                    "-" if share is None else f"{share * 100:.2f} %",
                ]
                for fpr in fprs:
                    point = entry["summary"][f"fpr_{fpr:g}"]
                    row += [
                        _stat(point["fpr"], percent=True, digits=2),
                        _stat(point["recall"], percent=True, digits=1),
                    ]
                row.append(f"{entry['calibration_error']:.3f}")
                lines.append("| " + " | ".join(row) + " |")
    errors = calibration_errors(studied)
    chosen = studied[0]["calibration"]
    ranked = ", ".join(
        f"{METHOD_NAMES.get(m, m).lower()} {e:.3f}"
        for m, e in sorted(errors.items(), key=lambda x: x[1])
    )
    lines += [
        "",
        f"Mean calibration error over both datasets and models: {ranked}. "
        f"Published numbers and saved models use **{METHOD_NAMES.get(chosen, chosen).lower()}**. "
        f"Rule, written down before the runs: {studied[0]['calibration_study']['rule']}",
    ]
    return "\n".join(lines)


ARM_NAMES = {
    "baseline": ("Baseline (step 16)", "nothing"),
    "standardise": ("Per-domain log standardisation", "pool features"),
    "quantile": ("Per-domain quantile map", "pool features"),
    "quantile-protocol": ("Per-domain, per-protocol quantile map", "pool features"),
    "coral": ("CORAL", "pool features"),
    "importance": ("Importance weighting", "pool features"),
    "invariant": ("Domain-invariant features only", "pool features"),
    "few-shot-10": ("10 labelled target flows", "10 pool labels"),
    "few-shot-50": ("50 labelled target flows", "50 pool labels"),
    "few-shot-100": ("100 labelled target flows", "100 pool labels"),
    "target-reference": ("Reference: trained on the target", "target labels"),
}


def _ci(pair: list[float], digits: int = 3) -> str:
    return f"{pair[0]:.{digits}f} to {pair[1]:.{digits}f}"


def render_adapt(results: dict[str, Any]) -> str:
    """The cross-dataset study's tables for docs/MODEL_CARD.md (step 30b, ADR-0041)."""
    lines = [
        f"Seeds {', '.join(map(str, results['seeds']))}; gradient boosting; scored on the "
        "target's test split. 95 % intervals from "
        f"{results['resamples']:,} paired bootstrap resamples of the target test rows. An arm "
        "**improves** only if the interval of its ROC-AUC difference excludes 0 and the "
        "difference has the same sign in every seed; it **helps** only if it improves in both "
        "directions. Thresholds come from the source's validation split (1 % false-positive "
        'rate); "at 1 % on target" reads recall off the target\'s own ROC curve instead (not '
        "deployable). Generated from `results/ml_adapt.json`; do not edit by hand.",
    ]
    for key, direction in results["directions"].items():
        src, dst = key.split("->")
        lines += [
            "",
            f"### {src} → {dst}",
            "",
            "| Arm | Sees from the target | ROC-AUC | 95 % interval | Difference to baseline "
            "| 95 % interval | Verdict | PR-AUC (chance) | Recall at the source threshold | "
            "Target FPR reached | Recall at 1 % on target | Gap closed |",
            "|" + "---|" * 12,
        ]
        for arm, found in direction["arms"].items():
            name, sees = ARM_NAMES.get(arm, (arm, ""))
            mean = found["mean"]
            if arm == "baseline":
                verdict, difference, diff_ci = "-", "-", "-"
            else:
                verdict = (
                    "improves"
                    if found["improves"]
                    else "worsens"
                    if found["worsens"]
                    else "no clear change"
                )
                if arm == "target-reference":
                    verdict = "reference"
                difference = f"{found['roc_auc_difference']:+.3f}"
                diff_ci = _ci(found["roc_auc_difference_interval"])
            gap = found["gap_closed"]
            shown = arm not in ("baseline", "target-reference") and gap is not None
            gap_text = f"{gap * 100:.0f} %" if shown else "-"
            lines.append(
                f"| {name} | {sees} | {mean['roc_auc']:.3f} | {_ci(found['roc_auc_interval'])} "
                f"| {difference} | {diff_ci} | {verdict} | {mean['pr_auc']:.3f} "
                f"({mean['prevalence']:.2f}) | {mean['recall_frozen'] * 100:.1f} % | "
                f"{mean['fpr_frozen'] * 100:.1f} % | {mean['recall_at_target_fpr'] * 100:.1f} % "
                f"| {gap_text} |"
            )
    lines += ["", "Diagnostics, per direction (mean over the seeds):", ""]
    lines += [
        "| Direction | Pool attack share | Domain classifier ROC-AUC | Effective sample share "
        "| Weights at a clip | Features dropped as not invariant |",
        "|---|---|---|---|---|---|",
    ]
    for key, direction in results["directions"].items():
        diag = direction["diagnostics"]

        def avg(name: str, rows: list[dict[str, Any]] = diag) -> float:
            return float(sum(r[name] for r in rows) / len(rows))

        dropped = sorted({f for r in diag for f in r["invariant_dropped"]})
        dropped_text = ", ".join(f"`{f}`" for f in dropped) or "none"
        lines.append(
            f"| {key.replace('->', ' → ')} | {avg('pool_attack_share') * 100:.0f} % | "
            f"{avg('domain_auc'):.3f} | {avg('effective_sample_share') * 100:.1f} % | "
            f"{avg('clipped_share') * 100:.1f} % | {dropped_text} |"
        )
    helping = [a for a, h in results["helps"].items() if h["improves_both_directions"]]
    methods = [a for a in helping if not a.startswith("few-shot")]
    lines += [
        "",
        "Helps in both directions: "
        + (", ".join(ARM_NAMES[a][0].lower() for a in helping) if helping else "no arm")
        + ". Unsupervised methods that help: "
        + (", ".join(ARM_NAMES[a][0].lower() for a in methods) if methods else "none")
        + ".",
    ]
    return "\n".join(lines)


def render_adapt_summary(results: dict[str, Any] | None) -> str:
    """One README paragraph on the cross-dataset study."""
    if not results:
        return "No cross-dataset study results yet."
    parts = []
    for key, direction in results["directions"].items():
        arms = direction["arms"]
        best = max(
            (
                a
                for a in arms
                if a not in ("baseline", "target-reference") and not a.startswith("few-shot")
            ),
            key=lambda a: arms[a]["mean"]["roc_auc"],
        )
        parts.append(
            f"{key.replace('->', ' → ')}: baseline {arms['baseline']['mean']['roc_auc']:.3f}, "
            f"best unsupervised method {ARM_NAMES[best][0].lower()} "
            f"{arms[best]['mean']['roc_auc']:.3f} ({arms[best]['roc_auc_difference']:+.3f}), "
            f"100 labelled target flows {arms['few-shot-100']['mean']['roc_auc']:.3f}, trained "
            f"on the target {arms['target-reference']['mean']['roc_auc']:.3f}"
        )
    helping = [
        ARM_NAMES[a][0].lower()
        for a, h in results["helps"].items()
        if h["improves_both_directions"] and not a.startswith("few-shot")
    ]
    verdict = (
        f"Unsupervised methods that help in both directions: {', '.join(helping)}."
        if helping
        else "No unsupervised method helps in both directions."
    )
    return (
        "A pre-registered study (ADR-0041) tried six low-compute ways to close the gap without "
        "target labels, and a few labelled target flows as an upper bound. Target-test ROC-AUC, "
        f"means over seeds {', '.join(map(str, results['seeds']))}: "
        + "; ".join(parts)
        + ". "
        + verdict
        + " Details: [model card](docs/MODEL_CARD.md#cross-dataset-study)."
    )


def render_ml_summary(all_results: list[dict[str, Any]]) -> str:
    """The README summary: the cleaned results of every model on every dataset."""
    if not all_results:
        return "No model results yet."
    fpr = all_results[0]["target_fprs"][-1]
    lines = [
        "| Dataset | Model | PR-AUC | Recall | Test FPR | False alerts / 10k |",
        "|---------|-------|-------:|-------:|---------:|-------------------:|",
    ]
    for results in all_results:
        for model, entry in results["variants"]["cleaned"]["models"].items():
            summary = entry["summary"]
            point = _point(summary, fpr)
            lines.append(
                f"| {results['dataset']} | {MODEL_NAMES.get(model, model)} | "
                f"{summary['pr_auc']['mean']:.3f} | {point['recall']['mean'] * 100:.2f} % | "
                f"{point['fpr']['mean'] * 100:.2f} % | "
                f"{point['false_alerts_per_10k']['mean']:.1f} |"
            )
    note = (
        f"Means over seeds {', '.join(map(str, all_results[0]['seeds']))} on the cleaned test "
        f"splits, with thresholds chosen for a {_label(fpr)} false-positive rate on the "
        "validation split and then frozen."
    )
    lines += ["", note]
    found = {r["dataset"]: r for r in all_results}
    if {"unsw-nb15", "cicids2017"} <= set(found):
        lines += ["", _ml_findings(found["unsw-nb15"], found["cicids2017"])]
    return "\n".join(lines)


def _cleaned_share(results: dict[str, Any]) -> tuple[float, int]:
    """The share of rows the leakage controls removed, and the rows before cleaning."""
    cleaning = results["variants"]["cleaned"]["cleaning"][0]
    kept = sum(cleaning["rows"].values())
    removed = sum(
        cleaning[k] for k in ("duplicates_removed", "conflicting_removed", "overlap_removed")
    )
    return removed / (kept + removed), kept + removed


def _ml_findings(unsw: dict[str, Any], cic: dict[str, Any]) -> str:
    """What the README's flow-model numbers say, written from the results."""
    loose, strict = unsw["target_fprs"][0], unsw["target_fprs"][-1]
    hgb = unsw["variants"]["cleaned"]["models"]["hgb"]["summary"]
    point = _point(hgb, strict)
    cic_point = _point(cic["variants"]["cleaned"]["models"]["hgb"]["summary"], strict)
    loose_fpr = _point(hgb, loose)["fpr"]["mean"]
    uncleaned = unsw["variants"]["uncleaned"]["models"]["hgb"]["summary"]["pr_auc"]["mean"]
    unsw_share, unsw_rows = _cleaned_share(unsw)
    cic_share, cic_rows = _cleaned_share(cic)
    threshold = (
        f"The {_label(loose)} threshold chosen on UNSW-NB15's validation data gave "
        f"{loose_fpr * 100:.1f} % false positives on its test file."
    )
    study = (unsw.get("calibration_study") or {}).get("methods", {})
    if loose_fpr <= 2 * loose and "random" in study:
        random = study["random"]["hgb"]["summary"][f"fpr_{loose:g}"]["fpr"]["mean"]
        threshold = (
            f"Thresholds chosen on validation time blocks held on UNSW-NB15's test file "
            f"({loose_fpr * 100:.1f} % false positives at the {_label(loose)} target); with "
            f"validation rows drawn at random, as in 1.0, the same target gave "
            f"{random * 100:.1f} %."
        )
    return (
        f"What the numbers say: gradient boosting catches {point['recall']['mean'] * 100:.0f} % "
        f"of UNSW-NB15's attacks at {point['false_alerts_per_10k']['mean']:.1f} false alerts per "
        "10,000 flows, missing most fuzzing and analysis traffic, and on CIC-IDS-2017 catches "
        f"{cic_point['recall']['mean'] * 100:.2f} %, which says more about that lab dataset than "
        f"about the model. {threshold} The Isolation Forest is "
        "not a usable detector on either dataset. Without the leakage controls the same pipeline "
        f"would report a PR-AUC of {uncleaned:.3f} instead of {hgb['pr_auc']['mean']:.3f} on "
        f"UNSW-NB15. Cleaning removed {unsw_share * 100:.0f} % of UNSW-NB15's {unsw_rows:,} rows "
        f"and {cic_share * 100:.0f} % of CIC-IDS-2017's {cic_rows:,} flows, mostly duplicates once "
        "the identifiers are gone."
    )


def render_cross(cross: dict[str, Any], in_dataset: list[dict[str, Any]]) -> str:
    """The cross-dataset tables for docs/MODEL_CARD.md."""
    full = {r["dataset"]: r["variants"]["cleaned"]["models"] for r in in_dataset}
    fprs = cross["target_fprs"]
    intro = (
        f"Seeds {', '.join(map(str, cross['seeds']))}; mean ± standard deviation. Each model is "
        f"trained on the source dataset's {len(cross['features'])} common features, its "
        "thresholds are chosen on the source's validation split, and it is scored once on the "
        "source's test split (in-dataset) and once on the target's (cross-dataset). Generated "
        "from `results/ml_cross.json`; do not edit by hand."
    )
    note = (
        "PR-AUC depends on the share of attacks, which differs between the datasets, so each "
        "PR-AUC has its chance level (the attack share) next to it. ROC-AUC does not depend on "
        "it (0.5 is chance) and is the fairer comparison across datasets."
    )
    header = (
        "| Direction | Model | PR-AUC, all features | PR-AUC, common features | Chance, source | "
        "PR-AUC, cross-dataset | Chance, target | ROC-AUC, in-dataset | ROC-AUC, cross-dataset |"
    )
    lines = [intro, "", note, "", header, "|-----------|-------|" + "------:|" * 7]
    for key, direction in cross["directions"].items():
        for model, entry in direction["models"].items():
            same, other = entry["summary"]["in_dataset"], entry["summary"]["cross_dataset"]
            reference = full.get(direction["source"], {}).get(model, {}).get("summary", {})
            lines.append(
                f"| {key.replace('->', ' → ')} | {MODEL_NAMES.get(model, model)} | "
                f"{_stat(reference.get('pr_auc', {}))} | {_stat(same['pr_auc'])} | "
                f"{same['prevalence']['mean']:.3f} | {_stat(other['pr_auc'])} | "
                f"{other['prevalence']['mean']:.3f} | {_stat(same['roc_auc'])} | "
                f"{_stat(other['roc_auc'])} |"
            )
    point_header = (
        "| Direction | Model | In-dataset recall | In-dataset test FPR | "
        "Cross-dataset recall | Cross-dataset FPR | False alerts / 10k |"
    )
    for fpr in fprs:
        caption = (
            f"At the threshold chosen for a {_label(fpr)} false-positive rate on the source's "
            "validation split:"
        )
        lines += ["", caption, "", point_header, "|-----------|-------|" + "------:|" * 5]
        for key, direction in cross["directions"].items():
            for model, entry in direction["models"].items():
                same = _point(entry["summary"]["in_dataset"], fpr)
                other = _point(entry["summary"]["cross_dataset"], fpr)
                lines.append(
                    f"| {key.replace('->', ' → ')} | {MODEL_NAMES.get(model, model)} | "
                    f"{_stat(same['recall'], percent=True, digits=1)} | "
                    f"{_stat(same['fpr'], percent=True, digits=2)} | "
                    f"{_stat(other['recall'], percent=True, digits=1)} | "
                    f"{_stat(other['fpr'], percent=True, digits=2)} | "
                    f"{_stat(other['false_alerts_per_10k'], digits=0)} |"
                )
    first = fprs[0]
    for key, direction in cross["directions"].items():
        if "hgb" not in direction["models"]:
            continue
        point = _point(direction["models"]["hgb"]["summary"]["cross_dataset"], first)
        caption = (
            f"Recall per attack class in the target, {key.replace('->', ' → ')} (gradient "
            f"boosting, {_label(first)} source-validation threshold):"
        )
        lines += ["", caption, "", "| Class | Test flows | Recall |", "|-------|------:|------:|"]
        for name, found in sorted(point["per_class_recall"].items()):
            lines.append(
                f"| {name} | {found['flows']['mean']:,.0f} | "
                f"{_stat(found['recall'], percent=True, digits=1)} |"
            )
    return "\n".join(lines)


def render_cross_summary(cross: dict[str, Any] | None) -> str:
    """The README summary of the cross-dataset test (gradient boosting)."""
    if cross is None:
        return "No cross-dataset results yet."
    fpr = cross["target_fprs"][0]
    header = (
        "| Trained on → tested on | ROC-AUC, same dataset | ROC-AUC, other dataset | "
        "PR-AUC (chance), same dataset | PR-AUC (chance), other dataset | "
        f"Benign flows flagged on the other dataset ({_label(fpr)} threshold) |"
    )
    rows = []
    same_roc, other_roc, flagged = [], [], []
    for key, direction in cross["directions"].items():
        if "hgb" not in direction["models"]:
            continue
        summary = direction["models"]["hgb"]["summary"]
        same, other = summary["in_dataset"], summary["cross_dataset"]
        point = _point(other, fpr)
        same_roc.append(f"{same['roc_auc']['mean']:.2f}")
        other_roc.append(f"{other['roc_auc']['mean']:.2f}")
        flagged.append(point["fpr"]["mean"] * 100)
        rows.append(
            f"| {key.replace('->', ' → ')} | {same['roc_auc']['mean']:.3f} | "
            f"{other['roc_auc']['mean']:.3f} | {same['pr_auc']['mean']:.3f} "
            f"({same['prevalence']['mean']:.2f}) | {other['pr_auc']['mean']:.3f} "
            f"({other['prevalence']['mean']:.2f}) | {point['fpr']['mean'] * 100:.1f} % |"
        )
    lines = []
    if rows:
        sentence = (
            f"Trained on the {len(cross['features'])} features both datasets share and tested on "
            f"the *other* dataset, gradient boosting's ROC-AUC falls from {' and '.join(same_roc)} "
            f"to {' and '.join(other_roc)}, weak but above chance, and the threshold that gave "
            f"{_label(fpr)} false positives at home flags {min(flagged):.0f} % to "
            f"{max(flagged):.0f} % of the other dataset's benign flows:"
        )
        lines += [sentence, ""]
    lines += [header, "|------------------------|" + "------:|" * 5, *rows]
    note = (
        "Gradient boosting, means over seeds "
        f"{', '.join(map(str, cross['seeds']))}. ROC-AUC: 0.5 is chance. PR-AUC: chance is "
        "the attack share, in brackets."
    )
    lines += ["", note]
    return "\n".join(lines)


def _caught(found: dict[str, Any]) -> str:
    return f"{found['attacks_caught']}/{found['attacks']}"


def _precision_text(found: dict[str, Any]) -> str:
    return "no alerts" if found["precision"] is None else f"{found['precision'] * 100:.0f} %"


def render_anomaly(results: dict[str, Any]) -> str:
    """The tables for docs/ANOMALY.md."""
    default, heldout = results["variants"]["default"], results["variants"]["heldout"]
    seeds = results["seeds"]
    intro = (
        f"Generated by `python -m prohori.ml.logeval`: {len(results['scenarios'])} scenarios, "
        f"seeds {seeds[0]} to {seeds[-1]} per variant, "
        f"{results['window_minutes']}-minute windows. Do not edit by hand."
    )
    header = (
        "| Detector | Attacks caught, default | Attacks caught, held-out | "
        "Precision, default | Precision, held-out | False alerts a run, held-out |"
    )
    lines = [intro, "", header, "|----------|------:|------:|------:|------:|------:|"]
    for name, found in heldout["detectors"].items():
        dev = default["detectors"][name]
        lines.append(
            f"| {DETECTOR_NAMES.get(name, name)} | {_caught(dev)} | {_caught(found)} | "
            f"{_precision_text(dev)} | {_precision_text(found)} | "
            f"{found['false_alerts_per_run']} |"
        )
    names = list(heldout["detectors"])
    columns = " | ".join(DETECTOR_NAMES.get(n, n) for n in names)
    caption = "Attacks caught in the held-out variants, by scenario:"
    lines += [
        "",
        caption,
        "",
        f"| Scenario | {columns} |",
        "|----------|" + "------:|" * len(names),
    ]
    for scenario in results["scenarios"]:
        counts = []
        for name in names:
            found = heldout["detectors"][name]
            per_run = found["attacks"] // heldout["runs"] if heldout["runs"] else 0
            total = per_run * len(seeds)
            counts.append(f"{found['caught_by_scenario'].get(scenario, 0)}/{total}")
        lines.append(f"| {scenario} | {' | '.join(counts)} |")
    versus = (
        "Against the rules in the held-out variants (an attack counts once however many "
        "detectors catch it):"
    )
    versus_header = (
        "| Detector | Caught by rules | Caught by the detector | Caught by either | "
        "Only the detector | Only the rules |"
    )
    lines += ["", versus, "", versus_header, "|----------|------:|------:|------:|------:|------:|"]
    for name, found in heldout["versus_rules"].items():
        lines.append(
            f"| {DETECTOR_NAMES.get(name, name)} | {found['caught_by_rules']} | "
            f"{found['caught_by_model']} | {found['caught_by_either']} | "
            f"{found['caught_by_model_only']} | {found['caught_by_rules_only']} |"
        )
    selection = (
        "Cut-off selection on the default variants (window-level precision, recall and F1; the "
        "chosen cut-off is in bold):"
    )
    lines += ["", selection, "", "| Detector | Cut-off | Precision | Recall | F1 |"]
    lines.append("|----------|------:|------:|------:|------:|")
    for name, found in results["cutoff_selection_on_default"].items():
        for row in found["candidates"]:
            mark = "**" if row["cutoff"] == found["chosen"] else ""
            lines.append(
                f"| {DETECTOR_NAMES.get(name, name)} | {mark}{row['cutoff']:g}{mark} | "
                f"{row['precision']:.3f} | {row['recall']:.3f} | {row['f1']:.3f} |"
            )
    return "\n".join(lines)


def render_anomaly_summary(results: dict[str, Any] | None) -> str:
    """The README summary of the log anomaly evaluation (held-out variants)."""
    if results is None:
        return "No anomaly results yet."
    heldout = results["variants"]["heldout"]
    header = "| Detector | Attacks caught | Precision | False alerts a run | Caught only by it |"
    lines = [header, "|----------|------:|------:|------:|------:|"]
    for name, found in heldout["detectors"].items():
        only = (
            "-" if name == "rules" else str(heldout["versus_rules"][name]["caught_by_model_only"])
        )
        lines.append(
            f"| {DETECTOR_NAMES.get(name, name)} | {_caught(found)} | {_precision_text(found)} | "
            f"{found['false_alerts_per_run']} | {only} |"
        )
    note = (
        f"Held-out variants, seeds {results['seeds'][0]} to {results['seeds'][-1]}; an attack is "
        "caught when a true-positive alert is credited to it. Any rule counts here, which is why "
        "the rules catch one attack more than in the expected-rule count above."
    )
    lines += ["", note]
    return "\n".join(lines)


def _systems(results: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """The evaluated LLM systems: the baselines first, then any real model."""
    order = {name: n for n, name in enumerate(LLM_ORDER)}
    return sorted(results["systems"].items(), key=lambda s: (order.get(s[0], len(order)), s[0]))


def _ratio(found: dict[str, int] | None, part: str, whole: str) -> str:
    return "-" if found is None else f"{found[part]}/{found[whole]}"


def _real_models(results: dict[str, Any]) -> list[str]:
    return [s for s in results["systems"] if s not in LLM_BASELINES]


def render_llm(results: dict[str, Any]) -> str:
    """The tables for docs/LLM_ANALYST.md."""
    kinds = results["kinds"]
    intro = (
        f"Generated from `results/llm_eval.json` by `python -m prohori.llm.evaluate score`: "
        f"{results['cases']} cases ({kinds['attack']} attacks, {kinds['benign']} false positives, "
        f"{kinds['injection']} injections). Do not edit by hand."
    )
    lines = [intro, ""]
    if not _real_models(results):
        note = (
            "**No real model has been recorded yet.** The rows below are baselines: the local "
            "summary, the offline mock (a template filled from the payload, so it cannot make "
            "up a value) and a scripted model that obeys every injection. They test the "
            "pipeline and the scorer, not the quality of a language model."
        )
        lines += [note, ""]
    header = (
        "| System | Answers | Accepted by the checks | With a factual error (model / shown) | "
        "Indicators named (model / shown) | Points covered (model / shown) | Stale |"
    )
    lines += [header, "|--------|------:|------:|------:|------:|------:|------:|"]
    for _, found in _systems(results):
        model, shown = found["model_answer"], found["shown"]
        accepted = "-" if found["accepted"] is None else f"{found['accepted']}/{found['cases']}"
        lines.append(
            f"| {found['label']} | {found['cases']} | {accepted} | "
            f"{_ratio(model, 'with_errors', 'answers')} / {_ratio(shown, 'with_errors', 'answers')}"
            f" | {_ratio(model, 'indicators_named', 'indicators')} / "
            f"{_ratio(shown, 'indicators_named', 'indicators')} | "
            f"{_ratio(model, 'points_covered', 'points')} / "
            f"{_ratio(shown, 'points_covered', 'points')} | {found['stale']} |"
        )
    names = [
        name
        for name, found in _systems(results)
        if found["injection"] and found["injection"]["followed_by_model"] is not None
    ]
    vectors = results["injection_vectors"]
    caption = (
        "Injections, by case: whether the injected text reached the model at all (always inside "
        "a fence), then for each system whether its answer followed the injection and whether "
        "that reached the analyst."
    )
    lines += [
        "",
        caption,
        "",
        "| Case | Hidden in | Reached the model | "
        + " | ".join(results["systems"][n]["label"] for n in names)
        + " |",
        "|------|-----------|------|" + "------|" * len(names),
    ]
    for case, vector in vectors.items():
        reached = None
        cells = []
        for name in names:
            found = results["per_case"][name].get(case)
            if found is None:
                cells.append("not recorded")
                continue
            injection = found["injection"]
            reached = injection["reached_model"]
            followed, shown = injection["followed_by_model"], injection["shown_to_analyst"]
            if followed is None:
                cells.append("shown" if shown else "-")
            elif not followed:
                cells.append("ignored")
            else:
                cells.append("followed, **shown**" if shown else "followed, stopped")
        lines.append(f"| {case} | {vector} | {'yes' if reached else 'no'} | {' | '.join(cells)} |")
    return "\n".join(lines)


def render_llm_summary(results: dict[str, Any] | None) -> str:
    """The README summary of the LLM analyst evaluation."""
    if results is None:
        return "No LLM evaluation results yet."
    kinds = results["kinds"]
    cases = (
        f"{results['cases']} cases: {kinds['attack']} attacks, {kinds['benign']} false positives "
        f"and {kinds['injection']} incidents with a hidden instruction."
    )
    lines = [cases, ""]
    if not _real_models(results):
        note = (
            "No real model has been evaluated yet; the scripted rows below test the safeguards, "
            "not a language model."
        )
        lines += [note, ""]
    header = (
        "| Model | Recorded | Answers accepted | With a factual error | Indicators named | "
        "Points covered |"
    )
    for name in _real_models(results):
        found = results["systems"][name]
        model = found["model_answer"]
        lines += [
            header,
            "|-------|----------|------:|------:|------:|------:|",
            f"| {found['label']} | {found['recorded']} | {found['accepted']}/{found['cases']} | "
            f"{_ratio(model, 'with_errors', 'answers')} | "
            f"{_ratio(model, 'indicators_named', 'indicators')} | "
            f"{_ratio(model, 'points_covered', 'points')} |",
            "",
        ]
        missing = results["cases"] - found["cases"]
        if found["stale"] or missing:
            lines += [
                f"{found['label']} answered {found['cases']} of the {results['cases']} cases; "
                f"{found['stale']} of its answers were recorded for an older version of their "
                "incident and are replayed against today's, which can count as errors the "
                "original answer did not make. Recording again needs an API key.",
                "",
            ]
    lines += [
        "| System | Injections the answer followed | Followed and shown to the analyst |",
        "|--------|------:|------:|",
    ]
    for _, found in _systems(results):
        injection = found["injection"]
        if injection is None or injection["followed_by_model"] is None:
            continue
        lines.append(
            f"| {found['label']} | {injection['followed_by_model']}/{injection['cases']} | "
            f"{injection['shown_to_analyst']}/{injection['cases']} |"
        )
    local = results["per_case"].get("local", {})
    vectors = results["injection_vectors"]
    reached = {
        vectors[c] for c in vectors if local.get(c, {}).get("injection", {}).get("reached_model")
    }
    if local and vectors:
        count = sum(bool(local[c]["injection"]["reached_model"]) for c in vectors if c in local)
        never = sorted(set(vectors.values()) - reached)
        sentence = f"{count} of the {len(vectors)} injected texts reached the model at all"
        if reached:
            sentence += f", always fenced ({', '.join(sorted(reached))})"
        if never:
            sentence += f"; those in a {' or a '.join(never)} never did"
        lines += ["", sentence + "."]
    return "\n".join(lines)


RUN_NAMES = {
    "incidents-access_log": "`incidents`, nginx/Apache access log",
    "incidents-auth_log": "`incidents`, auth.log (sshd)",
    "incidents-app_json": "`incidents`, JSON Lines app log",
    "pipeline-replay": "`pipeline replay` (lite mode), access log",
    "demo": "`demo`",
}


def _mib(found: dict[str, Any], key: str) -> str:
    return f"{found[key] / 2**20:,.0f} MiB"


def render_performance(results: dict[str, Any]) -> str:
    """The tables for docs/PERFORMANCE.md."""
    machine = results["machine"]
    intro = (
        f"Generated from `results/performance.json` by `scripts/benchmark.py`, run on "
        f"{results['date']} with Prohori {machine['prohori']} and Python {machine['python']} on "
        f"{machine['system']} ({machine['machine']}, {machine['cpus']} logical CPUs, "
        f"{machine['processor']}). Do not edit by hand."
    )
    lines = [
        intro,
        "",
        "| Run | Lines | Size | Time | Lines a second | Peak memory | Exit code |",
        "|-----|------:|-----:|-----:|------:|------:|------:|",
    ]
    for run in results["runs"]:
        name = RUN_NAMES.get(run["name"], run["name"])
        if "lines" in run:
            lines.append(
                f"| {name} | {run['lines']:,} | {_mib(run, 'bytes')} | {run['seconds']:,.1f} s | "
                f"{run['lines_per_second']:,} | {run['peak_memory_mib']:,.0f} MiB | "
                f"{run['exit_code']} |"
            )
        else:
            lines.append(
                f"| {name} | - | - | {run['seconds']:,.1f} s | - | "
                f"{run['peak_memory_mib']:,.0f} MiB | {run['exit_code']} |"
            )
    states = [r for r in results["runs"] if "state_bytes" in r]
    for run in states:
        lines += [
            "",
            f"Lite mode's state directory (topics, positions and the DuckDB warehouse) grew to "
            f"{_mib(run, 'state_bytes')} for the {_mib(run, 'bytes')} log; its topics are not "
            "trimmed.",
        ]
    storm = results.get("alert_storm")
    if storm is not None:
        lines += ["", *_storm_lines(storm)]
    return "\n".join(lines)


STORM_NAMES = {
    "storm-detect-json": "`detect -f json` (writes each alert as it is raised)",
    "storm-detect-table": "`detect` table (shows the first 100, counts the rest)",
    "storm-incidents": "`incidents` (keeps a bounded number of alerts)",
}


def _storm_lines(storm: dict[str, Any]) -> list[str]:
    """The alert-storm table: memory must not grow with the number of alerts."""
    raised = max((r["alerts"] or 0 for r in storm["runs"]), default=0)
    lines = [
        f"**Alert storm** ({storm['date']}): an application log of {storm['alerts']:,} lines in "
        f"which every line raises at least one alert ({raised:,} in all). Every run must stay "
        f"under {storm['bound_mib']:,} MiB of peak memory.",
        "",
        "| Run | Time | Peak memory | Alerts not kept | Within the bound |",
        "|-----|-----:|------:|------:|-----|",
    ]
    for run in storm["runs"]:
        within = run["within_bound"] and run["exit_code"] == 0
        lines.append(
            f"| {STORM_NAMES.get(run['name'], run['name'])} | {run['seconds']:,.1f} s | "
            f"{run['peak_memory_mib']:,.0f} MiB | {run['alerts_not_kept']:,} | "
            f"{'yes' if within else 'no'} |"
        )
    return lines


def render_performance_summary(results: dict[str, Any] | None) -> str:
    """The README summary of the performance measurements."""
    if results is None:
        return "No performance results yet."
    runs = {r["name"]: r for r in results["runs"]}
    batch = [r for r in results["runs"] if r["name"].startswith("incidents-")]
    lines = [
        "| Run | Lines | Lines a second | Peak memory |",
        "|-----|------:|------:|------:|",
    ]
    for run in results["runs"]:
        if "lines" in run:
            lines.append(
                f"| {RUN_NAMES.get(run['name'], run['name'])} | {run['lines']:,} | "
                f"{run['lines_per_second']:,} | {run['peak_memory_mib']:,.0f} MiB |"
            )
    machine = results["machine"]
    note = (
        f"One run each on {machine['system']} with {machine['cpus']} logical CPUs, Python "
        f"{machine['python']}, offline enrichment"
    )
    if "demo" in runs:
        note += f"; `prohori demo` took {runs['demo']['seconds']:.1f} s"
    if batch:
        note += f". The batch command peaked at {max(r['peak_memory_mib'] for r in batch):,.0f} MiB"
    lines += ["", note + "."]
    return "\n".join(lines)


def render_example(incident: dict[str, Any], log: Path) -> str:
    """The README's worked example, from the sample incident and the log it was built from."""
    from prohori.rules.attack import TECHNIQUES

    ip = incident["entities"]["source.ip"][0]
    failures = []
    for line in log.read_text(encoding="utf-8").splitlines():
        event = json.loads(line)
        if event.get("source", {}).get("ip") == ip and event["event"]["outcome"] == "failure":
            failures.append(datetime.fromisoformat(event["time"]))
    span = (max(failures) - min(failures)).total_seconds() if failures else 0
    intro = (
        f"`{log.relative_to(ROOT).as_posix()}` is a synthetic attack on a web shop account: "
        f"{len(failures)} wrong passwords from one IP in {span:.0f} seconds, a successful "
        "sign-in, two-step verification switched off and the bKash payout number changed. "
        f"Prohori raises {len(incident['alerts'])} alerts and joins them into **one "
        f"{incident['severity']} incident**:"
    )
    first = datetime.fromisoformat(incident["first_seen"])
    last = datetime.fromisoformat(incident["last_seen"])
    rules = sorted({a["detector_id"] for a in incident["alerts"]})
    entities = [f"{k}: {v}" for k, vs in incident["entities"].items() for v in vs]
    summary = [
        f"{incident['id']}  {incident['severity']}  score {incident['score']:g}",
        f"title       {incident['title']}",
        f"time (UTC)  {first:%Y-%m-%d %H:%M:%S} - {last:%Y-%m-%d %H:%M:%S}",
        f"confidence  {incident['confidence']}",
        f"rules       {', '.join(rules)}",
        f"entities    {entities[0]}",
        *(f"            {e}" for e in entities[1:]),
    ]
    points = [f"| {c['points']:+g} | {c['reason']} |" for c in incident["score_breakdown"]]
    techniques = [
        f"{t.removeprefix('attack.').upper()} {TECHNIQUES[t].name}"
        for t in incident["attack"]
        if t.startswith("attack.t") and t in TECHNIQUES
    ]
    outro = (
        f"The report adds the timeline, the IP's enrichment, the ATT&CK techniques "
        f"({', '.join(techniques)}), recommended actions from the runbooks and the limitations, "
        'such as "single log source" and "enrichment is bundled demo data".'
    )
    return "\n".join(
        [
            intro,
            "",
            "```text",
            *summary,
            "```",
            "",
            "Every point of the score is explained (from `prohori report`):",
            "",
            "| Points | Reason |",
            "|-------:|--------|",
            *points,
            f"| **{incident['score']:g}** | **Total** |",
            "",
            outro,
        ]
    )


def ml_results(directory: Path) -> list[dict[str, Any]]:
    """The model results present in ``directory``, in documentation order."""
    found = []
    for name in ML_DATASETS:
        path = directory / f"ml_{name}.json"
        if path.is_file():
            found.append(json.loads(path.read_text(encoding="utf-8")))
    return found


def updated(
    document: str, block: str, name: str, start_marker: str = START, end_marker: str = END
) -> str:
    start, end = document.find(start_marker), document.find(end_marker)
    if start < 0 or end < start:
        msg = f"{name} has no {start_marker} ... {end_marker} block"
        raise SystemExit(msg)
    return document[: start + len(start_marker)] + "\n" + compact(block) + "\n" + document[end:]


_DELIMITER_ROW = re.compile(r"^\|(?:\s*:?-+:?\s*\|)+$")


def compact(block: str) -> str:
    """Table delimiter rows in the docs' style, one space inside each pipe: ``| --- | --: |``."""
    lines = block.split("\n")
    for index, line in enumerate(lines):
        if _DELIMITER_ROW.match(line):
            cells = [cell.strip() for cell in line.strip("|").split("|")]
            lines[index] = "| " + " | ".join(cells) + " |"
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="only check that the docs are current")
    args = parser.parse_args(argv)
    results = json.loads(RESULTS.read_text(encoding="utf-8"))
    models = ml_results(RESULTS.parent)
    card = "\n\n".join(render_ml(r) for r in models) or "No model results yet."
    adapt_path = RESULTS.parent / "ml_adapt.json"
    adapt = json.loads(adapt_path.read_text(encoding="utf-8")) if adapt_path.is_file() else None
    cross_path = RESULTS.parent / "ml_cross.json"
    cross = json.loads(cross_path.read_text(encoding="utf-8")) if cross_path.is_file() else None
    cross_card = render_cross(cross, models) if cross else "No cross-dataset results yet."
    logs_path = RESULTS.parent / "ml_logs.json"
    logs = json.loads(logs_path.read_text(encoding="utf-8")) if logs_path.is_file() else None
    llm_path = RESULTS.parent / "llm_eval.json"
    llm = json.loads(llm_path.read_text(encoding="utf-8")) if llm_path.is_file() else None
    example = json.loads(EXAMPLE_INCIDENT.read_text(encoding="utf-8"))
    perf_path = RESULTS.parent / "performance.json"
    perf = json.loads(perf_path.read_text(encoding="utf-8")) if perf_path.is_file() else None
    blocks = (
        (DOCUMENT, render(results), START, END),
        (README, render_summary(results), START, END),
        (RULES_DOCUMENT, render_comparison(results), COMPARE_START, COMPARE_END),
        (MODEL_CARD, card, ML_START, ML_END),
        (README, render_ml_summary(models), ML_START, ML_END),
        (MODEL_CARD, render_calibration(models), CALIBRATION_START, CALIBRATION_END),
        (
            MODEL_CARD,
            render_adapt(adapt) if adapt else "No cross-dataset study results yet.",
            ADAPT_START,
            ADAPT_END,
        ),
        (README, render_adapt_summary(adapt), ADAPT_START, ADAPT_END),
        (MODEL_CARD, cross_card, CROSS_START, CROSS_END),
        (README, render_cross_summary(cross), CROSS_START, CROSS_END),
        (
            ANOMALY_DOCUMENT,
            render_anomaly(logs) if logs else "No anomaly results yet.",
            ANOMALY_START,
            ANOMALY_END,
        ),
        (README, render_anomaly_summary(logs), ANOMALY_START, ANOMALY_END),
        (
            LLM_DOCUMENT,
            render_llm(llm) if llm else "No LLM evaluation results yet.",
            LLM_START,
            LLM_END,
        ),
        (README, render_llm_summary(llm), LLM_START, LLM_END),
        (README, render_example(example, EXAMPLE_LOG), EXAMPLE_START, EXAMPLE_END),
        (
            PERF_DOCUMENT,
            render_performance(perf) if perf else "No performance results yet.",
            PERF_START,
            PERF_END,
        ),
        (README, render_performance_summary(perf), PERF_START, PERF_END),
    )
    stale: list[str] = []
    for path, block, start, end in blocks:
        document = path.read_text(encoding="utf-8")
        new = updated(document, block, path.name, start, end)
        if new == document:
            continue
        stale.append(path.name)
        if not args.check:
            path.write_text(new, encoding="utf-8", newline="\n")
            print(f"updated {path}")
    if args.check and stale:
        print(
            f"out of date: {', '.join(stale)}; run scripts/generate_results_table.py",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
