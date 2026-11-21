# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
# Copyright (c) 2026 Utsha Basak
"""Build the cross-dataset paper (step 30c) from its template and the committed results.

Every number in ``docs/research/cross-dataset-generalisation.md`` comes from ``results/``:
the template ``docs/research/src/cross-dataset-generalisation.md.in`` holds the prose with
``{{name}}`` placeholders and ``{{table:name}}`` tables, and never a number of its own (a test
checks that). The figures in ``docs/research/figures/`` are SVG written here too.

    uv run python scripts/build_paper.py           # write the paper and its figures
    uv run python scripts/build_paper.py --check   # fail if they are out of date

The LaTeX and PDF versions are built by the ``paper`` workflow with pandoc (see
``docs/research/README.md``).
"""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"
RESEARCH = ROOT / "docs" / "research"
TEMPLATE = RESEARCH / "src" / "cross-dataset-generalisation.md.in"
PAPER = RESEARCH / "cross-dataset-generalisation.md"
FIGURES = RESEARCH / "figures"
DIRECTIONS = {"u2c": "unsw-nb15->cicids2017", "c2u": "cicids2017->unsw-nb15"}
DIRECTION_NAMES = {"u2c": "UNSW-NB15 → CIC-IDS-2017", "c2u": "CIC-IDS-2017 → UNSW-NB15"}
ARM_KEYS = {
    "baseline": "baseline",
    "standardise": "standardise",
    "quantile": "quantile",
    "quantile-protocol": "qprotocol",
    "coral": "coral",
    "importance": "importance",
    "invariant": "invariant",
    "few-shot-10": "k10",
    "few-shot-50": "k50",
    "few-shot-100": "k100",
    "target-reference": "reference",
}
ARM_LABELS = {
    "baseline": "Baseline",
    "standardise": "Per-domain log standardisation",
    "quantile": "Per-domain quantile map",
    "quantile-protocol": "Per-domain, per-protocol quantile map",
    "coral": "CORAL",
    "importance": "Importance weighting",
    "invariant": "Domain-invariant feature selection",
    "few-shot-10": "10 labelled target flows",
    "few-shot-50": "50 labelled target flows",
    "few-shot-100": "100 labelled target flows",
    "target-reference": "Trained on the target (reference)",
}
PLACEHOLDER = re.compile(r"\{\{([a-z0-9_.:-]+)\}\}")


def _load(name: str) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((RESULTS / name).read_text(encoding="utf-8"))
    return data


def _pct(value: float, digits: int = 1) -> str:
    return f"{value * 100:.{digits}f} %"


def _range(pair: list[float]) -> str:
    return f"{pair[0]:.3f} to {pair[1]:.3f}"


def _signed_range(pair: list[float]) -> str:
    return f"{pair[0]:+.3f} to {pair[1]:+.3f}"


def values() -> dict[str, str]:
    """Every named value the template may use, already formatted."""
    adapt = _load("ml_adapt.json")
    cross = _load("ml_cross.json")
    unsw = _load("ml_unsw-nb15.json")
    cic = _load("ml_cicids2017.json")
    found: dict[str, str] = {
        "seeds": ", ".join(map(str, adapt["seeds"])),
        "seed_count": str(len(adapt["seeds"])),
        "resamples": f"{adapt['resamples']:,}",
        "target_fpr": _pct(adapt["target_fpr"], 0),
        "ci_level": "95 %",  # the interval level fixed in ADR-0041 (adapt.interval's default)
        "prohori_version": adapt["prohori_version"],
        "sklearn": unsw["libraries"]["scikit-learn"],
        "numpy": unsw["libraries"]["numpy"],
        "pandas": unsw["libraries"]["pandas"],
        "feature_count": str(len(adapt["features"])),
        "max_iter": str(adapt["params"]["max_iter"]),
        "learning_rate": str(adapt["params"]["learning_rate"]),
    }
    for name, results in (("unsw", unsw), ("cic", cic)):
        summary = results["variants"]["cleaned"]["models"]["hgb"]["summary"]
        found[f"{name}.full_auc"] = f"{summary['roc_auc']['mean']:.3f}"
        found[f"{name}.full_features"] = str(
            results["variants"]["cleaned"]["cleaning"][0]["features"]
        )
    for name, dataset in (("unsw", "unsw-nb15"), ("cic", "cicids2017")):
        rows = cross["cleaning"][dataset][0]["rows"]
        for split, count in rows.items():
            found[f"{name}.{split}_rows"] = f"{count:,}"
    for key, direction in DIRECTIONS.items():
        summary = cross["directions"][direction]["models"]["hgb"]["summary"]
        found[f"{key}.common_in_auc"] = f"{summary['in_dataset']['roc_auc']['mean']:.3f}"
        study = adapt["directions"][direction]
        for arm, short in ARM_KEYS.items():
            entry = study["arms"][arm]
            mean = entry["mean"]
            prefix = f"{key}.{short}"
            found[f"{prefix}.auc"] = f"{mean['roc_auc']:.3f}"
            found[f"{prefix}.auc_ci"] = _range(entry["roc_auc_interval"])
            found[f"{prefix}.diff"] = f"{entry['roc_auc_difference']:+.3f}"
            found[f"{prefix}.diff_ci"] = _signed_range(entry["roc_auc_difference_interval"])
            found[f"{prefix}.pr"] = f"{mean['pr_auc']:.3f}"
            found[f"{prefix}.chance"] = f"{mean['prevalence']:.2f}"
            found[f"{prefix}.recall_src"] = _pct(mean["recall_frozen"])
            found[f"{prefix}.fpr_src"] = _pct(mean["fpr_frozen"])
            found[f"{prefix}.recall_tgt"] = _pct(mean["recall_at_target_fpr"])
            gap = entry["gap_closed"]
            found[f"{prefix}.gap"] = "-" if gap is None else _pct(gap, 0)
        diag = study["diagnostics"]

        def avg(name: str, rows: list[dict[str, Any]] = diag) -> float:
            return float(sum(r[name] for r in rows) / len(rows))

        found[f"{key}.domain_auc"] = f"{avg('domain_auc'):.3f}"
        found[f"{key}.ess"] = _pct(avg("effective_sample_share"))
        found[f"{key}.clipped"] = _pct(avg("clipped_share"))
        found[f"{key}.pool_attack"] = _pct(avg("pool_attack_share"), 0)
        found[f"{key}.source_attack"] = _pct(avg("source_attack_share"), 0)
        found[f"{key}.dropped"] = str(len({f for r in diag for f in r["invariant_dropped"]}))
    aucs = [
        auc
        for direction in adapt["directions"].values()
        for row in direction["diagnostics"]
        for auc in row["feature_domain_auc"].values()
    ]
    found["feature_auc_min"] = f"{min(aucs):.2f}"
    found["feature_auc_max"] = f"{max(aucs):.2f}"
    methods = [a for a in ARM_KEYS if a not in ("baseline", "target-reference")]
    found["helping"] = ", ".join(
        ARM_LABELS[a].lower() for a in methods if adapt["helps"][a]["improves_both_directions"]
    )
    found["helping_unsupervised"] = ", ".join(
        ARM_LABELS[a].lower()
        for a in methods
        if adapt["helps"][a]["improves_both_directions"] and not a.startswith("few-shot")
    )
    return found


def _results_table(key: str, data: dict[str, str]) -> str:
    rows = [
        "| Arm | ROC-AUC (95 % CI) | Difference to baseline (95 % CI) | PR-AUC (chance) | "
        "Recall / FPR at the source threshold | Recall at the target FPR on target |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for arm, short in ARM_KEYS.items():
        p = f"{key}.{short}"
        difference = "-" if arm == "baseline" else f"{data[p + '.diff']} ({data[p + '.diff_ci']})"
        rows.append(
            f"| {ARM_LABELS[arm]} | {data[p + '.auc']} ({data[p + '.auc_ci']}) | {difference} "
            f"| {data[p + '.pr']} ({data[p + '.chance']}) | {data[p + '.recall_src']} / "
            f"{data[p + '.fpr_src']} | {data[p + '.recall_tgt']} |"
        )
    return "\n".join(rows)


def _diagnostics_table(data: dict[str, str]) -> str:
    rows = [
        "| Direction | Source attack share | Pool attack share | Domain classifier ROC-AUC | "
        "Effective sample share | Weights at a clip | Features dropped |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for key, name in DIRECTION_NAMES.items():
        rows.append(
            f"| {name} | {data[key + '.source_attack']} | {data[key + '.pool_attack']} | "
            f"{data[key + '.domain_auc']} | {data[key + '.ess']} | {data[key + '.clipped']} | "
            f"{data[key + '.dropped']} |"
        )
    return "\n".join(rows)


def _data_table(data: dict[str, str]) -> str:
    return "\n".join(
        [
            "| Dataset | Train | Validation | Test | All features | ROC-AUC, all features "
            "| ROC-AUC, common features |",
            "| --- | --- | --- | --- | --- | --- | --- |",
            f"| UNSW-NB15 | {data['unsw.train_rows']} | {data['unsw.validation_rows']} | "
            f"{data['unsw.test_rows']} | {data['unsw.full_features']} | {data['unsw.full_auc']} "
            f"| {data['u2c.common_in_auc']} |",
            f"| CIC-IDS-2017 | {data['cic.train_rows']} | {data['cic.validation_rows']} | "
            f"{data['cic.test_rows']} | {data['cic.full_features']} | {data['cic.full_auc']} | "
            f"{data['c2u.common_in_auc']} |",
        ]
    )


def tables(data: dict[str, str]) -> dict[str, str]:
    return {
        "table:data": _data_table(data),
        "table:u2c": _results_table("u2c", data),
        "table:c2u": _results_table("c2u", data),
        "table:diagnostics": _diagnostics_table(data),
    }


# --------------------------------------------------------------------------- figures

SVG_STYLE = (
    "<style>text{font-family:DejaVu Sans,Helvetica,Arial,sans-serif;font-size:12px;fill:#222}"
    ".axis{stroke:#555;stroke-width:1}.grid{stroke:#ccc;stroke-width:1;stroke-dasharray:3 3}"
    ".zero{stroke:#333;stroke-width:1.2}.bar{stroke:#1f5fa8;stroke-width:2}"
    ".dot{fill:#1f5fa8}.few{fill:#b5651d}.fewbar{stroke:#b5651d;stroke-width:2}"
    ".ref{stroke:#2a7a2a;stroke-width:1.5;stroke-dasharray:6 3}"
    ".base{stroke:#777;stroke-width:1.5;stroke-dasharray:2 3}</style>"
)


def _svg(width: int, height: int, body: list[str], title: str) -> str:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img" aria-label="{title}">'
        f'<title>{title}</title><rect width="100%" height="100%" fill="#fff"/>{SVG_STYLE}'
        + "".join(body)
        + "</svg>\n"
    )


def forest_plot(adapt: dict[str, Any]) -> str:
    """ROC-AUC difference to the baseline with 95 % intervals, per arm and direction."""
    arms = [a for a in ARM_KEYS if a not in ("baseline", "target-reference")]
    low, high = -0.2, 0.4
    left, plot_w, row_h, top = 300, 260, 22, 50
    panel_h = top + row_h * len(arms) + 40
    width = left + 2 * (plot_w + 70)
    body: list[str] = []

    def x_of(value: float, panel: int) -> float:
        start = left + panel * (plot_w + 70)
        return start + (min(max(value, low), high) - low) / (high - low) * plot_w

    for i, arm in enumerate(arms):
        y = top + row_h * i + row_h / 2
        body.append(
            f'<text x="{left - 8}" y="{y + 4:.1f}" text-anchor="end">{ARM_LABELS[arm]}</text>'
        )
    for panel, (key, name) in enumerate(DIRECTION_NAMES.items()):
        start = left + panel * (plot_w + 70)
        body.append(f'<text x="{start + plot_w / 2}" y="20" text-anchor="middle">{name}</text>')
        for tick in (-0.2, -0.1, 0.0, 0.1, 0.2, 0.3, 0.4):
            x = x_of(tick, panel)
            css = "zero" if tick == 0 else "grid"
            body.append(
                f'<line class="{css}" x1="{x:.1f}" y1="{top - 10}" x2="{x:.1f}" '
                f'y2="{panel_h - 30}"/>'
            )
            body.append(
                f'<text x="{x:.1f}" y="{panel_h - 14}" text-anchor="middle">{tick:+.1f}</text>'
            )
        study = adapt["directions"][DIRECTIONS[key]]["arms"]
        for i, arm in enumerate(arms):
            y = top + row_h * i + row_h / 2
            entry = study[arm]
            a, b = entry["roc_auc_difference_interval"]
            few = arm.startswith("few-shot")
            body.append(
                f'<line class="{"fewbar" if few else "bar"}" x1="{x_of(a, panel):.1f}" '
                f'y1="{y:.1f}" x2="{x_of(b, panel):.1f}" y2="{y:.1f}"/>'
            )
            body.append(
                f'<circle class="{"few" if few else "dot"}" '
                f'cx="{x_of(entry["roc_auc_difference"], panel):.1f}" '
                f'cy="{y:.1f}" r="4"/>'
            )
    body.append(
        f'<text x="{left + plot_w + 35}" y="{panel_h - 1}" text-anchor="middle">'
        "ROC-AUC difference to the baseline (95 % intervals, mostly narrower than the dots)</text>"
    )
    return _svg(width, panel_h + 6, body, "Figure 1: ROC-AUC difference to the baseline per arm")


def few_shot_plot(adapt: dict[str, Any]) -> str:
    """Target ROC-AUC against the number of labelled target flows, per direction."""
    shots = [("baseline", 0), ("few-shot-10", 10), ("few-shot-50", 50), ("few-shot-100", 100)]
    left, plot_w, plot_h, top = 60, 300, 220, 40
    width = left + 2 * (plot_w + 60)
    height = top + plot_h + 60
    body: list[str] = []

    def x_of(k: int, panel: int) -> float:
        return left + panel * (plot_w + 60) + k / 100 * plot_w

    def y_of(auc: float) -> float:
        return top + (1 - (auc - 0.5) / 0.5) * plot_h

    for panel, (key, name) in enumerate(DIRECTION_NAMES.items()):
        start = left + panel * (plot_w + 60)
        body.append(f'<text x="{start + plot_w / 2}" y="20" text-anchor="middle">{name}</text>')
        for tick in (0.5, 0.6, 0.7, 0.8, 0.9, 1.0):
            y = y_of(tick)
            body.append(
                f'<line class="grid" x1="{start}" y1="{y:.1f}" x2="{start + plot_w}" y2="{y:.1f}"/>'
            )
            body.append(
                f'<text x="{start - 6}" y="{y + 4:.1f}" text-anchor="end">{tick:.1f}</text>'
            )
        for k in (0, 10, 50, 100):
            body.append(
                f'<text x="{x_of(k, panel):.1f}" y="{top + plot_h + 18}" '
                f'text-anchor="middle">{k}</text>'
            )
        arms = adapt["directions"][DIRECTIONS[key]]["arms"]
        points = [(x_of(k, panel), y_of(arms[a]["mean"]["roc_auc"])) for a, k in shots]
        path = " ".join(f"{x:.1f},{y:.1f}" for x, y in points)
        body.append(f'<polyline points="{path}" fill="none" class="fewbar"/>')
        for (arm, _), (x, y) in zip(shots, points, strict=True):
            body.append(
                f'<circle class="few" cx="{x:.1f}" cy="{y:.1f}" r="4"><title>{arm}</title></circle>'
            )
        for arm, css in (("quantile", "base"), ("target-reference", "ref")):
            y = y_of(arms[arm]["mean"]["roc_auc"])
            body.append(
                f'<line class="{css}" x1="{start}" y1="{y:.1f}" '
                f'x2="{start + plot_w}" y2="{y:.1f}"/>'
            )
    body.append(
        f'<text x="{width / 2}" y="{height - 26}" text-anchor="middle">Target ROC-AUC against '
        "labelled target flows k (solid).</text>"
        f'<text x="{width / 2}" y="{height - 8}" text-anchor="middle">Dotted: per-domain '
        "quantile map, no labels. Dashed: trained on the target.</text>"
    )
    return _svg(width, height, body, "Figure 2: target ROC-AUC against labelled target flows")


def render() -> dict[Path, str]:
    """The paper and its figures, keyed by the path each is written to."""
    data = values()
    data.update(tables(data))
    template = TEMPLATE.read_text(encoding="utf-8")
    missing = sorted({m for m in PLACEHOLDER.findall(template) if m not in data})
    if missing:
        msg = f"unknown placeholders in {TEMPLATE.name}: {', '.join(missing)}"
        raise KeyError(msg)
    paper = PLACEHOLDER.sub(lambda m: data[m.group(1)], template)
    header = (
        "<!-- Generated by scripts/build_paper.py from "
        "docs/research/src/cross-dataset-generalisation.md.in and results/; do not edit. -->\n"
    )
    adapt = _load("ml_adapt.json")
    return {
        PAPER: header + paper,
        FIGURES / "fig1-roc-auc-difference.svg": forest_plot(adapt),
        FIGURES / "fig2-few-shot.svg": few_shot_plot(adapt),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="fail if the outputs are stale")
    args = parser.parse_args(argv)
    stale = []
    for path, text in render().items():
        current = path.read_text(encoding="utf-8") if path.is_file() else None
        if current == text:
            continue
        stale.append(path.name)
        if not args.check:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8", newline="\n")
            print(f"wrote {path.relative_to(ROOT)}")
    if args.check and stale:
        print(f"out of date: {', '.join(stale)}; run scripts/build_paper.py", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
