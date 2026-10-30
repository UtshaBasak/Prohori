"""Train and evaluate the flow detectors and write ``results/ml_<dataset>.json``.

For every seed, variant and model:

1. Prepare the data (:mod:`prohori.ml.cleaning`); the seed drives the split and the model.
2. Fit the model on the training split.
3. Score the validation split and choose one threshold per target false-positive rate on its
   benign flows. The thresholds are then frozen.
4. Score the test split **once** with the frozen thresholds and record every metric.

Variants: ``cleaned`` (every leakage control), ``uncleaned`` (no deduplication or overlap
removal, numeric identifiers and ports kept, to show what the controls change) and, for datasets
with suspect columns, ``cleaned-no-suspect``. Results are summarised as mean and standard
deviation over the seeds. Cleaned models are saved to ``--models-dir`` (git-ignored) unless
``--no-save``.

    uv run python -m prohori.ml.train --dataset unsw-nb15 --seeds 0 1 2
"""

import argparse
import json
import sys
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from prohori.ml import MissingExtraError

try:
    import numpy as np
    import pandas as pd
    import sklearn
except ImportError as exc:  # pragma: no cover - exercised in a subprocess test
    raise MissingExtraError("prohori.ml.train") from exc

from prohori.ml.cleaning import CATEGORY, LABEL, Prepared, prepare_frames
from prohori.ml.datasets import DEFAULT_DATA_DIR, DatasetMissingError, load
from prohori.ml.evaluate import TARGET_FPRS, evaluate, point_name, summarise, threshold_for_fpr
from prohori.ml.models import MODELS, PARAMS, UNSAFE_PICKLE_WARNING, Detector, fit, save_model
from prohori.ml.registry import DATASETS, Dataset, get_dataset
from prohori.version import __version__

RESULTS_FORMAT = "prohori.ml-eval/1"
DEFAULT_SEEDS = (0, 1, 2)
DEFAULT_MODELS_DIR = Path("models")
CAVEAT = (
    "Lab datasets captured in 2015 (UNSW-NB15) and 2017 (CIC-IDS-2017). Scores on them say "
    "little about a real network today; the cross-dataset test (step 16) measures how badly the "
    "models transfer. Thresholds were chosen on the validation split and the test split was "
    "scored once. The uncleaned variant shows what the same pipeline reports without the "
    "leakage controls and is not a usable model."
)

Log = Callable[[str], None]
#: Significant digits kept in the results file.
DIGITS = 6


def rounded(node: Any) -> Any:  # noqa: ANN401 - any JSON value
    """Round every float to ``DIGITS`` significant digits, keeping the results file small."""
    if isinstance(node, dict):
        return {key: rounded(value) for key, value in node.items()}
    if isinstance(node, list):
        return [rounded(value) for value in node]
    if isinstance(node, float):
        return float(f"{node:.{DIGITS}g}")
    return node


def variants(dataset: Dataset) -> tuple[str, ...]:
    names = ["cleaned", "uncleaned"]
    if dataset.suspect_columns:
        names.append("cleaned-no-suspect")
    return tuple(names)


def _prepare(
    dataset: Dataset, frames: dict[str, pd.DataFrame], seed: int, variant: str
) -> Prepared:
    return prepare_frames(
        dataset,
        frames,
        seed=seed,
        clean=variant != "uncleaned",
        drop_suspect=variant == "cleaned-no-suspect",
    )


def _cleaning_summary(prepared: Prepared) -> dict[str, Any]:
    report = prepared.report
    return {
        "seed": report.seed,
        "rows": report.rows,
        "duplicates_removed": sum(report.duplicates_removed.values()),
        "conflicting_removed": sum(report.conflicting_removed.values()),
        "overlap_removed": sum(report.overlap_removed.values()),
        "attempted_relabelled": report.attempted_relabelled,
        "features": len(prepared.features),
        "columns_dropped": report.columns_dropped,
    }


def run_model(
    prepared: Prepared, name: str, seed: int, fprs: Sequence[float]
) -> tuple[dict[str, Any], Detector, float]:
    """Fit, freeze thresholds on validation, score test once. Returns results, model, seconds."""
    x_train = prepared.x("train")
    started = time.perf_counter()
    detector = fit(name, x_train, prepared.y("train"), seed=seed, categorical=prepared.categorical)
    seconds = time.perf_counter() - started
    del x_train

    validation = prepared.validation
    val_scores = detector.scores(prepared.x("validation"))
    benign = validation[LABEL].to_numpy() == 0
    thresholds = {point_name(f): threshold_for_fpr(val_scores[benign], f) for f in fprs}
    val_result = evaluate(validation[LABEL], val_scores, validation[CATEGORY], thresholds)
    for point in val_result["operating_points"].values():
        del point["per_class_recall"]  # reported for the test split only

    # Thresholds are frozen from here on; the test split is scored exactly once.
    test = prepared.test
    test_scores = detector.scores(prepared.x("test"))
    test_result = evaluate(test[LABEL], test_scores, test[CATEGORY], thresholds)
    result = {"seed": seed, "thresholds": thresholds, "validation": val_result, "test": test_result}
    # Thresholds stay exact: the saved models use them.
    return {**rounded(result), "thresholds": thresholds}, detector, seconds


def run(
    dataset: Dataset,
    data_dir: Path = DEFAULT_DATA_DIR,
    *,
    seeds: Sequence[int] = DEFAULT_SEEDS,
    models: Sequence[str] = MODELS,
    variant_names: Sequence[str] | None = None,
    fprs: Sequence[float] = TARGET_FPRS,
    sample: float | None = None,
    models_dir: Path | None = None,
    log: Log | None = None,
) -> dict[str, Any]:
    """Every seed, variant and model; the results document written by :func:`main`."""
    log = log or (lambda _: None)
    chosen = tuple(variant_names or variants(dataset))
    unknown = sorted(set(chosen) - set(variants(dataset)))
    if unknown:
        msg = f"unknown variant(s) for {dataset.name}: {', '.join(unknown)}"
        raise ValueError(msg)
    found: dict[str, Any] = {
        v: {"cleaning": [], "models": {m: {"runs": []} for m in models}} for v in chosen
    }
    timings: dict[str, dict[str, list[float]]] = {v: {m: [] for m in models} for v in chosen}
    for seed in seeds:
        frames = load(dataset, data_dir, sample=sample, seed=seed).frames
        for variant in chosen:
            prepared = _prepare(dataset, frames, seed, variant)
            found[variant]["cleaning"].append(_cleaning_summary(prepared))
            for name in models:
                log(f"{dataset.name} seed {seed} {variant} {name}: training")
                result, detector, seconds = run_model(prepared, name, seed, fprs)
                found[variant]["models"][name]["runs"].append(result)
                timings[variant][name].append(round(seconds, 1))
                if models_dir is not None and variant == "cleaned":
                    _save(models_dir, dataset, prepared, detector, result, name, seed)
            del prepared
    for variant in chosen:
        for name in models:
            entry = found[variant]["models"][name]
            entry["summary"] = rounded(summarise([r["test"] for r in entry["runs"]]))
    return {
        "format": RESULTS_FORMAT,
        "dataset": dataset.name,
        "dataset_title": dataset.title,
        "dataset_version": dataset.version,
        "prohori_version": __version__,
        "libraries": {
            "scikit-learn": sklearn.__version__,
            "pandas": pd.__version__,
            "numpy": np.__version__,
        },
        "seeds": list(seeds),
        "sample": sample,
        "target_fprs": list(fprs),
        "params": {m: PARAMS[m] for m in models},
        "caveat": CAVEAT,
        "variants": found,
        "fit_seconds": timings,
    }


def _save(
    models_dir: Path,
    dataset: Dataset,
    prepared: Prepared,
    detector: Detector,
    result: dict[str, Any],
    name: str,
    seed: int,
) -> None:
    bundle = {
        "detector": detector,
        "preprocessor": prepared.preprocessor,
        "features": prepared.features,
        "thresholds": result["thresholds"],
    }
    meta = {
        "dataset": dataset.name,
        "model": name,
        "seed": seed,
        "prohori_version": __version__,
        "scikit_learn_version": sklearn.__version__,
        "features": prepared.features,
        "thresholds": result["thresholds"],
    }
    save_model(models_dir / dataset.name / f"{name}-seed{seed}.joblib", bundle, meta)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m prohori.ml.train", description=__doc__.splitlines()[0]
    )
    parser.add_argument("--dataset", required=True, choices=sorted(DATASETS))
    parser.add_argument("--seeds", type=int, nargs="+", default=list(DEFAULT_SEEDS))
    parser.add_argument("--models", nargs="+", choices=MODELS, default=list(MODELS))
    parser.add_argument("--variants", nargs="+", help="default: every variant of the dataset")
    parser.add_argument("--sample", type=float, help="fraction of rows, for quick runs")
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    parser.add_argument("--out", type=Path, help="default: results/ml_<dataset>.json")
    parser.add_argument("--models-dir", type=Path, default=DEFAULT_MODELS_DIR)
    parser.add_argument("--no-save", action="store_true", help="do not save the cleaned models")
    args = parser.parse_args(argv)
    if len(set(args.seeds)) != len(args.seeds):
        parser.error("--seeds must be distinct")
    dataset = get_dataset(args.dataset)

    def log(message: str) -> None:
        sys.stderr.write(f"{message}\n")

    try:
        results = run(
            dataset,
            args.data_dir,
            seeds=args.seeds,
            models=args.models,
            variant_names=args.variants,
            sample=args.sample,
            models_dir=None if args.no_save else args.models_dir,
            log=log,
        )
    except (DatasetMissingError, ValueError) as exc:
        log(f"error: {exc}")
        return 1
    out = args.out or Path("results") / f"ml_{dataset.name}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8", newline="\n")
    log(f"wrote {out}")
    if not args.no_save:
        log(f"models saved in {args.models_dir / dataset.name}. {UNSAFE_PICKLE_WARNING}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
