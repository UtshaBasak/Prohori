# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
# Copyright (c) 2026 Utsha Basak
"""Train and evaluate the flow detectors and write ``results/ml_<dataset>.json``.

For every seed, variant and model:

1. Prepare the data (:mod:`prohori.ml.cleaning`); the seed drives the split and the model.
   Validation is made of time blocks the training split does not touch.
2. Fit the model on the training split.
3. Score the validation split and choose one threshold per target false-positive rate on its
   benign flows. The thresholds are then frozen.
4. Score the test split **once** with the frozen thresholds and record every metric.

**Calibration study** (cleaned variant, since 1.1). The thresholds can be chosen three ways, and
every run measures all three on the same test split: ``time-block`` (above), ``out-of-fold``
(five models, each fitted without one fold of time blocks of training and validation, score
the fold they did not see; the thresholds come from those scores and the final model is fitted
on all of it) and ``random`` (the 1.0 validation split, rows drawn at random, kept to measure
what the change does). :data:`CALIBRATION` is the method used for the published numbers and the
saved models, chosen by :data:`SELECTION_RULE`.

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

from prohori.ml.cleaning import BLOCK, CATEGORY, LABEL, RANDOM, TIME_BLOCK, Prepared, prepare_frames
from prohori.ml.datasets import DEFAULT_DATA_DIR, DatasetMissingError, load
from prohori.ml.evaluate import TARGET_FPRS, evaluate, point_name, summarise, threshold_for_fpr
from prohori.ml.models import MODEL_FILE_NOTE, MODELS, PARAMS, SKOPS, Detector, fit, save_model
from prohori.ml.registry import DATASETS, Dataset, get_dataset
from prohori.version import __version__

RESULTS_FORMAT = "prohori.ml-eval/2"
OUT_OF_FOLD = "out-of-fold"
#: Ways of choosing thresholds, measured side by side on the cleaned variant.
CALIBRATIONS = (TIME_BLOCK, OUT_OF_FOLD, RANDOM)
#: The method behind the published numbers and saved models; see SELECTION_RULE.
CALIBRATION = TIME_BLOCK
#: Written down before the full runs of step 30 and applied once to their results.
SELECTION_RULE = (
    "Lower mean calibration error wins: |FPR reached on test / target FPR - 1|, averaged over "
    "both datasets, both models, both targets and seeds 0-2 (cleaned variant). time-block wins "
    "a difference under 0.05, being one fit instead of six. random is measured, never chosen. "
    "The choice uses the test split, once, to pick a method, never a threshold."
)
#: Folds of time blocks for out-of-fold thresholds.
FOLDS = 5
DEFAULT_SEEDS = (0, 1, 2)
DEFAULT_MODELS_DIR = Path("models")
CAVEAT = (
    "Lab datasets captured in 2015 (UNSW-NB15) and 2017 (CIC-IDS-2017). Scores on them say "
    "little about a real network today; the cross-dataset test (step 16) measures how badly the "
    "models transfer. Thresholds were chosen on validation time blocks the training split does "
    "not touch, and the test split was scored once. The uncleaned variant shows what the same "
    "pipeline reports without the leakage controls and is not a usable model."
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
    dataset: Dataset,
    frames: dict[str, pd.DataFrame],
    seed: int,
    variant: str,
    validation: str = TIME_BLOCK,
) -> Prepared:
    return prepare_frames(
        dataset,
        frames,
        seed=seed,
        clean=variant != "uncleaned",
        drop_suspect=variant == "cleaned-no-suspect",
        validation=validation,
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
        "validation_method": report.validation_method,
        "near_duplicate_share": report.near_duplicate_share,
    }


def _thresholds(scores: np.ndarray, labels: pd.Series, fprs: Sequence[float]) -> dict[str, float]:
    benign = labels.to_numpy() == 0
    return {point_name(f): threshold_for_fpr(scores[benign], f) for f in fprs}


def out_of_fold(
    prepared: Prepared, name: str, seed: int, fprs: Sequence[float], folds: int = FOLDS
) -> tuple[pd.DataFrame, np.ndarray, Detector, dict[str, float]]:
    """Thresholds from out-of-fold scores over training and validation, then a final fit.

    The folds are made of whole time blocks (``_block``), so no fold model has seen flows from
    the blocks it scores. Returns the pooled frame, its out-of-fold scores, the final detector
    (fitted on all of it) and the thresholds.
    """
    pool = pd.concat([prepared.train, prepared.validation], ignore_index=True)
    x = prepared.preprocessor.transform(pool[prepared.features]).astype("float32")
    y = pool[LABEL]
    names = np.array(sorted(set(pool[BLOCK].astype(str))), dtype=object)
    order = np.random.default_rng(seed).permutation(len(names))
    fold_of = dict(zip(names[order], np.arange(len(names)) % folds, strict=True))
    fold = pool[BLOCK].astype(str).map(fold_of).to_numpy()
    scores = np.zeros(len(pool), dtype="float64")
    for k in range(folds):
        held = fold == k
        if not held.any():
            continue
        model = fit(name, x[~held], y[~held], seed=seed, categorical=prepared.categorical)
        scores[held] = model.scores(x[held])
    thresholds = _thresholds(scores, y, fprs)
    detector = fit(name, x, y, seed=seed, categorical=prepared.categorical)
    return pool, scores, detector, thresholds


def run_model(
    prepared: Prepared,
    name: str,
    seed: int,
    fprs: Sequence[float],
    calibration: str = TIME_BLOCK,
) -> tuple[dict[str, Any], Detector, float]:
    """Fit, freeze thresholds, score test once. Returns results, model, seconds.

    ``calibration`` is ``time-block`` or ``random`` (thresholds from ``prepared``'s validation
    split, however it was drawn) or ``out-of-fold`` (see :func:`out_of_fold`).
    """
    started = time.perf_counter()
    if calibration == OUT_OF_FOLD:
        pool, val_scores, detector, thresholds = out_of_fold(prepared, name, seed, fprs)
        validation = pool
    else:
        x_train = prepared.x("train")
        detector = fit(
            name, x_train, prepared.y("train"), seed=seed, categorical=prepared.categorical
        )
        del x_train
        validation = prepared.validation
        val_scores = detector.scores(prepared.x("validation"))
        thresholds = _thresholds(val_scores, validation[LABEL], fprs)
    seconds = time.perf_counter() - started
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


def calibration_error(points: dict[str, Any], fprs: Sequence[float]) -> float:
    """Mean of ``|FPR reached / target - 1|`` over the targets: 0 is a perfect calibration."""
    errors = [abs(points[point_name(f)]["fpr"] / f - 1) for f in fprs]
    return float(np.mean(errors))


def _calibration_entry(result: dict[str, Any], near: float | None) -> dict[str, Any]:
    points = result["test"]["operating_points"]
    return {
        "seed": result["seed"],
        "near_duplicate_share": near,
        "points": {
            key: {"fpr": point["fpr"], "recall": point["recall"]} for key, point in points.items()
        },
    }


def _summarise_calibration(
    methods: dict[str, dict[str, Any]], fprs: Sequence[float]
) -> dict[str, dict[str, Any]]:
    for entries in methods.values():
        for entry in entries.values():
            runs = entry["runs"]
            entry["summary"] = rounded(summarise([r["points"] for r in runs]))
            entry["calibration_error"] = rounded(
                float(np.mean([calibration_error(r["points"], fprs) for r in runs]))
            )
    return methods


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
    use_cache: bool = True,
    log: Log | None = None,
    calibration: str = CALIBRATION,
    study: bool = True,
) -> dict[str, Any]:
    """Every seed, variant and model; the results document written by :func:`main`.

    ``study`` adds the calibration study (every method of :data:`CALIBRATIONS`, cleaned variant
    only) to the results.
    """
    if calibration not in (TIME_BLOCK, OUT_OF_FOLD):
        msg = f"calibration must be {TIME_BLOCK} or {OUT_OF_FOLD}, got {calibration!r}"
        raise ValueError(msg)
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
    studied = study and "cleaned" in chosen
    methods: dict[str, dict[str, Any]] = {
        c: {m: {"runs": []} for m in models} for c in (CALIBRATIONS if studied else ())
    }
    for seed in seeds:
        frames = load(dataset, data_dir, sample=sample, seed=seed, use_cache=use_cache).frames
        for variant in chosen:
            prepared = _prepare(dataset, frames, seed, variant)
            near = prepared.report.near_duplicate_share
            found[variant]["cleaning"].append(_cleaning_summary(prepared))
            for name in models:
                log(f"{dataset.name} seed {seed} {variant} {name}: training ({calibration})")
                result, detector, seconds = run_model(prepared, name, seed, fprs, calibration)
                found[variant]["models"][name]["runs"].append(result)
                timings[variant][name].append(round(seconds, 1))
                if models_dir is not None and variant == "cleaned":
                    _save(models_dir, dataset, prepared, detector, result, name, seed)
                if variant == "cleaned" and studied:
                    methods[calibration][name]["runs"].append(_calibration_entry(result, near))
                    other = OUT_OF_FOLD if calibration == TIME_BLOCK else TIME_BLOCK
                    log(f"{dataset.name} seed {seed} {name}: calibration study ({other})")
                    extra, _, _ = run_model(prepared, name, seed, fprs, other)
                    methods[other][name]["runs"].append(_calibration_entry(extra, near))
            if variant == "cleaned" and studied:
                random_split = _prepare(dataset, frames, seed, variant, validation=RANDOM)
                near_random = random_split.report.near_duplicate_share
                for name in models:
                    log(f"{dataset.name} seed {seed} {name}: calibration study (random)")
                    extra, _, _ = run_model(random_split, name, seed, fprs, RANDOM)
                    methods[RANDOM][name]["runs"].append(_calibration_entry(extra, near_random))
                del random_split
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
        "calibration": calibration,
        "calibration_study": (
            {"rule": SELECTION_RULE, "methods": _summarise_calibration(methods, fprs)}
            if studied
            else None
        ),
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
        "features": prepared.features,
        "thresholds": result["thresholds"],
    }
    save_model(models_dir / dataset.name / f"{name}-seed{seed}{SKOPS}", bundle, meta)


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
    parser.add_argument("--no-cache", action="store_true", help="do not read or write Parquet")
    parser.add_argument(
        "--calibration",
        choices=[TIME_BLOCK, OUT_OF_FOLD],
        default=CALIBRATION,
        help="how thresholds are chosen (default: %(default)s)",
    )
    parser.add_argument(
        "--no-study", action="store_true", help="skip the calibration study (faster)"
    )
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
            use_cache=not args.no_cache,
            log=log,
            calibration=args.calibration,
            study=not args.no_study,
        )
    except (DatasetMissingError, ValueError) as exc:
        log(f"error: {exc}")
        return 1
    out = args.out or Path("results") / f"ml_{dataset.name}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8", newline="\n")
    log(f"wrote {out}")
    if not args.no_save:
        log(f"models saved in {args.models_dir / dataset.name}. {MODEL_FILE_NOTE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
