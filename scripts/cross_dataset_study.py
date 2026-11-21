# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
# Copyright (c) 2026 Utsha Basak
"""The cross-dataset generalisation study (step 30b), as pre-registered in ADR-0041.

For each seed and both directions (UNSW-NB15 to CIC-IDS-2017 and back), every arm fits gradient
boosting on the source, freezes a 1 % threshold on the source's validation split and scores the
target's test split once. Arms differ only in what they do to the features or the training
weights, and in what target data they may see (ADR-0041 lists them). The results go to
``results/ml_adapt.json``, without timings, so a rerun from the same seeds, lockfile and platform
is byte-identical.

    uv run python scripts/cross_dataset_study.py                 # about an hour
    uv run python scripts/cross_dataset_study.py --sample 0.05 --resamples 50   # a quick check
"""

import argparse
import json
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier

from prohori.ml import adapt
from prohori.ml.cleaning import LABEL
from prohori.ml.datasets import DEFAULT_DATA_DIR, DatasetMissingError
from prohori.ml.evaluate import threshold_for_fpr
from prohori.ml.models import PARAMS
from prohori.ml.train import DEFAULT_SEEDS, rounded
from prohori.ml.transfer import COMMON_FEATURES, DIRECTIONS, mapped_splits
from prohori.version import __version__

RESULTS_FORMAT = "prohori.ml-adapt/1"
PREREGISTRATION = (
    "docs/DECISIONS.md#adr-0041-pre-registration-of-the-cross-dataset-generalisation-study"
)
OUT = Path("results") / "ml_adapt.json"
FPR = 0.01
SHOTS = (10, 50, 100)
DRAWS = 5
FEW_SHOT_WEIGHT = 0.1
RESAMPLES = 1_000
PROTOCOL = COMMON_FEATURES.index("protocol")
METHODS = ("standardise", "quantile", "quantile-protocol", "coral", "importance", "invariant")
ARMS = ("baseline", *METHODS, *(f"few-shot-{k}" for k in SHOTS), "target-reference")
CAVEAT = (
    "Two lab datasets, twelve shared features measured by different tools, three seeds, one "
    "model family. The unlabelled target pool is a lab training split with a large attack "
    "share, unlike real unlabelled traffic. See ADR-0041 for the pre-registration."
)

Log = Callable[[str], None]


@dataclass
class Domain:
    """One dataset's splits as arrays of the common features."""

    train: np.ndarray
    train_y: np.ndarray
    validation: np.ndarray
    validation_y: np.ndarray
    test: np.ndarray
    test_y: np.ndarray


def _domain(splits: dict[str, pd.DataFrame]) -> Domain:
    def arrays(name: str) -> tuple[np.ndarray, np.ndarray]:
        frame = splits[name]
        x = frame[list(COMMON_FEATURES)].to_numpy(dtype="float64")
        return x, frame[LABEL].to_numpy(dtype="int64")

    return Domain(*arrays("train"), *arrays("validation"), *arrays("test"))


def _frame(x: np.ndarray, columns: Sequence[str]) -> pd.DataFrame:
    return pd.DataFrame(np.asarray(x, dtype="float32"), columns=list(columns))


def _fit(
    x: np.ndarray, y: np.ndarray, seed: int, columns: Sequence[str], weight: np.ndarray | None
) -> HistGradientBoostingClassifier:
    model = HistGradientBoostingClassifier(**PARAMS["hgb"], random_state=seed)
    model.fit(_frame(x, columns), y, sample_weight=weight)
    return model


def _score(
    model: HistGradientBoostingClassifier, x: np.ndarray, columns: Sequence[str]
) -> np.ndarray:
    return np.asarray(model.predict_proba(_frame(x, columns))[:, 1], dtype="float64")


@dataclass
class Prepared:
    """What an arm trains on, sets its threshold on and scores."""

    train: np.ndarray
    validation: np.ndarray
    test: np.ndarray
    columns: list[str]
    weight: np.ndarray | None = None
    train_y: np.ndarray | None = None  # when the arm adds rows


def _baseline_inputs(source: Domain, target: Domain) -> Prepared:
    medians = adapt._medians(source.train)
    return Prepared(
        adapt.impute(source.train, medians),
        adapt.impute(source.validation, medians),
        adapt.impute(target.test, medians),
        list(COMMON_FEATURES),
    )


def _per_domain(
    source: Domain, target: Domain, transform: Callable[[np.ndarray, np.ndarray], Any]
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Fit ``transform`` on each domain's training features (source) and pool (target)."""
    numeric = [c for c in range(len(COMMON_FEATURES)) if c != PROTOCOL]
    fitted_source = transform(source.train[:, numeric], source.train[:, PROTOCOL])
    fitted_target = transform(target.train[:, numeric], target.train[:, PROTOCOL])

    def apply(fitted: Callable[..., np.ndarray], x: np.ndarray) -> np.ndarray:
        out = x.copy()
        out[:, numeric] = fitted(x[:, numeric], x[:, PROTOCOL])
        out[:, PROTOCOL] = np.nan_to_num(x[:, PROTOCOL], nan=-1.0)
        return out

    return (
        apply(fitted_source, source.train),
        apply(fitted_source, source.validation),
        apply(fitted_target, target.test),
    )


def _standardise(x: np.ndarray, _protocol: np.ndarray) -> Callable[..., np.ndarray]:
    fitted = adapt.Standardiser.fit(x)
    return lambda values, _p: fitted.transform(values)


def _quantile(seed: int, groups: Sequence[float]) -> Callable[..., Any]:
    def build(x: np.ndarray, protocol: np.ndarray) -> Callable[..., np.ndarray]:
        fitted = adapt.QuantileMap(seed).fit(x, protocol if groups else None, groups)
        return lambda values, p: fitted.transform(values, p if groups else None)

    return build


def inputs(arm: str, source: Domain, target: Domain, seed: int, diag: dict[str, Any]) -> Prepared:
    """The arm's training, validation and test matrices (never reading target labels)."""
    columns = list(COMMON_FEATURES)
    if arm == "baseline":
        return _baseline_inputs(source, target)
    if arm == "standardise":
        return Prepared(*_per_domain(source, target, _standardise), columns)
    if arm == "quantile":
        return Prepared(*_per_domain(source, target, _quantile(seed, ())), columns)
    if arm == "quantile-protocol":
        groups = adapt.shared_groups(source.train[:, PROTOCOL], target.train[:, PROTOCOL])
        diag["protocol_groups"] = groups
        return Prepared(*_per_domain(source, target, _quantile(seed, groups)), columns)
    if arm == "coral":
        train, validation, test = _per_domain(source, target, _standardise)
        numeric = [c for c in range(len(COMMON_FEATURES)) if c != PROTOCOL]
        pool = _per_domain(target, target, _standardise)[0]  # the pool, standardised as target
        matrix = adapt.coral_matrix(train[:, numeric], pool[:, numeric])
        for x in (train, validation):
            x[:, numeric] = x[:, numeric] @ matrix
        return Prepared(train, validation, test, columns)
    if arm == "importance":
        base = _baseline_inputs(source, target)
        medians = adapt._medians(source.train)
        weights = adapt.importance_weights(base.train, adapt.impute(target.train, medians), seed)
        diag["domain_auc"] = weights.domain_auc
        diag["effective_sample_share"] = weights.effective_share
        diag["clipped_share"] = weights.clipped_share
        base.weight = weights.weights
        return base
    if arm == "invariant":
        aucs = adapt.domain_auc(source.train, target.train)
        kept = adapt.invariant_features(aucs, PROTOCOL)
        diag["feature_domain_auc"] = {
            name: float(aucs[c]) for c, name in enumerate(COMMON_FEATURES) if c != PROTOCOL
        }
        diag["invariant_dropped"] = [COMMON_FEATURES[c] for c in range(12) if c not in kept]
        base = _baseline_inputs(source, target)
        return Prepared(
            base.train[:, kept],
            base.validation[:, kept],
            base.test[:, kept],
            [COMMON_FEATURES[c] for c in kept],
        )
    msg = f"unknown arm {arm!r}"
    raise ValueError(msg)


def few_shot_inputs(source: Domain, target: Domain, k: int, draw_seed: int) -> Prepared:
    """``baseline`` plus k labelled pool flows weighing 10 % of the source rows together."""
    base = _baseline_inputs(source, target)
    chosen = adapt.few_shot_indices(target.train_y, k, draw_seed)
    medians = adapt._medians(source.train)
    extra = adapt.impute(target.train[chosen], medians)
    shots = len(chosen)  # k, unless the pool is smaller (tiny test data)
    weight = np.r_[
        np.ones(len(base.train)), np.full(shots, FEW_SHOT_WEIGHT * len(base.train) / shots)
    ]
    return Prepared(
        np.vstack([base.train, extra]),
        base.validation,
        base.test,
        base.columns,
        weight=weight,
        train_y=np.r_[source.train_y, target.train_y[chosen]],
    )


def evaluate_arm(
    prepared: Prepared, source: Domain, target: Domain, seed: int
) -> tuple[dict[str, float], np.ndarray]:
    """Fit, freeze the 1 % threshold on source validation, score the target test split once."""
    y = source.train_y if prepared.train_y is None else prepared.train_y
    model = _fit(prepared.train, y, seed, prepared.columns, prepared.weight)
    validation = _score(model, prepared.validation, prepared.columns)
    threshold = threshold_for_fpr(validation[source.validation_y == 0], FPR)
    scores = _score(model, prepared.test, prepared.columns)
    return metrics(scores, target.test_y, threshold), scores


def metrics(scores: np.ndarray, labels: np.ndarray, threshold: float) -> dict[str, float]:
    attack = labels == 1
    alerts = scores >= threshold
    oracle = threshold_for_fpr(scores[~attack], FPR)
    return {
        "roc_auc": adapt.roc_auc(scores, labels),
        "pr_auc": adapt.average_precision(scores, labels),
        "prevalence": float(attack.mean()),
        "recall_frozen": float(alerts[attack].mean()),
        "fpr_frozen": float(alerts[~attack].mean()),
        "recall_at_target_fpr": float((scores[attack] >= oracle).mean()),
    }


def reference(target: Domain, seed: int) -> tuple[dict[str, float], np.ndarray]:
    """HGB on the target's own training split: the in-dataset ceiling (uses target labels)."""
    medians = adapt._medians(target.train)
    columns = list(COMMON_FEATURES)
    model = _fit(adapt.impute(target.train, medians), target.train_y, seed, columns, None)
    validation = _score(model, adapt.impute(target.validation, medians), columns)
    threshold = threshold_for_fpr(validation[target.validation_y == 0], FPR)
    scores = _score(model, adapt.impute(target.test, medians), columns)
    return metrics(scores, target.test_y, threshold), scores


def run_direction(
    source: Domain, target: Domain, seed: int, log: Log
) -> tuple[dict[str, Any], dict[str, list[np.ndarray]], dict[str, Any]]:
    """Every arm for one direction and seed: metrics, target-test scores, diagnostics."""
    diag: dict[str, Any] = {
        "pool_attack_share": float(target.train_y.mean()),
        "source_attack_share": float(source.train_y.mean()),
        "protocol_share": {
            side: {
                str(code): float((np.nan_to_num(d.train[:, PROTOCOL], nan=-1.0) == code).mean())
                for code in (6.0, 17.0, 1.0, -1.0)
            }
            for side, d in (("source", source), ("pool", target))
        },
    }
    found: dict[str, Any] = {}
    scores: dict[str, list[np.ndarray]] = {}
    for arm in ("baseline", *METHODS):
        log(f"  {arm}")
        result, values = evaluate_arm(inputs(arm, source, target, seed, diag), source, target, seed)
        found[arm] = result
        scores[arm] = [values]
    for k in SHOTS:
        log(f"  few-shot-{k}")
        draws = []
        scores[f"few-shot-{k}"] = []
        for d in range(DRAWS):
            prepared = few_shot_inputs(source, target, k, 1000 * seed + d)
            result, values = evaluate_arm(prepared, source, target, seed)
            draws.append(result)
            scores[f"few-shot-{k}"].append(values)
        found[f"few-shot-{k}"] = {key: float(np.mean([r[key] for r in draws])) for key in draws[0]}
    log("  target-reference")
    found["target-reference"], values = reference(target, seed)
    scores["target-reference"] = [values]
    return found, scores, diag


def summarise(
    per_seed: list[dict[str, Any]],
    scores: list[dict[str, list[np.ndarray]]],
    labels: list[np.ndarray],
    seeds: Sequence[int],
    resamples: int,
) -> dict[str, Any]:
    """Means, bootstrap intervals, the per-seed sign test and gap closed, for every arm."""
    flat: dict[str, list[np.ndarray]] = {}
    draws: dict[str, list[str]] = {}
    for arm in ARMS:
        keys = [f"{arm}#{d}" for d in range(len(scores[0][arm]))]
        draws[arm] = keys
        for d, key in enumerate(keys):
            flat[key] = [s[arm][d] for s in scores]
    flat["baseline"] = flat.pop("baseline#0")
    draws["baseline"] = ["baseline"]
    boot = adapt.paired_bootstrap(flat, labels, seeds, resamples=resamples)
    out: dict[str, Any] = {}
    base_auc = np.mean([r["baseline"]["roc_auc"] for r in per_seed])
    ref_auc = np.mean([r["target-reference"]["roc_auc"] for r in per_seed])
    for arm in ARMS:
        resampled = {
            metric: np.mean([boot[key][metric] for key in draws[arm]], axis=0)
            for metric in ("roc_auc", "pr_auc", "roc_auc_difference")
        }
        means = {key: float(np.mean([r[arm][key] for r in per_seed])) for key in per_seed[0][arm]}
        differences = [r[arm]["roc_auc"] - r["baseline"]["roc_auc"] for r in per_seed]
        low, high = adapt.interval(resampled["roc_auc_difference"])
        same_sign = all(d > 0 for d in differences) or all(d < 0 for d in differences)
        out[arm] = {
            "mean": means,
            "per_seed_roc_auc": [r[arm]["roc_auc"] for r in per_seed],
            "roc_auc_interval": adapt.interval(resampled["roc_auc"]),
            "pr_auc_interval": adapt.interval(resampled["pr_auc"]),
            "roc_auc_difference": float(np.mean(differences)),
            "roc_auc_difference_interval": [low, high],
            "difference_same_sign_every_seed": same_sign if arm != "baseline" else None,
            "gap_closed": (
                float((means["roc_auc"] - base_auc) / (ref_auc - base_auc))
                if ref_auc != base_auc
                else None
            ),
            "improves": bool(arm != "baseline" and low > 0 and same_sign),
            "worsens": bool(arm != "baseline" and high < 0 and same_sign),
        }
    return out


def run(
    data_dir: Path,
    *,
    seeds: Sequence[int] = DEFAULT_SEEDS,
    sample: float | None = None,
    resamples: int = RESAMPLES,
    use_cache: bool = True,
    log: Log | None = None,
) -> dict[str, Any]:
    log = log or (lambda _: None)
    per_seed: dict[str, list[dict[str, Any]]] = {f"{s}->{t}": [] for s, t in DIRECTIONS}
    scores: dict[str, list[dict[str, list[np.ndarray]]]] = {k: [] for k in per_seed}
    labels: dict[str, list[np.ndarray]] = {k: [] for k in per_seed}
    diagnostics: dict[str, list[dict[str, Any]]] = {k: [] for k in per_seed}
    for seed in seeds:
        mapped, _ = mapped_splits(data_dir, seed, sample=sample, use_cache=use_cache, log=log)
        domains = {name: _domain(splits) for name, splits in mapped.items()}
        del mapped
        for src, dst in DIRECTIONS:
            key = f"{src}->{dst}"
            log(f"seed {seed}: {key}")
            found, values, diag = run_direction(domains[src], domains[dst], seed, log)
            per_seed[key].append(found)
            scores[key].append(values)
            labels[key].append(domains[dst].test_y)
            diagnostics[key].append({"seed": seed, **diag})
    directions: dict[str, Any] = {}
    for key in per_seed:
        log(f"bootstrap {key}")
        directions[key] = {
            "per_seed": per_seed[key],
            "arms": summarise(per_seed[key], scores[key], labels[key], seeds, resamples),
            "diagnostics": diagnostics[key],
        }
    helps = {
        arm: {
            "improves_both_directions": all(
                d["arms"][arm]["improves"] for d in directions.values()
            ),
            "improves_in": [k for k, d in directions.items() if d["arms"][arm]["improves"]],
            "worsens_in": [k for k, d in directions.items() if d["arms"][arm]["worsens"]],
        }
        for arm in ARMS
        if arm not in ("baseline", "target-reference")
    }
    document: dict[str, Any] = rounded(
        {
            "format": RESULTS_FORMAT,
            "prohori_version": __version__,
            "preregistration": PREREGISTRATION,
            "seeds": list(seeds),
            "sample": sample,
            "resamples": resamples,
            "target_fpr": FPR,
            "features": list(COMMON_FEATURES),
            "params": PARAMS["hgb"],
            "arms": list(ARMS),
            "caveat": CAVEAT,
            "directions": directions,
            "helps": helps,
        }
    )
    return document


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--seeds", type=int, nargs="+", default=list(DEFAULT_SEEDS))
    parser.add_argument("--sample", type=float, help="fraction of rows, for quick runs")
    parser.add_argument("--resamples", type=int, default=RESAMPLES)
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    parser.add_argument("--out", type=Path, default=OUT)
    parser.add_argument("--no-cache", action="store_true", help="do not read or write Parquet")
    args = parser.parse_args(argv)
    if len(set(args.seeds)) != len(args.seeds):
        parser.error("--seeds must be distinct")

    def log(message: str) -> None:
        sys.stderr.write(f"{message}\n")

    try:
        results = run(
            args.data_dir,
            seeds=args.seeds,
            sample=args.sample,
            resamples=args.resamples,
            use_cache=not args.no_cache,
            log=log,
        )
    except (DatasetMissingError, ValueError) as exc:
        log(f"error: {exc}")
        return 1
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8", newline="\n")
    log(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
