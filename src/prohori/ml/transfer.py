"""Cross-dataset test: train on one flow dataset, test on the other.

UNSW-NB15 (Argus and Bro features) and CIC-IDS-2017 (CICFlowMeter features) describe flows
differently, so the test uses the few features that can be computed from both. **The mapping is
lossy:** most features of each dataset have no counterpart, and the ones that do were measured by
different tools. How each common feature is derived:

==============  =============================  ========================================
Feature         UNSW-NB15                      CIC-IDS-2017
==============  =============================  ========================================
duration_s      ``dur`` (seconds)              ``flow_duration`` / 10^6 (microseconds)
fwd_packets     ``spkts``                      ``total_fwd_packet``
bwd_packets     ``dpkts``                      ``total_bwd_packets``
fwd_bytes       ``sbytes``                     payload + transport headers + 34 a packet
bwd_bytes       ``dbytes``                     the same, backwards
fwd_mean_bytes  fwd_bytes / fwd_packets        the same
bwd_mean_bytes  bwd_bytes / bwd_packets        the same
fwd_iat_mean_s  ``sinpkt`` / 10^3 (ms)         ``fwd_iat_mean`` / 10^6 (microseconds)
bwd_iat_mean_s  ``dinpkt`` / 10^3              ``bwd_iat_mean`` / 10^6
packets_per_s   packets / duration             the same
bytes_per_s     bytes / duration               the same
protocol        ``proto``: tcp 6, udp 17,      ``protocol``: 6, 17 and 1 kept
                icmp 1
==============  =============================  ========================================

Bytes are made comparable as bytes on the wire: CICFlowMeter counts payload, so its bytes get
the transport header lengths it records plus 34 bytes per packet for the Ethernet (14) and IPv4
(20) headers. That UNSW-NB15 counts headers is inferred from the data, not documented: benign
DNS flows send a median of 146 bytes forward there and 154 after this conversion. Other
protocols are -1 on both sides. A rate over a zero duration is missing and imputed.

For each direction and seed: both datasets are prepared with every leakage control; the source's
splits are mapped and deduplicated again on the common features (fewer features make more rows
identical); the model is fitted on the source's training split, its thresholds are chosen on the
source's validation split and frozen, and it is scored once on the source's test split
(**in-dataset**) and once on the target's test split (**cross-dataset**). The difference is the
generalisation gap.

    uv run python -m prohori.ml.transfer --seeds 0 1 2
"""

import argparse
import json
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from prohori.ml import MissingExtraError

try:
    import pandas as pd
except ImportError as exc:  # pragma: no cover - exercised in a subprocess test
    raise MissingExtraError("prohori.ml.transfer") from exc

from prohori.ml.cleaning import (
    CATEGORY,
    LABEL,
    CleaningReport,
    deduplicate,
    make_preprocessor,
    prepare,
    remove_overlap,
)
from prohori.ml.datasets import DEFAULT_DATA_DIR, DatasetMissingError
from prohori.ml.evaluate import TARGET_FPRS, evaluate, point_name, summarise, threshold_for_fpr
from prohori.ml.models import MODELS, PARAMS, fit
from prohori.ml.registry import CICIDS2017, UNSW_NB15
from prohori.ml.train import DEFAULT_SEEDS, rounded
from prohori.version import __version__

RESULTS_FORMAT = "prohori.ml-transfer/1"
COMMON_FEATURES = (
    "duration_s",
    "fwd_packets",
    "bwd_packets",
    "fwd_bytes",
    "bwd_bytes",
    "fwd_mean_bytes",
    "bwd_mean_bytes",
    "fwd_iat_mean_s",
    "bwd_iat_mean_s",
    "packets_per_s",
    "bytes_per_s",
    "protocol",
)
#: Ethernet (14) and IPv4 (20) header bytes, which CICFlowMeter leaves out of its byte counts.
LINK_AND_IP_HEADER = 34
PROTOCOLS = {"tcp": 6, "udp": 17, "icmp": 1}
DIRECTIONS = ((UNSW_NB15.name, CICIDS2017.name), (CICIDS2017.name, UNSW_NB15.name))
SPLITS = ("train", "validation", "test")
CAVEAT = (
    "The two datasets share only twelve features, derived from columns that different tools "
    "measured in different ways; the mapping is lossy. A gap between in-dataset and "
    "cross-dataset results is the expected finding, not a defect to be tuned away: thresholds "
    "and models are fitted on the source dataset only and never see the target."
)

Log = Callable[[str], None]


def _ratio(numerator: pd.Series, denominator: pd.Series) -> pd.Series:
    """``numerator / denominator``, missing where the denominator is zero or missing."""
    return numerator / denominator.where(denominator > 0)


def to_common(frame: pd.DataFrame, dataset: str) -> pd.DataFrame:
    """The common features of a cleaned frame of ``dataset``, with its label and class."""
    out = pd.DataFrame(index=frame.index)
    if dataset == UNSW_NB15.name:
        out["duration_s"] = frame["dur"]
        out["fwd_packets"] = frame["spkts"]
        out["bwd_packets"] = frame["dpkts"]
        out["fwd_bytes"] = frame["sbytes"]
        out["bwd_bytes"] = frame["dbytes"]
        out["fwd_iat_mean_s"] = frame["sinpkt"] / 1e3
        out["bwd_iat_mean_s"] = frame["dinpkt"] / 1e3
        proto = frame["proto"].astype(str).str.lower()
        out["protocol"] = proto.map(PROTOCOLS).fillna(-1).astype("float64")
    elif dataset == CICIDS2017.name:
        out["duration_s"] = frame["flow_duration"] / 1e6
        out["fwd_packets"] = frame["total_fwd_packet"]
        out["bwd_packets"] = frame["total_bwd_packets"]
        out["fwd_bytes"] = (
            frame["total_length_of_fwd_packet"]
            + frame["fwd_header_length"]
            + LINK_AND_IP_HEADER * frame["total_fwd_packet"]
        )
        out["bwd_bytes"] = (
            frame["total_length_of_bwd_packet"]
            + frame["bwd_header_length"]
            + LINK_AND_IP_HEADER * frame["total_bwd_packets"]
        )
        out["fwd_iat_mean_s"] = frame["fwd_iat_mean"] / 1e6
        out["bwd_iat_mean_s"] = frame["bwd_iat_mean"] / 1e6
        known = frame["protocol"].isin(list(PROTOCOLS.values()))
        out["protocol"] = frame["protocol"].where(known, -1).astype("float64")
    else:
        msg = f"no common-feature mapping for {dataset!r}"
        raise ValueError(msg)
    out["fwd_mean_bytes"] = _ratio(out["fwd_bytes"], out["fwd_packets"])
    out["bwd_mean_bytes"] = _ratio(out["bwd_bytes"], out["bwd_packets"])
    packets = out["fwd_packets"] + out["bwd_packets"]
    out["packets_per_s"] = _ratio(packets, out["duration_s"])
    out["bytes_per_s"] = _ratio(out["fwd_bytes"] + out["bwd_bytes"], out["duration_s"])
    out = out[list(COMMON_FEATURES)].astype("float64")
    out[CATEGORY] = frame[CATEGORY].to_numpy()
    out[LABEL] = frame[LABEL].to_numpy()
    return out


def common_splits(
    splits: dict[str, pd.DataFrame], dataset: str, seed: int
) -> tuple[dict[str, pd.DataFrame], CleaningReport]:
    """Map every split and deduplicate again on the common features, then remove overlap."""
    report = CleaningReport(dataset=dataset, seed=seed)
    mapped = {}
    for name in SPLITS:
        frame = to_common(splits[name], dataset)
        report.rows_loaded[name] = len(frame)
        mapped[name] = deduplicate(frame, report, name)
    mapped["validation"] = remove_overlap(
        mapped["validation"], [mapped["train"]], report, "validation"
    )
    mapped["test"] = remove_overlap(
        mapped["test"], [mapped["train"], mapped["validation"]], report, "test"
    )
    for name, frame in mapped.items():
        mapped[name] = frame.reset_index(drop=True)
        report.rows[name] = len(frame)
    return mapped, report


def _cleaning(report: CleaningReport) -> dict[str, Any]:
    return {
        "seed": report.seed,
        "rows_before": report.rows_loaded,
        "duplicates_removed": report.duplicates_removed,
        "conflicting_removed": report.conflicting_removed,
        "overlap_removed": report.overlap_removed,
        "rows": report.rows,
    }


def run_direction(
    source: dict[str, pd.DataFrame],
    target: dict[str, pd.DataFrame],
    name: str,
    seed: int,
    fprs: Sequence[float],
) -> dict[str, Any]:
    """Fit on the source, freeze thresholds on its validation split, score both test splits."""
    features = list(COMMON_FEATURES)
    preprocessor = make_preprocessor(features, []).fit(source["train"][features])

    def x(frame: pd.DataFrame) -> pd.DataFrame:
        transformed: pd.DataFrame = preprocessor.transform(frame[features])
        return transformed.astype("float32")

    detector = fit(name, x(source["train"]), source["train"][LABEL], seed=seed, categorical=[])
    validation = source["validation"]
    val_scores = detector.scores(x(validation))
    benign = validation[LABEL].to_numpy() == 0
    thresholds = {point_name(f): threshold_for_fpr(val_scores[benign], f) for f in fprs}
    # Thresholds are frozen; each test split is scored exactly once.
    result: dict[str, Any] = {"seed": seed}
    for key, frame in (("in_dataset", source["test"]), ("cross_dataset", target["test"])):
        scores = detector.scores(x(frame))
        result[key] = evaluate(frame[LABEL], scores, frame[CATEGORY], thresholds)
    return {**rounded(result), "thresholds": thresholds}


def run(
    data_dir: Path = DEFAULT_DATA_DIR,
    *,
    seeds: Sequence[int] = DEFAULT_SEEDS,
    models: Sequence[str] = MODELS,
    fprs: Sequence[float] = TARGET_FPRS,
    sample: float | None = None,
    use_cache: bool = True,
    log: Log | None = None,
) -> dict[str, Any]:
    """Both directions, every seed and model; the results document written by :func:`main`."""
    log = log or (lambda _: None)
    found: dict[str, Any] = {
        f"{src}->{dst}": {"source": src, "target": dst, "models": {m: {"runs": []} for m in models}}
        for src, dst in DIRECTIONS
    }
    cleaning: dict[str, list[dict[str, Any]]] = {UNSW_NB15.name: [], CICIDS2017.name: []}
    for seed in seeds:
        mapped: dict[str, dict[str, pd.DataFrame]] = {}
        for dataset in (UNSW_NB15, CICIDS2017):
            log(f"seed {seed}: preparing {dataset.name}")
            prepared = prepare(dataset, data_dir, seed=seed, sample=sample, use_cache=use_cache)
            splits = {s: prepared.split(s) for s in SPLITS}
            mapped[dataset.name], report = common_splits(splits, dataset.name, seed)
            cleaning[dataset.name].append(_cleaning(report))
            del prepared, splits
        for src, dst in DIRECTIONS:
            for name in models:
                log(f"seed {seed}: {name} {src} -> {dst}")
                outcome = run_direction(mapped[src], mapped[dst], name, seed, fprs)
                found[f"{src}->{dst}"]["models"][name]["runs"].append(outcome)
    for direction in found.values():
        for entry in direction["models"].values():
            entry["summary"] = {
                key: rounded(summarise([r[key] for r in entry["runs"]]))
                for key in ("in_dataset", "cross_dataset")
            }
    return {
        "format": RESULTS_FORMAT,
        "prohori_version": __version__,
        "seeds": list(seeds),
        "sample": sample,
        "target_fprs": list(fprs),
        "features": list(COMMON_FEATURES),
        "params": {m: PARAMS[m] for m in models},
        "caveat": CAVEAT,
        "cleaning": cleaning,
        "directions": found,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m prohori.ml.transfer", description=__doc__.splitlines()[0]
    )
    parser.add_argument("--seeds", type=int, nargs="+", default=list(DEFAULT_SEEDS))
    parser.add_argument("--models", nargs="+", choices=MODELS, default=list(MODELS))
    parser.add_argument("--sample", type=float, help="fraction of rows, for quick runs")
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    parser.add_argument("--out", type=Path, default=Path("results") / "ml_cross.json")
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
            models=args.models,
            sample=args.sample,
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
