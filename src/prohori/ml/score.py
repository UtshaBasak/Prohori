"""Score a CSV of flows with a model saved by ``python -m prohori.ml.train``.

The CSV must have the columns of the dataset the model was trained on (UNSW-NB15 partition
columns, or CICFlowMeter columns as in CIC-IDS-2017); names are normalised the same way as in
training and label columns, if present, are ignored. It is read in chunks, so its size does not
matter. Identifier columns (addresses, ports, flow id, timestamp) are never given to the model
but are shown next to flagged flows so an analyst can find them.
"""

import heapq
import io
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Any

from prohori.ml import MissingExtraError

try:
    import numpy as np
    import pandas as pd
except ImportError as exc:  # pragma: no cover - exercised in a subprocess test
    raise MissingExtraError("prohori.ml.score") from exc

from prohori.ml.cleaning import MISSING_CATEGORY
from prohori.ml.datasets import CHUNK_ROWS
from prohori.ml.models import load_model
from prohori.ml.registry import get_dataset, normalise_column

#: Columns shown with a flagged flow when the CSV has them; never used for scoring.
CONTEXT_COLUMNS = (
    "flow_id",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "protocol",
    "proto",
    "service",
    "timestamp",
)


class ScoreInputError(ValueError):
    """The CSV cannot be scored with this model."""


@dataclass(order=True)
class FlaggedFlow:
    score: float
    row: int  # 1-based data row, not counting the header
    context: dict[str, str] = field(compare=False, default_factory=dict)


@dataclass
class ScoreResult:
    model: str
    dataset: str
    threshold_name: str
    threshold: float
    flows: int = 0
    flagged: int = 0
    non_numeric_values: int = 0
    #: The highest-scoring flagged flows, highest first.
    top: list[FlaggedFlow] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model,
            "dataset": self.dataset,
            "threshold": {"name": self.threshold_name, "value": self.threshold},
            "flows": self.flows,
            "flagged": self.flagged,
            "flagged_share": self.flagged / self.flows if self.flows else 0.0,
            "non_numeric_values": self.non_numeric_values,
            "flagged_flows": [{"row": f.row, "score": f.score, **f.context} for f in self.top],
        }


def resolve_model(name: str, models_dir: Path) -> Path:
    """A model file path, or a name such as ``cicids2017/hgb-seed0`` under ``models_dir``."""
    candidates = [Path(name), models_dir / name, models_dir / f"{name}.joblib"]
    for candidate in candidates:
        if candidate.is_file() and candidate.suffix == ".joblib":
            return candidate
    available = (
        sorted(
            str(p.relative_to(models_dir).with_suffix("")).replace("\\", "/")
            for p in models_dir.glob("*/*.joblib")
        )
        if models_dir.is_dir()
        else []
    )
    hint = (
        f"; available: {', '.join(available)}"
        if available
        else ("; train one with: python -m prohori.ml.train --dataset DATASET")
    )
    msg = f"no model {name!r} (looked in {models_dir}){hint}"
    raise FileNotFoundError(msg)


def _chunks(source: Path | bytes, features: list[str], text: set[str]) -> Iterator[pd.DataFrame]:
    def handle() -> IO[bytes] | Path:
        return io.BytesIO(source) if isinstance(source, bytes) else source

    header = pd.read_csv(handle(), nrows=0).columns
    names = [normalise_column(str(c)) for c in header]
    missing = [f for f in features if f not in names]
    if missing:
        shown = ", ".join(missing[:8]) + (
            f" and {len(missing) - 8} more" if len(missing) > 8 else ""
        )
        msg = f"the file lacks {len(missing)} column(s) the model needs: {shown}"
        raise ScoreInputError(msg)
    if len(set(names)) != len(names):
        msg = "the file has columns that are duplicated after normalising their names"
        raise ScoreInputError(msg)
    keep = [c for c in names if c in features or c in CONTEXT_COLUMNS]
    reader = pd.read_csv(
        handle(),
        header=0,
        names=names,
        usecols=keep,
        dtype="string",
        chunksize=CHUNK_ROWS,
        low_memory=False,
    )
    with reader:
        yield from reader


def score_file(
    source: Path | bytes,
    model_path: Path,
    *,
    fpr: float | None = None,
    top: int = 20,
) -> ScoreResult:
    """Score every flow; keep counts and the ``top`` highest-scoring flagged flows (0: all)."""
    bundle, meta = load_model(model_path)
    thresholds: dict[str, float] = bundle["thresholds"]
    if fpr is None:
        name = min(thresholds, key=lambda key: float(key.removeprefix("fpr_")))
    else:
        name = f"fpr_{fpr:g}"
        if name not in thresholds:
            known = ", ".join(k.removeprefix("fpr_") for k in sorted(thresholds))
            msg = f"the model has no threshold for a {fpr:g} false-positive rate; it has {known}"
            raise ScoreInputError(msg)
    dataset = get_dataset(meta["dataset"])
    features: list[str] = bundle["features"]
    categorical = [c for c in dataset.categorical_columns if c in features]
    result = ScoreResult(
        model=f"{meta['dataset']}/{meta['model']}-seed{meta['seed']}",
        dataset=meta["dataset"],
        threshold_name=name,
        threshold=thresholds[name],
    )
    heap: list[FlaggedFlow] = []
    try:
        for chunk in _chunks(source, features, set(categorical)):
            if chunk.empty:
                continue
            frame = pd.DataFrame(index=chunk.index)
            for column in features:
                if column in categorical:
                    values = chunk[column].str.strip().fillna(MISSING_CATEGORY)
                    frame[column] = values.astype(object)
                    continue
                numbers = pd.to_numeric(chunk[column].str.strip(), errors="coerce")
                result.non_numeric_values += int((numbers.isna() & chunk[column].notna()).sum())
                frame[column] = numbers.astype("float64").replace([np.inf, -np.inf], np.nan)
            x = bundle["preprocessor"].transform(frame[features]).astype("float32")
            scores = bundle["detector"].scores(x)
            flagged = np.flatnonzero(scores >= result.threshold)
            for position in flagged.tolist():
                row = int(chunk.index[position]) + 1
                score = float(scores[position])
                if top and len(heap) >= top and score <= heap[0].score:
                    continue
                context = {
                    c: str(chunk.iloc[position][c])
                    for c in CONTEXT_COLUMNS
                    if c in chunk and not pd.isna(chunk.iloc[position][c])
                }
                flow = FlaggedFlow(score=score, row=-row, context=context)
                if top and len(heap) >= top:
                    heapq.heapreplace(heap, flow)
                else:
                    heapq.heappush(heap, flow)
            result.flows += len(chunk)
            result.flagged += int(flagged.size)
    except (pd.errors.ParserError, UnicodeDecodeError, pd.errors.EmptyDataError) as exc:
        msg = f"cannot read the file as CSV: {exc}"
        raise ScoreInputError(msg) from exc
    result.top = [
        FlaggedFlow(score=f.score, row=-f.row, context=f.context)
        for f in sorted(heap, reverse=True)
    ]
    return result
