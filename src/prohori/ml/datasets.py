"""Read the raw dataset CSVs in chunks, with fixed column types, through a Parquet cache.

A CSV is read ``CHUNK_ROWS`` rows at a time, so a file larger than memory can still be
converted. Column names are normalised; text columns stay text and every other column becomes
float64, with values that are not numbers turned into missing values and counted. Float64 is
kept on purpose: deduplication then compares exact values. The conversion is written to
``data/processed/<dataset>/`` as Parquet, keyed by the raw file's SHA-256, so a changed file
is never read from a stale cache.

Nothing is downloaded here: the files must already be in ``data/raw/<dataset>/``
(``scripts/download_datasets.py``).
"""

import hashlib
import json
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from prohori.ml import MissingExtraError
from prohori.ml.registry import DataFile, Dataset, normalise_column

try:
    import pandas as pd
    import pyarrow as pa
    import pyarrow.parquet as pq
except ImportError as exc:  # pragma: no cover - exercised in a subprocess test
    raise MissingExtraError("prohori.ml.datasets") from exc

DEFAULT_DATA_DIR = Path("data")
CHUNK_ROWS = 200_000
#: Part of every cache file name; bump it when the cached layout changes.
CACHE_VERSION = 1
#: Key of the single frame of a dataset without an official split.
ALL = "all"


class DatasetMissingError(FileNotFoundError):
    """A dataset file is not in ``data/raw/<dataset>/``."""


class DatasetFormatError(ValueError):
    """A file does not have the columns its dataset should have."""


@dataclass
class FileStats:
    """What reading one CSV found."""

    rows: int = 0
    #: Column -> number of values that were not numbers and became missing.
    non_numeric: dict[str, int] = field(default_factory=dict)


@dataclass
class Loaded:
    """A dataset read into memory: one frame per split (``train``/``test``, or ``all``)."""

    dataset: Dataset
    frames: dict[str, pd.DataFrame]
    files: dict[str, FileStats]


def raw_dir(dataset: Dataset, data_dir: Path = DEFAULT_DATA_DIR) -> Path:
    return data_dir / "raw" / dataset.name


def cache_dir(dataset: Dataset, data_dir: Path = DEFAULT_DATA_DIR) -> Path:
    return data_dir / "processed" / dataset.name


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(1 << 20):
            digest.update(block)
    return digest.hexdigest()


def locate(dataset: Dataset, data_dir: Path = DEFAULT_DATA_DIR) -> dict[str, Path]:
    """The path of every file of ``dataset``, or :class:`DatasetMissingError` with the steps."""
    folder = raw_dir(dataset, data_dir)
    paths = {f.name: folder / f.name for f in dataset.files}
    missing = [name for name, path in paths.items() if not path.is_file()]
    if missing:
        steps = "\n".join(f"  {i}. {s}" for i, s in enumerate(dataset.manual_steps, 1))
        msg = f"{dataset.name}: missing {', '.join(missing)} in {folder}\nTo get it:\n{steps}"
        raise DatasetMissingError(msg)
    return paths


def _columns(path: Path, dataset: Dataset) -> list[str]:
    header = pd.read_csv(path, nrows=0).columns
    names = [normalise_column(str(c)) for c in header]
    duplicated = sorted({n for n in names if names.count(n) > 1})
    if duplicated:
        msg = f"{path.name}: columns {duplicated} are duplicated after normalising the names"
        raise DatasetFormatError(msg)
    absent = [c for c in dataset.required_columns if c not in names]
    if absent:
        msg = f"{path.name} does not look like {dataset.name}: no column(s) {', '.join(absent)}"
        raise DatasetFormatError(msg)
    return names


def read_csv_chunks(
    path: Path, dataset: Dataset, stats: FileStats | None = None, chunk_rows: int = CHUNK_ROWS
) -> Iterator[pd.DataFrame]:
    """Yield typed, normalised chunks of one CSV; ``stats`` collects rows and bad values."""
    stats = FileStats() if stats is None else stats
    names = _columns(path, dataset)
    text = [c for c in names if c in dataset.text_columns]
    reader = pd.read_csv(
        path,
        header=0,
        names=names,
        dtype=dict.fromkeys(text, "string"),
        chunksize=chunk_rows,
        low_memory=False,
    )
    with reader:
        for chunk in reader:
            for column in names:
                if column in text:
                    chunk[column] = chunk[column].str.strip()
                    continue
                values = pd.to_numeric(chunk[column], errors="coerce").astype("float64")
                bad = int((values.isna() & chunk[column].notna()).sum())
                if bad:
                    stats.non_numeric[column] = stats.non_numeric.get(column, 0) + bad
                chunk[column] = values
            stats.rows += len(chunk)
            yield chunk


def _cache_path(dataset: Dataset, data_file: DataFile, digest: str, data_dir: Path) -> Path:
    stem = Path(data_file.name).stem
    return cache_dir(dataset, data_dir) / f"{stem}-v{CACHE_VERSION}-{digest[:16]}.parquet"


def read_file(
    dataset: Dataset,
    data_file: DataFile,
    path: Path,
    data_dir: Path = DEFAULT_DATA_DIR,
    *,
    use_cache: bool = True,
    chunk_rows: int = CHUNK_ROWS,
) -> tuple[pd.DataFrame, FileStats]:
    """One CSV as a frame, converted once and then read from the Parquet cache."""
    target = _cache_path(dataset, data_file, sha256_file(path), data_dir)
    sidecar = target.with_suffix(".json")
    if use_cache and target.is_file() and sidecar.is_file():
        stats = FileStats(**json.loads(sidecar.read_text(encoding="utf-8")))
        return pd.read_parquet(target), stats
    stats = FileStats()
    target.parent.mkdir(parents=True, exist_ok=True)
    partial = target.with_suffix(".partial")
    writer: pq.ParquetWriter | None = None
    try:
        for chunk in read_csv_chunks(path, dataset, stats, chunk_rows):
            table = pa.Table.from_pandas(chunk, preserve_index=False)
            if writer is None:
                writer = pq.ParquetWriter(partial, table.schema)
            writer.write_table(table.cast(writer.schema))
    finally:
        if writer is not None:
            writer.close()
    if writer is None or stats.rows == 0:
        partial.unlink(missing_ok=True)
        msg = f"{path.name} has a header but no rows"
        raise DatasetFormatError(msg)
    partial.replace(target)
    sidecar.write_text(json.dumps(stats.__dict__, sort_keys=True), encoding="utf-8")
    return pd.read_parquet(target), stats


def load(
    dataset: Dataset,
    data_dir: Path = DEFAULT_DATA_DIR,
    *,
    sample: float | None = None,
    seed: int = 0,
    use_cache: bool = True,
    chunk_rows: int = CHUNK_ROWS,
) -> Loaded:
    """Read every file of ``dataset``; ``sample`` keeps that fraction of each split (seeded)."""
    if sample is not None and not 0 < sample <= 1:
        msg = f"sample must be in (0, 1], got {sample}"
        raise ValueError(msg)
    paths = locate(dataset, data_dir)
    parts: dict[str, list[pd.DataFrame]] = {}
    files: dict[str, FileStats] = {}
    for data_file in dataset.files:
        frame, stats = read_file(
            dataset,
            data_file,
            paths[data_file.name],
            data_dir,
            use_cache=use_cache,
            chunk_rows=chunk_rows,
        )
        parts.setdefault(data_file.split or ALL, []).append(frame)
        files[data_file.name] = stats
    frames: dict[str, pd.DataFrame] = {}
    for split, pieces in parts.items():
        frame = pd.concat(pieces, ignore_index=True) if len(pieces) > 1 else pieces[0]
        if sample is not None and sample < 1:
            frame = frame.sample(frac=sample, random_state=seed).reset_index(drop=True)
        frames[split] = frame
    return Loaded(dataset=dataset, frames=frames, files=files)
