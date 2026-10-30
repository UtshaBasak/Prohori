"""The dataset registry and chunked, cached CSV reading."""

import json
from dataclasses import replace
from pathlib import Path

import pandas as pd
import pytest

from prohori.ml import datasets
from prohori.ml.datasets import (
    ALL,
    DatasetFormatError,
    DatasetMissingError,
    FileStats,
    load,
    locate,
    read_csv_chunks,
)
from prohori.ml.registry import (
    CICIDS2017,
    DATASETS,
    UNSW_NB15,
    get_dataset,
    normalise_column,
)

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "ml"


def test_column_names_are_normalised() -> None:
    assert normalise_column(" Flow Bytes/s ") == "flow_bytes_s"
    assert normalise_column("Down/Up Ratio") == "down_up_ratio"
    assert normalise_column("FWD Init Win Bytes") == "fwd_init_win_bytes"
    assert normalise_column("ct_src_dport_ltm") == "ct_src_dport_ltm"
    assert normalise_column(chr(0xFEFF) + "id") == "id"  # the UNSW-NB15 files start with a BOM


def test_registry_describes_both_datasets() -> None:
    assert set(DATASETS) == {"unsw-nb15", "cicids2017"}
    assert get_dataset("unsw-nb15") is UNSW_NB15
    with pytest.raises(KeyError, match="known: unsw-nb15, cicids2017"):
        get_dataset("kdd99")
    assert UNSW_NB15.has_official_split
    assert not CICIDS2017.has_official_split
    for dataset in DATASETS.values():
        assert dataset.licence
        assert dataset.citation
        assert dataset.manual_steps
    # Every column the cleaning code names exists in the fixtures' headers.
    for dataset in DATASETS.values():
        for data_file in dataset.files:
            header = (FIXTURES / "raw" / dataset.name / data_file.name).read_text().splitlines()[0]
            names = {normalise_column(c) for c in header.split(",")}
            missing = set(dataset.required_columns) | set(dataset.suspect_columns)
            assert missing <= names, (data_file.name, missing - names)


def test_every_file_is_pinned() -> None:
    archive = CICIDS2017.archive
    assert archive is not None
    assert archive.url.startswith("https://")
    assert archive.size > 300_000_000
    assert len(archive.sha256) == 64
    assert all(f.size and f.sha256 for f in CICIDS2017.files)
    assert all(f.size and f.sha256 and f.rows for f in UNSW_NB15.files)


def test_missing_files_explain_how_to_get_them(tmp_path: Path) -> None:
    with pytest.raises(DatasetMissingError) as error:
        locate(UNSW_NB15, tmp_path)
    message = str(error.value)
    assert "UNSW_NB15_training-set.csv" in message
    assert "research.unsw.edu.au" in message
    assert "1. " in message


def test_chunked_reading_types_and_counts(data_dir: Path) -> None:
    path = data_dir / "raw" / "cicids2017" / "wednesday.csv"
    stats = FileStats()
    chunks = list(read_csv_chunks(path, CICIDS2017, stats, chunk_rows=4))
    assert len(chunks) == 4
    frame = pd.concat(chunks, ignore_index=True)
    whole = pd.concat(read_csv_chunks(path, CICIDS2017), ignore_index=True)
    pd.testing.assert_frame_equal(frame, whole)
    assert stats.rows == len(frame) == 15
    assert frame["flow_bytes_s"].dtype == "float64"
    assert frame["src_ip"].dtype == "string"
    assert frame["label"].dtype == "string"
    assert frame.loc[0, "flow_bytes_s"] == float("inf")  # "Infinity" is a number
    assert frame["flow_bytes_s"].isna().iloc[1]  # empty
    assert stats.non_numeric == {"flow_iat_min": 1}  # "not-a-number"


def test_unexpected_files_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "x.csv"
    path.write_text("id,proto,label\n1,tcp,0\n", encoding="utf-8")
    with pytest.raises(DatasetFormatError, match="does not look like unsw-nb15"):
        list(read_csv_chunks(path, UNSW_NB15))
    path.write_text("Src IP,src ip\n1,2\n", encoding="utf-8")
    with pytest.raises(DatasetFormatError, match="duplicated"):
        list(read_csv_chunks(path, CICIDS2017))


def test_header_only_file_is_an_error(data_dir: Path) -> None:
    folder = data_dir / "raw" / "unsw-nb15"
    train = folder / "UNSW_NB15_training-set.csv"
    train.write_text(train.read_text().splitlines()[0] + "\n", encoding="utf-8")
    with pytest.raises(DatasetFormatError, match="no rows"):
        load(UNSW_NB15, data_dir)


def test_load_splits_and_parquet_cache(data_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    loaded = load(UNSW_NB15, data_dir)
    assert set(loaded.frames) == {"train", "test"}
    assert len(loaded.frames["train"]) == 43
    assert loaded.files["UNSW_NB15_training-set.csv"].rows == 43
    cached = sorted((data_dir / "processed" / "unsw-nb15").iterdir())
    assert [p.suffix for p in cached] == [".json", ".parquet", ".json", ".parquet"]

    def no_csv(*_: object, **__: object) -> None:
        raise AssertionError("read the CSV although the cache is current")

    monkeypatch.setattr(datasets, "read_csv_chunks", no_csv)
    again = load(UNSW_NB15, data_dir)
    pd.testing.assert_frame_equal(again.frames["train"], loaded.frames["train"])
    assert again.files == loaded.files
    monkeypatch.undo()

    # A changed raw file gets a new cache entry rather than a stale one.
    train = data_dir / "raw" / "unsw-nb15" / "UNSW_NB15_training-set.csv"
    lines = train.read_text().splitlines()
    train.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")
    assert len(load(UNSW_NB15, data_dir).frames["train"]) == 42
    assert len(list((data_dir / "processed" / "unsw-nb15").glob("*.parquet"))) == 3


def test_days_are_concatenated_without_a_split(data_dir: Path) -> None:
    loaded = load(CICIDS2017, data_dir, use_cache=False)
    assert list(loaded.frames) == [ALL]
    assert len(loaded.frames[ALL]) == sum(s.rows for s in loaded.files.values()) == 69


def test_sampling_is_seeded_and_validated(data_dir: Path) -> None:
    first = load(CICIDS2017, data_dir, sample=0.5, seed=3).frames[ALL]
    second = load(CICIDS2017, data_dir, sample=0.5, seed=3).frames[ALL]
    other = load(CICIDS2017, data_dir, sample=0.5, seed=4).frames[ALL]
    assert len(first) == 34
    pd.testing.assert_frame_equal(first, second)
    assert not first["id"].equals(other["id"])
    for bad in (0, 1.5, -0.1):
        with pytest.raises(ValueError, match="sample must be"):
            load(CICIDS2017, data_dir, sample=bad)


def test_cache_sidecar_is_json(data_dir: Path) -> None:
    load(replace(UNSW_NB15), data_dir)
    sidecar = next((data_dir / "processed" / "unsw-nb15").glob("UNSW_NB15_testing-set-*.json"))
    assert json.loads(sidecar.read_text(encoding="utf-8")) == {"non_numeric": {}, "rows": 13}
