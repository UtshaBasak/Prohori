# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
# Copyright (c) 2026 Utsha Basak
"""Leakage controls: every rule in prohori.ml.cleaning, on the fixture datasets."""

from dataclasses import replace
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from prohori.ml.cleaning import (
    BENIGN,
    BLOCK,
    CATEGORY,
    LABEL,
    ORDER,
    RANDOM,
    SPLITS,
    TIME_BLOCK,
    CleaningReport,
    LeakageError,
    Prepared,
    _interleaved,
    block_split,
    check_leakage,
    check_time_blocks,
    feature_keys,
    make_preprocessor,
    near_duplicate_share,
    order_key,
    prepare,
    prepare_frames,
    standardise_labels,
    stratified_split,
    time_blocks,
)
from prohori.ml.datasets import ALL, load
from prohori.ml.registry import CICIDS2017, UNSW_NB15, Dataset


@pytest.fixture(params=["unsw-nb15", "cicids2017"])
def prepared(request: pytest.FixtureRequest, data_dir: Path) -> Prepared:
    dataset = UNSW_NB15 if request.param == "unsw-nb15" else CICIDS2017
    return prepare(dataset, data_dir, seed=0)


def _keys(prepared: Prepared, split: str) -> set[int]:
    return set(feature_keys(prepared.split(split), prepared.features))


# --------------------------------------------------------------------------- leakage assertions


def test_no_row_is_in_two_splits(prepared: Prepared) -> None:
    for i, first in enumerate(SPLITS):
        for second in SPLITS[i + 1 :]:
            assert not _keys(prepared, first) & _keys(prepared, second), (first, second)
    for split in SPLITS:
        assert not feature_keys(prepared.split(split), prepared.features).duplicated().any()
    assert check_leakage(prepared) == []


def test_identifier_and_label_columns_are_not_features(prepared: Prepared) -> None:
    dataset = prepared.dataset
    for column in [*dataset.drop_columns, LABEL, CATEGORY]:
        assert column not in prepared.features
        assert column not in prepared.x("test").columns
    assert prepared.report.columns_dropped == dataset.drop_columns


def test_transformers_are_fitted_on_train_only(prepared: Prepared) -> None:
    numeric = [c for c in prepared.features if c not in prepared.categorical]
    imputer = prepared.preprocessor.named_transformers_["numeric"]
    np.testing.assert_allclose(
        imputer.statistics_, prepared.train[numeric].median().fillna(0).to_numpy()
    )
    everything = pd.concat([prepared.train, prepared.validation, prepared.test])
    assert not np.allclose(imputer.statistics_, everything[numeric].median().fillna(0).to_numpy())
    # Transforming other data never changes what was learned.
    before = imputer.statistics_.copy()
    prepared.x("test")
    prepared.x("validation")
    np.testing.assert_array_equal(imputer.statistics_, before)


def test_preprocessor_fitted_on_all_data_is_caught(data_dir: Path) -> None:
    prepared = prepare(UNSW_NB15, data_dir)
    everything = pd.concat([prepared.train, prepared.test])
    numeric = [c for c in prepared.features if c not in prepared.categorical]
    leaky = make_preprocessor(numeric, prepared.categorical).fit(everything[prepared.features])
    problems = check_leakage(replace(prepared, preprocessor=leaky))
    assert "imputation medians are not the training medians" in problems
    assert any(p.startswith("categories of proto") for p in problems)


def test_overlap_and_identifier_features_are_caught(data_dir: Path) -> None:
    prepared = prepare(CICIDS2017, data_dir)
    leaked = replace(prepared, test=pd.concat([prepared.test, prepared.train.head(2)]))
    problems = check_leakage(leaked)
    assert "2 rows of test also occur in train" in problems
    assert "test has rows with identical features" not in problems
    with_id = replace(prepared, features=[*prepared.features, "src_ip"])
    with_id.train["src_ip"] = "192.0.2.1"
    with_id.validation["src_ip"] = "192.0.2.2"
    with_id.test["src_ip"] = "192.0.2.3"
    assert any("src_ip" in p for p in check_leakage(with_id))


def test_prepare_refuses_leaky_data(data_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from prohori.ml import cleaning

    monkeypatch.setattr(cleaning, "remove_overlap", lambda frame, *_: frame)
    with pytest.raises(LeakageError, match="rows of test also occur in train"):
        prepare(UNSW_NB15, data_dir)


# --------------------------------------------------------------------------- individual rules


def test_official_split_overlap_is_removed_and_counted(data_dir: Path) -> None:
    report = prepare(UNSW_NB15, data_dir).report
    assert report.rows_loaded == {"train": 43, "test": 13}
    assert report.duplicates_removed == {"train": 3, "test": 0}  # differ only in id
    assert report.conflicting_removed == {"train": 2, "test": 0}
    assert report.overlap_removed == {"validation": 0, "test": 2}
    assert report.rows["test"] == 11
    assert sum(report.rows.values()) == 43 + 13 - 3 - 2 - 2
    assert report.suspect_columns_kept == ["sttl", "dttl", "ct_state_ttl"]


def test_attempted_flows_become_benign(data_dir: Path) -> None:
    prepared = prepare(CICIDS2017, data_dir)
    assert prepared.report.attempted_relabelled == 2
    every = pd.concat([prepared.split(s) for s in SPLITS])
    assert not every[CATEGORY].str.contains("Attempted").any()
    assert set(every[CATEGORY]) >= {BENIGN, "DoS Hulk", "Heartbleed"}
    assert (every[LABEL] == (every[CATEGORY] != BENIGN)).all()


def test_duplicates_across_days_are_removed(data_dir: Path) -> None:
    report = prepare(CICIDS2017, data_dir).report
    # Monday's first flow reappears on each other day with another id, port and time.
    assert report.duplicates_removed == {ALL: 4}
    assert report.non_finite_replaced == 1
    assert report.non_numeric_values == {"flow_iat_min": 1}
    assert sum(report.rows.values()) == 69 - 4


def test_categories_are_learned_from_training_data(data_dir: Path) -> None:
    prepared = prepare(UNSW_NB15, data_dir)
    assert "sctp" not in set(prepared.train["proto"])
    assert "sctp" in set(prepared.test["proto"])
    test = prepared.x("test")
    assert (test.loc[prepared.test["proto"] == "sctp", "proto"] == -1).all()
    assert not test.isna().any().any()
    assert set(test.dtypes) == {np.dtype("float32")}
    assert "-" in set(prepared.test["service"])  # the empty value


def test_split_is_seeded_and_stratified(data_dir: Path) -> None:
    first = prepare(CICIDS2017, data_dir, seed=0)
    again = prepare(CICIDS2017, data_dir, seed=0)
    other = prepare(CICIDS2017, data_dir, seed=1)
    pd.testing.assert_frame_equal(first.test, again.test)
    assert not first.test.equals(other.test)
    classes = first.report.classes
    # A class with one row stays in train; every other class reaches every split.
    assert classes["train"]["Heartbleed"] == 1
    assert "Heartbleed" not in classes["test"]
    for name in classes["train"]:
        if name != "Heartbleed":
            assert name in classes["test"]
            assert name in classes["validation"], name
    assert first.report.seed == 0


def test_stratified_split_never_empties_a_class() -> None:
    frame = pd.DataFrame({CATEGORY: ["a"] * 2 + ["b"] * 10 + ["c"], "x": range(13)})
    rest, part = stratified_split(frame, 0.3, seed=0)
    assert part[CATEGORY].value_counts().to_dict() == {"b": 3, "a": 1}
    assert rest[CATEGORY].value_counts().to_dict() == {"b": 7, "a": 1, "c": 1}
    assert sorted([*rest["x"], *part["x"]]) == list(range(13))


def test_suspect_columns_can_be_dropped(data_dir: Path) -> None:
    prepared = prepare(UNSW_NB15, data_dir, drop_suspect=True)
    assert not set(UNSW_NB15.suspect_columns) & set(prepared.features)
    assert prepared.report.columns_dropped["sttl"] == "suspect"
    assert prepared.report.suspect_columns_kept == []


def test_class_wins_over_a_contradicting_label() -> None:
    frame = pd.DataFrame(
        {
            "attack_cat": pd.array(["Normal", "DoS", None, "Normal"], dtype="string"),
            "label": [0.0, 1.0, 0.0, 1.0],
            "x": [1.0, 2.0, 3.0, 4.0],
        }
    )
    report = CleaningReport(dataset="unsw-nb15", seed=0)
    out = standardise_labels(frame, UNSW_NB15, report)
    assert out[CATEGORY].tolist() == [BENIGN, "DoS", BENIGN, BENIGN]
    assert out[LABEL].tolist() == [0, 1, 0, 0]
    assert report.label_mismatches == 1
    assert list(out.columns) == ["x", CATEGORY, LABEL]


def test_attempted_suffix_alone_is_enough() -> None:
    dataset: Dataset = replace(CICIDS2017, attempted_column=None)
    frame = pd.DataFrame(
        {"label": pd.array(["BENIGN", "Bot - Attempted", "Bot"], dtype="string"), "x": [1, 2, 3]}
    )
    report = CleaningReport(dataset="cicids2017", seed=0)
    out = standardise_labels(frame, dataset, report)
    assert out[CATEGORY].tolist() == [BENIGN, BENIGN, "Bot"]
    assert report.attempted_relabelled == 1


def test_frames_must_be_a_known_layout(data_dir: Path) -> None:
    frames = load(UNSW_NB15, data_dir).frames
    with pytest.raises(ValueError, match="expected splits"):
        prepare_frames(UNSW_NB15, {"train": frames["train"]})


def test_report_is_plain_data(data_dir: Path) -> None:
    report = prepare(CICIDS2017, data_dir, sample=0.8, seed=2).report.to_dict()
    assert report["dataset"] == "cicids2017"
    assert report["rows_loaded"] == {ALL: 55}
    assert set(report["rows"]) == set(SPLITS)


# --------------------------------------------------------------------------- time blocks (step 30)


def _timeline(n: int, classes: tuple[str, ...] = ("Benign",)) -> pd.DataFrame:
    rng = np.random.default_rng(1)
    return pd.DataFrame(
        {
            CATEGORY: rng.choice(np.array(classes, dtype=object), size=n),
            ORDER: rng.permutation(n).astype("int64"),
            "x": rng.normal(size=n),
        }
    )


def test_no_training_row_lies_inside_a_held_out_time_block(prepared: Prepared) -> None:
    assert prepared.validation_method == TIME_BLOCK
    assert check_time_blocks(prepared) == []
    for name in ("train", "validation"):
        assert prepared.split(name)[BLOCK].notna().all()
    held = set(prepared.validation[BLOCK])
    assert held.isdisjoint(set(prepared.train[BLOCK]))


def test_whole_blocks_move_and_every_class_keeps_training_rows() -> None:
    frame = _timeline(1000, ("Benign", "DoS", "Worms"))
    rest, part = block_split(frame, 0.2, seed=0, blocks=10)
    assert len(rest) + len(part) == len(frame)
    for name, group in part.groupby(CATEGORY):
        assert group[BLOCK].nunique() == 2  # 20 % of 10 blocks
        assert name in set(rest[CATEGORY])
    assert set(part[BLOCK]).isdisjoint(set(rest[BLOCK]))
    assert _interleaved(part, rest, "validation", "train") == []
    again, _ = block_split(frame, 0.2, seed=0, blocks=10)
    other, _ = block_split(frame, 0.2, seed=1, blocks=10)
    assert again.equals(rest)
    assert not other.equals(rest)


def test_rows_moved_between_blocks_are_caught_by_their_times() -> None:
    frame = _timeline(400)
    rest, part = block_split(frame, 0.25, seed=0, blocks=8)
    # A held-out row put back into training sits inside its block's time range.
    middle = part.sort_values(ORDER).iloc[[len(part) // 2]]
    leaked = pd.concat([rest, middle])
    assert _interleaved(part, leaked, "validation", "train") == [
        "1 train rows lie inside a time block of validation"
    ]


def test_equal_times_share_a_block() -> None:
    frame = pd.DataFrame({CATEGORY: ["Benign"] * 6, ORDER: [5, 5, 5, 6, 6, 7], "x": range(6)})
    blocks = time_blocks(frame, blocks=6)
    assert blocks.tolist() == ["Benign#0"] * 3 + ["Benign#3"] * 2 + ["Benign#5"]


def test_order_comes_from_times_or_the_file_order() -> None:
    times = pd.DataFrame(
        {"timestamp": pd.array(["2017-07-07 11:59:50.5", None, "bad"], dtype="string")}
    )
    order = order_key(times, CICIDS2017)
    assert order[0] == pd.Timestamp("2017-07-07 11:59:50.5").value
    assert order[1:].tolist() == [1, 2]  # unreadable: the row's position
    ids = pd.DataFrame({"id": pd.array(["10", "x", "30"], dtype="string")})
    assert order_key(ids, UNSW_NB15).tolist() == [10, 1, 30]
    assert order_key(pd.DataFrame({"y": [1, 2]}), UNSW_NB15).tolist() == [0, 1]


def test_internal_columns_are_never_features(prepared: Prepared) -> None:
    for column in (ORDER, BLOCK):
        assert column not in prepared.features
        assert column not in prepared.x("train").columns


def test_random_validation_is_kept_for_comparison(data_dir: Path) -> None:
    random = prepare(UNSW_NB15, data_dir, seed=0, validation=RANDOM)
    assert random.report.validation_method == RANDOM
    assert check_leakage(random) == []
    with pytest.raises(ValueError, match="validation must be one of"):
        prepare(UNSW_NB15, data_dir, seed=0, validation="days")


def test_near_duplicates_are_counted_after_rounding() -> None:
    train = pd.DataFrame({LABEL: [0, 0, 1], "x": [1.234, 50.0, 7.0]})
    validation = pd.DataFrame({LABEL: [0, 0, 0, 1], "x": [1.236, 50.4, 9.0, 7.0]})
    # 1.236 rounds like 1.234 and 50.4 like 50 (two significant digits); attacks are ignored.
    assert near_duplicate_share(train, validation, ["x"]) == pytest.approx(2 / 3)
    assert near_duplicate_share(train, validation[validation[LABEL] == 1], ["x"]) is None
