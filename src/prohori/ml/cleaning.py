"""Leakage controls for flow datasets, applied in this order.

1. **Labels.** Every dataset gets the same two columns: ``attack_cat`` (``"Benign"`` or the
   attack class) and ``label`` (0 benign, 1 attack). Flows labelled ``"<attack> - Attempted"``
   carried no attack payload and become benign, as the CIC-IDS-2017 improved release's authors
   advise; they are never a class of their own.
2. **Columns.** Identifier, address, port, time and label-derived columns are dropped, with
   the reason recorded. Suspect columns are dropped only when asked.
3. **Values.** Infinite values become missing; missing values are imputed later, from the
   training data only.
4. **Duplicates.** Exact duplicates (features and class) are removed. Rows whose features are
   identical but whose classes differ are all removed, since no label is right for them.
5. **Split.** The official partition when there is one, with a validation set carved out of the
   training data; otherwise a seeded split stratified by class. Validation is for tuning
   thresholds; the test set is for the one final evaluation.
6. **Overlap.** A validation or test row whose features also occur in an earlier split is
   removed and counted.
7. **Transforms.** Imputation medians and category codes are fitted on the training split only.

:func:`check_leakage` verifies the result and :func:`prepare` refuses to return data that fails
it.

``clean=False`` skips steps 4 and 6 and keeps the numeric identifier and port columns. That
variant exists only to measure how much the controls change the results; it is what a pipeline
without them would report, and no model trained on it is meant to be used.
"""

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from prohori.ml import MissingExtraError
from prohori.ml.registry import LABEL_DERIVED, Dataset

try:
    import numpy as np
    import pandas as pd
    from sklearn.compose import ColumnTransformer
    from sklearn.impute import SimpleImputer
    from sklearn.preprocessing import OrdinalEncoder
except ImportError as exc:  # pragma: no cover - exercised in a subprocess test
    raise MissingExtraError("prohori.ml.cleaning") from exc

from prohori.ml.datasets import ALL, DEFAULT_DATA_DIR, load

LABEL = "label"
CATEGORY = "attack_cat"
BENIGN = "Benign"
ATTEMPTED_SUFFIX = " - attempted"
#: Value of a missing categorical feature; fixed, so it learns nothing from the data.
MISSING_CATEGORY = "-"
SUSPECT = "suspect"
SPLITS = ("train", "validation", "test")
VALIDATION_SIZE = 0.2
TEST_SIZE = 0.3


class LeakageError(AssertionError):
    """Prepared data failed :func:`check_leakage`."""


@dataclass
class CleaningReport:
    """What cleaning changed, for the results files and the documentation."""

    dataset: str
    seed: int
    #: False for the uncleaned comparison variant (no deduplication or overlap removal).
    cleaned: bool = True
    rows_loaded: dict[str, int] = field(default_factory=dict)
    attempted_relabelled: int = 0
    #: Rows whose 0/1 label disagrees with their class; the class is used.
    label_mismatches: int = 0
    columns_dropped: dict[str, str] = field(default_factory=dict)
    suspect_columns_kept: list[str] = field(default_factory=list)
    non_finite_replaced: int = 0
    #: Column -> values that were not numbers when the CSV was read (now missing).
    non_numeric_values: dict[str, int] = field(default_factory=dict)
    duplicates_removed: dict[str, int] = field(default_factory=dict)
    conflicting_removed: dict[str, int] = field(default_factory=dict)
    overlap_removed: dict[str, int] = field(default_factory=dict)
    rows: dict[str, int] = field(default_factory=dict)
    classes: dict[str, dict[str, int]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Prepared:
    """Clean train, validation and test frames with a preprocessor fitted on train."""

    dataset: Dataset
    train: pd.DataFrame
    validation: pd.DataFrame
    test: pd.DataFrame
    features: list[str]
    categorical: list[str]
    preprocessor: ColumnTransformer
    report: CleaningReport

    def split(self, name: str) -> pd.DataFrame:
        frames = {"train": self.train, "validation": self.validation, "test": self.test}
        return frames[name]

    def x(self, name: str) -> pd.DataFrame:
        """The split's features, transformed, as float32."""
        transformed: pd.DataFrame = self.preprocessor.transform(self.split(name)[self.features])
        return transformed.astype("float32")

    def y(self, name: str) -> pd.Series:
        return self.split(name)[LABEL]


def standardise_labels(
    frame: pd.DataFrame, dataset: Dataset, report: CleaningReport
) -> pd.DataFrame:
    """Replace the dataset's label columns with ``attack_cat`` and ``label``."""
    category = frame[dataset.category_column].astype("string").str.strip()
    given = frame[dataset.label_column] if dataset.label_column else None
    if given is not None:
        category = category.fillna(given.map({0: BENIGN}).astype("string"))
    category = category.fillna("Unknown")
    attempted = category.str.lower().str.endswith(ATTEMPTED_SUFFIX).to_numpy(dtype=bool)
    if dataset.attempted_column and dataset.attempted_column in frame:
        attempted |= (frame[dataset.attempted_column].fillna(-1) != -1).to_numpy()
    benign = (
        category.str.lower().isin([*dataset.benign_values, BENIGN.lower()]).to_numpy(dtype=bool)
        | attempted
    )
    if given is not None:
        report.label_mismatches += int(((given != 0).to_numpy() == benign).sum())
    report.attempted_relabelled += int(attempted.sum())
    labels = [c for c in (dataset.category_column, dataset.label_column) if c]
    out = frame.drop(columns=labels)
    out[CATEGORY] = np.where(benign, BENIGN, category.to_numpy(dtype=object))
    out[LABEL] = (~benign).astype("int8")
    return out


def drop_columns(
    frame: pd.DataFrame,
    dataset: Dataset,
    report: CleaningReport,
    *,
    drop_suspect: bool,
    clean: bool = True,
) -> pd.DataFrame:
    """Drop the dataset's listed columns; uncleaned, only text and label-derived ones."""
    dropped = {
        c: why
        for c, why in dataset.drop_columns.items()
        if c in frame
        and (clean or why == LABEL_DERIVED or not pd.api.types.is_numeric_dtype(frame[c]))
    }
    if drop_suspect:
        dropped |= {c: SUSPECT for c in dataset.suspect_columns if c in frame}
    else:
        report.suspect_columns_kept = [c for c in dataset.suspect_columns if c in frame]
    report.columns_dropped |= dropped
    return frame.drop(columns=list(dropped))


def feature_columns(frame: pd.DataFrame) -> list[str]:
    return [c for c in frame.columns if c not in (LABEL, CATEGORY)]


def replace_non_finite(frame: pd.DataFrame, report: CleaningReport) -> pd.DataFrame:
    numeric = frame[feature_columns(frame)].select_dtypes("number").columns
    values = frame[numeric].to_numpy(dtype="float64")
    infinite = np.isinf(values)
    report.non_finite_replaced += int(infinite.sum())
    if infinite.any():
        frame = frame.copy()
        frame[numeric] = np.where(infinite, np.nan, values)
    return frame


def feature_keys(frame: pd.DataFrame, features: list[str]) -> pd.Series:
    """A 64-bit hash of each row's features; equal features give equal keys."""
    return pd.util.hash_pandas_object(frame[features], index=False)


def deduplicate(frame: pd.DataFrame, report: CleaningReport, split: str) -> pd.DataFrame:
    """Drop exact duplicates, then every row of a group with equal features but other classes."""
    features = feature_columns(frame)
    keyed = frame.assign(_key=feature_keys(frame, features).to_numpy())
    exact = keyed.duplicated(subset=["_key", CATEGORY])
    keyed = keyed[~exact]
    conflicting = keyed["_key"].duplicated(keep=False)
    report.duplicates_removed[split] = int(exact.sum())
    report.conflicting_removed[split] = int(conflicting.sum())
    return keyed[~conflicting].drop(columns="_key")


def stratified_split(
    frame: pd.DataFrame, fraction: float, seed: int
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Move ``fraction`` of each class to the second frame (at least one row, never all).

    A class with a single row stays in the first frame, so it may be absent from the second;
    the cleaning report's class counts show it.
    """
    rng = np.random.default_rng(seed)
    chosen: list[Any] = []
    for _, group in frame.groupby(CATEGORY, sort=True):
        n = len(group)
        if n < 2:
            continue
        k = min(max(round(n * fraction), 1), n - 1)
        chosen.extend(rng.choice(group.index.to_numpy(), size=k, replace=False))
    taken = frame.index.isin(chosen)
    return frame[~taken], frame[taken]


def remove_overlap(
    frame: pd.DataFrame, earlier: list[pd.DataFrame], report: CleaningReport, split: str
) -> pd.DataFrame:
    """Drop rows of ``frame`` whose features occur in any of the ``earlier`` splits."""
    features = feature_columns(frame)
    seen: set[int] = set()
    for other in earlier:
        seen.update(feature_keys(other, features).tolist())
    overlap = feature_keys(frame, features).isin(seen).to_numpy()
    report.overlap_removed[split] = int(overlap.sum())
    return frame[~overlap]


def make_preprocessor(numeric: list[str], categorical: list[str]) -> ColumnTransformer:
    """Median imputation for numbers, train-learned codes for text (unseen values -> -1)."""
    transformers: list[tuple[str, Any, list[str]]] = [
        ("numeric", SimpleImputer(strategy="median", keep_empty_features=True), numeric)
    ]
    if categorical:
        encoder = OrdinalEncoder(handle_unknown="use_encoded_value", unknown_value=-1)
        transformers.append(("categorical", encoder, categorical))
    transformer = ColumnTransformer(transformers, verbose_feature_names_out=False)
    transformer.set_output(transform="pandas")
    return transformer


def _categorical(frame: pd.DataFrame, dataset: Dataset) -> pd.DataFrame:
    columns = [c for c in dataset.categorical_columns if c in frame]
    if not columns:
        return frame
    frame = frame.copy()
    for column in columns:
        frame[column] = frame[column].astype("string").fillna(MISSING_CATEGORY).astype(object)
    return frame


def prepare_frames(
    dataset: Dataset,
    frames: dict[str, pd.DataFrame],
    *,
    seed: int = 0,
    validation_size: float = VALIDATION_SIZE,
    test_size: float = TEST_SIZE,
    drop_suspect: bool = False,
    clean: bool = True,
) -> Prepared:
    """Apply every control to loaded frames (``train``/``test``, or ``all``)."""
    report = CleaningReport(dataset=dataset.name, seed=seed, cleaned=clean)
    cleaned: dict[str, pd.DataFrame] = {}
    for split, frame in frames.items():
        report.rows_loaded[split] = len(frame)
        frame = standardise_labels(frame, dataset, report)
        frame = drop_columns(frame, dataset, report, drop_suspect=drop_suspect, clean=clean)
        frame = replace_non_finite(frame, report)
        frame = _categorical(frame, dataset)
        cleaned[split] = deduplicate(frame, report, split) if clean else frame
    if set(cleaned) == {"train", "test"}:
        train, validation = stratified_split(cleaned["train"], validation_size, seed)
        test = cleaned["test"]
    elif set(cleaned) == {ALL}:
        rest, test = stratified_split(cleaned[ALL], test_size, seed)
        train, validation = stratified_split(rest, validation_size / (1 - test_size), seed + 1)
    else:
        msg = f"expected splits train+test or {ALL}, got {sorted(cleaned)}"
        raise ValueError(msg)
    if clean:
        validation = remove_overlap(validation, [train], report, "validation")
        test = remove_overlap(test, [train, validation], report, "test")

    features = feature_columns(train)
    categorical = [c for c in dataset.categorical_columns if c in features]
    numeric = [c for c in features if c not in categorical]
    preprocessor = make_preprocessor(numeric, categorical).fit(train[features])
    splits = {"train": train, "validation": validation, "test": test}
    for name, frame in splits.items():
        splits[name] = frame.reset_index(drop=True)
        report.rows[name] = len(frame)
        report.classes[name] = {
            str(k): int(v) for k, v in frame[CATEGORY].value_counts().sort_index().items()
        }
    prepared = Prepared(
        dataset=dataset,
        train=splits["train"],
        validation=splits["validation"],
        test=splits["test"],
        features=features,
        categorical=categorical,
        preprocessor=preprocessor,
        report=report,
    )
    problems = check_leakage(prepared) if clean else []
    if problems:
        raise LeakageError("; ".join(problems))
    return prepared


def prepare(
    dataset: Dataset,
    data_dir: Path = DEFAULT_DATA_DIR,
    *,
    seed: int = 0,
    sample: float | None = None,
    drop_suspect: bool = False,
    clean: bool = True,
    use_cache: bool = True,
) -> Prepared:
    """Load ``dataset`` from ``data_dir`` and :func:`prepare_frames` it."""
    loaded = load(dataset, data_dir, sample=sample, seed=seed, use_cache=use_cache)
    prepared = prepare_frames(
        dataset, loaded.frames, seed=seed, drop_suspect=drop_suspect, clean=clean
    )
    for stats in loaded.files.values():
        for column, count in stats.non_numeric.items():
            values = prepared.report.non_numeric_values
            values[column] = values.get(column, 0) + count
    return prepared


def check_leakage(prepared: Prepared) -> list[str]:
    """Every way the prepared data could leak information into the test result."""
    problems: list[str] = []
    dataset, features = prepared.dataset, prepared.features
    banned = set(dataset.drop_columns) | {LABEL, CATEGORY}
    if dataset.label_column:
        banned.add(dataset.label_column)
    present = sorted(banned & set(features))
    if present:
        problems.append(f"columns that must be dropped are features: {', '.join(present)}")
    keys = {name: feature_keys(prepared.split(name), features) for name in SPLITS}
    for name, key in keys.items():
        if key.duplicated().any():
            problems.append(f"{name} has rows with identical features")
    for i, first in enumerate(SPLITS):
        for second in SPLITS[i + 1 :]:
            shared = len(set(keys[first]) & set(keys[second]))
            if shared:
                problems.append(f"{shared} rows of {second} also occur in {first}")
    problems.extend(_fitted_on_train(prepared))
    return problems


def _fitted_on_train(prepared: Prepared) -> list[str]:
    """The preprocessor's learned values are exactly those of the training split."""
    problems: list[str] = []
    train = prepared.train
    for name, transformer, columns in prepared.preprocessor.transformers_:
        if name == "numeric":
            expected = train[columns].median(skipna=True).fillna(0).to_numpy(dtype="float64")
            if not np.allclose(transformer.statistics_, expected, equal_nan=True):
                problems.append("imputation medians are not the training medians")
        elif name == "categorical":
            for column, learned in zip(columns, transformer.categories_, strict=True):
                if set(learned) != set(train[column].unique()):
                    problems.append(f"categories of {column} were not learned from training data")
    return problems
