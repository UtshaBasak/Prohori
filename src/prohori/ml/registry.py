"""The public flow datasets Prohori prepares: where they come from, their files and columns.

Standard library only, so ``scripts/download_datasets.py list`` and ``verify`` work without the
``ml`` extra. Column names are normalised (see :func:`normalise_column`) before they are compared
with the names here.

Checksums were measured by the maintainer on the date in ``checked``; the publishers do not
publish any. ``None`` means the file has not been pinned yet: ``verify`` then prints the hash it
computed and warns instead of passing silently.
"""

import re
from dataclasses import dataclass, field

#: Why each dropped column is dropped. Shown in the cleaning report and in docs/DATASETS.md.
IDENTIFIER = "identifier"
ADDRESS = "address"
PORT = "port"
TIME = "time"
LABEL_DERIVED = "label-derived"


@dataclass(frozen=True)
class DataFile:
    """One CSV file of a dataset, as it sits in ``data/raw/<dataset>/``."""

    name: str
    size: int | None = None  # bytes
    sha256: str | None = None
    rows: int | None = None  # data rows, without the header
    split: str | None = None  # "train" or "test" for official partitions


@dataclass(frozen=True)
class Archive:
    """A zip the CSV files are extracted from, downloaded from ``url``."""

    name: str
    url: str
    size: int
    sha256: str


@dataclass(frozen=True)
class Dataset:
    """A dataset and everything the download script and the cleaning code need to know."""

    name: str
    title: str
    version: str
    homepage: str
    licence: str
    citation: str
    files: tuple[DataFile, ...]
    #: How to get the files by hand; used when there is no direct download.
    manual_steps: tuple[str, ...]
    #: Column holding the attack class (benign rows included).
    category_column: str
    #: Values of ``category_column`` that mean benign traffic, compared case-insensitively.
    benign_values: tuple[str, ...]
    #: Text (not numeric) feature columns, encoded with categories learned on training data.
    categorical_columns: tuple[str, ...]
    #: Columns removed before training, with the reason (see the constants above).
    drop_columns: dict[str, str]
    #: A 0/1 label column, if the dataset has one besides ``category_column``.
    label_column: str | None = None
    #: Column marking flows labelled "<attack> - Attempted"; -1 means not attempted.
    attempted_column: str | None = None
    #: Features reported in the literature to separate the classes for reasons unrelated to
    #: the attacks themselves. Kept by default and listed in the cleaning report.
    suspect_columns: tuple[str, ...] = ()
    archive: Archive | None = None
    checked: str = ""
    notes: tuple[str, ...] = field(default=())

    @property
    def has_official_split(self) -> bool:
        return any(f.split for f in self.files)

    @property
    def text_columns(self) -> tuple[str, ...]:
        """Columns read as text: categoricals, the class column and text identifiers."""
        text = [*self.categorical_columns, self.category_column]
        text += [c for c, why in self.drop_columns.items() if why in (IDENTIFIER, ADDRESS, TIME)]
        return tuple(dict.fromkeys(text))

    @property
    def required_columns(self) -> tuple[str, ...]:
        """Columns that must be present for the file to be recognised as this dataset."""
        columns = [self.category_column, *self.categorical_columns, *self.drop_columns]
        if self.label_column:
            columns.append(self.label_column)
        return tuple(dict.fromkeys(columns))


def normalise_column(name: str) -> str:
    """``"Flow Bytes/s"`` -> ``"flow_bytes_s"``: lower case, runs of other characters to ``_``."""
    return re.sub(r"[^0-9a-z]+", "_", name.strip().lower()).strip("_")


UNSW_NB15 = Dataset(
    name="unsw-nb15",
    title="UNSW-NB15 (official training and testing partition)",
    version="partition files as published by UNSW Canberra (page last updated 2021-06-02)",
    homepage="https://research.unsw.edu.au/projects/unsw-nb15-dataset",
    licence=(
        "Free use for academic research is granted in perpetuity; commercial use must be "
        "agreed with the authors (Nour Moustafa and Jill Slay), who assert copyright. "
        "Not redistributed by Prohori."
    ),
    citation=(
        "N. Moustafa and J. Slay, 'UNSW-NB15: a comprehensive data set for network intrusion "
        "detection systems (UNSW-NB15 network data set)', MilCIS 2015; the dataset page lists "
        "further papers its authors ask users to cite."
    ),
    files=(
        DataFile(
            "UNSW_NB15_training-set.csv",
            size=32_293_018,
            sha256="bec7dd5ec88dc2a0ccc7a07879d338395ed7421750f675fd0339e07dfe0648fa",
            rows=175_341,
            split="train",
        ),
        DataFile(
            "UNSW_NB15_testing-set.csv",
            size=15_380_800,
            sha256="734fe6642edf758f7c94d7d9149426b49d202fe8e7bf0bef47392489c3c0a559",
            rows=82_332,
            split="test",
        ),
    ),
    manual_steps=(
        "Open https://research.unsw.edu.au/projects/unsw-nb15-dataset and follow the 'HERE' "
        "download link (a UNSW SharePoint folder; it needs a browser).",
        "In the folder, open 'CSV Files', then 'Training and Testing Sets'.",
        "Download UNSW_NB15_training-set.csv and UNSW_NB15_testing-set.csv.",
        "Put both files, unrenamed, in data/raw/unsw-nb15/.",
        "Run: uv run python scripts/download_datasets.py verify unsw-nb15",
    ),
    category_column="attack_cat",
    label_column="label",
    benign_values=("normal",),
    categorical_columns=("proto", "service", "state"),
    drop_columns={"id": IDENTIFIER},
    # Time-to-live values reflect the testbed's hosts rather than the attacks; several studies
    # report that sttl alone separates most of the classes.
    suspect_columns=("sttl", "dttl", "ct_state_ttl"),
    notes=(
        "The partition files contain no addresses, ports or timestamps (those are only in the "
        "four full CSV files, which Prohori does not use).",
        "The training file is the larger one (175,341 rows) and the testing file the smaller "
        "(82,332), as published.",
    ),
)

_CICIDS_DAYS = (
    DataFile(
        "monday.csv",
        size=207_875_155,
        sha256="51fe5dc962626efb4ae70dce0303072fb780da0932822b651202ee9c2fbc1aff",
    ),
    DataFile(
        "tuesday.csv",
        size=178_397_720,
        sha256="e2a0a5b631dfc6b455cc9f9a88b944110637d70a7f74171473925f76f38b6b0c",
    ),
    DataFile(
        "wednesday.csv",
        size=291_290_505,
        sha256="bf46c5f3c792e8817381f724511229569606918eaf07ac986d7a2592b6341bc2",
    ),
    DataFile(
        "thursday.csv",
        size=189_519_159,
        sha256="78a4d11eaf473d099e30e71ddb01e0f38218e844c0a9cdd36602145d674af482",
    ),
    DataFile(
        "friday.csv",
        size=285_188_226,
        sha256="ebd499e6f23bd59f9cb81bec28178491b02b925fa5640a24215c9437d79482d0",
    ),
)

CICIDS2017 = Dataset(
    name="cicids2017",
    title="CIC-IDS-2017, improved release (Engelen, Liu et al., CNS 2022)",
    version="CICIDS2017_improved.zip, last modified 2023-04-27",
    homepage="https://intrusion-detection.distrinet-research.be/CNS2022/Dataset_Download.html",
    licence=(
        "No licence is stated on the distributor's site. The original CIC-IDS-2017 is "
        "'publicly available for researchers' and asks for a citation; the improved release "
        "asks for its own. Not redistributed by Prohori."
    ),
    citation=(
        "L. Liu, G. Engelen, T. Lynar, D. Essam and W. Joosen, 'Error Prevalence in NIDS "
        "datasets: A Case Study on CIC-IDS-2017 and CSE-CIC-IDS-2018', IEEE CNS 2022; and "
        "I. Sharafaldin, A. Habibi Lashkari and A. A. Ghorbani, 'Toward Generating a New "
        "Intrusion Detection Dataset and Intrusion Traffic Characterization', ICISSP 2018."
    ),
    files=_CICIDS_DAYS,
    archive=Archive(
        name="CICIDS2017_improved.zip",
        url="https://intrusion-detection.distrinet-research.be/CNS2022/Datasets/CICIDS2017_improved.zip",
        size=343_549_013,
        sha256="97fdb91d339e2d8cf5627f981b831e5e7e400b981c58181c451a38fd03c48883",
    ),
    checked="2026-10-30",
    manual_steps=(
        "Run: uv run python scripts/download_datasets.py fetch cicids2017",
        "Or download CICIDS2017_improved.zip by hand from the homepage, put it in "
        "data/raw/cicids2017/ and run the same command: it verifies and extracts it.",
    ),
    category_column="label",
    benign_values=("benign",),
    categorical_columns=(),
    attempted_column="attempted_category",
    drop_columns={
        "id": IDENTIFIER,
        "flow_id": IDENTIFIER,
        "src_ip": ADDRESS,
        "dst_ip": ADDRESS,
        "src_port": PORT,
        "dst_port": PORT,
        "timestamp": TIME,
        "attempted_category": LABEL_DERIVED,
    },
    notes=(
        "Supersedes the WTMC 2021 regeneration by the same group, which points to it.",
        "Flows labelled '<attack> - Attempted' carried no attack payload; following the "
        "authors' advice they are relabelled benign and never used as a class.",
        "There is no official split: Prohori makes a seeded, stratified one after removing "
        "duplicates.",
    ),
)

DATASETS: dict[str, Dataset] = {d.name: d for d in (UNSW_NB15, CICIDS2017)}


def get_dataset(name: str) -> Dataset:
    try:
        return DATASETS[name]
    except KeyError:
        msg = f"unknown dataset {name!r}; known: {', '.join(DATASETS)}"
        raise KeyError(msg) from None
