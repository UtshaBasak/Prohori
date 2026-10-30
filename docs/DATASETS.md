# Datasets

The flow-based detectors of the machine-learning track (v0.2.0) are trained and tested on two
public intrusion-detection datasets. This page covers where they come from, their terms, how to
get them and every step taken to keep information from the test data leaking into training.
The design decisions are recorded in [ADR-0019](DECISIONS.md#adr-0019-flow-datasets-and-leakage-controls).

Nothing in this repository contains real data from either dataset: the files are downloaded by
each user into the git-ignored `data/` directory, and the test fixtures are synthetic.

## Contents

- [The datasets](#the-datasets)
- [Getting the files](#getting-the-files)
- [Loading](#loading)
- [Leakage controls](#leakage-controls)
- [Columns removed](#columns-removed)
- [The cleaning report](#the-cleaning-report)
- [Measured on the real data](#measured-on-the-real-data)
- [Using it from Python](#using-it-from-python)
- [Limitations](#limitations)

## The datasets

| | UNSW-NB15 | CIC-IDS-2017 (improved) |
|--|-----------|--------------------------|
| Publisher | UNSW Canberra (Moustafa and Slay) | imec-DistriNet, KU Leuven (Liu, Engelen et al.), from the Canadian Institute for Cybersecurity's original |
| Files used | `UNSW_NB15_training-set.csv` (175,341 rows), `UNSW_NB15_testing-set.csv` (82,332 rows) | `CICIDS2017_improved.zip`: `monday.csv` to `friday.csv` (1.15 GB) |
| Split | Official training/testing partition | None; Prohori makes one |
| Features | 42 after cleaning, 3 of them text (`proto`, `service`, `state`); from the published feature list, to be confirmed on the real files | 82 after cleaning, all numeric |
| Classes | Normal and 9 attack classes | Benign and the attack classes of the five capture days |
| Download | By hand (a SharePoint folder) | `fetch` (direct HTTPS) |
| Licence | Free for academic research; commercial use by agreement with the authors | None stated by the distributor; research use, cite the papers |

**Why the improved CIC-IDS-2017.** The original CSV files have documented problems: flows cut at
the wrong place by a CICFlowMeter bug, wrong labels, and duplicated rows. The DistriNet group
regenerated the flows from the original packet captures with a fixed CICFlowMeter and relabelled
them, first for WTMC 2021 and then again for CNS 2022, whose release
(`CICIDS2017_improved.zip`, last modified 2023-04-27) the WTMC 2021 page itself points to as
the latest. Prohori uses the CNS 2022 release. Its columns differ from the original's (it adds
an `Attempted Category`, RST flag counts, ICMP fields and a total TCP flow time), so results are
not comparable with work on the original CSVs.

**Citations.** Cite the datasets when you publish anything based on them:

- UNSW-NB15: N. Moustafa and J. Slay, "UNSW-NB15: a comprehensive data set for network intrusion
  detection systems (UNSW-NB15 network data set)", MilCIS 2015, plus the further papers listed on
  the [dataset page](https://research.unsw.edu.au/projects/unsw-nb15-dataset).
- CIC-IDS-2017 improved: L. Liu, G. Engelen, T. Lynar, D. Essam and W. Joosen, "Error Prevalence
  in NIDS datasets: A Case Study on CIC-IDS-2017 and CSE-CIC-IDS-2018", IEEE CNS 2022; and the
  original, I. Sharafaldin, A. Habibi Lashkari and A. A. Ghorbani, "Toward Generating a New
  Intrusion Detection Dataset and Intrusion Traffic Characterization", ICISSP 2018.

Licence wording and the dates it was checked are in [LICENSES.md](LICENSES.md).

## Getting the files

Everything goes through `scripts/download_datasets.py`. It never runs on import, and only
`fetch` uses the network.

```bash
uv run python scripts/download_datasets.py --help              # every dataset, with its licence
uv run python scripts/download_datasets.py list                # files, sizes, citations, steps
uv run python scripts/download_datasets.py fetch cicids2017    # download, check, extract
uv run python scripts/download_datasets.py verify              # check sizes and SHA-256
uv run python scripts/download_datasets.py prepare unsw-nb15   # clean, split, print the report
```

**CIC-IDS-2017** (`fetch cicids2017`, about 330 MB, then 1.15 GB on disk):

1. The archive is streamed to `data/raw/cicids2017/CICIDS2017_improved.zip.part`; the download
   stops as soon as it is larger than the pinned size. Redirects are not followed.
2. Its size and SHA-256 are compared with the pinned values. On a mismatch nothing is kept.
3. Only the five expected members are extracted, each by its bare name (a member with a path,
   an unexpected or duplicate member refuses the whole archive), and no more bytes than its
   pinned size are written.
4. `verify` then checks every CSV's size and SHA-256.

If the archive is already in `data/raw/cicids2017/` (downloaded by hand, for example), `fetch`
checks it and extracts it without downloading.

**UNSW-NB15** must be downloaded by hand, because the files are in a SharePoint folder that needs
a browser:

1. Open <https://research.unsw.edu.au/projects/unsw-nb15-dataset> and follow the "HERE" link.
2. In the folder, open "CSV Files", then "Training and Testing Sets".
3. Download `UNSW_NB15_training-set.csv` and `UNSW_NB15_testing-set.csv`.
4. Put both, with their names unchanged, in `data/raw/unsw-nb15/`.
5. Run `uv run python scripts/download_datasets.py verify unsw-nb15`.

UNSW does not publish checksums and the files have not been pinned yet, so `verify` prints their
SHA-256 as `UNPINNED` instead of passing silently. Compare it with someone else's download if
you need certainty.

**Checksums.** Neither publisher gives checksums. The CIC-IDS-2017 values in
`src/prohori/ml/registry.py` were measured by the maintainer on 2026-10-30 from the
distributor's file:

| File | Bytes | SHA-256 |
|------|------:|---------|
| `CICIDS2017_improved.zip` | 343,549,013 | `97fdb91d339e2d8cf5627f981b831e5e7e400b981c58181c451a38fd03c48883` |
| `monday.csv` | 207,875,155 | `51fe5dc962626efb4ae70dce0303072fb780da0932822b651202ee9c2fbc1aff` |
| `tuesday.csv` | 178,397,720 | `e2a0a5b631dfc6b455cc9f9a88b944110637d70a7f74171473925f76f38b6b0c` |
| `wednesday.csv` | 291,290,505 | `bf46c5f3c792e8817381f724511229569606918eaf07ac986d7a2592b6341bc2` |
| `thursday.csv` | 189,519,159 | `78a4d11eaf473d099e30e71ddb01e0f38218e844c0a9cdd36602145d674af482` |
| `friday.csv` | 285,188,226 | `ebd499e6f23bd59f9cb81bec28178491b02b925fa5640a24215c9437d79482d0` |

## Loading

`prohori.ml.datasets.load()` reads each CSV 200,000 rows at a time, so memory use does not depend
on the file size:

- Column names are normalised (`Flow Bytes/s` becomes `flow_bytes_s`); duplicate names after
  normalising are an error, as is a file without the dataset's required columns.
- Text columns (the categorical features, the class, addresses, identifiers and timestamps) stay
  text; every other column is converted to a number. Values that are not numbers become missing
  and are counted per column. `Infinity` is a number and is handled in cleaning.
- Numbers are kept as float64 so that deduplication compares exact values; the models receive
  float32.
- Each converted file is written to `data/processed/<dataset>/<file>-v1-<hash>.parquet`, where
  the hash is the first 16 hex digits of the raw file's SHA-256. A changed raw file is therefore
  never read from a stale cache. The directory can be deleted at any time.
- `sample=0.1` keeps a seeded 10 % of each split, for development on a small machine.

## Leakage controls

`prohori.ml.cleaning.prepare()` applies these steps, in this order, and then runs
`check_leakage()`. If the check finds anything, `prepare()` raises `LeakageError` instead of
returning the data.

1. **Labels.** Every dataset gets the same two columns: `attack_cat` (`Benign` or the attack
   class) and `label` (0 benign, 1 attack). UNSW-NB15's `Normal` becomes `Benign`; where its 0/1
   `label` disagrees with `attack_cat`, the class wins and the row is counted.
2. **"Attempted" flows become benign.** In the improved CIC-IDS-2017, flows of an attack that
   carried no attack payload are labelled `<attack> - Attempted` and have an `Attempted Category`
   other than -1. Their authors write that they must never be a separate class and recommend
   treating them as benign, which Prohori does. The `Attempted Category` column is then dropped,
   because it is derived from the label.
3. **Columns** that identify a flow or the capture rather than describe the traffic are dropped;
   see [Columns removed](#columns-removed).
4. **Infinite values** become missing values (counted). Missing values are filled later with the
   training split's medians.
5. **Duplicates.** Rows equal in every remaining feature and in the class are duplicates; one
   is kept. Since identifiers are already gone, two flows that differ only in their id, port or
   timestamp count as duplicates. Then every row of a group with equal features but different
   classes is removed, because no label is right for all of them.
6. **Split.**
   - UNSW-NB15: the official training file is the training data, minus a validation set of
     20 % stratified by class; the official testing file is the test data.
   - CIC-IDS-2017: after deduplication, a split seeded by `seed` and stratified by class:
     50 % training, 20 % validation, 30 % test. Each class with at least two rows gets at least
     one row in the second part of each split; a class with a single row stays in training.
   - Validation is for choosing thresholds. The test split is meant to be used once, for the
     final result.
7. **Cross-split overlap.** Validation rows whose features occur in training, and test rows whose
   features occur in training or validation, are removed and counted. For UNSW-NB15 this changes
   the official test set: results are therefore not directly comparable with papers that keep it
   whole, and the number removed is always published with them.
8. **Train-only transforms.** Median imputation for numbers and category codes for text are
   fitted on the training split only. A category not seen in training (a new protocol in the
   test data, say) is encoded as -1.

`check_leakage()` verifies that:

- no dropped column, `label` or `attack_cat` is among the features;
- no split has two rows with the same features, and no two splits share a row (compared on a
  64-bit hash of all feature values);
- the imputation medians equal the training split's medians and the learned categories are
  exactly the training split's values.

The tests in `tests/unit/ml/` check each rule on the fixture datasets, and also that the check
catches a preprocessor fitted on all data, copied training rows in the test split and an
identifier left among the features.

## Columns removed

| Dataset | Column | Reason |
|---------|--------|--------|
| UNSW-NB15 | `id` | identifier: the row number |
| CIC-IDS-2017 | `id`, `flow_id` | identifier: row number; addresses, ports and protocol joined together |
| CIC-IDS-2017 | `src_ip`, `dst_ip` | address: the lab's hosts, not the attack's behaviour |
| CIC-IDS-2017 | `src_port`, `dst_port` | port: see below |
| CIC-IDS-2017 | `timestamp` | time: each attack ran at a known time of a known day |
| CIC-IDS-2017 | `attempted_category` | label-derived |

The UNSW-NB15 partition files have no addresses, ports or timestamps (those are only in the four
full CSV files, which Prohori does not use).

**Ports.** Source ports are ephemeral, so they act as identifiers. Destination ports identify the
lab's victim services: a model can learn that a port on a given capture day means an attack
instead of learning what the attack looks like, and the UNSW-NB15 partition has no port to map
it to in the cross-dataset test. Both are dropped; `protocol` is kept.

**Suspect columns.** UNSW-NB15's time-to-live columns (`sttl`, `dttl`, `ct_state_ttl`) are
reported in the literature to separate the classes because of how the testbed was built rather
than because of the attacks. They are kept by default and listed in the cleaning report;
`--drop-suspect` (or `drop_suspect=True`) removes them. Step 15 compares models with and without
them rather than deciding by assumption.

## The cleaning report

`prepare` prints, and `Prepared.report` holds, everything cleaning changed:

| Field | Meaning |
|-------|---------|
| `rows_loaded` | Rows read per file group (`train`/`test`, or `all`) |
| `attempted_relabelled` | "Attempted" flows turned benign |
| `label_mismatches` | UNSW-NB15 rows whose 0/1 label disagreed with the class |
| `columns_dropped` | Column and reason |
| `suspect_columns_kept` | Suspect columns still among the features |
| `non_finite_replaced` | Infinite values turned missing |
| `non_numeric_values` | Values that were not numbers when read, per column |
| `duplicates_removed`, `conflicting_removed` | Per file group |
| `overlap_removed` | Validation and test rows also found in an earlier split |
| `rows`, `classes` | Rows and rows per class in each final split |

## Measured on the real data

`prepare cicids2017` with seed 0 on the full release, run on 2026-10-30 (about a minute on a
laptop, most of it the first conversion to Parquet):

| Step | Rows |
|------|-----:|
| Read from the five CSVs | 2,099,976 |
| "Attempted" flows relabelled benign | 11,979 |
| Exact duplicates removed | 384,648 |
| Rows with equal features but different classes removed | 226 |
| Infinite values replaced | 10 values |
| Left: train / validation / test | 857,551 / 343,020 / 514,531 |
| Validation or test rows also in an earlier split | 0 |

| Class | Rows as published | After cleaning (all splits) |
|-------|------------------:|----------------------------:|
| Benign (incl. relabelled "Attempted") | 1,594,545 | 1,432,906 |
| DoS Hulk | 158,468 | 158,468 |
| Portscan | 159,066 | 1,572 |
| DDoS | 95,144 | 95,144 |
| Infiltration - Portscan | 71,767 | 6,026 |
| DoS GoldenEye | 7,567 | 7,567 |
| FTP-Patator | 3,972 | 3,972 |
| DoS Slowloris | 3,859 | 3,859 |
| SSH-Patator | 2,961 | 2,961 |
| DoS Slowhttptest | 1,740 | 1,740 |
| Botnet | 736 | 736 |
| Web Attack - Brute Force | 73 | 73 |
| Infiltration | 36 | 36 |
| Web Attack - XSS | 18 | 18 |
| Web Attack - SQL Injection | 13 | 13 |
| Heartbleed | 11 | 11 |

**What this shows.** Most of the rows removed (58 %) are port-scan probes: once the ports are
removed, the probes of a scan are the same tiny flow over and over, so 99 % of `Portscan` and
92 % of `Infiltration - Portscan` rows are copies. Kept, they would fill the test set with rows
the model has already seen in training and make port-scan detection look nearly perfect. The
rest are repeated benign flows: benign traffic loses 10 %. The other attack classes keep every row. The smallest classes (Heartbleed, SQL
injection, XSS, Infiltration) have only a few test rows, so their per-class results will be noisy
and are reported with their counts.

UNSW-NB15 has not been measured yet: its files must be downloaded by hand (see above).

## Using it from Python

```python
from prohori.ml.cleaning import prepare
from prohori.ml.registry import get_dataset

data = prepare(get_dataset("cicids2017"), seed=0, sample=0.1)
x_train, y_train = data.x("train"), data.y("train")  # float32 features, 0/1 labels
x_val, y_val = data.x("validation"), data.y("validation")
print(data.report.to_dict())
```

`data.train`, `data.validation` and `data.test` keep `attack_cat` for per-class results.

## Limitations

- **Old, lab-made traffic.** Both datasets were captured in testbeds in 2015 and 2017. Models
  trained on them say little about a real network today; step 16 measures how badly they
  transfer from one dataset to the other.
- **Removing overlap changes the benchmark.** Scores are lower than, and not comparable with,
  results on the untouched official UNSW-NB15 test set.
- **Hash-based comparison.** Duplicates and overlap are found with a 64-bit hash of the feature
  values; a collision could hide a duplicate, with a probability that is negligible at these
  sizes.
- **Unpinned UNSW-NB15 files.** Until their hashes are pinned, a modified copy would not be
  noticed by `verify`.
- **No licence for the improved CIC-IDS-2017.** It is used for research only and never
  redistributed.
