# Model Card: Flow Detectors

Prohori's flow detectors give each network flow a score: the higher the score, the more likely
the flow is part of an attack. This card covers what the models are for, what they were trained
and tested on, how well they work and where they fail. Design decisions:
[ADR-0020](DECISIONS.md#adr-0020-flow-models-and-how-they-are-evaluated); data preparation:
[DATASETS.md](DATASETS.md).

## Contents

- [Summary](#summary)
- [Models](#models)
- [Intended use](#intended-use)
- [Training and evaluation data](#training-and-evaluation-data)
- [How they are evaluated](#how-they-are-evaluated)
- [Results](#results)
- [Calibration study](#calibration-study)
- [Cross-dataset test](#cross-dataset-test)
- [Cross-dataset study](#cross-dataset-study)
- [Failure cases](#failure-cases)
- [Limitations](#limitations)
- [Reproducing the results](#reproducing-the-results)
- [Saved models and safety](#saved-models-and-safety)
- [History: the 1.0 numbers](#history-the-10-numbers)

## Summary

- **Gradient boosting works well inside one lab dataset and badly at telling some attacks from
  benign traffic.** On UNSW-NB15 it reaches a PR-AUC of 0.95. At a threshold that alerts on 1 in
  100 benign flows it catches 69 % of the attacks; at 1 in 1,000, about a quarter, with a wide
  spread between seeds (25 ± 17 %). It catches almost none of the `Fuzzers` and `Analysis`
  attacks at either.
- **Since 1.1 the thresholds hold on test data.** Validation is made of time blocks the
  training data does not touch, and on UNSW-NB15 the 1 % threshold now gives 0.91 % on the test
  file. In 1.0, with validation rows drawn at random from the training file, it gave 4.5 % (4.8 %
  re-measured with the same code), because validation flows had near-copies captured moments
  apart in training and scored more confidently than new traffic. The price is recall: 82 % in
  1.0 was bought with four times the false alerts. See the
  [calibration study](#calibration-study). A SOC deploying a model meets the same kind of shift
  between the data a threshold was set on and live traffic, so thresholds must still be
  re-checked there.
- **CIC-IDS-2017 is close to solved by gradient boosting, even after cleaning:** 99.92 % of
  attacks caught at a 0.1 % false-positive rate. That says more about the dataset than about the
  model: every attack in it comes from a few scripted tools run in one lab week.
- **Neither model transfers usefully to the other dataset.** Trained on the twelve features
  both datasets share, gradient boosting has a ROC-AUC of 0.95 (UNSW-NB15) and 1.00
  (CIC-IDS-2017) on its own dataset and 0.64 and 0.59 on the other: weak, though above chance.
  Its PR-AUC falls from 0.91 and 0.999 to 0.33 and 0.40, against chance levels of 0.16 and 0.33.
  Worst for a SOC, its 1 % threshold flags 42 % and 61 % of the other dataset's benign flows:
  thousands of false alerts per 10,000 flows. See [Cross-dataset test](#cross-dataset-test).
- **The Isolation Forest, trained on benign traffic only, is not useful as a detector here.** It
  catches fewer than 5 % of attacks at a 1 % false-positive rate on either dataset. Attacks in
  these datasets are not unusual in the way an Isolation Forest measures unusual.
- **Leakage controls matter:** without them, the same gradient-boosting pipeline reports a
  PR-AUC of 0.988 instead of 0.950 on UNSW-NB15, and 70 % instead of 25 % recall at the 0.1 %
  threshold.

## Models

| | Gradient boosting | Isolation Forest |
| -- | ------------------- | ------------------ |
| Implementation | scikit-learn `HistGradientBoostingClassifier` | scikit-learn `IsolationForest` |
| Learns from | Benign and attack training flows with their 0/1 labels | Benign training flows only; never sees an attack |
| Score | Predicted probability of an attack | Negated `score_samples`: higher is more anomalous |
| Settings | 300 iterations at most, learning rate 0.1, early stopping on 10 % of the training split after 10 rounds without improvement | 200 trees, 256 samples per tree |
| Text features | Categorical (UNSW-NB15's `proto`, `service`, `state`); values unseen in training count as missing | Their integer codes |

The settings were fixed before any result was seen and have not been tuned. The test splits were
scored during development, with these same settings, to check the pipeline; nothing about the
models, features or thresholds was changed afterwards. (One edit after that: the Isolation
Forest's sample size is now written as `"auto"`, which is the same 256 at these data sizes and
avoids a warning on tiny test data.)

## Intended use

- **For:** studying how flow-based intrusion detection behaves when it is evaluated honestly;
  comparing models and leakage controls; teaching. A score can be a lead for an analyst, never a
  verdict.
- **Not for:** blocking traffic or any automatic action; production detection on a real network
  without retraining and re-evaluating on that network's own traffic; judging people.
- **Users:** security students, detection engineers and researchers, comfortable with Python and
  with reading precision and recall.

## Training and evaluation data

| | UNSW-NB15 | CIC-IDS-2017 (improved) |
| -- | ----------- | -------------------------- |
| Captured | 2015, UNSW Canberra cyber range | 2017, one week in the CIC lab, regenerated and relabelled in 2022 |
| Split | Official training file (minus about 20 % of each class's time blocks, in file order, for validation) and official testing file | Seeded split by time blocks of each class, in capture order: about 50 % train, 20 % validation, 30 % test |
| Train / validation / test flows (seed 0) | 79,415 / 19,853 / 52,418 | 864,418 / 336,140 / 514,544 |
| Attack share in test | 35.6 % | 16.5 % |
| Features | 42 (3 of them text) | 82 |

Both datasets were deduplicated, test rows found in training were removed, and identifier,
address, port, time and label-derived columns were dropped before training. All of that is in
[DATASETS.md](DATASETS.md), with the numbers removed.

## How they are evaluated

For each seed (0, 1 and 2):

1. Prepare the data. The seed chooses which time blocks are held out for validation, and for
   CIC-IDS-2017 for the test split too.
2. Fit each model on the training split.
3. Score the validation split and choose, for each target false-positive rate (1 % and 0.1 %),
   the lowest threshold at which at most that share of benign validation flows alert. The
   thresholds are then frozen.
4. Score the test split once and record:
   - **PR-AUC**, which does not depend on a threshold and is compared with the attack share
     (a random score gets PR-AUC equal to the attack share), and ROC-AUC;
   - at each threshold: the **false-positive rate reached on test**, **recall**, precision,
     **false alerts per 10,000 flows** and **recall per attack class** with the class's number
     of test flows.

Tables show the mean and standard deviation over the three seeds. Accuracy is not reported: on
traffic that is mostly benign it rewards a model that never alerts. The UNSW-NB15 test file is
the same for every seed, so its spread reflects only the model and the validation split.

The columns are labelled with the **validation** target, for example "Test FPR (1 % val.)",
because the test rate can differ from the target and that difference is a result in itself.

## Results

Generated from `results/ml_unsw-nb15.json` and `results/ml_cicids2017.json` by
`scripts/generate_results_table.py`.

<!-- ml-results:start -->
### UNSW-NB15 (official training and testing partition)

Seeds 0, 1, 2; mean ± standard deviation over the seeds. Each threshold is chosen on the validation split for a target false-positive rate (FPR) and frozen; the test split is scored once. Generated from `results/ml_unsw-nb15.json`; do not edit by hand.

| Model | PR-AUC | ROC-AUC | Test FPR (1 % val.) | Recall | False alerts / 10k | Test FPR (0.1 % val.) | Recall | False alerts / 10k |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Gradient boosting (supervised) | 0.950 ± 0.003 | 0.967 ± 0.002 | 0.91 ± 0.44 % | 68.87 ± 2.18 % | 58.8 ± 28.2 | 0.03 ± 0.03 % | 24.72 ± 16.62 % | 1.9 ± 1.7 |
| Isolation Forest (benign only) | 0.532 ± 0.016 | 0.715 ± 0.012 | 0.97 ± 0.23 % | 4.84 ± 2.19 % | 62.3 ± 14.5 | 0.12 ± 0.09 % | 2.18 ± 1.79 % | 7.4 ± 5.9 |

Effect of the leakage controls on gradient boosting. Each variant has its own test split, so this compares what the same pipeline reports about itself, not two models on the same data:

| Variant | Test flows | Attack share | PR-AUC | ROC-AUC | Recall (0.1 % val.) | Test FPR |
| --------- | -----------: | -------------: | -------: | --------: | ------: | ------: |
| Cleaned (every leakage control) | 52,418 | 35.6 % | 0.950 ± 0.003 | 0.967 ± 0.002 | 24.7 ± 16.6 % | 0.03 ± 0.03 % |
| Uncleaned (no deduplication, ids and ports kept) | 82,332 | 55.1 % | 0.988 ± 0.001 | 0.984 ± 0.001 | 70.3 ± 3.2 % | 0.03 ± 0.02 % |
| Cleaned, without the TTL columns | 52,417 | 35.6 % | 0.944 ± 0.003 | 0.963 ± 0.002 | 28.6 ± 12.8 % | 0.03 ± 0.03 % |

Recall per attack class (gradient boosting, cleaned) with the class's test flows, averaged over the seeds:

| Class | Test flows | Recall (1 % val.) | Recall (0.1 % val.) |
| ------- | -----------: | ------: | ------: |
| Analysis | 58 | 1.7 ± 3.0 % | 0.0 ± 0.0 % |
| Backdoor | 57 | 71.9 ± 12.3 % | 7.0 ± 9.3 % |
| DoS | 1,163 | 77.7 ± 2.0 % | 18.6 ± 17.8 % |
| Exploits | 7,041 | 86.8 ± 1.3 % | 29.2 ± 23.4 % |
| Fuzzers | 4,321 | 7.1 ± 4.4 % | 0.1 ± 0.1 % |
| Generic | 3,399 | 94.4 ± 0.9 % | 63.7 ± 32.7 % |
| Reconnaissance | 2,215 | 90.9 ± 3.2 % | 7.0 ± 12.0 % |
| Shellcode | 365 | 62.3 ± 7.1 % | 0.5 ± 0.8 % |
| Worms | 43 | 80.6 ± 4.8 % | 12.4 ± 15.8 % |

### CIC-IDS-2017, improved release (Engelen, Liu et al., CNS 2022)

Seeds 0, 1, 2; mean ± standard deviation over the seeds. Each threshold is chosen on the validation split for a target false-positive rate (FPR) and frozen; the test split is scored once. Generated from `results/ml_cicids2017.json`; do not edit by hand.

| Model | PR-AUC | ROC-AUC | Test FPR (1 % val.) | Recall | False alerts / 10k | Test FPR (0.1 % val.) | Recall | False alerts / 10k |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Gradient boosting (supervised) | 0.999 ± 0.000 | 1.000 ± 0.000 | 0.98 ± 0.16 % | 99.98 ± 0.01 % | 82.1 ± 13.3 | 0.10 ± 0.09 % | 99.92 ± 0.07 % | 8.6 ± 7.2 |
| Isolation Forest (benign only) | 0.528 ± 0.043 | 0.926 ± 0.013 | 1.00 ± 0.05 % | 0.57 ± 0.27 % | 83.9 ± 4.4 | 0.09 ± 0.02 % | 0.00 ± 0.00 % | 7.9 ± 1.3 |

Effect of the leakage controls on gradient boosting. Each variant has its own test split, so this compares what the same pipeline reports about itself, not two models on the same data:

| Variant | Test flows | Attack share | PR-AUC | ROC-AUC | Recall (0.1 % val.) | Test FPR |
| --------- | -----------: | -------------: | -------: | --------: | ------: | ------: |
| Cleaned (every leakage control) | 514,531 | 16.5 % | 0.999 ± 0.000 | 1.000 ± 0.000 | 99.9 ± 0.1 % | 0.10 ± 0.09 % |
| Uncleaned (no deduplication, ids and ports kept) | 629,992 | 24.1 % | 1.000 ± 0.000 | 1.000 ± 0.000 | 100.0 ± 0.0 % | 0.10 ± 0.10 % |

Recall per attack class (gradient boosting, cleaned) with the class's test flows, averaged over the seeds:

| Class | Test flows | Recall (1 % val.) | Recall (0.1 % val.) |
| ------- | -----------: | ------: | ------: |
| Botnet | 220 | 100.0 ± 0.0 % | 99.8 ± 0.3 % |
| DDoS | 28,544 | 100.0 ± 0.0 % | 100.0 ± 0.0 % |
| DoS GoldenEye | 2,269 | 100.0 ± 0.0 % | 99.9 ± 0.2 % |
| DoS Hulk | 47,540 | 100.0 ± 0.0 % | 100.0 ± 0.0 % |
| DoS Slowhttptest | 522 | 100.0 ± 0.0 % | 99.6 ± 0.4 % |
| DoS Slowloris | 1,158 | 100.0 ± 0.0 % | 99.7 ± 0.4 % |
| FTP-Patator | 1,193 | 100.0 ± 0.0 % | 99.7 ± 0.4 % |
| Heartbleed | 3 | 100.0 ± 0.0 % | 77.8 ± 38.5 % |
| Infiltration | 11 | 87.9 ± 10.5 % | 69.7 ± 5.2 % |
| Infiltration - Portscan | 1,809 | 99.5 ± 0.2 % | 98.6 ± 1.2 % |
| Portscan | 470 | 99.6 ± 0.2 % | 98.2 ± 2.3 % |
| SSH-Patator | 889 | 99.9 ± 0.1 % | 99.0 ± 0.2 % |
| Web Attack - Brute Force | 23 | 98.5 ± 2.6 % | 94.2 ± 5.0 % |
| Web Attack - SQL Injection | 4 | 91.7 ± 14.4 % | 50.0 ± 50.0 % |
| Web Attack - XSS | 5 | 100.0 ± 0.0 % | 93.3 ± 11.5 % |
<!-- ml-results:end -->

## Calibration study

A threshold is only useful if the false-positive rate it was chosen for holds on new traffic.
In 1.0 it did not on UNSW-NB15 (see [History](#history-the-10-numbers)), and the validation
split was the suspect: its rows were drawn at random from the training file, so flows captured
moments apart could sit on both sides. Since 1.1 every run measures three ways of choosing the
thresholds on the same test split ([ADR-0040](DECISIONS.md#adr-0040-time-block-validation-and-model-files-without-pickle)):

- **Time blocks (validation):** each class's rows in time order are cut into 50 blocks; whole
  blocks are held out for validation, so no validation flow has a training neighbour in time.
- **Out-of-fold (time-block folds):** five models, each fitted without one fold of blocks of
  training and validation, score the fold they did not see; the thresholds come from those
  scores and the final model is fitted on all of it.
- **Random rows (1.0):** the old validation split, measured for comparison and never chosen.

**What it shows.** On UNSW-NB15, random validation rows put gradient boosting's 1 % threshold at
4.76 % on test; time blocks put it at 0.91 %. So the 1.0 shift came from the split, as
suspected, though near-duplicates in the narrow sense (equal at two significant digits) are too
few to be the whole cause: 1.2 % of benign validation flows with random rows, 0.7 % with time
blocks. The training file's benign flows come in long runs in file order, and flows close in
that order are alike in ways rounding does not capture. On CIC-IDS-2017 time blocks and random rows
both hold within a few tenths of a point; its benign traffic repeats all week (about 18 % near-duplicates
whichever split), so blocks change little. Out-of-fold thresholds came from models fitted on
four fifths of the data and did not carry over to the final model (0.30 % and 1.70 % at the
1 % target). Time blocks won by the rule below and are used for every other number on this
page. The rule used the test split once, to pick a method; no threshold was chosen on it.

<!-- ml-calibration:start -->
Seeds 0, 1, 2; cleaned variant; mean ± standard deviation. The same test split scores every method. Calibration error is |test FPR / target - 1| averaged over the targets (0 is perfect). Near-duplicates: the share of benign validation flows equal to a benign training flow once every number is rounded to two significant digits (out-of-fold uses the time-block split). Generated from `results/ml_*.json`; do not edit by hand.

| Dataset | Method | Model | Benign val. near-duplicates | Test FPR (1 % target) | Recall | Test FPR (0.1 % target) | Recall | Calibration error |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| unsw-nb15 | Time blocks (validation) | Gradient boosting (supervised) | 0.71 % | 0.91 ± 0.44 % | 68.9 ± 2.2 % | 0.03 ± 0.03 % | 24.7 ± 16.6 % | 0.525 |
| unsw-nb15 | Time blocks (validation) | Isolation Forest (benign only) | 0.71 % | 0.97 ± 0.23 % | 4.8 ± 2.2 % | 0.12 ± 0.09 % | 2.2 ± 1.8 % | 0.421 |
| unsw-nb15 | Out-of-fold (time-block folds) | Gradient boosting (supervised) | 0.71 % | 0.30 ± 0.26 % | 56.8 ± 13.0 % | 0.01 ± 0.01 % | 25.5 ± 14.3 % | 0.820 |
| unsw-nb15 | Out-of-fold (time-block folds) | Isolation Forest (benign only) | 0.71 % | 0.83 ± 0.33 % | 5.0 ± 0.8 % | 0.08 ± 0.08 % | 1.4 ± 1.2 % | 0.454 |
| unsw-nb15 | Random rows (1.0) | Gradient boosting (supervised) | 1.21 % | 4.76 ± 0.82 % | 82.5 ± 1.7 % | 0.12 ± 0.12 % | 51.5 ± 12.8 % | 2.279 |
| unsw-nb15 | Random rows (1.0) | Isolation Forest (benign only) | 1.21 % | 0.88 ± 0.17 % | 4.9 ± 0.8 % | 0.07 ± 0.06 % | 1.6 ± 1.2 % | 0.348 |
| cicids2017 | Time blocks (validation) | Gradient boosting (supervised) | 17.92 % | 0.98 ± 0.16 % | 100.0 ± 0.0 % | 0.10 ± 0.09 % | 99.9 ± 0.1 % | 0.383 |
| cicids2017 | Time blocks (validation) | Isolation Forest (benign only) | 17.92 % | 1.00 ± 0.05 % | 0.6 ± 0.3 % | 0.09 ± 0.02 % | 0.0 ± 0.0 % | 0.087 |
| cicids2017 | Out-of-fold (time-block folds) | Gradient boosting (supervised) | 17.92 % | 1.70 ± 1.04 % | 100.0 ± 0.0 % | 0.10 ± 0.04 % | 100.0 ± 0.0 % | 0.488 |
| cicids2017 | Out-of-fold (time-block folds) | Isolation Forest (benign only) | 17.92 % | 0.93 ± 0.08 % | 0.8 ± 0.5 % | 0.09 ± 0.03 % | 0.0 ± 0.0 % | 0.140 |
| cicids2017 | Random rows (1.0) | Gradient boosting (supervised) | 18.78 % | 1.17 ± 0.15 % | 100.0 ± 0.0 % | 0.16 ± 0.06 % | 100.0 ± 0.0 % | 0.394 |
| cicids2017 | Random rows (1.0) | Isolation Forest (benign only) | 18.78 % | 0.98 ± 0.04 % | 0.8 ± 0.3 % | 0.10 ± 0.01 % | 0.0 ± 0.0 % | 0.059 |

Mean calibration error over both datasets and models: time blocks (validation) 0.354, out-of-fold (time-block folds) 0.476, random rows (1.0) 0.770. Published numbers and saved models use **time blocks (validation)**. Rule, written down before the runs: Lower mean calibration error wins: |FPR reached on test / target FPR - 1|, averaged over both datasets, both models, both targets and seeds 0-2 (cleaned variant). time-block wins a difference under 0.05, being one fit instead of six. random is measured, never chosen. The choice uses the test split, once, to pick a method, never a threshold.
<!-- ml-calibration:end -->

## Cross-dataset test

A model is only useful if it works on traffic other than the lab it was trained in. The two
datasets were captured by different tools on different networks, so the test trains on one and
scores the other, using only the features both have.

**The mapping is lossy.** Twelve features can be computed from both datasets; everything else
(UNSW-NB15's TTLs, TCP sequence and window values and connection counters, CICFlowMeter's
packet-length extremes, flag counts, bulk and idle statistics) has no counterpart:

| Common feature | UNSW-NB15 | CIC-IDS-2017 |
| ---------------- | ----------- | -------------- |
| `duration_s` | `dur` (seconds) | `flow_duration` / 10^6 (microseconds) |
| `fwd_packets`, `bwd_packets` | `spkts`, `dpkts` | `total_fwd_packet`, `total_bwd_packets` |
| `fwd_bytes`, `bwd_bytes` | `sbytes`, `dbytes` (headers included, as measured) | payload + transport headers + 34 bytes a packet |
| `fwd_mean_bytes`, `bwd_mean_bytes` | bytes / packets | the same |
| `fwd_iat_mean_s`, `bwd_iat_mean_s` | `sinpkt`, `dinpkt` / 10^3 (ms) | `fwd_iat_mean`, `bwd_iat_mean` / 10^6 (µs) |
| `packets_per_s`, `bytes_per_s` | over the duration | the same |
| `protocol` | `proto`: tcp 6, udp 17, icmp 1, other -1 | `protocol`: 6, 17, 1, other -1 |

Bytes are counted on the wire on both sides. CICFlowMeter counts payload, so its byte counts
get the transport header lengths it records plus 34 bytes a packet for the Ethernet and IPv4
headers. This follows from what was measured, not from either tool's documentation: benign DNS
flows send a median of 146 bytes forward (in two packets) in UNSW-NB15 and 154 after conversion
in CIC-IDS-2017, consistent with UNSW-NB15 counting headers. The two tools also cut flows differently (timeouts, when a
flow ends), which no mapping can undo.

**Method.** For each seed, both datasets are prepared with every leakage control, mapped and
deduplicated again on the common features (fewer features make more rows identical). A model is
fitted on the source's training split; its thresholds come from the source's validation split;
it is scored once on the source's test split (in-dataset) and once on the target's test split
(cross-dataset). The target is never seen before it is scored, as on a new network.

<!-- ml-cross:start -->
Seeds 0, 1, 2; mean ± standard deviation. Each model is trained on the source dataset's 12 common features, its thresholds are chosen on the source's validation split, and it is scored once on the source's test split (in-dataset) and once on the target's (cross-dataset). Generated from `results/ml_cross.json`; do not edit by hand.

PR-AUC depends on the share of attacks, which differs between the datasets, so each PR-AUC has its chance level (the attack share) next to it. ROC-AUC does not depend on it (0.5 is chance) and is the fairer comparison across datasets.

| Direction | Model | PR-AUC, all features | PR-AUC, common features | Chance, source | PR-AUC, cross-dataset | Chance, target | ROC-AUC, in-dataset | ROC-AUC, cross-dataset |
| ----------- | ------- | ------: | ------: | ------: | ------: | ------: | ------: | ------: |
| unsw-nb15 → cicids2017 | Gradient boosting (supervised) | 0.950 ± 0.003 | 0.914 ± 0.001 | 0.329 | 0.329 ± 0.079 | 0.164 | 0.950 ± 0.001 | 0.636 ± 0.037 |
| unsw-nb15 → cicids2017 | Isolation Forest (benign only) | 0.532 ± 0.016 | 0.357 ± 0.006 | 0.329 | 0.211 ± 0.012 | 0.164 | 0.477 ± 0.006 | 0.678 ± 0.025 |
| cicids2017 → unsw-nb15 | Gradient boosting (supervised) | 0.999 ± 0.000 | 0.999 ± 0.000 | 0.164 | 0.401 ± 0.011 | 0.329 | 1.000 ± 0.000 | 0.590 ± 0.009 |
| cicids2017 → unsw-nb15 | Isolation Forest (benign only) | 0.528 ± 0.043 | 0.442 ± 0.006 | 0.164 | 0.304 ± 0.009 | 0.329 | 0.896 ± 0.002 | 0.439 ± 0.011 |

At the threshold chosen for a 1 % false-positive rate on the source's validation split:

| Direction | Model | In-dataset recall | In-dataset test FPR | Cross-dataset recall | Cross-dataset FPR | False alerts / 10k |
| ----------- | ------- | ------: | ------: | ------: | ------: | ------: |
| unsw-nb15 → cicids2017 | Gradient boosting (supervised) | 59.5 ± 7.0 % | 1.41 ± 1.36 % | 58.4 ± 9.0 % | 41.84 ± 4.50 % | 3496 ± 377 |
| unsw-nb15 → cicids2017 | Isolation Forest (benign only) | 1.1 ± 0.5 % | 0.74 ± 0.15 % | 1.3 ± 0.7 % | 3.95 ± 0.94 % | 330 ± 79 |
| cicids2017 → unsw-nb15 | Gradient boosting (supervised) | 99.9 ± 0.0 % | 0.84 ± 0.27 % | 69.5 ± 2.7 % | 60.50 ± 0.79 % | 4058 ± 53 |
| cicids2017 → unsw-nb15 | Isolation Forest (benign only) | 0.1 ± 0.0 % | 0.98 ± 0.03 % | 6.4 ± 1.9 % | 5.57 ± 0.85 % | 374 ± 57 |

At the threshold chosen for a 0.1 % false-positive rate on the source's validation split:

| Direction | Model | In-dataset recall | In-dataset test FPR | Cross-dataset recall | Cross-dataset FPR | False alerts / 10k |
| ----------- | ------- | ------: | ------: | ------: | ------: | ------: |
| unsw-nb15 → cicids2017 | Gradient boosting (supervised) | 24.4 ± 22.2 % | 0.10 ± 0.11 % | 31.7 ± 15.4 % | 19.22 ± 13.90 % | 1606 ± 1162 |
| unsw-nb15 → cicids2017 | Isolation Forest (benign only) | 0.5 ± 0.0 % | 0.02 ± 0.01 % | 0.1 ± 0.1 % | 1.83 ± 0.18 % | 153 ± 15 |
| cicids2017 → unsw-nb15 | Gradient boosting (supervised) | 99.9 ± 0.0 % | 0.10 ± 0.07 % | 43.9 ± 4.7 % | 34.73 ± 5.13 % | 2330 ± 344 |
| cicids2017 → unsw-nb15 | Isolation Forest (benign only) | 0.0 ± 0.0 % | 0.10 ± 0.01 % | 0.2 ± 0.1 % | 0.04 ± 0.04 % | 3 ± 3 |

Recall per attack class in the target, unsw-nb15 → cicids2017 (gradient boosting, 1 % source-validation threshold):

| Class | Test flows | Recall |
| ------- | ------: | ------: |
| Botnet | 220 | 0.2 ± 0.3 % |
| DDoS | 28,544 | 45.9 ± 20.7 % |
| DoS GoldenEye | 2,269 | 83.1 ± 5.9 % |
| DoS Hulk | 47,540 | 70.1 ± 4.9 % |
| DoS Slowhttptest | 519 | 14.3 ± 8.4 % |
| DoS Slowloris | 1,036 | 38.8 ± 30.3 % |
| FTP-Patator | 1,193 | 0.0 ± 0.0 % |
| Heartbleed | 3 | 33.3 ± 57.7 % |
| Infiltration | 11 | 33.3 ± 5.2 % |
| Infiltration - Portscan | 1,795 | 5.7 ± 4.6 % |
| Portscan | 305 | 7.1 ± 0.4 % |
| SSH-Patator | 889 | 33.6 ± 56.8 % |
| Web Attack - Brute Force | 23 | 100.0 ± 0.0 % |
| Web Attack - SQL Injection | 4 | 33.3 ± 38.2 % |
| Web Attack - XSS | 5 | 73.3 ± 46.2 % |

Recall per attack class in the target, cicids2017 → unsw-nb15 (gradient boosting, 1 % source-validation threshold):

| Class | Test flows | Recall |
| ------- | ------: | ------: |
| Analysis | 58 | 98.3 ± 0.0 % |
| Backdoor | 57 | 82.5 ± 1.8 % |
| DoS | 1,123 | 66.9 ± 2.9 % |
| Exploits | 6,989 | 55.3 ± 3.9 % |
| Fuzzers | 3,743 | 84.9 ± 4.6 % |
| Generic | 631 | 40.9 ± 2.5 % |
| Reconnaissance | 1,851 | 99.2 ± 0.4 % |
| Shellcode | 273 | 85.5 ± 12.1 % |
| Worms | 39 | 82.1 ± 0.0 % |
<!-- ml-cross:end -->

**What this shows.**

- Losing features costs little: gradient boosting on the twelve common features is almost as
  good as on all of them inside each dataset (PR-AUC 0.91 against 0.95 on UNSW-NB15, 0.999 on
  CIC-IDS-2017).
- Changing dataset costs most of the signal. ROC-AUC, which does not depend on the share of
  attacks, falls from 0.95 and 1.00 to 0.64 and 0.59. PR-AUC falls to 0.33 (chance 0.16) and 0.40
  (chance 0.33); it cannot be compared directly with the in-dataset PR-AUC, whose chance level is
  different.
- The frozen thresholds stop meaning anything: the 1 % threshold flags 42 % (UNSW-NB15 to
  CIC-IDS-2017) and 61 % (the reverse) of the target's benign flows. The high per-class recall
  in the reverse direction comes from flagging most of the traffic.
- The generalisation gap is the finding: a flow model trained on one lab's traffic learns that
  lab. Before relying on one, train it and set its threshold on the network it will watch.

## Cross-dataset study

Step 30b asked which low-compute methods close the cross-dataset gap without using the
target's labels. The questions, the methods with every setting, the metrics, the seeds and the
decision rule were written down and pushed before any run
([ADR-0041](DECISIONS.md#adr-0041-pre-registration-of-the-cross-dataset-generalisation-study)).
Each direction is studied separately. Methods may use the target's training split as an
**unlabelled pool**; its labels are read only by the few-shot arms (an upper bound) and the
reference arm (the in-dataset ceiling). Nothing is fitted on the target's test split.
`python scripts/cross_dataset_study.py` reproduces the results (about an hour on a laptop CPU).
The study is written up as a paper draft in
[docs/research/cross-dataset-generalisation.md](research/cross-dataset-generalisation.md).

<!-- ml-adapt:start -->
Seeds 0, 1, 2; gradient boosting; scored on the target's test split. 95 % intervals from 1,000 paired bootstrap resamples of the target test rows. An arm **improves** only if the interval of its ROC-AUC difference excludes 0 and the difference has the same sign in every seed; it **helps** only if it improves in both directions. Thresholds come from the source's validation split (1 % false-positive rate); "at 1 % on target" reads recall off the target's own ROC curve instead (not deployable). Generated from `results/ml_adapt.json`; do not edit by hand.

### unsw-nb15 → cicids2017

| Arm | Sees from the target | ROC-AUC | 95 % interval | Difference to baseline | 95 % interval | Verdict | PR-AUC (chance) | Recall at the source threshold | Target FPR reached | Recall at 1 % on target | Gap closed |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Baseline (step 16) | nothing | 0.636 | 0.635 to 0.638 | - | - | - | 0.329 (0.16) | 58.4 % | 41.8 % | 11.5 % | - |
| Per-domain log standardisation | pool features | 0.630 | 0.629 to 0.632 | -0.006 | -0.008 to -0.005 | no clear change | 0.476 (0.16) | 42.0 % | 12.2 % | 29.1 % | -2 % |
| Per-domain quantile map | pool features | 0.824 | 0.823 to 0.825 | +0.188 | 0.186 to 0.189 | improves | 0.603 (0.16) | 67.4 % | 22.0 % | 27.4 % | 52 % |
| Per-domain, per-protocol quantile map | pool features | 0.567 | 0.566 to 0.569 | -0.069 | -0.071 to -0.067 | worsens | 0.340 (0.16) | 38.0 % | 9.1 % | 9.0 % | -19 % |
| CORAL | pool features | 0.511 | 0.509 to 0.513 | -0.126 | -0.128 to -0.123 | worsens | 0.462 (0.16) | 37.2 % | 7.3 % | 32.7 % | -35 % |
| Importance weighting | pool features | 0.549 | 0.548 to 0.550 | -0.087 | -0.088 to -0.087 | worsens | 0.173 (0.16) | 62.8 % | 50.6 % | 0.1 % | -24 % |
| Domain-invariant features only | pool features | 0.636 | 0.635 to 0.638 | +0.000 | 0.000 to 0.000 | no clear change | 0.329 (0.16) | 58.4 % | 41.8 % | 11.5 % | 0 % |
| 10 labelled target flows | 10 pool labels | 0.810 | 0.809 to 0.810 | +0.173 | 0.173 to 0.174 | improves | 0.607 (0.16) | 62.8 % | 16.8 % | 37.0 % | 48 % |
| 50 labelled target flows | 50 pool labels | 0.932 | 0.932 to 0.933 | +0.296 | 0.295 to 0.297 | improves | 0.841 (0.16) | 77.4 % | 6.0 % | 59.7 % | 81 % |
| 100 labelled target flows | 100 pool labels | 0.966 | 0.966 to 0.966 | +0.330 | 0.329 to 0.331 | improves | 0.902 (0.16) | 82.1 % | 4.3 % | 69.5 % | 91 % |
| Reference: trained on the target | target labels | 1.000 | 1.000 to 1.000 | +0.363 | 0.362 to 0.364 | reference | 0.999 (0.16) | 99.9 % | 0.8 % | 99.9 % | - |

### cicids2017 → unsw-nb15

| Arm | Sees from the target | ROC-AUC | 95 % interval | Difference to baseline | 95 % interval | Verdict | PR-AUC (chance) | Recall at the source threshold | Target FPR reached | Recall at 1 % on target | Gap closed |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Baseline (step 16) | nothing | 0.590 | 0.587 to 0.593 | - | - | - | 0.401 (0.33) | 69.5 % | 60.5 % | 0.9 % | - |
| Per-domain log standardisation | pool features | 0.534 | 0.531 to 0.537 | -0.057 | -0.061 to -0.052 | no clear change | 0.353 (0.33) | 34.0 % | 35.4 % | 1.9 % | -16 % |
| Per-domain quantile map | pool features | 0.624 | 0.621 to 0.627 | +0.034 | 0.030 to 0.038 | improves | 0.421 (0.33) | 41.6 % | 30.3 % | 3.6 % | 9 % |
| Per-domain, per-protocol quantile map | pool features | 0.579 | 0.575 to 0.582 | -0.012 | -0.016 to -0.007 | worsens | 0.404 (0.33) | 34.9 % | 32.8 % | 4.8 % | -3 % |
| CORAL | pool features | 0.576 | 0.573 to 0.579 | -0.014 | -0.019 to -0.010 | no clear change | 0.408 (0.33) | 28.3 % | 24.4 % | 7.5 % | -4 % |
| Importance weighting | pool features | 0.638 | 0.636 to 0.641 | +0.048 | 0.046 to 0.050 | improves | 0.435 (0.33) | 67.1 % | 55.5 % | 1.6 % | 13 % |
| Domain-invariant features only | pool features | 0.590 | 0.587 to 0.593 | +0.000 | 0.000 to 0.000 | no clear change | 0.401 (0.33) | 69.5 % | 60.5 % | 0.9 % | 0 % |
| 10 labelled target flows | 10 pool labels | 0.626 | 0.623 to 0.628 | +0.035 | 0.034 to 0.037 | improves | 0.429 (0.33) | 68.3 % | 50.6 % | 2.8 % | 10 % |
| 50 labelled target flows | 50 pool labels | 0.710 | 0.708 to 0.712 | +0.120 | 0.118 to 0.122 | improves | 0.489 (0.33) | 80.0 % | 47.1 % | 1.9 % | 33 % |
| 100 labelled target flows | 100 pool labels | 0.758 | 0.756 to 0.760 | +0.167 | 0.165 to 0.170 | improves | 0.537 (0.33) | 88.4 % | 44.7 % | 3.5 % | 47 % |
| Reference: trained on the target | target labels | 0.950 | 0.949 to 0.951 | +0.359 | 0.356 to 0.363 | reference | 0.914 (0.33) | 59.5 % | 1.4 % | 59.0 % | - |

Diagnostics, per direction (mean over the seeds):

| Direction | Pool attack share | Domain classifier ROC-AUC | Effective sample share | Weights at a clip | Features dropped as not invariant |
| --- | --- | --- | --- | --- | --- |
| unsw-nb15 → cicids2017 | 16 % | 1.000 | 2.2 % | 98.4 % | none |
| cicids2017 → unsw-nb15 | 46 % | 1.000 | 4.6 % | 99.5 % | none |

Helps in both directions: per-domain quantile map, 10 labelled target flows, 50 labelled target flows, 100 labelled target flows. Unsupervised methods that help: per-domain quantile map.
<!-- ml-adapt:end -->

**What this shows.**

- **One unsupervised method helps in both directions: a per-domain quantile map.** Mapping
  each feature to its rank within its own dataset (fitted on unlabelled flows) raises ROC-AUC
  from 0.636 to 0.824 (UNSW-NB15 to CIC-IDS-2017) and from 0.590 to 0.624 (the reverse). It
  closes about half of the gap in the first direction and a tenth in the second. It is still
  not deployable: the frozen 1 % threshold flags 22 % and 30 % of the target's benign flows.
- **Every other unsupervised method fails the pre-registered test.** Per-domain log
  standardisation and CORAL change the result in different directions from seed to seed or
  make it worse; CORAL brings UNSW-NB15 to CIC-IDS-2017 down to chance (0.511). A per-protocol
  quantile map, which was expected to do better than the plain one, makes both directions
  worse. Importance weighting helps from CIC-IDS-2017 to UNSW-NB15 (+0.048) and hurts the other
  way (-0.087).
- **Why importance weighting cannot work here:** a domain classifier tells the datasets apart
  perfectly (ROC-AUC 1.000) from the twelve features together, though no single feature does
  (each feature's domain AUC is between 0.51 and 0.80). Almost every weight then sits at a
  clip, and the effective sample is 2 to 5 % of the source. The supports barely overlap, which
  is the assumption covariate-shift weighting needs.
- **Feature selection did nothing:** no feature reached the pre-registered domain AUC of 0.9,
  so the invariant arm kept all twelve and equals the baseline. The datasets differ in how
  features combine, not in any one feature.
- **A few labels beat every unsupervised method.** 10 labelled target flows match the quantile
  map in both directions; 100 bring UNSW-NB15 to CIC-IDS-2017 to 0.966 and the reverse to 0.758.
  Labelling a hundred flows of the network a model will watch is cheaper than any of the
  adaptation tried here, and it is the practical recommendation.
- **Caveat, stated in advance:** the unlabelled pools are lab training splits with 16 %
  (CIC-IDS-2017) and 46 % (UNSW-NB15) attacks. A quantile map fitted on them aligns the attack
  mix too, which real, mostly benign, unlabelled traffic would not allow. The quantile map's
  gain may be smaller on a real network.

## Failure cases

- **Fuzzers and Analysis on UNSW-NB15.** At the 1 % threshold gradient boosting catches about
  7 % of `Fuzzers` and 2 % of `Analysis` flows, and at 0.1 % almost none (1.0's looser threshold
  caught 37 % and 16 %, at 4.5 % false positives). Fuzzers send
  malformed but ordinary-looking traffic; many of their flows resemble benign ones in every
  feature the dataset has.
- **Low-rate operation costs recall on UNSW-NB15.** Moving from the 1 % to the 0.1 % threshold
  drops recall from about 69 % to 25 %, and most classes (Generic, Exploits, DoS, Worms,
  Reconnaissance) vary widely between seeds at 0.1 %, so a single run would be misleading.
- **Thresholds are set on few benign flows at 0.1 %.** About 10,000 benign validation flows
  leave ten above the 0.1 % threshold, so it moves between seeds (test FPR 0.03 ± 0.03 %), and
  with it the recall. Thresholds must be re-checked on the traffic a model is deployed on.
- **Tiny classes.** CIC-IDS-2017 has 3 Heartbleed, 4 SQL injection, 5 XSS and 11 Infiltration
  test flows on average; one missed flow changes their recall by 9 to 33 points. Read their
  recall with the count next to it.
- **The Isolation Forest.** Its PR-AUC (0.53 on both) is above the attack share (0.36 and 0.17),
  so its scores carry some signal, but its highest scores are benign outliers: at a 1 %
  false-positive rate it catches under 5 % of attacks. Using it would mean a queue of false
  alerts.
- **Nearly perfect CIC-IDS-2017 scores** are a warning about the dataset rather than evidence
  that the model would work on a real network.
- **Another network.** On the other dataset the 1 % threshold flags 42 % to 61 % of benign
  flows, and a model trained on UNSW-NB15 misses almost all of CIC-IDS-2017's FTP brute force,
  botnet traffic and port scans.

## Limitations

- **Lab data, years old.** Both datasets come from testbeds in 2015 and 2017, with a handful of
  attack tools and synthetic background traffic. Real networks have other traffic, other
  attacks and encrypted payloads.
- **Flow features only.** The models see flow statistics, not payloads, hosts or history, so they
  cannot tell a brute force against one account from one against many.
- **Different benchmark.** Removing duplicates and test rows found in training makes the results
  lower than, and not comparable with, papers that use the untouched files.
- **Three seeds** are enough to show the spread, not to estimate it precisely.
- **Not tuned.** Better settings exist, and a tuned model would look better; tuning would have
  to use the validation split only.
- **The cross-dataset test is limited by the mapping.** Only twelve features map, measured by
  different tools. A model with more shared information might transfer better, so the gap
  describes these two datasets and this mapping, not every flow model.

## Reproducing the results

With both datasets in `data/` (see [DATASETS.md](DATASETS.md#getting-the-files)):

```bash
uv run python -m prohori.ml.train --dataset unsw-nb15 --seeds 0 1 2    # about 2 minutes
uv run python -m prohori.ml.train --dataset cicids2017 --seeds 0 1 2   # about 17 minutes
uv run python -m prohori.ml.transfer --seeds 0 1 2                     # about 4 minutes
uv run python scripts/generate_results_table.py                        # update the tables
```

Times are for a laptop CPU with 16 GB of memory. `--sample 0.1` runs on a tenth of the rows,
`--models hgb` or `--variants cleaned` limit the work, `--no-study` skips the calibration
study (most of the time on CIC-IDS-2017), and `--no-save` skips saving the models.
The results record the library versions used; other versions of scikit-learn can give slightly
different numbers.

## Saved models and safety

Use a saved model with `prohori score FLOWS.csv --model <dataset>/<model>-seed<N>`
([CLI.md](CLI.md#prohori-score)). Each run saves the cleaned models to
`models/<dataset>/<model>-seed<N>.skops`, which git ignores, with a JSON file next to it
(`<model>-seed<N>.skops.json`) holding the features, the frozen thresholds, the versions of
Python, scikit-learn, numpy and pandas, and the model file's SHA-256.

**Since 1.1, model files are not pickles.** They are [skops](https://skops.readthedocs.io/)
files: zip archives of plain data, read back without pickle and only into the types Prohori
lists (`prohori.ml.safety.SKOPS_TYPES`); a file asking for anything else is refused. Before any
byte is read as objects, `prohori.ml.models.load_model`:

1. refuses a file without its JSON file, or whose SHA-256 does not match it;
2. refuses a file whose SHA-256 differs from `--sha256`, when given. Only this check stops
   someone who can replace both the model and its JSON file, so take the hash from a source
   you trust;
3. refuses a model made with another major or minor version of Python, scikit-learn, numpy or
   pandas: it could load and then score differently without any error.
   `--allow-version-mismatch` loads it anyway, with a warning.

**1.0 models** (`.joblib`, pickles) still load, through an unpickler that resolves only the
classes and functions a Prohori model needs (`prohori.ml.safety.JOBLIB_GLOBALS`), so a file that
asks for `os.system` or `eval` is refused before anything runs. Their JSON files recorded only
the scikit-learn version, which is checked; a warning says the rest is unknown. Retraining
replaces a `.joblib` model with a `.skops` one. Prohori never downloads models; only load
models you trained yourself or got from someone you trust.

## History: the 1.0 numbers

The numbers published with Prohori 1.0, frozen here; the [Results](#results) above replace
them. In 1.0 the validation split (and CIC-IDS-2017's test split) were rows drawn at random,
stratified by class, and model files were pickles. What moved and why is in the CHANGELOG
(1.1) and the [calibration study](#calibration-study).

### UNSW-NB15 (official training and testing partition)

Seeds 0, 1, 2; mean ± standard deviation.

| Model | PR-AUC | ROC-AUC | Test FPR (1 % val.) | Recall | False alerts / 10k | Test FPR (0.1 % val.) | Recall | False alerts / 10k |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Gradient boosting (supervised) | 0.952 ± 0.002 | 0.968 ± 0.001 | 4.50 ± 0.34 % | 81.75 ± 0.77 % | 290.1 ± 21.8 | 0.07 ± 0.07 % | 46.00 ± 8.53 % | 4.2 ± 4.8 |
| Isolation Forest (benign only) | 0.522 ± 0.003 | 0.710 ± 0.001 | 0.98 ± 0.15 % | 4.52 ± 0.97 % | 63.3 ± 9.4 | 0.11 ± 0.05 % | 0.71 ± 0.30 % | 6.9 ± 3.5 |

Effect of the leakage controls on gradient boosting. Each variant has its own test split, so this compares what the same pipeline reports about itself, not two models on the same data:

| Variant | Test flows | Attack share | PR-AUC | ROC-AUC | Recall (0.1 % val.) | Test FPR |
| --------- | -----------: | -------------: | -------: | --------: | ------: | ------: |
| Cleaned (every leakage control) | 52,418 | 35.6 % | 0.952 ± 0.002 | 0.968 ± 0.001 | 46.0 ± 8.5 % | 0.07 ± 0.07 % |
| Uncleaned (no deduplication, ids and ports kept) | 82,332 | 55.1 % | 0.989 ± 0.000 | 0.985 ± 0.001 | 78.0 ± 6.7 % | 0.18 ± 0.22 % |
| Cleaned, without the TTL columns | 52,417 | 35.6 % | 0.945 ± 0.000 | 0.963 ± 0.000 | 46.7 ± 11.0 % | 0.09 ± 0.10 % |

### CIC-IDS-2017, improved release (Engelen, Liu et al., CNS 2022)

Seeds 0, 1, 2; mean ± standard deviation.

| Model | PR-AUC | ROC-AUC | Test FPR (1 % val.) | Recall | False alerts / 10k | Test FPR (0.1 % val.) | Recall | False alerts / 10k |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Gradient boosting (supervised) | 0.999 ± 0.000 | 1.000 ± 0.000 | 1.00 ± 0.04 % | 99.99 ± 0.00 % | 83.8 ± 3.5 | 0.10 ± 0.01 % | 99.98 ± 0.00 % | 8.7 ± 0.7 |
| Isolation Forest (benign only) | 0.527 ± 0.044 | 0.926 ± 0.013 | 1.03 ± 0.02 % | 0.63 ± 0.32 % | 85.7 ± 2.0 | 0.10 ± 0.01 % | 0.00 ± 0.00 % | 8.7 ± 0.8 |

Effect of the leakage controls on gradient boosting. Each variant has its own test split, so this compares what the same pipeline reports about itself, not two models on the same data:

| Variant | Test flows | Attack share | PR-AUC | ROC-AUC | Recall (0.1 % val.) | Test FPR |
| --------- | -----------: | -------------: | -------: | --------: | ------: | ------: |
| Cleaned (every leakage control) | 514,531 | 16.5 % | 0.999 ± 0.000 | 1.000 ± 0.000 | 100.0 ± 0.0 % | 0.10 ± 0.01 % |
| Uncleaned (no deduplication, ids and ports kept) | 629,993 | 24.1 % | 1.000 ± 0.000 | 1.000 ± 0.000 | 100.0 ± 0.0 % | 0.09 ± 0.01 % |

### Cross-dataset test (1.0)

PR-AUC depends on the share of attacks, which differs between the datasets, so each PR-AUC has its chance level (the attack share) next to it. ROC-AUC does not depend on it (0.5 is chance) and is the fairer comparison across datasets.

| Direction | Model | PR-AUC, all features | PR-AUC, common features | Chance, source | PR-AUC, cross-dataset | Chance, target | ROC-AUC, in-dataset | ROC-AUC, cross-dataset |
| ----------- | ------- | ------: | ------: | ------: | ------: | ------: | ------: | ------: |
| unsw-nb15 → cicids2017 | Gradient boosting (supervised) | 0.952 ± 0.002 | 0.918 ± 0.001 | 0.329 | 0.323 ± 0.086 | 0.164 | 0.952 ± 0.000 | 0.639 ± 0.064 |
| unsw-nb15 → cicids2017 | Isolation Forest (benign only) | 0.522 ± 0.003 | 0.354 ± 0.006 | 0.329 | 0.213 ± 0.013 | 0.164 | 0.469 ± 0.019 | 0.681 ± 0.024 |
| cicids2017 → unsw-nb15 | Gradient boosting (supervised) | 0.999 ± 0.000 | 0.999 ± 0.001 | 0.164 | 0.404 ± 0.016 | 0.329 | 1.000 ± 0.000 | 0.614 ± 0.020 |
| cicids2017 → unsw-nb15 | Isolation Forest (benign only) | 0.527 ± 0.044 | 0.439 ± 0.005 | 0.164 | 0.303 ± 0.005 | 0.329 | 0.895 ± 0.003 | 0.432 ± 0.017 |

At the threshold chosen for a 1 % false-positive rate on the source's validation split:

| Direction | Model | In-dataset recall | In-dataset test FPR | Cross-dataset recall | Cross-dataset FPR | False alerts / 10k |
| ----------- | ------- | ------: | ------: | ------: | ------: | ------: |
| unsw-nb15 → cicids2017 | Gradient boosting (supervised) | 66.8 ± 2.2 % | 2.54 ± 0.42 % | 58.8 ± 10.8 % | 42.19 ± 1.15 % | 3525 ± 96 |
| unsw-nb15 → cicids2017 | Isolation Forest (benign only) | 1.3 ± 0.3 % | 0.78 ± 0.22 % | 1.1 ± 0.3 % | 3.71 ± 0.77 % | 310 ± 64 |
| cicids2017 → unsw-nb15 | Gradient boosting (supervised) | 100.0 ± 0.0 % | 0.98 ± 0.02 % | 75.4 ± 0.1 % | 60.49 ± 2.20 % | 4058 ± 147 |
| cicids2017 → unsw-nb15 | Isolation Forest (benign only) | 0.1 ± 0.0 % | 1.03 ± 0.03 % | 6.3 ± 0.5 % | 5.10 ± 0.18 % | 342 ± 12 |
