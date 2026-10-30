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
- [Cross-dataset test](#cross-dataset-test)
- [Failure cases](#failure-cases)
- [Limitations](#limitations)
- [Reproducing the results](#reproducing-the-results)
- [Saved models and safety](#saved-models-and-safety)

## Summary

- **Gradient boosting works well inside one lab dataset and badly at telling some attacks from
  benign traffic.** On UNSW-NB15 it reaches a PR-AUC of 0.95. At a threshold that would alert on
  1 in 1,000 benign flows it catches about half of the attacks, and almost none of the
  `Fuzzers` and `Analysis` attacks.
- **A threshold chosen on validation data does not always hold on test data.** On UNSW-NB15 the
  threshold for a 1 % false-positive rate on validation produced about 4.5 % on the test file:
  290 false alerts per 10,000 flows instead of 100. The benign flows of the official testing
  file score differently from the benign validation flows, which come from the training file;
  why is not established. A SOC deploying a model meets the same kind of shift between the data
  a threshold was set on and live traffic. The 0.1 % threshold held (0.07 %).
- **CIC-IDS-2017 is close to solved by gradient boosting, even after cleaning:** 99.98 % of
  attacks caught at a 0.1 % false-positive rate. That says more about the dataset than about the
  model: every attack in it comes from a few scripted tools run in one lab week.
- **Neither model transfers to the other dataset.** Trained on the twelve features both datasets
  share, gradient boosting keeps a PR-AUC of 0.92 (UNSW-NB15) and 0.999 (CIC-IDS-2017) on its
  own dataset but falls to 0.32 and 0.40 on the other, little above the attack shares there
  (0.16 and 0.33). Its 1 % threshold flags 42 % and 60 % of the other dataset's benign flows:
  thousands of false alerts per 10,000 flows. See [Cross-dataset test](#cross-dataset-test).
- **The Isolation Forest, trained on benign traffic only, is not useful as a detector here.** It
  catches fewer than 5 % of attacks at a 1 % false-positive rate on either dataset. Attacks in
  these datasets are not unusual in the way an Isolation Forest measures unusual.
- **Leakage controls matter:** without them, the same gradient-boosting pipeline reports a
  PR-AUC of 0.989 instead of 0.952 on UNSW-NB15, and 78 % instead of 46 % recall at the 0.1 %
  threshold.

## Models

| | Gradient boosting | Isolation Forest |
|--|-------------------|------------------|
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
|--|-----------|--------------------------|
| Captured | 2015, UNSW Canberra cyber range | 2017, one week in the CIC lab, regenerated and relabelled in 2022 |
| Split | Official training file (minus 20 % for validation) and official testing file | Seeded split stratified by class: 50 % train, 20 % validation, 30 % test |
| Train / validation / test flows | 79,415 / 19,853 / 52,418 | 857,551 / 343,020 / 514,531 |
| Attack share in test | 35.6 % | 16.5 % |
| Features | 42 (3 of them text) | 82 |

Both datasets were deduplicated, test rows found in training were removed, and identifier,
address, port, time and label-derived columns were dropped before training. All of that is in
[DATASETS.md](DATASETS.md), with the numbers removed.

## How they are evaluated

For each seed (0, 1 and 2):

1. Prepare the data. The seed sets the validation split, and for CIC-IDS-2017 the whole split.
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
#### UNSW-NB15 (official training and testing partition)

Seeds 0, 1, 2; mean ± standard deviation over the seeds. Each threshold is chosen on the validation split for a target false-positive rate (FPR) and frozen; the test split is scored once. Generated from `results/ml_unsw-nb15.json`; do not edit by hand.

| Model | PR-AUC | ROC-AUC | Test FPR (1 % val.) | Recall | False alerts / 10k | Test FPR (0.1 % val.) | Recall | False alerts / 10k |
|---|---|---|---|---|---|---|---|---|
| Gradient boosting (supervised) | 0.952 ± 0.002 | 0.968 ± 0.001 | 4.50 ± 0.34 % | 81.75 ± 0.77 % | 290.1 ± 21.8 | 0.07 ± 0.07 % | 46.00 ± 8.53 % | 4.2 ± 4.8 |
| Isolation Forest (benign only) | 0.522 ± 0.003 | 0.710 ± 0.001 | 0.98 ± 0.15 % | 4.52 ± 0.97 % | 63.3 ± 9.4 | 0.11 ± 0.05 % | 0.71 ± 0.30 % | 6.9 ± 3.5 |

Effect of the leakage controls on gradient boosting. Each variant has its own test split, so this compares what the same pipeline reports about itself, not two models on the same data:

| Variant | Test flows | Attack share | PR-AUC | ROC-AUC | Recall (0.1 % val.) | Test FPR |
|---------|-----------:|-------------:|-------:|--------:|------:|------:|
| Cleaned (every leakage control) | 52,418 | 35.6 % | 0.952 ± 0.002 | 0.968 ± 0.001 | 46.0 ± 8.5 % | 0.07 ± 0.07 % |
| Uncleaned (no deduplication, ids and ports kept) | 82,332 | 55.1 % | 0.989 ± 0.000 | 0.985 ± 0.001 | 78.0 ± 6.7 % | 0.18 ± 0.22 % |
| Cleaned, without the TTL columns | 52,417 | 35.6 % | 0.945 ± 0.000 | 0.963 ± 0.000 | 46.7 ± 11.0 % | 0.09 ± 0.10 % |

Recall per attack class (gradient boosting, cleaned) with the class's test flows, averaged over the seeds:

| Class | Test flows | Recall (1 % val.) | Recall (0.1 % val.) |
|-------|-----------:|------:|------:|
| Analysis | 58 | 15.5 ± 4.6 % | 0.0 ± 0.0 % |
| Backdoor | 57 | 84.8 ± 2.7 % | 23.4 ± 18.8 % |
| DoS | 1,163 | 92.2 ± 0.3 % | 45.2 ± 10.5 % |
| Exploits | 7,041 | 94.3 ± 0.2 % | 61.5 ± 9.9 % |
| Fuzzers | 4,321 | 37.0 ± 3.1 % | 0.4 ± 0.2 % |
| Generic | 3,399 | 98.7 ± 0.1 % | 88.9 ± 1.5 % |
| Reconnaissance | 2,215 | 97.6 ± 0.3 % | 28.7 ± 29.9 % |
| Shellcode | 365 | 89.5 ± 1.5 % | 5.8 ± 9.4 % |
| Worms | 43 | 97.7 ± 0.0 % | 41.1 ± 22.9 % |

#### CIC-IDS-2017, improved release (Engelen, Liu et al., CNS 2022)

Seeds 0, 1, 2; mean ± standard deviation over the seeds. Each threshold is chosen on the validation split for a target false-positive rate (FPR) and frozen; the test split is scored once. Generated from `results/ml_cicids2017.json`; do not edit by hand.

| Model | PR-AUC | ROC-AUC | Test FPR (1 % val.) | Recall | False alerts / 10k | Test FPR (0.1 % val.) | Recall | False alerts / 10k |
|---|---|---|---|---|---|---|---|---|
| Gradient boosting (supervised) | 0.999 ± 0.000 | 1.000 ± 0.000 | 1.00 ± 0.04 % | 99.99 ± 0.00 % | 83.8 ± 3.5 | 0.10 ± 0.01 % | 99.98 ± 0.00 % | 8.7 ± 0.7 |
| Isolation Forest (benign only) | 0.527 ± 0.044 | 0.926 ± 0.013 | 1.03 ± 0.02 % | 0.63 ± 0.32 % | 85.7 ± 2.0 | 0.10 ± 0.01 % | 0.00 ± 0.00 % | 8.7 ± 0.8 |

Effect of the leakage controls on gradient boosting. Each variant has its own test split, so this compares what the same pipeline reports about itself, not two models on the same data:

| Variant | Test flows | Attack share | PR-AUC | ROC-AUC | Recall (0.1 % val.) | Test FPR |
|---------|-----------:|-------------:|-------:|--------:|------:|------:|
| Cleaned (every leakage control) | 514,531 | 16.5 % | 0.999 ± 0.000 | 1.000 ± 0.000 | 100.0 ± 0.0 % | 0.10 ± 0.01 % |
| Uncleaned (no deduplication, ids and ports kept) | 629,993 | 24.1 % | 1.000 ± 0.000 | 1.000 ± 0.000 | 100.0 ± 0.0 % | 0.09 ± 0.01 % |

Recall per attack class (gradient boosting, cleaned) with the class's test flows, averaged over the seeds:

| Class | Test flows | Recall (1 % val.) | Recall (0.1 % val.) |
|-------|-----------:|------:|------:|
| Botnet | 221 | 99.8 ± 0.3 % | 99.8 ± 0.3 % |
| DDoS | 28,543 | 100.0 ± 0.0 % | 100.0 ± 0.0 % |
| DoS GoldenEye | 2,270 | 100.0 ± 0.0 % | 100.0 ± 0.0 % |
| DoS Hulk | 47,540 | 100.0 ± 0.0 % | 100.0 ± 0.0 % |
| DoS Slowhttptest | 522 | 100.0 ± 0.0 % | 99.9 ± 0.1 % |
| DoS Slowloris | 1,158 | 100.0 ± 0.0 % | 100.0 ± 0.0 % |
| FTP-Patator | 1,192 | 100.0 ± 0.0 % | 100.0 ± 0.0 % |
| Heartbleed | 3 | 100.0 ± 0.0 % | 100.0 ± 0.0 % |
| Infiltration | 11 | 84.8 ± 5.2 % | 72.7 ± 15.7 % |
| Infiltration - Portscan | 1,808 | 99.6 ± 0.1 % | 99.6 ± 0.1 % |
| Portscan | 472 | 99.9 ± 0.1 % | 99.6 ± 0.2 % |
| SSH-Patator | 888 | 100.0 ± 0.0 % | 99.9 ± 0.1 % |
| Web Attack - Brute Force | 22 | 97.0 ± 2.6 % | 93.9 ± 2.6 % |
| Web Attack - SQL Injection | 4 | 100.0 ± 0.0 % | 66.7 ± 28.9 % |
| Web Attack - XSS | 5 | 100.0 ± 0.0 % | 100.0 ± 0.0 % |
<!-- ml-results:end -->

## Cross-dataset test

A model is only useful if it works on traffic other than the lab it was trained in. The two
datasets were captured by different tools on different networks, so the test trains on one and
scores the other, using only the features both have.

**The mapping is lossy.** Twelve features can be computed from both datasets; everything else
(UNSW-NB15's TTLs, TCP sequence and window values and connection counters, CICFlowMeter's
packet-length extremes, flag counts, bulk and idle statistics) has no counterpart:

| Common feature | UNSW-NB15 | CIC-IDS-2017 |
|----------------|-----------|--------------|
| `duration_s` | `dur` (seconds) | `flow_duration` / 10^6 (microseconds) |
| `fwd_packets`, `bwd_packets` | `spkts`, `dpkts` | `total_fwd_packet`, `total_bwd_packets` |
| `fwd_bytes`, `bwd_bytes` | `sbytes`, `dbytes` (whole packets) | payload + transport headers + 34 bytes a packet |
| `fwd_mean_bytes`, `bwd_mean_bytes` | bytes / packets | the same |
| `fwd_iat_mean_s`, `bwd_iat_mean_s` | `sinpkt`, `dinpkt` / 10^3 (ms) | `fwd_iat_mean`, `bwd_iat_mean` / 10^6 (µs) |
| `packets_per_s`, `bytes_per_s` | over the duration | the same |
| `protocol` | `proto`: tcp 6, udp 17, icmp 1, other -1 | `protocol`: 6, 17, 1, other -1 |

Bytes are counted on the wire on both sides. UNSW-NB15 counts whole packets (a two-packet DNS
query is about 146 bytes); CICFlowMeter counts payload, so its byte counts get the transport
header lengths it records plus 34 bytes a packet for the Ethernet and IPv4 headers (the same
kind of DNS query: about 154 bytes). The two tools also cut flows differently (timeouts, when a
flow ends), which no mapping can undo.

**Method.** For each seed, both datasets are prepared with every leakage control, mapped and
deduplicated again on the common features (fewer features make more rows identical). A model is
fitted on the source's training split; its thresholds come from the source's validation split;
it is scored once on the source's test split (in-dataset) and once on the target's test split
(cross-dataset). The target is never seen before it is scored, as on a new network.

<!-- ml-cross:start -->
Seeds 0, 1, 2; mean ± standard deviation. Each model is trained on the source dataset's 12 common features, its thresholds are chosen on the source's validation split, and it is scored once on the source's test split (in-dataset) and once on the target's (cross-dataset). Generated from `results/ml_cross.json`; do not edit by hand.

| Direction | Model | PR-AUC, all features | PR-AUC, common features | PR-AUC, cross-dataset | Attack share in target |
|-----------|-------|------:|------:|------:|------:|
| unsw-nb15 → cicids2017 | Gradient boosting (supervised) | 0.952 ± 0.002 | 0.918 ± 0.001 | 0.323 ± 0.086 | 16.4 % |
| unsw-nb15 → cicids2017 | Isolation Forest (benign only) | 0.522 ± 0.003 | 0.354 ± 0.006 | 0.213 ± 0.013 | 16.4 % |
| cicids2017 → unsw-nb15 | Gradient boosting (supervised) | 0.999 ± 0.000 | 0.999 ± 0.001 | 0.404 ± 0.016 | 32.9 % |
| cicids2017 → unsw-nb15 | Isolation Forest (benign only) | 0.527 ± 0.044 | 0.439 ± 0.005 | 0.303 ± 0.005 | 32.9 % |

At the threshold chosen for a 1 % false-positive rate on the source's validation split:

| Direction | Model | In-dataset recall | In-dataset test FPR | Cross-dataset recall | Cross-dataset FPR | False alerts / 10k |
|-----------|-------|------:|------:|------:|------:|------:|
| unsw-nb15 → cicids2017 | Gradient boosting (supervised) | 66.8 ± 2.2 % | 2.54 ± 0.42 % | 58.8 ± 10.8 % | 42.19 ± 1.15 % | 3525 ± 96 |
| unsw-nb15 → cicids2017 | Isolation Forest (benign only) | 1.3 ± 0.3 % | 0.78 ± 0.22 % | 1.1 ± 0.3 % | 3.71 ± 0.77 % | 310 ± 64 |
| cicids2017 → unsw-nb15 | Gradient boosting (supervised) | 100.0 ± 0.0 % | 0.98 ± 0.02 % | 75.4 ± 0.1 % | 60.49 ± 2.20 % | 4058 ± 147 |
| cicids2017 → unsw-nb15 | Isolation Forest (benign only) | 0.1 ± 0.0 % | 1.03 ± 0.03 % | 6.3 ± 0.5 % | 5.10 ± 0.18 % | 342 ± 12 |

At the threshold chosen for a 0.1 % false-positive rate on the source's validation split:

| Direction | Model | In-dataset recall | In-dataset test FPR | Cross-dataset recall | Cross-dataset FPR | False alerts / 10k |
|-----------|-------|------:|------:|------:|------:|------:|
| unsw-nb15 → cicids2017 | Gradient boosting (supervised) | 24.3 ± 8.1 % | 0.06 ± 0.04 % | 27.9 ± 6.0 % | 11.33 ± 6.88 % | 947 ± 575 |
| unsw-nb15 → cicids2017 | Isolation Forest (benign only) | 0.5 ± 0.0 % | 0.05 ± 0.04 % | 0.3 ± 0.2 % | 2.14 ± 0.19 % | 179 ± 16 |
| cicids2017 → unsw-nb15 | Gradient boosting (supervised) | 99.9 ± 0.0 % | 0.10 ± 0.01 % | 48.7 ± 2.8 % | 35.61 ± 4.71 % | 2389 ± 316 |
| cicids2017 → unsw-nb15 | Isolation Forest (benign only) | 0.0 ± 0.0 % | 0.11 ± 0.00 % | 0.3 ± 0.1 % | 0.08 ± 0.07 % | 5 ± 5 |

Recall per attack class in the target, unsw-nb15 → cicids2017 (gradient boosting, 1 % source-validation threshold):

| Class | Test flows | Recall |
|-------|------:|------:|
| Botnet | 221 | 0.3 ± 0.3 % |
| DDoS | 28,543 | 46.7 ± 29.1 % |
| DoS GoldenEye | 2,270 | 77.3 ± 7.5 % |
| DoS Hulk | 47,540 | 70.6 ± 1.3 % |
| DoS Slowhttptest | 515 | 19.2 ± 7.2 % |
| DoS Slowloris | 1,001 | 45.1 ± 11.7 % |
| FTP-Patator | 1,192 | 0.2 ± 0.3 % |
| Heartbleed | 3 | 100.0 ± 0.0 % |
| Infiltration | 11 | 54.5 ± 15.7 % |
| Infiltration - Portscan | 1,797 | 6.5 ± 0.2 % |
| Portscan | 301 | 4.0 ± 0.9 % |
| SSH-Patator | 888 | 21.4 ± 35.7 % |
| Web Attack - Brute Force | 22 | 100.0 ± 0.0 % |
| Web Attack - SQL Injection | 4 | 16.7 ± 28.9 % |
| Web Attack - XSS | 5 | 100.0 ± 0.0 % |

Recall per attack class in the target, cicids2017 → unsw-nb15 (gradient boosting, 1 % source-validation threshold):

| Class | Test flows | Recall |
|-------|------:|------:|
| Analysis | 58 | 96.6 ± 3.0 % |
| Backdoor | 57 | 84.2 ± 0.0 % |
| DoS | 1,123 | 71.7 ± 1.4 % |
| Exploits | 6,989 | 62.8 ± 0.7 % |
| Fuzzers | 3,742 | 90.9 ± 1.2 % |
| Generic | 629 | 45.6 ± 1.2 % |
| Reconnaissance | 1,850 | 99.5 ± 0.1 % |
| Shellcode | 275 | 99.5 ± 0.4 % |
| Worms | 39 | 82.1 ± 0.0 % |
<!-- ml-cross:end -->

**What this shows.**

- Losing features costs little: gradient boosting on the twelve common features is almost as
  good as on all of them inside each dataset (PR-AUC 0.92 against 0.95 on UNSW-NB15, 0.999 on
  CIC-IDS-2017).
- Changing dataset costs almost everything: PR-AUC drops to 0.32 and 0.40, barely above what a
  random score gets (the attack share), and the frozen thresholds stop meaning anything. The 1 %
  threshold flags 42 % (UNSW-NB15 to CIC-IDS-2017) and 60 % (the reverse) of the target's benign
  flows. The high per-class recall in the reverse direction comes from flagging most of the
  traffic.
- The generalisation gap is the finding: a flow model trained on one lab's traffic learns that
  lab. Before relying on one, train it and set its threshold on the network it will watch.

## Failure cases

- **Fuzzers and Analysis on UNSW-NB15.** At the 1 % threshold gradient boosting catches about
  37 % of `Fuzzers` and 16 % of `Analysis` flows, and at 0.1 % almost none. Fuzzers send
  malformed but ordinary-looking traffic; many of their flows resemble benign ones in every
  feature the dataset has.
- **Low-rate operation costs recall on UNSW-NB15.** Moving from the 1 % to the 0.1 % threshold
  drops recall from about 82 % to 46 %, and some classes (Reconnaissance, Shellcode, Worms,
  Backdoor) vary widely between seeds at 0.1 %, so a single run would be misleading.
- **Thresholds shift between the UNSW-NB15 files.** See the summary: the 1 % threshold gives a
  4.5 % false-positive rate on the testing file. Thresholds must be re-checked on the traffic a
  model is deployed on.
- **Tiny classes.** CIC-IDS-2017 has 3 Heartbleed, 4 SQL injection, 5 XSS and 11 Infiltration
  test flows on average; one missed flow changes their recall by 9 to 33 points. Read their
  recall with the count next to it.
- **The Isolation Forest.** Its PR-AUC (0.52 and 0.53) is above the attack share (0.36 and 0.17),
  so its scores carry some signal, but its highest scores are benign outliers: at a 1 %
  false-positive rate it catches under 5 % of attacks. Using it would mean a queue of false
  alerts.
- **Nearly perfect CIC-IDS-2017 scores** are a warning about the dataset rather than evidence
  that the model would work on a real network.
- **Another network.** On the other dataset the 1 % threshold flags 42 % to 60 % of benign
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
uv run python -m prohori.ml.train --dataset unsw-nb15 --seeds 0 1 2    # about 1 minute
uv run python -m prohori.ml.train --dataset cicids2017 --seeds 0 1 2   # about 6 minutes
uv run python -m prohori.ml.transfer --seeds 0 1 2                     # about 3 minutes
uv run python scripts/generate_results_table.py                        # update the tables
```

Times are for a laptop CPU with 16 GB of memory. `--sample 0.1` runs on a tenth of the rows,
`--models hgb` or `--variants cleaned` limit the work, and `--no-save` skips saving the models.
The results record the library versions used; other versions of scikit-learn can give slightly
different numbers.

## Saved models and safety

Use a saved model with `prohori score FLOWS.csv --model <dataset>/<model>-seed<N>`
([CLI.md](CLI.md#prohori-score)). Each run saves the cleaned models to `models/<dataset>/<model>-seed<N>.joblib`, which git
ignores, with a JSON file next to it holding the features, the frozen thresholds, the library
versions and the model file's SHA-256.

**Model files are pickles, and loading a pickle runs code from it.** Only load models you trained
yourself or got from someone you trust. `prohori.ml.models.load_model` refuses a file whose hash
does not match its JSON file, which catches a corrupted or swapped file but not a deliberate
attack: whoever can replace the model can replace the JSON file too. Prohori never downloads
models.
