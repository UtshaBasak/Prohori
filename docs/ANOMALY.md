# Log Anomaly Detection

Prohori's detection rules find attacks they were written for. The anomaly detectors look for
something else: a source address that behaves unlike the others in the same log. This page covers
the features, the three detectors, how they reach incidents, and how they compare with the rules
on the simulator's labelled attacks. Design decisions are in
[ADR-0022](DECISIONS.md#adr-0022-log-anomaly-detection).

## Contents

- [Summary](#summary)
- [Features](#features)
- [Detectors](#detectors)
- [Using them](#using-them)
- [Evaluation](#evaluation)
- [Results](#results)
- [What the false alerts are](#what-the-false-alerts-are)
- [Limitations](#limitations)

## Summary

- **The detectors caught nothing the rules missed.** On the held-out variants the rules (any
  rule) catch all 40 attacks, and the attacks the detectors catch are a subset of those.
- **They are quieter.** On the held-out variants the robust z-score raised 2 false alerts in 40
  runs and the Isolation Forest 1, against almost seven a run for the rules (272 of their 277
  held-out false alerts come from PRH-ACCT-001, which is noisy by design).
- **They catch loud attacks only.** Brute force, scanning and injection probes stand out from the
  background (and both the z-score and the Isolation Forest catch all five slowed-down account
  takeovers); slow spraying, credential stuffing spread over many addresses, token reuse and an admin acting
  at night do not, because in a five-minute window from one address they look like anybody
  else.
- So the detectors are useful as a second, low-noise signal that confirms a rule, not as a way to
  find new attacks. That is a finding about these logs and this simulator, not about anomaly
  detection in general.

## Features

Events are grouped by source IP into five-minute windows (events without a source address are
skipped). Each window gets thirteen features (`prohori.ml.features`):

| Feature | Meaning |
| --------- | --------- |
| `events`, `rate_per_minute` | Events in the window, and per minute |
| `auth_attempts`, `auth_failures` | Sign-in events, and how many failed |
| `failure_ratio` | Failed share of the sign-ins |
| `distinct_users` | Accounts the address touched |
| `http_requests`, `distinct_paths` | Requests with a status, and different paths |
| `http_4xx_ratio` | Share of requests that ended in 4xx |
| `path_entropy` | How spread the requests were over paths, in bits |
| `distinct_user_agents` | Different user agents |
| `new_client_ratio` | Share of (account, client) pairs not seen earlier in the log |
| `night_ratio` | Share of events between 22:00 and 06:59 (UTC by default) |

Ratios and entropy are computed only when the window has at least five events of the kind they
are about, and are 0 otherwise: one failed sign-in is not a 100 % failure ratio. A window lists at
most 100 event ids, as many as a rule alert.

## Detectors

Each detector compares the windows of one log with each other. Nothing is trained in advance and
no model file is saved or loaded.

- **Robust z-score** (`PRH-ML-ZSCORE`, base install). For every feature: the median and the
  median absolute deviation (MAD) over the log's windows. A window scores its largest one-sided
  z, so only higher-than-usual values count. The scale never drops below a floor (one unit for
  counts, 0.1 for ratios, half a bit of entropy): in most logs the usual number of failures is 0
  with a MAD of 0, and without the floor one failure would be infinitely unusual. Features that
  are constant in the log are skipped. Flags windows with z of at least **10** (12 before
  step 28c; chosen again on the default variants of simulator address model 2).
- **Isolation Forest** (`PRH-ML-IFOREST`, `ml` extra). 200 trees over the log-scaled features,
  seeded. Flags windows with an anomaly score of at least **0.8** (about 0.5 is ordinary).
- **Fixed thresholds** (evaluation only): at least 10 failed sign-ins, 5 accounts, 30 paths or
  30 events a minute in a window. The simplest baseline, and close to what the rules do.

The z-score and the Isolation Forest need at least 20 windows in the log; with fewer, nothing is
judged unusual and the command says so.

The cut-offs (12 and 0.8) were chosen on the simulator's **default** variants, as the candidates
with the best window-level F1, and frozen before the held-out variants were scored once. The
selection table is in [Results](#results).

## Using them

```bash
prohori detect access.log --models        # rule alerts, then anomaly alerts
prohori incidents app.jsonl --models      # anomaly alerts join the incidents
prohori triage auth.log --models -o triage/
```

Anomaly alerts have `detector_kind: model`, severity `low`, the source IP as their entity, and an
explanation made only of feature names and numbers, such as
`z 38: distinct_paths 112 (usual 1), http_4xx_ratio 0.93 (usual 0.00)`. They group into incidents
like rule alerts. An incident that has one gets a limitation ("the activity is unusual compared
with the rest of this log, which is not proof of an attack") and an action to review the window.
A model alert next to a rule alert for the same address counts as one more detector in the
incident score (+10 points), which is the intended effect: two independent signals.

Without the `ml` extra, `--models` runs the z-score only and says so. Without `--models`, nothing
changes.

## Evaluation

`python -m prohori.ml.logeval` runs every simulator scenario, in both variants, for seeds 1 to 5.
Each log is parsed once; the built-in rules and the detectors see the same events. Alerts are
scored like the rules in [SIMULATOR.md](SIMULATOR.md): an alert is a true positive when at least
half of the events it lists are attack lines, and an attack is **caught** by a detector when a
true-positive alert is credited to it. Here **any** rule counts for the rules, not only the rules
a scenario expects, which is why the rules catch 40 held-out attacks here and also 40 in the rule
evaluation (where only expected rules count). The results below are on simulator address model
2 (ADR-0038); every number moved with it, including the cut-off selection.

## Results

<!-- anomaly:start -->
Generated by `python -m prohori.ml.logeval`: 8 scenarios, seeds 1 to 5 per variant, 5-minute windows. Do not edit by hand.

| Detector | Attacks caught, default | Attacks caught, held-out | Precision, default | Precision, held-out | False alerts a run, held-out |
| ---------- | ------: | ------: | ------: | ------: | ------: |
| Detection rules (any rule) | 40/40 | 40/40 | 62 % | 45 % | 6.92 |
| Robust z-score | 30/40 | 20/40 | 89 % | 97 % | 0.05 |
| Fixed thresholds | 25/40 | 10/40 | 100 % | 100 % | 0.0 |
| Isolation Forest | 30/40 | 17/40 | 91 % | 97 % | 0.03 |

Attacks caught in the held-out variants, by scenario:

| Scenario | Detection rules (any rule) | Robust z-score | Fixed thresholds | Isolation Forest |
| ---------- | ------: | ------: | ------: | ------: |
| account-takeover | 5/5 | 5/5 | 0/5 | 5/5 |
| admin-misuse | 5/5 | 0/5 | 0/5 | 0/5 |
| credential-stuffing | 5/5 | 0/5 | 0/5 | 0/5 |
| injection | 5/5 | 5/5 | 0/5 | 5/5 |
| password-spraying | 5/5 | 0/5 | 0/5 | 0/5 |
| ssh-bruteforce | 5/5 | 5/5 | 5/5 | 2/5 |
| token-reuse | 5/5 | 0/5 | 0/5 | 0/5 |
| web-scanning | 5/5 | 5/5 | 5/5 | 5/5 |

Against the rules in the held-out variants (an attack counts once however many detectors catch it):

| Detector | Caught by rules | Caught by the detector | Caught by either | Only the detector | Only the rules |
| ---------- | ------: | ------: | ------: | ------: | ------: |
| Robust z-score | 40 | 20 | 40 | 0 | 20 |
| Fixed thresholds | 40 | 10 | 40 | 0 | 30 |
| Isolation Forest | 40 | 17 | 40 | 0 | 23 |

Cut-off selection on the default variants (window-level precision, recall and F1; the chosen cut-off is in bold):

| Detector | Cut-off | Precision | Recall | F1 |
| ---------- | ------: | ------: | ------: | ------: |
| Robust z-score | 3 | 0.055 | 0.615 | 0.101 |
| Robust z-score | 4 | 0.076 | 0.615 | 0.136 |
| Robust z-score | 5 | 0.172 | 0.615 | 0.268 |
| Robust z-score | 6 | 0.331 | 0.615 | 0.430 |
| Robust z-score | 8 | 0.727 | 0.615 | 0.667 |
| Robust z-score | **10** | 0.889 | 0.615 | 0.727 |
| Robust z-score | 12 | 1.000 | 0.538 | 0.700 |
| Robust z-score | 15 | 1.000 | 0.462 | 0.632 |
| Robust z-score | 20 | 1.000 | 0.385 | 0.556 |
| Robust z-score | 30 | 1.000 | 0.308 | 0.471 |
| Isolation Forest | 0.55 | 0.024 | 0.769 | 0.047 |
| Isolation Forest | 0.6 | 0.035 | 0.769 | 0.066 |
| Isolation Forest | 0.65 | 0.063 | 0.769 | 0.116 |
| Isolation Forest | 0.7 | 0.164 | 0.677 | 0.264 |
| Isolation Forest | 0.75 | 0.455 | 0.615 | 0.523 |
| Isolation Forest | **0.8** | 0.909 | 0.615 | 0.734 |
| Isolation Forest | 0.85 | 1.000 | 0.323 | 0.488 |
| Isolation Forest | 0.9 | 1.000 | 0.077 | 0.143 |
<!-- anomaly:end -->

## What the false alerts are

Every false alert of the z-score and the Isolation Forest in the held-out runs was looked at:

- **Shared addresses.** Two of the three are the same window, flagged by both detectors: the
  simulated background's shared NAT address (five customers) with seven sign-in events and a
  typo in five minutes, at night. Such a window has more events, sign-ins and accounts than the
  usual window of one person. Incidents already treat an address seen with many accounts as
  shared.
- **A busy visitor.** The third (z-score) is a customer who opened twelve pages in five minutes.
- **Fixed thresholds** raised no false alert on address model 2. On model 1, where 13 customers
  shared the NAT address, they raised 37, all windows with five or more accounts on one address;
  how often that happens depends on how many people share an address, which is site-specific.

## Limitations

- **Synthetic logs by the same author.** The cut-offs were chosen on default variants written by
  the person who wrote the detectors; the held-out variants are the honest number, and real logs
  are noisier.
- **Unusual for this log.** A log that is mostly attack, or a quiet log, has a different
  "usual"; the 20-window minimum guards only against the smallest logs.
- **Per address, per five minutes.** Attacks spread over many addresses or over hours stay
  under every per-window cut-off; that is what the held-out variants do.
- **Night is UTC by default.** PRH-ADMIN-002 uses the shop's timezone; the `night_ratio` feature
  uses UTC unless the extractor is given another zone, so the admin-at-night scenario looks
  ordinary to the detectors.
- **No payloads.** Like the rules, the detectors see the request line and the event fields,
  nothing else.
