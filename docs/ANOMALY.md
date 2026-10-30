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

- **The detectors caught nothing the rules missed.** On the held-out variants, the attacks the
  detectors catch are a subset of what the rules catch; the four attacks every rule missed were
  missed by the detectors too.
- **They are quieter.** The robust z-score raised no false alert on the held-out variants and the
  Isolation Forest about one every three runs, against more than six a run for the rules
  (254 of their 259 held-out false alerts come from PRH-ACCT-001, which is noisy by design).
- **They catch loud attacks only.** Brute force, scanning and injection probes stand out from the
  background (and the Isolation Forest catches three of the five slowed-down account takeovers);
  slow spraying, credential stuffing spread over many addresses, token reuse and an admin acting
  at night do not, because in a five-minute window from one address they look like anybody
  else.
- So the detectors are useful as a second, low-noise signal that confirms a rule, not as a way to
  find new attacks. That is a finding about these logs and this simulator, not about anomaly
  detection in general.

## Features

Events are grouped by source IP into five-minute windows (events without a source address are
skipped). Each window gets thirteen features (`prohori.ml.features`):

| Feature | Meaning |
|---------|---------|
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
  are constant in the log are skipped. Flags windows with z of at least **12**.
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
a scenario expects, which is why the rules catch 36 held-out attacks here and 35 in the rule
evaluation.

## Results

<!-- anomaly:start -->
Generated by `python -m prohori.ml.logeval`: 8 scenarios, seeds 1 to 5 per variant, 5-minute windows. Do not edit by hand.

| Detector | Attacks caught, default | Attacks caught, held-out | Precision, default | Precision, held-out | False alerts a run, held-out |
|----------|------:|------:|------:|------:|------:|
| Detection rules (any rule) | 40/40 | 36/40 | 61 % | 39 % | 6.47 |
| Robust z-score | 30/40 | 15/40 | 97 % | 100 % | 0.0 |
| Fixed thresholds | 25/40 | 10/40 | 47 % | 49 % | 0.93 |
| Isolation Forest | 30/40 | 17/40 | 85 % | 70 % | 0.35 |

Attacks caught in the held-out variants, by scenario:

| Scenario | Detection rules (any rule) | Robust z-score | Fixed thresholds | Isolation Forest |
|----------|------:|------:|------:|------:|
| account-takeover | 5/5 | 0/5 | 0/5 | 3/5 |
| admin-misuse | 5/5 | 0/5 | 0/5 | 0/5 |
| credential-stuffing | 1/5 | 0/5 | 0/5 | 0/5 |
| injection | 5/5 | 5/5 | 0/5 | 5/5 |
| password-spraying | 5/5 | 0/5 | 0/5 | 0/5 |
| ssh-bruteforce | 5/5 | 5/5 | 5/5 | 4/5 |
| token-reuse | 5/5 | 0/5 | 0/5 | 0/5 |
| web-scanning | 5/5 | 5/5 | 5/5 | 5/5 |

Against the rules in the held-out variants (an attack counts once however many detectors catch it):

| Detector | Caught by rules | Caught by the detector | Caught by either | Only the detector | Only the rules |
|----------|------:|------:|------:|------:|------:|
| Robust z-score | 36 | 15 | 36 | 0 | 21 |
| Fixed thresholds | 36 | 10 | 36 | 0 | 26 |
| Isolation Forest | 36 | 17 | 36 | 0 | 19 |

Cut-off selection on the default variants (window-level precision, recall and F1; the chosen cut-off is in bold):

| Detector | Cut-off | Precision | Recall | F1 |
|----------|------:|------:|------:|------:|
| Robust z-score | 3 | 0.046 | 0.615 | 0.085 |
| Robust z-score | 4 | 0.065 | 0.615 | 0.118 |
| Robust z-score | 5 | 0.134 | 0.615 | 0.220 |
| Robust z-score | 6 | 0.258 | 0.615 | 0.364 |
| Robust z-score | 8 | 0.519 | 0.615 | 0.563 |
| Robust z-score | 10 | 0.625 | 0.615 | 0.620 |
| Robust z-score | **12** | 0.972 | 0.538 | 0.693 |
| Robust z-score | 15 | 1.000 | 0.462 | 0.632 |
| Robust z-score | 20 | 1.000 | 0.385 | 0.556 |
| Robust z-score | 30 | 1.000 | 0.308 | 0.471 |
| Isolation Forest | 0.55 | 0.025 | 0.769 | 0.048 |
| Isolation Forest | 0.6 | 0.034 | 0.769 | 0.066 |
| Isolation Forest | 0.65 | 0.061 | 0.708 | 0.113 |
| Isolation Forest | 0.7 | 0.145 | 0.646 | 0.237 |
| Isolation Forest | 0.75 | 0.351 | 0.615 | 0.447 |
| Isolation Forest | **0.8** | 0.851 | 0.615 | 0.714 |
| Isolation Forest | 0.85 | 1.000 | 0.292 | 0.452 |
| Isolation Forest | 0.9 | 1.000 | 0.077 | 0.143 |
<!-- anomaly:end -->

## What the false alerts are

Every false alert of the z-score and the Isolation Forest in the held-out runs was looked at,
and a sample of the fixed thresholds':

- **Shared addresses.** Each of the Isolation Forest's 14 false alerts is a window in which three
  to seven accounts used one address, as the simulated background's shared NAT address does:
  several customers sign in and refresh sessions within five minutes. Such a window has more
  events, sign-ins and accounts than the usual window of one person, and an occasional typo adds
  a failure. Incidents already treat an address seen with many accounts as shared.
- **Thin backgrounds make small bursts stand out.** In the day-long admin-misuse logs the usual
  window has one event, so four events and one failed sign-in through the NAT address are enough
  for the Isolation Forest.
- **Fixed thresholds** flag windows of the same kind far more often (37 false alerts; the ones
  sampled all had five or more accounts on one address), because that is common in a busy shop.
  The z-score's floors and cut-off keep it silent there.

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
