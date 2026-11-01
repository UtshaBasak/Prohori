# Warehouse Models

The pipeline stores raw events, alerts, incidents and rejected messages (see
[PIPELINE.md](PIPELINE.md)). A [dbt](https://www.getdbt.com/) project in `pipeline/dbt/` turns
them into tested tables that answer a SOC's everyday questions:
- What happened each day?
- Which addresses keep coming back?
- How long do incidents last?
- How precise is each rule, and how fast does it fire?
- Is the flow model getting better or worse?

The same models run on the lite-mode DuckDB file and on the Docker stack's PostgreSQL. Design
decisions are in [ADR-0025](DECISIONS.md#adr-0025-warehouse-models-with-dbt).

## Contents

- [Quick start](#quick-start)
- [Inputs](#inputs)
- [Models](#models)
- [Data-quality checks](#data-quality-checks)
- [Results on the simulator](#results-on-the-simulator)
- [Limitations](#limitations)

## Quick start

dbt is not part of the Prohori package. It lives in its own dependency group, so it is only
installed when you ask for it. From a clone:

```bash
uv sync --group dbt

# Lite mode: build a warehouse from the simulator (or replay your own logs), then the models.
uv run python scripts/build_lite_warehouse.py --db .prohori/pipeline/prohori.duckdb
uv run dbt build --project-dir pipeline/dbt --profiles-dir pipeline/dbt
uv run dbt source freshness --project-dir pipeline/dbt --profiles-dir pipeline/dbt

# The Docker stack: the same models in PostgreSQL.
uv run prohori pipeline up
uv run prohori pipeline replay logs/web-scanning.log --bootstrap 127.0.0.1:19092
uv run dbt build --project-dir pipeline/dbt --profiles-dir pipeline/dbt --target postgres
```

`dbt build` creates the models and runs every check; it exits non-zero if a check fails.

**Settings.** `pipeline/dbt/profiles.yml` reads its connection settings from the environment
and stores no secrets:
- the DuckDB file comes from `PROHORI_DUCKDB` (default `.prohori/pipeline/prohori.duckdb`);
- PostgreSQL comes from `PROHORI_POSTGRES_HOST`, `PROHORI_POSTGRES_PORT` and
  `PROHORI_POSTGRES_PASSWORD`, with the stack's defaults.

**DuckDB allows one writer**, so stop a running lite pipeline before you build the models. The
models are written next to the pipeline's tables, in the `staging`, `intermediate` and `marts`
schemas. dbt's anonymous usage statistics are turned off in `dbt_project.yml`.

Query the results:

```sql
SELECT * FROM marts.rule_precision ORDER BY precision;
SELECT * FROM marts.attack_detection;
SELECT * FROM marts.top_source_ips WHERE rank <= 10;
```

## Inputs

| Table | Written by | Holds |
|-------|------------|-------|
| `events`, `alerts`, `incidents`, `dead_letters` | the pipeline's sink | Everything the stream produced (see [PIPELINE.md](PIPELINE.md#the-database)) |
| `labels` | `prohori pipeline load-labels LOG` | The simulator's ground truth: one row per event of a simulated log, with its attack id or null for a benign line |
| `model_evaluations` | `prohori pipeline load-results results/ml_*.json` | Flow-model results: one row per dataset, variant, model, seed and operating point, on the test split |

These tables are in the `main` schema of the DuckDB file and the `raw` schema of PostgreSQL.
Every table has a `stored_at` column, set by the database when the row is first written.

- **Labels.** `load-labels` matches each line of a simulated log to the event it became. It
  uses the same parser, source name and file time as the replay, so the ids are the ones the
  pipeline stored. Pass the same `--year` and other parser options you used for the replay.
- **Model results.** `load-results` stamps each file with its modification time, or with
  `--evaluated-at`. A later evaluation adds new rows, which is what "over time" is built from.
  The nightly retraining job in step 22 will append one evaluation a night.
- **Idempotent.** Loading the same labels or results again adds nothing.

## Models

**Staging** (views): one per input table, renamed and typed.
- Each gets a UTC calendar date: the conversion is explicit, so the session's time zone never
  matters.
- Incidents also get their duration in seconds.
- `stg_alert_events` and `stg_incident_alerts` unnest the event ids of each alert and the alert
  ids of each incident from the JSON records.

**Intermediate:** `int_alert_judgements` judges each alert against the labels, exactly as the
rule evaluation in [SIMULATOR.md](SIMULATOR.md) does. An alert is a true positive when at least
half of its labelled events are attack events, and it is credited to the attack most of them
belong to. Alerts on unlabelled events are not judged.

**Marts** (tables):

| Model | One row per | Columns |
|-------|-------------|---------|
| `daily_attack_counts` | UTC day | events, failed events, source addresses, alerts, high and critical alerts, rules that fired, incidents, high and critical incidents |
| `daily_alerts_by_rule` | day, rule and severity | alerts |
| `top_source_ips` | source address | rank (by alerts, then events), events, failed events, accounts, alerts, incidents, first and last seen |
| `incident_durations` | incident | severity, confidence, score, first and last seen, duration in seconds, alerts, distinct rules |
| `rule_precision` | rule | alerts, judged alerts, true and false positives, precision (null when nothing could be judged) |
| `alert_latency` | alert | `activity_seconds`: from the first event the alert counts to the event that raised it, in log time; `pipeline_seconds`: from its last event being stored to the alert being stored, in wall-clock time |
| `detection_latency` | rule | median and maximum of both latencies |
| `attack_detection` | simulated attack | start and end, attack events, detected or not, first detection, time to detect in seconds, alerts and rules credited |
| `model_performance` | evaluation, dataset, variant, model and operating point | recall, precision, false-positive rate, false alerts per 10,000 flows, PR-AUC and ROC-AUC averaged over seeds, and the change in recall and PR-AUC since the previous evaluation |

`pipeline_seconds` is only as precise as one batch. It is 0 in lite mode, where events and
their alerts are written in the same batch. In the Docker stack it measures the trip through
the broker and the containers.

## Data-quality checks

`dbt build` runs 68 checks; `dbt source freshness` runs the freshness check.

| Kind | Checks |
|------|--------|
| Schema and nulls | Every id is unique and not null, in the inputs and in each model. |
| Accepted values | Severity is `low`, `medium`, `high` or `critical`. The detector kind is `rule` or `model`. The outcome is `success`, `failure` or `unknown`. |
| Ranges | HTTP status is 100 to 599. Score is 0 to 100. An alert counts at least one event. Precision and recall are 0 to 1. Durations and latencies are not negative. No timestamp is more than a day in the future. |
| Duplicates | Each (day, rule, severity), (alert, event), (incident, alert) and (evaluation, model, operating point) appears once. |
| Consistency | Every event an alert lists was stored. Every alert an incident holds was stored. An alert's `event_count` matches its event ids, and an incident's `alert_count` matches its alerts. Nothing ends before it starts. |
| Freshness | `events`, `alerts` and `incidents` got a row within the last day (warning) or week (error), measured on `stored_at`. |
| Dead letters | Any rejected message raises a warning, not a failure: the messages are kept, but they deserve a look. |

Labels that point to an event the warehouse does not hold also raise a warning. That happens
when the labels of a log are loaded but the log was never replayed.

## Results on the simulator

`scripts/build_lite_warehouse.py` builds a warehouse from every scenario's default variant
(seed 1): 7,498 events, 150 alerts and 60 incidents. CI builds the models on that warehouse
and checks that `rule_precision` equals the simulator's own rule evaluation for the same runs,
alert for alert. The models gave:

| Rule | Alerts | True positives | Precision |
|------|-------:|---------------:|----------:|
| PRH-ACCT-001 | 57 | 2 | 0.04 |
| PRH-ADMIN-001 | 2 | 1 | 0.50 |
| PRH-ADMIN-002, AUTH-001, AUTH-002, AUTH-003, SESS-001, SSH-001, WEB-001 to WEB-004 | 91 | 91 | 1.00 |

| Scenario | Detected | Time to detect |
|----------|----------|---------------:|
| account-takeover | yes | 27 s |
| admin-misuse | yes | 252 s |
| credential-stuffing | yes | 22 s |
| injection | yes | 19 s |
| password-spraying | yes | 60 s |
| ssh-bruteforce | yes | 15 s |
| token-reuse | yes | 0 s |
| web-scanning | yes | 2 s |

These are the default variants, which the rules were written against. The held-out variants
in [SIMULATOR.md](SIMULATOR.md) are the honest numbers. PRH-ACCT-001 flags every sensitive
change after a sign-in, including the owner's own, so it is noisy by design.

## Limitations

- **Precision and time to detect need labels**, so they exist only for simulated logs. On real
  logs those columns are empty.
- **Model performance over time** has as many points as evaluations were loaded. Until the
  nightly job runs, that is one per results file.
- **The models are rebuilt from scratch on every build.** They are full tables, not incremental,
  which is fine at this scale. Very large warehouses would need incremental models.
- **One writer on DuckDB.** Build the models while the lite pipeline is stopped. PostgreSQL has
  no such limit.
