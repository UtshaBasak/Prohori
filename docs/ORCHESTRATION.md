# Scheduled jobs (Airflow)

The Docker stack can also run [Apache Airflow](https://airflow.apache.org/) with five DAGs that
keep the warehouse and models current. Airflow is a separate compose profile, so it starts only
when you ask for it:

```bash
uv run prohori pipeline up --orchestration
# Airflow: http://127.0.0.1:18080   dashboards: http://127.0.0.1:13000
uv run prohori pipeline down                  # stops Airflow too
```

## Contents

- [The jobs](#the-jobs)
- [Running a job by hand](#running-a-job-by-hand)
- [Reading the output](#reading-the-output)
- [How it is set up](#how-it-is-set-up)
- [Tests](#tests)
- [Limitations](#limitations)

## The jobs

| DAG | When | What it does |
| ----- | ------ | -------------- |
| `prohori_backfill` | By hand | Simulates the eight scenarios one day apart, replays them through the broker, loads their labels, waits until the pipeline has stored everything and builds the dbt marts |
| `prohori_data_quality` | Hourly | `dbt build` (the marts behind the Detection quality dashboard, with the 68 checks), then `dbt source freshness` on the events |
| `prohori_nightly_evaluation` | 02:00 UTC | Retrains the cleaned UNSW-NB15 flow models with one seed, loads the results into the warehouse and **fails if recall dropped** below `min_recall` |
| `prohori_incident_digest` | 06:00 UTC | Writes a digest of the last 24 hours (incidents by severity, the top incidents, alerts per rule, dead letters) as Markdown and JSON |
| `prohori_enrichment_refresh` | 03:30 UTC | Removes expired answers from the incident stage's enrichment cache and looks up again the public addresses seen in the last week |

Each task runs a Prohori command, so the same jobs work without Airflow:

| Job | Command |
| ----- | --------- |
| Digest | `prohori pipeline digest --hours 24 [--out FILE] [-f json]` |
| Recall gate | `prohori pipeline check-recall results/ml_unsw-nb15.json --min-recall 0.75` |
| Enrichment refresh | `prohori pipeline refresh-enrichment --days 7 [--online]` |
| Marts and checks | `uv run dbt build --project-dir pipeline/dbt --profiles-dir pipeline/dbt --target postgres` |

They read the stack's warehouse with `--postgres` (or `PROHORI_POSTGRES_DSN`), or the lite-mode
DuckDB file by default. See [CLI.md](CLI.md#prohori-pipeline).

**The recall gate.** `check-recall` averages the test-split recall of one model, variant and
operating point over the seeds in a results file. It exits 1 below the minimum. The default
checks the gradient-boosting model on the cleaned data at a 1 % false-positive rate, with a
minimum of 0.75. The committed results measure 0.8175 on average over three seeds, and the
nightly job's seed 0 measured 0.8199. The results are loaded before the gate runs, so a drop
still shows on the dashboard.

**Without the dataset** (it is not in the repository; see [DATASETS.md](DATASETS.md)), the
nightly evaluation skips its tasks instead of failing. The datasets are mounted read-only from
the repository's `data/` folder and are never copied into an image.

**Freshness.** The check covers the `events` source: it warns when no event has arrived for a
day and fails after seven. An empty warehouse skips it, because nothing has been published yet.

**Enrichment stays offline** unless you set `ABUSEIPDB_API_KEY` or `VIRUSTOTAL_API_KEY` in the
environment of `prohori pipeline up`. Then the refresh looks addresses up online, within the
same daily limits as `prohori enrich`. Private, reserved and documentation addresses are never
looked up, which covers every simulated address.

## Running a job by hand

Open <http://127.0.0.1:18080>, pick a DAG and choose *Trigger*. For the backfill you can set the
first scenario's start, as a UTC time in exactly this form: `2026-10-26T06:00:00Z` (leave it empty
for eight days ago), and the seed. From a terminal:

```bash
docker compose -p prohori -f pipeline/docker-compose.yml --profile orchestration exec airflow \
    airflow dags trigger prohori_backfill --conf '{"start": "2026-10-20T06:00:00Z"}'
```

The backfill is meant for an empty stack. It writes older dates than events already stored, and
the pipeline has [one timeline](PIPELINE.md#limitations), so on a busy stack its events arrive
late.

When Airflow first sees a scheduled DAG it runs it once for the latest period, so a fresh stack
builds the marts, writes a digest and runs the evaluation within a minute of starting.

## Reading the output

Jobs write to the `airflow-output` volume:

```text
/opt/prohori-output/
├── digests/incidents-YYYY-MM-DD.md and .json
├── results/ml_unsw-nb15-<time>.json
└── models/unsw-nb15/              the retrained models (pickles; only load your own)
```

Copy them out with:

```bash
docker compose -p prohori -f pipeline/docker-compose.yml --profile orchestration \
    cp airflow:/opt/prohori-output/digests ./digests
```

The marts the jobs build show up in the Detection quality dashboard ([DASHBOARD.md](DASHBOARD.md)).

## How it is set up

- **Image:** `prohori-airflow:local`, built from `pipeline/airflow/Dockerfile` on top of
  `apache/airflow:slim-3.3.2-python3.13`, pinned by digest. Airflow 3.3.2 was released on
  2026-09-17. Prohori and dbt live in their own environment (`/opt/prohori`), with the versions
  in `uv.lock`, so Airflow's dependencies and Prohori's never mix. The DAGs and the dbt project
  are mounted read-only, so changing a DAG needs no rebuild.
- **One container** runs the scheduler, the DAG processor, the triggerer and the API server
  (`airflow standalone`), with the LocalExecutor. Its memory limit is 3 GB. It used about
  1.2 GB idle and peaked at 1.84 GB while retraining.
- **Airflow's own state** is in a separate `airflow` database on the stack's PostgreSQL, owned
  by an `airflow` role. The `warehouse-init` service creates both on every start. The password
  comes from `PROHORI_AIRFLOW_DB_PASSWORD` (local-only default `airflow`).
- **Access:** 127.0.0.1:18080 only (`PROHORI_AIRFLOW_PORT` moves it). Anyone who can reach that
  address is an admin without a login, as with the broker. Do not expose the port.
- **No secrets in files:** the key that signs Airflow's internal tokens is generated when the
  container starts and is never written down. Usage data collection is off.
- **Shared volumes:** `enrichment` is the enrichment cache, mounted by both the incident stage and
  Airflow. Both run as uid 10001, with group 0 for Airflow. `airflow-output` holds what the jobs
  write.

| Profile | Services | Memory limits |
| --------- | ---------- | --------------: |
| default | Redpanda, PostgreSQL, four stages, Grafana, warehouse-init | about 3.9 GB |
| `orchestration` | the above and Airflow | about 6.9 GB |

## Tests

- **DAG integrity** (`tests/dags/test_dags.py`, the `Airflow DAGs` job in CI on Linux):
  - every DAG imports with Airflow 3.3.2, installed in its own environment with Airflow's
    constraints;
  - no DAG has a cycle;
  - schedules, `catchup`, `max_active_runs`, tags and the shape of each DAG are as described
    here.

  It needs no Airflow on Windows: the module skips itself without it.
- **Without Airflow** (`tests/unit/pipeline/test_dag_files.py`), the DAG files are checked to
  call only `prohori pipeline` commands that exist, to backfill every scenario, and to use the
  paths the compose file mounts. The digest, recall gate and refresh have their own unit tests.
- **In the stack** (`tests/integration/test_airflow_stack.py`, the `Airflow in the Docker stack`
  job): it starts the stack with the orchestration profile from empty volumes and runs every DAG
  through the scheduler. It checks the data each job leaves behind: labels for every event,
  eight attacks in `marts.attack_detection`, and a digest that counts every event.

## Limitations

- **Local use only:** no login, default passwords, one container.
- **One seed, one dataset** in the nightly evaluation, to keep it to seconds. The full
  evaluation (three seeds, both datasets) stays a manual `python -m prohori.ml.train` run.
- **Model files** written by the nightly job are pickles in the output volume. Prohori never
  loads them on its own.
- **Linux containers only.** Airflow does not run on Windows; the stack runs it in Docker.
