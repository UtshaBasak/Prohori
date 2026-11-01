# Dashboards

The Docker stack includes [Grafana](https://grafana.com/oss/grafana/) with three dashboards and
a PostgreSQL data source. All of it is provisioned from files in the repository. There is
nothing to click through, no login and no import:

```bash
uv run prohori pipeline up
uv run prohori pipeline replay logs/web-scanning.log --bootstrap 127.0.0.1:19092
# open http://127.0.0.1:13000
```

The **Overview** opens as the home page. The other two dashboards are in the **Prohori** folder
and in the links at the top of each dashboard.

## Contents

- [Overview](#overview)
- [Detection quality](#detection-quality)
- [Pipeline health](#pipeline-health)
- [How it is set up](#how-it-is-set-up)
- [Time range](#time-range)
- [Changing a dashboard](#changing-a-dashboard)
- [Limitations](#limitations)

## Overview

![Overview dashboard: events, alerts and incidents over a week of simulated attacks](images/dashboard-overview.png)

What the pipeline saw in the selected time range:
- totals for events, failed events, alerts, incidents, and incidents of high or critical
  severity;
- incidents and alerts per hour by severity, and events per hour by outcome;
- hits per rule;
- the source addresses with the most failed events;
- the latest incidents.

These panels read the warehouse's raw tables (`raw.events`, `raw.alerts`, `raw.incidents`), so
they fill as soon as the sink stores rows. Event panels use the event's own time; alert and
incident panels use the time of their first or last alert. The screenshot shows the eight
simulator scenarios replayed one day apart.

## Detection quality

![Detection quality dashboard: rule precision, attack detection, detection latency and top sources](images/dashboard-detection-quality.png)

How good the detection is, from the dbt marts ([WAREHOUSE.md](WAREHOUSE.md)):

| Panel | Mart |
|-------|------|
| Rule precision: judged alerts, true and false positives per rule | `marts.rule_precision` |
| Attack detection: whether and how fast each simulated attack was caught | `marts.attack_detection` |
| Detection latency: how long activity ran before a rule fired, and how long the pipeline took | `marts.detection_latency` |
| Top source addresses, ranked by alerts | `marts.top_source_ips` |
| Flow models: the latest evaluation and recall over time | `marts.model_performance` |
| Daily summary | `marts.daily_attack_counts` |
| Incident durations (histogram) | `marts.incident_durations` |

The marts are not built by the stack itself. Until they are, these panels show
`relation "marts..." does not exist`. To build them on the stack's database:

```bash
uv sync --group dbt
uv run prohori pipeline load-labels logs/web-scanning.log --postgres postgresql://prohori:prohori@127.0.0.1:15432/prohori
uv run prohori pipeline load-results results/ml_cicids2017.json --postgres postgresql://prohori:prohori@127.0.0.1:15432/prohori
uv run dbt build --project-dir pipeline/dbt --profiles-dir pipeline/dbt --target postgres
```

Rule precision and attack detection need the simulator's labels (`load-labels`). The flow-model
panels need evaluation results (`load-results`). On real logs, precision stays empty. Step 22's
scheduled jobs will run the dbt build regularly.

## Pipeline health

![Pipeline health dashboard: time since the last stored event, rows stored per minute, tables and dead letters](images/dashboard-pipeline-health.png)

Whether the pipeline is keeping up, by wall-clock time (`stored_at`), not event time:
- time since the sink last stored an event;
- events stored and dead letters in the range, and dead letters of all time;
- rows stored per minute and table;
- each table's row count and its latest row;
- dead letters grouped by stage, topic and reason.

It refreshes every 30 seconds over the last 6 hours. `prohori pipeline status` shows the
containers' own health.

## How it is set up

```
pipeline/
├── docker-compose.yml               grafana and warehouse-init services
├── postgres/warehouse-init.sql      schemas and Grafana's read-only role
└── grafana/
    ├── provisioning/datasources/    the PostgreSQL data source
    ├── provisioning/dashboards/     where the dashboards come from
    └── dashboards/*.json            the three dashboards
```

- **Image:** `grafana/grafana:13.2.5` (Alpine), pinned by digest, with a 512 MB memory limit.
  Measured use is about 250 MB with the dashboards open.
- **Port:** 127.0.0.1:13000 only. Set `PROHORI_GRAFANA_PORT` to change it.
- **Access:** anonymous visitors get the Viewer role, so the dashboards open without a login. The
  `admin` account (password from `PROHORI_GRAFANA_PASSWORD`, local-only default `prohori`) can
  explore and edit. Edits to provisioned dashboards cannot be saved; see below.
- **Database access:** Grafana connects as its own `grafana` role, which can only `SELECT` from
  the `raw` and `marts` schemas. The `warehouse-init` service creates the role on every `up` and
  grants it read access to tables created later, so the access survives each dbt rebuild of the
  marts. The role's password comes from `PROHORI_GRAFANA_DB_PASSWORD` (local-only default
  `grafana`). The service's statements are idempotent, so it also upgrades a database created by
  an earlier version of the stack.
- **No calls home:** usage reporting, update checks, the news feed, feedback links and plugin
  pre-installation are all turned off.
- **No data volume:** everything Grafana shows comes from the provisioning files and the
  warehouse, so its container starts clean each time.

## Time range

The Overview and Detection quality dashboards open on the **last 30 days**, in UTC. The
simulator dates its logs in late October 2026 unless you pass `--set start=...`, so for older
logs widen the range with the time picker. Pipeline health opens on the last 6 hours.

## Changing a dashboard

The JSON files in `pipeline/grafana/dashboards/` are the source. Grafana re-reads them every 30
seconds, so you can:
1. Edit a panel in Grafana as `admin`. It will say the dashboard cannot be saved.
2. Copy the JSON through *Export → Export as JSON*.
3. Replace the file and commit it.

`tests/unit/pipeline/test_dashboards.py` checks every dashboard:
- the JSON is valid and every uid is unique;
- each panel uses the provisioned data source;
- each query only reads tables that exist in `raw` or in the dbt marts, and only reads.

The Docker smoke test then runs every panel's query through Grafana's own API. After a replay,
with no dbt run, the Overview and Pipeline health panels must all return rows. After
`dbt build`, every Detection quality panel must run without error.

## Limitations

- **The marts need a dbt build.** The Detection quality dashboard is empty until one has run
  (see above). The live panels use the raw tables so the dashboard works without it.
- **Local use only.** Anonymous viewing and default passwords are meant for one machine. Before
  exposing Grafana anywhere else, turn off anonymous access and set real passwords.
- **Grafana's licence** is AGPL-3.0. The stack runs the official image unmodified
  ([LICENSES.md](LICENSES.md)).
- **No alerting.** Grafana alerting is not configured; Prohori's own alerts are the panels'
  subject.
