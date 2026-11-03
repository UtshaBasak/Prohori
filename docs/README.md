# Documentation

| Document | Contents |
| ---------- | ---------- |
| [CLI.md](CLI.md) | Command-line reference: commands, shared options, formats and exit codes |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Components, data flow and run modes |
| [examples/](examples/) | Sample incident reports (Markdown, HTML, redacted) |
| [DECISIONS.md](DECISIONS.md) | Architecture decision log |
| [RELEASING.md](RELEASING.md) | Release process: tag, TestPyPI, approval, PyPI, GitHub release |
| [SCHEMA.md](SCHEMA.md) | Event, Alert and Incident schema |
| [PARSERS.md](PARSERS.md) | Parser framework and supported log formats |
| [RULES.md](RULES.md) | Detection rule format and authoring guide |
| [ENRICHMENT.md](ENRICHMENT.md) | IP enrichment providers, privacy, cache and rate limits |
| [INCIDENTS.md](INCIDENTS.md) | Incident grouping, scoring table, confidence and limitations |
| [REPORTS.md](REPORTS.md) | Report formats and sections, redaction and output safety |
| [SIMULATOR.md](SIMULATOR.md) | Attack scenarios, labels, and rule precision and recall |
| [DATASETS.md](DATASETS.md) | ML datasets: sources, licences, download, leakage controls, measured effects |
| [ANOMALY.md](ANOMALY.md) | Log anomaly detection: features, detectors, comparison with the rules |
| [MODEL_CARD.md](MODEL_CARD.md) | Flow detectors: intended use, evaluation method, results, cross-dataset test, failure cases |
| [PIPELINE.md](PIPELINE.md) | Streaming pipeline: lite mode and the Docker stack, topics, delivery guarantees, dead letters, tailing |
| [WAREHOUSE.md](WAREHOUSE.md) | dbt models, data-quality checks, labels and model results |
| [DASHBOARD.md](DASHBOARD.md) | The Grafana dashboards: panels, access, changing a dashboard |
| [ORCHESTRATION.md](ORCHESTRATION.md) | The Airflow jobs: backfill, data quality, nightly evaluation, digest, enrichment refresh |
| [LLM_ANALYST.md](LLM_ANALYST.md) | `prohori explain` and `ask`: what is sent, redaction, sources, injection defences, evaluation |
| [PERFORMANCE.md](PERFORMANCE.md) | Throughput and peak memory on logs of a million lines |
| [THREAT_MODEL.md](THREAT_MODEL.md) | Assets, trust boundaries, threats, controls and residual risks |
| [LICENSES.md](LICENSES.md) | Terms of third-party data and services |
