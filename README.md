# Prohori (প্রহরী)

[![CI](https://github.com/UtshaBasak/Prohori/actions/workflows/ci.yml/badge.svg)](https://github.com/UtshaBasak/Prohori/actions/workflows/ci.yml)
[![CodeQL](https://github.com/UtshaBasak/Prohori/actions/workflows/codeql.yml/badge.svg)](https://github.com/UtshaBasak/Prohori/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue)

**A laptop-sized mini-SOC: from raw logs to detections, enriched incidents and analyst-ready
reports, with honest machine-learning evaluation and a streaming data pipeline.**

*Prohori* is Bengali for "guard".

> **Status: pre-alpha.** The project skeleton is in place; features are being built
> incrementally. Nothing below the "Planned features" heading works yet.

## Planned features

| Area | What it does |
|------|--------------|
| Parsing | Linux `auth.log`, nginx/Apache access logs, app security events and generic JSON lines into one typed event schema |
| Detection | Readable YAML rules with thresholds, time windows and sequences, each with test fixtures |
| Enrichment | IP geolocation and reputation with caching, rate limiting and a fully offline mode |
| Incidents | Alert grouping, transparent points-based scoring and MITRE ATT&CK mapping |
| Reports | Markdown, self-contained HTML and JSON, with redaction |
| Simulation | Deterministic, labelled attack scenarios written as log files (no network activity) |
| Machine learning | Leakage-controlled intrusion detection on public flow datasets and log-derived features |
| Pipeline | Kafka-compatible streaming, a warehouse with dbt models, scheduled jobs and a dashboard |
| LLM analyst | Optional, opt-in, redacted incident explanations with output validation |

Prohori only **recommends** actions. It never blocks, disables or touches remote systems.

## Development

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/UtshaBasak/Prohori.git
cd Prohori
uv sync                        # create .venv with the package and dev tools
uv run pre-commit install      # optional: run checks on every commit

uv run prohori --version       # CLI smoke test
uv run ruff check .            # lint
uv run ruff format --check .   # formatting
uv run mypy                    # strict type check
uv run pytest --cov            # tests with coverage
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for conventions and [docs/](docs/) for design documents.

## Security

Logs are treated as untrusted input. To report a vulnerability, see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
