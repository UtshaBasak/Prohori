# Prohori (প্রহরী)

<!-- Build and security -->
[![CI](https://github.com/UtshaBasak/Prohori/actions/workflows/ci.yml/badge.svg)](https://github.com/UtshaBasak/Prohori/actions/workflows/ci.yml)
[![CodeQL](https://github.com/UtshaBasak/Prohori/actions/workflows/codeql.yml/badge.svg)](https://github.com/UtshaBasak/Prohori/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/UtshaBasak/Prohori/badge)](https://scorecard.dev/viewer/?uri=github.com/UtshaBasak/Prohori)
[![Secret scanning: gitleaks](https://img.shields.io/badge/secrets-gitleaks-blue?logo=git)](https://github.com/gitleaks/gitleaks)
[![Dependabot](https://img.shields.io/badge/dependabot-enabled-025E8C?logo=dependabot)](https://github.com/UtshaBasak/Prohori/blob/main/.github/dependabot.yml)

<!-- Package -->
![Status: pre-alpha](https://img.shields.io/badge/status-pre--alpha-orange)
![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-3776AB?logo=python&logoColor=white)
![Platforms](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey)
[![License: MIT](https://img.shields.io/github/license/UtshaBasak/Prohori)](LICENSE)

<!-- Tooling and conventions -->
[![uv](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/uv/main/assets/badge/v0.json)](https://github.com/astral-sh/uv)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![Checked with mypy](https://img.shields.io/badge/mypy-strict-2A6DB2)](https://mypy-lang.org/)
[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit)](https://github.com/pre-commit/pre-commit)
[![Conventional Commits](https://img.shields.io/badge/conventional%20commits-1.0.0-FE5196?logo=conventionalcommits&logoColor=white)](https://www.conventionalcommits.org/)
[![Contributor Covenant](https://img.shields.io/badge/contributor%20covenant-2.1-4baaaa)](CODE_OF_CONDUCT.md)

<!-- Repository -->
[![Last commit](https://img.shields.io/github/last-commit/UtshaBasak/Prohori)](https://github.com/UtshaBasak/Prohori/commits/main)
[![Commit activity](https://img.shields.io/github/commit-activity/m/UtshaBasak/Prohori)](https://github.com/UtshaBasak/Prohori/graphs/commit-activity)
[![Open issues](https://img.shields.io/github/issues/UtshaBasak/Prohori)](https://github.com/UtshaBasak/Prohori/issues)
[![Pull requests](https://img.shields.io/github/issues-pr/UtshaBasak/Prohori)](https://github.com/UtshaBasak/Prohori/pulls)
[![Wiki](https://img.shields.io/badge/docs-wiki-blue?logo=github)](https://github.com/UtshaBasak/Prohori/wiki)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)](CONTRIBUTING.md)

**A laptop-sized mini-SOC: from raw logs to detections, enriched incidents and analyst-ready
reports, with honest machine-learning evaluation and a streaming data pipeline.**

*Prohori* is Bengali for "guard".

> **Status: pre-alpha.** Log parsing works today (`prohori parse`); detection, enrichment,
> incidents and reports are being built incrementally. See the [CHANGELOG](CHANGELOG.md).

## Try it

```bash
git clone https://github.com/UtshaBasak/Prohori.git && cd Prohori
uv sync
uv run prohori parse samples/logs/auth.log
uv run prohori parse samples/logs/access.log --format json
uv run prohori rules list
uv run prohori rules test
```

`prohori parse` normalises Linux `auth.log`, nginx/Apache access logs, application security
events (JSON Lines) and any JSON Lines layout via a mapping file. See
[docs/PARSERS.md](docs/PARSERS.md). `prohori rules list` shows the built-in detection rules and
`prohori rules test` runs them against their fixtures; see [docs/RULES.md](docs/RULES.md).

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

See [CONTRIBUTING.md](CONTRIBUTING.md) for conventions, [docs/](docs/) for design documents and the
[project wiki](https://github.com/UtshaBasak/Prohori/wiki) for guides.

## Security

Logs are treated as untrusted input. To report a vulnerability, see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
