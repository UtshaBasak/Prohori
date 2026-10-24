# Contributing to Prohori

Thanks for your interest in improving Prohori.

## Development setup

```bash
uv sync
uv run pre-commit install
```

## Before opening a pull request

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run pytest --cov
```

All four must pass; CI runs the same checks on Linux and Windows.

## Conventions

- **Branches:** `step-NN-short-name` for roadmap work, `fix/...` or `feat/...` otherwise.
- **Commits:** [Conventional Commits](https://www.conventionalcommits.org/)
  (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`, `ci:`, `build:`).
- **Code:** fully typed (`mypy --strict`), formatted and linted with Ruff, `pathlib` for paths,
  timezone-aware UTC datetimes.
- **Tests:** every behaviour change comes with tests. Tests must not use the network and must be
  deterministic (fixed seeds).
- **Dependencies:** keep the base install small; heavy dependencies go behind the `ml`,
  `pipeline` or `llm` extras.
- **Changelog:** add a line under `[Unreleased]` in `CHANGELOG.md`.
- **Decisions:** record significant design decisions in `docs/DECISIONS.md`.

## Data rules

Never commit secrets, datasets, model binaries or real personal data. Sample files must be
synthetic and use documentation IP ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`,
`2001:db8::/32`).

## Code of conduct

This project follows the [Code of Conduct](CODE_OF_CONDUCT.md).
