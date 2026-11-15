# Contributing to Prohori

Thanks for your interest in Prohori.

## What is welcome

- **Bug reports and ideas:** open an issue with the templates.
- **Security problems:** report them privately as described in [SECURITY.md](SECURITY.md).
- **Questions and feedback:** GitHub Discussions.

**Code contributions from outside the project are not accepted.** Prohori is developed by one
owner, who holds the copyright to all of it and licenses it under the PolyForm Strict License
([LICENSE](LICENSE)); keeping a single copyright holder is what lets the project choose and
change its licence. Pull requests from others are closed without review; describe the change in
an issue instead. The licence does not allow publishing changed copies, and the name and logo
are covered by [TRADEMARKS.md](TRADEMARKS.md).

The rest of this page describes how the owner works on the code.

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
uv run pre-commit run --all-files   # also checks Markdown with markdownlint-cli2
```

All of them must pass; CI runs the same checks on Linux, Windows and macOS. Markdown style rules
are in `.markdownlint-cli2.jsonc` (the VS Code markdownlint extension reads the same file).

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
- **Licence headers:** every Python, SQL and Dockerfile, the report templates and the built-in
  rules start with the SPDX identifier and copyright line; `python scripts/licence_headers.py
  --fix` adds them, and a pre-commit hook and a test check them.
- **Changelog:** add a line under `[Unreleased]` in `CHANGELOG.md`.
- **Decisions:** record significant design decisions in `docs/DECISIONS.md`.
- **Releases:** maintainers follow [docs/RELEASING.md](docs/RELEASING.md).

## Data rules

Never commit secrets, datasets, model binaries or real personal data. Sample files must be
synthetic and use documentation IP ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`,
`2001:db8::/32`).

## Code of conduct

This project follows the [Code of Conduct](CODE_OF_CONDUCT.md).
