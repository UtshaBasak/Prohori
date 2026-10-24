# Decision Log

Significant design decisions, newest last. Each entry records the context, the decision and its
consequences. Superseded decisions are kept and marked as such.

---

## ADR-0001: Package name and licence

- **Date:** 2026-10-25
- **Status:** Accepted

**Context.** The distribution needs a name that is free on PyPI and matches the repository.

**Decision.** Publish as `prohori` (checked free on PyPI on 2026-10-25; `prohori-soc` is the
fallback if it is taken before the first release). Licence: MIT. Repository:
`github.com/UtshaBasak/Prohori`.

**Consequences.** The name is not reserved until the first upload; the release step re-checks it.

---

## ADR-0002: Supported Python versions

- **Date:** 2026-10-25
- **Status:** Accepted

**Context.** Python 3.14 is the newest stable release. The scientific and streaming dependencies
planned for later (scikit-learn, pyarrow, a Kafka client) need wheels on Windows and Linux.

**Decision.** Support Python **3.11 to 3.14** (`requires-python = ">=3.11"`). CI tests all four on
Linux and Windows. Development defaults to 3.13. Type checks target 3.11 syntax.

**Consequences.** Each step that adds a heavy dependency must confirm wheels exist for the whole
range on both platforms; if not, the dependency stays behind an extra and the gap is documented.

---

## ADR-0003: Build and environment tooling

- **Date:** 2026-10-25
- **Status:** Accepted

**Context.** The project needs reproducible environments on Windows and Linux, a standard build
backend and fast CI.

**Decision.**
- **uv** manages environments and the lock file (`uv.lock`, committed for reproducible CI).
- **Hatchling** is the build backend; the version lives in `src/prohori/version.py`.
- Development tools are a PEP 735 **dependency group** (`[dependency-groups] dev`) rather than a
  `dev` extra, so they are never published as installable package metadata. `uv sync` installs
  them by default. The user-facing extras are `ml`, `pipeline`, `llm` and `all`.
- **Ruff** (lint and format), **mypy `--strict`** over `src/` and `tests/`, **pytest** with
  coverage (`fail_under = 85`), **pre-commit** with gitleaks for secret scanning.
- The `Makefile` is a convenience wrapper only; every target is a plain `uv run ...` command, so
  nothing depends on `make` (which is not available on Windows by default).

**Consequences.** Contributors need uv. Plain `pip install -e .` still works for the package itself.

---

## ADR-0004: Dependencies are added by the step that needs them

- **Date:** 2026-10-25
- **Status:** Accepted

**Context.** The skeleton must install and pass checks without implementing features.

**Decision.** The base install currently depends only on `typer` (which brings `rich`). Extras
are declared but empty. Each roadmap step adds the dependencies it needs (for example `pydantic`
with the schema, `pyyaml` with the rule loader), after verifying current versions and
Windows/Python-version compatibility.

**Consequences.** `pyproject.toml` and `uv.lock` change in most feature steps; reviewers can see
exactly which step introduced each dependency.

---

## ADR-0005: Delivery roadmap structure

- **Date:** 2026-10-25
- **Status:** Accepted

**Context.** The initial outline had 17 phases, several of which bundle more work than can be
built, tested and reviewed in one session.

**Decision.** The roadmap is split into smaller steps, with these deliberate changes:

1. **Schema and parsers are split** into the event schema, the parser framework with the
   `auth.log` parser (year inference and rollover are the riskiest part), and the remaining
   parsers.
2. **The rule engine is split** into the rule format/loader/validator with field matching, and the
   stateful engine (windows, aggregations, sequences, lateness) with the test harness.
3. **Built-in rules are split into two batches** (identity/session/account rules, then
   web/SSH/abuse/admin rules) because each rule needs fixtures, a runbook and a verified ATT&CK
   mapping.
4. **Incidents and reports are separate steps.**
5. **The log simulator moves before the first release.** `prohori demo` is specified to generate a
   simulated scenario, and the simulator provides ground truth for rule precision/recall, so the
   v0.1.0 demo depends on it.
6. **ML Track A is split** into data preparation with leakage controls, modelling and metrics, and
   the cross-dataset test with `prohori score`.
7. **The streaming pipeline starts with lite mode** (file-based, no Docker) so it runs in CI, then
   adds the Docker stack; the warehouse transformations and the dashboard are separate steps.
8. **The LLM analyst is split** into provider/redaction, retrieval/safeguards, and evaluation.

**Consequences.** More, smaller steps; release points are unchanged (v0.1.0 after the batch core,
v0.2.0 after ML, v0.3.0 after the pipeline, v1.0.0 after final polish).
