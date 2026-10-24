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

---

## ADR-0006: Shape and invariants of the common schema

- **Date:** 2026-10-25
- **Status:** Accepted

**Context.** Every component consumes the event schema, and all of its content comes from
untrusted logs. Rules refer to fields by dotted names such as `event.action`.

**Decision.**
- **Nested models with a dotted-path accessor.** Events are nested Pydantic models that mirror
  the JSON shape (`event`, `source`, `user`, `http`); `prohori.schema.get_field(event, "event.action")`
  and `FIELD_PATHS` give flat dotted access for rules and features. One mapping, derived from the
  models, so the two cannot drift apart.
- **Naive datetimes are rejected**, aware ones converted to UTC. Guessing a timezone silently would
  corrupt time windows; parsers own that decision.
- **Untrusted text is truncated, not rejected**, at fixed limits (raw line 8,192 characters,
  free text 1,024, short identifiers 256). Rejecting would let an attacker hide events by sending
  oversized values. Structural fields (action names, IP addresses, HTTP status) are validated
  strictly.
- **Models are frozen and forbid unknown fields**, so events cannot be altered after parsing and
  typos in field names fail loudly.
- **Deterministic ids** (`evt-`/`alr-` + truncated SHA-256 of content) enable idempotent pipeline
  writes and reproducible reports. Same-second duplicate lines are separated by a parser-supplied
  discriminator.
- **One severity scale** (`low` < `medium` < `high` < `critical`) for events, alerts and incidents;
  sources use the first three.

**Consequences.** Parsers must construct timezone-aware timestamps and choose discriminators for
duplicate lines. Changes to field names are breaking and require updating `docs/SCHEMA.md`.

---

## ADR-0007: Parser framework and syslog time handling

- **Date:** 2026-10-25
- **Status:** Accepted

**Context.** Parsers read untrusted, sometimes huge or corrupt files. Traditional syslog
timestamps carry neither a year nor a timezone, and identical lines can occur within one second.

**Decision.**
- **Lines are read in binary with a hard length limit** (16,384 characters). Oversized lines are
  errors and are skipped in chunks, so neither memory nor regular-expression work depends on the
  input. Input is decoded as UTF-8 with replacement.
- **Three outcomes per line:** event, skipped (well-formed but irrelevant) or error (malformed),
  plus blank. Only errors indicate a problem with the input, so they are reported separately.
- **Sanitising** removes control characters, ANSI escapes and invisible formatting characters
  (bidirectional overrides, zero-width characters) that could disguise text in reports.
- **Default timezone is UTC**, not the machine's local zone: logs are usually analysed on a
  different machine from the one that wrote them, and a silent local-time guess would be wrong in
  a way that is hard to notice. Users pass `timezone` for RFC 3164 logs.
- **Year inference:** an explicit `year` is the year of the first line; otherwise the first line
  is placed no later than one day after the file's modification time. A month drop of six or more
  is a New Year rollover.
- **Event ids include `<input name>:<line number>`** so duplicates stay distinct and re-parsing is
  deterministic.
- **Fuzzing:** Hypothesis property tests run on every platform; an Atheris harness adds
  coverage-guided fuzzing in a Linux CI job. Atheris is not a project dependency because it has no
  Windows wheels.
- **`tzdata`** is a Windows-only dependency, because Windows has no system IANA timezone database.

**Consequences.** Archived logs need an explicit `year`. Ids change if a file is renamed.
