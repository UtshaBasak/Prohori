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

---

## ADR-0008: Parser set, format detection and the `parse` command

- **Date:** 2026-10-25
- **Status:** Accepted

**Context.** The first release needs web-server, application and arbitrary JSON logs in
addition to `auth.log`, plus a command that shows what was parsed and what failed.

**Decision.**
- **Query strings go to `extra.query`**, not `http.path`, by default. Paths then group cleanly
  for scanning rules, while injection rules can still inspect the query. `--keep-query` restores
  the full target.
- **Application events derive a missing category from the action prefix**, so producers can
  omit it, while unknown prefixes remain errors rather than guesses.
- **Arbitrary JSON uses an explicit YAML mapping** validated by a Pydantic model before any input
  is read. There is no guessing of field meanings.
- **Format detection votes over the first 20 non-blank lines** and never selects `generic_json`
  automatically, because that would need a mapping. Detection is documented as a convenience;
  scripts should pass `--parser`.
- **Exit codes:** `0` success, `1` when no events were produced and at least one line was
  malformed, `2` for usage and input errors (Typer's own usage code). Partial failures exit `0`
  and are visible in the summary.
- **JSON output** writes events to standard output (JSON Lines) and the summary to standard error,
  so output can be piped into other tools.
- **Terminal output never interprets log content:** table cells are literal text, so log lines
  cannot inject Rich markup.
- **`extra` string values are truncated** (1,024 characters) like other untrusted text, because
  parsers copy log fields such as query strings into it.

**Consequences.** Detection may need `--parser` for mixed or unusual files. The `extra` value
type changed from plain scalars to bounded scalars (no effect on valid data).

---

## ADR-0009: Rule format, matching semantics and regex safety

- **Date:** 2026-10-25
- **Status:** Accepted

**Context.** Rules must be readable, safe to load from untrusted files, and evaluated against
attacker-controlled log fields without risk of hangs.

**Decision.**
- **Sigma-inspired, not Sigma-compatible.** Selections, `|modifiers` and a boolean condition follow
  Sigma conventions (including case-insensitive string matching and `1 of x*`), plus Prohori's own
  `aggregate` and `sequence` blocks. `aggregate` and `sequence` appear in the condition only as
  top-level `and` terms, so the stateless filter and the stateful part are always separable.
  Their block schema is validated now; the stateful engine (next step) may refine it.
- **No `eval`.** Conditions use a recursive-descent parser with length and depth limits.
- **Wildcards without regular expressions.** `*` and `?` use a two-pointer matcher
  (O(pattern x text)); translating them to `.*` would backtrack polynomially on long values.
- **Rule regexes run on RE2, not `re`.** A first version used a static check over `re._parser`
  output to reject backtracking patterns. Measurements showed that this was not enough: patterns it
  accepted (`.*.*x`, `\w*\w*\w*x`) ran for more than five minutes on one 8 KiB field with
  `re.search`. RE2 (`google-re2`, imported as `re2`) matches in linear time by construction; the
  same hostile patterns take about 0.1 ms. It rejects backreferences, look-around, atomic groups
  and possessive quantifiers at compile time. Patterns are additionally capped at 256 characters
  and 1 MiB of compiled program. This adds one compiled dependency (BSD-licensed) to the core
  install; wheels exist for Windows, Linux and macOS on Python 3.11-3.14. Its import name `re2`
  collides with other PyPI projects, so the dependency is pinned by distribution name.
- **Backslash escapes follow Sigma:** `\*`, `\?` and `\\` are escapes; every other backslash is
  literal, so Windows paths (`C:\Windows\System32`) work as written.
- **Errors carry lines.** The loader composes the YAML node tree, maps every document path to its
  line, and maps both Pydantic errors and compiler errors back to it.
- **YAML anchors and aliases are rejected.** Safe loading still expands alias graphs; validation
  and serialisation would walk the expanded document.
- **Unused selections are errors**, because they are almost always typos.
- **Validation lives in `rules/compiler.py` and `rules/loader.py`** rather than a separate
  `validator.py` (as first planned): compiling is validating, so one pass produces both.
- **Test fixtures are split into `valid/` and `invalid/`** so the upcoming `rules test` command can
  run against valid rules only.

**Consequences.** Regex authors cannot use look-around or backreferences, and `\w`/`\d`/`\s`
are ASCII-only. A literal backslash before a wildcard must be written `\\*`.

---

## ADR-0010: Rule evaluation semantics and the rule test harness

- **Date:** 2026-10-26
- **Status:** Accepted

**Context.** Thresholds and sequences need precise, deterministic semantics: later steps (built-in
rules, incidents, the streaming pipeline) depend on them, and logs arrive out of order, with
duplicate timestamps and sometimes with bogus times.

**Decision.**
- **One total order** (timestamp, then event id) enforced by a reorder buffer with configurable
  `lateness`; events are released only once strictly older than `watermark - lateness`, so ties at
  the watermark are never split. Any arrival order within the bound gives identical alerts
  (property-tested).
- **Late events are dropped and counted**, never silently lost.
- **Future timestamps** beyond `reference_time + 1 day` are dropped and counted. The reference time
  is injected (the engine never reads the clock), keeping tests deterministic; archived logs can
  omit it.
- **Windows:** sliding windows exclude an event exactly `window` old; tumbling windows align to the
  Unix epoch.
- **Re-alerting:** a group's state is cleared when it fires, so one burst gives one alert and a
  continuing attack gives one alert per further threshold's worth of events, rather than one alert
  per event.
- **Sequences:** a sliding first step, a deadline of `start + within` for later steps, restart on
  expiry, and the current step winning when an event matches several.
- **Bounded state:** caps on the reorder buffer, groups per rule and events per ratio group, with
  counters for every eviction or drop.
- **Process-one-event-at-a-time API** with an idempotent `flush()`, so the streaming consumers can
  reuse the engine unchanged.
- **Rule fixtures** live next to each rule as `<rule>.tests.yml` (skipped by rule discovery), are
  loaded with the same safety limits, and must contain positive and negative cases. Cases can use a
  compact event timeline or real log lines through a parser, so the parsers are exercised too.
- **Alert scores follow severity** for now; incident scoring adds context later.

**Consequences.** Rules evaluated without lateness treat equal timestamps as simultaneous and
order them by event id. Alerts list at most 100 event ids.
