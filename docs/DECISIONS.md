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
  omit it. Without it, a bogus future timestamp still lets in-order events through but disables
  out-of-order tolerance for the rest of the input.
- **Fixtures never depend on today's date:** `auth_log` log cases default `year` to the fixture's
  `start`.
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

---

## ADR-0011: Packaged runbooks and a pinned, verified ATT&CK list

- **Date:** 2026-10-26
- **Status:** Accepted

**Context.** Built-in rules link runbooks that incident building and reports will show, so the
runbooks must be available in an installed package, not only in a source checkout. ATT&CK ids and
tactics change between releases (v20 has Stealth and Defense Impairment in place of Defense
Evasion), so unverified tags would silently go stale.

**Decision.**
- Runbooks live in `src/prohori/runbooks/` and ship in the wheel. A built-in rule's
  `response: runbooks/<name>.md` resolves against the `prohori` package. Every runbook uses the
  same sections so later steps can extract recommended actions mechanically.
- The ATT&CK tactics and techniques that rules may use are checked into
  `prohori.rules.attack`, pinned to Enterprise ATT&CK v20.0 with the STIX bundle URL and SHA-256.
  Tests check rules against this list offline; `scripts/verify_attack.py` re-checks the list
  against the official bundle by hand. The test suite never needs network access.
- Built-in rule fixtures live next to the rules and must include at least one case with real log
  lines through a parser, so field mapping mistakes surface in tests.

**Consequences.** Moving to a new ATT&CK release means updating the pin and running the script.
Custom rules may use any well-formed ATT&CK tag; only built-in rules are held to the verified list.

---

## ADR-0012: `prohori detect` behaviour and the second rule batch

- **Date:** 2026-10-26
- **Status:** Accepted

**Context.** `detect` is the first command that turns logs into alerts, so its exit codes, rule
selection and handling of untrusted input set the pattern for `triage` and the streaming
consumers. The second rule batch needed decisions where the plan's wording did not fit the data.

**Decision.**
- **Exit codes:** `0` no alerts, `3` alerts found, `1` unparseable input or an invalid rule file,
  `2` usage. Alerts get their own code so scripts can tell "found something" from "failed";
  `--exit-zero` turns it off for pipelines that only want the output.
- **Rule selection:** built-in rules always run unless `--no-builtin`; `--rules` adds rule files.
  Any invalid rule stops the run before parsing: a partial rule set would silently miss
  detections.
- **Time handling:** default `--lateness` of 5 minutes, and the current time as the reference for
  dropping events dated more than a day in the future. Both counters are shown when non-zero.
- **`urldecode` modifier** instead of decoding in the parser: the stored path and query stay
  exactly as logged (evidence), while rules can still match encoded payloads, including double
  encoding (bounded to three rounds).
- **PRH-WEB-004 (sensitive-file probes) split from PRH-WEB-001:** volume of 404s and a handful of
  `/.env`-style probes are different signals with different thresholds; one rule could not express
  both. The built-in set grows from the planned 13 to 14 rules.
- **Thresholded web rules:** injection and probe rules need several requests from one IP, so a
  scanner produces one alert per burst rather than one per request; single attempts are left to
  incident context.
- **SSH-001 counts each MaxAuthTries connection once** by matching only the disconnect line, since
  sshd logs two lines per such connection.
- **Admin actions at unusual hours deferred:** rules have no time-of-day matching yet, and the
  right hours depend on the deployment's timezone. PRH-ADMIN-001 covers role grants only.

**Consequences.** Golden files pin the JSON alert output for the sample logs; intended changes
regenerate them with `PROHORI_UPDATE_GOLDEN=1`.

---

## ADR-0013: Enrichment design

- **Date:** 2026-10-26
- **Status:** Accepted

**Context.** Enrichment sends data to third parties, depends on free tiers with strict limits and
terms, and must keep working offline for tests and demos.

**Decision.**
- **Explicit deny list** of non-public ranges instead of `ipaddress.is_global`, whose results
  changed across Python patch releases; embedded IPv4 (mapped, 6to4, NAT64) and zone ids are
  handled. The check applies only to external providers; local ones answer for any address.
- **Shared result keys** (`country`, `asn`, `abuse_score`, `malicious`, ...) so incident scoring
  does not depend on which provider answered.
- **Offline mode** = no network: bundled synthetic fixture (documentation addresses only, fixed
  retrieval time), local GeoLite2 and cached answers. The fixture's addresses can never be in the
  real cache, so fake and real data cannot mix.
- **SQLite cache** of successes and "no data" answers only; failures are never cached. Daily
  budgets live in the same file so they hold across runs; cache hits do not spend them.
- **Bounded behaviour:** at most 3 attempts, `Retry-After` honoured up to 60 s, a provider that
  asks for longer, runs out of quota or budget, or rejects its key is skipped for the rest of the
  run. A token bucket keeps VirusTotal within 4 requests per minute.
- **HTTP safety:** endpoints fixed in code (a stray `.env` cannot redirect keys), keys only in
  headers, no redirects, 1 MiB response cap, explicit timeouts, provider text sanitised and
  truncated.
- **GeoLite2 behind an extra** and never bundled or downloaded, per its licence; tests use a fake
  reader. Settings come from the environment over `.env`, reading only known variables.

**Consequences.** Online results depend on free-tier limits; large investigations need paid
plans or GeoLite2 only. Tests block real sockets and DNS for the whole enrichment suite.

---

## ADR-0014: Incident builder design

- **Date:** 2026-10-27
- **Status:** Accepted

**Context.** Alerts carry only the rule's grouping fields and event ids, so a brute force (grouped
by IP), a successful sign-in after it (by IP) and an account change (by user) would not join on
their own entities. Scoring must be explainable, and incidents must be reproducible.

**Decision.**
- **Link on `(field, value)` pairs** of IP, account, request id and `extra.session_id`; never on
  `host` or `log_source`. An alert also links on every such field with exactly one value across
  its matched events. Alerts within a gap (default 30 minutes, inclusive) of the last alert with
  the same pair join; links are transitive and order-independent.
- **Shared-IP cap:** an IP that has linked more than 10 distinct accounts stops linking, with a
  limitation on the incident, instead of merging a NAT gateway's users into one incident.
- **Integer points with reasons**, capped at 100 by a visible negative component, so the
  breakdown always sums to the score. Severity is the score band, never below the top alert.
- **Novelty is incident context**, not a rule feature: a bounded history of all successful
  sign-ins answers "earlier by timestamp". No history gives a limitation and no points.
- **Events are kept as slim summaries** (no raw line), at most 100,000, while they stream into the
  engine; missing ones become a limitation.
- **Enrichment offline by default** for `prohori incidents`, each address once, at most 100 per
  run; `--online` opts in to sending addresses to providers.
- **Deterministic ids:** `INC-` plus 16 hex digits of the SHA-256 of the sorted alert ids;
  `Incident.attack_version` records the ATT&CK release.
- `prohori incidents` is added now (the plan had only `triage` in a later step) so incidents can
  be inspected and saved as JSON for the report renderer.

**Consequences.** Linking through event fields joins more of an attack chain but can join two
attackers who used the same account; the shared-IP cap can split a real incident that crossed it.
Both are visible in the incident (entities, limitations).
