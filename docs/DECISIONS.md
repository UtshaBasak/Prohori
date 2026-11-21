# Decision Log

Significant design decisions, newest last. Each entry records the context, the decision and its
consequences. Superseded decisions are kept and marked as such.

---

## ADR-0001: Package name and licence

- **Date:** 2026-10-25
- **Status:** Accepted; the licence part superseded by ADR-0033

**Context.** The distribution needs a name that is free on PyPI and matches the repository.

**Decision.** Publish as `prohori` (checked free on PyPI on 2026-10-25; `prohori-soc` is the
fallback if it is taken before the first release). Licence: MIT (replaced by PolyForm Strict
from 1.1.0, ADR-0033). Repository:
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

---

## ADR-0015: Report rendering and redaction

- **Date:** 2026-10-27
- **Status:** Accepted

**Context.** Reports are shared outside the tool, and everything in them can come from attacker
log lines or third-party data. Redacted reports must not leak, and reports must be reproducible.

**Decision.**

- **Clean once, escape per format.** A view model cleans every value (control characters and ANSI
  escapes removed, one line, at most 500 characters). HTML uses Jinja2 autoescaping plus a CSP of
  `default-src 'none'` and builds no links from data. Markdown escapes through Jinja2's
  `finalize`, so no template expression can skip it; helper output (code spans) is marked safe.
  CSV prefixes formula-like cells with `'`.
- **Packaged templates only**; no user templates, no "generated at" time, so output is
  deterministic and golden-tested.
- **Redaction from structured fields, replacement everywhere.** Values come from entities, alert
  entities, timeline `account` / `source_ip` (added to `TimelineEntry` for this) and indicators,
  plus email and IP patterns in free text; they are replaced as whole tokens in every string in
  one pass. Pseudonyms are HMAC-SHA256 with a random per-run key: unsalted hashes of user ids or
  emails would be reversible.
- **Fail closed:** the command searches the redacted data for every original value and writes
  nothing if one remains.
- **Provenance on the incident** (input SHA-256 computed while streaming, rule-file SHA-256,
  versions, enrichment mode) rather than recomputed at report time, when the inputs may be gone.
- **CSV holds the timeline**, the part analysts sort and filter.

**Consequences.** Pseudonyms differ between runs, so two redacted reports cannot be correlated
(intended). Whole-token replacement can rewrite ordinary words that equal an account name; ids
and action names are protected.

---

## ADR-0016: Simulator and rule evaluation

- **Date:** 2026-10-27
- **Status:** Accepted

**Context.** The rules need a repeatable measure of what they catch and what they raise by
mistake, without real logs, network activity or real addresses, and without flattering them.

**Decision.**

- **Scenarios as code** (`prohori.simulate.scenarios`), each declaring its expected rules before
  any evaluation, written in the exact formats the parsers read, mixed into benign background
  that includes known false-positive sources (typos, shared NAT, crawlers, owners' own changes,
  planned admin work).
- **Two variants per scenario.** `default` matches the rules' design; `heldout` changes the
  attacker's behaviour (slower, more addresses, browser user agent, obfuscation, waiting, other
  hours) with the same expected rules. Both are reported; nothing was tuned after seeing the
  held-out results.
- **Determinism:** `random.Random` seeded from scenario, variant and seed, using only methods with
  stable output across Python versions; no clock; stable sort; LF line endings. A golden file of
  SHA-256 hashes catches drift in CI on every Python version.
- **Documentation ranges only**, enforced by one address allocator and checked by tests on both
  parsed addresses and a raw-text scan.
- **Scoring:** an alert is a true positive when at least half of its events are attack lines;
  recall is per expected rule and attack; rules no scenario expects are "not evaluated".
- **Sequences re-alert** (found while building the account-takeover scenario): a completed
  sequence stays open until `start + within`, so a second account change after one sign-in raises
  its own alert.
- **Time-of-day matching** (`timezone`, `time.*`) to express PRH-ADMIN-002.

**Consequences.** The numbers describe synthetic data written by the rules' author; the held-out
columns and the stated caveats matter more than the default columns. Adding a scenario changes
the committed results and golden files, which the tests make visible.

---

## ADR-0017: `triage` and `demo`

- **Date:** 2026-10-27
- **Status:** Accepted

**Context.** The batch core needed one command for real logs and one for a first look, without
duplicating the pipeline in each command.

**Decision.**

- **`triage` composes the existing pieces** (`run_incidents` from `prohori incidents`,
  `make_report` from `prohori report`) and writes a directory: `incidents.jsonl`, one report per
  incident and `summary.md`. HTML is the default report format because it is the one people open.
- **Redaction covers the whole directory** with one random key per run, so pseudonyms match across
  files, and the run fails closed before writing anything.
- **`demo` is offline by construction:** synthetic logs from the simulator, no `.env`, no keys
  and an enrichment cache inside `--out`, so it cannot reach the network or touch the user's
  cache. It compares the incidents with the simulator's expected rules and says so when one did
  not fire.
- **A terminal capture instead of a screen recording:** `docs/images/demo.svg` is generated from
  the real demo output with Rich, so it stays accurate and is regenerated by a script rather than
  re-recorded by hand.

**Consequences.** `triage` writes files rather than streaming to standard output; scripts that
want JSON use `prohori incidents -f json`.

---

## ADR-0018: Release process

- **Date:** 2026-10-27
- **Status:** Accepted

**Context.** Publishing to PyPI is public and permanent (a version can never be reused), and
long-lived upload tokens are a supply-chain risk.

**Decision.**

- **Trusted publishing (OIDC)** from one workflow, `release.yml`, with GitHub environments:
  `testpypi` publishes automatically, `pypi` needs a maintainer's approval. No API token is stored
  anywhere; the publish action adds build attestations.
- **Gates before anything is uploaded:** the tag must equal the package version, the changelog must
  have the version's section, `twine check --strict` must pass, and the wheel must install alone
  and run `prohori demo` and `prohori rules test` on Linux and Windows.
- **After PyPI:** a job installs the release from PyPI and runs the demo, so a broken upload is
  noticed at once. The maintainer then creates the GitHub release from the workflow's files with
  the changelog section as notes (amended 2026-10-27: no job in the release workflow may write to
  the repository; OpenSSF Scorecard's Token-Permissions check flagged the earlier release job).
- **PyPI README:** `hatch-fancy-pypi-readme` rewrites the README's relative links and images to
  GitHub URLs at build time, so the project page works on PyPI.
- Every action is pinned to a commit SHA; the workflow passes `actionlint` and `zizmor`.

**Consequences.** A failed release after TestPyPI is fixed with the next patch version.

---

## ADR-0019: Flow datasets and leakage controls

- **Date:** 2026-10-30
- **Status:** Accepted

**Context.** Published intrusion-detection results on UNSW-NB15 and CIC-IDS-2017 are often
inflated by leakage: identifier and time columns that encode the capture, duplicate rows shared
by the training and test data, transforms fitted on all the data, and labelling errors. Step 15
trains models on these datasets, so the data preparation must make leakage hard by construction
and test it.

**Decision.**

- **Datasets.** UNSW-NB15's official training and testing partition files, and the improved
  CIC-IDS-2017 release from the CNS 2022 paper (`CICIDS2017_improved.zip`), which regenerates
  the flows with a fixed CICFlowMeter and relabels them. It supersedes the same group's WTMC 2021
  release, as that release's page says; the original CSVs have documented labelling errors.
- **Getting the files.** `scripts/download_datasets.py` downloads only on an explicit `fetch`,
  and only CIC-IDS-2017 (a direct HTTPS link); UNSW-NB15 is in a SharePoint folder that needs a
  browser, so the script prints the steps and verifies the files once they are in place. Neither
  publisher gives checksums: the CIC-IDS-2017 archive and its five CSVs are pinned to the size
  and SHA-256 measured on 2026-10-30, the archive is checked before it is opened, and only the
  expected member names (no paths) are extracted, up to their pinned sizes. UNSW-NB15's hashes
  are printed as "not pinned" until the files are pinned from a real download.
- **Cleaning order** (`prohori.ml.cleaning`): labels, then columns, then infinite values, then
  duplicates, then the split, then cross-split overlap, then train-only transforms.
  `check_leakage` verifies the result and `prepare` refuses to return data that fails it.
- **Duplicates.** Exact duplicates are removed on features and class (identifiers are already
  gone, so rows differing only in an id or a timestamp are duplicates). When rows share every
  feature but not the class, all of them are removed: no label is right for them, and keeping
  one would choose a label arbitrarily.
- **Official test rows that also occur in training are removed** and counted. This changes the
  official UNSW-NB15 test set, so results are not directly comparable with papers that keep it
  whole; the count is published with the results.
- **Ports are dropped in CIC-IDS-2017**, source and destination. Source ports are ephemeral
  identifiers. Destination ports identify the lab's victim services, so a model can learn
  "port 80 on this capture day" instead of the behaviour of the attack, and the UNSW-NB15
  partition has no ports to map to in the cross-dataset test of step 16. Protocol is kept.
- **"Attempted" flows become benign**, as the release's authors advise: they carried no attack
  payload and must never be a class of their own.
- **Suspect columns are reported, not dropped by default.** UNSW-NB15's TTL columns (`sttl`,
  `dttl`, `ct_state_ttl`) are reported to separate the classes because of the testbed. Step 15
  compares models with and without them instead of deciding by assumption.
- **Splits.** UNSW-NB15 keeps its official partition, with a stratified validation set (20 %)
  from the training file. CIC-IDS-2017 gets a seeded split stratified by class (50/20/30) after
  deduplication. A class with one row stays in training, and the class counts per split are in
  the report.
- **Storage.** Values are kept as float64 in the Parquet cache so deduplication compares exact
  values; models get float32. Cache files are keyed by the raw file's SHA-256.
- **Dependencies.** The `ml` extra holds scikit-learn, pandas, pyarrow and joblib; the same
  packages are in the development group so CI runs the ML tests. Nothing outside
  `prohori.ml.datasets` and `prohori.ml.cleaning` imports them, and a test checks that the base
  install works without them.

**Consequences.** Scores will be lower than many published ones, and the documentation says why.
Results depend on the seed; step 15 reports the mean and standard deviation over several seeds.

*Amended 2026-11-03:* the dependency boundary no longer holds as written: `prohori.ml.models`,
`train`, `evaluate`, `transfer`, `score` and the Isolation Forest detector import the ML
packages too, always lazily or inside the `ml` extra, and the base-install test still passes.
The validation split is drawn at random from the training data with exact duplicates removed,
so near-duplicate flows can sit on both sides; the model card names this as the likely cause of
the threshold shift on UNSW-NB15.

*Amended 2026-11-21:* validation (and CIC-IDS-2017's test split) are now made of time blocks,
and the UNSW-NB15 threshold shift is gone; see
[ADR-0040](#adr-0040-time-block-validation-and-model-files-without-pickle).

---

## ADR-0020: Flow models and how they are evaluated

- **Date:** 2026-10-30
- **Status:** Accepted

**Context.** Step 15 trains the first models on the prepared datasets (ADR-0019). Intrusion
detection results are easy to make look good: accuracy on a mostly benign test set, thresholds
tuned on the test data, a single lucky seed. The evaluation has to answer the question a SOC
asks: how many attacks are caught for a tolerable number of false alerts.

**Decision.**

- **Two models, fixed in advance.** Histogram gradient boosting (supervised; scikit-learn, no
  extra dependency) and an Isolation Forest fitted on benign training flows only (unsupervised).
  Hyper-parameters are fixed in `prohori.ml.models.PARAMS` and were not tuned; gradient boosting's
  early stopping uses a slice of the training split.
- **Thresholds come from validation.** For each target false-positive rate (1 % and 0.1 %) the
  threshold is the lowest at which at most that share of the validation split's benign flows
  alert. It is frozen before the test split is scored, and the test split is scored once per
  seed. The rate actually reached on test is reported next to the target, because it need not
  match.
- **Metrics:** PR-AUC (with the attack share as its chance level), ROC-AUC, and per operating
  point the test FPR, recall, precision, false alerts per 10,000 flows and recall per attack
  class with the class's test flows. Accuracy is not computed anywhere.
- **Seeds:** 0, 1 and 2; the seed drives the validation split (and for CIC-IDS-2017 the whole
  split) and the models. Tables show mean and standard deviation. The UNSW-NB15 test split is the
  official file and the same for every seed, so its spread reflects the models and the
  validation split only.
- **Before and after cleaning:** an `uncleaned` variant (no deduplication or overlap removal,
  numeric identifiers and ports kept) is trained with the same code, and UNSW-NB15 also gets a
  variant without its TTL columns. Each variant has its own test split, so the comparison shows
  what the same pipeline would report about itself; prevalence and ROC-AUC are shown beside
  PR-AUC for that reason.
- **Results are committed** (`results/ml_<dataset>.json`, floats rounded to six significant
  digits) and the tables in `docs/MODEL_CARD.md` and the README are generated from them by
  `scripts/generate_results_table.py`, which CI checks.
- **Models are not committed.** Cleaned models are saved with joblib to the git-ignored
  `models/` directory with a JSON sidecar (features, thresholds, versions, SHA-256). Loading
  checks the hash and the documentation warns that a pickle runs code when loaded; the hash
  catches a corrupted or swapped file, not a deliberate attack.
- **The test splits were scored during development** with these same parameters, to check that
  the pipeline worked. Nothing about the models, features or thresholds was changed afterwards.

**Consequences.** The published numbers are reproducible from the data with one command per
dataset. They are lab results; step 16 measures how they transfer between datasets.

---

## ADR-0021: Cross-dataset test and `prohori score`

- **Date:** 2026-10-31
- **Status:** Accepted

**Context.** In-dataset results (ADR-0020) say nothing about another network. UNSW-NB15 and
CIC-IDS-2017 were captured by different tools, so a model trained on one cannot read the other's
columns. Users also need a way to run a saved model on their own flows.

**Decision.**

- **Twelve common features** (`prohori.ml.transfer.COMMON_FEATURES`), derived from both
  datasets: duration, packets and bytes each way, mean packet size each way, mean inter-arrival
  time each way, packet and byte rates, and protocol. Units are converted to seconds and bytes;
  bytes are counted on the wire, so CICFlowMeter's payload counts get its transport header
  lengths plus 34 bytes a packet (Ethernet and IPv4). That UNSW-NB15's byte counts include
  headers is inferred from the data (benign DNS flows send a median of 146 bytes forward, against
  154 after conversion), not from documentation. Nothing else maps, and the documentation
  says so.
- **Features that only look alike are left out:** UNSW-NB15's `rate`, `swin`/`dwin` (TCP window
  values with a different range from CICFlowMeter's initial window bytes) and the TTLs (absent
  from CIC-IDS-2017).
- **Method:** both datasets are prepared with every leakage control and deduplicated again on the
  common features. The model is trained and its thresholds chosen on the source only, then
  scored once on the source's test split and once on the target's. In-dataset results on the
  common features are reported next to the full-feature results, to separate what is lost by
  dropping features from what is lost by changing dataset.
- **The gap is reported as a finding**, not tuned away: no setting was changed after the
  cross-dataset results were seen.
- **`prohori score FLOWS --model NAME`** scores a CSV in the training dataset's layout with a saved
  cleaned model, chunk by chunk, at one of the model's frozen thresholds. It shows identifier
  columns next to flagged flows but never feeds them to the model, refuses a model whose hash does
  not match its sidecar, prints the pickle warning, and exits `3` when flows are flagged (like
  `detect`). The `ml` code is imported only when the command runs, so the base install keeps
  working and the command explains how to add the extra.
- **No model file is committed**, not even for tests: the tests train fixture models in a temporary
  directory, and the CLI documentation shows the two commands that do the same.

**Consequences.** The headline ML result of v0.2.0 is negative: flow models trained on one lab do
not transfer to the other. Track B (step 17) works on Prohori's own normalised log events instead.

---

## ADR-0022: Log anomaly detection

- **Date:** 2026-10-31
- **Status:** Accepted

**Context.** Track B of the machine-learning work looks for unusual behaviour in Prohori's own
normalised events and compares it honestly with the rules, using the simulator's labelled
attacks and its held-out variants.

**Decision.**

- **Unit of analysis:** one source IP in one five-minute tumbling window, with thirteen
  behaviour features (`prohori.ml.features`). Ratios and entropy need five events of their kind,
  so a single failure is not a 100 % failure ratio. Standard library only.
- **Detectors judge a log against itself.** Robust one-sided z-scores (median and MAD, with a
  floor on the scale per feature, constant features skipped) in the base install; an Isolation
  Forest over log-scaled features with the `ml` extra; fixed thresholds as an evaluation-only
  baseline. Nothing is trained in advance and no model file is saved or loaded, so there is no
  pickle to trust. A log needs 20 windows before anything is judged unusual.
- **Cut-offs chosen on development data only.** For the z-score and the Isolation Forest, the
  candidate with the best window-level F1 on the simulator's default variants (seeds 1-5), ties
  to the stricter value: z 12 and an anomaly score of 0.8. They were frozen in code before the
  held-out variants were scored, and the committed results record the selection table.
- **Evaluation like the rules:** an alert is a true positive when at least half of its events
  are attack lines; an attack is caught when a true-positive alert is credited to it. Any rule
  counts for the rules (not only expected ones), so the comparison is like for like; the
  documents say which definition each number uses.
- **Model alerts in the normal path:** `--models` on `detect`, `incidents` and `triage` runs the
  detectors on the same parsed events and adds alerts with `detector_kind: model`, severity
  `low`, the source IP as entity and at most 100 event ids. Their explanation holds only feature
  names and numbers, so redaction never has to act on it. Incidents with a model alert get a
  limitation and a review action, since anomaly detectors have no runbook; a model alert next to
  a rule alert counts as one more detector in the score, as two independent signals should.
- **Night is UTC by default.** The rule PRH-ADMIN-002 has its own timezone; the feature's
  timezone is a parameter of the extractor, and the limitation is documented.

**Consequences.** On the held-out variants the detectors catch no attack the rules miss, with far
fewer false alerts. They are positioned as a quiet second signal. Without `--models` nothing
changes, and all golden files are unchanged.

---

## ADR-0023: Streaming core and lite mode

- **Date:** 2026-11-01
- **Status:** Accepted; the detector's idle flush and the incident close amended by ADR-0034

**Context.** The pipeline track runs the batch core continuously: producers, a message queue,
consumers (normalise -> detect -> incident) and a warehouse. Step 19 adds Redpanda and PostgreSQL
in Docker; before that, the same consumers must run without Docker, on Windows and Linux, and be
tested end to end in CI.

**Decision.**

- **Topics and messages:** `raw-logs`, `events`, `alerts`, `incidents` and `dead-letter`, carrying
  keyed JSON objects. Events, alerts and incidents are the schema models unchanged; `RawLog` and
  `DeadLetter` are new payloads with a schema version. Raw lines are keyed by source file (order
  within a file), the rest by id. `events` is one partition, because the rule engine needs the
  whole stream in time order.
- **Transport protocol** (`publish`, `flush`, `poll`, `commit`, `rewind`) with an in-memory and a
  file implementation. The file transport keeps one JSON Lines file per topic and committed byte
  offsets replaced atomically; a torn final line is skipped by readers and terminated by the next
  writer. The Kafka transport in step 19 implements the same protocol.
- **At-least-once delivery, idempotent storage:** publish, flush (fsync), then commit. Ids are
  content hashes, so redelivery and replay produce the same ids, and the DuckDB sink writes with
  `INSERT OR IGNORE`. The detector drops event ids it has seen (bounded at 100,000) before the
  engine, so duplicates cannot inflate thresholds; the incident stage drops alerts it has already
  used.
- **Stateful stages rebuild rather than checkpoint:** the detector and the incident stage read
  their topics from the start when the pipeline starts. Checkpointing the engine's windows and
  open alert groups would need a serialisation format for every evaluator; rebuilding is
  deterministic and reuses the tested code paths. The cost (start-up time grows with the topics)
  is documented. *Amended 2026-11-21 (ADR-0034):* "deterministic" did not hold for the two
  wall-clock decisions; they are now recorded in the topics as control markers.
- **Incidents in a stream:** an alert group is final once the newest alert time is past its end by
  gap + longest aggregate or sequence window + lateness, or, when following live logs, after that
  much wall-clock time without new alerts. Final groups go through the unchanged
  `IncidentBuilder`. The integration tests require the stream's incidents to equal the batch
  command's for every simulator scenario, replayed twice.
- **Parsing:** `LineParser.parse_raw` parses one line without resetting the parser, so the
  normaliser keeps one parser per source and `auth_log` year inference carries across messages.
  Each raw message carries its line number (part of the event id) and the time it was read (the
  file's modification time for a replay, as in batch mode).
- **Dead letters, never retries:** unparseable lines, malformed messages, schema failures and
  processing errors go to `dead-letter` with a reason and a truncated payload, and are counted.
- **Tailing:** follows a path through rename and truncate rotation, with a saved position keyed
  by file identity. On Windows the file is opened through `CreateFileW` with read, write and
  delete sharing, because Python's `open` would block the writer's rotation. Clock and polling
  are injected so tests have no sleeps.
- **Lite-mode runner:** all stages in one process, taking turns in rounds; graceful shutdown on
  SIGINT, SIGTERM (and SIGBREAK on Windows) between rounds. `prohori pipeline replay` and
  `prohori pipeline tail`; DuckDB behind the new `pipeline` extra.
- **Scope:** the "dataset replayer" replays log files (such as the simulator's labelled logs);
  the flow datasets are tabular and have their own tooling. `--models` stays batch-only, because
  the anomaly detectors judge a whole log against itself.

**Consequences.** Lite mode reaches about 2,800 lines a second on the development laptop, against
about 14,000 for the batch command; each stage validates and serialises every message and every
batch is made durable. DuckDB 2.0 ships abi3 wheels for Python 3.12+ and cp311 wheels on Windows
and Linux, so the whole CI matrix runs the end-to-end test. No change to the batch outputs.

---

## ADR-0024: Docker stack, Kafka and PostgreSQL

- **Date:** 2026-11-01
- **Status:** Accepted; the idle close amended by ADR-0034

**Context.** Step 19 runs the lite-mode consumers over a Kafka-compatible queue with a PostgreSQL
warehouse in Docker. It has to fit next to other work on a 15.7 GB laptop where Docker has 6 GB,
and it has to be testable in CI.

**Decision.**

- **Broker:** Redpanda v26.2.4 Community Edition, a single node with one core and `--memory 1G`
  in a 1.5 GB container (Seastar needs headroom above its own limit). It has no ZooKeeper and no
  JVM and starts in seconds. Its Business Source License allows running it ourselves (see
  LICENSES.md).
- **Warehouse:** PostgreSQL 17.11 (Alpine), as assumed in the plan and confirmed by the owner
  when step 19 was started. Tables live in a `raw` schema mirroring the DuckDB tables, with
  `JSONB` records and `ON CONFLICT (id) DO NOTHING`.
- **Clients:** confluent-kafka (librdkafka) and psycopg 3 (binary), both with wheels for Python
  3.11 to 3.14 on Windows, Linux and macOS, in the `pipeline` extra. confluent-kafka is locked
  to 2.16.0 rather than 2.16.1, which was four days old.
- **Kafka transport, same protocol:**
  - one partition per topic, assigned directly to each consumer group (no rebalancing), with
    offsets committed synchronously after the output is flushed;
  - an idempotent producer with `acks=all`, whose `flush` raises on any delivery error;
  - topics created by the clients with unlimited retention, because stateful stages rebuild from
    the start.

  A new protocol method, `batches_to_end`, reads a topic up to its end offset, one batch at a
  time so a long backlog is never held in memory at once. Across processes an empty poll does
  not mean the end, and the incident stage needs every event behind the alerts it has polled.
- **One container per stage**, all from one image built from the checkout with `uv sync
  --frozen` (versions from `uv.lock`):
  - images pinned by digest, an unprivileged user, and `init: true` so SIGTERM reaches Python;
  - health from a heartbeat file each stage touches after every round;
  - memory limits adding up to about 3.3 GB;
  - ports on 127.0.0.1 only (19092 and 15432, so they do not clash with a local PostgreSQL).
  The PostgreSQL password defaults to a local-only value and can be set through
  `PROHORI_POSTGRES_PASSWORD`.
- **Incidents in a stack that never ends:** `run --idle-close SECONDS` writes open incidents after
  that much quiet. The stack uses 60 seconds, so a replay's last incident appears within a minute
  or two; the detector releases its held alerts after 10 quiet seconds, well inside that. The
  documented cost is that a very slow attack can split into two incidents. *Amended
  2026-11-21 (ADR-0034):* both decisions are written into the topics as markers and acted on
  when read back, so a restarted stage rebuilds the same incidents.
- **Sinks share one base class.** NUL characters are replaced before writing, because PostgreSQL
  text cannot hold them. If the database rejects a batch for data reasons, it is retried row by
  row and the rows still rejected become dead letters. Any other database error stops the stage
  without committing, so one bad row can neither stall the warehouse nor be lost silently.
- **Commands:** `prohori pipeline up` (`docker compose up --wait`), `status` (services, health,
  warehouse rows; exit 1 unless all healthy), `down` (`--volumes` deletes data), `run --stage`,
  and `replay` / `tail --bootstrap` to publish into the stack. Compose runs as project `prohori`
  from `pipeline/docker-compose.yml`, and no shell is involved.
- **Smoke test:** marked `slow` and `docker`. It runs only with `PROHORI_DOCKER_TESTS=1`,
  because it builds an image and deletes the stack's volumes. A separate `Docker stack` workflow
  runs it on Ubuntu for changes to the pipeline and weekly; GitHub's Windows runners have no
  Linux containers. Unit tests cover the Kafka transport, the PostgreSQL sink and the compose
  helpers with fakes on both operating systems.

**Consequences.** During a 50,700-line replay the stack peaked at about 700 MB of its 3.3 GB of
limits; the incident stage reads its backlog one batch at a time, which brought its rebuild peak
from 279 MB to about 100 MB. A replay
into the stack gives the same incident ids as `prohori incidents`, with each event stored once
when the file is replayed twice. The stack needs a clone of the repository; a published image is
out of scope until the v0.3.0 release.

---

## ADR-0025: Warehouse models with dbt

- **Date:** 2026-11-02
- **Status:** Accepted

**Context.** Step 20 turns the pipeline's raw tables into tested models: daily attack counts,
top source addresses, incident durations, rule precision, detection latency and model
performance over time. The same models must build on the lite-mode DuckDB file (CI) and on the
Docker stack's PostgreSQL.

**Decision.**

- **dbt in its own dependency group.** dbt-core 1.12.6, dbt-duckdb 1.11.0 and dbt-postgres 1.11.0
  live in a `dbt` dependency group (`uv sync --group dbt`), not in the package or its extras.
  The project in `pipeline/dbt/` is a repository tool, not something `pip install prohori`
  users run, and dbt's dependency tree is large. All three support Python 3.10 to 3.14 and
  resolve with the rest of the lock unchanged. dbt-duckdb is locked to 1.11.0 rather than
  1.11.1, which was six days old.
- **One project, two targets.** The profile reads the environment (no secrets in the
  repository). Only three things differ between the targets, and macros cover them: the source
  schema (`main` or `raw`), unnesting a JSON array, and seconds between two timestamps. UTC
  dates are explicit (`AT TIME ZONE 'UTC'`), so the session time zone never matters. Schema
  names are used as they are (`staging`, `intermediate`, `marts`).
- **No dbt packages.** The range, duplicate and future-timestamp checks are three small generic
  tests in the project, so `dbt build` needs no network.
- **Ground truth and model results as tables, not seeds.** `prohori pipeline load-labels`
  matches each simulated line to the event it became, using the replay's parser, source name and
  file time. `prohori pipeline load-results` turns `results/ml_*.json` into one row per model,
  seed, variant and operating point, stamped with the evaluation time. Both write through the
  sinks' idempotent writer. Rule precision uses the simulator's definition, with an alert a true
  positive when at least half its labelled events are attack events, so the CI test can require
  it to equal the simulator's own evaluation.
- **`stored_at` on every table** (database default, added to existing tables by `ALTER TABLE
  ... ADD COLUMN IF NOT EXISTS`). It drives the freshness checks and the pipeline-latency
  measure. The table definitions moved into `prohori.pipeline.tables`, which generates the DDL
  for both databases, and inserts now name their columns.
- **CI:** a `dbt (DuckDB)` job builds a warehouse from every scenario with
  `scripts/build_lite_warehouse.py` (one pipeline per scenario, so their clocks do not collide)
  and runs `dbt build` and `dbt source freshness`. The Docker smoke test builds the models on
  PostgreSQL after its replay.

**Consequences.** `dbt build` runs 18 models and 68 checks on both databases. The marts
were identical between DuckDB and PostgreSQL for the same replay. Precision and time to detect
exist only for labelled (simulated) logs. Model performance over time has one point per loaded
evaluation until the nightly job of step 22 adds more.

---

## ADR-0026: Provisioned Grafana dashboards

- **Date:** 2026-11-02
- **Status:** Accepted

**Context.** Step 21 adds dashboards to the Docker stack: incidents over time, top sources, rule
hits, model metrics and pipeline health. They must load with data after `prohori pipeline up`
and a replay, with no manual setup, and fit the memory budget beside the rest of the stack.

**Decision.**

- **Grafana** (open question 4, resolved) rather than Metabase. Its dashboards and data sources
  are files that can be reviewed and tested, it reads PostgreSQL directly, and it is lighter
  than Metabase's JVM. The image is `grafana/grafana:13.2.5`, pinned by digest. 13.2.5 was six
  days old, newer than the two-week rule allows, but it fixes four CVEs that 13.2.4 has, so the
  security fix wins.
- **Live panels on the raw tables, analysis panels on the marts.** The stack does not run dbt,
  so dashboards built only on the marts would be empty after `up` and a replay. The Overview and
  Pipeline health dashboards query `raw.*`, so they fill as soon as the sink stores rows.
  Detection quality reads the dbt marts and says how to build them. A dbt runner service was
  rejected: it adds an image and memory for a job that step 22's scheduler will own.
- **A read-only database role.** Grafana logs in as `grafana`, with `SELECT` on `raw` and `marts`
  only. A one-shot `warehouse-init` service (the PostgreSQL image again, so nothing new is
  pulled) creates it on every `up`. Default privileges give the role access to tables created
  later, so it keeps working when dbt replaces the marts. The statements are idempotent and run
  on every start, unlike an init script, which runs only on an empty volume. The stage
  containers wait for it, so they never race it to create the `raw` schema.
- **Local and quiet.** Grafana listens on 127.0.0.1:13000. Anonymous visitors get the Viewer
  role, and the admin password comes from the environment. Usage reporting, update checks, news
  and plugin pre-installation are off. There is no data volume: everything is provisioned, and
  provisioned dashboards cannot be saved from the UI.
- **Tested queries.** A unit test checks that every panel uses the provisioned data source and
  reads only existing tables. The Docker smoke test runs every panel's SQL through Grafana's API
  after a replay.
- **Two start-up races fixed on the way.** PostgreSQL's health check now connects over TCP. On
  the first start, the image initialises the database with a temporary server that only listens
  on its socket, so a socket check reported healthy too early. The Kafka transport now waits
  until every topic has a leader, because a topic another stage had just created could still be
  unknown to the broker.

**Consequences.** `up` starts eight services, with memory limits of about 3.9 GB in total.
Grafana used about 250 MB of its 512 MB with the dashboards open. The Grafana image takes about
2 GB on disk. Until a dbt build has run, the Detection quality dashboard shows that the marts
are missing.

---

## ADR-0027: Scheduled jobs with Airflow, and the container image on GitHub Packages

- **Date:** 2026-11-02
- **Status:** Accepted

**Context.** Step 22 adds scheduled jobs to the Docker stack: a dataset backfill, a nightly
retrain and evaluation that fails when recall drops, a daily incident digest, data-quality
checks and an enrichment cache refresh. The DAGs must be checked in CI without installing
Airflow on Windows, and must run in the stack. The step ends with the v0.3.0 release, which also
publishes the Prohori image to GitHub Packages.

**Decision.**

- **Airflow 3.3.2 in its own compose profile** (`orchestration`, `prohori pipeline up
  --orchestration`). It is the largest service, so the default stack stays at about 3.9 GB of
  memory limits. 3.3.2 is the newest release older than two weeks; 3.4 is still a release
  candidate.
- **One container, `airflow standalone`, with the LocalExecutor.** It runs the scheduler, the DAG
  processor, the triggerer and the API server. Separate containers for each would multiply the
  memory for no benefit on one machine. Airflow keeps its state in its own database and role on
  the stack's PostgreSQL, created idempotently by `warehouse-init`. The key that signs Airflow's
  internal tokens is generated when the container starts. Every visitor of 127.0.0.1:18080 is an
  admin (the simple auth manager's all-admins mode), like the unauthenticated local broker.
- **Thin DAGs over tested commands.** Each task runs a `prohori` or `dbt` command, so the logic is
  unit-tested without Airflow and works without it. Three commands are new: `prohori pipeline
  digest`, `check-recall` and `refresh-enrichment` (`prohori.pipeline.jobs`). Prohori and dbt
  are installed in their own environment in the Airflow image, from `uv.lock`, so Airflow's
  pinned dependencies and Prohori's never have to agree.
- **What each job does in practice:**
  - **Backfill:** one task per scenario, then waits until the warehouse has been quiet for 90
    seconds (longer than the incident stage's idle close) before building the marts.
  - **Data quality:** checks freshness on `events` only, and skips it on an empty warehouse; an
    empty `alerts` table, or a stack nobody has used yet, is not a data problem.
  - **Nightly evaluation:** one seed of the cleaned UNSW-NB15 models, which takes seconds. The
    datasets are mounted read-only from `data/`, and the job skips itself without them. The
    results are loaded before the gate, so a drop is recorded even when the run fails. The
    minimum, 0.75, sits below the measured 0.82.
  - **Enrichment refresh:** a cache volume shared with the incident stage (same uid 10001),
    online only when API keys are set.
- **DAG integrity in a Linux CI job.** Airflow is installed with its constraints file into a
  separate environment there. `tests/dags` skips itself without Airflow. A further test, without
  Airflow, checks that the DAG files call only commands that exist. The Docker workflow runs every
  DAG through the scheduler in the stack.
- **The image on GitHub Packages** (`ghcr.io/utshabasak/prohori`) is published by the release
  workflow only. A job builds it on pull requests and tag pushes:
  - for linux/amd64, where it runs `--version` and the demo and checks the user and contents;
  - for linux/arm64 as well.

  After PyPI is approved, a second job pushes `X.Y.Z`, `X.Y` and `latest` for both platforms,
  with OCI labels and a signed provenance attestation. That job alone has `packages: write`.
  The image is built from a clean checkout with the `.dockerignore` allow-list, so it holds only
  `pyproject.toml`, `uv.lock`, the README, licence, changelog and `src/`, installed for user
  10001. There is no build cache, which a release workflow should not trust.

**Consequences.** The orchestration profile adds a 3 GB limit; measured use is about 1.2 GB idle
and 1.84 GB at the peak of the nightly training. When Airflow first sees a scheduled DAG it runs
it once, so a fresh stack builds the marts within a minute. Locally, the Airflow image takes
about 2 GB of disk.

---

## ADR-0028: The LLM analyst: providers, redaction before sending, `explain`

- **Date:** 2026-11-02
- **Status:** Accepted

**Context.** Step 23 adds opt-in incident explanations by a large language model. The free
Gemini tier lets Google use what is sent to improve its products, so the design must make
sending deliberate, minimal and redacted, and must work fully without a model.

**Decision.**

- **Off by default, three providers.**
  - `none` (default) sends nothing; `explain` says so and exits 0.
  - `mock` answers offline and records its requests; the tests assert on exactly what it
    received.
  - `gemini` uses the official `google-genai` SDK (2.31.0, Apache 2.0; 2.34.0 was four days old)
    in the `llm` extra. It calls `models.generate_content`; the newer Interactions API adds
    nothing for a single request.
- **The client.** It gets an explicit key and `vertexai=False`, so environment variables cannot
  redirect it. It has a timeout, and the SDK's retries are off, so one explanation is one
  request against the daily budget.
- **An allow-list payload, redacted, then checked.** Fields are chosen one by one
  (`prohori.llm.payload`), never by dumping the incident.
  - Account names, ids and emails become keyed pseudonyms through the report redactor (step 11),
    with a random key per run. IP addresses become pseudonyms only with `--mask-ips`, because they
    are usually the evidence.
  - "Drop raw lines": incidents hold no log lines, but the timeline's event descriptions carry
    attacker-controlled paths and user agents. Only their count and the alert entries, which
    Prohori writes, are sent. Every free-text value is capped at 300 characters.
  - The exact text to be sent is searched, decoded, for every replaced value. One hit means
    nothing is sent (exit 1).
  - Oversized payloads drop indicators, then alerts, then the alert timeline, and say so.
- **Fallback, not failure.** A missing key or extra, the daily budget, HTTP 429, a timeout or an
  empty or blocked answer each give a local summary written from the incident, with the reason
  and whether anything was sent. The budget lives in the enrichment cache and is counted before
  sending.
- **The default model** is `gemini-3.5-flash-lite`, the newest stable Flash-Lite model with a free
  tier on 2026-11-02. It is configurable; never a `-latest` alias.
- **Untrusted output.** Control characters are stripped and the answer is never rendered as
  markup. Pseudonyms are mapped back only locally, by exact token.
- **Settings** have their own variable list (`PROHORI_LLM_*`, `GEMINI_API_KEY`). The `.env`
  reader now takes the list of known keys.

**Consequences.** Nothing about the analyst runs unless it is configured. A reminder about
free-tier data use is printed on every free-tier request. `--show-payload` shows what would be
sent. Prompt-injection defences beyond the instruction (field delimiting, output validation)
are step 24.

---

## ADR-0029: Grounded answers: retrieval, fencing, answer validation and `ask`

- **Date:** 2026-11-02
- **Status:** Accepted

**Context.** Step 24 makes the LLM analyst's answers grounded and resistant to prompt injection.
Logs are attacker-controlled; an incident can quote a user agent, a username or a path written
to instruct the model.

**Decision.**

- **Retrieval with BM25 in pure Python** (`prohori.llm.knowledge`), with no new dependency.
  - The ATT&CK corpus is built from the pinned Enterprise ATT&CK v20.0 STIX bundle (SHA-256
    checked) by `scripts/build_attack_corpus.py`. It covers the 706 active techniques: id, name,
    tactics, and the first paragraph of each description without citations, capped at 600
    characters.
  - It ships as `src/prohori/llm/data/attack.jsonl` (about 350 KB) with MITRE's notice. ATT&CK's
    terms allow reproduction and derivative works with the copyright designation.
  - Runbooks are indexed by section.
  - A technique id in a query is matched exactly first.
- **Fences instead of escaping.** Every value that can carry log content is wrapped in
  `⟦u:NONCE⟧...⟦/u:NONCE⟧` with a per-request random nonce, after the fence characters are
  stripped from the value, so the value cannot forge or close a fence.
  - Most attacker text is still never sent: event descriptions are dropped (ADR-0028) and
    usernames are pseudonyms.
  - A scanner's user agent stays, fenced, as an indicator, because it is evidence.
- **Conservative output validation** (`prohori.llm.guard`). The answer is rejected, and the local
  answer shown, if it cites any of the following that is unknown:
  - an IP address, email address or pseudonym;
  - an incident, rule or ATT&CK technique id;
  - a link anywhere but attack.mitre.org.

  Citable values come only from the incident's identity fields (addresses, pseudonymised
  accounts), its rules and techniques, and the sources and tool results, never from free text,
  so an injected address cannot make itself citable.
- **Tools through a plain-text protocol** (`CALL tool {json}`), so they work with every provider,
  including the mock.
  - The three tools are read-only: knowledge search, one technique, one alert.
  - At most three calls (0 to 5 with `--max-tool-calls`), with a 200-character argument cap and
    a 4,000-character result cap. Misuse ends the conversation with a local answer.
  - Each round counts against the daily budget. Native function calling would tie the design to
    one provider.
- **`prohori ask "..."`**, optionally about an incident (`-f`). With the provider `none` it shows
  the best-matching sources locally.
- **Tests:** an injection fixture suite builds incidents from real logs, with instructions in a
  user agent, a username and a path. It runs with the mock provider: the instruction must stay
  fenced, seven kinds of compromised answers are rejected for each vector, and an honest answer
  is accepted.

**Consequences.** Answers can cite only what Prohori gave the model. A judgement built from real
values but wrong (an injected "this is benign") is not detectable by these checks; the docs say
so. Step 25 measures the analyst.

## ADR-0030: Evaluating the LLM analyst offline

- **Date:** 2026-11-02
- **Status:** Accepted

**Context.** Step 25 measures the LLM analyst's answers. Free-tier quotas are small, answers
vary between runs, and no API key was available while the step was built.

**Decision.**

- **30 cases with truth from the simulator** (`evaluation/llm/`, built by
  `scripts/build_llm_eval_set.py`, rebuilt byte for byte in a test):
  - 15 attack incidents (each scenario's main incident, default and held-out variants);
  - 7 false positives raised on background lines;
  - 8 incidents from small logs with an instruction in a user agent, a request path or a
    username.

  An incident is an attack when at least half of its alert events are on attack lines, the
  rule used by the rule evaluation.
- **Hand-written references** (`references.yaml`): a summary for a reviewer, the indicators and
  points a good answer covers and the statements that are false for that incident. They were
  written from the payload the model receives, before any recorded answer was read, and each
  must score perfectly against itself.
- **Record once, score offline.** `python -m prohori.llm.evaluate record` saves every request's
  prompt hash and answer; `score` replays them through the real pipeline (fencing, tools,
  validation, fallback) with no network access.
  - Recording a real model resumes where it stopped and stops cleanly at the daily budget.
- **An evaluation-only redaction key and nonce**, derived from the incident id
  (`build_payload(key=...)`), so prompts are reproducible and recorded pseudonyms map back.
  Prohori itself keeps random ones.
  - A recorded answer whose prompt has changed is *stale*: an error for the offline systems,
    a counted warning for a real model.
- **What counts as an error.** Every answer is scored twice: the model's own answer and the
  text the analyst is shown, so a model whose answers are always rejected cannot look as good
  as the local summary.
  - A factual error is a value outside the incident's structured fields and the sources (the
    same rule as the answer check), or a statement that contradicts the truth or the reference.
  - Only assertions count: a match preceded by a hedge or condition in its sentence is skipped.
  - Injections are checked on the text before pseudonyms are restored. A username shown back
    as an account is data, not obedience.
- **Baselines are labelled as such**: the local summary, the mock (a template) and a scripted
  adversary that obeys every injection. The docs and README say plainly when no real model has
  been recorded.

**Consequences.** The scores are proxies based on patterns; the per-case details let a human
check them. Without a key, the published results measure the safeguards and the scorer, not a
language model. Recording Gemini once fills in that row without changing any code. The scripted
adversary shows the known gap: claims made with real values ("no action needed") pass the
answer checks.

*Amended 2026-11-03:* Gemini (`gemini-3.5-flash-lite`) was recorded on 2026-11-02
(`evaluation/llm/recordings/gemini.jsonl`), and its row is in the tables. The factual-error
column uses the same validator as the analyst itself, so it cannot show a value the validator
misses; ADR-0032 closes the gaps found since.

## ADR-0031: Release 1.0.0: what "stable" covers, and how its claims are checked

- **Date:** 2026-11-02
- **Status:** Accepted

**Context.** Step 26 is the 1.0.0 release: documentation, a threat model, performance notes on
logs of at least a million lines, every README number generated from result files, and the
project's success criteria checked with evidence.

**Decision.**

- **Stable means the interfaces.** The command line, its exit codes, the output formats and the
  rule format follow semantic versioning from 1.0.0. The classifier is Production/Stable. The
  detections themselves are still evaluated on synthetic data, and the README says so.
- **Measured numbers are generated; facts about the code are tested.**
  - Results come from files in `results/`, through `scripts/generate_results_table.py`: the
    rules, the flow models (including the findings sentences), the cross-dataset test, the
    anomaly detectors, the LLM evaluation, performance, and the worked example (from the
    sample incident and its log).
  - Counts that describe the code (the number of built-in rules, scenarios, the ATT&CK version)
    are pinned to the code by a test.
  - Numbers with no result file were reworded instead: the warehouse's detection delays and the
    Docker stack's memory now point to their documents.
- **Performance** (`scripts/benchmark.py`): one log per format, built from the simulator in
  chunks of a day (or three hours for SSH) with a seed each, every command in its own process.
  - Peak memory is read from the operating system for that process: `wait4` on Linux and macOS,
    `GetProcessMemoryInfo` on Windows. On Windows the virtual environment's launcher is skipped
    (the base interpreter with `__PYVENV_LAUNCHER__`), so the measured process is Prohori itself.
  - The million-line run is not part of CI; a small run is, so both measuring paths are tested.
  - Nothing was tuned for speed in this step.
- **Three operating systems.** macOS joins the CI test matrix (Python 3.13). The release's wheel
  check and install-from-PyPI check run on Linux, Windows and macOS, time `prohori demo` and
  fail if it takes more than a minute.
- **Core coverage is checked**, not asserted: a CI step holds schema, parsers, rules, enrichment,
  incidents, reports and the command line to at least 85 %.

**Consequences.** The benchmark found a real Windows failure: lite mode's atomic rename of a
consumer position failed with "access denied" while another process briefly had the file open.
The rename is now retried for up to about two seconds. Two success criteria, the tagged release
and `pip install prohori && prohori demo` from PyPI, can only be met when the release is
published; the release workflow's checks are their evidence.

---

## ADR-0032: Release 1.0.1: fixes from a review of the whole project

- **Date:** 2026-11-03
- **Status:** Accepted

**Context.** After 1.0.0, every part of the project was reviewed: the batch core, the pipeline,
the ML and LLM code, and the repository's CI and release. Each finding was reproduced before it
was fixed. All fixes keep the command line, the file formats and the rule format of 1.0.0.

**Decision.**

- **Redaction covers enrichment data.** An indicator's `enrichment` was skipped as structural, so
  `--redact-ips` left the network (`203.0.113.0/24`) and any address or email in provider data,
  and the leak check skipped it too. Now only `provenance.enrichment` (the run's mode, a string)
  is structural. Account values are matched ignoring letter case and next to `@`
  (`alice@bastion`, `@alice`); emails are found with non-ASCII letters. The `-` and `.`
  boundaries stay, so rule ids and action names are never rewritten; the residual (`alice-laptop`
  keeps the name) is documented.
- **The LLM payload fences and caps enrichment values**, drops them before giving up on size,
  and raises `PayloadTooLargeError` (nothing sent, exit 1) when trimming cannot meet
  `PROHORI_LLM_MAX_INPUT_TOKENS`; before, it sent an oversized payload. `ask` redacts the
  question with the incident's key. Restored real values are cleaned again before display.
- **The answer validator normalises first** (NFKC, defanged `[.]` and `hxxp`), finds compressed
  IPv6 addresses, treats an unparsable dotted quad as unknown, checks Prohori's detector ids in
  any case, and allows only `https://attack.mitre.org/` links: Markdown targets, scheme-less
  `//host`, other schemes and backslashes are untrusted.
- **Parsers:** a timestamp that overflows when moved to UTC is a line error, not a crash; JSON
  and nginx escapes that decode to control characters are sanitised again; a sudo command line
  can no longer overwrite the fields before `COMMAND=`; an unparseable request is kept as written.
- **Incidents:** the shared-address limit counts accounts, not (field, value) pairs, so an
  account seen by id, name and email hash counts once.
- **The Docker stack's stateful stages do not release state on SIGTERM.** They rebuild it from
  their topics on the next start, so a stop between two parts of an attack no longer writes the
  first part as an incident of its own next to the final one. The heartbeat is touched per batch
  so a long rebuild stays healthy.
- **Airflow parameters reach scripts only as environment variables** (`env=`, quoted), never
  rendered into a bash script, and the backfill's `start` has a pattern. Before, a string
  parameter could inject shell commands into the Airflow container.
- **Bounded stack roles and checks:** Grafana's database role is read-only by default, with a
  15-second statement timeout and five connections. The future-timestamp data check is a
  warning, so one bogus line cannot stop every mart from being rebuilt (reproduced with dbt).
- **Lite mode** fsyncs consumer positions and tailer checkpoints before the rename (about 5 %
  slower on a small replay).
- **CLI:** an unusable `-o` for `report` or `triage` is a usage error (exit 2), checked before
  any work; Typer never prints local variables on a crash.
- **Repository:** CI runs with `UV_LOCKED` (a stale lock fails), every job has a timeout, the
  fuzzer and twine are pinned, Dependabot covers the Docker images, the compose file and the
  Airflow requirements, and one "All checks passed" job sums up CI for branch protection. The
  release signs a SLSA provenance statement for the wheel and sdist and keeps the bundle as an
  artifact, which the maintainer attaches to the GitHub release; no job gains write access to
  the repository (ADR-0018).

**Consequences.** Redacted reports and LLM payloads can show more pseudonyms than before (the
sample's network is now `[ip:...]/24`). Not fixed here, and listed as candidates for later work:
the detector's idle flush depends on wall-clock time, so a rebuild can evaluate events the live
run dropped as late; a daylight-saving fall-back hour in `auth.log` can drop events as late;
SSH lines with a host name instead of an address are not grouped by source; alerts of a batch
run are held in memory; the raw tables have no indexes beyond their keys; the stages use the
database superuser; Redpanda runs in its development mode. *Amended 2026-11-21:* the idle
flush is fixed by ADR-0034; the daylight-saving hour, host names and batch alert memory by
ADR-0035.

## ADR-0033: Source-available licence and project control

- **Date:** 2026-11-16
- **Status:** Accepted

**Context.** The owner wants the repository to stay public, to show the work, while nobody may
copy Prohori and build their own product from it. Prohori was MIT-licensed up to 1.0.1, which
allows exactly that. Public code can always be read and downloaded, and GitHub's terms let
anyone fork a public repository inside GitHub, so no technical measure can prevent copying;
what can be controlled is what others may legally do, who owns the code, the name, and which
builds are official. Making the repository private until the project is finished was
considered and rejected: it would lose the free Actions minutes (Windows and macOS runners
count double and tenfold against a private repository's 2,000 free minutes), free CodeQL and
secret scanning, GitHub Pages and the OpenSSF Scorecard, against the project's free-of-cost
rule.

**Decision.**

- **Licence:** the PolyForm Strict License 1.0.0 for everything from this change on, with the
  required notice `Copyright (c) 2026 Utsha Basak`. It allows use for any non-commercial purpose
  (personal use, study, research, hobby projects; charities, schools, public research and
  government bodies) and forbids distributing the software and making changes or new works,
  for everyone but the licensor. Commercial use needs a separate licence from the owner. Of the
  source-available licences considered, it gives the owner the most control while keeping
  personal use free (PolyForm Noncommercial and Shield allow changes and redistribution; the
  Business Source License allows non-production use and becomes open source after a set
  time). A licence can be loosened later but not tightened for code already released, which is
  why the strictest suitable one is chosen now. The text is the official one, unmodified.
- **The MIT releases stay MIT.** Versions up to 1.0.1 were released under MIT; that cannot be
  withdrawn. Its text is kept in `docs/legal/MIT-LICENSE-up-to-1.0.1.txt` and the LICENSE file
  says which versions it covers.
- **Package metadata:** `license = "LicenseRef-PolyForm-Strict-1.0.0"` (PolyForm Strict is not
  on the SPDX list, so a `LicenseRef-` identifier is used, which PEP 639 and PyPI accept), the
  same identifier in the container image label, `prohori version` prints a one-line summary.
- **Every own source file carries the SPDX identifier and copyright line** (Python, SQL,
  Dockerfiles, the report templates and the built-in rules), added by
  `scripts/licence_headers.py` and checked by a pre-commit hook and a test. Templates use a Jinja
  comment that leaves rendered reports byte-identical. Reports themselves carry no licence
  notice: they are the user's documents.
- **One copyright holder:** outside code contributions are not accepted (CONTRIBUTING.md), so
  the owner stays the only author and can relicense later. Dependabot's version bumps are
  mechanical and accepted.
- **Name:** TRADEMARKS.md claims "Prohori" and the logo as unregistered marks (registration
  costs money); copies may not use them.
- **Official builds:** releases only from the protected release workflow (only the owner can
  create `v*` tags), with signed provenance (ADR-0032) and now signed tags; RELEASING.md shows
  how anyone can verify a download.
- **Dependency licences:** a test walks every installed runtime dependency and fails on GPL
  (other than LGPL), AGPL, SSPL, Commons Clause or non-commercial terms, so a new dependency
  cannot restrict how Prohori may be distributed. LGPL libraries (psycopg) stay separate and
  replaceable, which the later frozen builds must keep.

**Consequences.** Prohori is no longer open source in the OSI sense: GitHub shows the licence as
"Other", and directories that list only open-source software (such as Homebrew's core
repository) will not take it; the plan already uses its own Homebrew tap and Scoop bucket.
Contributors are fewer, as intended. Commercial users must ask. The research code of the
cross-dataset study can be run by readers for non-commercial research but not changed or
redistributed, which its reproducibility statement says. This is not legal advice; the owner
may ask a lawyer or a free legal clinic to review it.

## ADR-0034: Wall-clock decisions recorded in the stream

- **Date:** 2026-11-21
- **Status:** Accepted

**Context.** The detector and the incident stage rebuild their state by reading their topics
from the start (ADR-0023), which was meant to give the same alerts and incidents as the live
run. Two of their decisions depend on wall-clock time, not on the messages, so the promise did
not hold (found in the 1.0.1 review, ADR-0032):

- the detector releases its reorder buffer when the input has been quiet (`idle`) and at the end
  of a run (`finish`). Events released this way move the "already evaluated" point forward, so
  older events arriving later are dropped as late. A rebuild reads everything without pauses and
  keeps them. Reproduced: nine failed sign-ins from one address, a quiet period, then three
  older ones; live, no alert; rebuilt, PRH-AUTH-001.
- the incident stage closes every open incident after `--idle-close` seconds without alerts, and
  at the end of a run. A rebuild never waits, so it can group alerts that the live run had
  already written as separate incidents.

**Decision.**

- Each decision is recorded as a control marker in the deciding stage's own input topic, and the
  stage acts only when it reads the marker back, live and on a rebuild alike: the detector
  writes `{"control": "flush", "stage": "detect", ...}` into `events`, the incident stage
  `{"control": "close", "stage": "incidents", ...}` into `alerts`. The marker is acted on at its
  position, after everything published before it, so concurrent writers (the normaliser into
  `events`, the detector into `alerts`) cannot make live and rebuild disagree. Writing the
  marker after acting, with an offset, was rejected for exactly that reason.
- `finish` is recorded the same way, because it is the same kind of decision: a second replay
  into the same state directory rebuilds the first run's end-of-run flush and close instead of
  merging the two runs. `finish` writes its marker and reads the input up to it, so it still
  returns with everything released.
- A stage writes a marker only when it holds something (events in the buffer, open alerts) and
  is not already waiting for one of its own, so a quiet stack does not fill the topics. A marker
  written twice (after a crash) is harmless: the second finds nothing to release.
- Markers carry `v`, `control`, `stage`, `reason` (`idle` or `finish`) and a random `id`
  (`ctl-` and 32 hex digits). `is_control` (a `control` key, which no event, alert or incident
  has) lets the shared stage loop route them before validation: a stage acts on its own, skips
  other stages' markers, and turns a malformed marker into a dead letter. The sink stores none.
  The event, alert and incident payloads are unchanged, so no message version changes.
- Topics written by 1.0 have no markers and replay with 1.0's behaviour; a test copies a run's
  topics without the markers and gets the old divergent result back.

**Verification.** A Hypothesis property test (fixed seed, 200 examples per transport) drives
random scripts of event bursts (out of order, some too late), brute-force runs, stage turns in
random order with random batch sizes, idle flushes and idle closes, over the memory, file and
fake Kafka transports; a rebuild from offset 0 must publish the same alerts and incidents,
compared as whole messages (timelines, scores and provenance included), not only their ids.
Run against the previous stage code, it fails on all three transports. The audit repro is a
test of its own, and stream == batch still holds for every simulator scenario.

**Consequences.** The detector now writes to `events` and the incident stage to `alerts`, so the
broker permissions planned for step 31 must allow that. A flush or close happens one round
later than before (when the marker is read back), which in the stack is well under a second.
Not covered: the live detector's rejection of events stamped more than a day ahead depends on
the clock when the event is read, so an event rejected live can be accepted by a rebuild days
later; and the incident stage reads all events before alerts when rebuilding, so with more than
100,000 events in the backlog it can forget events the live run still had in memory. Both are
limits of a backlog, not of timing, and are documented in PIPELINE.md.

## ADR-0035: The daylight-saving hour, SSH host names and bounded alert output

- **Date:** 2026-11-21
- **Status:** Accepted

**Context.** Three gaps from the 1.0.1 review (ADR-0032). In `auth.log` lines without an offset,
the hour repeated when daylight saving time ends was always read as its first occurrence, so its
second half jumped back an hour and the rule engine dropped it as late. sshd with `UseDNS yes`
logs a client's host name instead of its address; the parsers kept the name in
`extra.source_host`, but every sign-in rule counted by `source.ip`, so such attacks raised no
alert. And `prohori incidents` and `triage` held every alert of a run in memory, as did the
`detect` table, so a scanner tripping a single-event rule on every request could exhaust it.

**Decision.**

- **The repeated hour** is resolved with state, like the year: a time in it is read as its first
  occurrence unless that would put it more than ten minutes before the previous line, then as
  the second. A tolerance (rather than "whichever is closer") keeps a second-pass line that is
  25 minutes after the previous one in the second pass, while lines a few minutes out of order
  in the first pass stay there. Ambiguity is detected by comparing the two offsets (fold 0 has
  the larger one only in the repeated hour, so the skipped hour in spring is unchanged), and UTC
  skips the check. Ambiguous lines are counted in a new `ParseStats.ambiguous_times`, which
  changes the JSON statistics (one more key) but no golden file. Because the event id contains
  the timestamp, a streaming normaliser restarted inside the repeated hour can read a
  redelivered line without its predecessor and store it twice; documented in PARSERS.md.
- **Host names** get an optional schema field, `source.host`, rather than a rule-level fallback
  over `extra.source_host`: that field holds whatever the log put in the address position, and
  the app logs' `unknown` would have become one shared group key, a false brute-force alert.
  Parsers set `source.host` only for a valid fully qualified name, lower-cased and without the
  trailing dot (so `Evil.Example.` and `evil.example` are one source); `extra.source_host` is
  unchanged, so 1.0 consumers see the same events. Events serialise one more key (`"host":
  null`); incidents do not embed events, so no golden changed except rule hashes.
- **Rule format:** a `group_by` / `by` entry may be a list of two or three fields, the first with
  a value being used. The field used is part of the group key and of the alert's entities, so an
  address and a host name are never counted together. Rules without alternatives are unchanged.
  PRH-AUTH-001, -002, -003 and PRH-SSH-001 use `[[source.ip, source.host]]`, which changes their
  file hashes (goldens, the sample incident and the examples were regenerated).
- **Everywhere a source address is handled, a host name is too:** incidents link on
  `source.host` with the shared-address cap; `--redact-ips` and
  `--mask-ips` pseudonymise host names as `[host:...]`, because reverse-DNS names often contain
  the address (tested with `203-0-113-9.dyn.isp.example`); answers may cite them. Redaction
  collects host names from the entities, so incident text only names a host where it is an
  entity (a group key, or a single-event rule's field): the timeline says "from" an address but
  never a host name, since an incident about several hosts would not list them all as entities.
  The warehouse gets no new column: the stored JSON record carries the field.
- **Bounded alert output.** The `detect` table keeps only the `--limit` earliest alerts (default
  100) with `heapq.nsmallest`, which equals sorting and slicing; the summary and exit code use
  the total. JSON output already streamed. `incidents` and `triage` keep at most 1,000 alerts per
  rule and entities (the first ones) and 10,000 of each severity, and count the rest; an
  incident whose rule and entities lost alerts says how many in its limitations, and the run's
  summary gives `alerts_not_kept`. The plan asked for a cap per incident group, but groups are
  only known once every alert is in; a cap per rule and entities is the closest bound that can
  be applied while the alerts arrive, and the per-severity budgets make the memory bound hold
  when there are many attackers too. One shared overall budget was rejected: first come, first
  kept, it would let about twenty addresses re-triggering a medium rule fill it, after which a
  critical PRH-AUTH-003 would be dropped like noise. With a budget per severity, a flood can only
  crowd out alerts of its own severity. The `detect` table's note counts the hidden alerts by
  severity for the same reason. The limits are far above what the simulator produces (at most 14 alerts per
  rule and entities across all scenarios, both variants and three seeds), so ordinary results
  are unchanged.
- **Measured, not assumed:** `scripts/benchmark.py --alerts N` builds a log in which every line
  raises alerts and checks the peak memory of `detect -f json`, the `detect` table and
  `incidents` against a fixed 512 MiB bound; the result goes into `results/performance.json` and
  the table into PERFORMANCE.md.

**Consequences.** An attacker who controls the reverse DNS of their addresses can rotate host
names to split counts, and one machine seen both by address and by name is counted twice; both
are stated in RULES.md. A run that exceeds the alert limits gives incidents built from part of
the alerts; their scores can be lower than with every alert, and the incidents say so. Once a
severity's budget is used up, later alerts of that severity about new entities form no incident
at all; only the run's summary counts them. The
streaming pipeline does not apply the limits (its incident stage releases alerts as their
incidents close), so above them stream and batch differ. `--models` still holds every event,
because the anomaly detectors compare a whole log with itself.

## ADR-0036: Evasion-resistant authentication rules, measured before and after

- **Date:** 2026-11-21
- **Status:** Accepted

**Context.** Every 1.0 authentication rule counts per source address. In the held-out variants,
where the attacker slows down or spreads over more addresses, credential stuffing was missed in
5 of 5 runs and PRH-AUTH-001 missed every password-spraying and SSH brute-force run. The
improvement has to be shown with numbers that cannot have been fitted to the test set.

**Decision: procedure, fixed before any held-out result was seen.**

1. The 1.0 rules' results were frozen as the `baseline` of `results/rules_eval.json` (commit
   792a49b) before any rule changed. `scripts/evaluate_rules.py` never replaces a frozen
   variant.
2. Thresholds were chosen on the default variants only (`--variants default`, which writes
   nothing), with one rule for all of them: **twice the largest value the benign background
   reaches in any default scenario and seed, rounded up**. Failures for accounts that do not
   exist (`event.reason: unknown_user`) are left out of the per-account and per-network counts:
   there is nothing to take over, and internet scanners produce them all day.
3. The rules, their fixtures and this reasoning were committed before the held-out variants were
   scored, and before the second held-out set (`heldout2`) was defined. One disclosure: before
   that commit, rebuilding the LLM evaluation set (which runs the rules over seed 1 of every
   variant) showed that a held-out credential-stuffing incident now exists. No rule was changed
   after that.
4. `heldout2` is derived from `heldout` by a fixed rule, written here before it existed: rates
   halved, sources doubled, and the attack's sources spread over every documentation network
   (three IPv4 /24s and IPv6 addresses in distinct /48s), with fresh random streams. It is scored
   once, after the rules are committed, for the 1.0 rules (taken from the 792a49b tree) and the
   new ones.

**Benign maxima in the default variants and the thresholds they give:**

| Measure (benign lines only) | Maximum | Rule | Threshold |
| --- | ---: | --- | ---: |
| Addresses one existing account failed from, per hour | 2 | PRH-AUTH-005 | 4 |
| Failures of one existing account in a 24-hour window (SSH root; the log is 3 hours long) | 11 | PRH-AUTH-006 | 22 |
| Existing accounts failing from one /24 or /48, per hour | 19 | PRH-AUTH-007 | 38 |
| Existing accounts / addresses failing in one log, per hour | 19 / 18 | PRH-AUTH-008 | 38 / 36 |
| Addresses with unknown-account failures in one log, per hour | 0 | PRH-AUTH-009 | 10 (reasoned) |
| Failures of one account, per hour | 6 | PRH-AUTH-010 | 12 |

The maxima come from `scripts/benign_maxima.py` (default variants only, the engine's window
semantics), and a test checks that every threshold is twice its maximum. Every maximum was
reached in a 3-hour simulated log, so "per 24 hours" means at most three hours of background
here: PRH-AUTH-006 will be much noisier on a real server than its threshold suggests.

PRH-AUTH-009 is the exception: the simulator's customers never mistype their email, so its
background maximum is 0 and the margin rule gives nothing. Its threshold comes from reasoning (a
small shop rarely sees unknown-email failures from ten addresses in an hour) and its status is
`experimental`: its false-positive rate is untested here. SSH is excluded from it.

**False-positive margin.** The definition of done asks that false positives on the default
variants rise by no more than a margin stated here. No margin was set in advance; the observed
rise is 0 in every variant (default 295, held-out 259, held-out 2 287 false-positive alerts,
before and after), so any margin is met.

**The baseline** is the rule files of commit 792a49b, which already include step 28's host-name
fallback (ADR-0035); on the simulator's logs, which always carry addresses, it reproduced the
committed 1.0 results exactly.

**The rules** (all additive; the 1.0 rules are unchanged): PRH-AUTH-005 failures for one account
from many addresses; PRH-AUTH-006 slow guessing on one account over 24 hours; PRH-AUTH-007 many
accounts failing from one network (`source.ip_prefix`); PRH-AUTH-008 many accounts and many
addresses failing in one log within an hour (two distinct thresholds at once); PRH-AUTH-009
unknown-account failures from many addresses; PRH-AUTH-010 a success after many failures on
one account. Accounts are grouped by `[user.id, user.name, user.email_hash]`, addresses by
`[source.ip, source.host]`, so SSH host names (ADR-0035) count too. New rules start as `test`
(PRH-AUTH-009 `experimental`); the built-in rule policy now allows those statuses.

**Engine additions:** an aggregate may list several distinct thresholds that must all be reached
in one window (each set keeps at most its threshold's values, so state stays bounded); a distinct
field may list alternatives; `source.ip_prefix` is a derived field (IPv4 /24, IPv6 /48) computed
when read.

**Not done, and why.**

- `source.asn` from enrichment before detection: no batch or streaming path enriches events
  before the rules run, so there is nothing to group by. Deferred.
- "Each account tried only a few times" (credential stuffing) cannot be expressed as an
  aggregate; PRH-AUTH-008 relies on many accounts and many addresses at once instead.
- Incident grouping needs no change: per-account alerts link on `user.*` already, and the
  per-log alerts (PRH-AUTH-008, 009) form incidents of their own. A test checks both.
- PRH-ACCT-001's false positives (48 to 80 per scenario) were checked: exactly one alert per
  benign account change after a sign-in, so the rule works as designed (it cannot know an owner's
  usual address); documented, not changed.

**Consequences.**

- A 24-hour window makes the streaming incident stage's hold time 24 h 35 min (65 min before):
  open incidents wait that long in alert time. Following live logs therefore now closes quiet
  incidents after at most an hour by default (`--idle-close` overrides it); the Docker stack
  already uses 60 seconds.
- The per-account rules are noisier behind shared networks, during password resets and on SSH
  servers open to the internet; the per-log thresholds are absolute and need raising on a busy
  site (suppressions come in step 32).
- **Simulator effects that flatter or hurt the numbers.** All simulated hostile addresses share
  one /24 (203.0.113.0/24) and internet hosts another, so a per-network rule groups a "spread"
  attack for free in the 1.0 held-out variants. All customers share 192.0.2.0/24 too, which
  pushes the benign per-network maximum (19), and with it PRH-AUTH-007's threshold, far above a
  real shop's. `heldout2` spreads sources over networks to measure the first effect.
- The account-takeover sample also raises PRH-AUTH-010 now, so its incident id (and the sample
  incident's file name) changed.
- **Not met:** "the per-account rules fire in every held-out spraying run". The per-network rule
  PRH-AUTH-007 missed every spraying run on both held-out sets (30 accounts against its 38), and
  spraying spread over networks (`heldout2`) is missed by every rule, old and new. The cause is
  the simulator's address model (every customer in one /24), not a threshold to tune after
  scoring; the follow-up is a simulator with customers spread over networks, with a re-frozen
  baseline, as its own step.
  **Amended 2026-11-21 (step 28c, ADR-0038):** done. On address model 2 the thresholds were
  derived again by this ADR's unchanged rule (the table above is address model 1's), and
  PRH-AUTH-007 now fires in 5 of 5 held-out spraying runs. The results above stay in
  `results/rules_eval.json` under the labels `1.0 rules (addresses 1)` and
  `1.1 rules, step 28b (addresses 1)`.
- After scoring, only wording changed: PRH-AUTH-006's description said "in a day" for a maximum
  measured in a 3-hour log. Its logic and threshold are unchanged.

## ADR-0037: SonarQube Cloud analysis from CI, with reviewed rule exceptions

- **Date:** 2026-11-21
- **Status:** Accepted

**Context.** SonarQube Cloud's Automatic Analysis failed the quality gate of pull requests #59
and #60 on its "new code" security rating. Every finding was the same: path traversal
(`pythonsecurity:S2083`) and "LLM-supplied CLI arguments" (`pythonsecurity:S8707`) wherever a path
given on a command line is used to read or write a file. In a local tool the person running it
chooses the path and could read or write that file anyway, so these are not vulnerabilities. Two
code-level checks (resolving the path and comparing it with allowed roots) did not satisfy the
analyser. Automatic Analysis cannot ignore specific rules: its `.sonarcloud.properties` file only
accepts source and exclusion paths, without wildcards.

**Decision.**

- Analyse from GitHub Actions instead (`.github/workflows/sonarcloud.yml`, the official
  `SonarSource/sonarqube-scan-action` pinned by SHA, read-only permissions, a `SONAR_TOKEN`
  secret), configured by `sonar-project.properties`. Automatic Analysis is turned off in the
  project settings, as CI-based analysis requires.
- Ignore exactly those two rules in `scripts/` (developer tools, not shipped) and in five reviewed
  modules where the path is an output or settings file named on the command line:
  `llm/evaluate.py` (recordings and results), `enrich/config.py` (`--env-file`, read only, size
  capped, known keys only), and `ml/logeval.py`, `ml/transfer.py`, `ml/train.py` (results files).
  Both rules stay active everywhere else; a new finding fails the gate and is reviewed before a
  file is added.
- The job also runs the tests with coverage, so SonarQube Cloud shows coverage on new code. It is
  informational; the 85 % floor is still enforced by the CI test job.

**Consequences.** One more Linux job per push (about the length of the test suite, free on a public
repository). The analysis needs the secret, so it cannot run for pull requests from forks; outside
code contributions are not accepted (ADR-0033). Ruff, mypy, CodeQL and zizmor keep checking
`scripts/` and the excepted modules.

## ADR-0038: Simulator address model 2 and re-baselined rule scores

- **Date:** 2026-11-21
- **Status:** Accepted

**Context.** ADR-0036 missed its spraying goal because of the simulator, not the rules: every
customer shared `192.0.2.0/24` (and a bug put every IPv6 address in one /48), so the benign
per-network maximum was 19, PRH-AUTH-007's threshold 38, and held-out spraying from one provider
network (30 accounts) stayed under it. Any numbers measured on that background say little about
a real site, whose customers come from thousands of networks.

**Decision: address model 2** (`prohori.simulate.addresses`, `ADDRESS_MODEL = 2`, recorded in
every manifest and results file and printed by `prohori simulate`). Its parameters were fixed and
committed (d46e17b) before any rule was scored on it, from a stated source where one exists:

- Benign hosts (customers, web visitors, staff, admins) have one stable home address each.
  **18 % are on IPv6**, each in a /48 of its own: APNIC Labs measured 18.3 % IPv6 use in
  Bangladesh in 2025 ("Bangladesh's Internet transformation", blog.apnic.net, 3 November 2025),
  and the simulated shop is in Bangladesh (its admins work in Asia/Dhaka time). The rest are on
  IPv4 in `192.0.2.0/24` or `198.51.100.0/24`.
- **Five customers** (`users // 8`; thirteen in model 1) also sign in through one shared NAT
  address, so the per-network rule's stated false positive stays in the background. The size is
  the author's choice.
- SSH background probes are spread the same way. `203.0.113.0/24` is the attackers' provider
  network and holds no benign address.
- Attackers keep their scenario's meaning: default attacks from one address (two for credential
  stuffing); held-out SSH guessing (3 addresses) and password spraying (4) inside the one
  provider network; held-out credential stuffing, described as spread out, and every multi-source
  `heldout2` attack spread over every network. SIMULATOR.md lists each choice.

**Decision: the re-baselining procedure** (each step its own commit, in this order):

1. `results/rules_eval.json` keeps several named baselines, each with its address model
   (format `prohori.rules-eval/2`); a baseline is never extended on another model. The model-1
   results moved, number for number, to `1.0 rules (addresses 1)` and
   `1.1 rules, step 28b (addresses 1)`. Rule files exported from git (792a49b and 294f971) were
   first checked to reproduce the committed model-1 numbers; the only difference was the 1.0
   baseline's older list of expected rules, which grew in step 28b.
2. Address model 2 was committed.
3. The 1.0 rules (792a49b) and the step-28b rules (294f971) were scored on it, all three
   variants, and frozen as `1.0 rules (addresses 2)` and `1.1 rules, step 28b (addresses 2)`.
4. The thresholds were derived again with ADR-0036's unchanged rule on the default variants only
   (`scripts/benign_maxima.py`), and committed (38e1c12) before held-out scoring:

   | Measure (benign lines only, default variants) | Max (model 1) | Max (model 2) | Rule | Threshold |
   | --- | ---: | ---: | --- | ---: |
   | Addresses one existing account failed from, per hour | 2 | 2 | PRH-AUTH-005 | 4 (unchanged) |
   | Failures of one existing account in 24 hours (3-hour logs) | 11 | 10 | PRH-AUTH-006 | 22 -> 20 |
   | Existing accounts failing from one /24 or /48, per hour | 19 | 13 | PRH-AUTH-007 | 38 -> 26 |
   | Existing accounts / addresses failing in one log, per hour | 19 / 18 | 19 / 19 | PRH-AUTH-008 | 38 / 36 -> 38 / 38 |
   | Addresses with unknown-account failures in one log, per hour | 0 | 0 | PRH-AUTH-009 | 10 (reasoned, unchanged) |
   | Failures of one account, per hour | 6 | 7 | PRH-AUTH-010 | 12 -> 14 |

5. Targets were written down before scoring (PLAN step 28c): PRH-AUTH-007 fires in at least 4 of
   5 held-out spraying runs; held-out and `heldout2` credential stuffing stay caught in at least 4
   of 5; false-positive alerts on the default variants rise by at most 10 % of their total
   compared with the step-28b rules on the same simulator. Spraying spread over many networks is
   reported, not a target. Then every variant was scored once.

**Results** (address model 2; the generated tables are in RULES.md and SIMULATOR.md):

- PRH-AUTH-007 fired in **5 of 5** held-out spraying runs (12 alerts, all on attack lines); the
  step-28b threshold on the same simulator fired in none. Credential stuffing: 5 of 5 on both
  held-out sets. False-positive alerts on the default variants: 295 for the 1.0, step-28b and
  step-28c rules alike, a rise of 0. **Every target was met.**
- Attacks caught by at least one expected rule: held-out 35/40 (1.0), 40/40 (step 28b), 40/40
  (now); `heldout2` 30/40, 35/40, 35/40.

**What still fails.**

- Spraying spread over many networks (`heldout2`) is missed by every rule, as expected.
  PRH-AUTH-007 raised 4 alerts on `heldout2`, all on credential stuffing whose spread addresses
  shared a /24.
- PRH-AUTH-010's new threshold (14) is above the simulated account takeover's attempts (12, and 9
  held out), so it fires in no variant; PRH-AUTH-003 catches every takeover. The sample
  account-takeover log (12 failures) no longer raises it either, so the sample incident has three
  rules again and its id is `INC-ee7c8818fbb34989`. The threshold follows the rule; the scenario
  was not changed to suit it.
- PRH-AUTH-005 misses held-out SSH guessing (3 addresses against its 4); PRH-AUTH-006 catches it.
- With only three IPv4 documentation /24s, IPv4 customers are far more concentrated than on a
  real site, so the measured per-network maximum (13) is an upper bound.

**Consequences.**

- Everything derived from the simulator moved, because address draws share each scenario's
  random stream: the anomaly detectors' cut-off (z-score 12 -> 10, chosen again on the default
  variants by the frozen procedure) and results, the LLM evaluation cases and their hand-written
  references (22 recorded Gemini answers are stale until recorded again), goldens, the demo, and
  the benchmark logs. The CHANGELOG explains each change.
- The LLM answer check now accepts the network address of a per-network alert
  (`source.ip_prefix`): an answer naming `203.0.113.0/24` was rejected as citing an unknown
  address, a bug the new evaluation cases exposed.
- The Kafka transport retries the broker's start-up errors (no leader or no coordinator yet) on
  every call made at start-up, which made the Docker smoke test fail now and then.

## ADR-0039: Least privilege in the warehouse, safe connection strings, a durable broker

- **Date:** 2026-11-21
- **Status:** Accepted

**Context.** The Docker stack ran every stage, dbt and Airflow's jobs as the PostgreSQL superuser
(`prohori`, the image's `POSTGRES_USER`), so a bug or an injected statement in any of them could
read every database, create roles or run programs on the server (`COPY ... TO PROGRAM`). Its
connection strings were URLs with the password inside, which break on `@`, `/`, `:`, `#` or `%`.
Redpanda ran in `dev-container` mode, and the dashboards filtered unindexed time columns.

**Decision.**

- **An application role.** `warehouse-init.sql` creates `prohori_app` (`NOSUPERUSER NOCREATEDB
  NOCREATEROLE NOREPLICATION NOBYPASSRLS`), which owns the `raw`, `staging`, `intermediate`,
  `marts` and `analytics` schemas. It has CREATE on the database only because PostgreSQL checks
  that privilege for `CREATE SCHEMA IF NOT EXISTS` even when the schema exists (checked against
  the stack's PostgreSQL 17), and the sink and dbt issue that statement. It is never granted a
  predefined role such as `pg_execute_server_program`, and `PUBLIC` loses CONNECT on Airflow's
  database. The stages, dbt and Airflow's jobs connect as `prohori_app`; the superuser only runs
  `warehouse-init`. Its password stays `PROHORI_POSTGRES_PASSWORD` (it is fixed when the volume
  is created, so renaming it would break existing stacks); the new role's is
  `PROHORI_APP_DB_PASSWORD`.
- **In-place migration.** On every start, `warehouse-init` hands the five schemas, and every
  table, view, materialised view and free-standing sequence in them, to `prohori_app` with a
  `DO` block over `pg_class`. `REASSIGN OWNED BY prohori` cannot be used: the bootstrap superuser
  owns the system catalogs and the database. Grafana's default privileges cover tables created
  by either role. Tested against a database built by the 1.0 script (tables, a view, a mart and a
  serial column owned by the superuser): after two runs every object belongs to `prohori_app`,
  the sink connects and adds its indexes, a dbt-style mart replacement works and Grafana reads it.
- **Connection strings.** Compose never puts a password in a URL: the stages and Airflow's jobs
  get a keyword DSN without a password and `PGPASSWORD`, which libpq reads; Airflow's own
  database URL is built by every Airflow process (`AIRFLOW__DATABASE__SQL_ALCHEMY_CONN_CMD`) with the password URL-quoted. On the host,
  `prohori.pipeline.stack.default_dsn` builds a keyword DSN with every value quoted. The smoke
  tests use passwords containing `@/:#%41`, a space and a quote (`%41` would turn into `A` if
  anything URL-decoded it).
- **Indexes** (PostgreSQL, created with the tables, so idempotent and applied to old stacks):
  `events(timestamp, stored_at)`, `alerts(last_seen, stored_at)`, `incidents(first_seen,
  last_seen, stored_at)` and `dead_letters(stored_at)`. The plan named `incidents(last_seen)`;
  the dashboards filter incidents by `first_seen`, so both are indexed, and the pipeline-health
  panels filter by `stored_at`. A unit test ties every dashboard time filter to an index, and the
  smoke test checks with `EXPLAIN` (sequential scans off, since a few thousand rows always fit a
  sequential scan) that each such query can use one. **DuckDB gets none**, against the plan:
  DuckDB's documentation says its ART indexes serve "point and very highly selective (i.e., <
  0.1%) queries" and equality or `IN` filters, slow loading, and use buffers "not yet
  buffer-managed", while the min-max indexes it creates automatically already skip row groups
  for range filters on ordered columns such as timestamps.
- **Redpanda syncs to disk.** Its documentation says `--mode dev-container` bundles
  `--unsafe-bypass-fsync` and `write_caching_default: true`. Dropping the mode was not enough:
  the image's own `redpanda.yaml` sets `developer_mode: true` and write caching, and with it rpk
  still passed `--unsafe-bypass-fsync=true`. The stack now passes
  `--unsafe-bypass-fsync=false`, `--set redpanda.developer_mode=false` and
  `--set redpanda.write_caching_default=false`, plus the container flags it needs
  (`--overprovisioned`, `--reserve-memory=0M`, `--check=false`); a one-shot `redpanda-init`
  service sets `write_caching_default` to false on a cluster created before, since `--set` only
  seeds a new cluster. Measured on the same machine, twice each: about 2.3-2.6 s to healthy and
  about 70 MB of memory either way.
- **Refused messages.** A message the Kafka client or broker refuses for its own sake
  (`MSG_SIZE_TOO_LARGE`, `RECORD_LIST_TOO_LARGE`, `INVALID_RECORD`, `INVALID_MSG`, not fatal)
  becomes a dead letter (stage `kafka-producer`), delivered before the batch is committed. Any
  other error still fails the batch, as before; a refused dead letter raises.
- **A consumer whose start-up read failed is replaced.** With fsync on, the local smoke test
  failed in 2 of 4 runs: everything started, the replay was published, and no event reached the
  warehouse for four minutes, without an error. A consumer whose first fetch of the group's
  committed offset fails ("Not coordinator") may never fetch it again; step 28c had made that
  error a silent retry, where before it crashed the stage and the restart recovered. The
  transport now closes that consumer and starts a fresh one on that read. Three runs in a row
  passed afterwards.

**Consequences.**

- Upgrading keeps working without any setting: the defaults of both passwords are local-only
  values, and `warehouse-init` migrates ownership on the first `up`. A user who set
  `PROHORI_POSTGRES_PASSWORD` keeps it for the superuser and should also set
  `PROHORI_APP_DB_PASSWORD`. An explicit `PROHORI_POSTGRES_DSN` still wins; pointing it at the
  superuser works but gives up the least privilege.
- Creating the indexes on a large existing table blocks writes to it once, on the first start.
- Fsync costs throughput under heavy load; it was not measurable at the stack's volumes here.
- Dead letters for refused messages are not counted in the stage's own `dead_letters` counter
  (the transport writes them); they are in the warehouse like any other.

---

## ADR-0040: Time-block validation and model files without pickle

- **Date:** 2026-11-21
- **Status:** Accepted

**Context.** Two weaknesses of the 1.0 flow models (plan items A6 and A7). First, the validation
split was rows drawn at random from the training data, so flows captured moments apart, often
near-copies, sat on both sides; on UNSW-NB15 the threshold chosen for a 1 % false-positive rate
gave 4.5 % on the test file, and ADR-0019's amendment named the random split as the likely
cause. Second, models were joblib pickles: loading one runs code from it, the JSON sidecar only
caught accidents, and a model made with other library versions loaded silently and could score
differently.

**Decision.**

- **Time blocks.** Each class's rows are put in time order (CIC-IDS-2017: the capture
  timestamp; UNSW-NB15's partition files have none, so the file order, `id`) and cut into 50
  contiguous blocks; whole blocks are held out, chosen by the seed. Validation is about 20 % of
  each class's training blocks. CIC-IDS-2017's test split is also made of blocks (about 30 %),
  so its comparison between methods is not biased by a random test split. Whole capture days
  were rejected: every CIC-IDS-2017 attack class was captured on one day, so holding out days
  would leave classes out of training. Blocks are per class so every class keeps training rows;
  for benign traffic, which is what thresholds are set on, a block is a true time window.
- **The leakage test checks times, not labels.** `check_time_blocks` fails if any training row
  lies inside the time range of a held-out block of its class, so a split that labelled blocks
  correctly but moved rows would still be caught. The order and block columns are internal:
  never features, never part of a deduplication key.
- **Chosen by measurement.** Every run measures three ways of choosing thresholds on the same
  test split: time-block validation, out-of-fold (five models on folds of whole time blocks of
  training and validation, final model fitted on all of it) and 1.0's random rows. The rule was
  written down before the full runs (`prohori.ml.train.SELECTION_RULE`): the lower mean
  |test FPR / target - 1| over both datasets, both models, both targets and three seeds wins;
  time-block wins a difference under 0.05; random is never chosen. Result: time-block 0.354,
  out-of-fold 0.476, random 0.770. Time-block is used for the published numbers and saved
  models. The choice used the test split once, to pick a method, never a threshold; that is
  disclosed in the model card.
- **skops by default.** Models are saved as skops files (zip archives of plain data, read
  without pickle). Loading trusts only the types skops trusts plus an explicit list measured on
  both detectors (`SKOPS_TYPES`), never the types a file declares. The `Detector` dataclass is
  stored as a plain dict and rebuilt. Sidecars are named per file (`m.skops.json`), so a 1.0
  `m.joblib` and its `m.json` never collide; saving `m.skops` removes them.
- **1.0 joblib files keep loading**, through joblib's unpickler with `find_class` limited to the
  30 globals the 1.0 models need (`JOBLIB_GLOBALS`), measured on all twelve. joblib stores an
  array of Python objects (an encoder's categories) as a nested pickle, which joblib before 1.6
  read with a plain `pickle.load`, past any `find_class`; Prohori reads that nested pickle
  itself, through the same allowlist, whatever the joblib version (tested by putting the old
  behaviour back). This relies on joblib internals; a test loads a freshly saved joblib model
  through them so an upgrade fails loudly. Static scanning with `pickletools` was rejected: joblib writes raw array bytes inside
  the pickle stream, which stops the scan. `scan_joblib` lists what a file asks for, standing in
  a harmless object for refused globals, which step 63's `prohori model scan` builds on.
- **Versions.** The sidecar records Python, scikit-learn, numpy and pandas; loading refuses a
  different major or minor version before any byte is deserialised, unless
  `--allow-version-mismatch` (a warning). 1.0 sidecars recorded scikit-learn only: it is
  checked, and a warning names the libraries that were not recorded, so those models still load.
- **`prohori score --sha256`** compares the file with a hash given out of band, the one check an
  attacker who can replace both the model and its sidecar cannot pass.
- **The recall gate** of the nightly evaluation moves from 0.75 to 0.62: 1.0's 0.8175 came with
  a threshold that let through 4.5 % false positives; at a true 1 % the mean is 0.6887, and the
  gate keeps about the same margin. The nightly run skips the calibration study (`--no-study`).

**Consequences.**

- On UNSW-NB15 the 1 % threshold now holds (0.91 % on test; 4.76 % with random validation rows
  in the same code), and gradient boosting's recall at that rate falls from 81.8 % to 68.9 %;
  at 0.1 % it falls from 46.0 % to 24.7 %. PR-AUC barely moves (0.952 to 0.950): the model is
  the same, the thresholds were too loose. That supports the cause named in ADR-0019's
  amendment, though not the mechanism exactly: benign validation flows with a near-duplicate in
  training (two significant digits) are 1.2 % with random rows and 0.7 % with time blocks, too
  few to explain a fourfold shift alone. The file order of the training file carries the rest
  (its benign rows come in long runs), and so does the remaining difference between the training
  and testing files, which no split inside the training file can remove.
- On CIC-IDS-2017 little moves: thresholds held before and hold now; near-duplicates are 17 to
  19 % with either split, because benign traffic there repeats all week rather than in bursts.
- Out-of-fold made gradient boosting's thresholds too strict on UNSW-NB15 (0.30 % test FPR at
  the 1 % target) and too loose on CIC-IDS-2017 (1.70 %): models fitted on four fifths of the
  data score differently from the final model.
- `skops` (MIT) joins the `ml` extra. skops files are larger than compressed joblib files.

---

## ADR-0041: Pre-registration of the cross-dataset generalisation study

- **Date:** 2026-11-21
- **Status:** Accepted (pre-registered: written and pushed before any run on the real datasets)

**Context.** A gradient-boosting flow model trained on one public dataset loses most of its
signal on the other (step 16; ROC-AUC about 0.95 within a dataset, 0.59 and 0.64 across). Step
30b asks which low-compute methods close how much of that gap without leaking the target
dataset. To keep the results from being cherry-picked, everything below was fixed before the
experiments were run. Anything added later is labelled *exploratory, not pre-registered* in the
results and the write-up.

**Questions.**

1. Q1: How much of the gap does each unsupervised method (unlabelled target data only) close?
2. Q2: Does dropping the features that differ most between the datasets help?
3. Q3: How much do k labelled target flows help (an upper bound, not an unsupervised method)?

**Data and roles.** For each seed s in 0, 1, 2 both datasets are prepared with every leakage
control of steps 14 and 30 (time-block splits) and mapped to the twelve common features with
`prohori.ml.transfer.common_splits`, exactly as in step 16. Both directions are studied
(UNSW-NB15 to CIC-IDS-2017 and back). Roles:

- source `train`: labelled, for fitting the model; source `validation`: labelled, for thresholds;
- target `train`: the **unlabelled pool**. Its features may be used by the methods allowed to
  see target data; its labels only by the few-shot arms and the reference arm;
- target `validation`: used only by the reference arm (its thresholds);
- target `test`: evaluation only; nothing is fitted on it.

**Model.** scikit-learn `HistGradientBoostingClassifier` with step 15's fixed settings
(`prohori.ml.models.PARAMS["hgb"]`, `random_state = s`), never tuned. The Isolation Forest is
excluded: steps 15 and 16 found it catches under 5 % of attacks at a 1 % false-positive rate even
within a dataset, so there is no in-dataset signal to transfer.

**Arms.** Features are the twelve common features; missing values (a rate over a zero duration)
are imputed with the source training medians as in step 16, except where an arm says otherwise.
`protocol` (6, 17, 1 or -1, a code) is never transformed. "Per-domain" means fitted separately
on the source training features and on the target pool, each applied to its own domain. A
transform applied identically to both domains is pointless for a tree model, which bins
features by quantiles; only per-domain transforms can change anything.

| Arm | What it does | Sees target |
| --- | --- | --- |
| `baseline` | Step 16 unchanged | nothing |
| `standardise` | `sign(x) log1p(abs(x))`, then per-domain mean and standard deviation (missing values imputed per domain with that domain's median first) | pool features |
| `quantile` | Per-domain `QuantileTransformer` (uniform output, 1,000 quantiles, fitted on at most 200,000 rows sampled with seed s), missing values imputed per domain first | pool features |
| `quantile-protocol` | As `quantile`, but fitted per domain and per protocol group (TCP, UDP, other); a group with fewer than 1,000 rows in either domain uses that domain's all-protocol transform | pool features |
| `coral` | `standardise`, then CORAL (Sun, Feng and Saenko, AAAI 2016): source features multiplied by `Cs^-1/2 Ct^1/2`, with `C = cov + I` (regularisation 1 on standardised features); matrix powers by symmetric eigendecomposition (`numpy.linalg.eigh`), eigenvalues floored at 1e-6 | pool features |
| `importance` | Covariate-shift weights: a domain classifier (HGB, 100 iterations, otherwise default, `random_state = s`) separates source training rows from an equal-size sample of the pool (or the whole pool if smaller), cross-fitted in 2 folds so no row is scored by a model that saw it; `w = p / (1 - p)`, clipped to [0.05, 20], normalised to mean 1, used as `sample_weight` when fitting | pool features |
| `invariant` | Drop every non-protocol feature whose univariate domain ROC-AUC (`max(auc, 1 - auc)` of the raw values, source training rows against the pool) is 0.9 or more; if fewer than 4 features would remain, keep the 4 with the lowest domain AUC | pool features |
| `few-shot-k`, k = 10, 50, 100 | `baseline`, plus k labelled flows drawn from the pool, stratified by label with at least one attack and one benign flow; each drawn flow gets weight `0.1 n_source / k` (the k flows weigh as much as 10 % of the source rows); 5 draws per seed (draw seeds `1000 s + d`, d = 0..4) | k pool labels |
| `target-reference` | HGB trained on the target's own training split, thresholds on its validation split: the in-dataset ceiling, reported as a reference, never as a method | target labels |

Thresholds of every arm except `target-reference` come from the **source** validation split
(benign flows, transformed with the source's transforms) for a 1 % false-positive rate, and are
frozen before the target test split is scored. HGB's `min_samples_leaf` counts rows, not weight,
so ten heavily weighted few-shot flows can shift splits but not form a leaf of their own; this is
accepted as part of the arm.

**Metrics** on the target test split, per seed:

- **Primary:** ROC-AUC (independent of the attack share, which differs between the datasets).
- Secondary: PR-AUC with its chance level (the attack share); recall and the false-positive rate
  reached at the frozen 1 % threshold (what a deployment would see); recall at a 1 %
  false-positive rate read off the target ROC curve (threshold-free, not deployable).
- Gap closed, `(AUC_arm - AUC_baseline) / (AUC_reference - AUC_baseline)`, is secondary; the
  headline is the absolute ROC-AUC difference to `baseline`.

**Statistics.** Per seed, 1,000 bootstrap resamples of the target test rows (multinomial counts,
generator seed `10,000 + s`), shared by every arm of that seed so differences are paired; each
resample's metric is averaged over the three seeds; 95 % percentile intervals for ROC-AUC,
PR-AUC and the ROC-AUC difference to `baseline`. Few-shot arms first average their five draws.
**An arm "helps" only if** the 95 % interval of its ROC-AUC difference to `baseline` excludes 0
and the difference has the same sign in all three seeds, **in both directions**. The bootstrap
captures evaluation noise only, not training variance, hence the per-seed sign condition. Every
arm is reported, whatever its result; a method that helps in one direction only is reported as
such and not called helpful.

**Harness check.** Before any arm is interpreted, `baseline` must reproduce
`results/ml_cross.json`'s gradient-boosting cross-dataset ROC-AUC for each seed, and
`target-reference` the reverse direction's in-dataset ROC-AUC.

**Diagnostics, always reported:** the overall domain-classifier ROC-AUC (cross-fitted), each
non-protocol feature's domain AUC, each domain's share of each protocol code, the importance
weights' effective sample size `(sum w)^2 / sum w^2` over n and the share of weights at either
clip, the features `invariant` dropped, and each pool's attack share.

**Threats to validity, stated in advance.**

- Twelve shared features measured by different tools limit everything (the main threat).
- The unlabelled pool is a lab training split with a large attack share, unlike real unlabelled
  traffic, which is mostly benign. Per-domain transforms and the domain classifier therefore
  partly align attack mix (label shift), not only covariate shift.
- The pool was cleaned with its labels (rows with equal features and different classes were
  removed), a small label leak shared by every arm.
- Two datasets, one pair, three seeds, one model family.

**Not run, with reasons.** Adversarial neural methods (DANN and similar): they need a deep
learning framework and are not expected to finish under an hour on a CPU at these sizes;
recorded as future work. A third dataset: none with a fitting licence and size is in the
repository, and adding one needs the owner to download it; recorded as future work.

**Deliverables.** `prohori.ml.adapt` (the transforms, weights, selection, few-shot sampling and
paired bootstrap, each unit-tested), `scripts/cross_dataset_study.py` (writes
`results/ml_adapt.json` without timings, so a rerun from the same seeds, lockfile and platform
is byte-identical; CORAL's linear algebra may differ on other platforms) and generated tables in
the model card and the README.

**Leakage tests.** Shuffling the pool's labels leaves every arm except `few-shot-k` and
`target-reference` scoring the target test split identically; changing target test features
leaves every fitted transform, weight and selection identical; the few-shot arm reads exactly k
target labels.

*Outcome, added after the runs (2026-11-21; nothing above was changed):* the harness check
passed exactly (baseline and reference reproduce `results/ml_cross.json` seed by seed). Of the
unsupervised arms only the per-domain quantile map helps in both directions (ROC-AUC +0.188 and
+0.034); importance weighting improves one direction and worsens the other; per-domain
standardisation, CORAL and the per-protocol quantile map do not help, and the invariant arm
dropped no feature (every univariate domain AUC was under 0.79) and equals the baseline. Every
few-shot arm helps in both directions; 10 labelled flows match the quantile map. The domain
classifier separated the datasets perfectly (ROC-AUC 1.000), leaving 98 to 99.5 % of importance
weights at a clip. A second full run gave a byte-identical results file. Tables: the model card's
"Cross-dataset study".

---

## ADR-0042: Logins for the Docker stack, Kafka authentication and release SBOMs

- **Date:** 2026-11-22
- **Status:** Accepted

**Context.** Until 1.1 the Docker stack assumed a single-user machine: Grafana showed every
dashboard to anonymous visitors, Airflow made everyone who reached its port an admin, and
Redpanda accepted any client. Ports are bound to 127.0.0.1, but on a shared or networked machine
(other local users, containers on the same Docker host, a forwarded port) that is not enough.
Releases also did not say what they contain.

**Decision.**

- **Generated secrets in `pipeline/.env`.** The first real compose command (`prohori pipeline
  up`, `down`, `status`) writes five random passwords (32 URL-safe characters, never `$`, which
  Compose would interpolate) into `pipeline/.env`: Grafana's admin, Airflow's user and three Kafka
  users. The file is git-ignored, created with owner-only permissions on POSIX systems, read by
  Docker Compose by itself, and never rewritten: a value is generated only when its line is
  missing. Environment variables of the same name win. The compose file requires every one
  (`${VAR:?}`), so no weak default ships, and plain `docker compose` fails with a message that
  says to run `prohori pipeline up` once. Unit tests never write the file (only a real run does).
- **Grafana:** anonymous access off; the admin password from the file.
  `PROHORI_GRAFANA_ANONYMOUS=true` restores 1.0's read-only anonymous access.
- **Airflow:** the simple auth manager with one user, `prohori` (admin role), whose password is
  written to the manager's password file inside the container before Airflow starts, so Airflow
  neither generates nor prints one. The health endpoint stays open for the container check.
- **Redpanda:** SASL/SCRAM-SHA-256 on the Kafka API, set up by `pipeline/redpanda/init.sh` on
  every `up`: users are created or given their current password, `prohori-admin` becomes the only
  superuser, SASL is turned on, and ACLs are created. `prohori-stage` (the stage containers) may
  do anything on the five Prohori topics and the `prohori-*` consumer groups;
  `prohori-producer` (`replay` and `tail --bootstrap`, Airflow's jobs) may create and describe the
  topics and write only `raw-logs` and `dead-letter`, and cannot join a consumer group. A stack
  created by an earlier version is converted on its first `up`. Clients read
  `PROHORI_KAFKA_USER` and `PROHORI_KAFKA_PASSWORD`; for the stack's own address the CLI falls
  back to the producer login in `pipeline/.env`.
- **Not done, accepted:** TLS on the Kafka listeners (documented as optional: the external
  listener is bound to 127.0.0.1), and a login on Redpanda's admin API (port 9644). That API is
  not published; only containers on the stack's private network can reach it, and it is what the
  health check and `redpanda-init` use. Turning on admin-API authentication would mean passing the
  administrator's password to the health check, for little gain on one host.
- **Printing passwords:** `pipeline up` prints the Grafana and Airflow passwords once when it
  generates them, and only when standard output is a terminal, so CI logs (the repository is
  public) show the file's path instead.
- **SBOMs.** Every release run (and its dry run on a pull request) writes two CycloneDX files: the
  Python package's dependency set from `uv.lock` (`uv export --format cyclonedx1.5`, the base
  install and every extra, not development tools) and the image's contents (syft through
  `anchore/sbom-action`, linux/amd64; syft pinned). On a tag both are attested with
  `actions/attest-sbom` (the package SBOM bound to the wheel and sdist, the image SBOM pushed to
  the registry next to the image) and kept as artifacts the maintainer attaches to the GitHub
  release. The action's own uploads are turned off, so no job gains `contents: write`.

**Consequences.** The dashboards and Airflow need a login (the password is in `pipeline/.env`);
outside Kafka clients need credentials. The README, PIPELINE, DASHBOARD, ORCHESTRATION, CLI and
THREAT_MODEL documents and the wiki say so. `prohori pipeline up` stays a one-command start.
