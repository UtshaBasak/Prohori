# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- The stage image builds again: an automatic update had moved it to Python 3.15, which Prohori
  does not support yet (no wheels for its dependencies). It is back on Python 3.13, and
  PostgreSQL is back on 17: version 18 cannot open a data volume written by 17. Dependency
  updates no longer propose new major versions of the images, or a new Python minor version.

## [1.0.1] - 2026-11-03

Fixes from a review of the whole project. The command line, the output formats and the rule
format are unchanged.

### Security

- Redaction now covers indicators' enrichment data: `--redact-ips` replaces the network
  (`203.0.113.0/24` became `[ip:...]/24`) and any address or email in provider data, and the
  fail-closed check searches it too. Account values are matched in any letter case and next to
  `@` (`alice@bastion`), and emails with non-ASCII letters are found.
- LLM analyst: enrichment values are fenced and capped; a payload still over
  `PROHORI_LLM_MAX_INPUT_TOKENS` after trimming is not sent (exit 1); `prohori ask` redacts the
  question with the incident's key; restored values are cleaned before display.
- The answer checks see through disguises: compressed IPv6 addresses, defanged and full-width
  addresses, unparsable dotted quads, detector ids in any case, Markdown link and image targets,
  scheme-less and non-https links, and backslash host tricks.
- Airflow: run parameters reach the task scripts only as quoted environment variables, so a
  backfill `start` value can no longer inject shell commands; `start` is checked by a pattern.
- Parsers remove control characters that JSON (``) or nginx (``) escapes decode to,
  so a log value cannot send terminal escape sequences to `parse`, `detect` or `incidents`.
- A sudo command line can no longer overwrite the target user or command recorded before it.
- `::/96` (IPv4-compatible IPv6) is never sent to enrichment services.
- Grafana's database role is read-only by default, with a 15-second statement timeout and at
  most five connections.
- A crash never prints local variables (Typer's `pretty_exceptions_show_locals` is off).
- Model files are hashed and loaded from the same bytes.

### Fixed

- A timestamp at the edge of the calendar (year 1 or 9999 with an offset) is a line error
  instead of crashing the whole run.
- The Docker stack no longer writes a partial incident when a stage is stopped between two parts
  of an attack: the detector and the incident stage rebuild their state on the next start
  instead of releasing it. A long rebuild keeps the stage healthy (heartbeat per batch).
- A shared address is one seen with more than ten accounts, as documented, rather than ten
  (field, value) pairs: an account known by id, name and email hash counts once.
- `report -o` and `triage -o` with a directory, a missing directory, or (for `report`) the
  incident file itself are usage errors (exit 2), checked before any work, instead of a
  traceback.
- One event with a future timestamp no longer stops `dbt build` from rebuilding every mart (the
  check is a warning).
- Lite mode flushes consumer positions and tailer checkpoints to disk before replacing them.
- An unparseable access-log request is kept as written (`...`) instead of decoded.
- `LLMSettings.load(environ={})` no longer falls back to the process environment.

### Added

- Releases sign a provenance attestation for the wheel and sdist; the bundle is attached to the
  GitHub release (`gh attestation verify`).
- An "All checks passed" CI job that fails when any other job fails, for branch protection.
- Dependabot also updates the digest-pinned images (stage, Airflow, Redpanda, PostgreSQL,
  Grafana) and the Airflow image's hash-pinned drivers.
- Documentation and Security links in the package metadata.

### Changed

- CI fails when `uv.lock` does not match `pyproject.toml` (`UV_LOCKED`), every job has a
  timeout, and the fuzzer and twine are pinned.
- Documentation: the docs index lists every document; corrected the model card's false-alert
  arithmetic, the threat model's dataset-hash claim, the LLM analyst's size cap, and stale
  README lines; ADR-0032.

## [1.0.0] - 2026-11-02

The first stable release: the batch core, machine learning and the streaming pipeline from
0.1 to 0.3, now with an opt-in LLM analyst, a threat model, performance measurements on a
million-line log and macOS in CI. The command line, the output formats and the rule format follow
semantic versioning from here on.

### Highlights

- An opt-in LLM analyst: `prohori explain` and `prohori ask`, with redaction before anything is
  sent, prompt-injection defences, answer checks and an offline evaluation.
- `docs/THREAT_MODEL.md`: assets, trust boundaries, threats, the control for each and the
  residual risks.
- `docs/PERFORMANCE.md`: throughput and peak memory on logs of more than a million lines.
- Every measured number in the README is generated from a result file.

### Added

- `scripts/benchmark.py` measures `incidents` on a million-line log in each format, lite mode and
  the demo, each in its own process, and writes `results/performance.json`; the tables in
  `docs/PERFORMANCE.md` and the README are generated from it.
- `docs/THREAT_MODEL.md`, linked from `SECURITY.md`.
- `docs/LICENSES.md` completed: the Gemini API terms, every Python dependency and extra with its
  licence from the package metadata, Airflow's drivers, and what the container image on GitHub
  Packages redistributes.
- macOS in CI (Python 3.13), and the release's wheel check and install-from-PyPI check on Linux,
  Windows and macOS. Both fail if `prohori demo` takes longer than a minute.
- A CI check that the core packages (schema, parsers, rules, enrichment, incidents, reports,
  command line) keep at least 85 % test coverage.
- The README's worked example, the flow-model findings, the cross-dataset sentence and the LLM
  evaluation's case counts are generated from the sample incident and the result files; a test
  pins the README's rule and scenario counts to the code.
- The opt-in LLM analyst (`docs/LLM_ANALYST.md`, ADR-0028): `prohori explain INCIDENT` explains
  an incident in plain language.
  - Off by default (`PROHORI_LLM_PROVIDER=none`): nothing is sent and the command says so.
  - Providers `none`, `mock` and `gemini`, the last through the official `google-genai` SDK in
    the `llm` extra, with a configurable model (default `gemini-3.5-flash-lite`).
  - What is sent is an allow-list of fields with account names, ids and emails replaced by
    keyed pseudonyms (`--mask-ips` for addresses too), no event descriptions from the logs, and
    a size cap. Nothing is sent if any replaced value would remain. `--show-payload` prints it
    without sending.
  - A daily request budget, a timeout and no automatic retries. A local summary is shown
    whenever the provider cannot answer, saying why and whether anything was sent.
  - A reminder on every free-tier request that Google may use what is sent.
- Grounded answers and prompt-injection defences for the LLM analyst (ADR-0029):
  - `prohori ask "QUESTION"` answers from ATT&CK and the runbooks, optionally about an incident
    (`-f`); offline it shows the best-matching sources;
  - BM25 retrieval over every active Enterprise ATT&CK v20.0 technique (shortened descriptions
    built from the pinned STIX bundle by `scripts/build_attack_corpus.py`) and the runbooks;
    `explain` now gives the model the incident's techniques and runbook actions as sources;
  - values that can carry log content are fenced with a random nonce, and the fence cannot be
    forged or closed from inside;
  - answers citing an address, email, pseudonym, incident, rule or technique not in the
    incident's identity fields or the sources, or linking anywhere but attack.mitre.org, are
    rejected in favour of the local answer;
  - read-only tools (knowledge search, one technique, one alert) with a call limit
    (`--max-tool-calls`);
  - an injection fixture suite with instructions hidden in user agents, usernames and paths.
- An offline evaluation of the LLM analyst (`docs/LLM_ANALYST.md#evaluation`, ADR-0030):
  - 30 cases with truth labels from the simulator: 15 attacks, 7 false positives and 8
    incidents with an instruction hidden in a user agent, a request path or a username;
  - a hand-written reference for each, with the indicators and points a good answer covers and
    the statements that would be false;
  - `python -m prohori.llm.evaluate record` saves answers once (a real model resumes where its
    daily budget stopped it); `score` replays them through the same checks offline and writes
    `results/llm_eval.json`;
  - factual errors, indicators named, points covered and whether injections were followed,
    for the model's answer and for what the analyst is shown; the tables in the docs and the
    README are generated from the results;
  - baselines: the local summary, the mock and a scripted model that obeys every injection;
  - one recorded run of Gemini (gemini-3.5-flash-lite): all 30 answers passed the checks with
    no factual error by these measures, every reference indicator named, 84 of 89 points
    covered and no injection followed.

### Changed

- Development status: Production/Stable. `SECURITY.md` supports 1.0.x.

### Fixed

- Lite mode on Windows: saving a consumer position could fail with "access denied" when another
  process, such as a virus scanner, briefly had the file open, which stopped a long replay. The
  rename is now retried for up to about two seconds.
- The mock LLM provider failed on an incident whose user agent contained `</incident>`.

- Docker stack start-up: a stage whose new Kafka consumer still found a just-created topic
  unknown crashed and restarted, which could make `prohori pipeline up` report the stack
  unhealthy. The topic's offsets are now asked for again until the broker knows it.

## [0.3.0] - 2026-11-02

### Added

- Scheduled jobs with Apache Airflow 3.3.2 (`pipeline/airflow/`, `docs/ORCHESTRATION.md`,
  ADR-0027), in the stack's new `orchestration` profile (`prohori pipeline up --orchestration`,
  Airflow on http://127.0.0.1:18080):
  - `prohori_backfill`: replays the eight simulated scenarios with their labels and builds the
    marts;
  - `prohori_data_quality`: hourly `dbt build` and a freshness check on the events;
  - `prohori_nightly_evaluation`: retrains the flow models and fails if recall drops below the
    minimum;
  - `prohori_incident_digest`: a daily digest of incidents, rules and dead letters;
  - `prohori_enrichment_refresh`: keeps the incident stage's enrichment cache current, offline
    unless API keys are configured.
- `prohori pipeline digest`, `check-recall` and `refresh-enrichment`, the commands the jobs run.
- DAG integrity tests (imports, cycles, settings) in a Linux CI job with Airflow installed, and
  a Docker smoke test that runs every DAG in the stack.
- The Docker image on GitHub Packages, `ghcr.io/utshabasak/prohori`, for linux/amd64 and
  linux/arm64 with a provenance attestation, published by the release workflow.

- Grafana dashboards in the Docker stack (`pipeline/grafana/`, `docs/DASHBOARD.md`, ADR-0026),
  provisioned from files and open without a login at http://127.0.0.1:13000:
  - **Overview**: events, alerts and incidents over time, rule hits, top source addresses and the
    latest incidents, from the raw tables, so it fills right after a replay;
  - **Detection quality**: rule precision, time to detect each simulated attack, detection
    latency, top sources and flow-model performance, from the dbt marts;
  - **Pipeline health**: time since the last stored event, rows stored per minute, table sizes
    and dead letters;
  - a read-only `grafana` database role, created by a new one-shot `warehouse-init` service;
  - `prohori pipeline up` and `status` print the dashboards' address;
  - tests for the dashboard definitions, and Docker smoke-test checks that run every panel's
    query through Grafana.

- Warehouse models with dbt (`pipeline/dbt/`, `docs/WAREHOUSE.md`, ADR-0025), built on the
  lite-mode DuckDB file and on the Docker stack's PostgreSQL:
  - staging and intermediate views and nine marts: daily attack counts, alerts per rule and day,
    top source addresses, incident durations, rule precision, per-alert and per-rule detection
    latency, time to detect each simulated attack, and flow-model performance over time;
  - 68 data-quality checks (keys, nulls, accepted values, ranges, duplicates, cross-table
    consistency, future timestamps, dead letters) and source freshness on `stored_at`;
  - `prohori pipeline load-labels` (simulator ground truth per event) and
    `prohori pipeline load-results` (flow-model evaluations), both idempotent;
  - `scripts/build_lite_warehouse.py` and a `dbt (DuckDB)` CI job that checks rule precision
    against the simulator's own evaluation; the Docker smoke test builds the models on
    PostgreSQL;
  - a `stored_at` column on every warehouse table, and the table definitions shared by both
    databases in `prohori.pipeline.tables`.

- The Docker stack (`pipeline/docker-compose.yml`): Redpanda, PostgreSQL and one container per
  pipeline stage, with digest-pinned images, health checks, memory limits (about 3.3 GB) and
  ports on 127.0.0.1 only:
  - a Kafka transport (confluent-kafka) with one partition per topic, synchronous commits, an
    idempotent producer whose flush fails on any delivery error, and topics created with
    unlimited retention;
  - a PostgreSQL sink (psycopg 3) writing a `raw` schema with `ON CONFLICT DO NOTHING`; both
    sinks now replace NUL characters and retry a rejected batch row by row, turning rows the
    database still rejects into dead letters;
  - `prohori pipeline up`, `status` and `down`; `prohori pipeline run --stage` for one stage per
    container, with a heartbeat file and `--idle-close`; `replay --bootstrap` and
    `tail --bootstrap` to publish into the stack;
  - a Docker smoke test (`PROHORI_DOCKER_TESTS=1`) and a `Docker stack` workflow that runs it on
    Linux;
  - ADR-0024, the Docker section of `docs/PIPELINE.md` and the pipeline software licences in
    `docs/LICENSES.md`.

- Streaming pipeline in lite mode (`prohori.pipeline`, `pipeline` extra with DuckDB), running
  the batch core continuously without Docker:
  - topics `raw-logs`, `events`, `alerts`, `incidents` and `dead-letter` with keyed JSON
    messages, and a transport protocol with in-memory and file (JSON Lines) implementations;
  - consumers normalise -> detect -> incidents and a DuckDB sink, with at-least-once delivery,
    writes keyed by content-derived ids (a replay or redelivery adds no rows), duplicate events
    dropped before the rule engine, and dead letters for unparseable lines and malformed
    messages, with counters;
  - incidents close once their alert group can no longer grow; the stream's incidents equal
    those of `prohori incidents` for every simulator scenario (integration test, replayed
    twice);
  - a rotation-aware file tailer (rename and truncate rotation, saved positions, Windows file
    sharing so writers can still rotate) and a file replayer;
  - `prohori pipeline replay FILE...` and `prohori pipeline tail FILE...`, with graceful
    shutdown and a table of counters;
  - `docs/PIPELINE.md` and ADR-0023.
- `LineParser.parse_raw` parses one line without resetting the parser.

### Changed

- The incident builder's event memory ignores an event it has already seen before updating the
  sign-in history, so a replayed event cannot count twice.

### Fixed

- Docker stack start-up: PostgreSQL's health check connects over TCP, so it no longer passes
  while the first start is still initialising the database, and the Kafka transport waits until
  every topic has a leader before using it.

## [0.2.0] - 2026-10-31

Machine learning, evaluated honestly: anomaly detection on your own logs, and intrusion-detection
models on two public flow datasets with leakage controls, a model card and a cross-dataset test.

### Highlights

- `--models` on `detect`, `incidents` and `triage`: anomaly detectors flag source IPs that behave
  unlike the rest of the log; their alerts join the incidents.
- Leakage-controlled UNSW-NB15 and CIC-IDS-2017 preparation, gradient boosting and Isolation
  Forest flow models, SOC metrics (PR-AUC, recall at frozen thresholds, false alerts per 10,000
  flows, per-class recall) and `docs/MODEL_CARD.md`.
- A cross-dataset test showing that the flow models do not transfer between the datasets.
- `prohori score FLOWS --model NAME` for scoring a CSV of flows with a saved model.

### Added

- Leakage-controlled preparation of the UNSW-NB15 and CIC-IDS-2017 flow datasets for the
  machine-learning track (`prohori.ml`, behind the `ml` extra):
  - `scripts/download_datasets.py` lists the datasets with their licences and citations,
    downloads CIC-IDS-2017 only when asked (checked against a pinned size and SHA-256 before it is
    opened, then extracted member by member), prints the manual steps for UNSW-NB15, verifies
    the files and prints a cleaning report.
  - Chunked CSV reading with fixed column types and a Parquet cache keyed by the raw file's hash.
  - Cleaning that drops identifier, address, port, time and label-derived columns, relabels
    "Attempted" CIC-IDS-2017 flows as benign, removes duplicates and conflicting rows, removes
    official test rows that also occur in training, and fits imputation and category encoding on
    the training split only. A leakage check runs on every prepared dataset.
  - Synthetic fixture datasets in `tests/fixtures/ml/` with the real headers.
  - `docs/DATASETS.md` and ADR-0019.
- The first flow detectors and their evaluation (`python -m prohori.ml.train`):
  - Gradient boosting (supervised) and an Isolation Forest trained on benign flows only, with
    fixed settings.
  - Thresholds chosen on the validation split for 1 % and 0.1 % false-positive rates and
    frozen; the test split is scored once per seed.
  - PR-AUC, ROC-AUC, the test false-positive rate reached, recall, precision, false alerts per
    10,000 flows and recall per attack class, as mean and standard deviation over seeds 0-2.
    Accuracy is not reported.
  - Uncleaned and no-TTL variants that show the effect of the leakage controls.
  - Results for both datasets in `results/ml_*.json`, tables generated into
    `docs/MODEL_CARD.md` and the README, and models saved outside git with a SHA-256 sidecar
    and a warning that model files are pickles.
  - `docs/MODEL_CARD.md` and ADR-0020.
- A cross-dataset test (`python -m prohori.ml.transfer`): models trained on one dataset's twelve
  common features (a documented, lossy mapping) and scored on the other. Gradient boosting's
  ROC-AUC falls from 0.95 and 1.00 to 0.64 and 0.61, and its 1 % threshold flags 42 % and 60 % of
  the other dataset's benign flows; results in `results/ml_cross.json` and the model card
  (ADR-0021).
- `prohori score FLOWS --model NAME`: score a CSV of flows with a saved model and list the
  flagged flows (`--fpr`, `--top`, `-f json`, `--exit-zero`); needs the `ml` extra and says so
  when it is missing.
- `--no-cache` for `prohori.ml.train` and `prohori.ml.transfer`: neither read nor write the
  Parquet cache.
- Anomaly detection on your own logs: `--models` on `detect`, `incidents` and `triage` cuts the
  events into five-minute windows per source IP, computes thirteen behaviour features and flags
  unusual windows with a robust z-score (base install) and an Isolation Forest (`ml` extra).
  Model alerts (`detector_kind: model`) join the incidents with a limitation and a review action.
- `python -m prohori.ml.logeval` compares the detectors with the rules on the simulator's
  attacks; cut-offs were chosen on the default variants and frozen before the held-out variants
  were scored. Results in `results/ml_logs.json` and `docs/ANOMALY.md` (ADR-0022): on the
  held-out variants the detectors catch 15 to 17 of 40 attacks against 36 for the rules, none
  that the rules miss, with 0 to 0.35 false alerts a run against 6.5.

### Changed

- The release workflow no longer creates the GitHub release, so none of its jobs can write to the
  repository; maintainers create it with one command (`docs/RELEASING.md`).
- The clones badge's data branch is published with `peaceiris/actions-gh-pages`; the workflow's
  top-level token is read-only.

### Fixed

- The UNSW-NB15 partition files are pinned to the size and SHA-256 of the published files, and
  the dataset documentation has the measured effect of cleaning them.

## [0.1.0] - 2026-10-27

First public release: the batch core, from a log file to scored incidents and shareable reports,
offline by default.

### Highlights

- `prohori demo`: simulated attacks triaged offline in seconds, with no configuration.
- `prohori triage FILE`: parse, detect, enrich, build incidents and write a report per incident.
- Parsers for Linux `auth.log`, nginx/Apache access logs and JSON Lines (app layout or a field
  mapping), into one typed event schema.
- 15 YAML detection rules with fixtures, runbooks and ATT&CK v20.0 tags, run by a stateful engine
  (thresholds, windows, sequences, time of day).
- Optional IP enrichment (GeoLite2, AbuseIPDB, VirusTotal) that never sends private or
  documentation addresses, with caching and rate limits.
- Incidents with a points-based score and its breakdown, confidence and limitations; reports in
  Markdown, self-contained HTML, JSON and CSV, with fail-closed redaction.
- A labelled attack simulator and published per-rule precision and recall, including held-out
  variants that show where the rules miss.

### Added

- Release workflow (`.github/workflows/release.yml`): tag-triggered build, `twine check`, wheel
  smoke tests on Linux and Windows, TestPyPI, PyPI after a maintainer's approval (trusted
  publishing, no tokens), a GitHub release with the changelog section, and an install-from-PyPI
  check. Documented in `docs/RELEASING.md`.
- `prohori triage FILE|-`: parse, detect, enrich (offline unless `--online`), build incidents and
  write `incidents.jsonl`, one report per incident (`--format md|html|json|csv`) and
  `summary.md`; `--redact` / `--redact-ips` redact every file with one key per run.
- `prohori demo`: simulates an account takeover, an SSH brute force and a web scan, triages them
  offline with no configuration and shows whether every expected rule fired.
- `prohori version` shows the ATT&CK release and a fingerprint of the built-in rule set.
- Command-line reference `docs/CLI.md`, sample reports in `docs/examples/`, a terminal capture of
  the demo (`docs/images/demo.svg`) and `scripts/generate_examples.py` to regenerate them.
- Golden tests for the table output of the main commands, a `--help` test for every command and
  an end-to-end test (simulator, triage, incidents) against the simulator's ground truth.
- Log simulator (`prohori.simulate`) and `prohori simulate SCENARIO --seed N --out DIR
  [--variant default|heldout] [--set NAME=VALUE] [--list]`: eight labelled attack scenarios
  (SSH brute force, password spraying, credential stuffing, refresh-token reuse, account takeover
  with a payout change, web scanning, injection attempts, admin misuse) in realistic benign
  background activity, as `auth.log`, access-log or app-JSON files with per-line labels and a
  manifest. Byte-identical for the same seed; documentation IP ranges only.
- Rule evaluation: `scripts/evaluate_rules.py` writes per-rule precision and recall for the
  default and held-out variants to `results/rules_eval.json`; `scripts/generate_results_table.py`
  puts the tables in `docs/SIMULATOR.md`.
- Time-of-day matching in rules: a `timezone` key and the `time.hour`, `time.weekday` and
  `time.minute_of_day` fields.
- Built-in rule PRH-ADMIN-002: admin actions between 22:00 and 07:00 (Asia/Dhaka), with fixtures
  and a runbook (15 built-in rules in total).
- Runbook actions starting with `For SSH,` or `For the web app,` are shown only for incidents
  with that kind of event.
- Incident reports (`prohori.reports`) and `prohori report INCIDENT [-f md|html|json|csv]`:
  header, summary, timeline, indicators with enrichment, entities, evidence, ATT&CK mapping,
  score breakdown, recommended actions, confidence and limitations, and an appendix with input
  and rule-file SHA-256 hashes and versions. HTML is one self-contained file with a strict
  Content-Security-Policy; Markdown escapes every value; CSV cells cannot become formulas.
  Documented in `docs/REPORTS.md`.
- `--redact` and `--redact-ips`: account names, ids, email hashes, emails and optionally IP
  addresses become keyed pseudonyms (HMAC-SHA256, random key per run); the command refuses to
  write a report that would still contain an original value.
- `Incident.provenance` (tool version, input files with SHA-256, rules fired with rule-file
  SHA-256, enrichment mode), filled in by `prohori incidents`; `TimelineEntry.account` and
  `TimelineEntry.source_ip`.
- Sample incident `samples/incidents/INC-ee7c8818fbb34989.json`.
- `jinja2` is now a core dependency.
- Incident builder (`prohori.incidents`) and `prohori incidents FILE|-`: alerts that share an IP,
  account, request or session within a time gap become one incident, with a points-based score
  and its breakdown, severity, confidence, ATT&CK mapping (with the ATT&CK version), a timeline,
  enriched indicators, recommended actions from the runbooks, and limitations. Sign-in novelty
  (a new IP or client for an account) is incident context from a bounded per-account history.
  Shared IP addresses stop linking alerts after 10 accounts. Enrichment is offline unless
  `--online` is given. Documented in `docs/INCIDENTS.md`.
- `Incident.attack_version` and `prohori.schema.incident_id()` (deterministic incident ids).
- Sample `samples/logs/account-takeover.jsonl`: brute force, sign-in, 2FA disabled, payout change.
- IP enrichment (`prohori.enrich`) and `prohori enrich IP... [--offline]`: providers for local
  MaxMind GeoLite2 databases (`prohori[geoip]` extra), AbuseIPDB and VirusTotal, a bundled
  synthetic fixture for offline runs, a SQLite cache with TTLs, daily budgets, a token bucket,
  bounded retries and timeouts. Private, reserved and documentation addresses are never sent to
  external services. Documented in `docs/ENRICHMENT.md`; third-party terms in `docs/LICENSES.md`.
- `httpx` is now a core dependency.
- `prohori detect FILE|-`: parse a log file and run the built-in rules plus any `--rules PATH`,
  with table or JSON Lines output, out-of-order tolerance (`--lateness`) and exit code 3 when
  alerts are found (`--exit-zero` to disable).
- Built-in rules PRH-ABUSE-001, PRH-ADMIN-001, PRH-WEB-001 to 004 and PRH-SSH-001, with fixtures
  and runbooks (14 built-in rules in total).
- `urldecode` rule modifier: percent-decode a field before matching.
- Built-in rules PRH-AUTH-001 to 004, PRH-SESS-001, PRH-ACCT-001 and PRH-AUTHZ-001, each with
  fixtures (including real log lines through the parsers) and a runbook in `prohori/runbooks/`.
- ATT&CK tags verified against Enterprise ATT&CK v20.0 (`prohori.rules.attack`), with
  `scripts/verify_attack.py` to re-check the list against the official STIX data.
- Stateful rule engine (`prohori.rules.engine`): single-pass evaluation of stateless rules,
  `aggregate` thresholds (count, distinct, ratio; sliding and tumbling windows) and `sequence`
  rules, with a reorder buffer for out-of-order events, protection against bogus future
  timestamps, and bounded state with eviction counters.
- Rule test harness and `prohori rules test`: each rule runs against its `<rule>.tests.yml`
  fixtures (generated event timelines or real log lines through a parser).
- Detection rule format (`prohori.rules`): YAML rules with selections, field modifiers
  (`contains`, `startswith`, `endswith`, `re`, `cidr`, `gt`/`gte`/`lt`/`lte`, `exists`, `all`,
  `cased`), wildcards, a boolean `condition` language, and `aggregate` / `sequence` blocks that are
  validated now and evaluated by the upcoming stateful engine. Documented in `docs/RULES.md`.
- Safe rule loading: size, depth and node limits, safe YAML only, no anchors or aliases, and every
  error reported with file, line and path.
- Rule regular expressions run on RE2 (`google-re2`), so matching time is linear in the input and
  no pattern can hang a run.
- `prohori rules list` and `prohori rules validate`.
- `prohori parse FILE|-`: parse and normalise logs with format detection, table or JSON Lines
  output, a parse summary with error examples, and exit codes (`0` ok, `1` every line failed,
  `2` usage error).
- `access_log` parser for nginx and Apache combined/common log formats, with custom patterns
  and query strings kept in `extra.query`.
- `app_json` parser for application security events in JSON Lines.
- `generic_json` parser driven by a validated YAML field-mapping file.
- Sample access, application and generic JSON logs, and a sample mapping file.
- `pyyaml` and `rich` as core dependencies.
- Parser framework (`prohori.parsers`): bounded binary line reading, sanitising of control,
  ANSI and invisible characters, per-run statistics with error examples, and a parser registry.
- `auth_log` parser for Linux `auth.log` / `secure`: sshd logins, invalid users, too many
  authentication failures, disconnects, `pam_unix` and sudo lines; RFC 3164 and RFC 3339
  timestamps with year inference, New Year rollover and configurable timezone.
  Documented in `docs/PARSERS.md`.
- Synthetic sample logs in `samples/logs/`.
- Atheris fuzz harness for the parser, run in CI.
- `tzdata` dependency on Windows for IANA timezone support.
- Common schema (`prohori.schema`): immutable `Event`, `Alert` and `Incident` models with UTC-only
  timestamps, IPv4/IPv6 validation, truncation of untrusted text, deterministic ids, dotted-path
  field access and JSON / JSON Lines helpers. Documented in `docs/SCHEMA.md`.
- `pydantic` as a core dependency.
- Project skeleton: `src/` layout package with typed, importable subpackages.
- `prohori` command-line entry point with `--version` and `version`.
- Tooling: uv, Ruff, mypy (strict), pytest with coverage, pre-commit with secret scanning.
- Continuous integration on Linux and Windows for Python 3.11 to 3.14, CodeQL and Dependabot.
- Contributor, security and code-of-conduct documents.
- OpenSSF Scorecard workflow, README status badges and a project wiki.

[Unreleased]: https://github.com/UtshaBasak/Prohori/compare/v1.0.1...HEAD
[1.0.1]: https://github.com/UtshaBasak/Prohori/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/UtshaBasak/Prohori/compare/v0.3.0...v1.0.0
[0.3.0]: https://github.com/UtshaBasak/Prohori/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/UtshaBasak/Prohori/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/UtshaBasak/Prohori/releases/tag/v0.1.0
