# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/UtshaBasak/Prohori/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/UtshaBasak/Prohori/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/UtshaBasak/Prohori/releases/tag/v0.1.0
