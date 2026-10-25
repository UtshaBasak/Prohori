# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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

### Changed

- String values in `Event.extra` and enrichment data are truncated to 1,024 characters.
- Parse error reasons name the invalid schema field.
- The fuzz harness covers every parser.

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
