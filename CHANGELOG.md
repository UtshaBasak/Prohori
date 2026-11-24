# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Network sensor logs.** Two parsers: `suricata_eve` for Suricata's `eve.json` (alert, http,
  dns, tls, ssh and flow records; Suricata 7 layout and 8's DNS version 3) and `zeek_conn` for
  Zeek's `conn.log` (tab-separated with a `#fields` header, or Zeek JSON; Zeek 6 and 7). Both
  are detected automatically, describe a connection with the same `extra` keys, date a
  connection at its last packet so long connections are not dropped as late, and are covered by
  the fuzz harness. Suricata `http` records become `web.request` events, so the web rules run on
  them too (ADR-0044).
- **Six network rules** (experimental): PRH-IDS-001 to PRH-IDS-003 pass Suricata alerts through
  by severity (1 high, 2 medium, 3 or above low); PRH-NET-001 port scan (25 distinct ports from
  one source in 5 minutes), PRH-NET-002 large outbound transfer (500 MB in one connection) and
  PRH-NET-003 long outbound connection (8 hours). Fixtures, runbooks and verified ATT&CK tags
  (T1046, T1595, T1048, T1071); the passthrough rules carry no technique of their own.
- Hand-written samples: `samples/logs/suricata-eve.json`, `zeek-conn.log` and `zeek-conn.json`.
- **Windows Security events.** A `windows_security` parser for Winlogbeat, NXLog and PowerShell
  JSON, evtx_dump JSON and event XML (one event per line or over several lines): sign-ins
  (4624, 4625 with the failure reason and logon type), logoffs, special privileges (4672),
  account changes (4720, 4722, 4726), group membership (4728, 4732, 4756), lockouts (4740) and a
  cleared log (1102). One format-independent mapping (`prohori.parsers.windows`) for every
  layout. Native `.evtx` files with the new `evtx` extra (ADR-0045).
- **systemd journal.** A `journald` parser for `journalctl -o json`; sshd, sudo and PAM messages
  go through the same code as `auth_log`, so they give the same alerts.
- **Six Windows rules:** PRH-WIN-001 (sign-in failures from one source), PRH-WIN-002 (many
  accounts from one source), PRH-WIN-003 (a sign-in after failures), PRH-WIN-004 (an account
  added to an administrators group, matched by SID), PRH-WIN-005 (Security log cleared,
  experimental) and PRH-WIN-006 (lockouts across accounts, experimental); fixtures, runbooks
  and ATT&CK (T1098.007, T1685.005 added).
- **Host activity in the schema:** optional `process.*` (with `process.parent.*`), `file.*`,
  `registry.*`, `destination.*` and `dns.question` fields and the categories `process`, `file`,
  `registry` and `dns`. Events without them serialise exactly as before. The network parsers and
  rules use `destination.ip`/`destination.port` (and `destination.domain`, `dns.question`) for
  what were `extra` keys earlier in this release.
- **Sysmon.** Sysmon events in every Windows layout: process creation, network connections,
  image loads, remote threads, process access, file creation and deletion, registry changes and
  DNS queries (Sysmon 13 to 15). `windows_security` reads Sysmon and Security events together; a
  `sysmon` parser reads Sysmon alone. Windows 4688 process creation is mapped too.
- **Four host rules:** PRH-PROC-001 (encoded PowerShell), PRH-PROC-002 (an Office application or
  browser starting a shell), PRH-PROC-003 (a new Windows service) and PRH-PROC-004 (lsass read by
  an unusual process, or the SAM hive saved); defanged fixtures and runbooks.
- **A tenth simulator scenario,** `windows-intrusion` (Sysmon and Security, defanged): every
  default run caught by all four host rules; the held-out variant is caught by PRH-PROC-004 only.
- **A ninth simulator scenario,** `windows-signin`, with default and held-out variants. The
  held-out variants are missed by PRH-WIN-001 and PRH-WIN-002 and caught by PRH-WIN-003 and
  PRH-WIN-004. The before-and-after comparison with the frozen baselines leaves it out.

### Changed

- The pinned ATT&CK v20.0 bundle URL names the commit its SHA-256 was taken from: MITRE changed
  the collection's creation time in the file on `master` on 2026-11-05 (no tactic or technique
  changed), so the `master` URL no longer matched the hash.

## [1.1.0] - 2026-11-24

The first release under the PolyForm Strict License 1.0.0 (free for personal and other
non-commercial use; 1.0.1 and earlier stay MIT). A hardening release: rules that hold up against
slower and spread-out attackers, measured against a frozen baseline; reviewed suppressions;
logins for the Docker stack; model files without pickle; and SBOMs with every release.

### Highlights

- **New licence**, PolyForm Strict 1.0.0 (ADR-0033); see *Changed* below and `LICENSE`.
- **Evasion-resistant sign-in rules**: six rules that count per account, network and log catch
  every held-out attack (40/40, 35/40 before), with no new false positive.
- **Suppressions and allow-lists** with a reason, an owner and an expiry date per entry;
  suppressed alerts are counted and listed, never dropped (ADR-0043).
- **Logins for the Docker stack** (Grafana, Airflow, SASL/SCRAM on Kafka with per-user ACLs) and
  **signed CycloneDX SBOMs** for the package and the image (ADR-0042). **Upgrade note** in
  *Security*.
- **Model files without pickle** (skops) and a time-block validation split (ADR-0040), plus a
  pre-registered cross-dataset generalisation study (ADR-0041).
- The LLM analyst's evaluation recorded again with Gemini on all 31 cases: no factual error,
  every injection ignored.

### Added

- **Evasion-resistant authentication rules.** Six rules count per account, per network and per
  log instead of per address, so slow and spread-out attacks are caught:
  PRH-AUTH-005 (one account failing from many addresses), PRH-AUTH-006 (slow guessing on one
  account over 24 hours), PRH-AUTH-007 (many accounts failing from one network),
  PRH-AUTH-008 (many accounts and many addresses failing in one log), PRH-AUTH-009
  (unknown-account failures from many addresses, experimental) and PRH-AUTH-010 (a success after
  many failures on one account). Thresholds are twice the benign maximum of the default
  variants, fixed before scoring (ADR-0036). Held-out credential stuffing is now caught in 5 of 5
  runs (0 of 5 before); all held-out attacks 40/40 (35/40 before); no new false positive in any
  variant. See `docs/case-studies/evasion-resistant-rules.md`.
- Rule format: an aggregate's `distinct` may list two or three thresholds that must all be
  reached, a `distinct` field may list alternatives, and `source.ip_prefix` (IPv4 /24, IPv6 /48)
  is a derived field rules can group by. Rules may have status `test` or `experimental`.
- Simulator: a second held-out variant, `heldout2` (rates halved, sources doubled and spread over
  every documentation network), defined after the new rules were fixed. `results/rules_eval.json`
  keeps a frozen baseline (the 1.0 rules), and RULES.md and the README show a generated
  before-and-after table. `scripts/evaluate_rules.py --variants` scores some variants without
  writing anything.

- **SSH attacks logged with host names are detected.** sshd with `UseDNS yes` logs the client's
  host name instead of its address, and the sign-in rules, which counted by `source.ip`, skipped
  those lines. Events now have an optional `source.host` (a valid, lower-case, fully qualified
  name; placeholders such as `unknown` are not host names), and a rule's `group_by` / `by` entry
  may list alternatives, the first with a value being used:
  `group_by: [[source.ip, source.host]]`. PRH-AUTH-001, PRH-AUTH-002, PRH-AUTH-003 and PRH-SSH-001
  group that way, incidents link on `source.host` (with the shared-address cap), and
  `--redact-ips` / `--mask-ips` replace host names too, since reverse-DNS names often contain the
  address. `extra.source_host` keeps the name as logged, as before.
- `prohori detect --limit N`: the table shows the earliest N alerts (default 100; 0 for all) and
  counts the rest, holding at most N in memory. `-f json` already wrote each alert as it was
  raised.
- `scripts/benchmark.py --alerts N` measures an alert storm (a log in which every line raises
  alerts) and checks that `detect` and `incidents` stay under a fixed memory bound.

- **Simulator address model 2** (ADR-0038). Customers, visitors and staff each have a stable
  home address spread over many networks: 18 % on IPv6 in a /48 of their own (APNIC Labs' 2025
  figure for Bangladesh, where the simulated shop is), the rest on IPv4 in two documentation
  /24s; five customers (thirteen before) share one NAT address; the attackers' provider network
  holds no benign address. Manifests and `results/rules_eval.json` record `"addresses": 2`, and
  `prohori simulate` prints it. `results/rules_eval.json` keeps several named baselines, each
  with its address model (format `prohori.rules-eval/2`); the address-model-1 results stay under
  their own labels for reference.

- Warehouse indexes on the time columns the dashboards filter (events, alerts, incidents and
  dead letters), created with the tables in PostgreSQL, so existing stacks get them too.
- A message the Kafka client or broker refuses (too large or malformed) becomes a dead letter
  (stage `kafka-producer`) instead of failing the batch on every restart.

- **Calibration study for the flow models** (ADR-0040). Every training run measures, on the same
  test split, three ways of choosing thresholds: validation time blocks, out-of-fold scores over
  folds of time blocks, and 1.0's random validation rows, with the share of benign validation
  flows that have a near-duplicate in training. `results/ml_*.json` (format
  `prohori.ml-eval/2`) holds the study and the model card a generated table; `--no-study` skips
  it and `--calibration out-of-fold` uses the other method.
- **Cross-dataset generalisation study** (step 30b), pre-registered in ADR-0041 and pushed
  before any run. `scripts/cross_dataset_study.py` tries six low-compute ways to close the gap
  between the two flow datasets without target labels (per-domain log standardisation,
  per-domain quantile maps with and without protocol groups, CORAL, importance weighting,
  domain-invariant feature selection), plus 10, 50 and 100 labelled target flows as an upper
  bound, in both directions over seeds 0-2 with paired bootstrap intervals; results in
  `results/ml_adapt.json` (byte-identical on a rerun) and a generated table in the model card.
  Only the per-domain quantile map helps in both directions (ROC-AUC 0.636 to 0.824 and 0.590
  to 0.624); 10 labelled target flows do as well, 100 do much better (0.966 and 0.758). The
  transforms, weights and metrics are in `prohori.ml.adapt`, with leakage tests (the pool's
  labels reach only the few-shot and reference arms; target test features change nothing that
  is fitted). Adversarial methods and a third dataset are recorded as future work.
- `prohori.ml.safety`: hash, library-version, skops-type and pickle-allowlist checks, reusable by
  other commands (`scan_joblib` lists what a pickle model asks for without running it).
- **Suppressions and allow-lists** (ADR-0043). `--suppressions FILE` on `detect`, `incidents`,
  `triage` and `pipeline replay` / `tail` / `run` applies reviewed exceptions: each entry names a
  rule (or `*`), field matchers in the rule syntax, a `reason`, an `owner` and an `expires` date;
  `allow_ips` lists addresses known to be benign. An alert is suppressed only when every one of
  its events matches an entry in force on the alert's day, so other alerts in the same incident
  are never hidden. Suppressed alerts are marked (`"suppression"` in their JSON), counted per
  entry and rule in every output, kept out of incidents and the alert cap, stored by the
  pipeline and counted apart by the warehouse marts (`stg_alerts.suppression_id`,
  `suppressed_alerts`); they do not count toward exit code 3. Allow-listed addresses get no
  reputation points, with a 0-point line in the score breakdown naming the entry. Expired
  entries and entries naming a rule that is not loaded warn on every run; an invalid file is
  refused whole (exit 2). `prohori rules validate --suppressions FILE` checks a file.
  `samples/suppressions.yml` silences the simulator's planned admin role grant: PRH-ADMIN-001
  precision 0.5 to 1.0 in every variant, no true positive lost, every attack still detected
  (`results/rules_eval.json`, `suppressions`, records both). Alerts without a suppression
  serialise exactly as before.

### Security

- **Logins for the Docker stack** (ADR-0042). Grafana no longer shows the dashboards to
  anonymous visitors, Airflow no longer makes everyone an admin, and Redpanda accepts only
  SASL/SCRAM-SHA-256 clients, with least-privilege ACLs per user (`prohori-stage` for the stages,
  `prohori-producer` for `replay`, `tail` and Airflow's jobs, which may write only `raw-logs` and
  `dead-letter`). The passwords are generated on the first `prohori pipeline up` into
  `pipeline/.env` (git-ignored, owner-only) and never changed afterwards; Grafana's and Airflow's
  are printed once on a terminal. **Upgrade note:** sign in to Grafana as `admin` and to Airflow
  as `prohori` with the passwords in `pipeline/.env`; `PROHORI_GRAFANA_ANONYMOUS=true` restores
  anonymous dashboards. Kafka clients outside the stack set `PROHORI_KAFKA_USER` and
  `PROHORI_KAFKA_PASSWORD` (the CLI finds the producer login for the stack's own address by
  itself). With plain `docker compose`, run `prohori pipeline up` once first. An existing stack
  is converted on its next `up`.
- **SBOMs for every release.** CycloneDX SBOMs of the Python package's dependencies (from
  `uv.lock`) and of the container image (syft), attested with Sigstore and attached to the GitHub
  release (`gh attestation verify --predicate-type https://cyclonedx.org/bom`). A release dry run
  produces both.
- The GitGuardian workflow no longer keeps the checkout's credentials (zizmor).
- **Least privilege in the Docker stack's warehouse** (ADR-0039). The stages, dbt and Airflow's
  jobs connect as a new role, `prohori_app`, which owns the warehouse schemas and cannot create
  roles or databases, run server programs or read Airflow's database; the superuser only runs
  `warehouse-init`, which hands an existing stack's tables and views to `prohori_app` on the first
  `up`. **Upgrade note:** set `PROHORI_APP_DB_PASSWORD` if you changed the defaults (the
  superuser keeps `PROHORI_POSTGRES_PASSWORD`); `prohori pipeline status` and the dbt profile now
  read `PROHORI_APP_DB_PASSWORD`. An explicit `PROHORI_POSTGRES_DSN` still wins.
- **Redpanda syncs to disk.** The stack no longer runs Redpanda in `dev-container` mode, which
  skipped fsync and cached writes; a host crash can no longer lose messages already committed.
  A one-shot `redpanda-init` service turns write caching off on clusters created before.
  Start-up time and memory measured the same.
- Any database password works in the stack, including `@/:#%`: passwords are never written into
  a URL (`PGPASSWORD`, libpq keyword strings, and a URL-quoted Airflow database URL).
- **Flow models are no longer pickles** (ADR-0040). Training saves skops files
  (`models/<dataset>/<model>-seed<N>.skops` with `.skops.json`), read without pickle into an
  explicit list of types; a file asking for anything else is refused. 1.0 `.joblib` models still
  load, through an unpickler that resolves only the 30 classes and functions a Prohori model
  needs, so a file asking for `os.system` or `eval` is refused before it runs; retraining
  replaces them. The sidecar records Python, scikit-learn, numpy and pandas versions, and
  loading refuses another major or minor version unless `prohori score --allow-version-mismatch`
  (a warning). `prohori score --sha256 HASH` refuses a file with another hash, the one check
  that stops someone who can replace both the model and its sidecar. `skops` (MIT) joins the
  `ml` extra.

### Changed

- **Step 30: the flow-model numbers moved, and why.** Validation is now made of time blocks the
  training split does not touch (each class's rows in time order, CIC-IDS-2017 by capture time,
  UNSW-NB15 by file order, cut into 50 blocks; whole blocks held out), and CIC-IDS-2017's test
  split is made of time blocks too. A leakage test checks that no training row lies inside a
  held-out block's time range. The 1.0 tables stay in the model card as history.
  - UNSW-NB15, gradient boosting (cleaned): the 1 % threshold now holds, 0.91 % false positives
    on the test file instead of 4.50 %, and recall at it falls from 81.8 % to 68.9 % (290 to
    59 false alerts per 10,000 flows). At 0.1 %: recall 46.0 % to 24.7 %, false positives
    0.07 % to 0.03 %. PR-AUC 0.952 to 0.950. The model is the same; 1.0's thresholds were too
    loose because random validation rows had near-copies in training. Without the TTL columns:
    recall at 1 % 79.3 % to 67.3 %. Uncleaned: PR-AUC 0.989 to 0.988, recall at 0.1 % 78.1 % to
    70.3 %. Fuzzers recall at 1 % 37 % to 7 %, Analysis 16 % to 2 %.
  - UNSW-NB15, Isolation Forest: within the seed spread (PR-AUC 0.522 to 0.532, recall at 1 %
    4.5 % to 4.8 %).
  - CIC-IDS-2017: within a few tenths of a point (gradient boosting recall at 0.1 % 99.98 % to
    99.92 %, false positives 0.10 % both); split sizes for seed 0 857,551 / 343,020 / 514,531 to
    864,418 / 336,140 / 514,544.
  - Cross-dataset test: ROC-AUC on the other dataset 0.639 to 0.636 and 0.614 to 0.590; benign
    flows flagged by the 1 % threshold on the other dataset 42.2 % to 41.8 % and 60.5 % (same).
  - The rule for choosing the method was fixed before the full runs; time blocks won (mean
    calibration error 0.354, out-of-fold 0.476, random rows 0.770).
  - The nightly evaluation's recall gate moves from 0.75 to 0.62: 1.0's 0.82 came with a 4.5 %
    false-positive rate, and at a true 1 % the committed results measure 0.69. The nightly job
    skips the calibration study. The warehouse loader reads results formats /1 and /2.
- SonarQube Cloud now analyses from a GitHub Actions workflow (`sonarcloud.yml`, configured by
  `sonar-project.properties`) instead of Automatic Analysis, with test coverage, and ignores its
  two path-traversal rules only in `scripts/` and five reviewed modules where the path is a file
  named on the command line by the person running the tool (ADR-0037).
- **Moved numbers, explained.** Held-out detection 35/40 to 40/40 and held-out 2 30/40 to 35/40
  (credential stuffing). The account-takeover sample also raises PRH-AUTH-010, so the sample
  incident is now `INC-14756953ade54922` (score and severity unchanged). The demo counts only
  stable rules as expected and names the new rules that its fast demo attacks do not trigger.
  The LLM evaluation set has 31 cases (the held-out credential-stuffing incident now exists);
  the offline baselines were recorded again, and three Gemini answers are marked stale.
- **Step 28c: everything derived from the simulator moved, and why.** The address model is
  drawn from each scenario's random stream, so every simulated log changed, including the web
  and SSH scenarios.
  - Rules: the 1.0 and step-28b rules were scored on the new simulator and frozen as baselines
    before any rule changed, then the thresholds were derived again by ADR-0036's unchanged rule:
    PRH-AUTH-006 22 -> 20, PRH-AUTH-007 38 -> 26, PRH-AUTH-008 addresses 36 -> 38, PRH-AUTH-010
    12 -> 14 (PRH-AUTH-005 and 009 unchanged). PRH-AUTH-007 now fires in 5 of 5 held-out
    spraying runs (0 of 5 with the old threshold on the same simulator); held-out credential
    stuffing stays caught in 5 of 5 on both held-out sets; false-positive alerts on the default
    variants are unchanged (295). Spraying spread over many networks is still missed, and
    PRH-AUTH-010 no longer fires on any simulated takeover (12 attempts, under 14). Held-out
    false-positive alerts are 277 and 274 (259 and 287 on the old simulator), almost all
    PRH-ACCT-001 on owners' own changes, whose number follows the background.
  - The sample account takeover (12 failures) no longer raises PRH-AUTH-010, so the sample
    incident is `INC-ee7c8818fbb34989` again (3 rules instead of 4, score still 100); the
    README example, sample reports, demo output and image follow.
  - Log anomaly detection: the z-score cut-off was chosen again on the default variants (12 ->
    10). On the held-out variants the z-score catches 20 of 40 attacks (15 before), the Isolation
    Forest 17 (unchanged), the rules 40 (36 in the previous results file); false alerts a run
    fall to 0.05, 0.03 and 0 for the fixed thresholds (0, 0.35 and 0.93), because fewer
    customers share one address.
  - LLM evaluation: every simulated case was rebuilt and its reference rewritten; the offline
    baselines were recorded again. Gemini (gemini-3.5-flash-lite) was then recorded again on
    all 31 cases (36 requests over four free-tier days, none stale): every answer passed the
    checks, none made a factual error, it named all 115 reference indicators, covered 91 of 93
    points and followed none of the 8 injections.
  - Golden files and counts taken from simulated logs (pipeline replays, digests, labels) and
    the performance results follow the new logs.
- A 24-hour rule makes the streaming incident hold time 24 h 35 min; following live logs now
  writes quiet incidents after at most an hour by default (`--idle-close` overrides it).
- `--redact-ips` and `--mask-ips` also replace networks named by the per-network rule.

- **New licence.** From this release on Prohori is source-available under the
  [PolyForm Strict License 1.0.0](LICENSE): free for personal and other non-commercial use, but
  no copying, changes or redistribution without the owner's written permission, and commercial
  use needs a separate licence. Versions up to 1.0.1 were MIT and stay MIT
  (`docs/legal/MIT-LICENSE-up-to-1.0.1.txt`). The package metadata, the container image label
  and `prohori version` show the new licence; see ADR-0033.
- Outside code contributions are no longer accepted (issues, ideas and security reports are);
  the name and logo are covered by the new `TRADEMARKS.md`.
- Every source file starts with an SPDX licence identifier and copyright line, added by
  `scripts/licence_headers.py` and checked by a pre-commit hook and a test. Rendered reports are
  unchanged.
- A test checks that no runtime dependency has a GPL (other than LGPL), AGPL, SSPL or
  non-commercial licence.
- Release tags are signed, and `docs/RELEASING.md` has a "Verifying a release" section.
- CircleCI runs the test suite with Smarter Testing: `.circleci/test-suites.yml` describes the
  pytest suite and the CircleCI job runs `circleci testsuite run "pytest"` in place of the
  starter job. Rerunning a failed workflow reruns only the failed tests, and results show on
  the job's Tests tab.
- Markdown is checked with markdownlint-cli2 in pre-commit and CI, with the rules in
  `.markdownlint-cli2.jsonc`; every document now follows them (one table style, fenced code with a
  language, links in angle brackets), and the generated result tables are written the same way.

### Fixed

- CodeQL: two unnecessary `del` statements in `prohori.ml.safety`'s scan stand-in, and two
  implicitly concatenated table headers in `scripts/generate_results_table.py`.
- `prohori.llm.evaluate record`: after a `--fresh` recording stops at the daily budget, the
  message says to continue without `--fresh` (running the same command again discarded it).
- The Kafka transport retries the broker's start-up errors (no leader or no coordinator yet,
  such as `NOT_LEADER_FOR_PARTITION` and `NOT_COORDINATOR`) on every call made at start-up, until
  the broker timeout; the Docker smoke test failed on them now and then.
- The LLM answer check accepts the network of a per-network alert (`203.0.113.0/24`); it was
  rejected as an unknown address.
- The Airflow stack test reads only the newest digest, so a run that crosses midnight UTC passes.
- **No lost events in the daylight-saving hour.** In `auth.log` without offsets, a local time in
  the hour repeated when the clocks go back was always read as its first occurrence, so the
  second half of that hour jumped back and the rules dropped it as late. It is now read as the
  second occurrence when the first would go back more than ten minutes before the previous line,
  and such lines are counted in the new `ambiguous_times` statistic. Sample:
  `samples/logs/auth-dst.log` (6 events, none late).
- **Bounded memory for huge alert counts.** `prohori incidents` and `triage` held every alert of
  a run. They now keep at most 1,000 per rule and entities and 10,000 of each severity (so a
  flood of low or medium alerts cannot crowd out a critical one); an incident that lost alerts
  says how many in its limitations, and the JSON summary reports `alerts_not_kept`. The `detect`
  table counts the alerts it does not show by severity.
  Ordinary runs are unchanged (the simulator's busiest rule and entities raise 14).
- **A restarted pipeline gives the same alerts and incidents as the live run.** The detector's
  idle flush and the incident stage's idle close (and both end-of-run releases) depended on
  wall-clock time, so a stage rebuilt from its topics could raise an alert the live run had not
  (nine failed sign-ins, a pause, three older ones: no alert live, a brute-force alert after a
  restart). Each decision is now written into the stage's own input topic as a control marker
  (`{"control": "flush", "stage": "detect", ...}` in `events`, `"close"` from `incidents` in
  `alerts`) and acted on when it is read back, live and on a rebuild alike. The sink and the
  other stage skip markers. Topics written by 1.0 have no markers and replay as before. A
  property test checks random interleavings on the memory, file and Kafka transports; see
  ADR-0034 and "Delivery guarantees" in `docs/PIPELINE.md`.
- The two Dockerfiles say `HEALTHCHECK NONE` on purpose: each service's health check lives in
  `docker-compose.yml`, because one image serves several roles. This closes Prowler's
  "No HEALTHCHECK defined" findings.
- The GitGuardian workflow no longer passes `github.event.base`, which push events don't have
  (it was always empty, and editors flagged it as an invalid context).
- The stage image builds again: an automatic update had moved it to Python 3.15, which Prohori
  does not support yet (no wheels for its dependencies). It is back on Python 3.13, and
  PostgreSQL is back on 17: version 18 cannot open a data volume written by 17. Dependency
  updates no longer propose new major versions of the images, or a new Python minor version.
- The Airflow backfill can be triggered from the form with `start` left empty (eight days ago):
  Airflow 3's form treated the parameter as required, so the *Trigger* button stayed disabled.
- The docs' DuckDB example queries the lite-mode database with the Python library the
  `pipeline` extra installs, and say that the `duckdb` command-line tool must be 2.0 or newer:
  older ones (1.5.x, still what some package managers install) cannot open the file.

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
  Airflow on <http://127.0.0.1:18080>):
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
  provisioned from files and open without a login at <http://127.0.0.1:13000>:
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

[Unreleased]: https://github.com/UtshaBasak/Prohori/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/UtshaBasak/Prohori/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/UtshaBasak/Prohori/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/UtshaBasak/Prohori/compare/v0.3.0...v1.0.0
[0.3.0]: https://github.com/UtshaBasak/Prohori/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/UtshaBasak/Prohori/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/UtshaBasak/Prohori/releases/tag/v0.1.0
