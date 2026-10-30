# Command-line reference

Every command has `--help`. Commands that read a log file also read standard input when the
file is `-`. Nothing uses the network unless you configure API keys and ask for it
(`prohori enrich` without `--offline`, or `--online` for `incidents` and `triage`).

| Command | What it does |
|---------|--------------|
| [`prohori demo`](#prohori-demo) | Simulate attacks, triage them and show the results; no configuration, offline |
| [`prohori triage FILE`](#prohori-triage) | Log file in, incidents and a report for each out |
| [`prohori parse FILE`](#prohori-parse) | Parse and normalise a log |
| [`prohori detect FILE`](#prohori-detect) | Run the detection rules over a log |
| [`prohori incidents FILE`](#prohori-incidents) | Group alerts into scored incidents |
| [`prohori report INCIDENT`](#prohori-report) | Render an incident report |
| [`prohori enrich IP...`](#prohori-enrich) | Look up IP addresses |
| [`prohori simulate SCENARIO`](#prohori-simulate) | Write a labelled attack scenario |
| [`prohori score FLOWS --model NAME`](#prohori-score) | Score a CSV of network flows with a saved model (`ml` extra) |
| `prohori rules list` / `validate` / `test` | Show, check and test detection rules ([RULES.md](RULES.md)) |
| `prohori version` | Version, ATT&CK release and built-in rule set |

## Formats

- **Terminal output** (`parse`, `detect`, `incidents`, `enrich`): `--format table` (default) for
  people, `--format json` for JSON Lines on standard output with a summary on standard error.
- **Reports** (`report`, `triage`, `demo`): `--format md`, `html`, `json` or `csv`.

Tables never interpret text from logs as markup, and every report format escapes it.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success, nothing found (or `--exit-zero`) |
| `1` | Nothing could be processed: every line failed to parse, a rule file is invalid, redaction could not hide every value (nothing is written), or `score` lacks the `ml` extra, a loadable model or a scorable file |
| `2` | Invalid usage, input or setting |
| `3` | Findings: `detect`, `incidents` and `triage` found alerts or incidents; `score` flagged flows |

Code `3` lets scripts and CI pipelines react to findings; add `--exit-zero` to get `0` instead.

## Options shared by the log commands

`parse`, `detect`, `incidents` and `triage` accept:

| Option | Meaning |
|--------|---------|
| `--parser`, `-p` | `auto` (default: detect the format), `auth_log`, `access_log`, `app_json`, `generic_json` |
| `--year` | `auth_log`: year of the first line (syslog lines have none; default: from the file date) |
| `--timezone` | `auth_log`: IANA timezone for timestamps without an offset (default `UTC`) |
| `--mapping FILE` | `generic_json`: YAML field mapping |
| `--pattern REGEX` | `access_log`: custom line pattern |
| `--keep-query` | `access_log`: keep the query string in `http.path` |

`detect`, `incidents` and `triage` also accept `--rules PATH` (repeatable; your rules run with
the built-in ones), `--no-builtin`, `--lateness 5m` (how far out of order events may arrive),
`--models` (anomaly detectors, see [ANOMALY.md](ANOMALY.md)) and `--exit-zero`. See [PARSERS.md](PARSERS.md) and [RULES.md](RULES.md).

## `prohori demo`

```bash
prohori demo                                  # three scenarios into ./prohori-demo
prohori demo -s admin-misuse -s injection --seed 7 -f md
```

Simulates attacks (by default account takeover, SSH brute force and web scanning), triages each
log offline and prints what was found: alerts, incidents, the top incident and whether every
expected rule fired. It reads no `.env`, uses no API keys and keeps its enrichment cache inside
`--out`. Options: `--out` (default `prohori-demo`), `--seed`, `--scenario` (repeatable),
`--format` (default `html`).

## `prohori triage`

```bash
prohori triage /var/log/auth.log --year 2026 -o triage/
prohori triage access.log -f md --redact-ips -o shareable/
cat app.jsonl | prohori triage - -o triage/
```

Parses the log, runs the rules, enriches addresses (offline unless `--online`), builds incidents
and writes to `--out` (default `triage`):

- `incidents.jsonl`: every incident as JSON (input for `prohori report`);
- `INC-<id>.<format>`: one report per incident (`--format`, default `html`);
- `summary.md`: every incident with severity, score, confidence, title and a link to its report.

Before writing, a run deletes what an earlier triage left in `--out` (`incidents.jsonl`,
`summary.md` and `INC-*` reports) and nothing else, so an old unredacted report never sits next to
new redacted ones. With `--redact` or `--redact-ips` every file, including `incidents.jsonl`, is
redacted with one key per run, so an account has the same pseudonym in all of them. If redaction cannot hide every
value, nothing is written. Other options: `--no-enrich`, `--gap`, `--env-file` and the shared
options above.

## `prohori parse`

Normalises a log into the common event schema. `--limit N` sets how many events the table shows.
See [PARSERS.md](PARSERS.md).

## `prohori detect`

Runs the 15 built-in rules (plus `--rules`) and prints the alerts and a summary.
See [RULES.md](RULES.md).

`--models` (also on `incidents` and `triage`) adds the anomaly detectors: source IPs whose
five-minute windows are unusual for the log get `low` alerts with `detector_kind: model`. The
robust z-score needs nothing extra; the Isolation Forest needs the `ml` extra and is skipped with a
note without it. See [ANOMALY.md](ANOMALY.md).

## `prohori incidents`

Groups alerts into incidents and prints them, or writes JSON Lines with `-f json`. Options:
`--online`, `--no-enrich`, `--gap 30m`, `--env-file`. See [INCIDENTS.md](INCIDENTS.md).

## `prohori report`

Renders one incident: `--format md|html|json|csv`, `-o FILE`, `--incident ID` (when the file
holds several), `--redact`, `--redact-ips`. Use `-o` on Windows rather than `>`.
See [REPORTS.md](REPORTS.md).

## `prohori enrich`

Looks up IP addresses: `--offline`, `--format table|json`, `--no-cache`, `--env-file`.
See [ENRICHMENT.md](ENRICHMENT.md).

## `prohori simulate`

Writes a labelled scenario: `--out DIR`, `--seed`, `--variant default|heldout`,
`--set NAME=VALUE` (repeatable), `--list`. See [SIMULATOR.md](SIMULATOR.md).

## `prohori score`

```bash
prohori score flows.csv --model cicids2017/hgb-seed0            # a model under ./models
prohori score flows.csv -m models/unsw-nb15/hgb-seed1.joblib --fpr 0.01 -f json --top 0
```

Scores every flow in a CSV with a model saved by `python -m prohori.ml.train` (see
[MODEL_CARD.md](MODEL_CARD.md)) and lists the flagged flows, highest score first, with a summary.
It needs the `ml` extra (`pip install "prohori[ml]"`); without it the command says so and exits
with `1`.

- **Input:** the columns of the dataset the model was trained on: CICFlowMeter output for a
  `cicids2017` model, UNSW-NB15 partition columns for a `unsw-nb15` model. A missing column is
  an error that names it; label columns are ignored. The file is read in chunks, and `-` reads
  standard input.
- **Threshold:** `--fpr` picks one of the model's frozen thresholds (`0.01` or `0.001`, the
  false-positive rate it was set for on validation data); the default is the strictest.
- **Output:** a table, or `-f json` with every count and the flagged flows. Addresses, ports and
  timestamps are shown next to flagged flows to help find them, but never used for scoring.
  `--top N` limits the list (default 20, `0` for all); `--models-dir` (default `models`) is where
  model names are looked up; `--exit-zero` exits `0` when flows are flagged.
- **Safety:** model files are pickles, and loading one runs code from it. The command refuses a
  file whose SHA-256 does not match its JSON sidecar and prints a warning; only use models you
  trained yourself. A model trained on lab data misses attacks and flags benign flows on other
  networks (see the cross-dataset results in the model card): treat flagged flows as leads.

To try it on the repository's synthetic fixtures:

```bash
uv run python -m prohori.ml.train --dataset cicids2017 --data-dir tests/fixtures/ml --seeds 0 --variants cleaned --no-cache --out tmp/results.json --models-dir tmp/models
uv run prohori score tests/fixtures/flows.csv --model cicids2017/iforest-seed0 --models-dir tmp/models --fpr 0.01
```
