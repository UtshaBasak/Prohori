# Threat model

What Prohori protects, who might attack it, how, and what stops them. Every control named here
exists in the code, with the file it lives in. The residual risks are the ones the other
documents already admit. To report a problem, see [SECURITY.md](../SECURITY.md).

Reviewed for v1.0.1 on 2026-11-03.

## Contents

- [The system](#the-system)
- [Assets](#assets)
- [Trust boundaries](#trust-boundaries)
- [Threats and controls](#threats-and-controls)
- [Residual risks](#residual-risks)
- [Out of scope](#out-of-scope)

## The system

Prohori reads log files (or tails them), parses them into events, runs detection rules and
optional anomaly detectors, groups alerts into scored incidents, optionally enriches IP
addresses with outside services, and writes reports. Optional parts:

- a streaming pipeline (lite mode on one machine, or a Docker stack with a broker, PostgreSQL,
  dbt, Grafana and Airflow);
- flow models trained on public datasets;
- an LLM analyst that sends a redacted incident to Gemini.

It runs as the user who starts it, on that user's machine, and never blocks, disables or changes
anything outside its own output.

## Assets

| Asset | Why it matters |
| ------- | ---------------- |
| The analyst's machine | Prohori runs on it with the user's rights |
| Log content | Holds account names, emails and addresses of real people |
| API keys (AbuseIPDB, VirusTotal, MaxMind, Gemini) | Quota and accounts belong to the user |
| Reports and shared outputs | Read by other people, in browsers, editors and spreadsheets |
| Detection results | An analyst acts on them; a hidden or invented finding misleads |
| The enrichment cache and the warehouse | Local copies of third-party data and of events |
| The released package and image | Installed by other people |

## Trust boundaries

1. **Log input.** Every log line is attacker-controlled: an attacker chooses the request path,
   the user agent and the username they try.
2. **Rule, mapping, model and dataset files.** Supplied by the user, possibly copied from
   elsewhere.
3. **Outside services.** Enrichment providers and Gemini receive data from Prohori and send
   answers back; the answers are untrusted.
4. **Output consumers.** Browsers, Markdown viewers, spreadsheets and terminals render what
   Prohori writes.
5. **The Docker stack's network.** Services talk over a Compose network and publish ports on
   the host.
6. **The supply chain.** Dependencies, container base images, GitHub Actions and the release
   pipeline.

## Threats and controls

### Malicious log content (boundary 1)

| Threat | Controls |
| -------- | ---------- |
| Resource exhaustion from huge lines or files | Lines capped at 16 KiB (`parsers/base.py`, `MAX_LINE_LENGTH`); streaming parsers that never load a file whole; bounded state in the rule engine and incident builder (`incidents/builder.py`: shared-IP account cap, sign-in history limit) |
| Regular-expression denial of service | Rules match with RE2, linear in the input (`rules/regex_safety.py`) |
| Crashing the parser | Fuzzing with Atheris in CI, Hypothesis property tests, malformed lines counted and skipped, never fatal |
| Terminal escape sequences in output | Control characters stripped from every parsed value (`parsers.sanitize`) and from model answers (`llm/explain.py`, `clean_answer`) |
| Timestamps in the future to hide or reorder events | Events too far after the reference time are rejected (`rules/engine.py`, `max_future`); lateness window for out-of-order events |
| Instructions to an LLM hidden in logs | See [the LLM analyst](#the-llm-analyst-boundaries-1-and-3) below |
| Evading detection | Not prevented; see [Residual risks](#residual-risks) |

### Untrusted files from the user (boundary 2)

| Threat | Controls |
| -------- | ---------- |
| Code execution from YAML rules or mappings | `yaml.safe_load` only; rule files capped at 128 KiB and one document (`rules/loader.py`); rules validated before they run |
| Code execution from model files | Models are joblib (pickle) files, which **can run code**. The CLI warns, checks the SHA-256 sidecar written at training (`ml/models.py`) and the docs say to load only models you trained ([MODEL_CARD.md](MODEL_CARD.md)) |
| Tampered datasets | The download script pins and checks the size and SHA-256 of the CIC-IDS-2017 archive it fetches, and `verify` checks the pinned UNSW-NB15 files (`scripts/download_datasets.py`); training does not re-check hashes. Datasets are never committed or fetched at import time |
| Path traversal in outputs | Outputs are written only under the directory given; report file names are built from incident ids, not log content |

### Outside services (boundary 3)

| Threat | Controls |
| -------- | ---------- |
| Leaking private addresses to third parties | Private, reserved, documentation and translated addresses are never sent (`enrich/` deny list, [ENRICHMENT.md](ENRICHMENT.md)) |
| Hostile or oversized responses | Fixed endpoints, no redirects, timeouts, 1 MiB response cap (`enrich/http.py`); responses parsed into typed fields |
| Key leakage | Keys read from the environment or a git-ignored `.env`; never logged, never in error messages (`enrich/http.py`, `llm/provider.py`), never cached |
| Quota exhaustion or bans | Daily budgets counted before each request, token buckets, bounded retries, provider disabled for the run on quota or auth errors |
| Personal data sent to the LLM provider | Off by default; allow-listed, redacted payload with no event descriptions; a leak check stops sending if a replaced value remains (`llm/payload.py`); a reminder on every free-tier request |

### The LLM analyst (boundaries 1 and 3)

| Threat | Controls |
| -------- | ---------- |
| Prompt injection from log values | Most log text is never sent (event descriptions dropped, usernames pseudonymised); what is sent is fenced with a per-request nonce that log text cannot forge or close (`llm/guard.py`) |
| A manipulated answer citing invented facts or links | Every IP, email, pseudonym, incident, rule and technique id must come from the incident's structured fields or the sources, and links only from attack.mitre.org; otherwise the answer is rejected and the local summary shown (`llm/guard.py`, `validate`) |
| Tool misuse | Three read-only tools, a call limit, argument and result caps (`llm/tools.py`) |
| Measured, not assumed | 30-case evaluation with 8 injection cases ([LLM_ANALYST.md](LLM_ANALYST.md#evaluation)) |

### Output consumers (boundary 4)

| Threat | Controls |
| -------- | ---------- |
| Script injection in HTML reports | Jinja2 autoescaping and a Content-Security-Policy with `default-src 'none'` (`reports/templates/report.html.j2`) |
| Link or markup injection in Markdown | Values escaped, code spans made safe (`reports/render.py`) |
| Spreadsheet formula injection in CSV | Cells starting with `=`, `+`, `-`, `@`, tab or carriage return are prefixed (`reports/render.py`) |
| Personal data in shared reports | `--redact` / `--redact-ips` replace values with keyed pseudonyms and fail closed if any remains (`reports/redact.py`) |

### The Docker stack (boundary 5)

| Threat | Controls |
| -------- | ---------- |
| Access from the network | Every port is published on 127.0.0.1 only (`pipeline/docker-compose.yml`) |
| A compromised stage | Prohori's containers run as a non-root user with memory limits; Grafana reads the warehouse through a read-only role (`pipeline/postgres/warehouse-init.sql`) |
| Tampered images | Every image pinned by digest |

### Supply chain (boundary 6)

| Threat | Controls |
| -------- | ---------- |
| Compromised dependencies | `uv.lock` with hashes; Dependabot; the Airflow image's drivers installed with `--require-hashes` |
| Compromised CI actions | Every action pinned to a full commit SHA (repository policy); zizmor and actionlint; least-privilege workflow permissions |
| Secrets committed | gitleaks in pre-commit and CI, GitHub secret scanning |
| Vulnerable code | CodeQL, OpenSSF Scorecard, strict mypy |
| Tampered releases | PyPI trusted publishing (no stored token) with PyPI attestations, a TestPyPI rehearsal, a signed provenance attestation for the wheel and sdist (from 1.0.1, attached to the GitHub release) and for the container image (`gh attestation verify`) |

## Residual risks

- **Detection can be evaded.** Slow or widely distributed attacks stay under the thresholds;
  the held-out evaluation measures this ([SIMULATOR.md](SIMULATOR.md)). Anything not in the
  logs is invisible.
- **Pickle model files run code when loaded.** The hash check only proves the file is the one
  you trained.
- **The Docker stack has no authentication.** It is bound to localhost and meant for one
  analyst's machine; do not expose it.
- **Free-tier LLM data use.** On Gemini's free tier, Google may use and review what is sent,
  even redacted.
- **Injected claims made with real values.** An answer such as "no action needed" names no
  unknown value and passes the checks; the scripted adversary in the evaluation shows it.
- **Third-party data is evidence, not proof.** Reputation and geolocation can be wrong or stale.
- **The evaluation is synthetic**, and written by the rules' author.

## Out of scope

- Attackers who already control the analyst's machine or account.
- Denial of service against the outside services themselves.
- Making Prohori safe to expose as a network service: it is not one.
