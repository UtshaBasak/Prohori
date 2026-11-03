# Third-Party Data and Services

Prohori's own code is MIT-licensed (see [LICENSE](../LICENSE)). It uses third-party data,
services and software whose terms apply in addition. This page summarises those terms as
checked on the date given in each section (first on **2026-10-26**, completed on
**2026-11-02**). It is not legal advice, and the linked originals are authoritative. Terms
change, so check them again before relying on them.

## Contents

- [MITRE ATT&CK](#mitre-attck)
- [MaxMind GeoLite2](#maxmind-geolite2)
- [AbuseIPDB](#abuseipdb)
- [VirusTotal](#virustotal)
- [Gemini API](#gemini-api)
- [UNSW-NB15](#unsw-nb15)
- [CIC-IDS-2017 (improved release)](#cic-ids-2017-improved-release)
- [Python dependencies](#python-dependencies)
- [Pipeline software (Docker stack and the `pipeline` extra)](#pipeline-software-docker-stack-and-the-pipeline-extra)
- [The container image on GitHub Packages](#the-container-image-on-github-packages)
- [Sample data](#sample-data)

## MITRE ATT&CK

- **Used for:** technique and tactic tags on the built-in rules (`prohori.rules.attack`), verified
  against Enterprise ATT&CK v20.0 (see [RULES.md](RULES.md#attck-mapping)).
- **Terms:** <https://attack.mitre.org/resources/legal-and-branding/terms-of-use/>. MITRE grants
  a non-exclusive, royalty-free licence to use ATT&CK for research, development and commercial
  purposes; copies must reproduce MITRE's copyright designation and the licence.
- **Notice:** © 2026 The MITRE Corporation. This work is reproduced and distributed with the
  permission of The MITRE Corporation.
- **Prohori ships:** technique ids, names and tactic names for the rules
  (`src/prohori/rules/attack.py`), and, for the LLM analyst's retrieval, every active technique's
  id, name, tactics and the first paragraph of its description, shortened and without citations
  (`src/prohori/llm/data/attack.jsonl`, built by `scripts/build_attack_corpus.py`). Both carry
  the notice above. The STIX bundle itself is not shipped.

## MaxMind GeoLite2

- **Used for:** optional local geolocation and ASN lookups (`geolite2` provider).
- **Terms:** GeoLite End User License Agreement, <https://www.maxmind.com/en/geolite2/eula>
  (updated 2026-02-12).
- **Attribution:** required. Prohori shows the example attribution from the agreement with every
  GeoLite2 result: "This product includes GeoLite Data created by MaxMind, available from
  `https://www.maxmind.com`."
- **No redistribution:** Prohori never downloads, bundles or publishes the databases. Each user
  downloads them with their own free MaxMind account.
- **Updates:** "You shall cease use of and destroy (i) any old versions of the Services within
  thirty (30) days following the release of the updated GeoLite Databases". Keep the databases
  current with MaxMind's `geoipupdate` tool.
- **Restrictions:** the data must not be used to identify or locate a specific person or
  household, or for purposes covered by the US Fair Credit Reporting Act.

## AbuseIPDB

- **Used for:** optional IP reputation (`abuseipdb` provider, API v2 `check` endpoint).
- **Terms:** <https://www.abuseipdb.com/legal>; API documentation and limits:
  <https://docs.abuseipdb.com/>.
- **Limits:** the documentation lists 1,000 `check` requests per day for the Standard plan, which
  is the plan a free account gets (the documentation does not label it "free"; this is our
  reading of the plan list). Prohori's default daily budget is 1,000 and configurable.
- **Use:** free plans are for evaluation, contributing reports and non-commercial personal
  projects; commercial use requires a paid plan. One account per person; multiple accounts to
  raise the quota are not allowed.
- **Data:** the terms prohibit republishing or reselling AbuseIPDB data. Prohori keeps answers in
  a private local cache only. Reports that include AbuseIPDB results should stay internal.

## VirusTotal

- **Used for:** optional IP reputation (`virustotal` provider, API v3).
- **Terms and limits:** <https://docs.virustotal.com/reference/public-vs-premium-api>: "The Public
  API is limited to 500 requests per day and a rate of 4 requests per minute." It "must not be
  used in commercial products or services" or in business workflows that do not contribute new
  files, and multiple accounts to get around the limits are not allowed.
- **Privacy:** indicators queried through the API are added to the VirusTotal dataset. Prohori
  never sends private, reserved or documentation addresses (see [ENRICHMENT.md](ENRICHMENT.md)).

## Gemini API

- **Used for:** the opt-in LLM analyst's `gemini` provider (`prohori explain`, `prohori ask`),
  through the `google-genai` SDK in the `llm` extra. Checked on **2026-11-02**.
- **Terms:** the [Gemini API Additional Terms of Service](https://ai.google.dev/gemini-api/terms)
  (effective 2026-03-23) and Google's Terms of Service.
- **Free tier:** content sent and answers received may be used to improve Google's products,
  and human reviewers may read them; the terms ask users not to submit sensitive,
  confidential or personal information. Prohori prints a reminder on every free-tier request
  (`PROHORI_LLM_TIER=free`, the default) and sends only a redacted payload
  ([LLM_ANALYST.md](LLM_ANALYST.md#what-is-sent)). Do not send data you may not share.
- **Prohori ships:** nothing from Google except, in `evaluation/llm/recordings/gemini.jsonl`
  (the repository only, not the package), answers Gemini gave about synthetic incidents,
  kept to make the evaluation reproducible.

## UNSW-NB15

- **Used for:** training and testing the flow detectors (`prohori.ml`, since 0.2.0); see
  [DATASETS.md](DATASETS.md). Terms checked on **2026-10-30**.
- **Terms:** <https://research.unsw.edu.au/projects/unsw-nb15-dataset>: "Free use of the
  UNSW-NB15 dataset for academic research purposes is hereby granted in perpetuity. Use for
  commercial purposes should be agreed by the authors." The authors (Nour Moustafa and Jill Slay)
  assert copyright and ask users to cite the papers listed on that page.
- **Prohori ships:** nothing from the dataset. Users download it themselves; the test fixtures
  copy only its column names, with made-up values.

## CIC-IDS-2017 (improved release)

- **Used for:** training and testing the flow detectors; see [DATASETS.md](DATASETS.md). Checked
  on **2026-10-30**.
- **Terms:** the distributor of the improved release
  (<https://intrusion-detection.distrinet-research.be/CNS2022/>) states no licence and asks users
  to cite its paper (Liu, Engelen et al., IEEE CNS 2022). The original dataset's page
  (<https://www.unb.ca/cic/datasets/ids-2017.html>) says the data is "publicly available for
  researchers" and asks for a citation of Sharafaldin et al., ICISSP 2018. With no licence
  stated, treat it as research use only and do not redistribute it.
- **Prohori ships:** nothing from the dataset. `scripts/download_datasets.py fetch cicids2017`
  downloads it from the distributor when a user asks; the fixtures copy only its column names.

## Python dependencies

Checked on **2026-11-02** from each installed package's own metadata (the versions in
`uv.lock`). Prohori's wheel contains only its own code and data; pip installs these packages
from PyPI.

| Package | Installed with | Licence |
| --------- | ---------------- | --------- |
| pydantic | always | MIT |
| PyYAML | always | MIT |
| rich | always | MIT |
| typer | always | MIT |
| tzdata | always | Apache 2.0 |
| google-re2 | always | BSD |
| httpx | always | BSD 3-Clause |
| Jinja2 | always | BSD 3-Clause |
| geoip2, maxminddb | `geoip` extra | Apache 2.0 |
| scikit-learn, pandas, joblib | `ml` extra | BSD 3-Clause |
| pyarrow | `ml` extra | Apache 2.0 |
| confluent-kafka | `pipeline` extra | Apache 2.0 (librdkafka: BSD 2-Clause) |
| duckdb | `pipeline` extra | MIT |
| psycopg, psycopg-binary | `pipeline` extra | LGPL 3.0 |
| google-genai | `llm` extra | Apache 2.0 |

Their dependencies, installed with them, are under permissive licences (MIT, BSD, Apache 2.0,
ISC, PSF) except **certifi** (MPL 2.0) and **psycopg** above. Both are used unmodified as
separate, replaceable libraries, which their licences allow from MIT-licensed code. The
development tools (pytest, ruff, mypy, dbt and others in the `dev` group) are not installed with
the package.

## Pipeline software (Docker stack and the `pipeline` extra)

Checked on **2026-11-01** (Airflow's drivers on **2026-11-02**). The Python package ships none
of this software: the `pipeline` extra installs the Python packages from PyPI, and
`prohori pipeline up` pulls the container images and builds Prohori's own two images locally.
The published image is covered [below](#the-container-image-on-github-packages).

| Software | Used for | Licence |
| ---------- | ---------- | --------- |
| [Redpanda](https://github.com/redpanda-data/redpanda/tree/dev/licenses) Community Edition (container image) | Kafka-compatible message broker | Business Source License 1.1 for the core (it converts to Apache 2.0 four years after each release); enterprise features under the Redpanda Community License. Running it yourself, as the stack does, is allowed; offering it as a hosted streaming service is not. |
| [PostgreSQL](https://www.postgresql.org/about/licence/) (container image) | The warehouse | PostgreSQL Licence (permissive, BSD-style) |
| [Apache Airflow](https://github.com/apache/airflow/blob/main/LICENSE) (container image) | Scheduled jobs (orchestration profile) | Apache 2.0 |
| [Grafana](https://github.com/grafana/grafana/blob/main/LICENSE) OSS (container image) | Dashboards | AGPL 3.0. The stack runs the official image unmodified; the dashboards and provisioning files are Prohori's own (MIT). |
| [confluent-kafka](https://github.com/confluentinc/confluent-kafka-python) and librdkafka | Kafka client | Apache 2.0; librdkafka BSD 2-Clause |
| [psycopg 3](https://www.psycopg.org/) | PostgreSQL client | LGPL 3.0 (used unmodified as a library, which the LGPL permits from MIT code) |
| [DuckDB](https://duckdb.org/) | Lite-mode database | MIT |
| [dbt-core](https://github.com/dbt-labs/dbt-core), dbt-duckdb, dbt-postgres | Warehouse models (a development dependency group, not installed with the package) | Apache 2.0 |
| [psycopg2-binary](https://www.psycopg.org/) and [asyncpg](https://github.com/MagicStack/asyncpg), in the locally built Airflow image | Airflow's own PostgreSQL database | psycopg2: LGPL with exceptions (unmodified); asyncpg: Apache 2.0 |
| [uv](https://github.com/astral-sh/uv) (build stage of both images only) | Installs the locked dependencies | MIT or Apache 2.0 |

## The container image on GitHub Packages

`ghcr.io/utshabasak/prohori`, published with each release ([RELEASING.md](RELEASING.md)), *does*
redistribute third-party software. Checked on **2026-11-02**:

- **Base image:** `python:3.13-slim` (Debian): the Python interpreter (PSF License) and Debian
  packages under their own licences, listed in the image under `/usr/share/doc/*/copyright`.
- **Python packages:** Prohori with the `pipeline` extra and the dependencies above, installed
  unmodified from PyPI at the versions in `uv.lock`. They keep their licence files in the
  image's `site-packages`. psycopg (LGPL 3.0) is a separate, replaceable package; its source is
  at <https://github.com/psycopg/psycopg>.
- **Not included:** uv (build stage only), the broker, PostgreSQL, Grafana and Airflow, which the
  stack pulls from their own publishers.

The image's `org.opencontainers.image.licenses` label is `MIT`, which is Prohori's own licence;
the components above keep theirs.

## Sample data

All sample logs and the offline enrichment fixture are synthetic and use documentation address
ranges (RFC 5737, RFC 3849). Organisation names in the fixture are fictional. The ML fixture
datasets in `tests/fixtures/ml/` are synthetic too.
