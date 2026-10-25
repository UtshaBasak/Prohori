# Enrichment

Prohori enriches IP addresses with geolocation, network ownership and reputation. Every source
is optional and Prohori works fully offline without them.

```bash
prohori enrich 203.0.113.7 --offline                 # bundled demo data, no network
prohori enrich 203.0.113.7 --offline --format json   # JSON Lines, one report per address
prohori enrich 8.8.8.8 1.1.1.1                       # configured providers, cached
prohori enrich 8.8.8.8 --no-cache                    # ignore cached answers
```

Exit codes: `0` done (a failed lookup is reported as a note on that address), `2` invalid usage,
an argument that is not an IP address, or an invalid setting. Arguments are validated before any
lookup, so a mistyped hostname is never sent anywhere.

## Providers

| Provider | Kind | Needs | Free-tier limits (checked 2026-10-26) |
|----------|------|-------|----------------------------------------|
| `offline` | Bundled synthetic fixture | Nothing; only with `--offline` | None |
| `geolite2` | Local MaxMind GeoLite2 databases | Free MaxMind account, downloaded `.mmdb` files, `pip install "prohori[geoip]"` | None (local files) |
| `abuseipdb` | AbuseIPDB API v2 `check` | `ABUSEIPDB_API_KEY` | 1,000 checks per day on the Standard plan |
| `virustotal` | VirusTotal API v3 IP report | `VIRUSTOTAL_API_KEY` | 4 requests per minute, 500 per day |

Both API free tiers are for **non-commercial use only**. Terms and sources are in
[LICENSES.md](LICENSES.md).

Every result records the provider, when the data was retrieved, and a note on how far it can be
trusted. Providers map their answers onto shared keys so later steps can score them without
knowing the source:

| Key | Meaning | From |
|-----|---------|------|
| `country`, `city` | ISO country code, city name | GeoLite2, AbuseIPDB, VirusTotal |
| `asn`, `as_org`, `network` | Autonomous system, its owner or ISP, network range | GeoLite2, AbuseIPDB, VirusTotal |
| `abuse_score`, `reports` | Abuse confidence 0-100, number of reports (last 90 days) | AbuseIPDB |
| `is_tor`, `usage_type` | Tor exit node, kind of network (data centre, ISP, ...) | AbuseIPDB |
| `malicious`, `suspicious` | Security vendors flagging the address in the last analysis | VirusTotal |

## Privacy: what leaves the machine

- **Private, reserved and documentation addresses are never sent to external services.** The
  blocked ranges are listed explicitly in `src/prohori/enrich/addresses.py` (RFC 1918, carrier-grade
  NAT, loopback, link-local, multicast, benchmarking, the RFC 5737 / RFC 3849 / RFC 9637
  documentation ranges and others), including IPv6 addresses that embed one of them
  (IPv4-mapped, 6to4, NAT64) and IPv6 addresses with a zone id.
- Local providers (the offline fixture and GeoLite2) answer for any address.
- Querying an address tells the provider you are interested in it. **VirusTotal adds queried
  indicators to its dataset**, visible to its other users; do not enrich addresses that would
  reveal something sensitive about you or your users.
- API keys are read from the environment or a git-ignored `.env` file, sent only in request
  headers, and never printed, logged or cached.

## Offline mode

`--offline` never opens a network connection. Answers come from:

1. the bundled fixture `prohori/enrich/data/offline.json`: synthetic data for the documentation
   addresses used in Prohori's samples (marked "not real data", retrieved 2026-10-01);
2. local GeoLite2 databases, if configured;
3. cached answers from earlier online runs.

The fixture only covers documentation addresses, which are never sent to real providers or
stored in the cache by them, so synthetic and real data cannot mix.

## Cache

Answers are cached in SQLite, per provider and address, for 24 hours by default
(`PROHORI_CACHE_TTL_HOURS`). The file lives in the per-user cache directory
(`%LOCALAPPDATA%\prohori\enrich.sqlite3` on Windows, `~/.cache/prohori/enrich.sqlite3` elsewhere)
unless `PROHORI_CACHE_PATH` is set.

- Successful answers and "no data" answers are cached. Failures (rate limits, timeouts, server
  errors, rejected keys) never are.
- Cached answers keep their original retrieval time and are marked `(cached)`.
- Values are stored as JSON, never pickled. The cache is private: AbuseIPDB's terms restrict
  republishing its data, so do not share the cache file.

## Rate limits and failures

- **Daily budgets** per provider and UTC day (`ABUSEIPDB_DAILY_LIMIT`, default 1,000;
  `VIRUSTOTAL_DAILY_LIMIT`, default 500), stored in the cache file so they hold across runs.
  Every request sent counts, retries included; cache hits do not.
- **Token bucket** for VirusTotal: `VIRUSTOTAL_PER_MINUTE` requests per minute (default 4).
- **Retries:** at most 3 attempts per lookup, with exponential backoff (1 s, 2 s) for timeouts
  and server errors. A `429` response's `Retry-After` is honoured up to 60 seconds.
- **Giving up:** a provider that asks for a longer wait, reports its daily quota used up, runs out
  of budget or rejects the key is skipped for the rest of the run, with a note on each address.
  Nothing retries forever.
- **Timeouts:** 10 seconds per request (`PROHORI_HTTP_TIMEOUT`), 5 seconds to connect.
- Redirects are not followed, responses over 1 MiB are rejected, and error messages never include
  request headers.

## Configuration

Settings come from environment variables, then a `.env` file in the working directory (or
`--env-file PATH`). Only the variables below are read; provider endpoints are fixed in code.

| Variable | Default | Meaning |
|----------|---------|---------|
| `ABUSEIPDB_API_KEY` | - | Enables AbuseIPDB |
| `VIRUSTOTAL_API_KEY` | - | Enables VirusTotal |
| `GEOLITE2_CITY_DB` | - | Path to `GeoLite2-City.mmdb` or `GeoLite2-Country.mmdb` |
| `GEOLITE2_ASN_DB` | - | Path to `GeoLite2-ASN.mmdb` |
| `PROHORI_CACHE_PATH` | per-user cache directory | Cache file |
| `PROHORI_CACHE_TTL_HOURS` | 24 | Cache lifetime |
| `ABUSEIPDB_DAILY_LIMIT` | 1000 | AbuseIPDB requests per UTC day |
| `VIRUSTOTAL_DAILY_LIMIT` | 500 | VirusTotal requests per UTC day |
| `VIRUSTOTAL_PER_MINUTE` | 4 | VirusTotal requests per minute |
| `PROHORI_HTTP_TIMEOUT` | 10 | Seconds per HTTP request |

### Getting the GeoLite2 databases

Prohori never downloads or bundles GeoLite2: the licence forbids redistribution. Create a free
MaxMind account, generate a licence key, and use MaxMind's
[`geoipupdate`](https://github.com/maxmind/geoipupdate) tool to download `GeoLite2-City` and
`GeoLite2-ASN`. The licence requires you to stop using and delete old versions within 30 days of
a new release, so run `geoipupdate` regularly (for example weekly).

## Limits of the data

Reputation is evidence, not proof. Shared hosting, VPNs, mobile carriers and NAT gateways carry
the history of many users; a high abuse score on such an address says little about one request.
Geolocation is approximate and must never be used to locate a person.
