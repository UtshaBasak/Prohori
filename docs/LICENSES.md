# Third-Party Data and Services

Prohori's own code is MIT-licensed (see [LICENSE](../LICENSE)). It uses third-party data and
services whose terms apply in addition. This page summarises the terms as checked on
**2026-10-26**; it is not legal advice, and the linked originals are authoritative. Terms change,
so check them again before relying on them.

## MITRE ATT&CK

- **Used for:** technique and tactic tags on the built-in rules (`prohori.rules.attack`), verified
  against Enterprise ATT&CK v20.0 (see [RULES.md](RULES.md#attck-mapping)).
- **Terms:** <https://attack.mitre.org/resources/legal-and-branding/terms-of-use/>. MITRE grants
  a non-exclusive, royalty-free licence to use ATT&CK for research, development and commercial
  purposes; copies must reproduce MITRE's copyright designation and the licence.
- **Notice:** © 2026 The MITRE Corporation. This work is reproduced and distributed with the
  permission of The MITRE Corporation.
- **Prohori ships:** technique ids, names and tactic names only (in
  `src/prohori/rules/attack.py`, which carries the same notice), not the STIX bundle.

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

## Sample data

All sample logs and the offline enrichment fixture are synthetic and use documentation address
ranges (RFC 5737, RFC 3849). Organisation names in the fixture are fictional.
