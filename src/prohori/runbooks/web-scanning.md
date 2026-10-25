# Web scanning

**Rules:** PRH-WEB-001

## What it means

One source IP requested many different paths that do not exist or are forbidden. A crawler or
scanner is looking for hidden pages, old backups or admin panels. Scanning is constant on the
internet; what matters is whether it found anything.

## Triage

1. List the requested paths and look for any that returned 200 or a redirect to content.
2. Check whether the same IP also sent injection attempts or sensitive-file probes (PRH-WEB-002,
   PRH-WEB-004).
3. Check the user agent and the IP: known search-engine crawler, scanning service or unknown host.

## Recommended actions

- Make sure nothing sensitive is reachable: remove backups, old admin panels and test pages from
  the web root.
- Block or rate-limit the IP if the scanning continues or is aggressive.
- Return the same response for missing and forbidden paths where possible.

## False positives

- Search-engine crawlers following stale links.
- A broken page that references many missing assets.

## ATT&CK

- T1595.003 Active Scanning: Wordlist Scanning (Reconnaissance)
