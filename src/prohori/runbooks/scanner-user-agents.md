# Scanner or empty user agent at a high rate

**Rules:** PRH-WEB-003

## What it means

One source IP sent many requests in a minute with a user agent that names a scanning tool (sqlmap,
Nikto, Nuclei, ...) or with no user agent at all. Someone is running an automated vulnerability
scan against the site.

## Triage

1. Check what the scan targeted and whether any requests succeeded unexpectedly.
2. Look for related alerts from the same IP (PRH-WEB-001, PRH-WEB-002, PRH-WEB-004).
3. Confirm the scan was not run by the site's own team or a contracted tester.

## Recommended actions

- Block the IP at the reverse proxy or CDN.
- Follow the runbook of any related alert that shows a successful request.
- Consider rejecting requests with empty user agents on public routes, after checking that
  monitoring and API clients send one.

## False positives

- Health checks or scripts that send no user agent, such as an internal monitor.
- Vulnerability scans the site's own team runs on purpose.

## ATT&CK

- T1595.002 Active Scanning: Vulnerability Scanning (Reconnaissance)
