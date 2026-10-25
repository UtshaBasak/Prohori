# Authorisation denials across many resources

**Rules:** PRH-AUTHZ-001

## What it means

One source IP was refused access to many different paths in a short time. Someone is probing for
records or routes they should not reach, such as other users' orders (insecure direct object
references) or admin endpoints.

## Triage

1. List the denied paths and look for patterns: sequential ids, admin routes, other users' records.
2. Identify the account behind the requests and whether it is new or recently took over.
3. Check whether requests to similar paths from the same IP or account succeeded, which would mean
   an access-control gap.

## Recommended actions

- Rate-limit or block the IP and suspend the account if the probing is deliberate.
- Fix any path that returned data it should not have, and review its access checks.
- Prefer unguessable identifiers for user-owned records.

## False positives

- A client release that calls endpoints the user's role no longer allows.
- Security testing or crawling by the site's own team.

## ATT&CK

- T1595.003 Active Scanning: Wordlist Scanning (Reconnaissance)
