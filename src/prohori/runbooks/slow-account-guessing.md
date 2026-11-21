# Slow password guessing on one account

**Rules:** PRH-AUTH-006

## What it means

One existing account collected many failed sign-ins over a day. Each burst may be small, and the
addresses may change, but someone keeps trying the same account. Slow attackers do this to stay
under rate limits and lockouts.

## Triage

1. Check whether any sign-in to the account succeeded after the failures (PRH-AUTH-010).
2. Group the failures by address and by hour: a steady trickle from many places is an attack; a
   burst from one device is usually a stale password.
3. For SSH root or admin accounts on an internet-facing server, check whether this is ordinary
   scanning noise.

## Recommended actions

- Make the account owner confirm recent activity; reset the password if in doubt.
- Require two-step verification for the account.
- For SSH, disable password logins (or root logins) and restrict SSH to known networks.
- For the web app, lock or slow down the account after repeated failures, with a recovery path.

## False positives

- SSH root on a server reachable from the internet, which scanners try all day.
- A script, integration or device retrying a stale password for hours.

## ATT&CK

- T1110 Brute Force, T1110.001 Password Guessing (Credential Access)
