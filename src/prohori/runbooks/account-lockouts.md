# Account lockouts across many accounts

**Rules:** PRH-AUTH-004

## What it means

Several different accounts were locked out within a short time. A brute-force or spraying campaign
spread over many IPs can stay below per-IP thresholds but still trips per-account lockouts.
Lockouts also stop real users from signing in.

## Triage

1. List the locked accounts and the source IPs of the failures that led to each lockout.
2. Check whether the IPs share a network, provider, country or user agent.
3. Check whether any of the accounts signed in successfully from those IPs.
4. Rule out a recent password policy change, forced reset or broken client release.

## Recommended actions

- Rate-limit or block the attacking networks and enable a bot check on the sign-in form.
- Tell affected users how to unlock their accounts safely; avoid unlocking them all at once while
  the attack continues.
- Force a password reset for accounts that signed in successfully from the attacking IPs.

## False positives

- A password policy change or forced reset that makes many users fail at once.
- A broken client release sending wrong credentials.

## ATT&CK

- T1110 Brute Force (Credential Access)
