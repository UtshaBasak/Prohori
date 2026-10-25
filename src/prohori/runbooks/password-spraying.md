# Password spraying or credential stuffing

**Rules:** PRH-AUTH-002

## What it means

One source IP failed to sign in to several different accounts in a short time. Spraying tries a
few common passwords against many accounts to stay under per-account lockouts; credential stuffing
replays username and password pairs leaked from other sites.

## Triage

1. List the targeted accounts (by email hash or user id) and check which of them signed in
   successfully from any IP afterwards.
2. Check whether the same accounts were targeted from other IPs (a distributed campaign).
3. Look up the source IP: hosting provider, proxy network or residential address.

## Recommended actions

- Block or rate-limit the source IP and add a bot check to the sign-in form.
- Force a password reset for targeted accounts that signed in successfully afterwards, and end
  their sessions.
- Encourage or require two-step verification for the targeted accounts.
- Check the targeted addresses against known breach data if your policy allows it.

## False positives

- An office or campus NAT where several users mistype their passwords at the same time.
- Automated sign-in tests run against several test accounts.

## ATT&CK

- T1110.003 Password Spraying, T1110.004 Credential Stuffing (Credential Access)
