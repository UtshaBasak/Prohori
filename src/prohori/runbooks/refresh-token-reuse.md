# Refresh-token reuse

**Rules:** PRH-SESS-001

## What it means

The app received a refresh token that had already been used. With rotating refresh tokens each one
is valid once, so reuse usually means two parties hold a copy: the user and someone who stole it
(for example through malware, a leaked backup or a compromised device).

## Triage

1. Identify the user and compare the IP, client and user agent of the reuse with the user's recent
   sessions.
2. Check what the token family was used for before the reuse was detected.
3. Look for other reuse events or sign-ins for the same user from unfamiliar IPs.

## Recommended actions

- Make sure the app revoked the whole token family; end all sessions of the user if not.
- Ask the user to sign in again, change their password and check their devices for malware.
- Review recent account changes, orders and payout changes made with the session.

## False positives

- A client that retries a refresh request after a network timeout.
- Two tabs or app instances refreshing the same session at once.

## ATT&CK

- T1528 Steal Application Access Token (Credential Access)
- T1550.001 Application Access Token (Lateral Movement)
