# Credential stuffing across many addresses

**Rules:** PRH-AUTH-008, PRH-AUTH-009

## What it means

Many different accounts failed to sign in from many different addresses within an hour, or many
addresses tried emails the site does not know. Credential stuffing replays leaked email and
password pairs from other breaches, spread over many addresses and trying each account only a
few times, so no per-address or per-account limit is reached.

## Triage

1. Check which accounts signed in successfully during the burst: those passwords are known to the
   attacker.
2. Compare the user agents and timing of the failures with normal traffic; scripted clients are
   often uniform.
3. Check whether the failure rate is far above the site's usual level for this hour.

## Recommended actions

- Force a password reset and end every session for accounts that signed in during the burst.
- For the web app, turn on a bot check for sign-in and rate-limit by device fingerprint as well
  as address.
- Encourage two-step verification and check new passwords against known breached passwords.

## False positives

- A busy site, where many users fail or mistype their email in an hour on an ordinary day.
- A sign-in outage, a forced password reset or a mail campaign with a wrong sign-in link.

## ATT&CK

- T1110.004 Credential Stuffing (Credential Access)
