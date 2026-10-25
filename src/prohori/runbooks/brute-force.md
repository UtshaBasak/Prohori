# Brute-force sign-in attempts

**Rules:** PRH-AUTH-001

## What it means

One source IP failed to sign in many times in a few minutes, against the web app or SSH. Someone
is guessing passwords. On its own this is an attempt, not a compromise; the danger is a later
success (PRH-AUTH-003).

## Triage

1. Check whether any sign-in from the same IP succeeded during or after the burst.
2. List the accounts targeted. One account suggests a targeted guess; many suggest spraying
   (PRH-AUTH-002).
3. Look up the IP: hosting provider, VPN, known abuse reports, or a customer's office NAT.
4. Check whether the burst is still going on.

## Recommended actions

- Block or rate-limit the source IP at the firewall, reverse proxy or application while you
  investigate.
- If any sign-in from the IP succeeded, follow the runbook for PRH-AUTH-003.
- For SSH, disable password authentication and allow keys only; restrict SSH to known networks.
- Make sure account lockout or progressive delays and bot checks are enabled on the sign-in form.

## False positives

- Many users behind one shared NAT or proxy address.
- A script, integration or password manager retrying a stale password.

## ATT&CK

- T1110 Brute Force, T1110.001 Password Guessing (Credential Access)
