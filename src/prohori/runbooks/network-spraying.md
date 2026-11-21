# Failed sign-ins for many accounts from one network

**Rules:** PRH-AUTH-007

## What it means

Many different accounts failed to sign in from addresses in the same network (a /24 for IPv4, a
/48 for IPv6) within an hour. Password spraying from several addresses of one provider stays
under the per-address limit of PRH-AUTH-002; counting per network shows it.

## Triage

1. Check whether any of the accounts signed in successfully from the network.
2. Look up the network: hosting provider, VPN, mobile carrier, or a customer's office.
3. Check how many accounts failed once each (spraying) and how many failed and then succeeded
   (ordinary typos behind a shared network).

## Recommended actions

- Rate-limit or challenge sign-ins from the network while you investigate.
- Make the affected account owners reset their passwords if any of them signed in from it.
- For the web app, enforce two-step verification and reject common passwords.

## False positives

- A large office, school or carrier-grade NAT where many people share one network.
- A company-wide password reset or a sign-in outage that makes many users fail at once.

## ATT&CK

- T1110.003 Password Spraying (Credential Access)
