# Successful sign-in after many failures

**Rules:** PRH-AUTH-003

## What it means

An IP failed to sign in several times and then succeeded. The attacker has probably found a valid
password. Treat the account, or the server for SSH, as compromised until shown otherwise.

## Triage

1. Identify the account that signed in and confirm with its owner whether it was them.
2. Review everything the session did after signing in: account changes, payout number changes,
   orders, data exports, admin actions; for SSH, commands run, new users, keys and cron jobs.
3. Check for other sign-ins to the same account from new IPs or clients.

## Recommended actions

- End all sessions of the account and force a password reset.
- Block the source IP.
- Revert unauthorised changes, such as a changed payout number or disabled two-step verification.
- For SSH, isolate the server, check `authorized_keys`, users and scheduled jobs, and rotate
  credentials stored on it.
- Require two-step verification for the account.

## False positives

- A legitimate user who forgot their password and finally entered it correctly.
- Several users behind one shared NAT, some failing and one succeeding.

## ATT&CK

- T1110 Brute Force (Credential Access)
- T1078 Valid Accounts (Initial Access)
