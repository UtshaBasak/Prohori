# Successful sign-in after many failures from one IP and 3 related alerts

| | |
|---|---|
| Incident | `INC-ee7c8818fbb34989` |
| Status | open |
| Severity | **critical** (score 100) |
| Confidence | high |
| First seen | 2026-10-24 21:10:00 UTC |
| Last seen | 2026-10-24 21:13:10 UTC |

## Summary

Critical incident (score 100, high confidence): 4 alert(s) from 3 rule(s) between 2026-10-24 21:10:00 UTC and 2026-10-24 21:13:10 UTC, from 203.0.113.7, involving u-2001.

Main factors:

- Most severe alert: PRH-AUTH-003 (critical)
- 2 more rules fired: PRH-ACCT-001, PRH-AUTH-001
- A sign-in succeeded after failed attempts

## Timeline

| Time | Kind | What happened |
|------|------|---------------|
| 2026-10-24 21:10:00 UTC | event | \[app-security\] auth.signin.failure (failure), account u-2001, from 203.0.113.7, POST /api/auth/signin, client web |
| 2026-10-24 21:10:03 UTC | event | \[app-security\] auth.signin.failure (failure), account u-2001, from 203.0.113.7, POST /api/auth/signin, client web |
| 2026-10-24 21:10:06 UTC | event | \[app-security\] auth.signin.failure (failure), account u-2001, from 203.0.113.7, POST /api/auth/signin, client web |
| 2026-10-24 21:10:09 UTC | event | \[app-security\] auth.signin.failure (failure), account u-2001, from 203.0.113.7, POST /api/auth/signin, client web |
| 2026-10-24 21:10:12 UTC | event | \[app-security\] auth.signin.failure (failure), account u-2001, from 203.0.113.7, POST /api/auth/signin, client web |
| 2026-10-24 21:10:15 UTC | event | \[app-security\] auth.signin.failure (failure), account u-2001, from 203.0.113.7, POST /api/auth/signin, client web |
| 2026-10-24 21:10:18 UTC | event | \[app-security\] auth.signin.failure (failure), account u-2001, from 203.0.113.7, POST /api/auth/signin, client web |
| 2026-10-24 21:10:21 UTC | event | \[app-security\] auth.signin.failure (failure), account u-2001, from 203.0.113.7, POST /api/auth/signin, client web |
| 2026-10-24 21:10:24 UTC | event | \[app-security\] auth.signin.failure (failure), account u-2001, from 203.0.113.7, POST /api/auth/signin, client web |
| 2026-10-24 21:10:27 UTC | event | \[app-security\] auth.signin.failure (failure), account u-2001, from 203.0.113.7, POST /api/auth/signin, client web |
| 2026-10-24 21:10:27 UTC | alert | Alert PRH-AUTH-001 (high): Brute-force sign-in attempts from one IP |
| 2026-10-24 21:11:05 UTC | event | \[app-security\] auth.signin.success (success), account u-2001, from 203.0.113.7, POST /api/auth/signin, client web |
| 2026-10-24 21:11:05 UTC | alert | Alert PRH-AUTH-003 (critical): Successful sign-in after many failures from one IP |
| 2026-10-24 21:12:30 UTC | event | \[app-security\] account.2fa.disabled (success), account u-2001, from 203.0.113.7, DELETE /api/account/2fa, client web |
| 2026-10-24 21:12:30 UTC | alert | Alert PRH-ACCT-001 (high): Sensitive account change shortly after sign-in |
| 2026-10-24 21:13:10 UTC | event | \[app-security\] account.bkash.changed (success), account u-2001, from 203.0.113.7, PATCH /api/account/payout, client web |
| 2026-10-24 21:13:10 UTC | alert | Alert PRH-ACCT-001 (high): Sensitive account change shortly after sign-in |

## Indicators

### ip: `203.0.113.7`

| Provider | Retrieved | Data |
|----------|-----------|------|
| offline | 2026-10-01 00:00:00 UTC | country: NL; city: Amsterdam; asn: 64501; as\_org: Example Hosting B.V. (fictional); network: 203.0.113.0/24; abuse\_score: 97; reports: 412; malicious: 9; suspicious: 2; is\_tor: False; usage\_type: Data Center/Web Hosting/Transit (Synthetic offline fixture for documentation addresses; not real data.) |

### user\_agent: `python-requests/2.32.3`

No enrichment.

## Affected entities

| Field | Values |
|-------|--------|
| `source.ip` | `203.0.113.7` |
| `user.email_hash` | `0cc175b9c0f1b6a831c399e269772661` |
| `user.id` | `u-2001` |

## Evidence

### `PRH-AUTH-003` Successful sign-in after many failures from one IP (critical)

- 2026-10-24 21:10:00 UTC to 2026-10-24 21:11:05 UTC
- 5 x failure then 1 x success for source.ip=203.0.113.7 within 15m
- Events: `evt-98e13f6d307f2e3be16558ed`, `evt-ef2ea440d254bf4a8d4680f6`, `evt-1ee56267cc7a1b10b9494687`, `evt-bbc30d1e50633effa8d81596`, `evt-c17a57243deeaf70a93c331e`, `evt-d921c9a6c26404450a3b9d46`

### `PRH-AUTH-001` Brute-force sign-in attempts from one IP (high)

- 2026-10-24 21:10:00 UTC to 2026-10-24 21:10:27 UTC
- 10 matching events (threshold 10) for source.ip=203.0.113.7 within a 5m window
- Events: `evt-98e13f6d307f2e3be16558ed`, `evt-ef2ea440d254bf4a8d4680f6`, `evt-1ee56267cc7a1b10b9494687`, `evt-bbc30d1e50633effa8d81596`, `evt-c17a57243deeaf70a93c331e`, `evt-e324aaa8ec2561e6cd038ca7`, `evt-ada9bb363aaf4af58d44c821`, `evt-c480d3039cfb186a6c233449`, `evt-3b80f435be26e14e36c3ac89`, `evt-b1604296ea5f5716a233d047`

### `PRH-ACCT-001` Sensitive account change shortly after sign-in (high)

- 2026-10-24 21:11:05 UTC to 2026-10-24 21:13:10 UTC
- 1 x signin then 1 x change for user.id=u-2001 within 30m
- Events: `evt-d921c9a6c26404450a3b9d46`, `evt-6f29461df339acb9232831d2`

### `PRH-ACCT-001` Sensitive account change shortly after sign-in (high)

- 2026-10-24 21:11:05 UTC to 2026-10-24 21:12:30 UTC
- 1 x signin then 1 x change for user.id=u-2001 within 30m
- Events: `evt-d921c9a6c26404450a3b9d46`, `evt-b4a805719a3e5812131f275e`

## ATT&CK mapping

Enterprise ATT&CK v20.0.

| Tactic | Techniques |
|--------|------------|
| Initial Access | T1078 Valid Accounts |
| Persistence | T1078 Valid Accounts, T1098 Account Manipulation, T1556.006 Multi-Factor Authentication |
| Privilege Escalation | T1078 Valid Accounts, T1098 Account Manipulation |
| Defense Impairment | T1556.006 Multi-Factor Authentication |
| Credential Access | T1110 Brute Force, T1110.001 Password Guessing, T1556.006 Multi-Factor Authentication |

## Score breakdown

| Points | Reason |
|-------:|--------|
| +50 | Most severe alert: PRH-AUTH-003 (critical) |
| +20 | 2 more rules fired: PRH-ACCT-001, PRH-AUTH-001 |
| +20 | A sign-in succeeded after failed attempts |
| +15 | Sensitive account or admin change: account.2fa.disabled, account.bkash.changed |
| +20 | Reputation of 203.0.113.7: abuse confidence 97; 9 vendors flag it as malicious (from bundled demo data) |
| +10 | Sign-in to u-2001 from 203.0.113.7, an IP not seen for this account before (1 earlier IP) |
| +5 | Sign-in to u-2001 with client web, not seen for this account before |
| -40 | Capped at 100 |
| **100** | **Total** |

## Recommended actions

Prohori only recommends actions; it never changes anything itself.

1. End all sessions of the account and force a password reset.
1. Block the source IP.
1. Revert unauthorised changes, such as a changed payout number or disabled two-step verification.
1. Require two-step verification for the account.
1. Block or rate-limit the source IP at the firewall, reverse proxy or application while you investigate.
1. If any sign-in from the IP succeeded, follow the runbook for PRH-AUTH-003.
1. For the web app, make sure account lockout or progressive delays and bot checks are enabled on the sign-in form.
1. If the owner did not make the change: end all sessions, revert the change, reset the password and re-enable two-step verification.
1. Hold payouts to a newly changed payout number until the owner confirms it.
1. Consider requiring re-authentication or a confirmation code for these changes.

## Confidence and limitations

Confidence: **high**.

- Enrichment offline: only bundled demo data, local GeoLite2 data and cached answers were used
- Enrichment of 203.0.113.7 is bundled demo data, not real reputation
- Single log source (app-security): no other log corroborates it
- Possible benign cause for PRH-ACCT-001: The account owner changing their own settings after signing in
- Possible benign cause for PRH-ACCT-001: Support staff helping a user recover an account
- Possible benign cause for PRH-AUTH-001: Many users behind one shared NAT or proxy address
- Possible benign cause for PRH-AUTH-001: A script or password manager retrying a stale password
- Possible benign cause for PRH-AUTH-003: A legitimate user who forgot their password and finally entered it correctly
- Possible benign cause for PRH-AUTH-003: Several users behind one shared NAT, some failing and one succeeding

## Appendix

### Rules fired

| Rule | Title | Alerts | Rule file SHA-256 |
|------|-------|-------:|-------------------|
| `PRH-ACCT-001` | Sensitive account change shortly after sign-in | 2 | `f523b6831891b2444e932426d69ce28f08156b251a5bc771b312de3fcf1049c9` |
| `PRH-AUTH-001` | Brute-force sign-in attempts from one IP | 1 | `510045192d86bc5c3e4baae6cea620b22206abf12aa0980b49125fd0af94e97f` |
| `PRH-AUTH-003` | Successful sign-in after many failures from one IP | 1 | `8c63236a86391c4cef1655511802f13d1c331a5a26c1392dc605d6815c73d6bd` |

### Inputs

| File | Parser | Events | Bytes | SHA-256 |
|------|--------|-------:|------:|---------|
| `account-takeover.jsonl` | app\_json | 17 | 7534 | `20fea77a6a1a1e56a5ccabd157109c79bb71796f9aa95389f2f8a069e62a48d6` |

### Versions

- Incident built with: prohori 0.1.0.dev0 (enrichment: offline)
- Report rendered with: prohori 0.1.0.dev0
- ATT&CK: Enterprise v20.0
- Incident file: `INC-ee7c8818fbb34989.json`, SHA-256 `79be9f57cd0df2cd371d06bfd7682f1bc6f7bdf5c27a460327ff5bce5170762b`

### Privacy

Not redacted: account names, ids and IP addresses are shown as logged.
