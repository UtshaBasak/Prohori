# Sensitive account change after sign-in

**Rules:** PRH-ACCT-001

## What it means

Soon after signing in, the account's password, payout number (bKash) or two-step verification
setting changed. Account takeovers usually do this first, to lock out the owner or redirect
payouts. Most of these changes are made by the owner, so the sign-in context decides.

## Triage

1. Compare the sign-in IP, client and user agent with the account's usual ones.
2. Check for failed sign-ins, lockouts or refresh-token reuse for the account beforehand
   (PRH-AUTH-001 to 004, PRH-SESS-001).
3. Contact the owner through a channel the attacker cannot control (not the account's own email if
   it may have changed).

## Recommended actions

- If the owner did not make the change: end all sessions, revert the change, reset the password and
  re-enable two-step verification.
- Hold payouts to a newly changed payout number until the owner confirms it.
- Consider requiring re-authentication or a confirmation code for these changes.

## False positives

- The account owner changing their own settings after signing in.
- Support staff helping a user recover an account.

## ATT&CK

- T1098 Account Manipulation (Persistence, Privilege Escalation)
- T1556.006 Modify Authentication Process: Multi-Factor Authentication (Defense Impairment,
  Persistence, Credential Access)
