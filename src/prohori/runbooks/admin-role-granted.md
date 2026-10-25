# Admin role granted

**Rules:** PRH-ADMIN-001

## What it means

An account received an admin role. Granting admin rights to an account they control is how
attackers keep access after taking over an admin session, so every grant should be confirmed with
the person who made it.

## Triage

1. Identify who granted the role (the acting admin) and which account received it.
2. Confirm the grant with the acting admin through a separate channel.
3. Check the acting admin's session: sign-in IP and client, recent failures, refresh-token reuse
   (PRH-AUTH-003, PRH-SESS-001).
4. Review what the new admin account did afterwards: payouts, user deletions, messages.

## Recommended actions

- If the grant was not planned: remove the role, end the sessions of both accounts and reset the
  acting admin's password.
- Revert any admin actions taken by the new account.
- Require two-step verification for all admin accounts and keep the number of admins small.

## False positives

- Planned onboarding of a new administrator.

## ATT&CK

- T1098 Account Manipulation (Persistence, Privilege Escalation)
