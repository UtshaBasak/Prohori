# Admin action at an unusual hour

**Rules:** PRH-ADMIN-002

## What it means

An admin account did something between 22:00 and 07:00 local time. Real admins rarely work then;
attackers who have taken over an admin session often do, because nobody is watching. On its own
this is a prompt to check, not proof of misuse.

## Triage

1. Ask the admin, through a separate channel, whether they were working at that time.
2. Check the session behind the action: sign-in IP and client, recent failures, new devices
   (PRH-AUTH-003, PRH-ACCT-001, PRH-SESS-001).
3. List everything the account did in that session: role grants, payouts, user changes, exports.

## Recommended actions

- If the admin was not working: end the account's sessions, reset its password and revert its
  actions.
- Require two-step verification for admin accounts, and re-authentication for sensitive admin
  actions.
- Adjust this rule's `timezone` and hours to your own working hours to keep false positives low.

## False positives

- An administrator working late or on call.
- Scheduled maintenance by an admin account.

## ATT&CK

- T1078 Valid Accounts (Persistence, Privilege Escalation)
