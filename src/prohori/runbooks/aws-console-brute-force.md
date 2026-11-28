# AWS console password guessing

**Rules:** PRH-AWS-001, PRH-AWS-002

## What it means

Many AWS console sign-ins failed from one address in a short time (PRH-AWS-001), or they were
followed by a successful sign-in from the same address (PRH-AWS-002). Someone is guessing an IAM
user's or the root user's password; after a success they may be in the account. CloudTrail
writes `HIDDEN_DUE_TO_SECURITY_REASONS` instead of user names that do not exist, so the failures
are counted per address.

## Triage

1. Which accounts were tried (`user.name`, where CloudTrail kept it) and which one signed in?
2. Did the successful sign-in use MFA (`extra.mfa_used`)? A sign-in without MFA after guessing
   is most likely the attacker.
3. Is the address one your staff use (office, VPN)? Look at the browser (`user_agent`).
4. After a success: list everything that account did next (`user.name`, from the same address),
   especially IAM changes, new access keys, security groups and CloudTrail settings.

## Recommended actions

- After a successful sign-in by the attacker: reset the user's password, remove their console
  sessions (attach the AWS "revoke older sessions" policy or `AWSDenyAll` for a while), delete
  any access keys created since, and review the account's changes.
- Require MFA for every IAM user that can sign in to the console, and use IAM Identity Center
  instead of IAM users where you can.
- Block the address at your edge if it keeps trying.

## False positives

- A user who forgot a changed password and tries several old ones (one account, an office
  address, then a success with MFA).
- Several people signing in through one office or VPN address.

## ATT&CK

- T1110 Brute Force (Credential Access)
- T1110.001 Brute Force: Password Guessing (Credential Access)
- T1078.004 Valid Accounts: Cloud Accounts (Initial Access, Persistence, Privilege Escalation, Stealth)
