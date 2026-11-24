# Account added to a Windows administrators group

**Rules:** PRH-WIN-004

## What it means

An account was added to a privileged group: the built-in Administrators group, or the domain's
Domain Admins, Schema Admins or Enterprise Admins. An attacker who has reached an
administrator session often adds an account they control, so they keep admin rights after the
first account's password is changed.

## Triage

1. Who made the change (`user.name`, `extra.subject_domain`) and who was added
   (`extra.member_name`, `extra.member_sid`)? Which group (`extra.group_name`,
   `extra.group_sid`) on which computer (`host`)?
2. Was the change planned: a ticket, an onboarding, a known administrator at work?
3. Was the added account created shortly before (4720), and did the person who made the
   change sign in after failures (PRH-WIN-003)?

## Recommended actions

- If the change was not planned, remove the account from the group, disable it, and treat the
  account that made the change as compromised.
- Review the group's other members, and every computer the new member signed in to.
- Record planned additions as a suppression with an owner and an expiry date.

## False positives

- Planned onboarding of a new administrator.

## ATT&CK

- T1098 Account Manipulation (Persistence, Privilege Escalation)
- T1098.007 Additional Local or Domain Groups (Persistence, Privilege Escalation)
