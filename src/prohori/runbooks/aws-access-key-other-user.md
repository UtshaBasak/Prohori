# AWS access key created for another user

**Rules:** PRH-AWS-005

## What it means

Someone created an access key for an IAM user other than themselves. Access keys do not expire
and work from anywhere, so an attacker with IAM rights creates them for other users (often
service users nobody watches) to keep access after the first account is cleaned up.

## Triage

1. Who created the key (`user.name`, `source.ip`) and for whom (`extra.target_user`)?
2. Was it planned (a new service, a key rotation)? Ask the creator and the owner of the user.
3. Has the new key been used? Search for calls by the target user from unfamiliar addresses
   after the key was created.

## Recommended actions

- If it was not planned: deactivate and delete the new key, review what it was used for, and
  treat the creator's account as compromised.
- Prefer IAM roles over long-term keys for programs, and limit `iam:CreateAccessKey` on other
  users to a small administrator group.

## False positives

- An administrator setting up a new service user or rotating a service user's key.

## ATT&CK

- T1098 Account Manipulation (Persistence, Privilege Escalation)
- T1098.001 Account Manipulation: Additional Cloud Credentials (Persistence, Privilege Escalation)
