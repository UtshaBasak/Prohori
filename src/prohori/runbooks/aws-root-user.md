# AWS root user used

**Rules:** PRH-AWS-003

## What it means

The root user of the AWS account signed in to the console, or used a long-term access key.
Root can do anything in the account, including closing it, and its use cannot be limited by IAM
policies. AWS recommends using it only for the few tasks that need it, with MFA, and having no
root access keys at all.

## Triage

1. Was it planned? Ask the account owner; root tasks are rare (billing settings, closing the
   account, changing the support plan, restoring an IAM administrator's access).
2. Where did it come from (`source.ip`, `user_agent`) and did the sign-in use MFA
   (`extra.mfa_used`)?
3. For an access key (`extra.access_key_id`): root access keys should not exist. Find out where
   the key is used and what it called.
4. List everything root did in the session.

## Recommended actions

- If nobody planned it: change the root password, check the root MFA device and the account's
  email address and contact details, and review what root changed.
- Delete root access keys; give programs an IAM role or user with only the rights they need.
- Make sure root has MFA and that its password is kept by the owner only.

## False positives

- The account owner doing one of the tasks only root can do.

## ATT&CK

- T1078 Valid Accounts (Initial Access, Persistence, Privilege Escalation, Stealth)
- T1078.004 Valid Accounts: Cloud Accounts (Initial Access, Persistence, Privilege Escalation, Stealth)
