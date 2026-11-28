# MFA removed from an AWS user

**Rules:** PRH-AWS-004

## What it means

An IAM user's MFA device was deactivated, or a virtual MFA device was deleted. After that, the
user's password alone is enough to sign in. An attacker who controls an administrator account
removes MFA from another user to take that user over, or from their own account to keep using
a stolen password.

## Triage

1. Whose MFA was removed (`extra.target_user`) and who removed it (`user.name`)?
2. Did the user ask for it (a lost or new phone)? Was a new device enabled soon after
   (`aws.iam.enable_mfa_device` for the same user)?
3. Did the same caller change the user's password or login profile, or create access keys,
   around the same time?

## Recommended actions

- If it was not requested: enable MFA on the user again, reset their password, and treat the
  caller's account as compromised.
- Require MFA with an IAM policy condition (`aws:MultiFactorAuthPresent`) so a user without it
  can do nothing but set it up.

## False positives

- A user replacing a lost or new phone.
- An administrator resetting MFA for a user who lost their device.

## ATT&CK

- T1556.006 Modify Authentication Process: Multi-Factor Authentication (Credential Access, Defense Impairment, Persistence)
