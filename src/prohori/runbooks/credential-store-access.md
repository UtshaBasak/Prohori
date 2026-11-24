# Credential store read by an unusual process

**Rules:** PRH-PROC-004

## What it means

A process opened `lsass.exe`, the Windows process that holds sign-in secrets, with rights to
read its memory, and it is not one of the Windows processes that do so routinely; or `reg.exe`
saved the SAM, SECURITY or SYSTEM registry hive. Both are how passwords and password hashes are
stolen, usually to sign in to other machines next.

## Triage

1. Which program opened `lsass.exe` (`process.executable`), with which rights
   (`extra.granted_access`), as which user (`user.name`)? `rundll32.exe` with `comsvcs.dll`,
   `procdump`, or any program in a user or temporary folder is an attack until shown otherwise.
2. Is it a security or backup product that is simply not in the rule's list of routine
   processes?
3. Look for what came before (a malicious document, encoded PowerShell, a new service) and after
   (sign-ins from this host to others).

## Recommended actions

- Isolate the host. Treat every account that signed in to it since the access as compromised:
  reset their passwords, and for administrators, their other credentials too.
- Look for sign-ins with those accounts on other hosts.
- Turn on LSA protection (RunAsPPL) and Credential Guard where possible.
- Record legitimate security tools as a suppression with an owner and an expiry date.

## False positives

- Security and backup products not in the rule's list.
- An administrator troubleshooting with a memory-dump tool.

## ATT&CK

- T1003 OS Credential Dumping (Credential Access)
- T1003.001 OS Credential Dumping: LSASS Memory (Credential Access)
