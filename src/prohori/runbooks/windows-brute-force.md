# Windows password guessing

**Rules:** PRH-WIN-001 (many failures from one source), PRH-WIN-002 (many accounts from one
source), PRH-WIN-003 (a success after many failures), PRH-WIN-006 (lockouts across many accounts)

## What it means

Someone is guessing Windows passwords: many failed sign-ins (event 4625) from one address or
workstation, for one account or many, sometimes enough to lock accounts out (4740). PRH-WIN-003
is the serious one: a successful sign-in (4624) from the same source right after the failures
means a guess may have worked.

## Triage

1. Look at the source (`source.ip`, or `extra.workstation` when Windows logged no address) and
   the logon type (`extra.logon_type_name`): `remote_interactive` is RDP, `network` is SMB or
   another network service. Is the source inside the network or on the internet?
2. Check the failure reasons (`event.reason`): `unknown_user` means guessed names,
   `bad_password` means real accounts are being tried.
3. For PRH-WIN-003, find what the signed-in account did next: other alerts on the same account
   or host, new accounts (4720), group changes (4728, 4732, 4756), a cleared log (1102).
4. For lockouts, `extra.caller_computer` names the computer the failures came from.

## Recommended actions

- If a sign-in succeeded after the guessing, treat the account as compromised: reset its
  password, end its sessions, and check the hosts it signed in to.
- Do not expose RDP or SMB to the internet; put them behind a VPN or gateway with two-factor
  sign-in.
- Block the source address if it is outside the network, and find the device if it is inside.
- Make sure the account lockout policy is set, and that local administrator passwords differ
  between machines (Windows LAPS).

## False positives

- A service, scheduled task or mapped drive still using an old password.
- A phone or mail client retrying a changed password.
- A shared terminal where several people mistype their passwords.

## ATT&CK

- T1110 Brute Force (Credential Access)
- T1110.001 Password Guessing (Credential Access)
- T1110.003 Password Spraying (Credential Access)
- T1078 Valid Accounts (Initial Access), for PRH-WIN-003
