# Windows Security log cleared

**Rules:** PRH-WIN-005

## What it means

Someone cleared the Security event log (event 1102). The log holds the record of sign-ins,
account changes and privilege use, so attackers clear it to hide what they did. Administrators
rarely need to: logs roll over on their own.

## Triage

1. Which account cleared the log (`user.name`), on which computer (`host`), and when?
2. Was it planned (a lab reset, a documented maintenance task)?
3. Look at what happened just before: sign-ins after failures, new accounts, group changes. If
   the events were forwarded elsewhere (a SIEM, Windows Event Forwarding), read them there: the
   copy was not cleared.

## Recommended actions

- If it was not planned, treat the computer and the account as compromised: isolate the
  computer and reset the account's password.
- Forward Security events to another system so clearing one computer's log does not erase
  them.
- Limit who has the right to manage the security log ("Manage auditing and security log").

## False positives

- An administrator clearing a full log by hand, or a lab machine being reset.

## ATT&CK

- T1685.005 Disable or Modify Tools: Clear Windows Event Logs (Defense Impairment)
