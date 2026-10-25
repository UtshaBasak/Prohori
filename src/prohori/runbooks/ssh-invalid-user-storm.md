# SSH invalid-user storm

**Rules:** PRH-SSH-001

## What it means

One source IP opened many SSH connections for usernames that do not exist on the server, or kept
hitting the server's limit of authentication attempts per connection. A script is working through
a list of common usernames and passwords.

## Triage

1. Check whether any SSH sign-in from the IP succeeded (PRH-AUTH-003).
2. List the usernames tried: real usernames in the list suggest the attacker knows something about
   the server.
3. Check whether password authentication is enabled on the server.

## Recommended actions

- Block the IP, or use a tool such as fail2ban to block repeat offenders automatically.
- Disable password authentication and root login over SSH; allow keys only.
- Restrict SSH to known networks or a VPN.
- If a sign-in succeeded, follow the runbook for PRH-AUTH-003.

## False positives

- An automation tool configured with a wrong username.
- A user whose SSH agent offers many keys and hits MaxAuthTries on every connection.

## ATT&CK

- T1110 Brute Force, T1110.001 Password Guessing (Credential Access)
