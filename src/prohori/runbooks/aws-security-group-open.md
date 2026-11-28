# AWS security group opened to the internet

**Rules:** PRH-AWS-008

## What it means

A security group rule now lets every address on the internet (`0.0.0.0/0` or `::/0`) reach the
machines in the group on ports other than 80 and 443 (`extra.world_ports`): SSH, remote desktop,
a database, or every port. Attackers do this to reach a machine directly; mistakes do it too,
and exposed SSH and RDP are scanned within minutes.

## Triage

1. Which group (`extra.security_group`), which ports (`extra.world_ports`) and who changed it
   (`user.name`, `source.ip`)?
2. Which machines are in the group, and what listens on those ports?
3. Was it planned and for how long?

## Recommended actions

- Remove the rule, or limit it to the addresses that need it.
- If it was not planned, treat the caller's account as compromised and check the machines in the
  group for sign-ins since the change.
- Use Systems Manager Session Manager or a VPN instead of opening SSH or RDP.

## False positives

- A short-lived test (still worth closing).
- A public service on another port, such as a mail or game server.

## ATT&CK

- T1686 Disable or Modify System Firewall (Defense Impairment)
- T1686.001 Disable or Modify System Firewall: Cloud Firewall (Defense Impairment)
