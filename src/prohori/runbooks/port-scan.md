# Port scan

**Rules:** PRH-NET-001

## What it means

One address tried TCP connections to many different ports in a few minutes, and most were not
answered or were refused. Someone is looking for open services: from outside, usually automated
internet scanning; from inside, possibly an attacker on a compromised host mapping the network
before moving on.

## Triage

1. Is the source inside or outside the network? An internal source scanning is far more serious.
2. List the destination addresses and ports (`destination.ip`, `destination.port`):
   one host and many ports, or many hosts.
3. Check whether any connection from the same source succeeded afterwards (Zeek `conn_state`
   `SF`), and whether other alerts name it (sign-in failures, web scanning, IDS alerts).
4. Ask whether it is the organisation's own scanner or monitoring.

## Recommended actions

- For an internal source, find the host and its user, and check it for malware or an unexpected
  remote-access tool; isolate it if the scan is not explained.
- For an outside source, make sure only the intended services are reachable, and block the
  address if the scanning continues.
- Record the organisation's own scanners in a suppression with an owner and an expiry date.

## False positives

- The organisation's own vulnerability scanner or asset inventory.
- Monitoring systems that check many service ports.

## ATT&CK

- T1046 Network Service Discovery (Discovery)
- T1595 Active Scanning (Reconnaissance)
