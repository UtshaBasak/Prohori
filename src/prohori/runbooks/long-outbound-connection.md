# Long outbound connection

**Rules:** PRH-NET-003

## What it means

A host inside the network kept one connection to an outside address open for at least 8 hours.
Remote-access tools and command-and-control channels often hold a connection open so an
attacker can send commands at any time. VPNs, remote desktops and chat applications do the same.
The sensor writes the record when the connection ends, so the alert comes late.

## Triage

1. Identify the internal host, the destination address and port, and the application protocol
   (`extra.app_protocol`).
2. Look up the destination: a VPN or remote-access service the organisation uses, a known
   application, or an unknown host.
3. Compare the bytes in each direction (`extra.bytes_out`, `extra.bytes_in`): a small, steady
   exchange over hours fits a command channel; a large one fits streaming or a transfer.
4. Check the host for other alerts and for the same destination on other hosts.

## Recommended actions

- If the destination and the program behind the connection are unknown, check the host for
  remote-access tools or malware, and isolate it if one is found.
- Block the destination if it is not a service the organisation uses.
- Record known long-lived services in a suppression with an owner and an expiry date.

## False positives

- VPN tunnels, remote-desktop and SSH sessions left open.
- Long-polling, streaming and messaging applications.

## ATT&CK

- T1071 Application Layer Protocol (Command and Control)
