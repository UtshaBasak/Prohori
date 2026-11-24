# Large outbound transfer

**Rules:** PRH-NET-002

## What it means

One connection from a host inside the network sent at least 500 MB to an outside address.
Attackers who steal data often send it out in one large upload. Backups, cloud sync and large
uploads by staff do the same, so the destination and the host decide.

## Triage

1. Identify the internal host and who uses it, and the destination address and port
   (`extra.destination_ip`, `extra.destination_port`, `extra.app_protocol`).
2. Look up the destination: the organisation's backup or cloud provider, a file-sharing service,
   or an unknown host.
3. Check the time and duration (`extra.start_time`, `extra.duration`) against the host's usual
   activity, and look for other alerts on the host before the transfer.
4. Check DNS and TLS records for the destination's name (`extra.tls_sni` in Suricata TLS events).

## Recommended actions

- If the destination is unknown and the transfer unexplained, isolate the host and preserve its
  disk and memory before cleaning it.
- Find out what data the host holds and whether its loss must be reported.
- Block the destination if it is not a service the organisation uses.
- Record known backup destinations in a suppression with an owner and an expiry date.

## False positives

- Off-site backups and uploads to the organisation's own cloud storage.
- Large software or media uploads by developers and designers.

## ATT&CK

- T1048 Exfiltration Over Alternative Protocol (Exfiltration)
