# Suricata IDS alert

**Rules:** PRH-IDS-001 (severity 1), PRH-IDS-002 (severity 2), PRH-IDS-003 (severity 3 or above)

## What it means

A Suricata signature matched traffic seen by the network sensor. Prohori passes the alert
through so it joins incidents with alerts from other logs; what it means depends on the
signature. The event keeps the signature's name (`event.reason` and `extra.signature`), its id
and revision (`extra.signature_id`, `extra.signature_rev`), its category, whether Suricata
allowed or blocked the traffic (`extra.alert_action`) and any MITRE metadata the rule set added
(`extra.mitre_technique_id`, `extra.mitre_tactic_id`).

## Triage

1. Read the signature and its category, and look the signature id up in the rule set's
   documentation to learn what it detects.
2. Work out the direction: is the internal address (source or `destination.ip`) the target
   of an attack or the origin of suspicious traffic, such as a malware check-in?
3. Check `extra.alert_action`: `blocked` means an IPS sensor already dropped the traffic.
4. Look for other alerts on the same addresses and for flows with the same `extra.flow_id`
   (the same connection's HTTP, TLS and flow records).

## Recommended actions

- Investigate the internal host when the signature describes malware, a check-in or an outbound
  attack: isolate it if the traffic is confirmed.
- Patch or harden the targeted service when the signature describes an exploit attempt that the
  server answered successfully.
- Block the outside address at the firewall if the activity continues.
- Tune or disable signatures that keep matching harmless traffic on this network, in Suricata
  (threshold or suppress), or with a Prohori suppression that has an owner and an expiry date.

## False positives

- Signatures that match ordinary traffic on this network.
- Alerts for traffic that an IPS sensor already blocked.

## ATT&CK

- No fixed technique: it depends on the signature. Many rule sets name one in their metadata,
  which Prohori keeps in `extra.mitre_technique_id`.
