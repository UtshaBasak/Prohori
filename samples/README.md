# Samples

Small, **synthetic** log files, incidents and flow subsets used by tests and the demo, so that
everything runs offline. All IP addresses come from documentation ranges (`192.0.2.0/24`,
`198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`). No real personal data.

- `logs/`: one log per supported format; `mappings/`: a `generic_json` field mapping. The
  network logs (`suricata-eve.json`, `zeek-conn.log`, `zeek-conn.json`) were written by hand
  from the Suricata 7/8 and Zeek 6/7 documentation; their signatures are made up (`PRH SAMPLE`)
  and contain a port scan, a 750 MB upload, a nine-hour connection and web scanning.
- `incidents/`: a sample incident (`prohori report samples/incidents/INC-*.json`).
- `suppressions.yml`: an example suppressions file for the simulated shop (the planned admin
  role grant). Use it with `--suppressions` on `detect`, `incidents`, `triage` or the pipeline;
  [docs/RULES.md](../docs/RULES.md#suppressions-and-allow-lists) has the format.
