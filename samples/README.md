# Samples

Small, **synthetic** log files, incidents and flow subsets used by tests and the demo, so that
everything runs offline. All IP addresses come from documentation ranges (`192.0.2.0/24`,
`198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`). No real personal data.

- `logs/`: one log per supported format; `mappings/`: a `generic_json` field mapping.
- `incidents/`: a sample incident (`prohori report samples/incidents/INC-*.json`).
- `suppressions.yml`: an example suppressions file for the simulated shop (the planned admin
  role grant). Use it with `--suppressions` on `detect`, `incidents`, `triage` or the pipeline;
  [docs/RULES.md](../docs/RULES.md#suppressions-and-allow-lists) has the format.
