# Samples

Small, **synthetic** log files, incidents and flow subsets used by tests and the demo, so that
everything runs offline. All IP addresses come from documentation ranges (`192.0.2.0/24`,
`198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`). No real personal data.

- `logs/`: one log per supported format; `mappings/`: a `generic_json` field mapping. The
  network logs (`suricata-eve.json`, `zeek-conn.log`, `zeek-conn.json`) were written by hand
  from the Suricata 7/8 and Zeek 6/7 documentation; their signatures are made up (`PRH SAMPLE`)
  and contain a port scan, a 750 MB upload, a nine-hour connection and web scanning.
  `windows-security.jsonl` (Winlogbeat) and `windows-security.xml` (event XML, one event per
  line and over several lines) hold hand-written Windows Security events: staff sign-ins,
  remote-desktop spraying and guessing, a sign-in that works, a new account added to
  Administrators, a cleared log and lockouts. `journald.json` is `auth.log` as the systemd journal
  would export it (`journalctl -o json`), so both give the same alerts. `windows-sysmon.jsonl`
  holds hand-written, defanged Sysmon events (Winlogbeat) of every mapped type: a working
  morning, then a macro document, encoded PowerShell, a new service, lsass read through
  `comsvcs.dll` and files deleted; the encoded command decodes to `Write-Output`.
  `aws-cloudtrail.json` is a hand-written CloudTrail trail file in the layout CloudTrail writes
  to S3 (`{"Records": [...]}` on one line, here not compressed): console sign-ins, a CI role and
  an AWS service at work, then password guessing, a sign-in, a key for another user, denied
  calls, MFA removed, SSH opened to everyone, logging stopped, and a root sign-in. The account
  is AWS's documentation example `111122223333` and the key ids are shortened.
- `incidents/`: a sample incident (`prohori report samples/incidents/INC-*.json`).
- `suppressions.yml`: an example suppressions file for the simulated shop (the planned admin
  role grant). Use it with `--suppressions` on `detect`, `incidents`, `triage` or the pipeline;
  [docs/RULES.md](../docs/RULES.md#suppressions-and-allow-lists) has the format.
