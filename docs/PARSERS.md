# Parsers

Parsers turn raw log lines into [common-schema events](SCHEMA.md). They live in
`prohori.parsers` and share one framework.

| Parser | Registry name | Input | Status |
| -------- | --------------- | ------- | -------- |
| Linux `auth.log` / `secure` | `auth_log` | sshd, sudo and PAM lines from syslog | Available |
| nginx / Apache access logs | `access_log` | Combined or common log format, or a custom pattern | Available |
| App security events | `app_json` | JSON Lines in the documented application format | Available |
| Generic JSON Lines | `generic_json` | Any JSON Lines, with a YAML field-mapping file | Available |
| Suricata EVE | `suricata_eve` | `eve.json`: alert, http, dns, tls, ssh and flow records | Since 1.2 |
| Zeek connections | `zeek_conn` | `conn.log` as tab-separated values with a `#fields` header, or Zeek JSON | Since 1.2 |

## Command line

```bash
prohori parse samples/logs/auth.log                 # format detected, table output
prohori parse samples/logs/access.log --format json # one event per line (JSON Lines)
cat samples/logs/auth.log | prohori parse - --year 2026
prohori parse samples/logs/payments.jsonl --parser generic_json \
    --mapping samples/mappings/payments.yaml
prohori detect samples/logs/suricata-eve.json        # IDS alerts, web scanning seen on the wire
prohori detect samples/logs/zeek-conn.log            # port scan, large and long connections
```

| Option | Applies to | Meaning |
| -------- | ------------ | --------- |
| `--parser`, `-p` | all | `auto` (default) or a parser name |
| `--format`, `-f` | all | `table` (summary and the first `--limit` events) or `json` (events on standard output as JSON Lines, summary as JSON on standard error) |
| `--year` | `auth_log` | Year of the first line (default: from the file date) |
| `--timezone` | `auth_log` | IANA timezone for timestamps without an offset (default `UTC`) |
| `--pattern` | `access_log` | Custom regular expression |
| `--keep-query` | `access_log`, `suricata_eve` | Keep the query string in `http.path` |
| `--mapping` | `generic_json` | YAML field-mapping file |
| `--limit` | `table` | Events to show (default 20; counts always cover the whole input) |

Exit codes: `0` success, `1` no events and at least one malformed line (every line failed),
`2` invalid usage or input (unknown parser, missing file, undetectable format, bad options).

Table output never interprets log content as formatting: cell text is rendered literally.

### Format detection

With `--parser auto`, up to 20 non-blank lines are classified and the most common format wins
(ties go to the first in this order):

1. `suricata_eve`: a JSON object with an `event_type` and a `timestamp` string.
2. `zeek_conn`: a JSON object with `uid`, `conn_state` and the originator address (`id.orig_h`,
   or a nested `id` object); a Zeek header line (`#separator`, `#path conn`, `#fields ts ...`);
   or a tab-separated line that starts with epoch seconds and a connection uid (`C...`).
3. `app_json`: a JSON object with a `time` string and an `event` object containing `action`.
4. `generic_json`: any other JSON object. This needs a mapping file, so detection stops with a
   message asking for `--parser generic_json --mapping FILE`.
5. `auth_log`: a syslog line (RFC 3164 or RFC 3339 timestamp, host, program).
6. `access_log`: a combined or common log format line.

Detection is a convenience. Use `--parser` in scripts.

## Framework guarantees

- **Streaming.** Parsers are generators; memory use does not grow with input size.
- **Bounded lines.** Files are read in binary with a per-line limit of 16,384 characters. Longer
  lines are counted as errors without being matched (which also bounds regular-expression work),
  and the remainder of such a line is discarded in chunks rather than loaded into memory.
- **Tolerant.** A malformed line is counted and reported; it never stops the run.
- **Sanitised.** Line endings (`\n` and `\r\n`), ANSI escape sequences, control characters and
  invisible formatting characters (zero-width, bidirectional overrides, byte-order marks) are
  removed before parsing. Tabs become spaces, except for `zeek_conn`, which splits on them and
  sanitises each column instead.
- **Any encoding damage is survivable.** Input is decoded as UTF-8; invalid bytes become `U+FFFD`
  and the line is counted in `decode_errors`.

### Statistics

Every run fills a `ParseStats`. Each line read is counted in exactly one of:

| Counter | Meaning |
| --------- | --------- |
| `events` | Parsed into an event |
| `skipped` | Well-formed but not relevant to this parser (for example a `CRON` line in `auth.log`) |
| `blank` | Empty or whitespace only |
| `errors` | Malformed: no timestamp, invalid date, line too long, and so on |

`decode_errors` counts lines that contained invalid UTF-8 (they may still parse),
`ambiguous_times` counts `auth_log` lines whose local time fell in the hour repeated when daylight
saving time ends (see [Timestamps](#timestamps); `prohori parse` shows it when it is not zero),
and `error_examples` keeps the first ten errors with line numbers and reasons.

### Event ids

Each event id includes the input name and line number (`auth.log:1042`), so two identical lines
in the same second remain two events, and re-parsing the same file gives the same ids.

## `auth_log`

### Supported messages

| Program | Message | `event.action` | Outcome | `event.reason` |
| --------- | --------- | ---------------- | --------- | ---------------- |
| sshd | `Failed <method> for <user> from <ip> port <n>` | `ssh.login.failure` | failure | `bad_password`, `bad_key` or `auth_failed` |
| sshd | `Failed <method> for invalid user <user> from ...` | `ssh.login.failure` | failure | `unknown_user` |
| sshd | `Accepted <method> for <user> from ...` | `ssh.login.success` | success | |
| sshd | `Invalid user <user> from <ip> [port <n>]` | `ssh.invalid_user` | failure | `unknown_user` |
| sshd | `error: maximum authentication attempts exceeded for ...` | `ssh.auth.too_many_failures` | failure | `too_many_failures` or `unknown_user` |
| sshd | `Disconnecting ... : Too many authentication failures` | `ssh.auth.too_many_failures` | failure | as above |
| sshd | `Disconnected from ...`, `Received disconnect from ...`, `Connection closed by ...` | `ssh.disconnect` | unknown | |
| any | `pam_unix(<service>:auth): authentication failure; ...` | `pam.auth.failure` | failure | `auth_failed` |
| any | `pam_unix(<service>:session): session opened/closed for user ...` | `session.opened` / `session.closed` | success | |
| sudo | `<user> : TTY=... ; PWD=... ; USER=... ; COMMAND=...` | `sudo.command` | success | |
| sudo | `<user> : N incorrect password attempts ; ...` | `sudo.auth.failure` | failure | `bad_password` |
| sudo | `<user> : user NOT in sudoers ; ...` | `sudo.denied` | failure | `not_permitted` |

`sshd-session` (OpenSSH 9.8+) is treated as `sshd`. Other programs and unrecognised messages are
counted as `skipped`. Useful details go into `extra`: `pid`, `source_port`, `auth_method`,
`pam_service`, `by_user`, `target_user`, `command`, `tty`, `cwd`, `attempts`.

### Untrusted usernames

sshd writes attacker-chosen usernames verbatim, including spaces and text such as
`x from 192.0.2.1 port 1`. The parser takes the address and port that sshd appends **last**, so a
crafted username cannot change `source.ip`. When sshd logs a host name instead of an address
(`UseDNS yes`), `source.ip` is empty and the name is kept in `extra.source_host` as logged.
Since 1.1 a valid fully qualified name is also put in `source.host`, in lower case and without a
trailing dot, so the SSH and sign-in rules can group by it; a placeholder such as `UNKNOWN` is
not a host name and stays only in `extra`. The other parsers do the same for a name in the
address field.
IPv4-mapped IPv6 addresses (`::ffff:203.0.113.7`) are stored as IPv4.

### Timestamps

Two syslog header formats are accepted:

| Format | Example | Year | Timezone |
| -------- | --------- | ------ | ---------- |
| RFC 3164 (traditional) | `Oct 24 13:50:12 web01 sshd[1]: ...` | Not in the line | Not in the line |
| RFC 3339 (rsyslog high precision, default on recent distributions) | `2026-10-24T13:50:12.345678+06:00 web01 sshd[1]: ...` | In the line | In the line |

For RFC 3164 lines:

- **Timezone:** the `timezone` option (an IANA name such as `Asia/Dhaka`, default `UTC`).
- **The repeated hour.** When daylight saving time ends, an hour of local times happens twice
  (01:00 to 01:59 in America/New_York on the first Sunday of November). Such a time is read as
  its first occurrence, unless that would put it more than ten minutes before the previous line;
  then it is the second occurrence. A log that runs through the repeated hour therefore keeps
  moving forward, and the rule engine does not drop its second half as late (since 1.1;
  `samples/logs/auth-dst.log` is an example). The same applies to RFC 3339 lines without an
  offset. Lines are counted in `ambiguous_times`. A time skipped when the clocks go forward
  keeps the offset from before the change.
- **Year:** the `year` option is the year of the **first** line. Without it, the year is
  inferred from a reference time: the file's modification time for `parse_file`, otherwise the
  current time. The first line is assumed to be no later than one day after the reference time,
  so a file written on 3 January that starts on 30 December is dated correctly.
- **New Year rollover:** when the month goes back by six or more (December to January), the year
  advances. A line that jumps forward by six or more months (a late December line after January
  lines) is dated in the previous year without changing the running year.

Invalid dates (for example `Feb 29` in a non-leap year) are counted as errors.

### Limitations

- Year inference is a heuristic. A file whose first line is more than a year older than its
  modification time is dated a year late; pass `year` explicitly for archived logs.
- Logs that span more than one New Year without lines in December or January are not detected
  as rolling over.
- Only the sshd, sudo and `pam_unix` messages listed above produce events.
- Throughput and memory on logs of a million lines are measured in
  [PERFORMANCE.md](PERFORMANCE.md).
- In the repeated daylight-saving hour, the choice between the two occurrences depends on the
  previous line. A log whose first line falls in the second occurrence, or that is silent for
  the whole first occurrence, is read as the first; and a line more than ten minutes out of
  order inside the repeated hour is read as the second. Use `--timezone UTC` for hosts that log
  in UTC.
- The choice depends on the previous line, and the event id contains the timestamp. If the
  streaming pipeline's normaliser restarts in the middle of the repeated hour with a batch not
  yet committed, a redelivered line is read without the line before it, can land in the other
  occurrence and is then stored as a second event. The window is one hour a year and needs a
  restart inside it.

### Example

```python
from pathlib import Path

from prohori.parsers import ParseStats, get_parser

parser = get_parser("auth_log", timezone="Asia/Dhaka")
stats = ParseStats()
for event in parser.parse_file(Path("samples/logs/auth.log"), stats=stats):
    print(event.timestamp, event.event.action, event.source.ip, event.user.name)
print(stats.as_dict())
```

## `access_log`

Every line becomes a `web.request` event in category `web`; the outcome is `failure` for
status 400 and above, `success` otherwise.

| Source | Field |
| -------- | ------- |
| Remote address | `source.ip`; a host name goes to `source.host` (and as logged to `extra.source_host`) |
| Authenticated user (`-` means none) | `user.name` |
| `[24/Oct/2026:13:50:12 +0600]` | `timestamp` (converted to UTC; month names are parsed independently of the locale) |
| Request line `GET /path?query HTTP/1.1` | `http.method`, `http.path`, `extra.query`, `extra.protocol` |
| Status, bytes (`-` means none) | `http.status`, `http.bytes` |
| Referer, user agent | `extra.referer`, `user_agent` |

- **Query strings** are removed from `http.path` and kept in `extra.query`, so paths group cleanly
  while injection rules can still inspect the query. `--keep-query` keeps them in the path.
- **Unparseable request lines** (for example a TLS handshake sent to a plain-HTTP port) leave
  method and path empty and keep the request text in `extra.request` as written, escapes and
  all (`\x16\x03...`).
- **Escapes** written by nginx (`\x22`) and Apache (`\"`) are decoded in the request, referer
  and user agent. Control characters an escape decodes to (`\x1B`) are removed again, as are
  those decoded from JSON escapes (`\u001b`) by the JSON parsers, so no log value can reach a
  terminal as an escape sequence.
- **Custom formats:** pass a regular expression with named groups `ip`, `time`, `status`, and
  either `request` or `method` and `path`; `user`, `bytes`, `referer`, `agent`, `host` and
  `protocol` are optional.
- Fields after the user agent (for example `$http_x_forwarded_for` or timings) are ignored by
  the default pattern.

## `app_json`

Parses application security events, one JSON object per line:

```json
{"time": "2026-10-24T13:50:12.345Z", "log_type": "security",
 "event": {"action": "auth.signin.failure", "category": "authentication",
           "outcome": "failure", "severity": "low", "reason": "bad_password"},
 "request_id": "9f3c0a", "source": {"ip": "203.0.113.7"}, "user_agent": "Mozilla/5.0",
 "client": "web", "http": {"method": "POST", "route": "/api/auth/signin"},
 "user": {"id": "665f1c", "email_hash": "3a91d0"}}
```

- `time` must be ISO 8601 **with** a timezone (`Z` or an offset).
- Records with a `log_type` other than `security` are skipped; records without `log_type` are
  accepted.
- `http.route` (or `http.path`) becomes `http.path`.
- If `event.category` is missing or not a schema category, it is derived from the action prefix:

| Prefix | Category |
| -------- | ---------- |
| `auth.` | `authentication` |
| `session.` | `session` |
| `account.` | `account` |
| `authz.` | `authorization` |
| `ratelimit.`, `turnstile.`, `upload.` | `abuse` |
| `admin.` | `admin` |

- Invalid JSON, non-object records, deeply nested input, missing `time` or `event.action`, and
  values that do not fit the schema are counted as errors.

## `generic_json`

Maps any JSON Lines layout onto the schema with a YAML file (loaded with `yaml.safe_load`,
at most 64 KiB):

```yaml
log_source: payments-api
timestamp:
  field: ts                     # dotted path in each record
  format: "%Y-%m-%d %H:%M:%S"   # iso8601 (default), epoch, epoch_ms or a strptime pattern
  timezone: Asia/Dhaka          # used when the timestamp has no offset
fields:                         # schema field: dotted path in the record
  event.action: kind
  event.outcome: result
  source.ip: client.addr
  user.name: actor
constants:                      # schema field: fixed value
  event.category: authentication
values:                         # optional value translation per schema field
  event.outcome: {ok: success, denied: failure}
extra:                          # extra key: dotted path in the record (scalars only)
  merchant: merchant.id
```

- `event.action` and `event.category` must come from `fields` or `constants`.
- Targets must be schema fields; `id`, `timestamp`, `log_source` and `raw` are set by the parser.
- Mapped values must still satisfy the schema (for example `event.action` must be a dotted
  lower-case name); use `values` to translate.
- The mapping file is validated when the parser is created, so mistakes fail before any input is
  read.

## `suricata_eve`

Parses Suricata's EVE JSON output (`eve.json`), one record per line. The layout follows the
**Suricata 7.0** EVE documentation, plus the one change **Suricata 8.0** made to these record
types: DNS logging version 3, which lists the question in a `queries` array (version 2's
top-level `rrname` and `rrtype` are read too). The samples were written by hand from the
documentation, not copied from real traffic.

| `event_type` | `event.action` | `event.category` | What is kept |
| ------------ | -------------- | ---------------- | ------------ |
| `alert` | `ids.alert` | `network` | `event.severity` from the signature's severity (below); the signature in `event.reason` and `extra.signature`, with `extra.signature_id`, `extra.signature_rev`, `extra.alert_gid`, `extra.alert_category`, `extra.alert_action` (`allowed` or `blocked`) and `extra.alert_severity`; from the signature metadata `extra.mitre_technique_id`, `extra.mitre_tactic_id` and `extra.signature_severity`. HTTP details when the record has them |
| `http` | `web.request` | `web` | As `access_log`: `http.method`, `http.path` (query in `extra.query`), `http.status`, `http.bytes`, `user_agent`, `extra.http_host`, `extra.protocol`, `extra.referer`, `extra.content_type`. Outcome `failure` for status 400 and above |
| `dns` | `network.dns` | `network` | `extra.dns_question` (as logged), `extra.dns_domain` (lower case, when it is a valid name), `extra.dns_type`, `extra.dns_rcode`, `extra.dns_message` (`query`, `answer`, ...) |
| `tls` | `network.tls` | `network` | `extra.tls_sni`, `extra.tls_domain`, `extra.tls_version`, `extra.tls_subject`, `extra.tls_issuer`, `extra.ja3_hash`, `extra.ja3s_hash` |
| `ssh` | `network.ssh` | `network` | `extra.ssh_client_software`, `extra.ssh_server_software`, `extra.ssh_client_protocol`, `extra.ssh_server_protocol` |
| `flow` | `network.flow` | `network` | The connection fields below, plus `extra.flow_state` and `extra.flow_reason` |

Other record types (`stats`, `fileinfo`, `anomaly`, `netflow`, `smb`, ...) are counted as
skipped.

- **Severity.** Suricata's alert severity runs the other way round: 1 is the most severe.
  1 becomes `high`, 2 `medium`, and 3 or above (or none) `low`. `critical` is never set on
  events; it is reserved for Prohori's own alerts and incidents.
- **Times.** `timestamp` must carry an offset (`+0000` without a colon is accepted, as Suricata
  writes it). A `flow` record is dated at its last packet (`flow.end`), because Suricata writes
  it when the flow ends; `extra.start_time` keeps `flow.start`, and `extra.duration` is the time
  between them (or `flow.age` when they are missing).
- **Web rules apply.** `http` records become `web.request` events like access-log lines, so the
  web rules (PRH-WEB-001 to PRH-WEB-004) work on what Suricata saw on the wire, for any web
  server behind it. `--keep-query` works as for `access_log`.
- **Long lines.** Alerts with `payload` or `packet` logging turned on can exceed the
  16,384-character line limit and are then counted as errors. Turn those options off for the
  file Prohori reads; the rules use the signature and the addresses.
- `src_ip` and `dest_ip` must be valid addresses, ports 0-65535 and counts non-negative whole
  numbers; flows longer than a year are rejected as corrupt. Anything else is counted as an
  error for that line only.

### Connection fields (both network parsers)

`suricata_eve` and `zeek_conn` describe a connection with the same keys, so one rule works on
either sensor's output. The originator is `source.ip`.

| Key | Meaning |
| --- | ------- |
| `extra.destination_ip`, `extra.destination_port` | The responder |
| `extra.source_port` | The originator's port |
| `extra.transport` | `tcp`, `udp`, `icmp`, ... (lower case) |
| `extra.app_protocol` | The application protocol the sensor recognised (`http`, `dns`, `ssl` or `tls`, ...) |
| `extra.bytes_out`, `extra.packets_out` | Sent by the originator (Zeek `orig_bytes`, Suricata `bytes_toserver`) |
| `extra.bytes_in`, `extra.packets_in` | Sent by the responder |
| `extra.duration` | Seconds from the first to the last packet |
| `extra.start_time` | The first packet (ISO 8601, UTC); the event's `timestamp` is the last |
| `extra.direction` | `outbound`, `inbound`, `internal` or `external` (Zeek only, from `local_orig` and `local_resp`) |
| `extra.flow_id` (Suricata), `extra.uid` and `extra.community_id` (Zeek) | Ids that tie the records of one connection together |

These are `extra` fields for now. A later 1.2 step adds `destination.*` schema fields and moves
the built-in rules to them (ADR-0044).

## `zeek_conn`

Parses Zeek's connection log, `conn.log`. The layout follows the `Conn::Info` record of
**Zeek 6 and 7** (`ip_proto` was added in 7.1); the samples were written by hand.

- **Tab-separated logs** are read by their `#fields` header, so column order, extra columns
  added by policy scripts (`community_id`, `vlan`, ...) and missing optional columns all work.
  `#separator` (any one character, written as `\x09`), `#unset_field` (`-`), `#empty_field`
  (`(empty)`) and `#path` are honoured; Zeek's `\xNN` escapes are decoded and the result is
  sanitised again. Header lines are counted as skipped.
- **Lines before any header** (following a log from the middle) are read in Zeek 7.1's default
  column order when they have 21 or 22 columns, and are errors otherwise.
- **Other logs** (`#path dns`, or a JSON record whose `_path` is not `conn`) are skipped line by
  line, not parsed as connections.
- **Zeek JSON** with flat dotted keys (`"id.orig_h"`, Zeek's default) or a nested `id` object is
  accepted; `ts` may be epoch seconds or ISO 8601.
- **Times.** Zeek writes a connection's line when the connection ends, but `ts` is its first
  packet. Each event is dated at `ts + duration`, the **last** packet, so a nine-hour connection
  written after hours of later lines is still in order for the rules (it would otherwise be
  dropped as late). `extra.start_time` keeps `ts`.
- **Outcome** from `conn_state`: `success` for established connections (`SF`, `S1`, `S2`, `S3`,
  `RSTO`, `RSTR`), `failure` for unanswered, rejected or half-open attempts (`S0`, `REJ`,
  `RSTOS0`, `RSTRH`, `SH`, `SHR`), `unknown` otherwise (`OTH`, missing).
- **Direction** from `local_orig` and `local_resp`, which Zeek fills only when
  `Site::local_nets` is configured: `T`/`F` is `outbound`, `F`/`T` `inbound`, `T`/`T`
  `internal`, `F`/`F` `external`.
- `extra` also keeps `conn_state`, `history`, `uid` and `community_id`. Invalid addresses,
  ports, counts, flags and durations are counted as errors for their line. A `#fields` header
  with more than 64 columns, duplicate or invalid names, or without `ts`, `id.orig_h` and
  `id.resp_h` is an error, and data lines after it are errors until a valid header comes.

## Testing and fuzzing

Parser tests cover every supported message, malformed and oversized lines, invalid UTF-8, CRLF
files, IPv6, New Year rollover and username injection; for the network parsers also every
record type, hostile values (bad addresses, ports, counts and durations, escapes, oversized
headers) and column orders. Hypothesis property tests check that
arbitrary text never raises and that the statistics always add up. An
[Atheris](https://github.com/google/atheris) harness in `fuzz/` runs coverage-guided fuzzing of
every parser in CI (Linux only).
