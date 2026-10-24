# Parsers

Parsers turn raw log lines into [common-schema events](SCHEMA.md). They live in
`prohori.parsers` and share one framework.

| Parser | Registry name | Input | Status |
|--------|---------------|-------|--------|
| Linux `auth.log` / `secure` | `auth_log` | sshd, sudo and PAM lines from syslog | Available |
| nginx / Apache access logs | `access_log` | Combined or common log format, or a custom pattern | Available |
| App security events | `app_json` | JSON Lines in the documented application format | Available |
| Generic JSON Lines | `generic_json` | Any JSON Lines, with a YAML field-mapping file | Available |

## Command line

```bash
prohori parse samples/logs/auth.log                 # format detected, table output
prohori parse samples/logs/access.log --format json # one event per line (JSON Lines)
cat samples/logs/auth.log | prohori parse - --year 2026
prohori parse samples/logs/payments.jsonl --parser generic_json \
    --mapping samples/mappings/payments.yaml
```

| Option | Applies to | Meaning |
|--------|------------|---------|
| `--parser`, `-p` | all | `auto` (default) or a parser name |
| `--format`, `-f` | all | `table` (summary and the first `--limit` events) or `json` (events on standard output as JSON Lines, summary as JSON on standard error) |
| `--year` | `auth_log` | Year of the first line (default: from the file date) |
| `--timezone` | `auth_log` | IANA timezone for timestamps without an offset (default `UTC`) |
| `--pattern` | `access_log` | Custom regular expression |
| `--keep-query` | `access_log` | Keep the query string in `http.path` |
| `--mapping` | `generic_json` | YAML field-mapping file |
| `--limit` | `table` | Events to show (default 20; counts always cover the whole input) |

Exit codes: `0` success, `1` no events and at least one malformed line (every line failed),
`2` invalid usage or input (unknown parser, missing file, undetectable format, bad options).

Table output never interprets log content as formatting: cell text is rendered literally.

### Format detection

With `--parser auto`, up to 20 non-blank lines are classified and the most common format wins
(ties go to the first in this order):

1. `app_json`: a JSON object with a `time` string and an `event` object containing `action`.
2. `generic_json`: any other JSON object. This needs a mapping file, so detection stops with a
   message asking for `--parser generic_json --mapping FILE`.
3. `auth_log`: a syslog line (RFC 3164 or RFC 3339 timestamp, host, program).
4. `access_log`: a combined or common log format line.

Detection is a convenience. Use `--parser` in scripts.

## Framework guarantees

- **Streaming.** Parsers are generators; memory use does not grow with input size.
- **Bounded lines.** Files are read in binary with a per-line limit of 16,384 characters. Longer
  lines are counted as errors without being matched (which also bounds regular-expression work),
  and the remainder of such a line is discarded in chunks rather than loaded into memory.
- **Tolerant.** A malformed line is counted and reported; it never stops the run.
- **Sanitised.** Line endings (`\n` and `\r\n`), ANSI escape sequences, control characters and
  invisible formatting characters (zero-width, bidirectional overrides, byte-order marks) are
  removed before parsing. Tabs become spaces.
- **Any encoding damage is survivable.** Input is decoded as UTF-8; invalid bytes become `U+FFFD`
  and the line is counted in `decode_errors`.

### Statistics

Every run fills a `ParseStats`. Each line read is counted in exactly one of:

| Counter | Meaning |
|---------|---------|
| `events` | Parsed into an event |
| `skipped` | Well-formed but not relevant to this parser (for example a `CRON` line in `auth.log`) |
| `blank` | Empty or whitespace only |
| `errors` | Malformed: no timestamp, invalid date, line too long, and so on |

`decode_errors` counts lines that contained invalid UTF-8 (they may still parse), and
`error_examples` keeps the first ten errors with line numbers and reasons.

### Event ids

Each event id includes the input name and line number (`auth.log:1042`), so two identical lines
in the same second remain two events, and re-parsing the same file gives the same ids.

## `auth_log`

### Supported messages

| Program | Message | `event.action` | Outcome | `event.reason` |
|---------|---------|----------------|---------|----------------|
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
(`UseDNS yes`), `source.ip` is empty and the name is kept in `extra.source_host`.
IPv4-mapped IPv6 addresses (`::ffff:203.0.113.7`) are stored as IPv4.

### Timestamps

Two syslog header formats are accepted:

| Format | Example | Year | Timezone |
|--------|---------|------|----------|
| RFC 3164 (traditional) | `Oct 24 13:50:12 web01 sshd[1]: ...` | Not in the line | Not in the line |
| RFC 3339 (rsyslog high precision, default on recent distributions) | `2026-10-24T13:50:12.345678+06:00 web01 sshd[1]: ...` | In the line | In the line |

For RFC 3164 lines:

- **Timezone:** the `timezone` option (an IANA name such as `Asia/Dhaka`, default `UTC`).
  Ambiguous local times during a daylight-saving change resolve to the first occurrence.
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
- Throughput is roughly 25,000 lines per second on a laptop CPU (Python 3.13); performance work
  is planned for a later release.

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
|--------|-------|
| Remote address | `source.ip` (or `extra.source_host` if it is not an address) |
| Authenticated user (`-` means none) | `user.name` |
| `[24/Oct/2026:13:50:12 +0600]` | `timestamp` (converted to UTC; month names are parsed independently of the locale) |
| Request line `GET /path?query HTTP/1.1` | `http.method`, `http.path`, `extra.query`, `extra.protocol` |
| Status, bytes (`-` means none) | `http.status`, `http.bytes` |
| Referer, user agent | `extra.referer`, `user_agent` |

- **Query strings** are removed from `http.path` and kept in `extra.query`, so paths group cleanly
  while injection rules can still inspect the query. `--keep-query` keeps them in the path.
- **Unparseable request lines** (for example a TLS handshake sent to a plain-HTTP port) leave
  method and path empty and keep the request text in `extra.request`.
- **Escapes** written by nginx (`\x22`) and Apache (`\"`) are decoded in the request, referer
  and user agent.
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
|--------|----------|
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

## Testing and fuzzing

Parser tests cover every supported message, malformed and oversized lines, invalid UTF-8, CRLF
files, IPv6, New Year rollover and username injection. Hypothesis property tests check that
arbitrary text never raises and that the statistics always add up. An
[Atheris](https://github.com/google/atheris) harness in `fuzz/` runs coverage-guided fuzzing of
every parser in CI (Linux only).
