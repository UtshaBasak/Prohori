# Parsers

Parsers turn raw log lines into [common-schema events](SCHEMA.md). They live in
`prohori.parsers` and share one framework.

| Parser | Registry name | Input | Status |
|--------|---------------|-------|--------|
| Linux `auth.log` / `secure` | `auth_log` | sshd, sudo and PAM lines from syslog | Available |
| nginx / Apache access logs | - | Combined log format | Planned |
| App security events | - | JSON Lines | Planned |
| Generic JSON Lines | - | JSON Lines with a field-mapping file | Planned |

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

## Testing and fuzzing

Parser tests cover every supported message, malformed and oversized lines, invalid UTF-8, CRLF
files, IPv6, New Year rollover and username injection. Hypothesis property tests check that
arbitrary text never raises and that the statistics always add up. An
[Atheris](https://github.com/google/atheris) harness in `fuzz/` runs coverage-guided fuzzing in
CI (Linux only).
