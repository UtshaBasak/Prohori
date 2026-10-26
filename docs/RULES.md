# Detection Rules

Prohori rules are YAML files, one rule per file. The format is **inspired by
[Sigma](https://github.com/SigmaHQ/sigma)** but is smaller and adds thresholds and sequences.
It is **not** Sigma-compatible.

```bash
prohori rules validate path/to/rules/   # every problem with file and line; exit 1 if any invalid
prohori rules list path/to/rules/       # valid rules with severity, status and ATT&CK tags
prohori rules list                      # the built-in rules
prohori rules test path/to/rules/       # run each rule against its fixtures
prohori detect samples/logs/auth.log    # run the rules over a log file
```

Both commands accept files and directories (searched recursively for `*.yml` and `*.yaml`) and
`--format json`. Exit codes: `0` all valid, `1` at least one invalid rule, `2` invalid usage.

> **Status.** Rules are loaded, validated, compiled and evaluated (stateless, `aggregate` and
> `sequence`), tested against fixtures with `prohori rules test`, and run over log files with
> `prohori detect`. Fourteen built-in rules ship today.

## Running rules: `prohori detect`

`prohori detect FILE` parses a log file (or `-` for standard input) and runs the rules over it.

```bash
prohori detect samples/logs/auth.log                  # built-in rules, alerts as a table
prohori detect access.log --format json > alerts.jsonl  # one alert per line, summary on stderr
prohori detect app.jsonl --rules my-rules/            # built-in rules plus your own
prohori detect app.jsonl --rules my-rules/ --no-builtin
```

| Option | Meaning |
|--------|---------|
| `--rules PATH` | Extra rule file or directory, run together with the built-in rules (repeatable) |
| `--no-builtin` | Run only the rules given with `--rules` |
| `--format table\|json` | Table of alerts and a summary, or JSON Lines alerts on stdout with a JSON summary on stderr |
| `--lateness 5m` | How far out of order events may arrive and still count (default `5m`; `0` for none). Later events are dropped and counted as late |
| `--exit-zero` | Exit 0 even when alerts are found |
| `--parser`, `--year`, `--timezone`, `--mapping`, `--pattern`, `--keep-query` | As for `prohori parse` |

Exit codes: `0` no alerts, `3` alerts found, `1` every non-blank line failed to parse or a rule
file is invalid (nothing is run with a partial rule set), `2` invalid usage or input.

Events dated more than one day after the current time are dropped and counted as future events,
so one bogus timestamp cannot stall detection for the rest of the file.

## Built-in rules

Run `prohori rules list` for the current set. Each rule ships with a fixture file, a runbook and
verified ATT&CK tags.

| Id | Severity | Detects | Logic |
|----|----------|---------|-------|
| PRH-AUTH-001 | high | Brute-force sign-ins from one IP | >= 10 app or SSH sign-in failures per `source.ip` in 5 min (sliding) |
| PRH-AUTH-002 | high | Password spraying or credential stuffing | app sign-in failures for >= 5 distinct `user.email_hash` per `source.ip` in 10 min |
| PRH-AUTH-003 | critical | Successful sign-in after many failures | >= 5 failures then a success, same `source.ip`, within 15 min |
| PRH-AUTH-004 | high | Account lockouts across many accounts | `auth.lockout` for >= 3 distinct `user.id` per `log_source` in 15 min |
| PRH-SESS-001 | high | Refresh-token reuse (probable stolen token) | every `session.refresh.reuse_detected` event |
| PRH-ACCT-001 | high | Sensitive account change shortly after sign-in | sign-in success, then a password, payout number or two-step change, same `user.id`, within 30 min |
| PRH-AUTHZ-001 | medium | Authorisation denials across many resources | `authz.denied` for >= 5 distinct `http.path` per `source.ip` in 10 min |
| PRH-ABUSE-001 | medium | Rate-limit bursts or bot-check failures | >= 20 `ratelimit.exceeded` / `turnstile.failed` per `source.ip` in 5 min |
| PRH-ADMIN-001 | high | Admin role granted | every `admin.role.granted` event |
| PRH-ADMIN-002 | medium | Admin action at an unusual hour | any admin event from 22:00 to 06:59 in `Asia/Dhaka` (`time.hour`) |
| PRH-WEB-001 | medium | Web scanning | 403/404 responses for >= 10 distinct `http.path` per `source.ip` in 5 min |
| PRH-WEB-002 | medium | Injection patterns in request paths | >= 3 requests per `source.ip` in 10 min whose URL-decoded path or query contains SQL injection, traversal or XSS markers |
| PRH-WEB-003 | medium | Scanner or empty user agent at a high rate | >= 30 requests per `source.ip` in 1 min with a scanning-tool or empty user agent |
| PRH-WEB-004 | medium | Probes for sensitive files and admin tools | >= 3 distinct sensitive paths (`/.env`, `/.git/`, `/wp-login.php`, ...) per `source.ip` in 10 min |
| PRH-SSH-001 | high | SSH invalid-user storm | >= 5 invalid-user attempts or MaxAuthTries disconnects per `source.ip` in 10 min |

Known limits, also stated in each rule's description:

- **PRH-AUTH-002** counts accounts by `user.email_hash`, which the app security log provides.
  Failures without one (unknown-user attempts the app logs without a hash) and SSH logs are not
  counted; their volume still triggers PRH-AUTH-001.
- **PRH-ACCT-001** cannot tell whether the sign-in came from a new IP or client: rules keep no
  per-account history. It fires for every sensitive change within 30 minutes of a sign-in, so the
  analyst compares the sign-in IP and client with the account's usual ones.
- **PRH-AUTHZ-001** counts distinct paths. The app logs `http.route`; if that is a route template
  (`/api/orders/:id`), probing many ids of one route counts once.
- **PRH-WEB-002** inspects only the request line (path and query string), not bodies or headers.
  Its markers are basic signatures: obfuscated payloads are missed, and harmless URLs that contain
  the same text (a search for "union select") can match. It needs three matching requests, so a
  single manual attempt does not alert.
- **PRH-WEB-003** relies on the user agent; a scanner that sends a browser user agent is caught
  only by PRH-WEB-001, PRH-WEB-002 or PRH-WEB-004.
- **PRH-ADMIN-001** fires for every grant, planned or not.
- **PRH-ADMIN-002** uses the shop's local time (`timezone: Asia/Dhaka`) and fixed night hours.
  Other sites should copy the rule and set their own `timezone` and hours.

### ATT&CK mapping

Tags are verified against **MITRE ATT&CK Enterprise v20.0**, using the official STIX bundle:

- URL: `https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-20.0.json`
- SHA-256: `81113ba98afa2928f3dcff62022539f7ce30c315c32e14422f11ff95ce534352`

The verified tactics and techniques, with names and tactics, are listed in
`src/prohori/rules/attack.py`. A test fails if a built-in rule uses a tag outside that list, has
no technique or tactic, or pairs a technique with tactics it does not belong to. ATT&CK v20
has the **Stealth** and **Defense Impairment** tactics in place of Defense Evasion, so
`attack.defense_evasion` is not used. To re-check the list, or after moving to a new ATT&CK
release, run (downloads about 50 MB):

```bash
uv run python scripts/verify_attack.py
```

| Technique | Name | Used by |
|-----------|------|---------|
| T1110 | Brute Force | AUTH-001, AUTH-003, AUTH-004, SSH-001 |
| T1110.001 | Password Guessing | AUTH-001, SSH-001 |
| T1110.003 | Password Spraying | AUTH-002 |
| T1110.004 | Credential Stuffing | AUTH-002 |
| T1078 | Valid Accounts | AUTH-003 |
| T1528 | Steal Application Access Token | SESS-001 |
| T1550.001 | Application Access Token | SESS-001 |
| T1098 | Account Manipulation | ACCT-001, ADMIN-001 |
| T1556.006 | Modify Authentication Process: Multi-Factor Authentication | ACCT-001 |
| T1595.003 | Active Scanning: Wordlist Scanning | AUTHZ-001 (closest fit for probing many resources), WEB-001, WEB-004 |
| T1595.002 | Active Scanning: Vulnerability Scanning | WEB-003 |
| T1190 | Exploit Public-Facing Application | WEB-002 |
| T1499.002 | Endpoint Denial of Service: Service Exhaustion Flood | ABUSE-001 |

### Runbooks

A rule's `response` key names its runbook. Built-in runbooks are packaged in
`src/prohori/runbooks/` and `response: runbooks/<name>.md` is resolved against the `prohori`
package, so they are available after `pip install`. Every runbook has the same sections, in this
order: *What it means*, *Triage*, *Recommended actions* (a bullet list), *False positives* and
*ATT&CK*.

Recommended actions that start with exactly `For SSH,` are shown only for incidents that contain
SSH events, and those starting with exactly `For the web app,` only for incidents that contain
web-app events.

## Example

```yaml
id: PRH-AUTH-001
title: Brute-force sign-in attempts from one IP
status: stable
severity: high
description: Many failed sign-ins from a single source IP in a short window.
tags: [attack.credential_access, attack.t1110]
logsource: {category: authentication}
detection:
  selection:
    event.action: [auth.signin.failure, ssh.login.failure]
  aggregate:
    group_by: [source.ip]
    window: 5m
    count_gte: 10
  condition: selection and aggregate
falsepositives: [Users behind a shared NAT, password-manager misconfiguration]
response: runbooks/brute-force.md
```

## Top-level keys

| Key | Required | Rules |
|-----|----------|-------|
| `id` | yes | Upper-case words joined by hyphens, for example `PRH-AUTH-001`. Unique across all loaded rules |
| `title` | yes | 3-200 characters |
| `status` | yes | `stable`, `test`, `experimental` or `deprecated` |
| `severity` | yes | `low`, `medium`, `high` or `critical` |
| `description` | no | Free text |
| `author` | no | Free text |
| `tags` | no | Lower-case tags. ATT&CK tags must be `attack.tNNNN`, `attack.tNNNN.NNN` or `attack.<tactic>` |
| `logsource` | no | `category` (an event category) and/or `log_source`; events must match every given key |
| `detection` | yes | Selections, a `condition`, and optionally one `aggregate` or `sequence` block |
| `falsepositives` | no | List of known benign causes |
| `response` | no | Relative path to a Markdown runbook, for example `runbooks/brute-force.md` |
| `references` | no | List of `http(s)://` links |
| `timezone` | no | IANA timezone for the `time.*` fields, for example `Asia/Dhaka` (default `UTC`) |

Unknown keys are errors, so typos are caught.

## Selections

Every key in `detection` other than `condition`, `aggregate` and `sequence` is a **selection**:
a name (letters, digits, underscore) mapped to field conditions.

```yaml
detection:
  scanner:                         # all keys must match
    http.status|gte: 400
    user_agent|contains: [sqlmap, nikto, zgrab]   # any value may match
  admin_paths:                     # a list of mappings: any mapping may match
    - http.path|startswith: /admin
    - http.path: [/wp-login.php, /phpmyadmin*]
  internal:
    source.ip|cidr: [10.0.0.0/8, 192.168.0.0/16]
  condition: scanner and admin_paths and not internal
```

Field names are the dotted schema names from [SCHEMA.md](SCHEMA.md) (`event.action`,
`source.ip`, `http.path`, ...) or `extra.<key>`. Unknown fields are errors.

Three **time fields** are computed from the event's `timestamp` in the rule's `timezone`:
`time.hour` (0-23), `time.weekday` (0 = Monday ... 6 = Sunday) and `time.minute_of_day`
(0-1439). Use them with numeric comparisons in selections; they cannot be used in `group_by`,
`distinct` or sequence `by` fields.

```yaml
timezone: Asia/Dhaka
detection:
  admin:
    event.category: admin
  night:
    - time.hour|gte: 22
    - time.hour|lt: 7
  condition: admin and night
```

### Matching rules

| Rule | Example |
|------|---------|
| Keys within one mapping must **all** match | `{http.method: GET, http.status: 404}` |
| A list of mappings matches if **any** mapping matches | `- {a: 1}` / `- {b: 2}` |
| A list of values matches if **any** value matches | `event.action: [x, y]` |
| `\|all` requires **every** value to match | `http.path\|contains\|all: [wp, login]` |
| Strings compare **case-insensitively** | `GET` matches `get` |
| `\|cased` makes the comparison case-sensitive | `http.path\|cased: /Admin` |
| `*` matches any run of characters and `?` one character in plain values | `/phpmyadmin*` |
| `\*`, `\?` and `\\` match literal `*`, `?` and `\`; any other backslash is literal | `'C:\Windows\System32'`; `'C:\Users\\*'` (backslash, then a wildcard) |
| A YAML number equals a numeric field or a numeric string with the same value | `http.status: 404` matches `404` and `"404"` |
| `true` / `false` match booleans (and the strings `true` / `false`) | `extra.flag: true` |
| `null` matches a **missing** field | `user.name: null` |
| A missing field never matches a non-null value or an operator other than `exists` | |

### Modifiers

Append modifiers to the field name with `|`. Use at most one operator, optionally with the
flags `all`, `cased` and `urldecode`.

| Modifier | Meaning |
|----------|---------|
| *(none)* | Equality, with wildcards for strings |
| `contains` | Substring |
| `startswith` / `endswith` | Prefix / suffix |
| `re` | Regular-expression **search** with RE2 (linear time; case-insensitive unless `cased`); see below |
| `cidr` | IP address inside a network, for example `203.0.113.0/24` or `2001:db8::/32` |
| `gt`, `gte`, `lt`, `lte` | Numeric comparison; non-numeric field values never match |
| `exists` | `true`: the field is set; `false`: it is missing |
| `all` (flag) | Every listed value must match (needs at least two values) |
| `cased` (flag) | Case-sensitive comparison |
| `urldecode` (flag) | Percent-decode the value first (`%27` becomes `'`, `+` a space), repeatedly for double encoding (at most three rounds). Only with equality, `contains`, `startswith`, `endswith` and `re` |

Limits: at most 512 values per key and 1,024 characters per value.

### Regular expressions (`re`)

`|re` patterns are compiled with [RE2](https://github.com/google/re2) (the `google-re2`
package), not Python's `re` module. RE2 never backtracks: matching time is **linear in the length
of the field by construction**, so no pattern can hang a run, even on hostile 8 KiB log lines.
Patterns are searched (they may match anywhere in the value) and are case-insensitive unless
`|cased` is used.

What RE2 does not support, and rejects when the rule is validated:

| Not supported | Example |
|---------------|---------|
| Backreferences | `(a)\1` |
| Look-ahead and look-behind | `(?=admin)`, `(?<!x)` |
| Atomic groups and possessive quantifiers | `(?>a+)`, `a++` |
| Repeat counts above 1,000 | `a{1001}` |
| Patterns longer than 256 characters | |

Differences from Python's `re` worth knowing:

- `\w`, `\d` and `\s` match ASCII characters only; use `\pL` (letters) or `\pN` (digits) for Unicode.
- `$` matches only at the end of the value. Event fields contain no newlines, so this rarely matters.

Accepted examples: `\.env$`, `union\s+select`, `(\d{1,3}\.){3}\d{1,3}`, `^/(wp-login\.php|phpmyadmin)`.
Prefer `contains`, `startswith`, `endswith` or wildcards where they suffice; they are simpler to
read.

## Condition

The `condition` combines selections:

```text
selection and not filter
(probe_paths or probe_agents) and not internal
1 of probe_*            # any selection whose name starts with probe_
all of probe_*          # every such selection
1 of them               # any selection
selection and aggregate # threshold rule (see below)
sequence                # sequence rule (see below)
```

Grammar: `not` binds tightest, then `and`, then `or`; parentheses group. Keywords are
case-insensitive. Conditions are parsed by a small recursive-descent parser (never `eval`),
limited to 1,000 characters and 32 levels of nesting.

Validation errors: unknown names, unparseable conditions, and selections that are defined but never
used (usually a typo).

## Thresholds: `aggregate`

Counts the events that pass the rest of the condition, per group and time window.

```yaml
aggregate:
  group_by: [source.ip]       # 1-5 fields
  window: 5m                  # 1s to 7d: a number followed by s, m, h or d
  mode: sliding               # sliding (default) or tumbling
  count_gte: 10               # exactly one of count_gte, distinct or ratio
  # distinct: {field: user.name, gte: 5}
  # ratio: {selection: client_error, gte: 0.8, min_count: 20}
```

- `count_gte`: at least N matching events.
- `distinct`: the field takes at least N distinct values (for example many users from one IP).
- `ratio`: the share of matching events that also match another selection reaches `gte`, once at
  least `min_count` events have been seen.

`aggregate` must appear in the condition as a top-level `and` term next to at least one selection:
`selection and aggregate`.

## Sequences: `sequence`

Ordered steps for the same entity within a time limit, for example many failures then a success.

```yaml
detection:
  failure: {event.action: [ssh.login.failure, auth.signin.failure]}
  success: {event.action: [ssh.login.success, auth.signin.success]}
  sequence:
    by: [source.ip]           # 1-5 fields identifying the entity
    within: 15m
    steps:                    # 2-5 steps, in order
      - {selection: failure, count_gte: 5}
      - {selection: success}
  condition: sequence
```

A sequence rule's condition must be exactly `sequence`. A rule uses either `aggregate` or
`sequence`, not both.

## Evaluation semantics

The engine (`prohori.rules.engine.RuleEngine`) evaluates every rule in a single pass over the
events, holding only bounded state.

| Topic | Behaviour |
|-------|-----------|
| Order | Events are evaluated in one total order: by timestamp, ties broken by event id. A reorder buffer holds events until the newest timestamp seen (the *watermark*) is more than `lateness` past them |
| Out-of-order events | An event that arrives with a timestamp of at least `watermark - lateness` is never late, so any arrival order within that bound produces identical alerts |
| Late events | An event that would sort before one already evaluated is dropped and counted (`late_events`) |
| Held events | Events at the newest timestamp (or within `lateness` of it) wait until a later event arrives or the input ends (`flush()`). With `lateness` 0 this only delays ties |
| Future timestamps | With a reference time ("now"), events more than one day after it are dropped and counted (`future_events`). Without one, a bogus future timestamp still lets in-order events through, but it disables out-of-order tolerance for the rest of the input. The engine never reads the clock itself |
| Sliding windows | An event is inside the window at time `t` when `t - event time < window`; an event exactly `window` old is outside |
| Tumbling windows | Aligned to the Unix epoch in UTC (a `1m` window runs from :00 to :59) |
| Re-alerting | When a threshold fires, that group's state is cleared; the next alert needs the threshold to be reached again by later events. A completed sequence stays open until `start + within`: every further `count_gte` events matching its last step raise another alert with the earlier steps' events (a second account change after one sign-in is reported too). Stateless rules alert once per matching event |
| Missing group fields | An event without a value for every `group_by` / `by` field is skipped for that rule and counted (`ungrouped_events`) |
| Sequences | Step 1 keeps its matches within `within` of the newest one; when it reaches its count, the sequence starts at the oldest of them. Later steps must complete before `start + within`; an event at or after that moment restarts the sequence with that event. After step 1 completes, more step-1 events are ignored. An event matching several steps counts for the current step. After the last step, see re-alerting |

Alerts carry the rule's id, title, severity, ATT&CK tags and an explanation. Their entities are
the `group_by` / `by` values, or for stateless rules whichever of `source.ip`, `user.name`,
`user.id`, `host` and `request_id` the event has. An alert lists at most the 100 most recent event
ids; the explanation gives the full count. Scores follow severity (low 25, medium 50, high 75,
critical 100) until incident scoring adds context.

Bounded state: the reorder buffer holds at most 100,000 events (overflows are released early and
counted); each stateful rule tracks at most 50,000 groups (the least recently seen are evicted and
counted); expired groups are removed as time advances; ratio thresholds keep at most 10,000 events
per group.

## Rule tests

Every rule `<name>.yml` needs a fixture file `<name>.tests.yml` next to it, with at least one
positive case (`alerts` >= 1) and one negative case (`alerts: 0`). `prohori rules test` fails for a
rule without fixtures, a fixture for a different rule id, or any case whose result differs.

```yaml
rule: PRH-AUTH-001
start: 2026-10-24T13:50:00Z         # first event time (default 2026-01-01T00:00:00Z)
defaults:                           # merged into every event (dotted schema fields)
  log_source: app-security
  event.category: authentication
cases:
  - name: ten failures within five minutes alert once
    expect: {alerts: 1, entities: [{source.ip: 203.0.113.7}]}
    events:
      - {event.action: auth.signin.failure, source.ip: 203.0.113.7, repeat: 10, every: 20s}
  - name: nine failures do not alert
    expect: {alerts: 0}
    events:
      - {event.action: auth.signin.failure, source.ip: 203.0.113.7, repeat: 9, every: 20s}
  - name: real log lines through a parser
    expect: {alerts: 0}
    log:
      parser: auth_log
      options: {year: 2026}
      lines:
        - "Oct 24 13:50:02 web01 sshd[1]: Failed password for root from 203.0.113.7 port 1 ssh2"
```

- **Timeline:** `at` sets an absolute time (with a timezone); otherwise `after` (default `1s`)
  advances from the previous event. `repeat` (default 1) emits copies `every` (default `1s`) apart.
- **Events** use the dotted schema fields; `raw` is generated if not given.
- **Log cases** run raw lines through a parser; any line that fails to parse fails the case.
  `auth_log` cases without a `year` option use the year of `start`, so results never depend on
  today's date.
- **Expectations:** `alerts` is the exact number of alerts; each mapping in `entities` must be
  contained in some alert's entities.
- Fixture files are loaded with the same safety limits as rules, and `rules list` / `validate`
  ignore them.

## File safety

Rule files are untrusted input:

- At most 128 KiB, UTF-8, exactly one YAML document.
- Loaded with `yaml.SafeLoader` only, so tags such as `!!python/object` are rejected.
- YAML anchors and aliases are rejected (they enable "billion laughs" expansion).
- At most 10,000 YAML nodes and 32 levels of nesting.

## Error messages

Every problem is reported with the file, the line of the offending YAML node, and its path:

```text
INVALID  rules/web.yml
  rules/web.yml:7: detection.selection.http.path|re: unsafe regex: a repeat inside an unbounded repeat (for example '(a+)+') is not allowed
```

## Authoring checklist

1. Give the rule a unique `id`, a clear `title`, `status` and `severity`.
2. Tag ATT&CK techniques and tactics (`attack.t1110`, `attack.credential_access`).
3. Prefer exact values, lists and `contains` / `startswith` / `endswith` over `re`.
4. Add a `filter` selection for known benign sources and use `and not filter`.
5. List `falsepositives` and link a `response` runbook.
6. Run `prohori rules validate` until it reports no errors.
7. Write `<name>.tests.yml` with positive and negative cases and run `prohori rules test`.
