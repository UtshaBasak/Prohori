# Detection Rules

Prohori rules are YAML files, one rule per file. The format is **inspired by
[Sigma](https://github.com/SigmaHQ/sigma)** but is smaller and adds thresholds and sequences.
It is **not** Sigma-compatible.

```bash
prohori rules validate path/to/rules/   # every problem with file and line; exit 1 if any invalid
prohori rules list path/to/rules/       # valid rules with severity, status and ATT&CK tags
prohori rules list                      # the built-in rules
prohori rules test path/to/rules/       # run each rule against its fixtures
```

Both commands accept files and directories (searched recursively for `*.yml` and `*.yaml`) and
`--format json`. Exit codes: `0` all valid, `1` at least one invalid rule, `2` invalid usage.

> **Status.** Rules are loaded, validated, compiled and evaluated (stateless, `aggregate` and
> `sequence`), and every rule can be tested against fixtures with `prohori rules test`.
> Running rules over log files from the command line (`prohori detect`) arrives next.

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
flags `all` and `cased`.

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
| Re-alerting | When a threshold or sequence fires, that group's state is cleared; the next alert needs the threshold to be reached again by later events. Stateless rules alert once per matching event |
| Missing group fields | An event without a value for every `group_by` / `by` field is skipped for that rule and counted (`ungrouped_events`) |
| Sequences | Step 1 keeps its matches within `within` of the newest one; when it reaches its count, the sequence starts at the oldest of them. Later steps must complete before `start + within`; an event at or after that moment restarts the sequence with that event. After step 1 completes, more step-1 events are ignored. An event matching several steps counts for the current step |

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
