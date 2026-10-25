# Detection Rules

Prohori rules are YAML files, one rule per file. The format is **inspired by
[Sigma](https://github.com/SigmaHQ/sigma)** but is smaller and adds thresholds and sequences.
It is **not** Sigma-compatible.

```bash
prohori rules validate path/to/rules/   # every problem with file and line; exit 1 if any invalid
prohori rules list path/to/rules/       # valid rules with severity, status and ATT&CK tags
prohori rules list                      # the built-in rules
```

Both commands accept files and directories (searched recursively for `*.yml` and `*.yaml`) and
`--format json`. Exit codes: `0` all valid, `1` at least one invalid rule, `2` invalid usage.

> **Status.** Rules are loaded, validated and compiled, and stateless matching works.
> Evaluating `aggregate` and `sequence` blocks over time (the stateful engine) and
> `prohori rules test` arrive in the next release step; their block format may still change.

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
