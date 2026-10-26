# Incidents

The incident builder turns alerts into incidents: related alerts grouped together, scored with a
documented points system, mapped to MITRE ATT&CK and given recommended actions, a timeline,
indicators, a confidence level and the limitations of the evidence.

```bash
prohori incidents samples/logs/account-takeover.jsonl            # one table per incident
prohori incidents samples/logs/account-takeover.jsonl -f json    # JSON Lines, one incident each
prohori incidents auth.log --online                              # enrich with configured providers
prohori incidents auth.log --no-enrich --gap 1h
```

`prohori incidents` takes the same parser and rule options as `prohori detect` (`--parser`,
`--year`, `--rules`, `--no-builtin`, `--lateness`, ...). Exit codes: `0` no incidents, `3`
incidents found (`0` with `--exit-zero`), `1` nothing could be parsed or a rule file is invalid,
`2` invalid usage or setting. With `-f json` a summary is printed on standard error.

**Enrichment is offline by default**: bundled demo data, local GeoLite2 data and cached answers,
never the network. Logs contain other people's IP addresses, and querying VirusTotal adds them to
its dataset, so sending them out is a choice: add `--online` to use the providers configured in
[ENRICHMENT.md](ENRICHMENT.md). At most 100 distinct addresses are looked up per run, each once.

## Grouping

Alerts that share an **entity** within a **time gap** (default 30 minutes, `--gap`) form one
incident. Entities are these fields:

| Field | Why |
|-------|-----|
| `source.ip` | The attacker's (or victim's) address |
| `user.id`, `user.name`, `user.email_hash` | The account involved |
| `request_id` | One request seen by several rules |
| `extra.session_id` | One session, when a parser or field mapping provides it |

- Pairs are compared as `(field, value)`: a user id that happens to equal an IP links nothing.
- An alert's entities are its own (the rule's `group_by` or `sequence.by` fields, or the fixed
  fields of a single-event rule) **plus every entity field that has exactly one value across its
  matched events**. A brute-force alert grouped by IP therefore also links on the one account it
  targeted, which joins it to a later account change made from another address; an SSH scan that
  tried a dozen user names links on its IP only.
- `host` and `log_source` never link: every line of one server's log shares them.
- Two alerts with a common entity are linked when the later one starts at most `gap` after the
  latest end of the earlier alerts with that entity (inclusive). Links are transitive.
- **Shared addresses.** NAT gateways, proxies and VPNs put many people behind one IP. Once an IP
  has linked alerts about more than 10 distinct accounts it is treated as shared: it links no
  further alerts, and the incidents it appears in say so in their limitations.
- The result does not depend on the order of the alerts.

## Score

The score is a sum of points, each with a reason, shown as the incident's `score_breakdown`. The
breakdown always adds up to the score.

| Component | Points |
|-----------|--------|
| Most severe alert | low 10, medium 20, high 35, critical 50 |
| Each further distinct rule | +10, at most +30 |
| A sign-in succeeded after failed attempts from the same IP or for the same account (or `PRH-AUTH-003` fired) | +20 |
| A sensitive change: `account.password.changed`, `account.bkash.changed`, `account.2fa.disabled`, `admin.role.granted` (or `PRH-ACCT-001` / `PRH-ADMIN-001` fired) | +15 |
| Reputation of the worst IP address: abuse confidence >= 75 (+15) or >= 25 (+8); >= 3 vendors flag it as malicious (+15) or at least one (+8); Tor exit node (+5) | at most +20 |
| Spread: each source IP and each account after the first | +5, at most +15 |
| Novelty: a sign-in from an IP not seen before for an account that signed in earlier | +10 |
| Novelty: a sign-in with a client not seen before for the account | +5 |
| Cap | the total is capped at 100, shown as a negative component |

**Severity** comes from the score: low below 25, medium from 25, high from 50, critical from 75.
An incident is never less severe than its most severe alert.

**Novelty** uses a bounded history of every successful sign-in in the input (not just the ones in
alerts), per account and by timestamp. If the account has no earlier sign-in in the input, Prohori
cannot tell whether the address is new: that gives no points and a limitation instead. Up to
50,000 accounts and 64 addresses and clients per account are remembered; beyond that novelty is
reported as unknown.

## Confidence

| Confidence | When |
|------------|------|
| `high` | At least two distinct rules, corroborated by a second log source, bad IP reputation or a sign-in after failures |
| `low` | A single low- or medium-severity alert with no bad reputation |
| `medium` | Everything else |

## ATT&CK

The incident's `attack` tags are the union of its alerts' rule tags: tactics in ATT&CK order, then
techniques. `attack_version` names the release they were verified against (Enterprise ATT&CK
v20.0, see [RULES.md](RULES.md#attck-mapping)). Tags from custom rules that are not in the
verified list are kept and listed as a limitation.

## Recommended actions

The bullets under `## Recommended actions` in each rule's runbook, most severe rule first,
without duplicates and at most 15. Built-in runbooks are packaged with Prohori; a custom rule's
`response` path is read relative to the rule file. A missing runbook gives no actions, not an
error.

## Timeline, indicators and entities

- **Timeline:** every matched event (log source, action, outcome, account, IP, request, client)
  and every alert, by time. Long timelines keep the earliest and latest 100 events.
- **Indicators:** the incident's IP addresses with their enrichment, and up to 10 user agents.
- **Entities:** every entity of the incident's alerts, at most 50 values per field.

## Limitations

Each incident lists what weakens its evidence, for example:

- enrichment not run, offline, from bundled demo data, or incomplete for an address;
- a single log source;
- matched events that were no longer in memory (Prohori keeps a slim summary of the last 100,000
  events, never the raw lines);
- no earlier sign-in to compare a sign-in with;
- a shared IP address that stopped linking alerts;
- unverified ATT&CK tags;
- the rules' known benign causes (their `falsepositives`).

## Determinism

The same input gives the same incidents: the id is `INC-` and the first 16 hex digits of the
SHA-256 of the sorted alert ids, nothing reads the clock, and every list is sorted. Online
enrichment results carry their retrieval times, which naturally differ between runs.
