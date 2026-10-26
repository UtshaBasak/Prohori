# Simulator and rule evaluation

`prohori simulate` writes realistic, labelled attack scenarios as log files: an attack hidden in
benign background activity, a label for every line, and a manifest. They are for trying Prohori
without real logs and for measuring how well the detection rules work.

**Nothing is attacked and nothing is sent anywhere.** The simulator only writes files. Every IP
address is from a documentation range (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`,
`2001:db8::/32`), every account is made up, and tests check both.

```bash
prohori simulate --list                                         # scenarios and parameters
prohori simulate ssh-bruteforce --seed 1 --out out/             # write a scenario
prohori simulate ssh-bruteforce --seed 1 --out out/ --variant heldout
prohori simulate account-takeover --seed 7 --out out/ --set attempts=20 --set rate=5
prohori detect out/ssh-bruteforce.log --parser auth_log --year 2026
prohori incidents out/account-takeover.jsonl
```

The same scenario, variant, seed and parameters always give byte-identical files (checked in CI
on Linux and Windows with Python 3.11 to 3.14). Exit codes: `0` written, `2` invalid usage,
scenario, variant or parameter.

## Scenarios

| Scenario | Log | Attack | Expected rules |
|----------|-----|--------|----------------|
| `ssh-bruteforce` | `auth.log` | Password guessing against root and common user names | PRH-AUTH-001, PRH-SSH-001 |
| `password-spraying` | app JSON | One password tried against many accounts | PRH-AUTH-002, PRH-AUTH-001 |
| `credential-stuffing` | app JSON | Leaked credentials replayed; a few still work | PRH-AUTH-001, PRH-AUTH-002, PRH-AUTH-003 |
| `token-reuse` | app JSON | Stolen refresh tokens replayed | PRH-SESS-001 |
| `account-takeover` | app JSON | Guessing one account's password, then disabling 2FA and changing the payout number | PRH-AUTH-001, PRH-AUTH-003, PRH-ACCT-001 |
| `web-scanning` | access log | Automated scan for admin tools, backups and leaked files | PRH-WEB-001, PRH-WEB-003, PRH-WEB-004 |
| `injection` | access log | SQL injection, cross-site scripting and path traversal in query strings | PRH-WEB-002 |
| `admin-misuse` | app JSON | A hijacked admin session at night grants admin rights to another account | PRH-ADMIN-001, PRH-ADMIN-002 |

The expected rules are declared in the scenario code (`src/prohori/simulate/scenarios.py`)
before any evaluation is run.

### Variants

Every scenario has two variants with the same expected rules:

- **`default`**: the attack as the rules were designed for: fast, from one or two addresses,
  with obvious tools.
- **`heldout`**: how a careful attacker would change it. Slower than the rules' thresholds
  (SSH guessing at 1.5 attempts per minute per address, spraying at 0.4), spread over more
  addresses (credential stuffing from 30), with a browser user agent instead of a scanner's,
  obfuscated injection payloads, an account takeover that waits more than 30 minutes before
  changing settings, and admin misuse at 21:30 instead of 02:40.

The held-out `token-reuse` variant is no harder than its default (only the address family and
client change): the reuse event itself is logged either way. A miss in a held-out variant is a
real miss, and the results below report it.

### Background activity

Each attack is mixed into normal activity of the same log type, including the cases that
cause false positives:

- **SSH:** staff logging in with keys, a mistyped password followed by a success, cron
  sessions, and stray probes from the internet.
- **Web:** customers browsing pages and static files, the odd 404, and a search-engine crawler
  that hits a few dead links.
- **App:** customers signing in, refreshing sessions, an occasional typo, many customers behind
  one shared NAT address, authorisation denials, rate-limit hits, owners changing their password
  or payout number shortly after signing in (2% of background events), and admins doing routine
  work in office hours, including one planned role grant.

### Parameters

Each scenario's defaults are listed by `prohori simulate --list`. Change them with
`--set NAME=VALUE`; values outside the allowed range are rejected.

| Parameter | Meaning | Range |
|-----------|---------|-------|
| `start` | Start time, ISO 8601 with a timezone | any |
| `duration` | Minutes of background activity | 10-1440 |
| `users` | Accounts in the background population (app scenarios) | 5-500 |
| `noise` | Background events per minute | 0-60 |
| `attack_at` | Minutes after the start when the attack begins | 0-1440 |
| `rate` | Attack attempts per minute, per attacking address | 0.1-600 |
| `attempts` | Attack attempts | 1-10,000 |
| `sources` | Attacking addresses | 1-50 |

A run writes at most 200,000 lines.

## Output

`--out DIR` receives three files:

- `<scenario>.log` or `<scenario>.jsonl`: the log, in time order.
- `<scenario>.labels.jsonl`: one line per log line, `{"line": 12, "attack": "ssh-bruteforce-1"}`,
  with `"attack": null` for benign lines. Line numbers start at 1, as in the parsers.
- `manifest.json`: scenario, variant, seed, start time, the year (`auth.log` lines have none;
  pass it with `--year`), parameters, the parser to use, file names with SHA-256 hashes, line
  counts and each attack with its expected rules.

## Rule evaluation

```bash
uv run python scripts/evaluate_rules.py          # writes results/rules_eval.json
uv run python scripts/generate_results_table.py  # updates the tables below
```

The evaluation runs each scenario, in both variants, for seeds 1 to 5. Each log goes through
the same path as `prohori detect`: the scenario's parser and all built-in rules with 5 minutes of
lateness. Then:

- An alert is a **true positive** if at least half of the events it lists come from attack
  lines; otherwise it is a false positive. **Precision** = true-positive alerts / all alerts.
- An attack is **detected by a rule** if the rule raised a true-positive alert for it.
  **Recall** = attacks detected by the rule / attacks that expect the rule.
- Rules that no scenario expects (PRH-ABUSE-001, PRH-AUTH-004, PRH-AUTHZ-001) have no recall:
  they are **not evaluated**, not "0%" or "100%".

### Results

<!-- results:start -->
Generated by `scripts/evaluate_rules.py`: 8 scenarios, seeds 1 to 5 per variant. Do not edit by hand.

| Rule | Precision (default) | Recall (default) | Precision (held-out) | Recall (held-out) |
|------|--------------------:|-----------------:|---------------------:|------------------:|
| PRH-ABUSE-001 | not evaluated | not evaluated | not evaluated | not evaluated |
| PRH-ACCT-001 | 3% (10/300) | 100% | 2% (4/258) | 40% |
| PRH-ADMIN-001 | 50% (5/10) | 100% | 50% (5/10) | 100% |
| PRH-ADMIN-002 | 100% (10/10) | 100% | no alerts (0/0) | 0% |
| PRH-AUTH-001 | 100% (101/101) | 100% | no alerts (0/0) | 0% |
| PRH-AUTH-002 | 100% (107/107) | 100% | 100% (19/19) | 50% |
| PRH-AUTH-003 | 100% (28/28) | 100% | 100% (5/5) | 50% |
| PRH-AUTH-004 | not evaluated | not evaluated | not evaluated | not evaluated |
| PRH-AUTHZ-001 | not evaluated | not evaluated | not evaluated | not evaluated |
| PRH-SESS-001 | 100% (15/15) | 100% | 100% (15/15) | 100% |
| PRH-SSH-001 | 100% (50/50) | 100% | 100% (10/10) | 100% |
| PRH-WEB-001 | 100% (70/70) | 100% | 100% (70/70) | 100% |
| PRH-WEB-002 | 100% (30/30) | 100% | 100% (20/20) | 100% |
| PRH-WEB-003 | 100% (25/25) | 100% | no alerts (0/0) | 0% |
| PRH-WEB-004 | 100% (15/15) | 100% | 100% (15/15) | 100% |

Attacks caught by at least one of their expected rules:

| Scenario | Default | Held-out | Missed in held-out by |
|----------|--------:|---------:|-----------------------|
| account-takeover | 5/5 | 5/5 | PRH-ACCT-001 (3/5), PRH-AUTH-001 (5/5) |
| admin-misuse | 5/5 | 5/5 | PRH-ADMIN-002 (5/5) |
| credential-stuffing | 5/5 | 0/5 | PRH-AUTH-001 (5/5), PRH-AUTH-002 (5/5), PRH-AUTH-003 (5/5) |
| injection | 5/5 | 5/5 | - |
| password-spraying | 5/5 | 5/5 | PRH-AUTH-001 (5/5) |
| ssh-bruteforce | 5/5 | 5/5 | PRH-AUTH-001 (5/5) |
| token-reuse | 5/5 | 5/5 | - |
| web-scanning | 5/5 | 5/5 | PRH-WEB-003 (5/5) |
<!-- results:end -->

### How to read these numbers

- **They are not a measure of real-world accuracy.** The same author wrote the rules and the
  scenarios, and the default variants were written knowing the rules' thresholds, so the default
  columns mostly confirm that the rules do what they say. The held-out columns are the more
  honest number: they show which plausible changes in attacker behaviour slip past the rules.
- **Precision depends on the background mix.** PRH-ACCT-001 fires for every sensitive change
  shortly after a sign-in, so the owners' own changes in the background are false positives, as
  they would be in real use. The planned admin role grant is a false positive for PRH-ADMIN-001.
- Rules and scenarios were not adjusted after the held-out results were seen. The results were
  regenerated once in this step after an engine bug fix (a second sign-in did not open a new
  sequence window), which changed no threshold.
- Real logs are noisier and more varied than any simulator. Test rules on your own logs before
  trusting them.
