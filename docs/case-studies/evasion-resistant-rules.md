# Case study: catching slow and distributed credential attacks

A short write-up of one improvement to Prohori's detection rules: what was wrong, what changed,
how it was measured so the numbers could not be fitted, and what still fails. The full decision
record is ADR-0036 in [DECISIONS.md](../DECISIONS.md); the generated tables are in
[RULES.md](../RULES.md#evasion-resistant-rules-before-and-after) and
[SIMULATOR.md](../SIMULATOR.md#results).

## The problem

Prohori 1.0's sign-in rules all counted **per source address**: ten failures from one address
in five minutes, five accounts from one address in ten minutes, and so on. That is the classic
design, and it is easy to evade. An attacker who slows down, or spreads attempts over many
addresses, keeps every address under every threshold.

The simulator already showed it. Its held-out variants replay each attack the way a careful
attacker would. With the 1.0 rules:

- **Credential stuffing** (leaked email and password pairs replayed from 30 addresses) was missed
  in 5 of 5 runs. No rule fired.
- The per-address brute-force rule (PRH-AUTH-001) missed every held-out password-spraying and
  SSH brute-force run. Other rules happened to catch those attacks, but not for the right reason.

## What changed

Six rules that count what the attacker cannot spread out:

| Rule | Counts | Catches |
| --- | --- | --- |
| PRH-AUTH-005 | addresses failing on **one account** | guesses on one account from a botnet |
| PRH-AUTH-006 | failures of **one account over 24 hours** | slow guessing under every rate limit |
| PRH-AUTH-007 | accounts failing from **one network** (/24, /48) | spraying from one provider |
| PRH-AUTH-008 | accounts **and** addresses failing **in one log** | credential stuffing |
| PRH-AUTH-009 | addresses trying **unknown accounts** | credential stuffing (leaked lists) |
| PRH-AUTH-010 | **one account**: many failures, then a success | a slow or distributed attack that got in |

Three small engine features made them possible: a threshold on several distinct counts at once
(accounts *and* addresses), field alternatives (an account is `user.id`, else `user.name`, else
`user.email_hash`), and a derived `source.ip_prefix` field. Failures for accounts that do not
exist are ignored by the per-account rules, because there is nothing to take over and internet
scanners produce them all day.

## Keeping the numbers honest

A detection improvement is easy to fake by tuning thresholds until the test set passes. The
procedure was fixed first:

1. **Freeze the baseline.** The 1.0 rules' results were recorded before any rule changed, in a
   part of `results/rules_eval.json` the evaluation script refuses to overwrite.
2. **One rule for every threshold:** twice the largest value the benign background reaches in the
   default (non-held-out) scenarios. For example, no benign account failed from more than 2
   addresses in an hour, so PRH-AUTH-005 needs 4. Tuning used a mode that scores the default
   variants only and writes nothing.
3. **Commit before scoring.** The rules and their reasoning were committed before the held-out
   variants were scored, and the held-out set was then scored once.
4. **A second, fresh test set.** `heldout2` was defined only after the rules were fixed, by a rule
   written down beforehand: rates halved, sources doubled and spread over every documentation
   network. Both the old and the new rules were scored on it once.

One disclosure, also in the ADR: before step 3, rebuilding an unrelated evaluation set ran the
new rules over one held-out seed and showed that a held-out credential-stuffing incident now
existed. No rule was changed after that.

## Results

Attacks caught by at least one of their expected rules, 5 runs per scenario:

| | Held-out, 1.0 | Held-out, now | Held-out 2, 1.0 | Held-out 2, now |
| --- | ---: | ---: | ---: | ---: |
| Credential stuffing | 0/5 | **5/5** | 0/5 | **5/5** |
| Password spraying | 5/5 | 5/5 | 0/5 | **0/5** |
| All 8 scenarios | 35/40 | **40/40** | 30/40 | **35/40** |
| False-positive alerts on benign lines | 259 | 259 | 287 | 287 |

- Credential stuffing went from never caught to always caught, on both held-out sets, through
  PRH-AUTH-008 and PRH-AUTH-009.
- The per-account rules fire in every held-out SSH brute-force run (PRH-AUTH-006 on both sets,
  PRH-AUTH-005 on the second).
- **Not one new false positive** in any variant: the default variants' 295 false-positive alerts
  (almost all one rule, PRH-ACCT-001, firing on owners' own account changes, by design) are
  unchanged.

## What still fails, and why

- **Spraying spread over many networks** (`heldout2`) is missed by everything, old and new. The
  per-network rule needs 38 accounts from one network, because the simulator puts every customer
  in one documentation /24, so benign traffic already reaches 19 per network and the 2x rule
  doubles it. Against real traffic, with customers spread over many networks, the threshold
  could be far lower. The fix belongs in the simulator's address model, not in a threshold
  tuned after the fact.
- **The per-network rule also missed the first held-out spraying** (30 accounts, under its 38).
  PRH-AUTH-002 still caught those runs.
- **PRH-AUTH-009 has no measured false-positive rate:** the simulator's customers never mistype
  their email, so there was no benign baseline. It ships as `experimental`.
- **Simulator effects.** Simulated attackers in the 1.0 held-out variants share one /24, which a
  per-network rule groups for free; `heldout2` spreads them out to measure that. The default
  variants were written knowing the old thresholds. None of this is real-world accuracy.
- **Operational cost.** The per-account rules are noisier behind shared networks, during password
  resets and on SSH servers open to the internet; the per-log thresholds are absolute and need
  raising on a busy site. A 24-hour window also keeps open incidents in the streaming pipeline
  longer.

## Takeaways

Count what the attacker has to keep constant (the target account, the log, the network) as well
as what they can rotate (the address). Decide how thresholds are chosen before looking at the
test data, freeze the "before" numbers, and keep a test set back that did not exist while the
rules were written. Then report the misses as plainly as the wins.
