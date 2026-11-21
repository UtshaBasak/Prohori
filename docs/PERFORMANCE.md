# Performance

How fast Prohori processes logs and how much memory it needs, measured on logs of more than a
million lines each.

## Contents

- [How it is measured](#how-it-is-measured)
- [Results](#results)
- [What the numbers mean](#what-the-numbers-mean)
- [Running it yourself](#running-it-yourself)

## How it is measured

`scripts/benchmark.py` builds one log per input format from the simulator, chunk after chunk of
busy background activity with the scenario's attack in each chunk, every chunk with its own seed
and later in time:

- an nginx/Apache access log (the web-scanning scenario, a day per chunk);
- an `auth.log` from sshd (the SSH brute-force scenario, three hours per chunk, so the log is
  under constant attack);
- a JSON Lines application log (the account-takeover scenario, a day per chunk).

It then runs each command once, in its own process, and records:

- **time:** wall-clock time from start to exit;
- **peak memory:** the process's peak resident set (Linux and macOS) or peak working set
  (Windows), read from the operating system for that process alone;
- **exit code** and the machine it ran on.

The runs below (2026-11-21, step 28c) use 1.1's 21 rules and logs from simulator address model
2. Compared with the 2026-11-02 runs (1.0's 15 rules, address model 1), the auth.log and app log
read about 22 % and 28 % fewer lines a second and lite mode 15 % fewer, the cost of the six
per-account, per-network and per-log rules; the app log's peak memory fell from 524 to 245 MiB.
One run each on one machine, so differences of a few percent are noise. The commands are `prohori incidents` on every log
(parsing, the rules, offline enrichment,
incident building and JSON output), `prohori pipeline replay` in lite mode on the access log, and
`prohori demo`. Output goes to files, not a terminal.

## Results

<!-- performance:start -->
Generated from `results/performance.json` by `scripts/benchmark.py`, run on 2026-11-21 with Prohori 1.0.1 and Python 3.13.14 on Windows 11 (AMD64, 12 logical CPUs, Intel64 Family 6 Model 141 Stepping 1, GenuineIntel). Do not edit by hand.

| Run | Lines | Size | Time | Lines a second | Peak memory | Exit code |
| ----- | ------: | -----: | -----: | ------: | ------: | ------: |
| `incidents`, nginx/Apache access log | 1,068,041 | 206 MiB | 149.3 s | 7,155 | 149 MiB | 0 |
| `pipeline replay` (lite mode), access log | 1,068,041 | 206 MiB | 563.9 s | 1,894 | 1,096 MiB | 0 |
| `incidents`, auth.log (sshd) | 1,000,591 | 101 MiB | 100.0 s | 10,009 | 180 MiB | 0 |
| `incidents`, JSON Lines app log | 1,036,150 | 464 MiB | 166.1 s | 6,238 | 245 MiB | 0 |
| `demo` | - | - | 1.5 s | - | 62 MiB | 0 |

Lite mode's state directory (topics, positions and the DuckDB warehouse) grew to 1,753 MiB for the 206 MiB log; its topics are not trimmed.

**Alert storm** (2026-11-21): an application log of 1,000,000 lines in which every line raises at least one alert (1,360,000 in all). Every run must stay under 512 MiB of peak memory.

| Run | Time | Peak memory | Alerts not kept | Within the bound |
| ----- | -----: | ------: | ------: | ----- |
| `detect -f json` (writes each alert as it is raised) | 134.1 s | 68 MiB | 0 | yes |
| `detect` table (shows the first 100, counts the rest) | 118.5 s | 68 MiB | 0 | yes |
| `incidents` (keeps a bounded number of alerts) | 131.8 s | 201 MiB | 1,340,000 | yes |
<!-- performance:end -->

## What the numbers mean

- **The batch command streams the file** instead of loading it. Its memory depends on how much
  state is alive at once (windows, sequences, sign-in histories, open incidents), so it varies
  with the log's content: the application log, with thousands of accounts and many incidents,
  needs the most.
- **Lite mode needs more memory.** All four stages and the DuckDB warehouse run in one process,
  and DuckDB keeps a buffer of its own.
- **Alerts do not fill memory.** In the alert storm, memory stays flat however many alerts a
  log raises: `detect -f json` writes each alert as it is raised, the `detect` table keeps only
  the alerts it shows (`--limit`, 100 by default), and `incidents` keeps at most 1,000 alerts per
  rule and entities and 10,000 of each severity, saying in each incident how many it did not
  keep (see
  [INCIDENTS.md](INCIDENTS.md#bounded-alerts)).
- **Lite mode is slower than the batch command.** Every stage validates, serialises and writes
  each message to a topic file and syncs it, and the sink writes every row to DuckDB; that is
  the price of restartable, at-least-once processing. Its topics are not trimmed, so its state
  directory grows with everything it has read.
- **Formats differ** by up to about a factor of two in lines a second, depending on how much
  work each line causes in the parser and the rules.
- **One machine, one run.** The numbers are a guide to the order of magnitude, not a benchmark
  to compare machines with. Prohori 1.0.0 is not tuned for speed; the parsers and the engine are
  plain Python.

## Running it yourself

```bash
uv run --extra pipeline python scripts/benchmark.py            # about 1 million lines per log
uv run python scripts/generate_results_table.py               # updates this page and the README
```

`--lines N` sets the size, `--no-pipeline` skips lite mode and `--keep` keeps the logs in
`data/benchmark/` (git-ignored). The logs and lite mode's state need about 3 GB of disk while it
runs and are deleted at the end.
