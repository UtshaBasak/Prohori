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

The commands are `prohori incidents` on every log (parsing, the 15 rules, offline enrichment,
incident building and JSON output), `prohori pipeline replay` in lite mode on the access log, and
`prohori demo`. Output goes to files, not a terminal.

## Results

<!-- performance:start -->
Generated from `results/performance.json` by `scripts/benchmark.py`, run on 2026-11-02 with Prohori 1.0.0 and Python 3.13.14 on Windows 11 (AMD64, 12 logical CPUs, Intel64 Family 6 Model 141 Stepping 1, GenuineIntel). Do not edit by hand.

| Run | Lines | Size | Time | Lines a second | Peak memory | Exit code |
|-----|------:|-----:|-----:|------:|------:|------:|
| `incidents`, nginx/Apache access log | 1,068,043 | 202 MiB | 150.4 s | 7,102 | 142 MiB | 0 |
| `pipeline replay` (lite mode), access log | 1,068,043 | 202 MiB | 478.1 s | 2,234 | 1,078 MiB | 0 |
| `incidents`, auth.log (sshd) | 1,000,198 | 100 MiB | 77.8 s | 12,859 | 181 MiB | 0 |
| `incidents`, JSON Lines app log | 1,035,764 | 462 MiB | 119.9 s | 8,641 | 524 MiB | 0 |
| `demo` | - | - | 1.5 s | - | 61 MiB | 0 |

Lite mode's state directory (topics, positions and the DuckDB warehouse) grew to 1,711 MiB for the 202 MiB log; its topics are not trimmed.
<!-- performance:end -->

## What the numbers mean

- **The batch command streams the file** instead of loading it. Its memory depends on how much
  state is alive at once (windows, sequences, sign-in histories, open incidents), so it varies
  with the log's content: the application log, with thousands of accounts and many incidents,
  needs the most.
- **Lite mode needs more memory.** All four stages and the DuckDB warehouse run in one process,
  and DuckDB keeps a buffer of its own.
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
