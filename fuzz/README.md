# Fuzzing

Coverage-guided fuzz harnesses for the parsers, using [Atheris](https://github.com/google/atheris).
Atheris ships Linux wheels only; on Windows, use WSL. CI runs each harness for a short time on
every push and pull request; the Hypothesis property tests in `tests/` cover the same code on
every platform.

```bash
uv run --with atheris python fuzz/fuzz_auth_log.py -max_total_time=60
```

Seed inputs can be passed as a corpus directory, for example `samples/logs/`.
