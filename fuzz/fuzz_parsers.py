"""Coverage-guided fuzzing of the auth.log parser with Atheris (Linux only).

Run: uv run --with atheris python fuzz/fuzz_auth_log.py -max_total_time=60

The harness feeds arbitrary bytes through the same path as a real file: bounded line reading,
sanitising and parsing. Any exception other than the counted, per-line errors is a bug.
"""

import io
import sys

import atheris

with atheris.instrument_imports():
    from prohori.parsers import AuthLogParser, ParseStats, read_lines


def test_one_input(data: bytes) -> None:
    stats = ParseStats()
    parser = AuthLogParser(year=2026)
    for _ in parser.parse(read_lines(io.BytesIO(data), max_length=2048), stats=stats):
        pass
    if stats.lines != stats.events + stats.skipped + stats.blank + stats.errors:
        raise AssertionError(stats.as_dict())


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
