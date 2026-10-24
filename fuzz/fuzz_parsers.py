"""Coverage-guided fuzzing of every line parser with Atheris (Linux only).

Run: uv run --with atheris python fuzz/fuzz_parsers.py -max_total_time=60

The first input byte selects the parser; the rest goes through the same path as a real file:
bounded line reading, sanitising and parsing. Any exception other than the counted, per-line
errors is a bug.
"""

import io
import sys

import atheris

with atheris.instrument_imports():
    from prohori.parsers import (
        AccessLogParser,
        AppJsonParser,
        AuthLogParser,
        FieldMapping,
        GenericJsonParser,
        LineParser,
        ParseStats,
        read_lines,
    )

_MAPPING = FieldMapping.model_validate(
    {
        "log_source": "fuzz",
        "timestamp": {"field": "t", "format": "iso8601"},
        "fields": {"event.action": "a", "source.ip": "ip", "http.status": "s"},
        "constants": {"event.category": "web"},
        "extra": {"x": "x.y"},
    }
)
_PARSERS: list[LineParser] = [
    AuthLogParser(year=2026),
    AccessLogParser(),
    AppJsonParser(),
    GenericJsonParser(mapping=_MAPPING),
]


def test_one_input(data: bytes) -> None:
    if not data:
        return
    parser = _PARSERS[data[0] % len(_PARSERS)]
    stats = ParseStats()
    for _ in parser.parse(read_lines(io.BytesIO(data[1:]), max_length=2048), stats=stats):
        pass
    if stats.lines != stats.events + stats.skipped + stats.blank + stats.errors:
        raise AssertionError(stats.as_dict())


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
