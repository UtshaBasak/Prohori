"""Tests for the parser framework: line reading, sanitising, stats and the registry."""

import io

import pytest
from hypothesis import given
from hypothesis import strategies as st

from prohori.parsers import (
    MAX_LINE_LENGTH,
    AuthLogParser,
    LineParser,
    ParseError,
    ParseStats,
    available,
    get_parser,
    iter_text_lines,
    read_lines,
    register,
    sanitize,
)
from prohori.parsers.base import MAX_ERROR_EXAMPLES


class TestReadLines:
    def test_lf_and_crlf(self) -> None:
        lines = list(read_lines(io.BytesIO(b"one\r\ntwo\nthree")))
        assert [(raw.number, raw.text) for raw in lines] == [(1, "one"), (2, "two"), (3, "three")]

    def test_invalid_utf8_replaced_and_flagged(self) -> None:
        (raw,) = read_lines(io.BytesIO(b"caf\xe9 \xff\n"))
        assert raw.decode_error
        assert "�" in raw.text

    def test_oversized_line_flagged_and_skipped_past(self) -> None:
        data = b"a" * (MAX_LINE_LENGTH * 4 + 50) + b"\nnext\n"
        lines = list(read_lines(io.BytesIO(data)))
        assert lines[0].too_long
        assert len(lines[0].text) == MAX_LINE_LENGTH
        assert (lines[1].number, lines[1].text, lines[1].too_long) == (2, "next", False)

    def test_line_just_over_character_limit(self) -> None:
        (raw,) = read_lines(io.BytesIO(b"b" * (MAX_LINE_LENGTH + 1)))
        assert raw.too_long

    def test_empty_stream(self) -> None:
        assert list(read_lines(io.BytesIO(b""))) == []

    @given(st.binary(max_size=2000))
    def test_arbitrary_bytes_never_raise(self, data: bytes) -> None:
        for raw in read_lines(io.BytesIO(data), max_length=64):
            assert len(raw.text) <= 64

    def test_iter_text_lines(self) -> None:
        lines = list(iter_text_lines(["x\r\n", "y" * (MAX_LINE_LENGTH + 1)]))
        assert lines[0].text == "x"
        assert lines[1].too_long


class TestSanitize:
    @pytest.mark.parametrize(
        ("dirty", "clean"),
        [
            ("plain text", "plain text"),
            ("line\r\n", "line"),
            ("\x1b[31mred\x1b[0m text", "red text"),
            ("title\x1b]0;evil\x07 after", "title after"),
            ("nul\x00byte\x7fdel", "nulbytedel"),
            ("tab\there", "tab here"),
            ("user‮NIMDA", "userNIMDA"),
            ("zero​width﻿", "zerowidth"),
            ("ünïcödé ✓", "ünïcödé ✓"),
        ],
    )
    def test_cases(self, dirty: str, clean: str) -> None:
        assert sanitize(dirty) == clean


class _EchoParser(LineParser):
    """Skips lines starting with 'skip' and rejects everything else."""

    name = "echo-test"

    def parse_line(self, line: str, number: int, source: str) -> None:
        if line.startswith("skip"):
            return None
        raise ValueError(f"bad line {number}")


class TestParseStats:
    def test_counts_partition_lines(self) -> None:
        stats = ParseStats()
        lines = ["skip", "", "   ", "bad", "z" * (MAX_LINE_LENGTH + 1)]
        list(_EchoParser().parse(iter_text_lines(lines), stats=stats))
        assert stats.lines == 5
        assert (stats.events, stats.skipped, stats.blank, stats.errors) == (0, 1, 2, 2)
        assert stats.lines == stats.events + stats.skipped + stats.blank + stats.errors

    def test_error_examples_are_bounded(self) -> None:
        stats = ParseStats()
        list(_EchoParser().parse(iter_text_lines(["bad"] * 50), stats=stats))
        assert stats.errors == 50
        assert len(stats.error_examples) == MAX_ERROR_EXAMPLES
        assert stats.error_examples[0].line == 1

    def test_as_dict(self) -> None:
        stats = ParseStats()
        stats.record_error(3, "broken")
        assert stats.as_dict()["error_examples"] == [{"line": 3, "reason": "broken"}]

    def test_decode_errors_counted(self) -> None:
        stats = ParseStats()
        list(_EchoParser().parse(read_lines(io.BytesIO(b"skip \xff\n")), stats=stats))
        assert stats.decode_errors == 1
        assert stats.skipped == 1

    def test_parse_raw_reports_the_reason_and_keeps_state(self) -> None:
        stats = ParseStats()
        parser = _EchoParser()
        (skip, bad, long) = iter_text_lines(["skip", "bad", "z" * (MAX_LINE_LENGTH + 1)])
        assert parser.parse_raw(skip, source="s", stats=stats) is None
        with pytest.raises(ParseError, match="bad line 2"):
            parser.parse_raw(bad, source="s", stats=stats)
        with pytest.raises(ParseError, match="longer than"):
            parser.parse_raw(long, source="s", stats=stats)
        assert (stats.lines, stats.skipped, stats.errors) == (3, 1, 2)


class TestRegistry:
    def test_auth_log_registered(self) -> None:
        assert "auth_log" in available()
        assert isinstance(get_parser("auth_log", year=2026), AuthLogParser)

    def test_unknown_parser(self) -> None:
        with pytest.raises(KeyError, match="unknown parser"):
            get_parser("nope")

    def test_name_required(self) -> None:
        class Nameless(_EchoParser):
            name = ""

        with pytest.raises(ValueError, match="non-empty"):
            register(Nameless)

    def test_duplicate_name_rejected(self) -> None:
        class Impostor(_EchoParser):
            name = "auth_log"

        with pytest.raises(ValueError, match="already registered"):
            register(Impostor)

    def test_reregistering_same_class_is_allowed(self) -> None:
        assert register(AuthLogParser) is AuthLogParser


@pytest.mark.parametrize(
    ("parser", "line"),
    [
        ("auth_log", "0001-01-01T00:00:00+14:00 h sshd[1]: Failed password for root from 1.2.3.4"),
        ("auth_log", "9999-12-31T23:59:59-14:00 h sshd[1]: Failed password for root from 1.2.3.4"),
        ("access_log", '192.0.2.1 - - [01/Jan/0001:00:00:00 +1400] "GET / HTTP/1.1" 200 1 "-" "-"'),
        ("app_json", '{"time": "0001-01-01T00:00:00+14:00", "event": {"action": "x"}}'),
    ],
)
def test_timestamps_at_the_edge_of_the_calendar_are_line_errors(parser: str, line: str) -> None:
    # Moving year 1 or 9999 with an offset to UTC overflows; that is one bad line, not a crash.
    stats = ParseStats()
    events = list(get_parser(parser).parse(iter_text_lines([line]), source="x", stats=stats))
    assert events == []
    assert stats.errors == 1


@pytest.mark.parametrize(
    ("parser", "line"),
    [
        ("app_json", '{"time": "2026-10-24T21:00:00Z", "event": {"action": "auth.signin.failure"},'
         ' "user": {"id": "u-\u001b[31m1001"}, "reason": "bad\u001b]0;PWNED\u0007x"}'),
        ("access_log", '192.0.2.1 - - [24/Oct/2026:21:00:00 +0000] '
         '"GET /\x1B]0;PWNED\x07\x1B[31mred HTTP/1.1" 404 1 "-" "a\x1Bb"'),
    ],
)  # fmt: skip
def test_escaped_control_characters_are_removed_after_decoding(parser: str, line: str) -> None:
    (event,) = get_parser(parser).parse(iter_text_lines([line]), source="x")
    text = event.model_dump_json(exclude={"raw"})
    assert "\u001b" not in text
    assert "\u0007" not in text
