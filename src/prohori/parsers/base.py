"""Parser framework: bounded line reading, sanitising, error accounting and the parser base class.

Parsers are streaming generators. A malformed line is counted and reported, never fatal: one
hostile or corrupt line must not stop the analysis of the rest of a file.
"""

import re
from abc import ABC, abstractmethod
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from pydantic import ValidationError

from prohori.schema import Event

#: Longest line (in characters after decoding) a parser will look at. Longer lines are counted
#: as errors without being matched, which also bounds regular-expression work per line.
MAX_LINE_LENGTH = 16_384

#: Number of example errors kept in :class:`ParseStats` for reporting.
MAX_ERROR_EXAMPLES = 10

# ANSI escape sequences (CSI and OSC); C0/C1 control characters except tab; and invisible
# formatting characters (zero-width, bidirectional overrides, BOM) that can disguise text.
_ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?|\x1b[@-Z\\-_]")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0a-\x1f\x7f-\x9f​-‏‪-‮⁦-⁩﻿]")


class ParseError(ValueError):
    """Raised by a parser for a line it recognises as malformed."""


@dataclass(frozen=True, slots=True)
class RawLine:
    """One input line as read from a stream, before parsing."""

    number: int
    text: str
    too_long: bool = False
    decode_error: bool = False


@dataclass(frozen=True, slots=True)
class LineError:
    """A line that could not be parsed, kept as an example for the summary."""

    line: int
    reason: str


@dataclass(slots=True)
class ParseStats:
    """Counters for one parse run.

    ``skipped`` lines are well-formed but not relevant to the parser (for example a cron line in
    ``auth.log``); ``errors`` are malformed. Every line read is exactly one of ``events``,
    ``skipped``, ``blank`` or ``errors``.
    """

    lines: int = 0
    events: int = 0
    skipped: int = 0
    blank: int = 0
    errors: int = 0
    decode_errors: int = 0
    error_examples: list[LineError] = field(default_factory=list)

    def record_error(self, line: int, reason: str) -> None:
        """Count an error and keep it as an example if there is room."""
        self.errors += 1
        if len(self.error_examples) < MAX_ERROR_EXAMPLES:
            self.error_examples.append(LineError(line, reason))

    def as_dict(self) -> dict[str, Any]:
        """Return the counters as a JSON-serialisable mapping."""
        return {
            "lines": self.lines,
            "events": self.events,
            "skipped": self.skipped,
            "blank": self.blank,
            "errors": self.errors,
            "decode_errors": self.decode_errors,
            "error_examples": [{"line": e.line, "reason": e.reason} for e in self.error_examples],
        }


def sanitize(text: str) -> str:
    """Remove line endings, ANSI escapes, control and invisible formatting characters.

    Tabs become spaces.
    """
    text = text.rstrip("\r\n")
    text = _ANSI_RE.sub("", text)
    text = _CONTROL_RE.sub("", text)
    return text.replace("\t", " ")


class LineSource(Protocol):
    """Anything with a binary ``readline``, such as an open file or ``sys.stdin.buffer``."""

    def readline(self, size: int = -1, /) -> bytes: ...


def read_lines(stream: LineSource, max_length: int = MAX_LINE_LENGTH) -> Iterator[RawLine]:
    """Yield decoded lines from a binary stream with bounded memory.

    Lines are split on ``\\n`` (so ``\\r\\n`` files work), decoded as UTF-8 with invalid bytes
    replaced, and never held in memory beyond ``max_length`` (+ a little) characters: the rest of
    an oversized line is read in chunks and discarded.
    """
    # UTF-8 uses at most 4 bytes per character.
    byte_limit = max_length * 4 + 1
    number = 0
    while True:
        chunk = stream.readline(byte_limit)
        if not chunk:
            return
        number += 1
        too_long = False
        if not chunk.endswith(b"\n") and len(chunk) >= byte_limit:
            too_long = True
            while True:  # discard the remainder of the line
                rest = stream.readline(byte_limit)
                if not rest or rest.endswith(b"\n"):
                    break
        try:
            text = chunk.decode("utf-8")
            decode_error = False
        except UnicodeDecodeError:
            text = chunk.decode("utf-8", errors="replace")
            decode_error = True
        text = text.rstrip("\r\n")
        if len(text) > max_length:
            too_long = True
        if too_long:
            text = text[:max_length]
        yield RawLine(number, text, too_long, decode_error)


def iter_text_lines(lines: Iterable[str], max_length: int = MAX_LINE_LENGTH) -> Iterator[RawLine]:
    """Wrap already-decoded lines (for example from ``io.StringIO``) as :class:`RawLine`."""
    for number, text in enumerate(lines, start=1):
        text = text.rstrip("\r\n")
        too_long = len(text) > max_length
        yield RawLine(number, text[:max_length] if too_long else text, too_long)


class LineParser(ABC):
    """Base class for parsers that turn one line into at most one event.

    Subclasses implement :meth:`parse_line`. The base class handles sanitising, size limits,
    blank lines and error accounting.
    """

    #: Registry name, for example ``"auth_log"``.
    name: str = ""

    def reset(self) -> None:  # noqa: B027 - optional hook, intentionally empty
        """Clear per-input state before a new input is parsed."""

    @abstractmethod
    def parse_line(self, line: str, number: int, source: str) -> Event | None:
        """Parse one sanitised, non-blank line.

        Return ``None`` for a well-formed line that is not relevant, raise :class:`ParseError`
        for a malformed one.
        """

    def parse(
        self, lines: Iterable[RawLine], *, source: str = "<stdin>", stats: ParseStats | None = None
    ) -> Iterator[Event]:
        """Parse ``lines`` lazily, updating ``stats`` as a side effect.

        ``source`` names the input (for example the file name); it is part of each event id so
        identical lines at different positions stay distinct.
        """
        stats = stats if stats is not None else ParseStats()
        self.reset()
        for raw in lines:
            stats.lines += 1
            if raw.decode_error:
                stats.decode_errors += 1
            if raw.too_long:
                stats.record_error(raw.number, f"line longer than {MAX_LINE_LENGTH} characters")
                continue
            text = sanitize(raw.text)
            if not text.strip():
                stats.blank += 1
                continue
            try:
                event = self.parse_line(text, raw.number, source)
            except ValueError as exc:  # ParseError and pydantic.ValidationError
                stats.record_error(raw.number, _short_reason(exc))
                continue
            if event is None:
                stats.skipped += 1
            else:
                stats.events += 1
                yield event

    def parse_file(self, path: Path, *, stats: ParseStats | None = None) -> Iterator[Event]:
        """Parse a file lazily. The file stays open until the generator is exhausted or closed."""
        with path.open("rb") as stream:
            yield from self.parse(read_lines(stream), source=path.name, stats=stats)


def _short_reason(exc: ValueError) -> str:
    if isinstance(exc, ValidationError) and exc.errors():
        first = exc.errors()[0]
        location = ".".join(str(part) for part in first["loc"]) or "record"
        return f"invalid {location}: {first['msg']}"[:200]
    message = str(exc).splitlines()[0] if str(exc) else type(exc).__name__
    return message[:200]
