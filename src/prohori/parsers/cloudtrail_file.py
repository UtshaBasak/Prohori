# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
# Copyright (c) 2026 Utsha Basak
"""Split CloudTrail files into one record per line, with bounded memory.

CloudTrail writes trail files to S3 as ``{"Records": [...]}``, gzip-compressed and usually on one
line many megabytes long; ``aws cloudtrail lookup-events`` prints ``{"Events": [...]}`` over many
lines. Neither can be read line by line. :class:`JsonRecordLines` scans the bytes for the end of
each element of the list (counting brackets outside strings, a chunk at a time) and returns each
record as one line of compact JSON. JSON Lines whose records look like CloudTrail are read the
same way, so a record longer than a line may be (16,384 characters) is shortened by
:func:`prohori.parsers.cloudtrail.shrink` instead of being refused.

At most :data:`MAX_RECORD` bytes of one record are held. A longer record, invalid JSON, or a
record that is still too long after shrinking becomes a ``{"cloudtrail_error": ...}`` line,
which the parser counts as an error; the rest of the file is still read.
"""

import json
import re
from typing import Protocol

from prohori.parsers.base import MAX_LINE_LENGTH, ConvertedInput
from prohori.parsers.cloudtrail import shrink

#: Bytes read at a time.
CHUNK = 1 << 16
#: Most bytes of one record that are held; longer records are skipped and counted as errors.
MAX_RECORD = 4 << 20

#: A file of records in a list: ``{"Records": [`` (S3) or ``{"Events": [`` (lookup-events).
RECORDS_RE = re.compile(rb'\A(?:\xef\xbb\xbf)?\s*\{\s*"(?:Records|Events)"\s*:\s*\[')
_STRUCTURE_RE = re.compile(rb'["{}\[\],]')
_STRING_RE = re.compile(rb'["\\]')
_SPACE = b" \t\r\n"
#: Most bytes read to find the opening ``{"Records": [``.
_OPENING = 1 << 16


class Readable(Protocol):
    """A binary stream with ``read``."""

    def read(self, size: int = -1, /) -> bytes:
        """Read at most ``size`` bytes (everything when negative); ``b""`` at the end."""


class Digest(Protocol):
    """Where the bytes of the stored input are counted and hashed."""

    count: int

    def hexdigest(self) -> str:
        """SHA-256 of the bytes read so far."""

    def drain(self) -> None:
        """Read the rest of the input, so the count and hash cover all of it."""


def sniff(head: bytes) -> str:
    """``records`` for a list of records, ``sequence`` for CloudTrail JSON Lines, else ``lines``."""
    if RECORDS_RE.match(head):
        return "records"
    first = head.removeprefix(b"\xef\xbb\xbf").lstrip(_SPACE).split(b"\n", 1)[0]
    if first.startswith(b"{") and b'"eventSource"' in first and b'"eventName"' in first:
        return "sequence"
    return "lines"


class JsonRecordLines(ConvertedInput):
    """``readline`` over the records of a CloudTrail file, one compact JSON line each.

    Args:
        stream: The (decompressed) input.
        digest: Counts and hashes the input as stored.
        array: The records are the elements of the file's ``Records`` or ``Events`` list;
            otherwise they are JSON objects one after another (JSON Lines).
    """

    def __init__(self, stream: Readable, digest: Digest, *, array: bool) -> None:
        self._stream = stream
        self._digest = digest
        self._array = array
        self._buffer = bytearray()
        self._eof = False
        self._done = False
        self._pending = b""
        self._fill()
        if array:  # skip the opening, which may arrive over several reads
            while (match := RECORDS_RE.match(self._buffer)) is None:
                if len(self._buffer) > _OPENING or not self._fill():
                    break
            if match is not None:
                del self._buffer[: match.end()]
        else:
            while len(self._buffer) < 3 and self._fill():
                pass
            if self._buffer.startswith(b"\xef\xbb\xbf"):
                del self._buffer[:3]

    def stored_size(self) -> int:
        return self._digest.count

    def hexdigest(self) -> str:
        return self._digest.hexdigest()

    def readline(self, size: int = -1, /) -> bytes:
        if not self._pending:
            self._pending = self._next_line()
        if size < 0 or len(self._pending) <= size:
            line, self._pending = self._pending, b""
        else:
            line, self._pending = self._pending[:size], self._pending[size:]
        return line

    # ------------------------------------------------------------------ scanning

    def _fill(self) -> bool:
        """Read one more chunk; ``False`` at the end of the input."""
        if self._eof:
            return False
        chunk = self._stream.read(CHUNK)
        if not chunk:
            self._eof = True
            return False
        self._buffer += chunk
        return True

    def _finish(self) -> bytes:
        self._done = True
        self._buffer.clear()
        self._digest.drain()
        return b""

    def _next_line(self) -> bytes:
        while not self._done:
            start = self._skip_separators()
            if start is None:
                return self._finish()
            element, error = self._element(start)
            if error is None and element is None:
                return self._finish()
            return self._convert(element) if error is None else _error(error)
        return b""

    def _skip_separators(self) -> int | None:
        """Index of the next element's first byte, or ``None`` at the end of the records."""
        index = 0
        while True:
            while index < len(self._buffer) and (
                self._buffer[index] in _SPACE or (self._array and self._buffer[index] == ord(","))
            ):
                index += 1
            if index < len(self._buffer):
                del self._buffer[:index]
                if self._array and self._buffer[0] == ord("]"):
                    return None
                return 0
            self._buffer.clear()
            index = 0
            if not self._fill():
                return None

    def _element(self, start: int) -> tuple[bytes | None, str | None]:
        """The next element's bytes, or an error. ``(None, None)`` when the input ended cleanly."""
        buffer = self._buffer
        if not self._array and buffer[start] != ord("{"):
            return self._bad_line()
        depth, in_string, index, skipped = 0, False, start, 0
        while True:
            if in_string:
                match = _STRING_RE.search(buffer, index)
                if match is None:
                    index = len(buffer)
                elif match.group() == b"\\":
                    if match.end() < len(buffer):
                        index = match.end() + 1  # skip the escaped byte
                        continue
                    index = match.start()  # look at the backslash again with more data
                else:
                    in_string, index = False, match.end()
                    continue
            else:
                match = _STRUCTURE_RE.search(buffer, index)
                if match is not None:
                    byte = match.group()
                    index = match.end()
                    if byte == b'"':
                        in_string = True
                    elif byte in {b"{", b"["}:
                        depth += 1
                    elif byte in {b"}", b"]"}:
                        depth -= 1
                        if depth == 0:
                            return self._take(index, skipped)
                        if depth < 0:  # the list closed after a value that is not an object
                            return self._take(index - 1, skipped)
                    elif depth == 0:  # a comma after a value that is not an object
                        return self._take(index - 1, skipped)
                    continue
                index = len(buffer)
            # The element continues past the buffer: drop what an oversized record has used.
            if index - start > MAX_RECORD:
                skipped += index - start
                del buffer[start:index]
                index = start
            if not self._fill():
                self._buffer.clear()
                if skipped or depth or in_string:
                    return None, "the file ends inside a record"
                return None, None

    def _take(self, end: int, skipped: int) -> tuple[bytes | None, str | None]:
        element = bytes(self._buffer[:end])
        del self._buffer[:end]
        if skipped:
            return None, f"record longer than {MAX_RECORD} bytes"
        return element, None

    def _bad_line(self) -> tuple[bytes | None, str | None]:
        """In JSON Lines, text that does not start an object: skip to the end of its line."""
        while (newline := self._buffer.find(b"\n")) < 0:
            if len(self._buffer) > MAX_RECORD:
                self._buffer.clear()
            if not self._fill():
                self._buffer.clear()
                return None, "not a JSON object"
        del self._buffer[: newline + 1]
        return None, "not a JSON object"

    def _convert(self, element: bytes | None) -> bytes:
        text = (element or b"").decode("utf-8", errors="replace")
        try:
            record = json.loads(text)
        except RecursionError:
            return _error("JSON nested too deeply")
        except ValueError as exc:
            message = exc.msg if isinstance(exc, json.JSONDecodeError) else str(exc)
            return _error(f"invalid JSON record: {message}")
        if not isinstance(record, dict):
            return _error(f"record is a {type(record).__name__}, not an object")
        line = shrink(record, MAX_LINE_LENGTH)
        if line is None:
            return _error(f"record longer than {MAX_LINE_LENGTH} characters after shortening")
        return line.encode("utf-8") + b"\n"


def _error(reason: str) -> bytes:
    return json.dumps({"cloudtrail_error": reason}).encode() + b"\n"
